use std::{
  io::{self, BufReader, Cursor, Write},
  sync::Arc,
};

use sha3::{Digest, Sha3_256};

use super::{FileHint, FileTransform, FileTransformConfig, TransformSelection, TransformSpec, spool::StoredStreamSpool};
use crate::{
  FastCdcSplitter,
  error::Result,
  hash::Hash32,
  pipeline::{ChunkCompressionPolicy, ChunkCompressor, DefaultChunkCompressor, Pipeline, PipelineConfig},
};

struct HashingSink {
  hasher: Sha3_256,
  bytes: u64,
}

impl HashingSink {
  fn new() -> Self {
    Self {
      hasher: Sha3_256::new(),
      bytes: 0,
    }
  }

  fn finish(self) -> (Hash32, u64) {
    let digest = self.hasher.finalize();
    (Hash32::new(digest.into()), self.bytes)
  }
}

impl Write for HashingSink {
  fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
    self.hasher.update(buf);
    self.bytes += buf.len() as u64;
    Ok(buf.len())
  }

  fn flush(&mut self) -> io::Result<()> {
    Ok(())
  }
}

#[derive(Clone)]
pub struct TransformSelector {
  config: FileTransformConfig,
  temp_dir: Option<std::path::PathBuf>,
  candidates: Vec<TransformCandidate>,
}

impl TransformSelector {
  pub fn new(config: FileTransformConfig, temp_dir: Option<std::path::PathBuf>, candidates: Vec<TransformSpec>) -> Self {
    let candidates = candidates
      .into_iter()
      .filter(|spec| spec.selectable && (spec.enabled)(&config))
      .map(|spec| TransformCandidate {
        transform: (spec.build)(&config),
        use_quick_check: spec.use_quick_check,
      })
      .collect();

    Self {
      config,
      temp_dir,
      candidates,
    }
  }

  pub fn select_bytes(&self, data: Vec<u8>, hint: &FileHint, original_hash: Hash32) -> Result<TransformSelection> {
    let original_size = data.len() as u64;
    if !self.config.enabled {
      return Ok(TransformSelection::none(data, original_hash));
    }
    if original_size > self.config.max_transform_bytes {
      return Ok(TransformSelection::none(data, original_hash));
    }
    if self.candidates.is_empty() {
      return Ok(TransformSelection::none(data, original_hash));
    }
    let pipeline = Pipeline::new(PipelineConfig {
      splitter: FastCdcSplitter::v1_defaults(),
      chunk_compression: ChunkCompressionPolicy::Auto,
      discard_payload: true,
    });
    let compressor = DefaultChunkCompressor;
    let extension = hint.extension.as_deref();
    let mut candidate_plans = Vec::new();

    for candidate in &self.candidates {
      let attempt = TransformAttempt {
        transform: candidate.transform.as_ref(),
        data: &data,
        hint,
        original_hash,
        original_size,
        extension,
        use_quick_check: candidate.use_quick_check,
        pipeline: &pipeline,
        compressor: &compressor,
      };
      if let Some(result) = self.try_transform(attempt)? {
        candidate_plans.push(result);
      }
    }

    let baseline_selection = TransformSelection::none(data, original_hash);
    let baseline_plan = match pipeline.run_with_selection_ref(&baseline_selection, extension, &compressor) {
      Ok(plan) => plan,
      Err(_) => {
        return Ok(baseline_selection);
      }
    };
    let threshold = (baseline_plan.estimated_bytes as f64 * (1.0 - self.config.min_gain)).floor();

    let _plans = candidate_plans
      .iter()
      .map(|(sel, size)| (sel.transform_id, *size))
      .collect::<Vec<_>>();
    let mut best: Option<(TransformSelection, u64)> = None;
    for candidate in candidate_plans {
      if (candidate.1 as f64) <= threshold {
        best = pick_best(best, candidate);
      }
    }

    // println!(
    //   "Transform selection plans: baseline={} bytes, candidates={:?}, best={:?}",
    //   baseline_plan.estimated_bytes,
    //   plans,
    //   best.as_ref().map(|(sel, size)| (sel.transform_id, size))
    // );
    if let Some((selection, _)) = best {
      return Ok(selection);
    }

    Ok(baseline_selection)
  }

  fn try_transform(&self, attempt: TransformAttempt<'_>) -> Result<Option<(TransformSelection, u64)>> {
    let TransformAttempt {
      transform,
      data,
      hint,
      original_hash,
      original_size,
      extension,
      use_quick_check,
      pipeline,
      compressor,
    } = attempt;

    if use_quick_check && !transform.quick_check(hint) {
      return Ok(None);
    }

    let mut spool = if original_size <= self.config.max_in_memory_bytes {
      StoredStreamSpool::new_memory(self.config.eval.max_buffer_bytes)
    } else if self.config.spill_to_disk {
      match StoredStreamSpool::new_file(self.temp_dir.as_deref()) {
        Ok(spool) => spool,
        Err(_) => {
          return Ok(None);
        }
      }
    } else {
      return Ok(None);
    };

    if transform.encode(&mut BufReader::new(Cursor::new(data)), &mut spool).is_err() {
      return Ok(None);
    }

    let mut verify_reader = match spool.reader() {
      Ok(reader) => reader,
      Err(_) => {
        return Ok(None);
      }
    };
    let mut verify_reader = BufReader::new(&mut verify_reader);
    let mut sink = HashingSink::new();
    if transform.decode(&mut verify_reader, &mut sink).is_err() {
      return Ok(None);
    }

    let (decoded_hash, decoded_size) = sink.finish();
    if decoded_hash != original_hash || decoded_size != original_size {
      return Ok(None);
    }

    let stored_stream = match spool.into_bytes() {
      Ok(bytes) => bytes,
      Err(_) => {
        return Ok(None);
      }
    };

    let selection = TransformSelection {
      transform_id: transform.id(),
      transform_version: transform.version(),
      original_size,
      original_hash,
      stored_stream,
    };
    let plan = match pipeline.run_with_selection_ref(&selection, extension, compressor) {
      Ok(plan) => plan,
      Err(_) => {
        return Ok(None);
      }
    };

    Ok(Some((selection, plan.estimated_bytes)))
  }
}

impl std::fmt::Debug for TransformSelector {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("TransformSelector")
      .field("config", &self.config)
      .field("temp_dir", &self.temp_dir)
      .field("candidate_count", &self.candidates.len())
      .finish()
  }
}

#[derive(Clone)]
struct TransformCandidate {
  transform: Arc<dyn FileTransform>,
  use_quick_check: bool,
}

struct TransformAttempt<'a> {
  transform: &'a dyn FileTransform,
  data: &'a [u8],
  hint: &'a FileHint,
  original_hash: Hash32,
  original_size: u64,
  extension: Option<&'a str>,
  use_quick_check: bool,
  pipeline: &'a Pipeline,
  compressor: &'a dyn ChunkCompressor,
}

fn pick_best(best: Option<(TransformSelection, u64)>, candidate: (TransformSelection, u64)) -> Option<(TransformSelection, u64)> {
  match best {
    None => Some(candidate),
    Some((best_sel, best_est)) => {
      if candidate.1 < best_est {
        Some(candidate)
      } else {
        Some((best_sel, best_est))
      }
    }
  }
}
