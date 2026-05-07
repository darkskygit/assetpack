use crate::{
  FastCdcSplitter,
  codec::{Codec, compress, compress_auto},
  error::Result,
  file_transform::{FileHint, TRANSFORM_ID_NONE, TransformSelection, TransformSelector},
  hash::Hash32,
};

#[derive(Debug, Clone, Copy)]
pub enum ChunkCompressionPolicy {
  Auto,
  Raw,
  ForceCodec(Codec),
}

#[derive(Debug, Clone)]
pub struct PipelineConfig {
  pub splitter: FastCdcSplitter,
  pub chunk_compression: ChunkCompressionPolicy,
  pub discard_payload: bool,
}

impl Default for PipelineConfig {
  fn default() -> Self {
    Self {
      splitter: FastCdcSplitter::v1_defaults(),
      chunk_compression: ChunkCompressionPolicy::Auto,
      discard_payload: false,
    }
  }
}

#[derive(Debug, Clone)]
pub struct ChunkPlan {
  pub hash: Hash32,
  pub raw_len: u32,
  pub codec: Codec,
  pub stored_len: u32,
  pub payload: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct PipelinePlan {
  pub transform_id: u16,
  pub transform_version: u16,
  pub original_size: u64,
  pub original_hash: Hash32,
  pub stored_stream_size: u64,
  pub chunks: Vec<ChunkPlan>,
  pub estimated_bytes: u64,
}

pub trait ChunkCompressor: Send + Sync {
  fn compress(&self, hash: Hash32, data: &[u8], extension: Option<&str>, policy: ChunkCompressionPolicy) -> Result<(Codec, Vec<u8>)>;
}

#[derive(Debug, Default)]
pub struct DefaultChunkCompressor;

impl ChunkCompressor for DefaultChunkCompressor {
  fn compress(&self, _hash: Hash32, data: &[u8], extension: Option<&str>, policy: ChunkCompressionPolicy) -> Result<(Codec, Vec<u8>)> {
    match policy {
      ChunkCompressionPolicy::Auto => compress_auto(data, extension),
      ChunkCompressionPolicy::Raw => Ok((Codec::Raw, data.to_vec())),
      ChunkCompressionPolicy::ForceCodec(codec) => Ok((codec, compress(codec, data)?)),
    }
  }
}

#[derive(Debug, Clone)]
pub struct Pipeline {
  config: PipelineConfig,
}

impl Pipeline {
  pub fn new(config: PipelineConfig) -> Self {
    Self { config }
  }

  pub fn run(&self, data: Vec<u8>, hint: &FileHint, original_hash: Hash32, selector: Option<&TransformSelector>) -> Result<PipelinePlan> {
    self.run_with_compressor(data, hint, original_hash, selector, &DefaultChunkCompressor)
  }

  pub fn run_with_compressor(
    &self,
    data: Vec<u8>,
    hint: &FileHint,
    original_hash: Hash32,
    selector: Option<&TransformSelector>,
    compressor: &dyn ChunkCompressor,
  ) -> Result<PipelinePlan> {
    let selection = if let Some(selector) = selector {
      selector.select_bytes(data, hint, original_hash)?
    } else {
      TransformSelection::none(data, original_hash)
    };
    self.run_with_selection(selection, hint.extension.as_deref(), compressor)
  }

  pub fn run_with_selection(
    &self,
    selection: TransformSelection,
    extension: Option<&str>,
    compressor: &dyn ChunkCompressor,
  ) -> Result<PipelinePlan> {
    self.run_with_selection_ref(&selection, extension, compressor)
  }

  pub fn run_with_selection_ref(
    &self,
    selection: &TransformSelection,
    extension: Option<&str>,
    compressor: &dyn ChunkCompressor,
  ) -> Result<PipelinePlan> {
    let stored_stream_size = selection.stored_stream.len() as u64;
    let compress_ext = if selection.transform_id == TRANSFORM_ID_NONE {
      extension
    } else {
      None
    };

    let mut chunks = Vec::new();
    let mut estimated_bytes = 0u64;
    for chunk in self.config.splitter.split_bytes(&selection.stored_stream) {
      let start = chunk.offset;
      let end = start + chunk.length;
      let slice = &selection.stored_stream[start..end];
      let hash = Hash32::sha3_256(slice);
      let (codec, stored) = compressor.compress(hash, slice, compress_ext, self.config.chunk_compression)?;
      let stored_len = stored.len() as u32;
      estimated_bytes += stored_len as u64;
      let payload = if self.config.discard_payload { None } else { Some(stored) };
      chunks.push(ChunkPlan {
        hash,
        raw_len: chunk.length as u32,
        codec,
        stored_len,
        payload,
      });
    }
    estimated_bytes += recipe_bytes_len(chunks.len());

    Ok(PipelinePlan {
      transform_id: selection.transform_id,
      transform_version: selection.transform_version,
      original_size: selection.original_size,
      original_hash: selection.original_hash,
      stored_stream_size,
      chunks,
      estimated_bytes,
    })
  }
}

fn recipe_bytes_len(chunk_count: usize) -> u64 {
  let header = 1 + 8 + 32 + 2 + 2 + 4;
  let per_chunk = 32 + 4;
  (header + per_chunk * chunk_count) as u64
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::codec::Codec;

  #[test]
  fn pipeline_discard_payload_strips_chunks() {
    let config = PipelineConfig {
      splitter: FastCdcSplitter::v1_defaults(),
      chunk_compression: ChunkCompressionPolicy::Raw,
      discard_payload: true,
    };
    let pipeline = Pipeline::new(config);
    let data = b"pipeline payload test".to_vec();
    let hash = Hash32::sha3_256(&data);
    let selection = TransformSelection::none(data.clone(), hash);
    let plan = pipeline
      .run_with_selection(selection, Some("txt"), &DefaultChunkCompressor)
      .unwrap();
    assert!(!plan.chunks.is_empty());
    for chunk in &plan.chunks {
      assert!(chunk.payload.is_none());
      assert_eq!(chunk.codec, Codec::Raw);
      assert_eq!(chunk.stored_len, chunk.raw_len);
    }
  }
}
