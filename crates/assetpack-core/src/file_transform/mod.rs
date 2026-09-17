mod config;
mod selector;
mod spool;
mod transforms;

#[cfg(test)]
mod tests;

use crate::{
  hash::Hash32,
  transform::{TRANSFORM_ID_NONE, TRANSFORM_VERSION_NONE, TransformDecoder},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransformInfo {
  pub id: u16,
  pub name: &'static str,
}

#[derive(Debug, Clone)]
pub struct FileHint {
  pub size: u64,
  pub extension: Option<String>,
  pub head: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy)]
pub struct TransformStats {
  pub input_bytes: u64,
  pub output_bytes: u64,
}

pub trait FileTransform: TransformDecoder {
  fn quick_check(&self, hint: &FileHint) -> bool;
  fn encode(&self, input: &mut dyn std::io::BufRead, out: &mut dyn std::io::Write) -> crate::Result<TransformStats>;

  fn encode_with_context(
    &self,
    input: &[u8],
    out: &mut dyn std::io::Write,
    _context: &mut TransformEncodeContext,
  ) -> crate::Result<TransformStats> {
    self.encode(&mut std::io::Cursor::new(input), out)
  }
}

/// A preparation cache belonging to one input and one selector invocation.
/// Never reuse it for another input: keys identify settings, not file contents.
#[derive(Default)]
pub struct TransformEncodeContext {
  prepared: std::collections::HashMap<String, Vec<u8>>,
}

impl TransformEncodeContext {
  /// Keys must include the transform namespace and all preparation settings.
  pub fn get_or_prepare(&mut self, key: String, prepare: impl FnOnce() -> crate::Result<Vec<u8>>) -> crate::Result<&[u8]> {
    use std::collections::hash_map::Entry;
    Ok(match self.prepared.entry(key) {
      Entry::Occupied(entry) => entry.into_mut(),
      Entry::Vacant(entry) => entry.insert(prepare()?),
    })
  }
}

#[derive(Clone)]
pub struct TransformSelection {
  pub transform_id: u16,
  pub transform_version: u16,
  pub original_size: u64,
  pub original_hash: Hash32,
  pub stored_stream: Vec<u8>,
}

impl TransformSelection {
  pub fn none(data: Vec<u8>, original_hash: Hash32) -> Self {
    let size = data.len() as u64;
    Self {
      transform_id: TRANSFORM_ID_NONE,
      transform_version: TRANSFORM_VERSION_NONE,
      original_size: size,
      original_hash,
      stored_stream: data,
    }
  }
}

pub fn transform_info(id: u16, specs: &[TransformSpec]) -> Option<TransformInfo> {
  specs.iter().find(|spec| spec.id == id).map(|spec| TransformInfo {
    id: spec.id,
    name: spec.name,
  })
}

pub fn selectable_transforms(specs: &[TransformSpec]) -> Vec<TransformInfo> {
  specs
    .iter()
    .filter(|spec| spec.selectable)
    .map(|spec| TransformInfo {
      id: spec.id,
      name: spec.name,
    })
    .collect()
}

pub fn enabled_transforms(config: &FileTransformConfig, specs: &[TransformSpec]) -> Vec<TransformInfo> {
  specs
    .iter()
    .filter(|spec| spec.selectable && (spec.enabled)(config))
    .map(|spec| TransformInfo {
      id: spec.id,
      name: spec.name,
    })
    .collect()
}

pub use config::{
  FileTransformConfig, FileTransformEvalConfig, FileTransformPrecomp2Config, FileTransformPrecomp2LzmaConfig,
  FileTransformPrecomp2ZstdConfig,
};
pub use selector::{CandidateOutcome, CandidateReport, SelectionReport, TransformSelector};
pub use spool::{StoredStreamReader, StoredStreamSpool};
pub use transforms::TransformSpec;
