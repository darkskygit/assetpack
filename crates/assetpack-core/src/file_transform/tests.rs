use std::{
  io::{BufRead, Write},
  sync::Arc,
};

use super::*;
use crate::hash::Hash32;

#[derive(Debug, Clone)]
struct DummyTransform;

impl crate::TransformDecoder for DummyTransform {
  fn id(&self) -> u16 {
    0xFFFF
  }

  fn version(&self) -> u16 {
    1
  }

  fn decode(&self, input: &mut dyn BufRead, out: &mut dyn Write) -> crate::Result<()> {
    std::io::copy(input, out)?;
    Ok(())
  }
}

impl FileTransform for DummyTransform {
  fn quick_check(&self, _hint: &FileHint) -> bool {
    true
  }

  fn encode(&self, input: &mut dyn BufRead, out: &mut dyn Write) -> crate::Result<TransformStats> {
    let bytes = std::io::copy(input, out)?;
    Ok(TransformStats {
      input_bytes: bytes,
      output_bytes: bytes,
    })
  }
}

fn dummy_spec() -> TransformSpec {
  fn enabled(_config: &FileTransformConfig) -> bool {
    true
  }

  fn build(_config: &FileTransformConfig) -> Arc<dyn FileTransform> {
    Arc::new(DummyTransform)
  }

  TransformSpec {
    id: 0xFFFF,
    name: "dummy",
    selectable: true,
    use_quick_check: false,
    enabled,
    build,
  }
}

#[test]
fn spool_overflow_falls_back() {
  let mut spool = StoredStreamSpool::new_memory(4);
  assert!(spool.write_all(&[1, 2, 3]).is_ok());
  assert!(spool.write_all(&[4, 5]).is_err());
}

#[test]
fn precomp2_config_default_matches_expected() {
  let config = FileTransformPrecomp2Config::default();
  assert!(config.enabled);
  assert_eq!(config.max_depth, 4);
  assert_eq!(config.max_expand_ratio, 16.0);
  assert_eq!(config.max_total_output, 1 << 32);
  assert!(!config.recover);
}

#[test]
fn selector_skips_too_large() {
  let config = FileTransformConfig {
    min_size: 0,
    max_transform_bytes: 4,
    allow_ext: vec!["bin".into()],
    ..Default::default()
  };
  let selector = TransformSelector::new(config, None, vec![dummy_spec()]);
  let data = vec![0u8; 8];
  let hint = FileHint {
    size: data.len() as u64,
    extension: Some("bin".into()),
    head: Some(data[..4].to_vec()),
  };
  let selection = selector.select_bytes(data.clone(), &hint, Hash32::sha3_256(&data)).unwrap();
  assert_eq!(selection.transform_id, TRANSFORM_ID_NONE);
}

#[test]
fn selector_respects_no_spill() {
  let config = FileTransformConfig {
    min_size: 0,
    allow_ext: vec!["bin".into()],
    max_in_memory_bytes: 4,
    spill_to_disk: false,
    ..Default::default()
  };
  let selector = TransformSelector::new(config, None, vec![dummy_spec()]);
  let data = vec![1u8; 8];
  let hint = FileHint {
    size: data.len() as u64,
    extension: Some("bin".into()),
    head: Some(data[..4].to_vec()),
  };
  let selection = selector.select_bytes(data.clone(), &hint, Hash32::sha3_256(&data)).unwrap();
  assert_eq!(selection.transform_id, TRANSFORM_ID_NONE);
}

#[test]
fn selector_falls_back_when_temp_dir_invalid() {
  let config = FileTransformConfig {
    min_size: 0,
    allow_ext: vec!["bin".into()],
    max_in_memory_bytes: 1,
    spill_to_disk: true,
    ..Default::default()
  };
  let bad_dir = tempfile::NamedTempFile::new().unwrap();
  let selector = TransformSelector::new(config, Some(bad_dir.path().to_path_buf()), vec![dummy_spec()]);
  let data = vec![2u8; 8];
  let hint = FileHint {
    size: data.len() as u64,
    extension: Some("bin".into()),
    head: Some(data[..4].to_vec()),
  };
  let selection = selector.select_bytes(data.clone(), &hint, Hash32::sha3_256(&data)).unwrap();
  assert_eq!(selection.transform_id, TRANSFORM_ID_NONE);
}
