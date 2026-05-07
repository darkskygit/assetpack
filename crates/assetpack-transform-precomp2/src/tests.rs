use std::io::{BufReader, Cursor};

use assetpack_core::{
  FileHint, FileTransformConfig, FileTransformPrecomp2Config, Hash32, TRANSFORM_ID_NONE, TRANSFORM_ID_PRECOMP2, TRANSFORM_ID_PRECOMP2_LZMA,
  TRANSFORM_ID_PRECOMP2_ZSTD, TransformSelector, file_transform::FileTransform,
};

const TINY_PNG: &[u8] = &[
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x01, 0x08, 0x04, 0x00, 0x00, 0x00, 0xb5, 0x1c, 0x0c, 0x02, 0x00, 0x00, 0x00, 0x0b, 0x49, 0x44, 0x41, 0x54, 0x78, 0xda, 0x63, 0xfc, 0xff,
  0x1f, 0x00, 0x03, 0x03, 0x02, 0x00, 0xee, 0x6a, 0x93, 0xa9, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
];

fn assert_roundtrip_keeps_hash(transform: &dyn FileTransform, data: &[u8]) {
  let original_hash = Hash32::sha3_256(data);
  let mut encoded = Vec::new();
  let mut reader = BufReader::new(Cursor::new(data));
  transform.encode(&mut reader, &mut encoded).unwrap();

  let mut decoded = Vec::new();
  let mut reader = BufReader::new(Cursor::new(encoded));
  transform.decode(&mut reader, &mut decoded).unwrap();

  assert_eq!(Hash32::sha3_256(&decoded), original_hash);
}

#[test]
fn base_precomp2_config_defaults_match_precomp2_defaults() {
  let config = FileTransformPrecomp2Config::default();
  let encode = precomp2::EncodeConfig::default();
  let decode = precomp2::DecodeConfig::default();
  assert_eq!(config.max_depth, encode.max_depth);
  assert_eq!(config.max_expand_ratio, encode.max_expand_ratio);
  assert_eq!(config.max_total_output, encode.max_total_output);
  assert_eq!(config.recover, decode.recover);
}

#[test]
fn precomp2_encode_config_enables_features() {
  let config = FileTransformPrecomp2Config::default();
  let encode = crate::common::precomp2_encode_config(&config);
  assert!(encode.enable_png_webp);
  assert!(encode.enable_pdf_predictor);
  assert!(encode.enable_pdf_bmp_fallback);
}

#[test]
fn precomp2_roundtrip_keeps_hash() {
  let config = FileTransformConfig::default();
  let transform = crate::Precomp2Transform::new(&config);
  assert_roundtrip_keeps_hash(&transform, TINY_PNG);
}

#[test]
fn precomp2_zstd_roundtrip_keeps_hash() {
  let config = FileTransformConfig::default();
  let transform = crate::Precomp2ZstdTransform::new(&config);
  assert_roundtrip_keeps_hash(&transform, TINY_PNG);
}

#[test]
fn precomp2_lzma_roundtrip_keeps_hash() {
  let config = FileTransformConfig::default();
  let transform = crate::Precomp2LzmaTransform::new(&config);
  assert_roundtrip_keeps_hash(&transform, TINY_PNG);
}

#[test]
fn selector_accepts_with_negative_gain() {
  let config = FileTransformConfig {
    min_size: 0,
    min_gain: -10.0,
    allow_ext: vec!["bin".into()],
    ..Default::default()
  };
  let selector = TransformSelector::new(config, None, crate::default_specs());
  let data = b"preflate selector smoke test".repeat(8);
  let hint = FileHint {
    size: data.len() as u64,
    extension: Some("bin".into()),
    head: Some(data[..8].to_vec()),
  };
  let selection = selector.select_bytes(data.to_vec(), &hint, Hash32::sha3_256(&data)).unwrap();
  assert_ne!(selection.transform_id, TRANSFORM_ID_NONE);
  assert!(
    matches!(
      selection.transform_id,
      TRANSFORM_ID_PRECOMP2 | TRANSFORM_ID_PRECOMP2_ZSTD | TRANSFORM_ID_PRECOMP2_LZMA
    ),
    "unexpected transform id {}",
    selection.transform_id
  );
}

#[test]
fn selector_accepts_precomp2_family_with_negative_gain() {
  let config = FileTransformConfig {
    min_size: 0,
    min_gain: -10.0,
    allow_ext: vec!["png".into()],
    ..Default::default()
  };
  let selector = TransformSelector::new(config, None, crate::default_specs());
  let data = TINY_PNG.to_vec();
  let hint = FileHint {
    size: data.len() as u64,
    extension: Some("png".into()),
    head: Some(data[..8].to_vec()),
  };
  let selection = selector.select_bytes(data, &hint, Hash32::sha3_256(TINY_PNG)).unwrap();
  assert_ne!(selection.transform_id, TRANSFORM_ID_NONE);
  assert!(
    matches!(
      selection.transform_id,
      TRANSFORM_ID_PRECOMP2 | TRANSFORM_ID_PRECOMP2_ZSTD | TRANSFORM_ID_PRECOMP2_LZMA
    ),
    "unexpected transform id {}",
    selection.transform_id
  );
}
