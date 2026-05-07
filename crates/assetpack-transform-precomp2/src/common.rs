use std::{
  collections::HashSet,
  io::{BufRead, Cursor, Read, Write},
};

use assetpack_core::{
  error::{Error, Result},
  file_transform::{FileHint, FileTransformConfig, FileTransformPrecomp2Config},
};
use lzma_rust2::{DICT_SIZE_MAX, DICT_SIZE_MIN, Lzma2Options, Lzma2Reader, Lzma2Writer};
use precomp2::{DecodeConfig as Precomp2DecodeConfig, EncodeConfig as Precomp2EncodeConfig};

use crate::guards::{magic_match, precomp2_guard};

#[derive(Debug, Clone)]
pub(crate) struct TransformGate {
  allow_ext: HashSet<String>,
  min_size: u64,
  max_size: u64,
}

impl TransformGate {
  pub(crate) fn new(config: &FileTransformConfig) -> Self {
    let allow_ext = config.allow_ext.iter().map(|ext| ext.to_ascii_lowercase()).collect::<HashSet<_>>();
    Self {
      allow_ext,
      min_size: config.min_size,
      max_size: config.max_transform_bytes,
    }
  }

  pub(crate) fn quick_check(&self, hint: &FileHint) -> bool {
    if hint.size < self.min_size || hint.size > self.max_size {
      return false;
    }
    let ext_ok = hint
      .extension
      .as_deref()
      .map(|ext| self.allow_ext.contains(&ext.to_ascii_lowercase()))
      .unwrap_or(false);
    if ext_ok {
      return true;
    }
    let Some(head) = hint.head.as_deref() else {
      return false;
    };
    magic_match(head)
  }
}

pub(crate) fn read_all(input: &mut dyn BufRead) -> Result<Vec<u8>> {
  let mut data = Vec::new();
  input.read_to_end(&mut data)?;
  Ok(data)
}

pub(crate) fn precomp2_encode_config(config: &FileTransformPrecomp2Config) -> Precomp2EncodeConfig {
  Precomp2EncodeConfig {
    max_depth: config.max_depth,
    max_expand_ratio: config.max_expand_ratio,
    max_total_output: config.max_total_output,
    enable_png_webp: true,
    enable_pdf_predictor: true,
    enable_pdf_bmp_fallback: true,
  }
}

pub(crate) fn precomp2_decode_config(config: &FileTransformPrecomp2Config) -> Precomp2DecodeConfig {
  Precomp2DecodeConfig {
    max_depth: config.max_depth,
    max_total_output: config.max_total_output,
    recover: config.recover,
  }
}

pub(crate) fn precomp2_encode_bytes(input: &[u8], config: &Precomp2EncodeConfig) -> Result<Vec<u8>> {
  precomp2_guard("encode", precomp2::encode_bytes(input, config))
}

pub(crate) fn precomp2_decode_bytes(encoded: &[u8], config: &Precomp2DecodeConfig) -> Result<Vec<u8>> {
  precomp2_guard("decode", precomp2::decode_bytes(encoded, config))
}

pub(crate) fn zstd_compress(input: &[u8], level: i32) -> Result<Vec<u8>> {
  zstd::encode_all(Cursor::new(input), level).map_err(|e| Error::Compress(e.to_string()))
}

pub(crate) fn zstd_decompress(input: &[u8]) -> Result<Vec<u8>> {
  zstd::decode_all(Cursor::new(input)).map_err(|e| Error::Decompress(e.to_string()))
}

pub(crate) fn clamp_dict_size(value: usize) -> u32 {
  let min = DICT_SIZE_MIN as u64;
  let max = DICT_SIZE_MAX as u64;
  let value = value as u64;
  value.clamp(min, max) as u32
}

pub(crate) fn lzma_compress(input: &[u8], preset: u32, dict_size: u32) -> Result<Vec<u8>> {
  let mut options = Lzma2Options::with_preset(preset);
  options.lzma_options.dict_size = dict_size;
  let mut compressed = Vec::new();
  let mut writer = Lzma2Writer::new(&mut compressed, options);
  writer.write_all(input).map_err(|e| Error::Compress(e.to_string()))?;
  writer.finish().map_err(|e| Error::Compress(e.to_string()))?;
  Ok(compressed)
}

pub(crate) fn lzma_decompress(input: &[u8], dict_size: u32) -> Result<Vec<u8>> {
  let mut reader = Lzma2Reader::new(Cursor::new(input), dict_size, None);
  let mut decoded = Vec::new();
  reader.read_to_end(&mut decoded).map_err(|e| Error::Decompress(e.to_string()))?;
  Ok(decoded)
}
