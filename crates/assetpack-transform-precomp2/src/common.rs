use std::{
  collections::HashSet,
  io::{self, BufRead, Cursor, Read, Write},
};

use assetpack_core::{
  error::{Error, Result},
  file_transform::{FileHint, FileTransformConfig, FileTransformPrecomp2Config, TransformEncodeContext},
};
use lzma_rust2::{DICT_SIZE_MAX, DICT_SIZE_MIN, Lzma2Options, Lzma2Reader, Lzma2Writer};
use precomp2::{DecodeConfig as Precomp2DecodeConfig, EncodeConfig as Precomp2EncodeConfig};

use super::{magic_match, precomp2_guard};

/// Small framing slack above `max_total_output` so tiny valid files (such as a
/// 68-byte PNG whose PCF2 wrapper is ~143 bytes) still stream cleanly under an
/// exact output budget.
const MID_STREAM_SLACK_BYTES: u64 = 64 * 1024;

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

  pub(crate) fn max_size(&self) -> u64 {
    self.max_size
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

pub(crate) fn max_mid_stream_bytes(config: &FileTransformConfig) -> u64 {
  config.precomp2.max_total_output.saturating_add(MID_STREAM_SLACK_BYTES)
}

pub(crate) fn read_bounded(input: &mut dyn BufRead, max_bytes: u64, label: &'static str) -> Result<Vec<u8>> {
  let mut data = Vec::new();
  input.take(max_bytes.saturating_add(1)).read_to_end(&mut data)?;
  if data.len() as u64 > max_bytes {
    return Err(Error::Other(format!("{label} input exceeds limit ({max_bytes} bytes)")));
  }
  Ok(data)
}

struct BoundedReader<R> {
  inner: R,
  limit: u64,
  read: u64,
  exceeded: bool,
}

impl<R> BoundedReader<R> {
  fn new(inner: R, limit: u64) -> Self {
    Self {
      inner,
      limit,
      read: 0,
      exceeded: false,
    }
  }

  fn is_exceeded(&self) -> bool {
    self.exceeded
  }
}

impl<R: Read> Read for BoundedReader<R> {
  fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
    if buf.is_empty() {
      return Ok(0);
    }
    let remaining = self.limit.saturating_sub(self.read);
    if remaining == 0 {
      let mut probe = [0u8; 1];
      let n = self.inner.read(&mut probe)?;
      if n > 0 {
        self.exceeded = true;
        return Err(io::Error::new(
          io::ErrorKind::FileTooLarge,
          "precomp2 intermediate stream exceeds budget",
        ));
      }
      return Ok(0);
    }
    let max_read = (buf.len() as u64).min(remaining) as usize;
    let n = self.inner.read(&mut buf[..max_read])?;
    self.read = self.read.saturating_add(n as u64);
    Ok(n)
  }
}

pub(crate) fn precomp2_encode_config(config: &FileTransformPrecomp2Config) -> Precomp2EncodeConfig {
  Precomp2EncodeConfig {
    max_depth: config.max_depth,
    max_expand_ratio: config.max_expand_ratio,
    max_total_output: config.max_total_output,
    enable_png_webp: true,
    enable_pdf_predictor: config.enable_pdf_predictor,
    enable_pdf_dct: config.enable_pdf_dct,
    enable_pdf_ascii: config.enable_pdf_ascii,
    enable_pdf_images: config.enable_pdf_images,
    max_pdf_filters: config.max_pdf_filters,
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

pub(crate) fn prepare_precomp2<'a>(
  input: &[u8],
  config: &Precomp2EncodeConfig,
  context: &'a mut TransformEncodeContext,
) -> Result<&'a [u8]> {
  context.get_or_prepare(format!("precomp2-v2:{config:?}"), || precomp2_encode_bytes(input, config))
}

pub(crate) fn precomp2_decode_reader<R: Read>(
  reader: R,
  out: &mut dyn Write,
  config: &Precomp2DecodeConfig,
  max_mid_bytes: u64,
) -> Result<()> {
  if config.recover {
    let mut encoded = Vec::new();
    reader
      .take(max_mid_bytes.saturating_add(1))
      .read_to_end(&mut encoded)
      .map_err(|e| Error::Decompress(e.to_string()))?;
    if encoded.len() as u64 > max_mid_bytes {
      return Err(Error::Decompress("precomp2 intermediate stream exceeds budget".to_string()));
    }
    let decoded = precomp2_guard("decode", precomp2::decode_bytes(&encoded, config))?;
    out.write_all(&decoded)?;
    return Ok(());
  }

  let mut bounded = BoundedReader::new(reader, max_mid_bytes);
  match precomp2::decode_reader(&mut bounded, out, config) {
    Ok(_) => Ok(()),
    Err(_) if bounded.is_exceeded() => Err(Error::Decompress("precomp2 intermediate stream exceeds budget".to_string())),
    Err(err) => precomp2_guard("decode", Err(err)),
  }
}

pub(crate) fn zstd_compress(input: &[u8], level: i32) -> Result<Vec<u8>> {
  zstd::encode_all(Cursor::new(input), level).map_err(|e| Error::Compress(e.to_string()))
}

pub(crate) fn zstd_decode_precomp2(
  input: &mut dyn BufRead,
  out: &mut dyn Write,
  config: &Precomp2DecodeConfig,
  max_mid_bytes: u64,
) -> Result<()> {
  let decoder = zstd::stream::read::Decoder::with_buffer(input).map_err(|e| Error::Decompress(e.to_string()))?;
  precomp2_decode_reader(decoder, out, config, max_mid_bytes)
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

pub(crate) fn lzma_decode_precomp2(
  input: &mut dyn BufRead,
  out: &mut dyn Write,
  dict_size: u32,
  config: &Precomp2DecodeConfig,
  max_mid_bytes: u64,
) -> Result<()> {
  let reader = Lzma2Reader::new(input, dict_size, None);
  precomp2_decode_reader(reader, out, config, max_mid_bytes)
}
