use std::io::{BufRead, Write};

use assetpack_core::{
  TRANSFORM_ID_PRECOMP2_ZSTD, TRANSFORM_VERSION_PRECOMP2_ZSTD, TransformDecoder,
  file_transform::{FileHint, FileTransform, FileTransformConfig, TransformEncodeContext, TransformStats},
};

use super::{
  TransformGate, precomp2_decode_bytes, precomp2_decode_config, precomp2_encode_bytes, precomp2_encode_config, read_all, zstd_compress,
  zstd_decompress,
};

#[derive(Debug, Clone)]
pub struct Precomp2ZstdTransform {
  gate: TransformGate,
  encode_config: precomp2::EncodeConfig,
  decode_config: precomp2::DecodeConfig,
  level: i32,
}

impl Precomp2ZstdTransform {
  pub fn new(config: &FileTransformConfig) -> Self {
    Self {
      gate: TransformGate::new(config),
      encode_config: precomp2_encode_config(&config.precomp2),
      decode_config: precomp2_decode_config(&config.precomp2),
      level: config.precomp2_zstd.level,
    }
  }
}

impl TransformDecoder for Precomp2ZstdTransform {
  fn id(&self) -> u16 {
    TRANSFORM_ID_PRECOMP2_ZSTD
  }

  fn version(&self) -> u16 {
    TRANSFORM_VERSION_PRECOMP2_ZSTD
  }

  fn decode(&self, input: &mut dyn BufRead, out: &mut dyn Write) -> assetpack_core::Result<()> {
    let encoded = read_all(input)?;
    let decoded = zstd_decompress(&encoded)?;
    let output = precomp2_decode_bytes(&decoded, &self.decode_config)?;
    out.write_all(&output)?;
    Ok(())
  }
}

impl FileTransform for Precomp2ZstdTransform {
  fn encode_with_context(
    &self,
    input: &[u8],
    out: &mut dyn Write,
    context: &mut TransformEncodeContext,
  ) -> assetpack_core::Result<TransformStats> {
    let encoded = super::prepare_precomp2(input, &self.encode_config, context)?;
    let compressed = zstd_compress(encoded, self.level)?;
    out.write_all(&compressed)?;
    Ok(TransformStats {
      input_bytes: input.len() as u64,
      output_bytes: compressed.len() as u64,
    })
  }

  fn quick_check(&self, hint: &FileHint) -> bool {
    self.gate.quick_check(hint)
  }

  fn encode(&self, input: &mut dyn BufRead, out: &mut dyn Write) -> assetpack_core::Result<TransformStats> {
    let input_bytes = read_all(input)?;
    let input_len = input_bytes.len() as u64;
    let encoded = precomp2_encode_bytes(&input_bytes, &self.encode_config)?;
    let compressed = zstd_compress(&encoded, self.level)?;
    out.write_all(&compressed)?;
    Ok(TransformStats {
      input_bytes: input_len,
      output_bytes: compressed.len() as u64,
    })
  }
}
