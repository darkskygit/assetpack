use std::io::{BufRead, Write};

use assetpack_core::{
  TRANSFORM_ID_PRECOMP2_LZMA, TRANSFORM_VERSION_PRECOMP2_LZMA, TransformDecoder,
  file_transform::{FileHint, FileTransform, FileTransformConfig, TransformEncodeContext, TransformStats},
};

use super::{
  TransformGate, clamp_dict_size, lzma_compress, lzma_decompress, precomp2_decode_bytes, precomp2_decode_config, precomp2_encode_bytes,
  precomp2_encode_config, read_all,
};

#[derive(Debug, Clone)]
pub struct Precomp2LzmaTransform {
  gate: TransformGate,
  encode_config: precomp2::EncodeConfig,
  decode_config: precomp2::DecodeConfig,
  preset: u32,
  dict_size: u32,
}

impl Precomp2LzmaTransform {
  pub fn new(config: &FileTransformConfig) -> Self {
    Self {
      gate: TransformGate::new(config),
      encode_config: precomp2_encode_config(&config.precomp2),
      decode_config: precomp2_decode_config(&config.precomp2),
      preset: config.precomp2_lzma.preset as u32,
      dict_size: clamp_dict_size(config.precomp2_lzma.dict_size),
    }
  }
}

impl TransformDecoder for Precomp2LzmaTransform {
  fn id(&self) -> u16 {
    TRANSFORM_ID_PRECOMP2_LZMA
  }

  fn version(&self) -> u16 {
    TRANSFORM_VERSION_PRECOMP2_LZMA
  }

  fn decode(&self, input: &mut dyn BufRead, out: &mut dyn Write) -> assetpack_core::Result<()> {
    let encoded = read_all(input)?;
    let decoded = lzma_decompress(&encoded, self.dict_size)?;
    let output = precomp2_decode_bytes(&decoded, &self.decode_config)?;
    out.write_all(&output)?;
    Ok(())
  }
}

impl FileTransform for Precomp2LzmaTransform {
  fn encode_with_context(
    &self,
    input: &[u8],
    out: &mut dyn Write,
    context: &mut TransformEncodeContext,
  ) -> assetpack_core::Result<TransformStats> {
    let encoded = super::prepare_precomp2(input, &self.encode_config, context)?;
    let compressed = lzma_compress(encoded, self.preset, self.dict_size)?;
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
    let compressed = lzma_compress(&encoded, self.preset, self.dict_size)?;
    out.write_all(&compressed)?;
    Ok(TransformStats {
      input_bytes: input_len,
      output_bytes: compressed.len() as u64,
    })
  }
}
