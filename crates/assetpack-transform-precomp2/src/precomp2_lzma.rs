use std::io::{BufRead, Write};

use assetpack_core::{
  TRANSFORM_ID_PRECOMP2_LZMA, TRANSFORM_VERSION_PRECOMP2_LZMA, TransformDecoder,
  file_transform::{FileHint, FileTransform, FileTransformConfig, TransformEncodeContext, TransformStats},
};

use super::{
  TransformGate, clamp_dict_size, lzma_compress, lzma_decode_precomp2, max_mid_stream_bytes, precomp2_decode_config, precomp2_encode_bytes,
  precomp2_encode_config, read_bounded, tighten_decode_config,
};

#[derive(Debug, Clone)]
pub struct Precomp2LzmaTransform {
  gate: TransformGate,
  encode_config: precomp2::EncodeConfig,
  decode_config: precomp2::DecodeConfig,
  max_mid_bytes: u64,
  preset: u32,
  dict_size: u32,
}

impl Precomp2LzmaTransform {
  pub fn new(config: &FileTransformConfig) -> Self {
    Self {
      gate: TransformGate::new(config),
      encode_config: precomp2_encode_config(&config.precomp2),
      decode_config: precomp2_decode_config(&config.precomp2),
      max_mid_bytes: max_mid_stream_bytes(config),
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
    lzma_decode_precomp2(input, out, self.dict_size, &self.decode_config, self.max_mid_bytes)
  }

  fn decode_for_size(&self, input: &mut dyn BufRead, out: &mut dyn Write, original_file_size: u64) -> assetpack_core::Result<()> {
    let (decode_config, max_mid_bytes) = tighten_decode_config(&self.decode_config, self.max_mid_bytes, original_file_size);
    lzma_decode_precomp2(input, out, self.dict_size, &decode_config, max_mid_bytes)
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
    let input_bytes = read_bounded(input, self.gate.max_size(), "precomp2-lzma encode")?;
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
