use std::io::Cursor;

use brotli::enc::backward_references::BrotliEncoderParams;

use crate::error::{Error, Result};

pub const SAMPLE_LIMIT: usize = 64 * 1024;
const COMPRESSED_WHITELIST: &[&str] = &[
  "jpg", "jpeg", "png", "webp", "zip", "epub", "gz", "tgz", "bz2", "xz", "br", "zst", "mp4", "mov", "pdf",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
  Raw,
  Zstd,
  Brotli,
}

pub struct EntropyEstimator;

impl EntropyEstimator {
  pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    let sample = if bytes.len() > SAMPLE_LIMIT {
      &bytes[..SAMPLE_LIMIT]
    } else {
      bytes
    };
    let mut counts = [0usize; 256];
    for b in sample {
      counts[*b as usize] += 1;
    }
    let total = sample.len() as f64;
    counts
      .iter()
      .filter(|&&c| c > 0)
      .map(|&c| {
        let p = c as f64 / total;
        -p * p.log2()
      })
      .sum()
  }
}

fn is_compressed_extension(ext: &str) -> bool {
  COMPRESSED_WHITELIST.contains(&ext)
}

pub fn decide_codec(data: &[u8], extension: Option<&str>) -> Codec {
  if let Some(ext) = extension.map(|s| s.to_ascii_lowercase())
    && is_compressed_extension(&ext)
  {
    return Codec::Raw;
  }

  let entropy = EntropyEstimator::shannon_entropy(data);
  if entropy >= 7.7 {
    Codec::Raw
  } else if entropy >= 6.9 {
    Codec::Zstd
  } else {
    Codec::Brotli
  }
}

pub fn compress(codec: Codec, data: &[u8]) -> Result<Vec<u8>> {
  match codec {
    Codec::Raw => Ok(data.to_vec()),
    Codec::Zstd => zstd::encode_all(Cursor::new(data), 5).map_err(|e| Error::Compress(e.to_string())),
    Codec::Brotli => {
      let params = BrotliEncoderParams {
        quality: 5,
        lgwin: 20,
        ..Default::default()
      };
      let mut output = Vec::new();
      brotli::BrotliCompress(&mut Cursor::new(data), &mut output, &params).map_err(|e| Error::Compress(e.to_string()))?;
      Ok(output)
    }
  }
}

pub fn decompress(codec: Codec, data: &[u8]) -> Result<Vec<u8>> {
  match codec {
    Codec::Raw => Ok(data.to_vec()),
    Codec::Zstd => {
      let mut out = Vec::new();
      zstd::stream::copy_decode(Cursor::new(data), &mut out).map_err(|e| Error::Decompress(e.to_string()))?;
      Ok(out)
    }
    Codec::Brotli => {
      let mut out = Vec::new();
      brotli::BrotliDecompress(&mut Cursor::new(data), &mut out).map_err(|e| Error::Decompress(e.to_string()))?;
      Ok(out)
    }
  }
}

pub fn compress_auto(data: &[u8], extension: Option<&str>) -> Result<(Codec, Vec<u8>)> {
  let choice = decide_codec(data, extension);
  let compressed = compress(choice, data)?;
  if choice == Codec::Raw {
    return Ok((choice, compressed));
  }
  let ratio = compressed.len() as f64 / data.len().max(1) as f64;
  if ratio >= 0.98 {
    Ok((Codec::Raw, data.to_vec()))
  } else {
    Ok((choice, compressed))
  }
}

#[cfg(test)]
mod tests {
  use rand::RngCore;

  use super::*;

  #[test]
  fn entropy_detects_noise_and_structure() {
    let mut random = [0u8; 1024];
    rand::rng().fill_bytes(&mut random);
    let random_h = EntropyEstimator::shannon_entropy(&random);
    let structured = vec![0u8; 1024];
    let structured_h = EntropyEstimator::shannon_entropy(&structured);
    assert!(random_h > 7.5);
    assert!(structured_h < 1.0);
  }

  #[test]
  fn roundtrip_for_all_codecs() {
    let data = b"The quick brown fox jumps over the lazy dog".repeat(64);
    for codec in [Codec::Raw, Codec::Zstd, Codec::Brotli] {
      let compressed = compress(codec, &data).unwrap();
      let restored = decompress(codec, &compressed).unwrap();
      assert_eq!(restored, data);
    }
  }

  #[test]
  fn auto_prefers_brotli_for_low_entropy() {
    let data = vec![1u8; 4096];
    let (codec, compressed) = compress_auto(&data, None).unwrap();
    assert_eq!(codec, Codec::Brotli);
    assert!(compressed.len() < data.len());
  }

  #[test]
  fn auto_falls_back_to_raw_when_not_smaller() {
    let data = vec![0u8; 8];
    let (codec, compressed) = compress_auto(&data, None).unwrap();
    assert_eq!(codec, Codec::Raw);
    assert_eq!(compressed, data);
  }

  #[test]
  fn auto_respects_compressed_whitelist_extensions() {
    let mut data = vec![0u8; 4096];
    rand::rng().fill_bytes(&mut data);
    let (codec, compressed) = compress_auto(&data, Some("jpg")).unwrap();
    assert_eq!(codec, Codec::Raw);
    assert_eq!(compressed, data);
  }

  #[test]
  fn auto_skips_compression_for_high_entropy_data() {
    let data = (0u8..=255).cycle().take(64 * 1024).collect::<Vec<_>>();
    let (codec, compressed) = compress_auto(&data, None).unwrap();
    assert_eq!(codec, Codec::Raw);
    assert_eq!(compressed, data);
  }
}
