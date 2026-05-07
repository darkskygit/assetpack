use fastcdc::v2020::FastCDC;

use crate::error::{Error, Result};

pub const DEFAULT_MIN: usize = 4 * 1024;
pub const DEFAULT_AVG: usize = 64 * 1024;
pub const DEFAULT_MAX: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunk {
  pub offset: usize,
  pub length: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct FastCdcSplitter {
  min_size: usize,
  avg_size: usize,
  max_size: usize,
}

impl FastCdcSplitter {
  pub fn new(min_size: usize, avg_size: usize, max_size: usize) -> Result<Self> {
    if min_size == 0 || min_size > avg_size || avg_size > max_size {
      return Err(Error::InvalidCdcParams);
    }
    Ok(Self {
      min_size,
      avg_size,
      max_size,
    })
  }

  pub fn v1_defaults() -> Self {
    Self::new(DEFAULT_MIN, DEFAULT_AVG, DEFAULT_MAX).expect("defaults are valid")
  }

  pub fn split_bytes(&self, data: &[u8]) -> Vec<Chunk> {
    FastCDC::new(data, self.min_size as u32, self.avg_size as u32, self.max_size as u32)
      .map(|c| Chunk {
        offset: c.offset,
        length: c.length,
      })
      .collect()
  }
}

#[cfg(test)]
mod tests {
  use rand::RngCore;

  use super::*;

  #[test]
  fn rejects_invalid_params() {
    assert!(FastCdcSplitter::new(0, DEFAULT_AVG, DEFAULT_MAX).is_err());
    assert!(FastCdcSplitter::new(DEFAULT_AVG, DEFAULT_MIN, DEFAULT_MAX).is_err());
  }

  #[test]
  fn splits_and_respects_bounds() {
    let mut data = vec![0u8; DEFAULT_MAX * 2 + DEFAULT_AVG];
    rand::rng().fill_bytes(&mut data);
    let splitter = FastCdcSplitter::v1_defaults();
    let chunks = splitter.split_bytes(&data);
    assert!(!chunks.is_empty());

    let mut total = 0usize;
    for (i, c) in chunks.iter().enumerate() {
      assert_eq!(c.offset, total);
      total += c.length;
      if i + 1 != chunks.len() {
        assert!(c.length >= DEFAULT_MIN);
        assert!(c.length <= DEFAULT_MAX);
      } else {
        assert!(c.length <= DEFAULT_MAX);
      }
    }
    assert_eq!(total, data.len());
  }

  #[test]
  fn small_input_returns_single_chunk() {
    let data = vec![1u8; 1024];
    let splitter = FastCdcSplitter::v1_defaults();
    let chunks = splitter.split_bytes(&data);
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].length, data.len());
    assert_eq!(chunks[0].offset, 0);
  }
}
