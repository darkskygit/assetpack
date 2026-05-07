use std::io::{self, BufRead, Write};

use super::super::{FileHint, FileTransform, TRANSFORM_ID_NONE, TRANSFORM_VERSION_NONE, TransformStats};
use crate::error::Result;

#[derive(Debug, Clone)]
pub(super) struct NoneTransform;

impl FileTransform for NoneTransform {
  fn id(&self) -> u16 {
    TRANSFORM_ID_NONE
  }

  fn version(&self) -> u16 {
    TRANSFORM_VERSION_NONE
  }

  fn quick_check(&self, _hint: &FileHint) -> bool {
    true
  }

  fn encode(&self, input: &mut dyn BufRead, out: &mut dyn Write) -> Result<TransformStats> {
    let mut bytes = 0u64;
    let mut buf = [0u8; 8192];
    loop {
      let n = input.read(&mut buf)?;
      if n == 0 {
        break;
      }
      out.write_all(&buf[..n])?;
      bytes += n as u64;
    }
    Ok(TransformStats {
      input_bytes: bytes,
      output_bytes: bytes,
    })
  }

  fn decode(&self, input: &mut dyn BufRead, out: &mut dyn Write) -> Result<()> {
    io::copy(input, out)?;
    Ok(())
  }
}
