use std::io::{self, BufRead, Read};

use sha3::{Digest, Sha3_256};

#[cfg(feature = "sealed-encryption")]
use super::FrameUnsealer;
use super::{DirectoryRecord, Header, PayloadReader, invalid};
use crate::{
  codec::Codec,
  error::{Error, Result},
  hash::Hash32,
  object::{ObjectSource, VerifiedObject},
};

const STREAM_BUFFER_BYTES: usize = 32 * 1024;
const ZSTD_MAX_WINDOW_LOG: u32 = 22;
const BROTLI_MAX_WINDOW_LOG: u32 = 20;

pub struct SealedPackReader<'a> {
  bytes: &'a [u8],
  pub(super) header: Header,
  root_recipe: Hash32,
  pub(super) records: Vec<DirectoryRecord>,
  #[cfg(feature = "sealed-encryption")]
  unsealer: Option<&'a dyn FrameUnsealer>,
}

impl<'a> SealedPackReader<'a> {
  pub(super) fn from_records(
    bytes: &'a [u8],
    header: Header,
    root_recipe: Hash32,
    records: Vec<DirectoryRecord>,
    #[cfg(feature = "sealed-encryption")] unsealer: Option<&'a dyn FrameUnsealer>,
    #[cfg(not(feature = "sealed-encryption"))] _unsealer: Option<&'a ()>,
  ) -> Result<Self> {
    Ok(Self {
      bytes,
      header,
      root_recipe,
      records,
      #[cfg(feature = "sealed-encryption")]
      unsealer,
    })
  }

  pub fn pack_id(&self) -> Hash32 {
    self.header.pack_id
  }

  pub fn root_recipe(&self) -> Hash32 {
    self.root_recipe
  }

  pub fn object_count(&self) -> usize {
    self.records.len()
  }

  pub fn verify_all_objects(&self) -> Result<()> {
    let mut scratch = [0_u8; 32 * 1024];
    for record in &self.records {
      let mut object = self.open_object(record)?;
      loop {
        let read = object.read(&mut scratch).map_err(error_from_io)?;
        if read == 0 {
          break;
        }
      }
    }
    Ok(())
  }

  fn open_object(&self, record: &DirectoryRecord) -> Result<VerifyingReader<'a>> {
    let source = PayloadReader::new(
      self.bytes,
      &self.header,
      record.clone(),
      #[cfg(feature = "sealed-encryption")]
      self.unsealer,
    )?;
    let decoded: Box<dyn Read + 'a> = match record.codec {
      Codec::Raw => Box::new(source),
      Codec::Zstd => {
        let mut decoder = zstd::stream::read::Decoder::new(source).map_err(|error| Error::Decompress(error.to_string()))?;
        decoder
          .window_log_max(ZSTD_MAX_WINDOW_LOG)
          .map_err(|error| Error::Decompress(error.to_string()))?;
        Box::new(decoder)
      }
      Codec::Brotli => {
        let mut source = io::BufReader::with_capacity(STREAM_BUFFER_BYTES, source);
        let first = source
          .fill_buf()
          .map_err(error_from_io)?
          .first()
          .copied()
          .ok_or_else(|| invalid("empty Brotli payload"))?;
        if brotli_window_bits(first)? > BROTLI_MAX_WINDOW_LOG {
          return Err(invalid("Brotli window exceeds sealed decoder limit"));
        }
        Box::new(brotli::Decompressor::new(source, STREAM_BUFFER_BYTES))
      }
    };
    Ok(VerifyingReader::new(decoded, record.hash, record.decoded_length))
  }
}

impl ObjectSource for SealedPackReader<'_> {
  fn read_object(&self, hash: &Hash32) -> Result<Option<VerifiedObject>> {
    let Some(record) = self
      .records
      .binary_search_by_key(hash, |record| record.hash)
      .ok()
      .and_then(|index| self.records.get(index))
    else {
      return Ok(None);
    };
    let mut reader = self.open_object(record)?;
    let capacity: usize = record
      .decoded_length
      .try_into()
      .map_err(|_| invalid("object length exceeds address space"))?;
    let mut bytes = Vec::with_capacity(capacity);
    reader.read_to_end(&mut bytes).map_err(error_from_io)?;
    Ok(Some(VerifiedObject {
      hash: record.hash,
      kind: record.kind,
      bytes,
    }))
  }
}

fn brotli_window_bits(first: u8) -> Result<u32> {
  if first & 1 == 0 {
    return Ok(16);
  }
  let primary = (first >> 1) & 7;
  if primary != 0 {
    return Ok(17 + u32::from(primary));
  }
  let secondary = (first >> 4) & 7;
  match secondary {
    0 => Ok(17),
    1 => Err(invalid("large-window Brotli is not supported")),
    value => Ok(8 + u32::from(value)),
  }
}

struct VerifyingReader<'a> {
  inner: Option<Box<dyn Read + 'a>>,
  hasher: Sha3_256,
  expected_hash: Hash32,
  expected_length: u64,
  decoded_length: u64,
  verified: bool,
}

impl<'a> VerifyingReader<'a> {
  fn new(inner: Box<dyn Read + 'a>, expected_hash: Hash32, expected_length: u64) -> Self {
    Self {
      inner: Some(inner),
      hasher: Sha3_256::new(),
      expected_hash,
      expected_length,
      decoded_length: 0,
      verified: false,
    }
  }

  fn release_working_set(&mut self) {
    self.inner.take();
  }
}

impl Read for VerifyingReader<'_> {
  fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
    if self.verified {
      return Ok(0);
    }
    let read = match self.inner.as_mut().expect("unverified reader has an inner stream").read(output) {
      Ok(read) => read,
      Err(error) => {
        self.release_working_set();
        return Err(error);
      }
    };
    if read == 0 {
      let actual = Hash32::new(self.hasher.clone().finalize().into());
      if self.decoded_length != self.expected_length {
        self.release_working_set();
        return Err(io_error(Error::ObjectLengthMismatch {
          expected: self.expected_length,
          actual: self.decoded_length,
        }));
      }
      if actual != self.expected_hash {
        self.release_working_set();
        return Err(io_error(Error::ObjectHashMismatch {
          expected: self.expected_hash,
          actual,
        }));
      }
      self.verified = true;
      self.release_working_set();
      return Ok(0);
    }
    self.hasher.update(&output[..read]);
    self.decoded_length = match self.decoded_length.checked_add(read as u64) {
      Some(length) => length,
      None => {
        self.release_working_set();
        return Err(io::Error::new(io::ErrorKind::InvalidData, "sealed object length overflow"));
      }
    };
    if self.decoded_length > self.expected_length {
      let actual = self.decoded_length;
      self.release_working_set();
      return Err(io_error(Error::ObjectLengthMismatch {
        expected: self.expected_length,
        actual,
      }));
    }
    Ok(read)
  }
}

fn io_error(error: Error) -> io::Error {
  io::Error::new(io::ErrorKind::InvalidData, error)
}

fn error_from_io(error: io::Error) -> Error {
  let kind = error.kind();
  match error.into_inner() {
    Some(inner) => match inner.downcast::<Error>() {
      Ok(error) => *error,
      Err(inner) => Error::Decompress(inner.to_string()),
    },
    None => Error::Decompress(io::Error::from(kind).to_string()),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn brotli_window_bits_decodes_rfc7932_first_byte() {
    for (first, expected) in [
      (0x00, 16),
      (0x02, 16),
      (0xfe, 16),
      (0x01, 17),
      (0x03, 18),
      (0x05, 19),
      (0x0b, 22),
      (0x0f, 24),
      (0x21, 10),
      (0x71, 15),
    ] {
      assert_eq!(brotli_window_bits(first).unwrap(), expected, "first byte {first:#04x}");
    }
    for first in [0x11, 0x91] {
      let error = brotli_window_bits(first).unwrap_err();
      assert!(error.to_string().contains("large-window"), "first byte {first:#04x}: {error}");
    }
  }
}
