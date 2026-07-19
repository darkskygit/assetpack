use std::io::{self, Read};

#[cfg(feature = "sealed-encryption")]
use zeroize::{Zeroize, Zeroizing};

use super::{DirectoryRecord, Header, checked_slice, invalid};
#[cfg(feature = "sealed-encryption")]
use super::{FrameUnsealer, MAX_ENCRYPTED_FRAME_BYTES, SealedRecordContext, frame_count};
use crate::Result;

pub(super) enum PayloadReader<'a> {
  Plain(io::Cursor<&'a [u8]>),
  #[cfg(feature = "sealed-encryption")]
  Encrypted(Box<EncryptedPayloadReader<'a>>),
}

impl<'a> PayloadReader<'a> {
  pub(super) fn new(
    bytes: &'a [u8],
    header: &Header,
    record: DirectoryRecord,
    #[cfg(feature = "sealed-encryption")] unsealer: Option<&'a dyn FrameUnsealer>,
  ) -> Result<Self> {
    if !header.encrypted() {
      return Ok(Self::Plain(io::Cursor::new(checked_slice(
        bytes,
        record.payload_offset,
        record.stored_length,
        "plain payload",
      )?)));
    }
    #[cfg(feature = "sealed-encryption")]
    {
      let unsealer = unsealer.ok_or_else(|| invalid("encrypted payload reader is locked"))?;
      Ok(Self::Encrypted(Box::new(EncryptedPayloadReader::new(
        bytes,
        header.clone(),
        record,
        unsealer,
      ))))
    }
    #[cfg(not(feature = "sealed-encryption"))]
    Err(invalid("encrypted payload support is not compiled"))
  }
}

impl Read for PayloadReader<'_> {
  fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
    match self {
      Self::Plain(reader) => reader.read(output),
      #[cfg(feature = "sealed-encryption")]
      Self::Encrypted(reader) => reader.read(output),
    }
  }
}

#[cfg(feature = "sealed-encryption")]
pub(super) struct EncryptedPayloadReader<'a> {
  bytes: &'a [u8],
  header: Header,
  record: DirectoryRecord,
  unsealer: &'a dyn FrameUnsealer,
  frame_index: u64,
  frame_count: u64,
  frame: Zeroizing<Vec<u8>>,
  frame_position: usize,
}

#[cfg(feature = "sealed-encryption")]
impl<'a> EncryptedPayloadReader<'a> {
  fn new(bytes: &'a [u8], header: Header, record: DirectoryRecord, unsealer: &'a dyn FrameUnsealer) -> Self {
    Self {
      bytes,
      frame_count: frame_count(record.stored_length),
      header,
      record,
      unsealer,
      frame_index: 0,
      frame: Zeroizing::new(Vec::new()),
      frame_position: 0,
    }
  }

  fn load_frame(&mut self) -> Result<bool> {
    if self.frame_index >= self.frame_count {
      return Ok(false);
    }
    self.frame.zeroize();
    self.frame.clear();
    let plaintext_offset = self.frame_index * MAX_ENCRYPTED_FRAME_BYTES as u64;
    let plaintext_length = (self.record.stored_length - plaintext_offset).min(MAX_ENCRYPTED_FRAME_BYTES as u64);
    let physical_offset = self
      .record
      .payload_offset
      .checked_add(plaintext_offset)
      .and_then(|value| value.checked_add(self.frame_index * 16))
      .ok_or_else(|| invalid("encrypted frame offset overflow"))?;
    let stored = checked_slice(self.bytes, physical_offset, plaintext_length + 16, "encrypted frame")?;
    let (ciphertext, tag) = stored.split_at(plaintext_length as usize);
    self.frame.extend_from_slice(ciphertext);
    let tag: &[u8; 16] = tag.try_into().map_err(|_| invalid("invalid encrypted frame tag"))?;
    let context = SealedRecordContext::frame(&self.header, &self.record, self.frame_index, self.frame_count, plaintext_length);
    self.unsealer.unseal_record(&context, &mut self.frame, tag)?;
    self.frame_position = 0;
    self.frame_index += 1;
    Ok(true)
  }
}

#[cfg(feature = "sealed-encryption")]
impl Read for EncryptedPayloadReader<'_> {
  fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
    if output.is_empty() {
      return Ok(0);
    }
    if self.frame_position == self.frame.len()
      && !self
        .load_frame()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
    {
      return Ok(0);
    }
    let available = &self.frame[self.frame_position..];
    let length = available.len().min(output.len());
    output[..length].copy_from_slice(&available[..length]);
    self.frame_position += length;
    Ok(length)
  }
}
