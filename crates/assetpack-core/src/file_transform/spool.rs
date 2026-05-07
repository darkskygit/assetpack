use std::{
  fs,
  io::{self, Cursor, Read, Seek, SeekFrom, Write},
  path::Path,
};

use crate::error::{Error, Result};

#[derive(Debug)]
pub enum StoredStreamSpool {
  Memory { buffer: Vec<u8>, max_bytes: u64 },
  File { file: tempfile::NamedTempFile, len: u64 },
}

impl StoredStreamSpool {
  pub fn from_bytes(buffer: Vec<u8>) -> Self {
    let max_bytes = buffer.len().max(1) as u64;
    Self::Memory { buffer, max_bytes }
  }

  pub fn new_memory(max_bytes: u64) -> Self {
    Self::Memory {
      buffer: Vec::new(),
      max_bytes: max_bytes.max(1),
    }
  }

  pub fn new_file(temp_dir: Option<&Path>) -> Result<Self> {
    let file = if let Some(dir) = temp_dir {
      fs::create_dir_all(dir)?;
      tempfile::Builder::new()
        .prefix("assetpack-transform-precomp2-")
        .tempfile_in(dir)
        .map_err(Error::Io)?
    } else {
      tempfile::Builder::new()
        .prefix("assetpack-transform-precomp2-")
        .tempfile()
        .map_err(Error::Io)?
    };
    Ok(Self::File { file, len: 0 })
  }

  pub fn len(&self) -> u64 {
    match self {
      StoredStreamSpool::Memory { buffer, .. } => buffer.len() as u64,
      StoredStreamSpool::File { len, .. } => *len,
    }
  }

  pub fn is_empty(&self) -> bool {
    self.len() == 0
  }

  pub fn as_slice(&self) -> Option<&[u8]> {
    match self {
      StoredStreamSpool::Memory { buffer, .. } => Some(buffer.as_slice()),
      StoredStreamSpool::File { .. } => None,
    }
  }

  pub fn reader(&self) -> Result<StoredStreamReader<'_>> {
    match self {
      StoredStreamSpool::Memory { buffer, .. } => Ok(StoredStreamReader::Memory(Cursor::new(buffer.as_slice()))),
      StoredStreamSpool::File { file, .. } => Ok(StoredStreamReader::File(file.reopen()?)),
    }
  }

  pub fn into_bytes(self) -> Result<Vec<u8>> {
    match self {
      StoredStreamSpool::Memory { buffer, .. } => Ok(buffer),
      StoredStreamSpool::File { mut file, .. } => {
        let mut buf = Vec::new();
        file.rewind()?;
        file.read_to_end(&mut buf)?;
        Ok(buf)
      }
    }
  }
}

impl Write for StoredStreamSpool {
  fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
    match self {
      StoredStreamSpool::Memory { buffer, max_bytes } => {
        let next_len = buffer.len().saturating_add(buf.len());
        if next_len as u64 > *max_bytes {
          return Err(io::Error::new(io::ErrorKind::OutOfMemory, "stored stream exceeded memory limit"));
        }
        buffer.extend_from_slice(buf);
        Ok(buf.len())
      }
      StoredStreamSpool::File { file, len } => {
        file.as_file_mut().write_all(buf)?;
        *len += buf.len() as u64;
        Ok(buf.len())
      }
    }
  }

  fn flush(&mut self) -> io::Result<()> {
    match self {
      StoredStreamSpool::Memory { .. } => Ok(()),
      StoredStreamSpool::File { file, .. } => file.as_file_mut().flush(),
    }
  }
}

pub enum StoredStreamReader<'a> {
  Memory(Cursor<&'a [u8]>),
  File(std::fs::File),
}

impl Read for StoredStreamReader<'_> {
  fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
    match self {
      StoredStreamReader::Memory(cursor) => cursor.read(buf),
      StoredStreamReader::File(file) => file.read(buf),
    }
  }
}

impl Seek for StoredStreamReader<'_> {
  fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
    match self {
      StoredStreamReader::Memory(cursor) => cursor.seek(pos),
      StoredStreamReader::File(file) => file.seek(pos),
    }
  }
}
