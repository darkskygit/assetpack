use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
  #[error(transparent)]
  Io(#[from] std::io::Error),
  #[error(transparent)]
  Sql(#[from] sqlx::Error),
  #[error("invalid hash length: {0}, expected 32 bytes")]
  InvalidHashLength(usize),
  #[error("invalid hex encoding: {0}")]
  InvalidHex(String),
  #[error("invalid fastcdc parameters")]
  InvalidCdcParams,
  #[error("compress failed: {0}")]
  Compress(String),
  #[error("decompress failed: {0}")]
  Decompress(String),
  #[error("invalid codec value {0}")]
  InvalidCodec(String),
  #[error("merkle meta missing {0}")]
  MissingMeta(String),
  #[error("hash mismatch when writing object")]
  HashMismatch,
  #[error("sqlite integrity_check failed: {0}")]
  Integrity(String),
  #[error("object not found")]
  ObjectNotFound,
  #[error("invalid config: {0}")]
  InvalidConfig(String),
  #[error("generic error: {0}")]
  Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
