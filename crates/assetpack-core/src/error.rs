use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
  #[error(transparent)]
  Io(#[from] std::io::Error),
  #[cfg(feature = "sqlite")]
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
  #[error("object decoded length mismatch: expected {expected}, got {actual}")]
  ObjectLengthMismatch { expected: u64, actual: u64 },
  #[error("object hash mismatch: expected {expected}, got {actual}")]
  ObjectHashMismatch { expected: crate::Hash32, actual: crate::Hash32 },
  #[error("sqlite integrity_check failed: {0}")]
  Integrity(String),
  #[error("object not found")]
  ObjectNotFound,
  #[error("invalid config: {0}")]
  InvalidConfig(String),
  #[error("generic error: {0}")]
  Other(String),
  #[error("invalid sealed pack: {0}")]
  InvalidSealed(String),
  #[error("sealed pack authentication failed")]
  AuthenticationFailed,
  #[error("duplicate transform decoder {id} version {version}")]
  DuplicateTransformDecoder { id: u16, version: u16 },
  #[error("unsupported transform {id} version {version}")]
  UnsupportedTransform { id: u16, version: u16 },
  #[error("object {hash} has kind {actual:?}, expected {expected:?}")]
  ObjectKindMismatch {
    hash: crate::Hash32,
    expected: crate::ObjectKind,
    actual: crate::ObjectKind,
  },
  #[error("recipe chunk {hash} length mismatch: expected {expected}, got {actual}")]
  RecipeChunkLengthMismatch { hash: crate::Hash32, expected: u64, actual: u64 },
  #[error("invalid recipe: {0}")]
  InvalidRecipe(String),
  #[error("file read limit {limit} exceeded: maximum {maximum}, actual {actual}")]
  FileReadLimitExceeded { limit: &'static str, maximum: u64, actual: u64 },
  #[error("unable to allocate {requested} bytes for {buffer}")]
  FileReadAllocationFailed { buffer: &'static str, requested: u64 },
  #[error("original file mismatch")]
  OriginalFileMismatch {
    expected_size: u64,
    actual_size: u64,
    expected_hash: crate::Hash32,
    actual_hash: crate::Hash32,
  },
}

pub type Result<T> = std::result::Result<T, Error>;
