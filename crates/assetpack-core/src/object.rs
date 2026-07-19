use crate::{Result, codec::Codec, hash::Hash32};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ObjectKind {
  Chunk = 1,
  Recipe = 2,
}

impl ObjectKind {
  #[cfg(feature = "sqlite")]
  pub(crate) fn from_i64(value: i64) -> Option<Self> {
    Self::from_u8(value.try_into().ok()?)
  }

  #[cfg(any(feature = "sealed", feature = "sqlite"))]
  pub(crate) fn from_u8(value: u8) -> Option<Self> {
    match value {
      1 => Some(Self::Chunk),
      2 => Some(Self::Recipe),
      _ => None,
    }
  }
}

#[derive(Debug, Clone)]
pub struct VerifiedObject {
  pub hash: Hash32,
  pub kind: ObjectKind,
  pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ObjectRecord {
  pub hash: Hash32,
  pub kind: ObjectKind,
  pub decoded_len: u64,
  pub codec: Codec,
  pub stored_bytes: Vec<u8>,
}

#[allow(async_fn_in_trait)]
pub trait ObjectSource: Send + Sync {
  async fn read_object(&self, hash: &Hash32) -> Result<Option<VerifiedObject>>;
}
