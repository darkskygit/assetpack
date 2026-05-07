use std::{fmt, io::Read, str::FromStr};

use sha3::{Digest, Sha3_256};

use crate::error::{Error, Result};

pub const HASH_LEN: usize = 32;

#[derive(Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String", into = "String"))]
pub struct Hash32(pub [u8; HASH_LEN]);

impl Hash32 {
  pub fn new(bytes: [u8; HASH_LEN]) -> Self {
    Self(bytes)
  }

  pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
    if bytes.len() != HASH_LEN {
      return Err(Error::InvalidHashLength(bytes.len()));
    }
    let mut arr = [0u8; HASH_LEN];
    arr.copy_from_slice(bytes);
    Ok(Self(arr))
  }

  pub fn sha3_256(data: impl AsRef<[u8]>) -> Self {
    let mut hasher = Sha3_256::new();
    hasher.update(data.as_ref());
    let digest = hasher.finalize();
    Hash32::new(digest.into())
  }

  pub fn sha3_256_reader(mut reader: impl Read) -> Result<Self> {
    let mut hasher = Sha3_256::new();
    let mut buf = [0u8; 8192];
    loop {
      let n = reader.read(&mut buf)?;
      if n == 0 {
        break;
      }
      hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    Ok(Hash32::new(digest.into()))
  }

  pub fn to_hex(&self) -> String {
    hex::encode(self.0)
  }

  pub fn from_hex(s: &str) -> Result<Self> {
    let bytes = hex::decode(s).map_err(|_| Error::InvalidHex(s.to_string()))?;
    Self::from_bytes(&bytes)
  }

  pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
    &self.0
  }
}

impl fmt::Display for Hash32 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.to_hex())
  }
}

impl fmt::Debug for Hash32 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "Hash32({})", self.to_hex())
  }
}

impl FromStr for Hash32 {
  type Err = Error;

  fn from_str(s: &str) -> Result<Self> {
    Hash32::from_hex(s)
  }
}

#[cfg(feature = "serde")]
impl From<Hash32> for String {
  fn from(value: Hash32) -> Self {
    value.to_hex()
  }
}

#[cfg(feature = "serde")]
impl TryFrom<String> for Hash32 {
  type Error = Error;

  fn try_from(value: String) -> Result<Self> {
    Hash32::from_hex(&value)
  }
}

#[cfg(test)]
mod tests {
  use rand::RngCore;

  use super::*;

  #[test]
  fn sha3_known_value() {
    let hash = Hash32::sha3_256("hello");
    assert_eq!(hash.to_hex(), "3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392");
  }

  #[test]
  fn from_hex_roundtrip() {
    let mut bytes = [0u8; HASH_LEN];
    rand::rng().fill_bytes(&mut bytes);
    let h = Hash32::new(bytes);
    let encoded = h.to_hex();
    let decoded = Hash32::from_hex(&encoded).unwrap();
    assert_eq!(decoded, h);
  }

  #[test]
  fn invalid_hex_rejected() {
    let err = Hash32::from_hex("abcd").unwrap_err();
    assert!(matches!(err, Error::InvalidHashLength(2)));
    let err2 = Hash32::from_hex(&"zz".repeat(32)).unwrap_err();
    assert!(matches!(err2, Error::InvalidHex(_)));
  }

  #[test]
  fn odd_length_hex_is_rejected() {
    let err = Hash32::from_hex("abc").unwrap_err();
    assert!(matches!(err, Error::InvalidHex(_)));
  }

  #[test]
  fn from_bytes_rejects_wrong_length() {
    let err = Hash32::from_bytes(&[0u8; HASH_LEN - 1]).unwrap_err();
    assert!(matches!(err, Error::InvalidHashLength(_)));
  }

  #[test]
  fn reader_digest_matches() {
    let data = vec![42u8; 1024];
    let expected = Hash32::sha3_256(&data);
    let via_reader = Hash32::sha3_256_reader(&data[..]).unwrap();
    assert_eq!(expected, via_reader);
  }
}
