mod builder;
#[cfg(feature = "sealed-encryption")]
mod crypto;
mod index;
mod payload;
mod reader;
#[cfg(test)]
mod tests;

#[cfg(feature = "sealed-encryption")]
use builder::{build_encrypted_bytes, reseal_plain_as_encrypted_bytes};
use builder::{build_plain_bytes, validated_objects};
#[cfg(feature = "sealed-encryption")]
pub use crypto::{FrameSealer, FrameUnsealer, SealedRecordContext, SoftwareFrameKey};
pub(in crate::sealed) use payload::PayloadReader;
pub use reader::SealedPackReader;
use sha3::{Digest, Sha3_256};
#[cfg(feature = "sealed-encryption")]
use zeroize::Zeroizing;

use crate::{
  codec::Codec,
  error::{Error, Result},
  hash::Hash32,
  object::{ObjectKind, ObjectRecord},
};

pub const HEADER_BYTES: usize = 140;
pub const DIRECTORY_RECORD_BYTES: usize = 50;
pub const MAX_ENCRYPTED_FRAME_BYTES: usize = 256 * 1024;
pub const DEFAULT_FORMAT_TAG: SealedPackTag = SealedPackTag(*b"aspk.sealed.v1!!");

const FORMAT_REVISION: u16 = 1;
const CRYPTO_PLAIN_SHA3: u16 = 0;
const CRYPTO_CHACHA20_POLY1305_FRAMES: u16 = 1;
const MAX_OBJECT_COUNT: u64 = 1_000_000;
const MAX_INDEX_DECODED_BYTES: usize = 8 * 1024 * 1024;
const MAX_INDEX_COMPRESSED_BYTES: usize = 3 * 1024 * 1024;
const MAX_DECODED_OBJECT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_STORED_OBJECT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SealedPackTag(pub [u8; 16]);

impl SealedPackTag {
  pub const fn new(bytes: [u8; 16]) -> Self {
    Self(bytes)
  }

  pub const fn as_bytes(&self) -> &[u8; 16] {
    &self.0
  }
}

impl std::fmt::Debug for SealedPackTag {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter.debug_tuple("SealedPackTag").field(&hex::encode(self.0)).finish()
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackOpenPolicy {
  PlainAllowed,
  EncryptedRequired,
}

#[derive(Clone)]
pub(super) struct DirectoryRecord {
  pub hash: Hash32,
  pub kind: ObjectKind,
  pub codec: Codec,
  pub decoded_length: u64,
  pub stored_length: u64,
  pub payload_offset: u64,
}

#[derive(Clone)]
pub(super) struct Header {
  pub tag: SealedPackTag,
  pub crypto_suite: u16,
  pub index_stored_length: u64,
  pub pack_id: Hash32,
  pub pack_salt: [u8; 32],
  pub key_slot: [u8; 16],
  pub index_digest: Hash32,
}

impl Header {
  pub(super) fn encrypted(&self) -> bool {
    self.crypto_suite == CRYPTO_CHACHA20_POLY1305_FRAMES
  }

  pub(super) fn encode_without_digest(&self) -> [u8; 108] {
    let mut bytes = [0_u8; 108];
    bytes[..16].copy_from_slice(self.tag.as_bytes());
    bytes[16..18].copy_from_slice(&FORMAT_REVISION.to_le_bytes());
    bytes[18..20].copy_from_slice(&self.crypto_suite.to_le_bytes());
    bytes[20..28].copy_from_slice(&self.index_stored_length.to_le_bytes());
    bytes[28..60].copy_from_slice(self.pack_id.as_bytes());
    bytes[60..92].copy_from_slice(&self.pack_salt);
    bytes[92..108].copy_from_slice(&self.key_slot);
    bytes
  }

  fn encode(&self) -> [u8; HEADER_BYTES] {
    let mut bytes = [0_u8; HEADER_BYTES];
    bytes[..108].copy_from_slice(&self.encode_without_digest());
    bytes[108..].copy_from_slice(self.index_digest.as_bytes());
    bytes
  }
}

pub struct SealedPackBuilder;

impl SealedPackBuilder {
  pub fn build_plain(tag: SealedPackTag, root_recipe: Hash32, objects: impl IntoIterator<Item = ObjectRecord>) -> Result<Vec<u8>> {
    let objects = validated_objects(root_recipe, objects)?;
    build_plain_bytes(tag, root_recipe, objects)
  }

  #[cfg(feature = "sealed-encryption")]
  pub fn build_encrypted(
    tag: SealedPackTag,
    root_recipe: Hash32,
    objects: impl IntoIterator<Item = ObjectRecord>,
    sealer: &dyn FrameSealer,
  ) -> Result<Vec<u8>> {
    if tag == DEFAULT_FORMAT_TAG {
      return Err(invalid("encrypted packs require a product-specific tag"));
    }
    let objects = validated_objects(root_recipe, objects)?;
    build_encrypted_bytes(tag, root_recipe, objects, sealer)
  }

  #[cfg(feature = "sealed-encryption")]
  pub fn reseal_plain_as_encrypted(
    source: &[u8],
    source_tag: SealedPackTag,
    target_tag: SealedPackTag,
    sealer: &dyn FrameSealer,
  ) -> Result<Vec<u8>> {
    if target_tag == DEFAULT_FORMAT_TAG {
      return Err(invalid("encrypted packs require a product-specific tag"));
    }
    let reader = ParsedSealedPack::open(source, source_tag, PackOpenPolicy::PlainAllowed)?.open_plain()?;
    reseal_plain_as_encrypted_bytes(source, reader.root_recipe(), reader.records, target_tag, sealer)
  }
}

pub struct ParsedSealedPack<'a> {
  pub(super) bytes: &'a [u8],
  pub(super) header: Header,
}

impl<'a> ParsedSealedPack<'a> {
  pub fn open(bytes: &'a [u8], expected_tag: SealedPackTag, policy: PackOpenPolicy) -> Result<Self> {
    if bytes.len() < HEADER_BYTES {
      return Err(invalid("truncated outer header"));
    }
    if !constant_time_eq(&bytes[..16], expected_tag.as_bytes()) {
      return Err(invalid("format tag mismatch"));
    }
    let header = parse_header(bytes, expected_tag)?;
    if policy == PackOpenPolicy::EncryptedRequired {
      if !header.encrypted() {
        return Err(invalid("encrypted pack required"));
      }
      if expected_tag == DEFAULT_FORMAT_TAG {
        return Err(invalid("protected open rejects DEFAULT_FORMAT_TAG"));
      }
    }
    Ok(Self { bytes, header })
  }

  pub fn pack_id(&self) -> Hash32 {
    self.header.pack_id
  }

  pub fn encrypted(&self) -> bool {
    self.header.encrypted()
  }

  pub fn open_plain(&self) -> Result<SealedPackReader<'a>> {
    if self.header.encrypted() {
      return Err(invalid("encrypted pack requires an unsealer"));
    }
    let index = self.index_bytes()?;
    if stored_index_digest(&self.header, index) != self.header.index_digest {
      return Err(invalid("stored index digest mismatch"));
    }
    let (root, records) = index::decode_index(&self.header, index, self.bytes.len())?;
    SealedPackReader::from_records(self.bytes, self.header.clone(), root, records, None)
  }

  #[cfg(feature = "sealed-encryption")]
  pub fn unlock<'u>(&self, unsealer: &'u dyn FrameUnsealer) -> Result<SealedPackReader<'u>>
  where
    'a: 'u,
  {
    if !self.header.encrypted() {
      return Err(invalid("plain pack must use open_plain"));
    }
    if !unsealer.accepts_key_slot(&self.header.key_slot) {
      return Err(Error::AuthenticationFailed);
    }
    let stored = self.index_bytes()?;
    if stored_index_digest(&self.header, stored) != self.header.index_digest {
      return Err(invalid("stored index digest mismatch"));
    }
    let split = stored
      .len()
      .checked_sub(16)
      .ok_or_else(|| invalid("encrypted index is missing its tag"))?;
    let (ciphertext, tag) = stored.split_at(split);
    let mut plaintext = Zeroizing::new(ciphertext.to_vec());
    let context = SealedRecordContext::index(&self.header);
    let tag: &[u8; 16] = tag.try_into().map_err(|_| invalid("invalid encrypted index tag"))?;
    unsealer.unseal_record(&context, &mut plaintext, tag)?;
    let (root, records) = index::decode_index(&self.header, &plaintext, self.bytes.len())?;
    drop(plaintext);
    SealedPackReader::from_records(self.bytes, self.header.clone(), root, records, Some(unsealer))
  }

  fn index_bytes(&self) -> Result<&'a [u8]> {
    checked_slice(self.bytes, HEADER_BYTES as u64, self.header.index_stored_length, "index")
  }
}

fn parse_header(bytes: &[u8], tag: SealedPackTag) -> Result<Header> {
  if read_u16(bytes, 16)? != FORMAT_REVISION {
    return Err(invalid("unsupported format revision"));
  }
  let crypto_suite = read_u16(bytes, 18)?;
  match crypto_suite {
    CRYPTO_PLAIN_SHA3 | CRYPTO_CHACHA20_POLY1305_FRAMES => {}
    _ => return Err(invalid("unknown crypto suite")),
  }
  let index_stored_length = read_u64(bytes, 20)?;
  let encrypted = crypto_suite == CRYPTO_CHACHA20_POLY1305_FRAMES;
  let compressed_length = index_stored_length
    .checked_sub(u64::from(encrypted) * 16)
    .ok_or_else(|| invalid("encrypted index is missing its tag"))?;
  if compressed_length > MAX_INDEX_COMPRESSED_BYTES as u64 {
    return Err(invalid("compressed index exceeds hard limit"));
  }
  checked_slice(bytes, HEADER_BYTES as u64, index_stored_length, "index")?;
  let mut pack_salt = [0; 32];
  pack_salt.copy_from_slice(&bytes[60..92]);
  let mut key_slot = [0; 16];
  key_slot.copy_from_slice(&bytes[92..108]);
  if !encrypted && (pack_salt.iter().any(|byte| *byte != 0) || key_slot.iter().any(|byte| *byte != 0)) {
    return Err(invalid("plain pack salt and key slot must be zero"));
  }
  Ok(Header {
    tag,
    crypto_suite,
    index_stored_length,
    pack_id: Hash32::from_bytes(&bytes[28..60])?,
    pack_salt,
    key_slot,
    index_digest: Hash32::from_bytes(&bytes[108..140])?,
  })
}

fn logical_pack_id_records(root_recipe: Hash32, records: &[DirectoryRecord]) -> Hash32 {
  let mut hasher = Sha3_256::new();
  hasher.update(b"assetpack.sealed.pack-id.v1\0");
  hasher.update(root_recipe.as_bytes());
  for record in records {
    hasher.update(record.hash.as_bytes());
    hasher.update([record.kind as u8]);
    hasher.update(record.decoded_length.to_le_bytes());
  }
  Hash32::new(hasher.finalize().into())
}

fn stored_index_digest(header: &Header, index: &[u8]) -> Hash32 {
  domain_hash(b"assetpack.sealed.index.stored.v1\0", &[&header.encode_without_digest(), index])
}

fn domain_hash(domain: &[u8], parts: &[&[u8]]) -> Hash32 {
  let mut hasher = Sha3_256::new();
  hasher.update(domain);
  for part in parts {
    hasher.update(part);
  }
  Hash32::new(hasher.finalize().into())
}

#[cfg(feature = "sealed-encryption")]
fn seal_payload(output: &mut Vec<u8>, header: &Header, record: &DirectoryRecord, plaintext: &[u8], sealer: &dyn FrameSealer) -> Result<()> {
  let count = frame_count(record.stored_length);
  for (index, frame) in plaintext.chunks(MAX_ENCRYPTED_FRAME_BYTES).enumerate() {
    let mut ciphertext = Zeroizing::new(frame.to_vec());
    let context = SealedRecordContext::frame(header, record, index as u64, count, frame.len() as u64);
    let tag = sealer.seal_record(&context, &mut ciphertext)?;
    output.extend_from_slice(&ciphertext);
    output.extend_from_slice(&tag);
  }
  Ok(())
}

pub(super) fn frame_count(stored_length: u64) -> u64 {
  stored_length.div_ceil(MAX_ENCRYPTED_FRAME_BYTES as u64)
}

pub(super) fn checked_slice<'a>(bytes: &'a [u8], offset: u64, length: u64, label: &str) -> Result<&'a [u8]> {
  let range = checked_range(bytes.len(), offset, length, label)?;
  Ok(&bytes[range])
}

pub(super) fn checked_range(pack_len: usize, offset: u64, length: u64, label: &str) -> Result<std::ops::Range<usize>> {
  let start: usize = offset
    .try_into()
    .map_err(|_| invalid(format!("{label} offset exceeds address space")))?;
  let len: usize = length
    .try_into()
    .map_err(|_| invalid(format!("{label} length exceeds address space")))?;
  let end = start.checked_add(len).ok_or_else(|| invalid(format!("{label} range overflow")))?;
  if end > pack_len {
    return Err(invalid(format!("{label} range exceeds pack")));
  }
  Ok(start..end)
}

fn codec_id(codec: Codec) -> u8 {
  match codec {
    Codec::Raw => 0,
    Codec::Zstd => 1,
    Codec::Brotli => 2,
  }
}

fn codec_from_id(value: u8) -> Result<Codec> {
  match value {
    0 => Ok(Codec::Raw),
    1 => Ok(Codec::Zstd),
    2 => Ok(Codec::Brotli),
    _ => Err(invalid("unknown object codec")),
  }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
  Ok(u16::from_le_bytes(
    bytes[offset..offset + 2].try_into().map_err(|_| invalid("truncated u16"))?,
  ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
  Ok(u64::from_le_bytes(
    bytes[offset..offset + 8].try_into().map_err(|_| invalid("truncated u64"))?,
  ))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
  left.len() == right.len()
    && left
      .iter()
      .zip(right)
      .fold(0_u8, |difference, (left, right)| difference | (left ^ right))
      == 0
}

pub(super) fn invalid(message: impl Into<String>) -> Error {
  Error::InvalidSealed(message.into())
}

#[cfg(test)]
mod header_tests {
  use super::*;

  #[test]
  fn compact_header_is_byte_exact() {
    assert_eq!(HEADER_BYTES, 140);
    let header = Header {
      tag: SealedPackTag(*b"0123456789abcdef"),
      crypto_suite: 0x1234,
      index_stored_length: 0x0102_0304_0506_0708,
      pack_id: Hash32::new([0x11; 32]),
      pack_salt: [0x22; 32],
      key_slot: [0x33; 16],
      index_digest: Hash32::new([0x44; 32]),
    };
    let mut expected = [0_u8; HEADER_BYTES];
    expected[..16].copy_from_slice(b"0123456789abcdef");
    expected[16..18].copy_from_slice(&1_u16.to_le_bytes());
    expected[18..20].copy_from_slice(&0x1234_u16.to_le_bytes());
    expected[20..28].copy_from_slice(&0x0102_0304_0506_0708_u64.to_le_bytes());
    expected[28..60].fill(0x11);
    expected[60..92].fill(0x22);
    expected[92..108].fill(0x33);
    expected[108..140].fill(0x44);
    assert_eq!(header.encode(), expected);
  }
}
