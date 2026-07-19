use chacha20poly1305::{AeadInOut, ChaCha20Poly1305, Key, KeyInit, Nonce, Tag};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use super::{DirectoryRecord, Header, codec_id, constant_time_eq};
use crate::error::{Error, Result};

pub trait FrameSealer: Send + Sync {
  fn key_slot(&self) -> [u8; 16];
  fn seal_record(&self, context: &SealedRecordContext, in_out: &mut [u8]) -> Result<[u8; 16]>;
}

pub trait FrameUnsealer: Send + Sync {
  fn accepts_key_slot(&self, key_slot: &[u8; 16]) -> bool;
  fn unseal_record(&self, context: &SealedRecordContext, in_out: &mut [u8], tag: &[u8; 16]) -> Result<()>;
}

pub struct SealedRecordContext {
  pack_salt: [u8; 32],
  key_slot: [u8; 16],
  kdf_info: Vec<u8>,
  aad: Vec<u8>,
}

impl SealedRecordContext {
  pub fn pack_salt(&self) -> &[u8; 32] {
    &self.pack_salt
  }

  pub fn key_slot(&self) -> &[u8; 16] {
    &self.key_slot
  }

  pub fn kdf_info(&self) -> &[u8] {
    &self.kdf_info
  }

  pub fn aad(&self) -> &[u8] {
    &self.aad
  }

  pub(super) fn index(header: &Header) -> Self {
    let semantic_header = header.encode_without_digest();
    let mut kdf_info = Vec::with_capacity(26 + semantic_header.len());
    kdf_info.extend_from_slice(b"assetpack.sealed.index.v1\0");
    kdf_info.extend_from_slice(&semantic_header);
    Self {
      pack_salt: header.pack_salt,
      key_slot: header.key_slot,
      kdf_info,
      aad: semantic_header.to_vec(),
    }
  }

  pub(super) fn frame(header: &Header, record: &DirectoryRecord, frame_index: u64, frame_count: u64, plaintext_length: u64) -> Self {
    let mut fields = Vec::with_capacity(16 + 2 + 32 + 32 + 2 + 8 * 5);
    fields.extend_from_slice(header.tag.as_bytes());
    fields.extend_from_slice(&1_u16.to_le_bytes());
    fields.extend_from_slice(header.pack_id.as_bytes());
    fields.extend_from_slice(record.hash.as_bytes());
    fields.push(record.kind as u8);
    fields.push(codec_id(record.codec));
    fields.extend_from_slice(&record.decoded_length.to_le_bytes());
    fields.extend_from_slice(&record.stored_length.to_le_bytes());
    fields.extend_from_slice(&frame_index.to_le_bytes());
    fields.extend_from_slice(&frame_count.to_le_bytes());
    let mut kdf_info = Vec::with_capacity(27 + fields.len());
    kdf_info.extend_from_slice(b"assetpack.sealed.frame.v1\0");
    kdf_info.extend_from_slice(&fields);
    fields.extend_from_slice(&plaintext_length.to_le_bytes());
    Self {
      pack_salt: header.pack_salt,
      key_slot: header.key_slot,
      kdf_info,
      aad: fields,
    }
  }
}

pub struct SoftwareFrameKey {
  secret: Zeroizing<[u8; 32]>,
  key_slot: [u8; 16],
}

impl SoftwareFrameKey {
  pub fn new(secret: [u8; 32], key_slot: [u8; 16]) -> Self {
    Self {
      secret: Zeroizing::new(secret),
      key_slot,
    }
  }

  fn material(&self, context: &SealedRecordContext) -> Result<Zeroizing<[u8; 44]>> {
    if context.key_slot != self.key_slot {
      return Err(Error::AuthenticationFailed);
    }
    let hkdf = Hkdf::<Sha256>::new(Some(context.pack_salt()), self.secret.as_ref());
    let mut material = Zeroizing::new([0_u8; 44]);
    hkdf
      .expand(context.kdf_info(), material.as_mut())
      .map_err(|_| Error::AuthenticationFailed)?;
    Ok(material)
  }
}

impl FrameSealer for SoftwareFrameKey {
  fn key_slot(&self) -> [u8; 16] {
    self.key_slot
  }

  fn seal_record(&self, context: &SealedRecordContext, in_out: &mut [u8]) -> Result<[u8; 16]> {
    let result = (|| {
      let material = self.material(context)?;
      let key = Key::try_from(&material[..32]).expect("derived key has fixed length");
      let nonce = Nonce::try_from(&material[32..44]).expect("derived nonce has fixed length");
      let cipher = ChaCha20Poly1305::new(&key);
      let tag = cipher
        .encrypt_inout_detached(&nonce, context.aad(), in_out.into())
        .map_err(|_| Error::AuthenticationFailed)?;
      Ok(tag.into())
    })();
    if result.is_err() {
      in_out.zeroize();
    }
    result
  }
}

impl FrameUnsealer for SoftwareFrameKey {
  fn accepts_key_slot(&self, key_slot: &[u8; 16]) -> bool {
    constant_time_eq(key_slot, &self.key_slot)
  }

  fn unseal_record(&self, context: &SealedRecordContext, in_out: &mut [u8], tag: &[u8; 16]) -> Result<()> {
    let result = (|| {
      let material = self.material(context)?;
      let key = Key::try_from(&material[..32]).expect("derived key has fixed length");
      let nonce = Nonce::try_from(&material[32..44]).expect("derived nonce has fixed length");
      let tag = Tag::from(*tag);
      let cipher = ChaCha20Poly1305::new(&key);
      cipher
        .decrypt_inout_detached(&nonce, context.aad(), in_out.into(), &tag)
        .map_err(|_| Error::AuthenticationFailed)
    })();
    if result.is_err() {
      in_out.zeroize();
    }
    result
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn rfc8439_aead_vector() {
    let key = hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
    let nonce = hex::decode("070000004041424344454647").unwrap();
    let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
    let mut plaintext = hex::decode(
      "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
    )
    .unwrap();
    let expected = hex::decode(
      "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
    )
    .unwrap();
    let key = Key::try_from(key.as_slice()).unwrap();
    let nonce = Nonce::try_from(nonce.as_slice()).unwrap();
    let cipher = ChaCha20Poly1305::new(&key);
    let tag = cipher
      .encrypt_inout_detached(&nonce, &aad, plaintext.as_mut_slice().into())
      .unwrap();
    assert_eq!(plaintext, expected);
    assert_eq!(tag.as_slice(), &hex::decode("1ae10b594f09e26a7e902ecbd0600691").unwrap());
  }
}
