use std::collections::BTreeMap;

#[cfg(feature = "sealed-encryption")]
use zeroize::Zeroizing;

use super::{
  CRYPTO_CHACHA20_POLY1305_FRAMES, CRYPTO_PLAIN_SHA3, DirectoryRecord, Header, MAX_DECODED_OBJECT_BYTES, MAX_OBJECT_COUNT,
  MAX_STORED_OBJECT_BYTES, SealedPackTag, index, invalid, logical_pack_id_records, stored_index_digest,
};
#[cfg(feature = "sealed-encryption")]
use super::{FrameSealer, SealedRecordContext, checked_slice, seal_payload};
use crate::{
  codec::decompress,
  error::{Error, Result},
  hash::Hash32,
  object::{ObjectKind, ObjectRecord},
  recipe::parse_recipe,
};

pub(super) fn build_plain_bytes(tag: SealedPackTag, root_recipe: Hash32, objects: Vec<ObjectRecord>) -> Result<Vec<u8>> {
  let records = records(&objects);
  let index = index::compress_index(&index::encode_decoded_index(root_recipe, &records))?;
  let mut header = header(
    tag,
    logical_pack_id_records(root_recipe, &records),
    false,
    [0; 32],
    [0; 16],
    index.len(),
  )?;
  header.index_digest = stored_index_digest(&header, &index);
  let mut output = header.encode().to_vec();
  output.extend_from_slice(&index);
  for object in &objects {
    output.extend_from_slice(&object.stored_bytes);
  }
  Ok(output)
}

#[cfg(feature = "sealed-encryption")]
pub(super) fn build_encrypted_bytes(
  tag: SealedPackTag,
  root_recipe: Hash32,
  objects: Vec<ObjectRecord>,
  sealer: &dyn FrameSealer,
) -> Result<Vec<u8>> {
  let records = records(&objects);
  let (header, index) = sealed_header_and_index(tag, root_recipe, &records, sealer)?;
  let mut output = header.encode().to_vec();
  output.extend_from_slice(&index);
  for (object, record) in objects.iter().zip(&records) {
    seal_payload(&mut output, &header, record, &object.stored_bytes, sealer)?;
  }
  Ok(output)
}

#[cfg(feature = "sealed-encryption")]
pub(super) fn reseal_plain_as_encrypted_bytes(
  source: &[u8],
  root_recipe: Hash32,
  records: Vec<DirectoryRecord>,
  target_tag: SealedPackTag,
  sealer: &dyn FrameSealer,
) -> Result<Vec<u8>> {
  let (header, index) = sealed_header_and_index(target_tag, root_recipe, &records, sealer)?;
  let mut output = header.encode().to_vec();
  output.extend_from_slice(&index);
  for record in &records {
    let stored = checked_slice(source, record.payload_offset, record.stored_length, "plain payload")?;
    seal_payload(&mut output, &header, record, stored, sealer)?;
  }
  Ok(output)
}

#[cfg(feature = "sealed-encryption")]
fn sealed_header_and_index(
  tag: SealedPackTag,
  root_recipe: Hash32,
  records: &[DirectoryRecord],
  sealer: &dyn FrameSealer,
) -> Result<(Header, Zeroizing<Vec<u8>>)> {
  let mut pack_salt = [0_u8; 32];
  getrandom::fill(&mut pack_salt).map_err(|error| Error::Other(error.to_string()))?;
  let mut index = Zeroizing::new(index::compress_index(&index::encode_decoded_index(root_recipe, records))?);
  let mut header = header(
    tag,
    logical_pack_id_records(root_recipe, records),
    true,
    pack_salt,
    sealer.key_slot(),
    index.len() + 16,
  )?;
  let context = SealedRecordContext::index(&header);
  let index_tag = sealer.seal_record(&context, &mut index)?;
  index.extend_from_slice(&index_tag);
  header.index_digest = stored_index_digest(&header, &index);
  Ok((header, index))
}

fn header(
  tag: SealedPackTag,
  pack_id: Hash32,
  encrypted: bool,
  pack_salt: [u8; 32],
  key_slot: [u8; 16],
  index_stored_length: usize,
) -> Result<Header> {
  Ok(Header {
    tag,
    crypto_suite: if encrypted {
      CRYPTO_CHACHA20_POLY1305_FRAMES
    } else {
      CRYPTO_PLAIN_SHA3
    },
    index_stored_length: index_stored_length.try_into().map_err(|_| invalid("index length exceeds u64"))?,
    pack_id,
    pack_salt,
    key_slot,
    index_digest: Hash32::new([0; 32]),
  })
}

fn records(objects: &[ObjectRecord]) -> Vec<DirectoryRecord> {
  objects
    .iter()
    .map(|object| DirectoryRecord {
      hash: object.hash,
      kind: object.kind,
      codec: object.codec,
      decoded_length: object.decoded_len,
      stored_length: object.stored_bytes.len() as u64,
      payload_offset: 0,
    })
    .collect()
}

pub(super) fn validated_objects(root_recipe: Hash32, objects: impl IntoIterator<Item = ObjectRecord>) -> Result<Vec<ObjectRecord>> {
  let mut by_hash = BTreeMap::new();
  for object in objects {
    if object.decoded_len > MAX_DECODED_OBJECT_BYTES || object.stored_bytes.len() as u64 > MAX_STORED_OBJECT_BYTES {
      return Err(invalid("object exceeds hard limit"));
    }
    let decoded = decompress(object.codec, &object.stored_bytes)?;
    if decoded.len() as u64 != object.decoded_len || Hash32::sha3_256(&decoded) != object.hash {
      return Err(Error::HashMismatch);
    }
    if by_hash.insert(object.hash, object).is_some() {
      return Err(invalid("duplicate object hash"));
    }
  }
  if by_hash.len() as u64 > MAX_OBJECT_COUNT {
    return Err(invalid("object count exceeds hard limit"));
  }
  let root = by_hash.get(&root_recipe).ok_or_else(|| invalid("root recipe is missing"))?;
  if root.kind != ObjectKind::Recipe {
    return Err(invalid("root object is not a recipe"));
  }
  for object in by_hash.values().filter(|object| object.kind == ObjectKind::Recipe) {
    let decoded = decompress(object.codec, &object.stored_bytes)?;
    let recipe = parse_recipe(&decoded)?;
    for (chunk_hash, chunk_length) in recipe.chunks {
      let chunk = by_hash
        .get(&chunk_hash)
        .ok_or_else(|| invalid("recipe references a missing chunk"))?;
      if chunk.kind != ObjectKind::Chunk || chunk.decoded_len != u64::from(chunk_length) {
        return Err(invalid("recipe chunk kind or length mismatch"));
      }
    }
  }
  Ok(by_hash.into_values().collect())
}
