use crate::{
  error::{Error, Result},
  hash::Hash32,
};

pub const RECIPE_VERSION_V1: u8 = 1;
pub const RECIPE_VERSION_V2: u8 = 2;
pub const RECIPE_VERSION_V3: u8 = 3;

type RecipeChunkList = Vec<(Hash32, u32)>;
type ParsedChunks = (RecipeChunkList, u64, usize);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipeData {
  pub version: u8,
  pub original_file_size: u64,
  pub original_file_hash: Hash32,
  pub transform_id: u16,
  pub transform_version: u16,
  pub chunks: RecipeChunkList,
  pub stored_stream_size: u64,
}

pub fn build_recipe(
  original_file_size: u64,
  chunks: &[(Hash32, u32)],
  original_file_hash: Hash32,
  transform_id: u16,
  transform_version: u16,
) -> Vec<u8> {
  let mut buf = Vec::with_capacity(1 + 8 + 32 + 2 + 2 + 4 + chunks.len() * (32 + 4));
  buf.push(RECIPE_VERSION_V3);
  buf.extend_from_slice(&original_file_size.to_le_bytes());
  buf.extend_from_slice(original_file_hash.as_bytes());
  buf.extend_from_slice(&transform_id.to_le_bytes());
  buf.extend_from_slice(&transform_version.to_le_bytes());
  buf.extend_from_slice(&(chunks.len() as u32).to_le_bytes());
  for (hash, len) in chunks {
    buf.extend_from_slice(hash.as_bytes());
    buf.extend_from_slice(&len.to_le_bytes());
  }
  buf
}

pub fn parse_recipe(bytes: &[u8]) -> Result<RecipeData> {
  if bytes.is_empty() {
    return Err(Error::Other("empty recipe".into()));
  }

  let version = bytes[0];
  let offset = 1;
  match version {
    RECIPE_VERSION_V1 | RECIPE_VERSION_V2 => parse_recipe_v1(bytes, offset, version),
    RECIPE_VERSION_V3 => parse_recipe_v3(bytes, offset, version),
    _ => Err(Error::Other(format!("unexpected recipe version {version}"))),
  }
}

pub fn parse_recipe_checked(bytes: &[u8], expected_hash: &Hash32) -> Result<RecipeData> {
  if Hash32::sha3_256(bytes) != *expected_hash {
    return Err(Error::Other(format!("recipe hash mismatch for {expected_hash}")));
  }
  parse_recipe(bytes)
}

pub(crate) fn preflight_recipe_limits(bytes: &[u8]) -> Result<(u64, u32)> {
  let version = *bytes.first().ok_or_else(|| Error::Other("empty recipe".into()))?;
  let original_file_size = u64::from_le_bytes(
    bytes
      .get(1..9)
      .ok_or_else(|| Error::Other("recipe too short".into()))?
      .try_into()
      .expect("the slice length is fixed"),
  );
  let chunk_count_offset = match version {
    RECIPE_VERSION_V1 | RECIPE_VERSION_V2 => 9,
    RECIPE_VERSION_V3 => 45,
    _ => return Err(Error::Other(format!("unexpected recipe version {version}"))),
  };
  let chunk_count = u32::from_le_bytes(
    bytes
      .get(chunk_count_offset..chunk_count_offset + 4)
      .ok_or_else(|| Error::Other("recipe too short".into()))?
      .try_into()
      .expect("the slice length is fixed"),
  );
  Ok((original_file_size, chunk_count))
}

fn parse_recipe_v1(bytes: &[u8], mut offset: usize, version: u8) -> Result<RecipeData> {
  if bytes.len() < offset + 8 + 4 + 32 {
    return Err(Error::Other("recipe too short".into()));
  }

  let original_file_size = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
  offset += 8;
  let chunk_count = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
  offset += 4;
  let (chunks, stored_stream_size, mut offset) = parse_chunks(bytes, offset, chunk_count)?;
  if bytes.len() < offset + 32 {
    return Err(Error::Other("recipe missing file hash".into()));
  }
  let original_file_hash = Hash32::from_bytes(&bytes[offset..offset + 32])?;
  offset += 32;
  if offset != bytes.len() {
    return Err(Error::Other("recipe has trailing bytes".into()));
  }

  Ok(RecipeData {
    version,
    original_file_size,
    original_file_hash,
    transform_id: 0,
    transform_version: 0,
    chunks,
    stored_stream_size,
  })
}

fn parse_recipe_v3(bytes: &[u8], mut offset: usize, version: u8) -> Result<RecipeData> {
  if bytes.len() < offset + 8 + 32 + 2 + 2 + 4 {
    return Err(Error::Other("recipe too short".into()));
  }

  let original_file_size = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
  offset += 8;
  let original_file_hash = Hash32::from_bytes(&bytes[offset..offset + 32])?;
  offset += 32;
  let transform_id = u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap());
  offset += 2;
  let transform_version = u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap());
  offset += 2;
  let chunk_count = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
  offset += 4;
  let (chunks, stored_stream_size, offset) = parse_chunks(bytes, offset, chunk_count)?;
  if offset != bytes.len() {
    return Err(Error::Other("recipe has trailing bytes".into()));
  }

  Ok(RecipeData {
    version,
    original_file_size,
    original_file_hash,
    transform_id,
    transform_version,
    chunks,
    stored_stream_size,
  })
}

fn parse_chunks(bytes: &[u8], mut offset: usize, chunk_count: u32) -> Result<ParsedChunks> {
  let mut chunks = Vec::with_capacity(chunk_count as usize);
  let mut total = 0u64;
  for _ in 0..chunk_count {
    if bytes.len() < offset + 32 + 4 {
      return Err(Error::Other("recipe truncated".into()));
    }
    let hash = Hash32::from_bytes(&bytes[offset..offset + 32])?;
    offset += 32;
    let len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    offset += 4;
    total += len as u64;
    chunks.push((hash, len));
  }
  Ok((chunks, total, offset))
}

#[cfg(test)]
mod tests {
  use super::*;

  fn build_recipe_v1(file_size: u64, chunks: &[(Hash32, u32)], file_hash: Hash32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 8 + 4 + chunks.len() * (32 + 4) + 32);
    buf.push(RECIPE_VERSION_V1);
    buf.extend_from_slice(&file_size.to_le_bytes());
    buf.extend_from_slice(&(chunks.len() as u32).to_le_bytes());
    for (hash, len) in chunks {
      buf.extend_from_slice(hash.as_bytes());
      buf.extend_from_slice(&len.to_le_bytes());
    }
    buf.extend_from_slice(file_hash.as_bytes());
    buf
  }

  #[test]
  fn recipe_v3_roundtrip_preserves_transform_metadata() {
    let chunk_a = Hash32::sha3_256(b"chunk-a");
    let chunk_b = Hash32::sha3_256(b"chunk-b");
    let file_hash = Hash32::sha3_256(b"file");
    let bytes = build_recipe(42, &[(chunk_a, 5), (chunk_b, 7)], file_hash, 9, 3);

    let parsed = parse_recipe(&bytes).unwrap();
    assert_eq!(parsed.version, RECIPE_VERSION_V3);
    assert_eq!(parsed.original_file_size, 42);
    assert_eq!(parsed.original_file_hash, file_hash);
    assert_eq!(parsed.transform_id, 9);
    assert_eq!(parsed.transform_version, 3);
    assert_eq!(parsed.chunks, vec![(chunk_a, 5), (chunk_b, 7)]);
    assert_eq!(parsed.stored_stream_size, 12);
  }

  #[test]
  fn recipe_v1_roundtrip_uses_legacy_shape() {
    let chunk = Hash32::sha3_256(b"legacy-chunk");
    let file_hash = Hash32::sha3_256(b"legacy-file");
    let bytes = build_recipe_v1(11, &[(chunk, 11)], file_hash);

    let parsed = parse_recipe(&bytes).unwrap();
    assert_eq!(parsed.version, RECIPE_VERSION_V1);
    assert_eq!(parsed.original_file_size, 11);
    assert_eq!(parsed.original_file_hash, file_hash);
    assert_eq!(parsed.transform_id, 0);
    assert_eq!(parsed.transform_version, 0);
    assert_eq!(parsed.chunks, vec![(chunk, 11)]);
    assert_eq!(parsed.stored_stream_size, 11);
  }

  #[test]
  fn recipe_hash_is_checked_before_parse() {
    let chunk = Hash32::sha3_256(b"checked-chunk");
    let file_hash = Hash32::sha3_256(b"checked-file");
    let bytes = build_recipe(8, &[(chunk, 8)], file_hash, 0, 0);
    let expected_hash = Hash32::sha3_256(&bytes);

    let parsed = parse_recipe_checked(&bytes, &expected_hash).unwrap();
    assert_eq!(parsed.original_file_hash, file_hash);

    let error = parse_recipe_checked(&bytes, &Hash32::sha3_256(b"wrong")).unwrap_err();
    assert!(error.to_string().contains("recipe hash mismatch"));
  }
}
