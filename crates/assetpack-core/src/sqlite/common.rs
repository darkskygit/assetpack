use crate::{Codec, Error, Hash32, ObjectKind, ObjectRecord, Result, VerifiedObject, compress, decompress};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MerkleMode {
  Disabled,
  #[default]
  Enabled,
}

#[derive(Debug, Clone, Default)]
pub struct SqliteStoreOptions {
  pub namespace: Option<String>,
  pub merkle: MerkleMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
  pub leaf_pos: u64,
  pub siblings: Vec<Hash32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleSummary {
  pub root: Hash32,
  pub leaf_count: u64,
}

#[derive(Debug, Clone)]
pub(in crate::sqlite) struct SqliteLayout {
  pub namespace: Option<String>,
  pub objects: String,
  pub file_recipe_cache: String,
  pub merkle_leaves: String,
  pub merkle_nodes: String,
  pub merkle_meta: String,
  pub merkle_leaves_pos_index: String,
}

impl SqliteLayout {
  pub fn new(namespace: Option<&str>) -> Result<Self> {
    let namespace = normalize_namespace(namespace)?;
    let prefix = namespace.as_ref().map(|value| format!("{value}_")).unwrap_or_default();
    let index_prefix = namespace
      .as_ref()
      .map(|value| format!("idx_{value}_"))
      .unwrap_or_else(|| "idx_".into());
    Ok(Self {
      namespace,
      objects: format!("{prefix}objects"),
      file_recipe_cache: format!("{prefix}file_recipe_cache"),
      merkle_leaves: format!("{prefix}merkle_leaves"),
      merkle_nodes: format!("{prefix}merkle_nodes"),
      merkle_meta: format!("{prefix}merkle_meta"),
      merkle_leaves_pos_index: format!("{index_prefix}merkle_leaves_pos"),
    })
  }
}

fn normalize_namespace(namespace: Option<&str>) -> Result<Option<String>> {
  let Some(namespace) = namespace else {
    return Ok(None);
  };
  if namespace.is_empty() {
    return Err(Error::InvalidConfig("store namespace cannot be empty".into()));
  }
  if namespace.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_') {
    Ok(Some(namespace.to_string()))
  } else {
    Err(Error::InvalidConfig(format!(
      "store namespace must contain only ASCII letters, digits, or underscores: {namespace}"
    )))
  }
}

pub(in crate::sqlite) fn schema_statements(layout: &SqliteLayout, merkle: MerkleMode) -> Vec<String> {
  let mut statements = vec![
    format!(
      "CREATE TABLE IF NOT EXISTS {} (hash BLOB PRIMARY KEY, kind INTEGER NOT NULL, size INTEGER NOT NULL, stored_size INTEGER NOT NULL, \
       codec TEXT NOT NULL, content BLOB NOT NULL, created_at INTEGER NOT NULL);",
      layout.objects
    ),
    format!(
      "CREATE TABLE IF NOT EXISTS {} (file_hash BLOB PRIMARY KEY, recipe_hash BLOB NOT NULL, updated_at INTEGER NOT NULL);",
      layout.file_recipe_cache
    ),
  ];
  if merkle == MerkleMode::Enabled {
    statements.extend([
      format!(
        "CREATE TABLE IF NOT EXISTS {} (hash BLOB PRIMARY KEY, pos INTEGER NOT NULL);",
        layout.merkle_leaves
      ),
      format!(
        "CREATE UNIQUE INDEX IF NOT EXISTS {} ON {}(pos);",
        layout.merkle_leaves_pos_index, layout.merkle_leaves
      ),
      format!(
        "CREATE TABLE IF NOT EXISTS {} (level INTEGER NOT NULL, pos INTEGER NOT NULL, hash BLOB NOT NULL, PRIMARY KEY(level, pos));",
        layout.merkle_nodes
      ),
      format!(
        "CREATE TABLE IF NOT EXISTS {} (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
        layout.merkle_meta
      ),
    ]);
  }
  statements
}

pub(in crate::sqlite) struct StoredObjectRow {
  pub hash: Hash32,
  pub kind: i64,
  pub decoded_len: i64,
  pub codec: String,
  pub stored_bytes: Vec<u8>,
}

pub(in crate::sqlite) fn prepare_object(hash: Hash32, kind: ObjectKind, content: &[u8], codec: Codec) -> Result<ObjectRecord> {
  if Hash32::sha3_256(content) != hash {
    return Err(Error::HashMismatch);
  }
  let mut selected = codec;
  let stored_bytes = if codec == Codec::Raw {
    content.to_vec()
  } else {
    let candidate = compress(codec, content)?;
    if candidate.len() as f64 / content.len().max(1) as f64 >= 0.98 {
      selected = Codec::Raw;
      content.to_vec()
    } else {
      candidate
    }
  };
  Ok(ObjectRecord {
    hash,
    kind,
    decoded_len: content.len() as u64,
    codec: selected,
    stored_bytes,
  })
}

pub(in crate::sqlite) fn verified_object_from_row(row: StoredObjectRow) -> Result<VerifiedObject> {
  let kind = ObjectKind::from_i64(row.kind).ok_or_else(|| Error::Integrity("invalid kind".into()))?;
  let expected = u64::try_from(row.decoded_len).map_err(|_| Error::Integrity("negative object size".into()))?;
  let bytes = decompress(codec_from_str(&row.codec)?, &row.stored_bytes)?;
  let actual = bytes.len() as u64;
  if actual != expected {
    return Err(Error::ObjectLengthMismatch { expected, actual });
  }
  let actual_hash = Hash32::sha3_256(&bytes);
  if actual_hash != row.hash {
    return Err(Error::ObjectHashMismatch {
      expected: row.hash,
      actual: actual_hash,
    });
  }
  Ok(VerifiedObject {
    hash: row.hash,
    kind,
    bytes,
  })
}

pub(in crate::sqlite) fn object_record_from_row(row: StoredObjectRow) -> Result<ObjectRecord> {
  Ok(ObjectRecord {
    hash: row.hash,
    kind: ObjectKind::from_i64(row.kind).ok_or_else(|| Error::Integrity("invalid kind".into()))?,
    decoded_len: u64::try_from(row.decoded_len).map_err(|_| Error::Integrity("negative object size".into()))?,
    codec: codec_from_str(&row.codec)?,
    stored_bytes: row.stored_bytes,
  })
}

pub(in crate::sqlite) fn codec_to_str(codec: Codec) -> &'static str {
  match codec {
    Codec::Raw => "raw",
    Codec::Zstd => "zstd",
    Codec::Brotli => "brotli",
  }
}

pub(in crate::sqlite) fn codec_from_str(value: &str) -> Result<Codec> {
  match value {
    "raw" => Ok(Codec::Raw),
    "zstd" => Ok(Codec::Zstd),
    "brotli" => Ok(Codec::Brotli),
    other => Err(Error::InvalidCodec(other.to_string())),
  }
}

pub(in crate::sqlite) fn hash_pair(left: &Hash32, right: &Hash32) -> Hash32 {
  let mut bytes = Vec::with_capacity(64);
  bytes.extend_from_slice(left.as_bytes());
  bytes.extend_from_slice(right.as_bytes());
  Hash32::sha3_256(bytes)
}

pub(in crate::sqlite) fn merkle_root_from_hashes(hashes: &[Hash32]) -> MerkleSummary {
  if hashes.is_empty() {
    return MerkleSummary {
      root: Hash32::sha3_256([]),
      leaf_count: 0,
    };
  }
  let mut current = hashes.to_vec();
  while current.len() > 1 {
    current = current
      .chunks(2)
      .map(|pair| hash_pair(&pair[0], pair.get(1).unwrap_or(&pair[0])))
      .collect();
  }
  MerkleSummary {
    root: current[0],
    leaf_count: hashes.len() as u64,
  }
}
