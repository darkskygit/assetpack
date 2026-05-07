use std::{
  collections::{HashMap, HashSet},
  path::Path,
  sync::Arc,
};

use chrono::Utc;
use sqlx::{
  Executor, QueryBuilder, Row, Sqlite, SqlitePool, Transaction,
  sqlite::{SqliteConnectOptions, SqlitePoolOptions, SqliteRow},
};
use tokio::sync::Mutex;

use crate::{
  codec::{Codec, compress, decompress},
  error::{Error, Result},
  hash::Hash32,
  pack::{MerkleProof, MerkleSummary, ObjectKind, ObjectRecord, StoredObject, merkle_root_from_hashes},
};

const SQLITE_PARAM_LIMIT: usize = 999;
const OBJECT_COLUMNS: usize = 7;
const MAX_OBJECTS_PER_BATCH: usize = SQLITE_PARAM_LIMIT / OBJECT_COLUMNS;
const FILE_RECIPE_COLUMNS: usize = 3;
const MAX_FILE_RECIPE_PER_BATCH: usize = SQLITE_PARAM_LIMIT / FILE_RECIPE_COLUMNS;

pub type StoreWriteTx<'a> = Transaction<'a, Sqlite>;

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

#[derive(Default)]
struct MerkleCache {
  summary: Option<MerkleSummary>,
  leaf_pos: HashMap<Hash32, u64>,
  leaf_hashes: HashMap<u64, Hash32>,
  node_hashes: HashMap<i64, HashMap<u64, Hash32>>,
}

#[derive(Debug, Clone)]
struct TableNames {
  namespace: Option<String>,
  objects: String,
  file_recipe_cache: String,
  merkle_leaves: String,
  merkle_nodes: String,
  merkle_meta: String,
  merkle_leaves_pos_index: String,
}

impl TableNames {
  fn new(namespace: Option<&str>) -> Result<Self> {
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

#[derive(Clone)]
pub struct SqliteStore {
  pool: SqlitePool,
  tables: TableNames,
  merkle: MerkleMode,
  cache: Arc<Mutex<MerkleCache>>,
}

impl SqliteStore {
  pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
    Self::open_with_options(path, SqliteStoreOptions::default()).await
  }

  pub async fn open_with_options(path: impl AsRef<Path>, options: SqliteStoreOptions) -> Result<Self> {
    let path = path.as_ref().to_path_buf();
    if let Some(parent) = path.parent() {
      tokio::fs::create_dir_all(parent).await?;
    }
    let pool = SqlitePoolOptions::new()
      .max_connections(1)
      .connect_with(SqliteConnectOptions::new().filename(&path).create_if_missing(true))
      .await?;
    Self::from_pool_with_options(pool, options).await
  }

  pub async fn from_pool(pool: SqlitePool) -> Result<Self> {
    Self::from_pool_with_options(pool, SqliteStoreOptions::default()).await
  }

  pub async fn from_pool_with_namespace(pool: SqlitePool, namespace: impl AsRef<str>) -> Result<Self> {
    Self::from_pool_with_options(
      pool,
      SqliteStoreOptions {
        namespace: Some(namespace.as_ref().to_string()),
        ..Default::default()
      },
    )
    .await
  }

  pub async fn from_pool_with_options(pool: SqlitePool, options: SqliteStoreOptions) -> Result<Self> {
    let tables = TableNames::new(options.namespace.as_deref())?;
    Self::ensure_schema_with_options(&pool, &options).await?;
    Ok(Self {
      pool,
      tables,
      merkle: options.merkle,
      cache: Arc::new(Mutex::new(MerkleCache::default())),
    })
  }

  pub async fn ensure_schema(pool: &SqlitePool) -> Result<()> {
    Self::ensure_schema_with_options(pool, &SqliteStoreOptions::default()).await
  }

  pub async fn ensure_schema_with_namespace(pool: &SqlitePool, namespace: impl AsRef<str>) -> Result<()> {
    Self::ensure_schema_with_options(
      pool,
      &SqliteStoreOptions {
        namespace: Some(namespace.as_ref().to_string()),
        ..Default::default()
      },
    )
    .await
  }

  pub async fn ensure_schema_with_options(pool: &SqlitePool, options: &SqliteStoreOptions) -> Result<()> {
    let tables = TableNames::new(options.namespace.as_deref())?;
    for statement in schema_statements(&tables, options.merkle) {
      pool.execute(statement.as_str()).await?;
    }
    Ok(())
  }

  pub fn pool(&self) -> &SqlitePool {
    &self.pool
  }

  pub fn namespace(&self) -> Option<&str> {
    self.tables.namespace.as_deref()
  }

  pub fn merkle_mode(&self) -> MerkleMode {
    self.merkle
  }

  pub async fn begin_write_tx(&self) -> Result<StoreWriteTx<'_>> {
    Ok(self.pool.begin().await?)
  }

  pub async fn put_objects_batch_tx(&self, tx: &mut StoreWriteTx<'_>, objects: &[ObjectRecord]) -> Result<()> {
    if objects.is_empty() {
      return Ok(());
    }

    let now = Utc::now().timestamp();
    for chunk in objects.chunks(MAX_OBJECTS_PER_BATCH.max(1)) {
      let mut builder = QueryBuilder::<Sqlite>::new(format!(
        "INSERT OR IGNORE INTO {} (hash, kind, size, stored_size, codec, content, created_at) ",
        self.tables.objects
      ));
      builder.push_values(chunk, |mut b, obj| {
        b.push_bind(obj.hash.as_bytes().as_ref())
          .push_bind(obj.kind as i64)
          .push_bind(obj.size as i64)
          .push_bind(obj.content.len() as i64)
          .push_bind(codec_to_str(obj.codec))
          .push_bind(obj.content.as_slice())
          .push_bind(now);
      });
      builder.build().execute(&mut **tx).await?;
    }
    Ok(())
  }

  pub async fn put_file_recipe_cache_batch_tx(&self, tx: &mut StoreWriteTx<'_>, entries: &[(Hash32, Hash32)]) -> Result<()> {
    if entries.is_empty() {
      return Ok(());
    }

    let now = Utc::now().timestamp();
    for chunk in entries.chunks(MAX_FILE_RECIPE_PER_BATCH.max(1)) {
      let mut builder = QueryBuilder::<Sqlite>::new(format!(
        "INSERT INTO {} (file_hash, recipe_hash, updated_at) ",
        self.tables.file_recipe_cache
      ));
      builder.push_values(chunk, |mut b, (file_hash, recipe_hash)| {
        b.push_bind(file_hash.as_bytes().as_ref())
          .push_bind(recipe_hash.as_bytes().as_ref())
          .push_bind(now);
      });
      builder.push(" ON CONFLICT(file_hash) DO UPDATE SET recipe_hash=excluded.recipe_hash, updated_at=excluded.updated_at");
      builder.build().execute(&mut **tx).await?;
    }
    Ok(())
  }

  pub async fn put_chunk(&self, hash: Hash32, content: &[u8], codec: Codec) -> Result<()> {
    self.put_object(hash, ObjectKind::Chunk, content, codec).await
  }

  pub async fn put_recipe(&self, hash: Hash32, content: &[u8], codec: Codec) -> Result<()> {
    self.put_object(hash, ObjectKind::Recipe, content, codec).await
  }

  async fn put_object(&self, hash: Hash32, kind: ObjectKind, content: &[u8], codec: Codec) -> Result<()> {
    let calc = Hash32::sha3_256(content);
    if calc != hash {
      return Err(Error::HashMismatch);
    }

    let size = content.len() as i64;
    let mut final_codec = codec;
    let compressed = if codec == Codec::Raw {
      content.to_vec()
    } else {
      let candidate = compress(codec, content)?;
      let ratio = candidate.len() as f64 / size.max(1) as f64;
      if ratio >= 0.98 {
        final_codec = Codec::Raw;
        content.to_vec()
      } else {
        candidate
      }
    };

    let query = format!(
      "INSERT OR IGNORE INTO {} (hash, kind, size, stored_size, codec, content, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
      self.tables.objects
    );
    sqlx::query(&query)
      .bind(hash.as_bytes().as_ref())
      .bind(kind as i64)
      .bind(size)
      .bind(compressed.len() as i64)
      .bind(codec_to_str(final_codec))
      .bind(compressed)
      .bind(Utc::now().timestamp())
      .execute(&self.pool)
      .await?;
    Ok(())
  }

  pub async fn get_object(&self, hash: &Hash32) -> Result<Option<StoredObject>> {
    let query = format!("SELECT kind, size, codec, content FROM {} WHERE hash = ?1", self.tables.objects);
    let row = sqlx::query(&query)
      .bind(hash.as_bytes().as_ref())
      .fetch_optional(&self.pool)
      .await?;
    let Some(row) = row else {
      return Ok(None);
    };
    Ok(Some(stored_object_from_row(row, *hash)?))
  }

  pub async fn existing_hashes(&self, hashes: &[Hash32]) -> Result<HashSet<Hash32>> {
    let mut found = HashSet::new();
    if hashes.is_empty() {
      return Ok(found);
    }

    for chunk in hashes.chunks(SQLITE_PARAM_LIMIT.max(1)) {
      let mut builder = QueryBuilder::<Sqlite>::new(format!("SELECT hash FROM {} WHERE hash IN (", self.tables.objects));
      let mut separated = builder.separated(", ");
      for hash in chunk {
        separated.push_bind(hash.as_bytes().as_ref());
      }
      separated.push_unseparated(")");
      let rows = builder.build().fetch_all(&self.pool).await?;
      for row in rows {
        let bytes: Vec<u8> = row.get("hash");
        found.insert(Hash32::from_bytes(&bytes)?);
      }
    }
    Ok(found)
  }

  pub async fn chunk_sizes(&self) -> Result<Vec<(Hash32, u64)>> {
    let query = format!("SELECT hash, stored_size FROM {} WHERE kind=?1", self.tables.objects);
    let rows = sqlx::query(&query).bind(ObjectKind::Chunk as i64).fetch_all(&self.pool).await?;
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
      let hash_bytes: Vec<u8> = row.get("hash");
      let hash = Hash32::from_bytes(&hash_bytes)?;
      let stored_size: i64 = row.get("stored_size");
      items.push((hash, stored_size as u64));
    }
    Ok(items)
  }

  pub async fn file_recipe_cache(&self) -> Result<HashMap<Hash32, Hash32>> {
    let query = format!("SELECT file_hash, recipe_hash FROM {}", self.tables.file_recipe_cache);
    let rows = sqlx::query(&query).fetch_all(&self.pool).await?;
    let mut map = HashMap::with_capacity(rows.len());
    for row in rows {
      let file_bytes: Vec<u8> = row.get("file_hash");
      let recipe_bytes: Vec<u8> = row.get("recipe_hash");
      map.insert(Hash32::from_bytes(&file_bytes)?, Hash32::from_bytes(&recipe_bytes)?);
    }
    Ok(map)
  }

  pub async fn recipe_for_file_hash(&self, file_hash: &Hash32) -> Result<Option<Hash32>> {
    let query = format!("SELECT recipe_hash FROM {} WHERE file_hash=?1", self.tables.file_recipe_cache);
    let row = sqlx::query(&query)
      .bind(file_hash.as_bytes().as_ref())
      .fetch_optional(&self.pool)
      .await?;
    let Some(row) = row else {
      return Ok(None);
    };
    let bytes: Vec<u8> = row.get("recipe_hash");
    Ok(Some(Hash32::from_bytes(&bytes)?))
  }

  pub async fn all_objects(&self) -> Result<Vec<StoredObject>> {
    let query = format!(
      "SELECT hash, kind, size, codec, content FROM {} ORDER BY hash ASC",
      self.tables.objects
    );
    let rows = sqlx::query(&query).fetch_all(&self.pool).await?;
    let mut objects = Vec::with_capacity(rows.len());
    for row in rows {
      let hash_bytes: Vec<u8> = row.get("hash");
      let hash = Hash32::from_bytes(&hash_bytes)?;
      objects.push(stored_object_from_row(row, hash)?);
    }
    Ok(objects)
  }

  pub async fn integrity_check(&self) -> Result<()> {
    let row = sqlx::query("PRAGMA integrity_check;").fetch_one(&self.pool).await?;
    let status: String = row.get(0);
    if status.trim() == "ok" {
      Ok(())
    } else {
      Err(Error::Integrity(status))
    }
  }

  pub async fn rebuild_merkle_index(&self) -> Result<MerkleSummary> {
    self.ensure_merkle_enabled()?;

    let mut tx = self.pool.begin().await?;
    sqlx::query(&format!("DELETE FROM {}", self.tables.merkle_leaves))
      .execute(&mut *tx)
      .await?;
    sqlx::query(&format!("DELETE FROM {}", self.tables.merkle_nodes))
      .execute(&mut *tx)
      .await?;
    sqlx::query(&format!("DELETE FROM {}", self.tables.merkle_meta))
      .execute(&mut *tx)
      .await?;

    let rows = sqlx::query(&format!("SELECT hash FROM {} ORDER BY hash ASC", self.tables.objects))
      .fetch_all(&mut *tx)
      .await?;
    let mut leaves = Vec::with_capacity(rows.len());
    for row in rows {
      let bytes: Vec<u8> = row.get("hash");
      leaves.push(Hash32::from_bytes(&bytes)?);
    }

    for (idx, hash) in leaves.iter().enumerate() {
      sqlx::query(&format!("INSERT INTO {} (hash, pos) VALUES (?1, ?2)", self.tables.merkle_leaves))
        .bind(hash.as_bytes().as_ref())
        .bind(idx as i64)
        .execute(&mut *tx)
        .await?;
    }

    let summary = merkle_root_from_hashes(&leaves);
    let mut current = leaves;
    let mut next_level = Vec::new();
    let mut level = 0i64;
    while current.len() > 1 {
      next_level.clear();
      for (idx, chunk) in current.chunks(2).enumerate() {
        let left = chunk[0];
        let right = if chunk.len() > 1 { chunk[1] } else { chunk[0] };
        let parent = hash_pair(&left, &right);
        sqlx::query(&format!(
          "INSERT INTO {} (level, pos, hash) VALUES (?1, ?2, ?3) ON CONFLICT(level, pos) DO UPDATE SET hash=excluded.hash",
          self.tables.merkle_nodes
        ))
        .bind(level)
        .bind(idx as i64)
        .bind(parent.as_bytes().as_ref())
        .execute(&mut *tx)
        .await?;
        next_level.push(parent);
      }
      current.clear();
      current.extend_from_slice(&next_level);
      level += 1;
    }

    for (key, value) in [
      ("leaf_count", summary.leaf_count.to_string()),
      ("root_hash", summary.root.to_hex()),
      ("algo", "sha3-256".to_string()),
      ("tree", "merkle-set-v1".to_string()),
      ("sorted", "byte-lex".to_string()),
    ] {
      sqlx::query(&format!(
        "INSERT INTO {} (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        self.tables.merkle_meta
      ))
      .bind(key)
      .bind(value)
      .execute(&mut *tx)
      .await?;
    }

    tx.commit().await?;
    let mut cache = self.cache.lock().await;
    cache.summary = Some(summary.clone());
    cache.leaf_pos.clear();
    cache.leaf_hashes.clear();
    cache.node_hashes.clear();
    Ok(summary)
  }

  pub async fn merkle_summary(&self) -> Result<MerkleSummary> {
    self.ensure_merkle_enabled()?;

    if let Some(summary) = self.cache.lock().await.summary.clone() {
      return Ok(summary);
    }

    let leaf_count = read_meta_u64(&self.pool, &self.tables.merkle_meta, "leaf_count").await?;
    let root_hex = read_meta_value(&self.pool, &self.tables.merkle_meta, "root_hash")
      .await?
      .ok_or_else(|| Error::MissingMeta("root_hash".into()))?;
    let root = Hash32::from_hex(&root_hex).map_err(|_| Error::MissingMeta("root_hash".into()))?;
    let summary = MerkleSummary { root, leaf_count };
    self.cache.lock().await.summary = Some(summary.clone());
    Ok(summary)
  }

  pub async fn prove_membership(&self, hash: &Hash32) -> Result<Option<MerkleProof>> {
    self.ensure_merkle_enabled()?;

    let summary = self.merkle_summary().await?;
    if summary.leaf_count == 0 {
      return Ok(None);
    }

    let row = sqlx::query(&format!("SELECT pos FROM {} WHERE hash=?1", self.tables.merkle_leaves))
      .bind(hash.as_bytes().as_ref())
      .fetch_optional(&self.pool)
      .await?;
    let Some(row) = row else {
      return Ok(None);
    };

    let mut pos = row.get::<i64, _>("pos") as u64;
    let leaf_pos = pos;
    let mut count = summary.leaf_count;
    let mut siblings = Vec::new();
    let mut current_hash = *hash;
    let mut node_level = 0i64;
    let mut on_leaf = true;

    while count > 1 {
      let sibling_pos = pos ^ 1;
      let sibling_hash = if on_leaf {
        if sibling_pos >= count {
          current_hash
        } else {
          fetch_hash_by_pos(&self.pool, &self.tables.merkle_leaves, None, sibling_pos).await?
        }
      } else if sibling_pos >= count {
        current_hash
      } else {
        fetch_hash_by_pos(&self.pool, &self.tables.merkle_nodes, Some(node_level), sibling_pos).await?
      };

      siblings.push(sibling_hash);
      let (left, right) = if pos.is_multiple_of(2) {
        (current_hash, sibling_hash)
      } else {
        (sibling_hash, current_hash)
      };
      current_hash = hash_pair(&left, &right);
      pos /= 2;
      count = count.div_ceil(2);
      if on_leaf {
        on_leaf = false;
      } else {
        node_level += 1;
      }
    }

    Ok(Some(MerkleProof { leaf_pos, siblings }))
  }

  pub fn verify_proof(target: &Hash32, proof: &MerkleProof, expected_root: &Hash32, leaf_count: u64) -> bool {
    if leaf_count == 0 {
      return false;
    }
    let mut hash = *target;
    let mut pos = proof.leaf_pos;
    let mut count = leaf_count;
    for sibling in &proof.siblings {
      let (left, right) = if pos.is_multiple_of(2) {
        (hash, *sibling)
      } else {
        (*sibling, hash)
      };
      hash = hash_pair(&left, &right);
      pos /= 2;
      count = count.div_ceil(2);
      if count == 1 {
        break;
      }
    }
    hash == *expected_root
  }

  fn ensure_merkle_enabled(&self) -> Result<()> {
    if self.merkle == MerkleMode::Enabled {
      Ok(())
    } else {
      Err(Error::Integrity("merkle disabled for sqlite store".into()))
    }
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

fn schema_statements(tables: &TableNames, merkle: MerkleMode) -> Vec<String> {
  let mut statements = vec![
    format!(
      "CREATE TABLE IF NOT EXISTS {} (hash BLOB PRIMARY KEY, kind INTEGER NOT NULL, size INTEGER NOT NULL, stored_size INTEGER NOT NULL, \
       codec TEXT NOT NULL, content BLOB NOT NULL, created_at INTEGER NOT NULL);",
      tables.objects
    ),
    format!(
      "CREATE TABLE IF NOT EXISTS {} (file_hash BLOB PRIMARY KEY, recipe_hash BLOB NOT NULL, updated_at INTEGER NOT NULL);",
      tables.file_recipe_cache
    ),
  ];

  if merkle == MerkleMode::Enabled {
    statements.extend([
      format!(
        "CREATE TABLE IF NOT EXISTS {} (hash BLOB PRIMARY KEY, pos INTEGER NOT NULL);",
        tables.merkle_leaves
      ),
      format!(
        "CREATE UNIQUE INDEX IF NOT EXISTS {} ON {}(pos);",
        tables.merkle_leaves_pos_index, tables.merkle_leaves
      ),
      format!(
        "CREATE TABLE IF NOT EXISTS {} (level INTEGER NOT NULL, pos INTEGER NOT NULL, hash BLOB NOT NULL, PRIMARY KEY(level, pos));",
        tables.merkle_nodes
      ),
      format!(
        "CREATE TABLE IF NOT EXISTS {} (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
        tables.merkle_meta
      ),
    ]);
  }

  statements
}

fn stored_object_from_row(row: SqliteRow, hash: Hash32) -> Result<StoredObject> {
  let kind = ObjectKind::from_i64(row.get::<i64, _>("kind")).ok_or_else(|| Error::Integrity("invalid kind".into()))?;
  let size: i64 = row.get("size");
  let codec = codec_from_str(&row.get::<String, _>("codec"))?;
  let stored: Vec<u8> = row.get("content");
  let content = decompress(codec, &stored)?;
  if content.len() as i64 != size {
    return Err(Error::Integrity("size mismatch".into()));
  }
  if Hash32::sha3_256(&content) != hash {
    return Err(Error::HashMismatch);
  }
  Ok(StoredObject {
    hash,
    kind,
    size: size as u64,
    codec,
    content,
  })
}

async fn read_meta_value(pool: &SqlitePool, table: &str, key: &str) -> Result<Option<String>> {
  let row = sqlx::query(&format!("SELECT value FROM {table} WHERE key=?1"))
    .bind(key)
    .fetch_optional(pool)
    .await?;
  Ok(row.map(|row| row.get::<String, _>("value")))
}

async fn read_meta_u64(pool: &SqlitePool, table: &str, key: &str) -> Result<u64> {
  let value = read_meta_value(pool, table, key)
    .await?
    .ok_or_else(|| Error::MissingMeta(key.to_string()))?;
  value.parse::<u64>().map_err(|_| Error::MissingMeta(key.to_string()))
}

async fn fetch_hash_by_pos(pool: &SqlitePool, table: &str, level: Option<i64>, pos: u64) -> Result<Hash32> {
  let row = match level {
    Some(level) => {
      sqlx::query(&format!("SELECT hash FROM {table} WHERE level=?1 AND pos=?2"))
        .bind(level)
        .bind(pos as i64)
        .fetch_one(pool)
        .await?
    }
    None => {
      sqlx::query(&format!("SELECT hash FROM {table} WHERE pos=?1"))
        .bind(pos as i64)
        .fetch_one(pool)
        .await?
    }
  };
  let bytes: Vec<u8> = row.get("hash");
  Hash32::from_bytes(&bytes)
}

fn codec_to_str(codec: Codec) -> &'static str {
  match codec {
    Codec::Raw => "raw",
    Codec::Zstd => "zstd",
    Codec::Brotli => "brotli",
  }
}

fn codec_from_str(value: &str) -> Result<Codec> {
  match value {
    "raw" => Ok(Codec::Raw),
    "zstd" => Ok(Codec::Zstd),
    "brotli" => Ok(Codec::Brotli),
    other => Err(Error::InvalidCodec(other.to_string())),
  }
}

fn hash_pair(left: &Hash32, right: &Hash32) -> Hash32 {
  let mut bytes = Vec::with_capacity(64);
  bytes.extend_from_slice(left.as_bytes());
  bytes.extend_from_slice(right.as_bytes());
  Hash32::sha3_256(bytes)
}

#[cfg(test)]
mod tests {
  use sqlx::sqlite::SqliteConnectOptions;

  use super::*;

  async fn memory_pool() -> SqlitePool {
    SqlitePoolOptions::new()
      .max_connections(1)
      .connect_with(SqliteConnectOptions::new().filename(":memory:").create_if_missing(true))
      .await
      .unwrap()
  }

  async fn table_exists(pool: &SqlitePool, table: &str) -> bool {
    sqlx::query("SELECT name FROM sqlite_master WHERE type='table' AND name=?1")
      .bind(table)
      .fetch_optional(pool)
      .await
      .unwrap()
      .is_some()
  }

  #[tokio::test]
  async fn namespaced_store_creates_prefixed_tables_and_roundtrips_objects() {
    let pool = memory_pool().await;
    let store = SqliteStore::from_pool_with_namespace(pool.clone(), "ipg").await.unwrap();
    assert_eq!(store.namespace(), Some("ipg"));
    assert!(table_exists(&pool, "ipg_objects").await);
    assert!(table_exists(&pool, "ipg_file_recipe_cache").await);
    assert!(!table_exists(&pool, "objects").await);

    let data = b"hello embedded store".to_vec();
    let hash = Hash32::sha3_256(&data);
    store.put_chunk(hash, &data, Codec::Zstd).await.unwrap();
    let loaded = store.get_object(&hash).await.unwrap().unwrap();
    assert_eq!(loaded.hash, hash);
    assert_eq!(loaded.kind, ObjectKind::Chunk);
    assert_eq!(loaded.content, data);
  }

  #[tokio::test]
  async fn store_batch_writes_can_share_host_transaction_boundary() {
    let pool = memory_pool().await;
    sqlx::query("CREATE TABLE app_history (id INTEGER PRIMARY KEY, label TEXT NOT NULL);")
      .execute(&pool)
      .await
      .unwrap();
    let store = SqliteStore::from_pool(pool.clone()).await.unwrap();

    let data = b"tx-object".to_vec();
    let hash = Hash32::sha3_256(&data);
    let object = ObjectRecord {
      hash,
      kind: ObjectKind::Chunk,
      size: data.len() as u64,
      codec: Codec::Raw,
      content: data.clone(),
    };

    let mut tx = pool.begin().await.unwrap();
    sqlx::query("INSERT INTO app_history (label) VALUES (?1)")
      .bind("draft")
      .execute(&mut *tx)
      .await
      .unwrap();
    store.put_objects_batch_tx(&mut tx, &[object]).await.unwrap();
    tx.rollback().await.unwrap();

    let app_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM app_history")
      .fetch_one(&pool)
      .await
      .unwrap();
    let object_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM objects").fetch_one(&pool).await.unwrap();
    assert_eq!(app_count, 0);
    assert_eq!(object_count, 0);
  }

  #[tokio::test]
  async fn merkle_can_be_disabled_for_embedded_store() {
    let pool = memory_pool().await;
    let store = SqliteStore::from_pool_with_options(
      pool.clone(),
      SqliteStoreOptions {
        namespace: Some("ipg".into()),
        merkle: MerkleMode::Disabled,
      },
    )
    .await
    .unwrap();
    assert_eq!(store.merkle_mode(), MerkleMode::Disabled);
    assert!(!table_exists(&pool, "ipg_merkle_leaves").await);
    assert!(!table_exists(&pool, "ipg_merkle_nodes").await);
    assert!(!table_exists(&pool, "ipg_merkle_meta").await);

    let error = store.rebuild_merkle_index().await.unwrap_err();
    assert!(error.to_string().contains("merkle disabled"));
  }

  #[tokio::test]
  async fn merkle_enabled_store_can_build_and_verify_proof() {
    let pool = memory_pool().await;
    let store = SqliteStore::from_pool_with_options(
      pool,
      SqliteStoreOptions {
        namespace: Some("ipg".into()),
        merkle: MerkleMode::Enabled,
      },
    )
    .await
    .unwrap();

    for item in [b"foo".as_slice(), b"bar".as_slice(), b"baz".as_slice()] {
      let hash = Hash32::sha3_256(item);
      store.put_chunk(hash, item, Codec::Raw).await.unwrap();
    }

    let target = Hash32::sha3_256(b"bar");
    let summary = store.rebuild_merkle_index().await.unwrap();
    let proof = store.prove_membership(&target).await.unwrap().unwrap();
    assert!(SqliteStore::verify_proof(&target, &proof, &summary.root, summary.leaf_count));
  }
}
