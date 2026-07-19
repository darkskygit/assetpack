use std::{
  collections::{HashMap, HashSet},
  path::Path,
  sync::Arc,
};

use chrono::Utc;
use sqlx::{
  AssertSqlSafe, Executor, QueryBuilder, Row, Sqlite, SqlitePool, Transaction,
  sqlite::{SqliteConnectOptions, SqlitePoolOptions, SqliteRow},
};
use tokio::sync::Mutex;

use super::{
  MerkleMode, MerkleProof, MerkleSummary, SqliteLayout, SqliteStoreOptions, hash_pair, merkle_root_from_hashes, statements::INTEGRITY_CHECK,
};
use crate::{
  codec::Codec,
  error::{Error, Result},
  hash::Hash32,
  object::{AsyncObjectSource, ObjectKind, ObjectRecord, VerifiedObject},
};

mod merkle;

const SQLITE_PARAM_LIMIT: usize = 999;
const OBJECT_COLUMNS: usize = 7;
const MAX_OBJECTS_PER_BATCH: usize = SQLITE_PARAM_LIMIT / OBJECT_COLUMNS;
const FILE_RECIPE_COLUMNS: usize = 3;
const MAX_FILE_RECIPE_PER_BATCH: usize = SQLITE_PARAM_LIMIT / FILE_RECIPE_COLUMNS;

pub type SqlxStoreWriteTx<'a> = Transaction<'a, Sqlite>;

#[derive(Default)]
struct MerkleCache {
  summary: Option<MerkleSummary>,
  leaf_pos: HashMap<Hash32, u64>,
  leaf_hashes: HashMap<u64, Hash32>,
  node_hashes: HashMap<i64, HashMap<u64, Hash32>>,
}

#[derive(Clone)]
pub struct SqlxStore {
  pool: SqlitePool,
  tables: SqliteLayout,
  merkle: MerkleMode,
  cache: Arc<Mutex<MerkleCache>>,
}

impl SqlxStore {
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
    let tables = SqliteLayout::new(options.namespace.as_deref())?;
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
    let tables = SqliteLayout::new(options.namespace.as_deref())?;
    for statement in schema_statements(&tables, options.merkle) {
      pool.execute(AssertSqlSafe(statement)).await?;
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

  pub async fn begin_write_tx(&self) -> Result<SqlxStoreWriteTx<'_>> {
    Ok(self.pool.begin().await?)
  }

  pub async fn put_objects_batch_tx(&self, tx: &mut SqlxStoreWriteTx<'_>, objects: &[ObjectRecord]) -> Result<()> {
    if objects.is_empty() {
      return Ok(());
    }

    let now = Utc::now().timestamp();
    for chunk in objects.chunks(MAX_OBJECTS_PER_BATCH.max(1)) {
      let mut builder = QueryBuilder::<Sqlite>::new(self.tables.insert_objects_prefix());
      builder.push_values(chunk, |mut b, obj| {
        b.push_bind(obj.hash.as_bytes().as_ref())
          .push_bind(obj.kind as i64)
          .push_bind(obj.decoded_len as i64)
          .push_bind(obj.stored_bytes.len() as i64)
          .push_bind(super::codec_to_str(obj.codec))
          .push_bind(obj.stored_bytes.as_slice())
          .push_bind(now);
      });
      builder.build().execute(&mut **tx).await?;
    }
    Ok(())
  }

  pub async fn put_file_recipe_cache_batch_tx(&self, tx: &mut SqlxStoreWriteTx<'_>, entries: &[(Hash32, Hash32)]) -> Result<()> {
    if entries.is_empty() {
      return Ok(());
    }

    let now = Utc::now().timestamp();
    for chunk in entries.chunks(MAX_FILE_RECIPE_PER_BATCH.max(1)) {
      let mut builder = QueryBuilder::<Sqlite>::new(self.tables.upsert_recipe_cache_prefix());
      builder.push_values(chunk, |mut b, (file_hash, recipe_hash)| {
        b.push_bind(file_hash.as_bytes().as_ref())
          .push_bind(recipe_hash.as_bytes().as_ref())
          .push_bind(now);
      });
      builder.push(super::statements::UPSERT_RECIPE_CACHE_SUFFIX);
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
    let object = super::prepare_object(hash, kind, content, codec)?;

    let query = self.tables.insert_object();
    sqlx::query(AssertSqlSafe(query))
      .bind(object.hash.as_bytes().as_ref())
      .bind(object.kind as i64)
      .bind(object.decoded_len as i64)
      .bind(object.stored_bytes.len() as i64)
      .bind(super::codec_to_str(object.codec))
      .bind(object.stored_bytes)
      .bind(Utc::now().timestamp())
      .execute(&self.pool)
      .await?;
    Ok(())
  }

  async fn read_verified_object(&self, hash: &Hash32) -> Result<Option<VerifiedObject>> {
    let query = self.tables.select_object();
    let row = sqlx::query(AssertSqlSafe(query))
      .bind(hash.as_bytes().as_ref())
      .fetch_optional(&self.pool)
      .await?;
    let Some(row) = row else {
      return Ok(None);
    };
    Ok(Some(verified_object_from_row(row, *hash)?))
  }

  pub async fn existing_hashes(&self, hashes: &[Hash32]) -> Result<HashSet<Hash32>> {
    let mut found = HashSet::new();
    if hashes.is_empty() {
      return Ok(found);
    }

    for chunk in hashes.chunks(SQLITE_PARAM_LIMIT.max(1)) {
      let mut builder = QueryBuilder::<Sqlite>::new(self.tables.select_hashes_prefix());
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
    let query = self.tables.select_chunk_sizes();
    let rows = sqlx::query(AssertSqlSafe(query))
      .bind(ObjectKind::Chunk as i64)
      .fetch_all(&self.pool)
      .await?;
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
      let hash_bytes: Vec<u8> = row.get("hash");
      let hash = Hash32::from_bytes(&hash_bytes)?;
      let stored_size: i64 = row.get("stored_size");
      items.push((hash, stored_size as u64));
    }
    Ok(items)
  }

  pub async fn chunk_stored_bytes(&self, hash: &Hash32) -> Result<Option<u64>> {
    let query = self.tables.select_chunk_stored_size();
    let row = sqlx::query(AssertSqlSafe(query))
      .bind(hash.as_bytes().as_ref())
      .fetch_optional(&self.pool)
      .await?;
    match row {
      Some(row) if row.get::<i64, _>("kind") == ObjectKind::Chunk as i64 => {
        let size = row.get::<i64, _>("stored_size");
        Ok(Some(size.try_into().map_err(|_| Error::Integrity("negative stored size".into()))?))
      }
      _ => Ok(None),
    }
  }

  pub async fn file_recipe_cache(&self) -> Result<HashMap<Hash32, Hash32>> {
    let query = self.tables.select_recipe_cache();
    let rows = sqlx::query(AssertSqlSafe(query)).fetch_all(&self.pool).await?;
    let mut map = HashMap::with_capacity(rows.len());
    for row in rows {
      let file_bytes: Vec<u8> = row.get("file_hash");
      let recipe_bytes: Vec<u8> = row.get("recipe_hash");
      map.insert(Hash32::from_bytes(&file_bytes)?, Hash32::from_bytes(&recipe_bytes)?);
    }
    Ok(map)
  }

  pub async fn recipe_for_file_hash(&self, file_hash: &Hash32) -> Result<Option<Hash32>> {
    let query = self.tables.select_recipe_for_file();
    let row = sqlx::query(AssertSqlSafe(query))
      .bind(file_hash.as_bytes().as_ref())
      .fetch_optional(&self.pool)
      .await?;
    let Some(row) = row else {
      return Ok(None);
    };
    let bytes: Vec<u8> = row.get("recipe_hash");
    Ok(Some(Hash32::from_bytes(&bytes)?))
  }

  pub async fn all_objects(&self) -> Result<Vec<VerifiedObject>> {
    let query = self.tables.select_objects();
    let rows = sqlx::query(AssertSqlSafe(query)).fetch_all(&self.pool).await?;
    let mut objects = Vec::with_capacity(rows.len());
    for row in rows {
      let hash_bytes: Vec<u8> = row.get("hash");
      let hash = Hash32::from_bytes(&hash_bytes)?;
      objects.push(verified_object_from_row(row, hash)?);
    }
    Ok(objects)
  }

  pub async fn object_records(&self, offset: u64, limit: usize) -> Result<Vec<ObjectRecord>> {
    let query = self.tables.select_object_records();
    sqlx::query(AssertSqlSafe(query))
      .bind(limit as i64)
      .bind(offset as i64)
      .fetch_all(&self.pool)
      .await?
      .into_iter()
      .map(object_record_from_sqlx_row)
      .collect()
  }
}

fn schema_statements(tables: &SqliteLayout, merkle: MerkleMode) -> Vec<String> {
  super::schema_statements(tables, merkle)
}

fn verified_object_from_row(row: SqliteRow, hash: Hash32) -> Result<VerifiedObject> {
  super::verified_object_from_row(super::StoredObjectRow {
    hash,
    kind: row.get("kind"),
    decoded_len: row.get("size"),
    codec: row.get("codec"),
    stored_bytes: row.get("content"),
  })
}

fn object_record_from_sqlx_row(row: SqliteRow) -> Result<ObjectRecord> {
  let hash = Hash32::from_bytes(&row.get::<Vec<u8>, _>("hash"))?;
  super::object_record_from_row(super::StoredObjectRow {
    hash,
    kind: row.get("kind"),
    decoded_len: row.get("size"),
    codec: row.get("codec"),
    stored_bytes: row.get("content"),
  })
}

impl AsyncObjectSource for SqlxStore {
  async fn read_object(&self, hash: &Hash32) -> Result<Option<VerifiedObject>> {
    self.read_verified_object(hash).await
  }
}

async fn read_meta_value(pool: &SqlitePool, layout: &SqliteLayout, key: &str) -> Result<Option<String>> {
  let row = sqlx::query(AssertSqlSafe(layout.select_merkle_meta()))
    .bind(key)
    .fetch_optional(pool)
    .await?;
  Ok(row.map(|row| row.get::<String, _>("value")))
}

async fn read_meta_u64(pool: &SqlitePool, layout: &SqliteLayout, key: &str) -> Result<u64> {
  let value = read_meta_value(pool, layout, key)
    .await?
    .ok_or_else(|| Error::MissingMeta(key.to_string()))?;
  value.parse::<u64>().map_err(|_| Error::MissingMeta(key.to_string()))
}

async fn fetch_hash_by_pos(pool: &SqlitePool, layout: &SqliteLayout, level: Option<i64>, pos: u64) -> Result<Hash32> {
  let row = match level {
    Some(level) => {
      sqlx::query(AssertSqlSafe(layout.select_node_hash_at()))
        .bind(level)
        .bind(pos as i64)
        .fetch_one(pool)
        .await?
    }
    None => {
      sqlx::query(AssertSqlSafe(layout.select_leaf_hash_at()))
        .bind(pos as i64)
        .fetch_one(pool)
        .await?
    }
  };
  let bytes: Vec<u8> = row.get("hash");
  Hash32::from_bytes(&bytes)
}

#[cfg(test)]
mod tests;
