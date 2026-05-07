use std::{
  collections::{HashMap, HashSet, VecDeque},
  iter::repeat_n,
  path::{Path, PathBuf},
  sync::Arc,
};

use chrono::Utc;
use futures_core::stream::Stream;
use futures_util::{StreamExt, stream};
use sqlx::{
  Executor, QueryBuilder, Row, Sqlite, SqlitePool, Transaction,
  sqlite::{SqliteConnectOptions, SqliteJournalMode, SqliteRow},
};
use tokio::sync::Mutex;

use crate::{
  codec::{Codec, compress, decompress},
  error::{Error, Result},
  hash::Hash32,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
  Chunk = 1,
  Recipe = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackJournalMode {
  Delete,
  Wal,
}

impl PackJournalMode {
  fn to_sqlite(self) -> SqliteJournalMode {
    match self {
      PackJournalMode::Delete => SqliteJournalMode::Delete,
      PackJournalMode::Wal => SqliteJournalMode::Wal,
    }
  }
}

impl ObjectKind {
  pub(crate) fn from_i64(v: i64) -> Option<Self> {
    match v {
      1 => Some(ObjectKind::Chunk),
      2 => Some(ObjectKind::Recipe),
      _ => None,
    }
  }
}

#[derive(Debug, Clone)]
pub struct StoredObject {
  pub hash: Hash32,
  pub kind: ObjectKind,
  pub size: u64,
  pub codec: Codec,
  pub content: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ObjectRecord {
  pub hash: Hash32,
  pub kind: ObjectKind,
  pub size: u64,
  pub codec: Codec,
  pub content: Vec<u8>,
}

pub type PackWriteTx<'a> = Transaction<'a, Sqlite>;

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

#[derive(Default)]
struct MerkleCache {
  summary: Option<MerkleSummary>,
  leaf_pos: HashMap<Hash32, u64>,
  leaf_hashes: HashMap<u64, Hash32>,
  node_hashes: HashMap<i64, HashMap<u64, Hash32>>,
}

const FULL_SCAN_RATIO: f64 = 0.3;
const SQLITE_PARAM_LIMIT: usize = 999;
const OBJECT_COLUMNS: usize = 7;
const MAX_OBJECTS_PER_BATCH: usize = SQLITE_PARAM_LIMIT / OBJECT_COLUMNS;
const FILE_RECIPE_COLUMNS: usize = 3;
const MAX_FILE_RECIPE_PER_BATCH: usize = SQLITE_PARAM_LIMIT / FILE_RECIPE_COLUMNS;

#[derive(Clone)]
pub struct Pack {
  pool: SqlitePool,
  path: PathBuf,
  cache: Arc<Mutex<MerkleCache>>,
  journal_mode: PackJournalMode,
}

impl Pack {
  pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
    Self::open_with_journal(path, PackJournalMode::Delete).await
  }

  pub async fn open_with_journal(path: impl AsRef<Path>, journal_mode: PackJournalMode) -> Result<Self> {
    let path = path.as_ref().to_path_buf();
    if let Some(parent) = path.parent() {
      tokio::fs::create_dir_all(parent).await?;
    }
    let mut opts = SqliteConnectOptions::new().filename(&path).create_if_missing(true);
    opts = opts.journal_mode(journal_mode.to_sqlite());
    opts = opts.vfs(local_vfs_name());
    let pool = SqlitePool::connect_with(opts).await?;
    apply_schema(&pool).await?;
    Ok(Self {
      pool,
      path,
      cache: Arc::new(Mutex::new(MerkleCache::default())),
      journal_mode,
    })
  }

  pub async fn open_readonly(path: impl AsRef<Path>) -> Result<Self> {
    let path = path.as_ref().to_path_buf();
    let mut opts = SqliteConnectOptions::new().filename(&path).create_if_missing(false).read_only(true);
    opts = opts.vfs(local_vfs_name());
    let pool = SqlitePool::connect_with(opts).await?;
    Ok(Self {
      pool,
      path,
      cache: Arc::new(Mutex::new(MerkleCache::default())),
      journal_mode: PackJournalMode::Delete,
    })
  }

  pub fn path(&self) -> &Path {
    &self.path
  }

  pub async fn close(&self) {
    if self.journal_mode == PackJournalMode::Wal {
      let _ = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE);").execute(&self.pool).await;
    }
    self.pool.close().await;
  }

  pub async fn begin_write_tx(&self) -> Result<PackWriteTx<'_>> {
    Ok(self.pool.begin().await?)
  }

  pub async fn put_objects_batch_tx(tx: &mut PackWriteTx<'_>, objects: &[ObjectRecord]) -> Result<()> {
    if objects.is_empty() {
      return Ok(());
    }
    let now = Utc::now().timestamp();
    for chunk in objects.chunks(MAX_OBJECTS_PER_BATCH.max(1)) {
      let mut builder = QueryBuilder::new("INSERT OR IGNORE INTO objects (hash, kind, size, stored_size, codec, content, created_at) ");
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

  pub async fn put_file_recipe_cache_batch_tx(tx: &mut PackWriteTx<'_>, entries: &[(Hash32, Hash32)]) -> Result<()> {
    if entries.is_empty() {
      return Ok(());
    }
    let now = Utc::now().timestamp();
    for chunk in entries.chunks(MAX_FILE_RECIPE_PER_BATCH.max(1)) {
      let mut builder = QueryBuilder::new("INSERT INTO file_recipe_cache (file_hash, recipe_hash, updated_at) ");
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
    let stored_size = compressed.len() as i64;
    let codec_str = codec_to_str(final_codec);
    let now = Utc::now().timestamp();
    let mut tx = self.pool.begin().await?;

    sqlx::query(
      r#"INSERT OR IGNORE INTO objects (hash, kind, size, stored_size, codec, content, created_at)
              VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
    )
    .bind(hash.as_bytes().as_ref())
    .bind(kind as i64)
    .bind(size)
    .bind(stored_size)
    .bind(codec_str)
    .bind(compressed)
    .bind(now)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(())
  }

  pub async fn get_object(&self, hash: &Hash32) -> Result<Option<StoredObject>> {
    let row = sqlx::query(r#"SELECT kind, size, codec, content FROM objects WHERE hash = ?1"#)
      .bind(hash.as_bytes().as_ref())
      .fetch_optional(&self.pool)
      .await?;

    let Some(row) = row else {
      return Ok(None);
    };

    let kind = ObjectKind::from_i64(row.get::<i64, _>("kind")).ok_or_else(|| Error::Integrity("invalid kind".into()))?;
    let size: i64 = row.get("size");
    let codec_str: String = row.get("codec");
    let codec = codec_from_str(&codec_str)?;
    let stored: Vec<u8> = row.get("content");
    let decompressed = decompress(codec, &stored)?;
    if decompressed.len() as i64 != size {
      return Err(Error::Integrity("size mismatch".into()));
    }
    if Hash32::sha3_256(&decompressed) != *hash {
      return Err(Error::HashMismatch);
    }
    Ok(Some(StoredObject {
      hash: *hash,
      kind,
      size: size as u64,
      codec,
      content: decompressed,
    }))
  }

  pub async fn existing_hashes(&self, hashes: &[Hash32]) -> Result<HashSet<Hash32>> {
    let mut found = HashSet::new();
    if hashes.is_empty() {
      return Ok(found);
    }
    for chunk in hashes.chunks(SQLITE_PARAM_LIMIT.max(1)) {
      let mut builder = QueryBuilder::new("SELECT hash FROM objects WHERE hash IN (");
      let mut separated = builder.separated(", ");
      for hash in chunk {
        separated.push_bind(hash.as_bytes().as_ref());
      }
      separated.push_unseparated(")");
      let rows = builder.build().fetch_all(&self.pool).await?;
      for row in rows {
        let bytes: Vec<u8> = row.get("hash");
        found.insert(Hash32::from_bytes(&bytes).map_err(|_| Error::HashMismatch)?);
      }
    }
    Ok(found)
  }

  pub async fn chunk_stored_bytes(&self, hash: &Hash32) -> Result<Option<u64>> {
    let row = sqlx::query("SELECT kind, stored_size FROM objects WHERE hash=?1")
      .bind(hash.as_bytes().as_ref())
      .fetch_optional(&self.pool)
      .await?;
    let Some(row) = row else {
      return Ok(None);
    };
    let kind = ObjectKind::from_i64(row.get::<i64, _>("kind")).ok_or_else(|| Error::Integrity("invalid kind".into()))?;
    if kind != ObjectKind::Chunk {
      return Ok(None);
    }
    let stored_size: i64 = row.get("stored_size");
    Ok(Some(stored_size as u64))
  }

  pub async fn chunk_sizes(&self) -> Result<Vec<(Hash32, u64)>> {
    let rows = sqlx::query("SELECT hash, stored_size FROM objects WHERE kind=?1")
      .bind(ObjectKind::Chunk as i64)
      .fetch_all(&self.pool)
      .await?;
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
      let hash_bytes: Vec<u8> = row.get("hash");
      let hash = Hash32::from_bytes(&hash_bytes).map_err(|_| Error::HashMismatch)?;
      let stored_size: i64 = row.get("stored_size");
      items.push((hash, stored_size as u64));
    }
    Ok(items)
  }

  pub async fn file_recipe_cache(&self) -> Result<HashMap<Hash32, Hash32>> {
    if !self.file_recipe_cache_table_exists().await? {
      return Ok(HashMap::new());
    }
    let rows = sqlx::query("SELECT file_hash, recipe_hash FROM file_recipe_cache")
      .fetch_all(&self.pool)
      .await?;
    let mut map = HashMap::with_capacity(rows.len());
    for row in rows {
      let file_bytes: Vec<u8> = row.get("file_hash");
      let recipe_bytes: Vec<u8> = row.get("recipe_hash");
      let file_hash = Hash32::from_bytes(&file_bytes)?;
      let recipe_hash = Hash32::from_bytes(&recipe_bytes)?;
      map.insert(file_hash, recipe_hash);
    }
    Ok(map)
  }

  pub async fn recipe_for_file_hash(&self, file_hash: &Hash32) -> Result<Option<Hash32>> {
    if !self.file_recipe_cache_table_exists().await? {
      return Ok(None);
    }
    let row = sqlx::query("SELECT recipe_hash FROM file_recipe_cache WHERE file_hash=?1")
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
    let rows = sqlx::query("SELECT hash, kind, size, codec, content FROM objects ORDER BY hash ASC")
      .fetch_all(&self.pool)
      .await?;
    let mut objects = Vec::new();
    for row in rows {
      let hash_bytes: Vec<u8> = row.get("hash");
      let hash = Hash32::from_bytes(&hash_bytes).map_err(|_| Error::HashMismatch)?;
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
      objects.push(StoredObject {
        hash,
        kind,
        size: size as u64,
        codec,
        content,
      });
    }
    Ok(objects)
  }

  pub fn stream_object_records(&self) -> impl Stream<Item = Result<ObjectRecord>> + '_ {
    sqlx::query("SELECT hash, kind, size, codec, content FROM objects ORDER BY hash ASC")
      .fetch(&self.pool)
      .map(|row| match row {
        Ok(row) => object_record_from_row(row),
        Err(err) => Err(Error::from(err)),
      })
  }

  pub fn stream_object_records_with_batch_size(&self, batch_size: usize) -> impl Stream<Item = Result<ObjectRecord>> + '_ {
    let batch_size = batch_size.max(1);
    let pool = self.pool.clone();
    stream::try_unfold((0i64, VecDeque::new()), move |(offset, mut buffer)| {
      let pool = pool.clone();
      async move {
        if let Some(record) = buffer.pop_front() {
          return Ok(Some((record, (offset, buffer))));
        }

        let rows = sqlx::query("SELECT hash, kind, size, codec, content FROM objects ORDER BY hash ASC LIMIT ?1 OFFSET ?2")
          .bind(batch_size as i64)
          .bind(offset)
          .fetch_all(&pool)
          .await?;
        if rows.is_empty() {
          return Ok(None);
        }
        let rows_len = rows.len();
        for row in rows {
          buffer.push_back(object_record_from_row(row)?);
        }
        let record = buffer.pop_front().expect("buffer should contain fetched rows");
        Ok(Some((record, (offset + rows_len as i64, buffer))))
      }
    })
  }

  async fn file_recipe_cache_table_exists(&self) -> Result<bool> {
    let row = sqlx::query("SELECT name FROM sqlite_master WHERE type='table' AND name='file_recipe_cache'")
      .fetch_optional(&self.pool)
      .await?;
    Ok(row.is_some())
  }

  pub async fn rebuild_merkle_index(&self) -> Result<MerkleSummary> {
    let mut tx = self.pool.begin().await?;
    sqlx::query("DELETE FROM merkle_leaves").execute(&mut *tx).await?;
    sqlx::query("DELETE FROM merkle_nodes").execute(&mut *tx).await?;
    sqlx::query("DELETE FROM merkle_meta").execute(&mut *tx).await?;

    let rows = sqlx::query("SELECT hash FROM objects ORDER BY hash ASC")
      .fetch_all(&mut *tx)
      .await?;
    let mut leaves = Vec::new();
    for row in rows {
      let bytes: Vec<u8> = row.get("hash");
      leaves.push(Hash32::from_bytes(&bytes).map_err(|_| Error::HashMismatch)?);
    }

    for (idx, hash) in leaves.iter().enumerate() {
      sqlx::query("INSERT INTO merkle_leaves (hash, pos) VALUES (?1, ?2)")
        .bind(hash.as_bytes().as_ref())
        .bind(idx as i64)
        .execute(&mut *tx)
        .await?;
    }

    let leaf_count = leaves.len() as u64;
    let mut current = leaves.clone();
    let mut level = 0;
    let mut next_level = Vec::new();
    while current.len() > 1 {
      next_level.clear();
      for (i, chunk) in current.chunks(2).enumerate() {
        let left = chunk[0];
        let right = if chunk.len() > 1 { chunk[1] } else { chunk[0] };
        let parent = hash_pair(&left, &right);
        sqlx::query(
          "INSERT INTO merkle_nodes (level, pos, hash) VALUES (?1, ?2, ?3)
                     ON CONFLICT(level, pos) DO UPDATE SET hash=excluded.hash",
        )
        .bind(level as i64)
        .bind(i as i64)
        .bind(parent.as_bytes().as_ref())
        .execute(&mut *tx)
        .await?;
        next_level.push(parent);
      }
      current.clear();
      current.extend_from_slice(&next_level);
      level += 1;
    }

    let root = if current.is_empty() { Hash32::sha3_256([]) } else { current[0] };

    for (key, value) in [
      ("leaf_count", leaf_count.to_string()),
      ("root_hash", root.to_hex()),
      ("algo", "sha3-256".to_string()),
      ("tree", "merkle-set-v1".to_string()),
      ("sorted", "byte-lex".to_string()),
    ] {
      sqlx::query(
        "INSERT INTO merkle_meta (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value=excluded.value",
      )
      .bind(key)
      .bind(value)
      .execute(&mut *tx)
      .await?;
    }

    tx.commit().await?;
    let summary = MerkleSummary { root, leaf_count };
    let mut cache = self.cache.lock().await;
    cache.summary = Some(summary.clone());
    cache.leaf_pos.clear();
    cache.leaf_hashes.clear();
    cache.node_hashes.clear();
    Ok(summary)
  }

  pub async fn merkle_summary(&self) -> Result<MerkleSummary> {
    if let Some(summary) = self.cache.lock().await.summary.clone() {
      return Ok(summary);
    }
    let leaf_count = read_meta_u64(&self.pool, "leaf_count").await?;
    let root_hex = read_meta_value(&self.pool, "root_hash")
      .await?
      .ok_or_else(|| Error::MissingMeta("root_hash".into()))?;
    let root = Hash32::from_hex(&root_hex).map_err(|_| Error::MissingMeta("root_hash".into()))?;
    let summary = MerkleSummary { root, leaf_count };
    self.cache.lock().await.summary = Some(summary.clone());
    Ok(summary)
  }

  pub async fn recompute_merkle_summary(&self) -> Result<MerkleSummary> {
    let rows = sqlx::query("SELECT hash FROM merkle_leaves ORDER BY pos ASC")
      .fetch_all(&self.pool)
      .await?;
    let mut hashes = Vec::with_capacity(rows.len());
    for row in rows {
      let bytes: Vec<u8> = row.get("hash");
      hashes.push(Hash32::from_bytes(&bytes).map_err(|_| Error::HashMismatch)?);
    }
    let summary = merkle_root_from_hashes(&hashes);
    self.cache.lock().await.summary = Some(summary.clone());
    Ok(summary)
  }

  pub async fn prove_membership(&self, hash: &Hash32) -> Result<Option<MerkleProof>> {
    let summary = self.merkle_summary().await?;
    if summary.leaf_count == 0 {
      return Ok(None);
    }

    let row = sqlx::query("SELECT pos FROM merkle_leaves WHERE hash=?1")
      .bind(hash.as_bytes().as_ref())
      .fetch_optional(&self.pool)
      .await?;
    let Some(row) = row else {
      return Ok(None);
    };

    let mut pos: u64 = row.get::<i64, _>("pos") as u64;
    let mut count = summary.leaf_count;
    let mut siblings = Vec::new();
    let mut current_hash = *hash;
    let mut node_level: i64 = 0;
    let mut on_leaf = true;

    while count > 1 {
      let sibling_pos = pos ^ 1;
      let sibling_hash = if on_leaf {
        if sibling_pos >= count {
          current_hash
        } else {
          fetch_leaf_hash(&self.pool, sibling_pos).await?
        }
      } else if sibling_pos >= count {
        current_hash
      } else {
        fetch_node_hash(&self.pool, node_level, sibling_pos).await?
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

    Ok(Some(MerkleProof {
      leaf_pos: row.get::<i64, _>("pos") as u64,
      siblings,
    }))
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

  pub async fn integrity_check(&self) -> Result<()> {
    let row = sqlx::query("PRAGMA integrity_check;").fetch_one(&self.pool).await?;
    let status: String = row.get(0);
    if status.trim() == "ok" {
      Ok(())
    } else {
      Err(Error::Integrity(status))
    }
  }

  pub async fn prove_memberships_batch(&self, hashes: &[Hash32]) -> Result<Vec<Option<MerkleProof>>> {
    let summary = self.merkle_summary().await?;
    if summary.leaf_count == 0 {
      return Ok(vec![None; hashes.len()]);
    }

    let positions = self.fetch_positions(hashes, 800).await?;

    let mut need_leaf_pos = HashSet::new();
    for pos in positions.values() {
      let sib = pos ^ 1;
      if sib < summary.leaf_count {
        need_leaf_pos.insert(sib);
      }
    }

    let leaf_hash_by_pos = if need_leaf_pos.is_empty() {
      HashMap::new()
    } else if (need_leaf_pos.len() as f64) / (summary.leaf_count as f64) >= FULL_SCAN_RATIO {
      self.fetch_all_leaf_hashes(summary.leaf_count).await?
    } else {
      self
        .fetch_leaf_hashes_by_pos(&need_leaf_pos.into_iter().collect::<Vec<_>>(), 800)
        .await?
    };

    let level_counts = level_node_counts(summary.leaf_count);
    let mut need_nodes: Vec<HashSet<u64>> = vec![HashSet::new(); level_counts.len()];

    for pos in positions.values() {
      let mut current = *pos / 2;
      for (level, count) in level_counts.iter().enumerate() {
        let sib = current ^ 1;
        if sib < *count {
          need_nodes[level].insert(sib);
        }
        current /= 2;
      }
    }

    let mut node_hashes = HashMap::new();
    for (level, need) in need_nodes.iter().enumerate() {
      if need.is_empty() {
        continue;
      }
      let count = level_counts[level];
      let use_full_scan = count > 0 && (need.len() as f64) / (count as f64) >= FULL_SCAN_RATIO;
      let fetched = if use_full_scan {
        self.fetch_all_node_hashes(level as i64, count).await?
      } else {
        self
          .fetch_node_hashes_by_pos(level as i64, &need.iter().copied().collect::<Vec<_>>(), 800)
          .await?
      };
      for (pos, hash) in fetched {
        node_hashes.insert((level as i64, pos), hash);
      }
    }

    let mut proofs = Vec::with_capacity(hashes.len());
    for target in hashes {
      let Some(&leaf_pos) = positions.get(target) else {
        proofs.push(None);
        continue;
      };
      let mut siblings = Vec::new();
      let mut pos = leaf_pos;
      let mut count = summary.leaf_count;
      let mut level_idx: i64 = -1;
      let mut current_hash = *target;

      while count > 1 {
        let sib_pos = pos ^ 1;
        let sibling_hash = if level_idx == -1 {
          if sib_pos >= count {
            current_hash
          } else {
            match leaf_hash_by_pos.get(&sib_pos) {
              Some(h) => *h,
              None => fetch_leaf_hash(&self.pool, sib_pos).await?,
            }
          }
        } else if sib_pos >= count {
          current_hash
        } else {
          match node_hashes.get(&(level_idx, sib_pos)) {
            Some(h) => *h,
            None => fetch_node_hash(&self.pool, level_idx, sib_pos).await?,
          }
        };
        siblings.push(sibling_hash);

        let (left, right) = if pos % 2 == 0 {
          (current_hash, sibling_hash)
        } else {
          (sibling_hash, current_hash)
        };
        current_hash = hash_pair(&left, &right);

        pos /= 2;
        count = count.div_ceil(2);
        level_idx += 1;
      }

      proofs.push(Some(MerkleProof { leaf_pos, siblings }));
    }

    Ok(proofs)
  }

  async fn fetch_positions(&self, hashes: &[Hash32], chunk: usize) -> Result<HashMap<Hash32, u64>> {
    let mut map = HashMap::new();
    let mut missing = Vec::new();
    {
      let cache = self.cache.lock().await;
      for h in hashes {
        if let Some(pos) = cache.leaf_pos.get(h) {
          map.insert(*h, *pos);
        } else {
          missing.push(*h);
        }
      }
    }

    let mut fetched = HashMap::new();
    for group in missing.chunks(chunk) {
      let placeholders = repeat_n("?", group.len()).collect::<Vec<_>>().join(",");
      let sql = format!("SELECT hash, pos FROM merkle_leaves WHERE hash IN ({placeholders})");
      let mut query = sqlx::query(&sql);
      for h in group {
        query = query.bind(h.as_bytes().as_ref());
      }
      let rows = query.fetch_all(&self.pool).await?;
      for row in rows {
        let hash_bytes: Vec<u8> = row.get("hash");
        let hash = Hash32::from_bytes(&hash_bytes).map_err(|_| Error::HashMismatch)?;
        let pos: i64 = row.get("pos");
        fetched.insert(hash, pos as u64);
      }
    }

    map.extend(fetched.iter().map(|(h, pos)| (*h, *pos)));
    if !fetched.is_empty() {
      let mut cache = self.cache.lock().await;
      for (hash, pos) in fetched {
        cache.leaf_pos.insert(hash, pos);
      }
    }
    Ok(map)
  }

  async fn fetch_leaf_hashes_by_pos(&self, positions: &[u64], chunk: usize) -> Result<HashMap<u64, Hash32>> {
    let mut map = HashMap::new();
    let mut missing = Vec::new();
    {
      let cache = self.cache.lock().await;
      for pos in positions {
        if let Some(hash) = cache.leaf_hashes.get(pos) {
          map.insert(*pos, *hash);
        } else {
          missing.push(*pos);
        }
      }
    }

    let mut fetched = HashMap::new();
    for group in missing.chunks(chunk) {
      if group.is_empty() {
        continue;
      }
      let placeholders = repeat_n("?", group.len()).collect::<Vec<_>>().join(",");
      let sql = format!("SELECT pos, hash FROM merkle_leaves WHERE pos IN ({placeholders})");
      let mut query = sqlx::query(&sql);
      for pos in group {
        query = query.bind(*pos as i64);
      }
      let rows = query.fetch_all(&self.pool).await?;
      for row in rows {
        let pos: i64 = row.get("pos");
        let bytes: Vec<u8> = row.get("hash");
        fetched.insert(pos as u64, Hash32::from_bytes(&bytes).map_err(|_| Error::HashMismatch)?);
      }
    }

    map.extend(fetched.iter().map(|(pos, hash)| (*pos, *hash)));
    if !fetched.is_empty() {
      let mut cache = self.cache.lock().await;
      for (pos, hash) in fetched {
        cache.leaf_hashes.insert(pos, hash);
      }
    }
    Ok(map)
  }

  async fn fetch_node_hashes_by_pos(&self, level: i64, positions: &[u64], chunk: usize) -> Result<HashMap<u64, Hash32>> {
    let mut map = HashMap::new();
    let mut missing = Vec::new();
    {
      let cache = self.cache.lock().await;
      if let Some(level_cache) = cache.node_hashes.get(&level) {
        for pos in positions {
          if let Some(hash) = level_cache.get(pos) {
            map.insert(*pos, *hash);
          } else {
            missing.push(*pos);
          }
        }
      } else {
        missing.extend_from_slice(positions);
      }
    }

    let mut fetched = HashMap::new();
    for group in missing.chunks(chunk) {
      if group.is_empty() {
        continue;
      }
      let placeholders = repeat_n("?", group.len()).collect::<Vec<_>>().join(",");
      let sql = format!("SELECT pos, hash FROM merkle_nodes WHERE level=?1 AND pos IN ({placeholders})");
      let mut query = sqlx::query(&sql).bind(level);
      for pos in group {
        query = query.bind(*pos as i64);
      }
      let rows = query.fetch_all(&self.pool).await?;
      for row in rows {
        let pos: i64 = row.get("pos");
        let bytes: Vec<u8> = row.get("hash");
        fetched.insert(pos as u64, Hash32::from_bytes(&bytes).map_err(|_| Error::HashMismatch)?);
      }
    }

    map.extend(fetched.iter().map(|(pos, hash)| (*pos, *hash)));
    if !fetched.is_empty() {
      let mut cache = self.cache.lock().await;
      let level_cache = cache.node_hashes.entry(level).or_default();
      for (pos, hash) in fetched {
        level_cache.insert(pos, hash);
      }
    }
    Ok(map)
  }

  async fn fetch_all_leaf_hashes(&self, leaf_count: u64) -> Result<HashMap<u64, Hash32>> {
    if leaf_count == 0 {
      return Ok(HashMap::new());
    }
    if let Some(cached) = {
      let cache = self.cache.lock().await;
      if cache.leaf_hashes.len() == leaf_count as usize {
        Some(cache.leaf_hashes.clone())
      } else {
        None
      }
    } {
      return Ok(cached);
    }

    let rows = sqlx::query("SELECT pos, hash FROM merkle_leaves ORDER BY pos ASC")
      .fetch_all(&self.pool)
      .await?;
    let mut map = HashMap::with_capacity(rows.len());
    for row in rows {
      let pos: i64 = row.get("pos");
      let bytes: Vec<u8> = row.get("hash");
      map.insert(pos as u64, Hash32::from_bytes(&bytes).map_err(|_| Error::HashMismatch)?);
    }
    let mut cache = self.cache.lock().await;
    cache.leaf_hashes = map.clone();
    Ok(map)
  }

  async fn fetch_all_node_hashes(&self, level: i64, count: u64) -> Result<HashMap<u64, Hash32>> {
    if count == 0 {
      return Ok(HashMap::new());
    }
    if let Some(cached) = {
      let cache = self.cache.lock().await;
      if let Some(level_cache) = cache.node_hashes.get(&level) {
        if level_cache.len() == count as usize {
          Some(level_cache.clone())
        } else {
          None
        }
      } else {
        None
      }
    } {
      return Ok(cached);
    }

    let rows = sqlx::query("SELECT pos, hash FROM merkle_nodes WHERE level=?1")
      .bind(level)
      .fetch_all(&self.pool)
      .await?;
    let mut map = HashMap::with_capacity(rows.len());
    for row in rows {
      let pos: i64 = row.get("pos");
      let bytes: Vec<u8> = row.get("hash");
      map.insert(pos as u64, Hash32::from_bytes(&bytes).map_err(|_| Error::HashMismatch)?);
    }
    let mut cache = self.cache.lock().await;
    cache.node_hashes.insert(level, map.clone());
    Ok(map)
  }

  pub async fn verified_object_hashes(&self) -> Result<Vec<Hash32>> {
    let rows = sqlx::query("SELECT hash, kind, size, codec, content FROM objects ORDER BY hash ASC")
      .fetch_all(&self.pool)
      .await?;
    let mut hashes = Vec::with_capacity(rows.len());
    for row in rows {
      let hash_bytes: Vec<u8> = row.get("hash");
      let stored_hash = Hash32::from_bytes(&hash_bytes).map_err(|_| Error::HashMismatch)?;
      let size: i64 = row.get("size");
      let codec = codec_from_str(&row.get::<String, _>("codec"))?;
      let stored: Vec<u8> = row.get("content");
      let content = decompress(codec, &stored)?;
      if content.len() as i64 != size {
        return Err(Error::Integrity("size mismatch".into()));
      }
      if Hash32::sha3_256(&content) != stored_hash {
        return Err(Error::HashMismatch);
      }
      hashes.push(stored_hash);
    }
    Ok(hashes)
  }
}

fn object_record_from_row(row: SqliteRow) -> Result<ObjectRecord> {
  let hash_bytes: Vec<u8> = row.get("hash");
  let hash = Hash32::from_bytes(&hash_bytes).map_err(|_| Error::HashMismatch)?;
  let kind = ObjectKind::from_i64(row.get::<i64, _>("kind")).ok_or_else(|| Error::Integrity("invalid kind".into()))?;
  let size: i64 = row.get("size");
  let codec = codec_from_str(&row.get::<String, _>("codec"))?;
  let content: Vec<u8> = row.get("content");
  Ok(ObjectRecord {
    hash,
    kind,
    size: size as u64,
    codec,
    content,
  })
}

fn local_vfs_name() -> &'static str {
  if cfg!(windows) { "win32" } else { "unix" }
}

async fn apply_schema(pool: &SqlitePool) -> Result<()> {
  let statements = [
    r#"
        CREATE TABLE IF NOT EXISTS pack_meta (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );
        "#,
    r#"
        CREATE TABLE IF NOT EXISTS objects (
          hash BLOB PRIMARY KEY,
          kind INTEGER NOT NULL,
          size INTEGER NOT NULL,
          stored_size INTEGER NOT NULL,
          codec TEXT NOT NULL,
          content BLOB NOT NULL,
          created_at INTEGER NOT NULL
        );
        "#,
    r#"
        CREATE TABLE IF NOT EXISTS file_recipe_cache (
          file_hash BLOB PRIMARY KEY,
          recipe_hash BLOB NOT NULL,
          updated_at INTEGER NOT NULL
        );
        "#,
    r#"
        CREATE TABLE IF NOT EXISTS merkle_leaves (
          hash BLOB PRIMARY KEY,
          pos INTEGER NOT NULL
        );
        "#,
    r#"
        CREATE UNIQUE INDEX IF NOT EXISTS idx_merkle_leaves_pos ON merkle_leaves(pos);
        "#,
    r#"
        CREATE TABLE IF NOT EXISTS merkle_nodes (
          level INTEGER NOT NULL,
          pos INTEGER NOT NULL,
          hash BLOB NOT NULL,
          PRIMARY KEY(level, pos)
        );
        "#,
    r#"
        CREATE TABLE IF NOT EXISTS merkle_meta (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );
        "#,
  ];

  for stmt in statements {
    pool.execute(stmt).await?;
  }
  Ok(())
}

async fn read_meta_value(pool: &SqlitePool, key: &str) -> Result<Option<String>> {
  let row = sqlx::query("SELECT value FROM merkle_meta WHERE key=?1")
    .bind(key)
    .fetch_optional(pool)
    .await?;
  Ok(row.map(|r| r.get::<String, _>("value")))
}

async fn read_meta_u64(pool: &SqlitePool, key: &str) -> Result<u64> {
  let value = read_meta_value(pool, key)
    .await?
    .ok_or_else(|| Error::MissingMeta(key.to_string()))?;
  value.parse::<u64>().map_err(|_| Error::MissingMeta(key.to_string()))
}

async fn fetch_leaf_hash(pool: &SqlitePool, pos: u64) -> Result<Hash32> {
  let row = sqlx::query("SELECT hash FROM merkle_leaves WHERE pos=?1")
    .bind(pos as i64)
    .fetch_one(pool)
    .await?;
  let bytes: Vec<u8> = row.get("hash");
  Hash32::from_bytes(&bytes).map_err(|_| Error::HashMismatch)
}

async fn fetch_node_hash(pool: &SqlitePool, level: i64, pos: u64) -> Result<Hash32> {
  let row = sqlx::query("SELECT hash FROM merkle_nodes WHERE level=?1 AND pos=?2")
    .bind(level)
    .bind(pos as i64)
    .fetch_one(pool)
    .await?;
  let bytes: Vec<u8> = row.get("hash");
  Hash32::from_bytes(&bytes).map_err(|_| Error::HashMismatch)
}

fn hash_pair(left: &Hash32, right: &Hash32) -> Hash32 {
  let mut buf = Vec::with_capacity(64);
  buf.extend_from_slice(left.as_bytes());
  buf.extend_from_slice(right.as_bytes());
  Hash32::sha3_256(buf)
}

pub fn merkle_root_from_hashes(hashes: &[Hash32]) -> MerkleSummary {
  if hashes.is_empty() {
    return MerkleSummary {
      root: Hash32::sha3_256([]),
      leaf_count: 0,
    };
  }
  let mut current: Vec<Hash32> = hashes.to_vec();
  let mut next_level = Vec::new();
  while current.len() > 1 {
    next_level.clear();
    for chunk in current.chunks(2) {
      let left = chunk[0];
      let right = if chunk.len() > 1 { chunk[1] } else { chunk[0] };
      next_level.push(hash_pair(&left, &right));
    }
    current.clear();
    current.extend_from_slice(&next_level);
  }
  MerkleSummary {
    root: current[0],
    leaf_count: hashes.len() as u64,
  }
}

fn codec_to_str(codec: Codec) -> &'static str {
  match codec {
    Codec::Raw => "raw",
    Codec::Zstd => "zstd",
    Codec::Brotli => "brotli",
  }
}

fn codec_from_str(s: &str) -> Result<Codec> {
  match s {
    "raw" => Ok(Codec::Raw),
    "zstd" => Ok(Codec::Zstd),
    "brotli" => Ok(Codec::Brotli),
    other => Err(Error::InvalidCodec(other.to_string())),
  }
}

fn level_node_counts(mut leaf_count: u64) -> Vec<u64> {
  let mut counts = Vec::new();
  while leaf_count > 1 {
    leaf_count = leaf_count.div_ceil(2);
    counts.push(leaf_count);
  }
  counts
}

#[cfg(test)]
mod tests {
  use std::{collections::HashMap, fs};

  use futures_util::TryStreamExt;
  use rand::RngCore;
  use tempfile::tempdir;

  use super::*;

  #[tokio::test]
  async fn write_and_read_object_roundtrip() {
    let dir = tempdir().unwrap();
    let pack_path = dir.path().join("test.db");
    let pack = Pack::open(&pack_path).await.unwrap();

    let mut data = vec![0u8; 4096];
    rand::rng().fill_bytes(&mut data);
    let hash = Hash32::sha3_256(&data);

    pack.put_chunk(hash, &data, Codec::Zstd).await.unwrap();
    let loaded = pack.get_object(&hash).await.unwrap().unwrap();
    assert_eq!(loaded.hash, hash);
    assert_eq!(loaded.kind, ObjectKind::Chunk);
    assert_eq!(loaded.content, data);
  }

  #[tokio::test]
  async fn compression_falls_back_to_raw_when_not_smaller() {
    let dir = tempdir().unwrap();
    let pack_path = dir.path().join("small.db");
    let pack = Pack::open(&pack_path).await.unwrap();

    // Very small data compresses poorly; should store as raw even if codec asks for
    // zstd.
    let data = b"abcde".to_vec();
    let hash = Hash32::sha3_256(&data);
    pack.put_chunk(hash, &data, Codec::Zstd).await.unwrap();

    let stored = pack.get_object(&hash).await.unwrap().unwrap();
    assert_eq!(stored.codec, Codec::Raw);
    assert_eq!(stored.content, data);
  }

  #[tokio::test]
  async fn rebuild_merkle_and_prove_membership() {
    let dir = tempdir().unwrap();
    let pack_path = dir.path().join("pack.db");
    let pack = Pack::open(&pack_path).await.unwrap();
    let items = vec![b"foo".to_vec(), b"bar".to_vec(), b"baz".to_vec()];
    for item in &items {
      let h = Hash32::sha3_256(item);
      pack.put_chunk(h, item, Codec::Raw).await.unwrap();
    }

    let summary = pack.rebuild_merkle_index().await.unwrap();
    assert_eq!(summary.leaf_count, items.len() as u64);

    let target = Hash32::sha3_256(b"bar");
    let proof = pack.prove_membership(&target).await.unwrap().unwrap();
    assert!(Pack::verify_proof(&target, &proof, &summary.root, summary.leaf_count));
  }

  #[tokio::test]
  async fn batch_proofs_match_individual() {
    let dir = tempdir().unwrap();
    let pack_path = dir.path().join("pack.db");
    let pack = Pack::open(&pack_path).await.unwrap();
    let items = vec![b"foo".to_vec(), b"bar".to_vec(), b"baz".to_vec()];
    let mut hashes = Vec::new();
    for item in &items {
      let h = Hash32::sha3_256(item);
      pack.put_chunk(h, item, Codec::Raw).await.unwrap();
      hashes.push(h);
    }
    let summary = pack.rebuild_merkle_index().await.unwrap();

    let batch = pack.prove_memberships_batch(&hashes).await.unwrap().into_iter().collect::<Vec<_>>();
    for (hash, proof_opt) in hashes.iter().zip(batch.into_iter()) {
      let proof = proof_opt.expect("proof expected");
      assert!(Pack::verify_proof(hash, &proof, &summary.root, summary.leaf_count));
    }

    let missing = Hash32::sha3_256("missing");
    let proofs = pack
      .prove_memberships_batch(&[missing])
      .await
      .unwrap()
      .into_iter()
      .collect::<Vec<_>>();
    assert!(proofs[0].is_none());
  }

  #[tokio::test]
  async fn batch_proofs_cover_sparse_and_full_scan() {
    let dir = tempdir().unwrap();
    let pack_path = dir.path().join("batch.db");
    let pack = Pack::open(&pack_path).await.unwrap();
    let mut hashes = Vec::new();
    for i in 0..64u8 {
      let data = format!("item-{i}").into_bytes();
      let hash = Hash32::sha3_256(&data);
      pack.put_chunk(hash, &data, Codec::Raw).await.unwrap();
      hashes.push(hash);
    }
    let summary = pack.rebuild_merkle_index().await.unwrap();

    let sparse = vec![hashes[0], hashes[1], hashes[2]];
    let sparse_proofs = pack.prove_memberships_batch(&sparse).await.unwrap();
    for (hash, proof_opt) in sparse.iter().zip(sparse_proofs.into_iter()) {
      let proof = proof_opt.expect("sparse proof expected");
      assert!(Pack::verify_proof(hash, &proof, &summary.root, summary.leaf_count));
    }

    let full_proofs = pack.prove_memberships_batch(&hashes).await.unwrap();
    for (hash, proof_opt) in hashes.iter().zip(full_proofs.into_iter()) {
      let proof = proof_opt.expect("full proof expected");
      assert!(Pack::verify_proof(hash, &proof, &summary.root, summary.leaf_count));
    }
  }

  #[tokio::test]
  async fn stream_object_records_matches_all_objects() {
    let dir = tempdir().unwrap();
    let pack_path = dir.path().join("stream.db");
    let pack = Pack::open(&pack_path).await.unwrap();

    let payloads = vec![b"alpha".to_vec(), b"beta".to_vec(), b"gamma".to_vec()];
    for payload in &payloads {
      let hash = Hash32::sha3_256(payload);
      pack.put_chunk(hash, payload, Codec::Raw).await.unwrap();
    }

    let recipe = b"recipe-bytes".to_vec();
    let recipe_hash = Hash32::sha3_256(&recipe);
    pack.put_recipe(recipe_hash, &recipe, Codec::Raw).await.unwrap();

    let expected = pack.all_objects().await.unwrap();
    let expected_map: HashMap<Hash32, (ObjectKind, u64, Codec)> = expected
      .into_iter()
      .map(|obj| (obj.hash, (obj.kind, obj.size, obj.codec)))
      .collect();

    let streamed = pack.stream_object_records().try_collect::<Vec<_>>().await.unwrap();
    assert_eq!(streamed.len(), expected_map.len());
    for record in streamed {
      let expected = expected_map.get(&record.hash).unwrap();
      assert_eq!(record.kind, expected.0);
      assert_eq!(record.size, expected.1);
      assert_eq!(record.codec, expected.2);
    }

    let streamed_batched = pack.stream_object_records_with_batch_size(2).try_collect::<Vec<_>>().await.unwrap();
    assert_eq!(streamed_batched.len(), expected_map.len());
    for record in streamed_batched {
      let expected = expected_map.get(&record.hash).unwrap();
      assert_eq!(record.kind, expected.0);
      assert_eq!(record.size, expected.1);
      assert_eq!(record.codec, expected.2);
    }
  }

  #[tokio::test]
  async fn integrity_check_passes() {
    let dir = tempdir().unwrap();
    let pack_path = dir.path().join("ok.db");
    let pack = Pack::open(&pack_path).await.unwrap();
    pack.integrity_check().await.unwrap();
  }

  #[tokio::test]
  async fn open_with_journal_wal_truncates() {
    let dir = tempdir().unwrap();
    let pack_path = dir.path().join("wal.db");
    let pack = Pack::open_with_journal(&pack_path, PackJournalMode::Wal).await.unwrap();
    let data = b"wal-check".to_vec();
    let hash = Hash32::sha3_256(&data);
    pack.put_chunk(hash, &data, Codec::Raw).await.unwrap();
    pack.close().await;

    let wal_path = pack_path.with_extension("db-wal");
    if wal_path.exists() {
      let len = fs::metadata(&wal_path).unwrap().len();
      assert_eq!(len, 0);
    }

    let reopened = Pack::open_readonly(&pack_path).await.unwrap();
    let loaded = reopened.get_object(&hash).await.unwrap().unwrap();
    assert_eq!(loaded.content, data);
  }
}
