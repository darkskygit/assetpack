use std::collections::{HashMap, HashSet};

use rusqlite::{Connection, OptionalExtension, params, params_from_iter};

use super::{
  MerkleMode, MerkleProof, MerkleSummary, SqliteLayout, SqliteStoreOptions, StoredObjectRow, codec_to_str, hash_pair,
  merkle_root_from_hashes, object_record_from_row, prepare_object, schema_statements, verified_object_from_row,
};
use crate::{Codec, Error, Hash32, ObjectKind, ObjectRecord, ObjectSource, Result, VerifiedObject};

pub struct RusqliteStore<'connection> {
  connection: &'connection Connection,
  layout: SqliteLayout,
  merkle: MerkleMode,
}

impl<'connection> RusqliteStore<'connection> {
  pub fn from_connection(connection: &'connection Connection) -> Result<Self> {
    Self::from_connection_with_options(connection, SqliteStoreOptions::default())
  }

  pub fn from_connection_with_namespace(connection: &'connection Connection, namespace: impl AsRef<str>) -> Result<Self> {
    Self::from_connection_with_options(
      connection,
      SqliteStoreOptions {
        namespace: Some(namespace.as_ref().to_string()),
        ..Default::default()
      },
    )
  }

  pub fn from_connection_with_options(connection: &'connection Connection, options: SqliteStoreOptions) -> Result<Self> {
    let layout = SqliteLayout::new(options.namespace.as_deref())?;
    for statement in schema_statements(&layout, options.merkle) {
      connection.execute_batch(&statement)?;
    }
    Ok(Self::view(connection, options, layout))
  }

  pub(in crate::sqlite) fn view(connection: &'connection Connection, options: SqliteStoreOptions, layout: SqliteLayout) -> Self {
    Self {
      connection,
      layout,
      merkle: options.merkle,
    }
  }

  pub fn ensure_schema(connection: &Connection) -> Result<()> {
    Self::ensure_schema_with_options(connection, &SqliteStoreOptions::default())
  }

  pub fn ensure_schema_with_options(connection: &Connection, options: &SqliteStoreOptions) -> Result<()> {
    let layout = SqliteLayout::new(options.namespace.as_deref())?;
    for statement in schema_statements(&layout, options.merkle) {
      connection.execute_batch(&statement)?;
    }
    Ok(())
  }

  pub fn connection(&self) -> &Connection {
    self.connection
  }

  pub fn namespace(&self) -> Option<&str> {
    self.layout.namespace.as_deref()
  }

  pub fn merkle_mode(&self) -> MerkleMode {
    self.merkle
  }

  pub fn put_objects_batch(&self, objects: &[ObjectRecord]) -> Result<()> {
    if objects.is_empty() {
      return Ok(());
    }
    let sql = self.layout.insert_object();
    let mut statement = self.connection.prepare_cached(&sql)?;
    for object in objects {
      statement.execute(params![
        object.hash.as_bytes().as_slice(),
        object.kind as i64,
        i64::try_from(object.decoded_len).map_err(|_| Error::Integrity("object size exceeds SQLite integer".into()))?,
        i64::try_from(object.stored_bytes.len()).map_err(|_| Error::Integrity("stored size exceeds SQLite integer".into()))?,
        codec_to_str(object.codec),
        &object.stored_bytes,
        unix_timestamp(),
      ])?;
    }
    Ok(())
  }

  pub fn put_file_recipe_cache_batch(&self, entries: &[(Hash32, Hash32)]) -> Result<()> {
    let sql = self.layout.upsert_recipe_cache();
    let mut statement = self.connection.prepare_cached(&sql)?;
    for (file_hash, recipe_hash) in entries {
      statement.execute(params![
        file_hash.as_bytes().as_slice(),
        recipe_hash.as_bytes().as_slice(),
        unix_timestamp()
      ])?;
    }
    Ok(())
  }

  pub fn put_chunk(&self, hash: Hash32, content: &[u8], codec: Codec) -> Result<()> {
    self.put_object(hash, ObjectKind::Chunk, content, codec)
  }

  pub fn put_recipe(&self, hash: Hash32, content: &[u8], codec: Codec) -> Result<()> {
    self.put_object(hash, ObjectKind::Recipe, content, codec)
  }

  fn put_object(&self, hash: Hash32, kind: ObjectKind, content: &[u8], codec: Codec) -> Result<()> {
    self.put_objects_batch(&[prepare_object(hash, kind, content, codec)?])
  }

  pub fn read_object_record(&self, hash: &Hash32) -> Result<Option<ObjectRecord>> {
    let sql = self.layout.select_object();
    self
      .connection
      .query_row(&sql, [hash.as_bytes().as_slice()], stored_row)
      .optional()?
      .map(object_record_from_row)
      .transpose()
  }

  pub fn existing_hashes(&self, hashes: &[Hash32]) -> Result<HashSet<Hash32>> {
    let mut found = HashSet::new();
    for chunk in hashes.chunks(999) {
      if chunk.is_empty() {
        continue;
      }
      let placeholders = std::iter::repeat_n("?", chunk.len()).collect::<Vec<_>>().join(",");
      let sql = format!("{}{placeholders})", self.layout.select_hashes_prefix());
      let values = chunk.iter().map(|hash| hash.as_bytes().as_slice());
      let mut statement = self.connection.prepare(&sql)?;
      let rows = statement.query_map(params_from_iter(values), |row| row.get::<_, Vec<u8>>(0))?;
      for row in rows {
        found.insert(Hash32::from_bytes(&row?)?);
      }
    }
    Ok(found)
  }

  pub fn chunk_stored_bytes(&self, hash: &Hash32) -> Result<Option<u64>> {
    let sql = self.layout.select_chunk_stored_size();
    let value = self
      .connection
      .query_row(&sql, [hash.as_bytes().as_slice()], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
      })
      .optional()?;
    match value {
      Some((kind, size)) if kind == ObjectKind::Chunk as i64 => {
        Ok(Some(size.try_into().map_err(|_| Error::Integrity("negative stored size".into()))?))
      }
      _ => Ok(None),
    }
  }

  pub fn chunk_sizes(&self) -> Result<Vec<(Hash32, u64)>> {
    let sql = self.layout.select_chunk_sizes();
    let mut statement = self.connection.prepare(&sql)?;
    let rows = statement.query_map([ObjectKind::Chunk as i64], |row| {
      Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
    })?;
    rows
      .map(|row| {
        let (hash, size) = row?;
        Ok((
          Hash32::from_bytes(&hash)?,
          size.try_into().map_err(|_| Error::Integrity("negative stored size".into()))?,
        ))
      })
      .collect()
  }

  pub fn file_recipe_cache(&self) -> Result<HashMap<Hash32, Hash32>> {
    let sql = self.layout.select_recipe_cache();
    let mut statement = self.connection.prepare(&sql)?;
    let rows = statement.query_map([], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)))?;
    let mut cache = HashMap::new();
    for row in rows {
      let (file, recipe) = row?;
      cache.insert(Hash32::from_bytes(&file)?, Hash32::from_bytes(&recipe)?);
    }
    Ok(cache)
  }

  pub fn recipe_for_file_hash(&self, file_hash: &Hash32) -> Result<Option<Hash32>> {
    let sql = self.layout.select_recipe_for_file();
    self
      .connection
      .query_row(&sql, [file_hash.as_bytes().as_slice()], |row| row.get::<_, Vec<u8>>(0))
      .optional()?
      .map(|bytes| Hash32::from_bytes(&bytes))
      .transpose()
  }

  pub fn all_objects(&self) -> Result<Vec<VerifiedObject>> {
    let sql = self.layout.select_objects();
    let mut statement = self.connection.prepare(&sql)?;
    statement
      .query_map([], stored_row)?
      .map(|row| verified_object_from_row(row?))
      .collect()
  }

  pub fn object_records(&self, offset: u64, limit: usize) -> Result<Vec<ObjectRecord>> {
    let sql = self.layout.select_object_records();
    let mut statement = self.connection.prepare(&sql)?;
    statement
      .query_map(params![limit as i64, offset as i64], stored_row)?
      .map(|row| object_record_from_row(row?))
      .collect()
  }

  pub fn integrity_check(&self) -> Result<()> {
    let status: String = self
      .connection
      .query_row(super::statements::INTEGRITY_CHECK, [], |row| row.get(0))?;
    if status.trim() == "ok" {
      Ok(())
    } else {
      Err(Error::Integrity(status))
    }
  }

  pub fn rebuild_merkle_index(&self) -> Result<MerkleSummary> {
    self.ensure_merkle_enabled()?;
    self.connection.execute(&self.layout.delete_merkle_leaves(), [])?;
    self.connection.execute(&self.layout.delete_merkle_nodes(), [])?;
    self.connection.execute(&self.layout.delete_merkle_meta(), [])?;
    let hashes = self.object_hashes()?;
    let leaf_sql = self.layout.insert_merkle_leaf();
    let mut leaf_statement = self.connection.prepare_cached(&leaf_sql)?;
    for (position, hash) in hashes.iter().enumerate() {
      leaf_statement.execute(params![hash.as_bytes().as_slice(), position as i64])?;
    }
    let mut current = hashes.clone();
    let node_sql = self.layout.insert_merkle_node();
    let mut node_statement = self.connection.prepare_cached(&node_sql)?;
    let mut level = 0i64;
    while current.len() > 1 {
      let next = current
        .chunks(2)
        .enumerate()
        .map(|(position, pair)| {
          let parent = hash_pair(&pair[0], pair.get(1).unwrap_or(&pair[0]));
          node_statement.execute(params![level, position as i64, parent.as_bytes().as_slice()])?;
          Ok(parent)
        })
        .collect::<Result<Vec<_>>>()?;
      current = next;
      level += 1;
    }
    let summary = merkle_root_from_hashes(&hashes);
    let meta_sql = self.layout.upsert_merkle_meta();
    let mut statement = self.connection.prepare_cached(&meta_sql)?;
    for (key, value) in [
      ("leaf_count", summary.leaf_count.to_string()),
      ("root_hash", summary.root.to_hex()),
      ("algo", "sha3-256".into()),
      ("tree", "merkle-set-v1".into()),
      ("sorted", "byte-lex".into()),
    ] {
      statement.execute(params![key, value])?;
    }
    Ok(summary)
  }

  pub fn merkle_summary(&self) -> Result<MerkleSummary> {
    self.ensure_merkle_enabled()?;
    let leaf_count = self
      .meta("leaf_count")?
      .parse()
      .map_err(|_| Error::MissingMeta("leaf_count".into()))?;
    let root = Hash32::from_hex(&self.meta("root_hash")?).map_err(|_| Error::MissingMeta("root_hash".into()))?;
    Ok(MerkleSummary { root, leaf_count })
  }

  pub fn recompute_merkle_summary(&self) -> Result<MerkleSummary> {
    self.ensure_merkle_enabled()?;
    let sql = self.layout.select_merkle_hashes();
    let mut statement = self.connection.prepare(&sql)?;
    let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
    let hashes = rows.map(|row| Hash32::from_bytes(&row?)).collect::<Result<Vec<_>>>()?;
    Ok(merkle_root_from_hashes(&hashes))
  }

  pub fn prove_membership(&self, hash: &Hash32) -> Result<Option<MerkleProof>> {
    let summary = self.merkle_summary()?;
    let position_sql = self.layout.select_merkle_position();
    let Some(mut position) = self
      .connection
      .query_row(&position_sql, [hash.as_bytes().as_slice()], |row| row.get::<_, i64>(0))
      .optional()?
    else {
      return Ok(None);
    };
    let leaf_pos = position as u64;
    let mut count = summary.leaf_count;
    let mut current = *hash;
    let mut level = -1i64;
    let mut siblings = Vec::new();
    while count > 1 {
      let sibling_pos = (position as u64) ^ 1;
      let sibling = if sibling_pos >= count {
        current
      } else {
        self.hash_at(level, sibling_pos)?
      };
      siblings.push(sibling);
      current = if position % 2 == 0 {
        hash_pair(&current, &sibling)
      } else {
        hash_pair(&sibling, &current)
      };
      position /= 2;
      count = count.div_ceil(2);
      level += 1;
    }
    Ok(Some(MerkleProof { leaf_pos, siblings }))
  }

  pub fn prove_memberships_batch(&self, hashes: &[Hash32]) -> Result<Vec<Option<MerkleProof>>> {
    hashes.iter().map(|hash| self.prove_membership(hash)).collect()
  }

  pub fn verify_proof(target: &Hash32, proof: &MerkleProof, expected_root: &Hash32, leaf_count: u64) -> bool {
    if leaf_count == 0 {
      return false;
    }
    let mut current = *target;
    let mut position = proof.leaf_pos;
    for sibling in &proof.siblings {
      current = if position.is_multiple_of(2) {
        hash_pair(&current, sibling)
      } else {
        hash_pair(sibling, &current)
      };
      position /= 2;
    }
    current == *expected_root
  }

  pub fn verified_object_hashes(&self) -> Result<Vec<Hash32>> {
    Ok(self.all_objects()?.into_iter().map(|object| object.hash).collect())
  }

  fn object_hashes(&self) -> Result<Vec<Hash32>> {
    let sql = self.layout.select_object_hashes();
    let mut statement = self.connection.prepare(&sql)?;
    statement
      .query_map([], |row| row.get::<_, Vec<u8>>(0))?
      .map(|row| Hash32::from_bytes(&row?))
      .collect()
  }

  fn meta(&self, key: &str) -> Result<String> {
    let sql = self.layout.select_merkle_meta();
    self
      .connection
      .query_row(&sql, [key], |row| row.get(0))
      .optional()?
      .ok_or_else(|| Error::MissingMeta(key.into()))
  }

  fn hash_at(&self, level: i64, position: u64) -> Result<Hash32> {
    let (sql, values): (String, Vec<i64>) = if level < 0 {
      (self.layout.select_leaf_hash_at(), vec![position as i64])
    } else {
      (self.layout.select_node_hash_at(), vec![level, position as i64])
    };
    let bytes: Vec<u8> = self.connection.query_row(&sql, params_from_iter(values), |row| row.get(0))?;
    Hash32::from_bytes(&bytes)
  }

  fn ensure_merkle_enabled(&self) -> Result<()> {
    if self.merkle == MerkleMode::Enabled {
      Ok(())
    } else {
      Err(Error::Integrity("merkle disabled for sqlite store".into()))
    }
  }
}

impl ObjectSource for RusqliteStore<'_> {
  fn read_object(&self, hash: &Hash32) -> Result<Option<VerifiedObject>> {
    let sql = self.layout.select_object();
    self
      .connection
      .query_row(&sql, [hash.as_bytes().as_slice()], stored_row)
      .optional()?
      .map(verified_object_from_row)
      .transpose()
  }
}

fn stored_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredObjectRow> {
  let hash = row.get::<_, Vec<u8>>(0)?;
  Ok(StoredObjectRow {
    hash: Hash32::from_bytes(&hash).map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?,
    kind: row.get(1)?,
    decoded_len: row.get(2)?,
    codec: row.get(3)?,
    stored_bytes: row.get(4)?,
  })
}

fn unix_timestamp() -> i64 {
  std::time::UNIX_EPOCH.elapsed().unwrap_or_default().as_secs() as i64
}
