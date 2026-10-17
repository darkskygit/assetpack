use std::collections::{BTreeSet, HashSet};

use super::{Error, Hash32, MerkleMode, ObjectKind, ObjectSource, Result, RusqliteStore, parse_recipe_checked};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GcReport {
  pub deleted_chunks: u64,
  pub deleted_recipes: u64,
  pub freed_bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClosureReport {
  pub missing_objects: Vec<Hash32>,
  pub orphan_chunks: u64,
  pub orphan_recipes: u64,
}

impl RusqliteStore<'_> {
  /// Deletes objects and dangling file recipe cache entries in the caller's
  /// transaction.
  pub fn delete_objects(&self, hashes: &[Hash32]) -> Result<()> {
    self.gc_savepoint(|| {
      let sql = format!("DELETE FROM {} WHERE hash=?1", self.layout.objects);
      let mut statement = self.connection.prepare(&sql)?;
      for hash in hashes {
        statement.execute([hash.as_bytes().as_slice()])?;
      }
      self.finish_object_deletion()
    })
  }

  /// Collects objects outside the live recipe closure in the caller's
  /// transaction. All live recipes and chunk references are checked before
  /// any object is deleted.
  pub fn collect_garbage(&self, live_recipes: &[Hash32]) -> Result<GcReport> {
    self.gc_savepoint(|| {
      let (live, missing) = self.recipe_closure(live_recipes)?;
      if !missing.is_empty() {
        return Err(Error::Integrity(format!(
          "live recipe closure is missing {} objects",
          missing.len()
        )));
      }
      self
        .connection
        .execute_batch("CREATE TEMP TABLE assetpack_gc_live (hash BLOB PRIMARY KEY) WITHOUT ROWID;")?;
      {
        let mut insert = self.connection.prepare("INSERT INTO temp.assetpack_gc_live (hash) VALUES (?1)")?;
        for hash in live {
          insert.execute([hash.as_bytes().as_slice()])?;
        }
      }
      let orphan = format!(
        "NOT EXISTS (SELECT 1 FROM temp.assetpack_gc_live live WHERE live.hash={}.hash)",
        self.layout.objects
      );
      let sql = format!(
        "SELECT kind,COUNT(*),SUM(stored_size) FROM {} WHERE {orphan} GROUP BY kind",
        self.layout.objects
      );
      let mut statement = self.connection.prepare(&sql)?;
      let mut report = GcReport::default();
      for row in statement.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?)))? {
        let (kind, count, bytes) = row?;
        let count = u64::try_from(count).map_err(|_| Error::Integrity("negative orphan count".into()))?;
        let bytes = u64::try_from(bytes).map_err(|_| Error::Integrity("negative orphan stored size".into()))?;
        match ObjectKind::from_i64(kind) {
          Some(ObjectKind::Chunk) => report.deleted_chunks += count,
          Some(ObjectKind::Recipe) => report.deleted_recipes += count,
          None => return Err(Error::Integrity("invalid object kind during garbage collection".into())),
        }
        report.freed_bytes += bytes;
      }
      self
        .connection
        .execute(&format!("DELETE FROM {} WHERE {orphan}", self.layout.objects), [])?;
      self.finish_object_deletion()?;
      self.connection.execute("DROP TABLE temp.assetpack_gc_live", [])?;
      Ok(report)
    })
  }

  /// Reads recipes and object metadata only; this also works on read-only
  /// connections.
  pub fn check_closure(&self, live_recipes: &[Hash32]) -> Result<ClosureReport> {
    let (live, missing_objects) = self.recipe_closure(live_recipes)?;
    let mut report = ClosureReport {
      missing_objects,
      ..Default::default()
    };
    let mut statement = self.connection.prepare(&format!("SELECT hash,kind FROM {}", self.layout.objects))?;
    for row in statement.query_map([], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)))? {
      let (hash, kind) = row?;
      if live.contains(&Hash32::from_bytes(&hash)?) {
        continue;
      }
      match ObjectKind::from_i64(kind) {
        Some(ObjectKind::Chunk) => report.orphan_chunks += 1,
        Some(ObjectKind::Recipe) => report.orphan_recipes += 1,
        None => return Err(Error::Integrity("invalid object kind during closure check".into())),
      }
    }
    Ok(report)
  }

  fn recipe_closure(&self, live_recipes: &[Hash32]) -> Result<(HashSet<Hash32>, Vec<Hash32>)> {
    let mut live = HashSet::new();
    let mut missing = BTreeSet::new();
    let mut chunks = HashSet::new();
    for hash in live_recipes.iter().copied().collect::<BTreeSet<_>>() {
      live.insert(hash);
      let Some(object) = self.read_object(&hash)? else {
        missing.insert(hash);
        continue;
      };
      if object.kind != ObjectKind::Recipe {
        return Err(Error::ObjectKindMismatch {
          hash,
          expected: ObjectKind::Recipe,
          actual: object.kind,
        });
      }
      for (chunk, _) in parse_recipe_checked(&object.bytes, &hash)?.chunks {
        live.insert(chunk);
        chunks.insert(chunk);
      }
    }
    let mut statement = self
      .connection
      .prepare(&format!("SELECT kind FROM {} WHERE hash=?1", self.layout.objects))?;
    for hash in chunks {
      use rusqlite::OptionalExtension;
      let kind = statement
        .query_row([hash.as_bytes().as_slice()], |row| row.get::<_, i64>(0))
        .optional()?;
      match kind {
        None => {
          missing.insert(hash);
        }
        Some(kind) if kind == ObjectKind::Chunk as i64 => {}
        Some(kind) => {
          let actual = ObjectKind::from_i64(kind).ok_or_else(|| Error::Integrity("invalid chunk object kind".into()))?;
          return Err(Error::ObjectKindMismatch {
            hash,
            expected: ObjectKind::Chunk,
            actual,
          });
        }
      }
    }
    Ok((live, missing.into_iter().collect()))
  }

  fn gc_savepoint<T>(&self, action: impl FnOnce() -> Result<T>) -> Result<T> {
    if self.connection.is_autocommit() {
      return Err(Error::InvalidConfig("object deletion requires a caller transaction".into()));
    }
    self.connection.execute_batch("SAVEPOINT assetpack_object_deletion")?;
    match action() {
      Ok(value) => {
        self.connection.execute_batch("RELEASE assetpack_object_deletion")?;
        Ok(value)
      }
      Err(error) => {
        self
          .connection
          .execute_batch("ROLLBACK TO assetpack_object_deletion; RELEASE assetpack_object_deletion")?;
        Err(error)
      }
    }
  }

  fn finish_object_deletion(&self) -> Result<()> {
    self.connection.execute(
      &format!(
        "DELETE FROM {} WHERE NOT EXISTS (SELECT 1 FROM {} objects WHERE objects.hash=recipe_hash AND objects.kind={})",
        self.layout.file_recipe_cache,
        self.layout.objects,
        ObjectKind::Recipe as i64,
      ),
      [],
    )?;
    if self.merkle == MerkleMode::Enabled {
      self.rebuild_merkle_index()?;
    }
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use rusqlite::Connection;

  use super::{GcReport, RusqliteStore};
  use crate::{Codec, Hash32, MerkleMode, ObjectSource, SqliteStoreOptions, build_recipe};

  fn store(connection: &Connection) -> RusqliteStore<'_> {
    RusqliteStore::from_connection_with_options(
      connection,
      SqliteStoreOptions {
        namespace: Some("test".into()),
        merkle: MerkleMode::Disabled,
      },
    )
    .unwrap()
  }

  fn recipe(store: &RusqliteStore<'_>, content: &[u8], chunk: Hash32) -> Hash32 {
    let file = Hash32::sha3_256(content);
    let bytes = build_recipe(content.len() as u64, &[(chunk, content.len() as u32)], file, 0, 0);
    let hash = Hash32::sha3_256(&bytes);
    store.put_recipe(hash, &bytes, Codec::Raw).unwrap();
    store.put_file_recipe_cache_batch(&[(file, hash)]).unwrap();
    hash
  }

  #[test]
  fn garbage_collection_preserves_shared_chunks_and_cleans_recipe_cache() {
    let mut connection = Connection::open_in_memory().unwrap();
    let blobs = store(&connection);
    let shared = Hash32::sha3_256(b"shared");
    let orphan = Hash32::sha3_256(b"orphan");
    blobs.put_chunk(shared, b"shared", Codec::Raw).unwrap();
    blobs.put_chunk(orphan, b"orphan", Codec::Raw).unwrap();
    let live = recipe(&blobs, b"live", shared);
    let dead = recipe(&blobs, b"dead", shared);
    let closure = blobs.check_closure(&[live]).unwrap();
    assert!(closure.missing_objects.is_empty());
    assert_eq!((closure.orphan_chunks, closure.orphan_recipes), (1, 1));
    let dead_bytes = blobs.read_object(&dead).unwrap().unwrap().bytes.len() as u64;
    let transaction = connection.transaction().unwrap();
    let report = store(&transaction).collect_garbage(&[live, live]).unwrap();
    assert_eq!(
      report,
      GcReport {
        deleted_chunks: 1,
        deleted_recipes: 1,
        freed_bytes: 6 + dead_bytes
      }
    );
    transaction.commit().unwrap();
    let blobs = store(&connection);
    assert!(blobs.read_object(&shared).unwrap().is_some());
    assert!(blobs.read_object(&dead).unwrap().is_none());
    assert_eq!(blobs.recipe_for_file_hash(&Hash32::sha3_256(b"dead")).unwrap(), None);
    assert_eq!(blobs.recipe_for_file_hash(&Hash32::sha3_256(b"live")).unwrap(), Some(live));
    let transaction = connection.transaction().unwrap();
    store(&transaction).delete_objects(&[live]).unwrap();
    transaction.rollback().unwrap();
    assert_eq!(store(&connection).file_recipe_cache().unwrap().len(), 1);
    let transaction = connection.transaction().unwrap();
    store(&transaction).delete_objects(&[live]).unwrap();
    transaction.commit().unwrap();
    assert!(store(&connection).file_recipe_cache().unwrap().is_empty());
  }

  #[test]
  fn invalid_live_closure_never_deletes_objects_even_if_caller_commits() {
    for invalid in ["missing_recipe", "malformed_recipe", "missing_chunk", "wrong_kind"] {
      let mut connection = Connection::open_in_memory().unwrap();
      let blobs = store(&connection);
      let orphan = Hash32::sha3_256(b"keep-on-failure");
      blobs.put_chunk(orphan, b"keep-on-failure", Codec::Raw).unwrap();
      let live = match invalid {
        "missing_recipe" => Hash32::sha3_256(b"missing"),
        "malformed_recipe" => {
          let hash = Hash32::sha3_256(b"malformed");
          blobs.put_recipe(hash, b"malformed", Codec::Raw).unwrap();
          hash
        }
        "missing_chunk" => recipe(&blobs, b"live", Hash32::sha3_256(b"absent-chunk")),
        "wrong_kind" => orphan,
        _ => unreachable!(),
      };
      let before = blobs.verified_object_hashes().unwrap();
      let cache = blobs.file_recipe_cache().unwrap();
      let transaction = connection.transaction().unwrap();
      assert!(store(&transaction).collect_garbage(&[live]).is_err(), "{invalid}");
      transaction.commit().unwrap();
      assert_eq!(store(&connection).verified_object_hashes().unwrap(), before, "{invalid}");
      assert_eq!(store(&connection).file_recipe_cache().unwrap(), cache, "{invalid}");
    }
  }

  #[test]
  fn closure_check_is_read_only_and_gc_joins_host_rollback() {
    let mut connection = Connection::open_in_memory().unwrap();
    let blobs = store(&connection);
    let chunk = Hash32::sha3_256(b"chunk");
    blobs.put_chunk(chunk, b"chunk", Codec::Raw).unwrap();
    let live = recipe(&blobs, b"live", chunk);
    let missing = Hash32::sha3_256(b"missing");
    connection.pragma_update(None, "query_only", true).unwrap();
    let read_only = RusqliteStore::from_existing_connection_with_options(
      &connection,
      SqliteStoreOptions {
        namespace: Some("test".into()),
        merkle: MerkleMode::Disabled,
      },
    )
    .unwrap();
    assert_eq!(read_only.check_closure(&[live, missing]).unwrap().missing_objects, vec![missing]);
    connection.pragma_update(None, "query_only", false).unwrap();
    assert!(blobs.collect_garbage(&[]).is_err());
    assert!(blobs.delete_objects(&[chunk]).is_err());
    let transaction = connection.transaction().unwrap();
    assert_eq!(store(&transaction).collect_garbage(&[]).unwrap().deleted_chunks, 1);
    transaction.rollback().unwrap();
    assert!(store(&connection).read_object(&chunk).unwrap().is_some());
    let transaction = connection.transaction().unwrap();
    store(&transaction).collect_garbage(&[]).unwrap();
    transaction.commit().unwrap();
    assert!(store(&connection).verified_object_hashes().unwrap().is_empty());
    assert!(store(&connection).file_recipe_cache().unwrap().is_empty());
  }

  #[test]
  fn gc_failure_rolls_back_sweep_and_preserves_foreign_temp_table() {
    let mut connection = Connection::open_in_memory().unwrap();
    let blobs = store(&connection);
    let chunk = Hash32::sha3_256(b"chunk");
    blobs.put_chunk(chunk, b"chunk", Codec::Raw).unwrap();
    recipe(&blobs, b"live", chunk);
    connection
      .execute_batch("CREATE TEMP TABLE assetpack_gc_live (marker TEXT); INSERT INTO assetpack_gc_live VALUES ('caller');")
      .unwrap();
    let transaction = connection.transaction().unwrap();
    assert!(store(&transaction).collect_garbage(&[]).is_err());
    transaction.commit().unwrap();
    assert_eq!(
      connection
        .query_row("SELECT marker FROM temp.assetpack_gc_live", [], |row| row.get::<_, String>(0))
        .unwrap(),
      "caller"
    );
    connection
      .execute_batch(
        "DROP TABLE temp.assetpack_gc_live; CREATE TRIGGER fail_cache_delete BEFORE DELETE ON test_file_recipe_cache BEGIN SELECT \
         RAISE(ABORT, 'injected'); END;",
      )
      .unwrap();
    let before = store(&connection).verified_object_hashes().unwrap();
    let transaction = connection.transaction().unwrap();
    assert!(store(&transaction).collect_garbage(&[]).is_err());
    transaction.commit().unwrap();
    assert_eq!(store(&connection).verified_object_hashes().unwrap(), before);
    connection.execute_batch("DROP TRIGGER fail_cache_delete").unwrap();
    let transaction = connection.transaction().unwrap();
    store(&transaction).collect_garbage(&[]).unwrap();
    transaction.commit().unwrap();
    assert!(store(&connection).verified_object_hashes().unwrap().is_empty());
  }

  #[test]
  fn deletion_rebuilds_enabled_merkle_index_in_host_transaction() {
    let mut connection = Connection::open_in_memory().unwrap();
    let blobs = RusqliteStore::from_connection(&connection).unwrap();
    let chunk = Hash32::sha3_256(b"chunk");
    blobs.put_chunk(chunk, b"chunk", Codec::Raw).unwrap();
    let live = recipe(&blobs, b"live", chunk);
    let before = blobs.rebuild_merkle_index().unwrap();
    let transaction = connection.transaction().unwrap();
    let blobs = RusqliteStore::from_connection(&transaction).unwrap();
    blobs.collect_garbage(&[]).unwrap();
    assert_eq!(blobs.merkle_summary().unwrap().leaf_count, 0);
    transaction.rollback().unwrap();
    assert_eq!(
      RusqliteStore::from_connection(&connection).unwrap().merkle_summary().unwrap(),
      before
    );
    let transaction = connection.transaction().unwrap();
    let blobs = RusqliteStore::from_connection(&transaction).unwrap();
    blobs.delete_objects(&[live]).unwrap();
    assert_eq!(blobs.merkle_summary().unwrap(), blobs.recompute_merkle_summary().unwrap());
    assert_eq!(blobs.merkle_summary().unwrap().leaf_count, 1);
    transaction.commit().unwrap();
  }
}
