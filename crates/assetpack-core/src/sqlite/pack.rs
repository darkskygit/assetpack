use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags};

use super::{MerkleProof, MerkleSummary, RusqliteStore, SqliteLayout, SqliteStoreOptions};
use crate::{Codec, Hash32, ObjectRecord, ObjectSource, Result, VerifiedObject};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlitePackJournalMode {
  Delete,
  Wal,
}

pub struct SqlitePack {
  connection: Connection,
  path: PathBuf,
  journal_mode: SqlitePackJournalMode,
  options: SqliteStoreOptions,
}

impl SqlitePack {
  pub fn open(path: impl AsRef<Path>) -> Result<Self> {
    Self::open_with_journal(path, SqlitePackJournalMode::Delete)
  }

  pub fn open_with_journal(path: impl AsRef<Path>, journal_mode: SqlitePackJournalMode) -> Result<Self> {
    let path = path.as_ref().to_path_buf();
    if let Some(parent) = path.parent() {
      std::fs::create_dir_all(parent)?;
    }
    let connection = Connection::open(&path)?;
    connection.pragma_update(
      None,
      "journal_mode",
      match journal_mode {
        SqlitePackJournalMode::Delete => "DELETE",
        SqlitePackJournalMode::Wal => "WAL",
      },
    )?;
    let options = SqliteStoreOptions::default();
    RusqliteStore::ensure_schema_with_options(&connection, &options)?;
    Ok(Self {
      connection,
      path,
      journal_mode,
      options,
    })
  }

  pub fn open_readonly(path: impl AsRef<Path>) -> Result<Self> {
    let path = path.as_ref().to_path_buf();
    let connection = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    Ok(Self {
      connection,
      path,
      journal_mode: SqlitePackJournalMode::Delete,
      options: SqliteStoreOptions::default(),
    })
  }

  pub fn path(&self) -> &Path {
    &self.path
  }

  pub fn close(self) -> Result<()> {
    if self.journal_mode == SqlitePackJournalMode::Wal {
      self.connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    }
    self.connection.close().map_err(|(_, error)| error)?;
    Ok(())
  }

  pub fn transaction<T>(&mut self, operation: impl FnOnce(&RusqliteStore<'_>) -> Result<T>) -> Result<T> {
    let transaction = self.connection.transaction()?;
    let result = {
      let layout = SqliteLayout::new(self.options.namespace.as_deref())?;
      let store = RusqliteStore::view(&transaction, self.options.clone(), layout);
      operation(&store)?
    };
    transaction.commit()?;
    Ok(result)
  }

  pub fn put_objects_batch(&self, objects: &[ObjectRecord]) -> Result<()> {
    self.store()?.put_objects_batch(objects)
  }

  pub fn put_file_recipe_cache_batch(&self, entries: &[(Hash32, Hash32)]) -> Result<()> {
    self.store()?.put_file_recipe_cache_batch(entries)
  }

  pub fn put_chunk(&self, hash: Hash32, content: &[u8], codec: Codec) -> Result<()> {
    self.store()?.put_chunk(hash, content, codec)
  }

  pub fn put_recipe(&self, hash: Hash32, content: &[u8], codec: Codec) -> Result<()> {
    self.store()?.put_recipe(hash, content, codec)
  }

  pub fn existing_hashes(&self, hashes: &[Hash32]) -> Result<std::collections::HashSet<Hash32>> {
    self.store()?.existing_hashes(hashes)
  }

  pub fn chunk_stored_bytes(&self, hash: &Hash32) -> Result<Option<u64>> {
    self.store()?.chunk_stored_bytes(hash)
  }

  pub fn chunk_sizes(&self) -> Result<Vec<(Hash32, u64)>> {
    self.store()?.chunk_sizes()
  }

  pub fn file_recipe_cache(&self) -> Result<std::collections::HashMap<Hash32, Hash32>> {
    self.store()?.file_recipe_cache()
  }

  pub fn recipe_for_file_hash(&self, hash: &Hash32) -> Result<Option<Hash32>> {
    self.store()?.recipe_for_file_hash(hash)
  }

  pub fn all_objects(&self) -> Result<Vec<VerifiedObject>> {
    self.store()?.all_objects()
  }

  pub fn object_records(&self, offset: u64, limit: usize) -> Result<Vec<ObjectRecord>> {
    self.store()?.object_records(offset, limit)
  }

  pub fn rebuild_merkle_index(&self) -> Result<MerkleSummary> {
    self.store()?.rebuild_merkle_index()
  }

  pub fn merkle_summary(&self) -> Result<MerkleSummary> {
    self.store()?.merkle_summary()
  }

  pub fn recompute_merkle_summary(&self) -> Result<MerkleSummary> {
    self.store()?.recompute_merkle_summary()
  }

  pub fn prove_membership(&self, hash: &Hash32) -> Result<Option<MerkleProof>> {
    self.store()?.prove_membership(hash)
  }

  pub fn prove_memberships_batch(&self, hashes: &[Hash32]) -> Result<Vec<Option<MerkleProof>>> {
    self.store()?.prove_memberships_batch(hashes)
  }

  pub fn verify_proof(target: &Hash32, proof: &MerkleProof, expected_root: &Hash32, leaf_count: u64) -> bool {
    RusqliteStore::verify_proof(target, proof, expected_root, leaf_count)
  }

  pub fn integrity_check(&self) -> Result<()> {
    self.store()?.integrity_check()
  }

  pub fn verified_object_hashes(&self) -> Result<Vec<Hash32>> {
    self.store()?.verified_object_hashes()
  }

  fn store(&self) -> Result<RusqliteStore<'_>> {
    let layout = SqliteLayout::new(self.options.namespace.as_deref())?;
    Ok(RusqliteStore::view(&self.connection, self.options.clone(), layout))
  }
}

impl ObjectSource for SqlitePack {
  fn read_object(&self, hash: &Hash32) -> Result<Option<VerifiedObject>> {
    self.store()?.read_object(hash)
  }
}
