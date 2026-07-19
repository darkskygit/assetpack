use super::SqliteLayout;

pub(super) const INTEGRITY_CHECK: &str = "PRAGMA integrity_check";
#[cfg(feature = "sqlx-store")]
pub(super) const UPSERT_RECIPE_CACHE_SUFFIX: &str =
  " ON CONFLICT(file_hash) DO UPDATE SET recipe_hash=excluded.recipe_hash, updated_at=excluded.updated_at";

impl SqliteLayout {
  pub fn insert_object(&self) -> String {
    format!(
      "INSERT OR IGNORE INTO {} (hash, kind, size, stored_size, codec, content, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
      self.objects
    )
  }

  #[cfg(feature = "sqlx-store")]
  pub fn insert_objects_prefix(&self) -> String {
    format!(
      "INSERT OR IGNORE INTO {} (hash, kind, size, stored_size, codec, content, created_at) ",
      self.objects
    )
  }

  #[cfg(any(feature = "sqlite-pack", feature = "rusqlite-store"))]
  pub fn upsert_recipe_cache(&self) -> String {
    format!(
      "INSERT INTO {} (file_hash, recipe_hash, updated_at) VALUES (?1, ?2, ?3) ON CONFLICT(file_hash) DO UPDATE SET \
       recipe_hash=excluded.recipe_hash, updated_at=excluded.updated_at",
      self.file_recipe_cache
    )
  }

  #[cfg(feature = "sqlx-store")]
  pub fn upsert_recipe_cache_prefix(&self) -> String {
    format!("INSERT INTO {} (file_hash, recipe_hash, updated_at) ", self.file_recipe_cache)
  }

  pub fn select_object(&self) -> String {
    format!("SELECT hash, kind, size, codec, content FROM {} WHERE hash=?1", self.objects)
  }

  pub fn select_hashes_prefix(&self) -> String {
    format!("SELECT hash FROM {} WHERE hash IN (", self.objects)
  }

  pub fn select_chunk_stored_size(&self) -> String {
    format!("SELECT kind, stored_size FROM {} WHERE hash=?1", self.objects)
  }

  pub fn select_chunk_sizes(&self) -> String {
    format!("SELECT hash, stored_size FROM {} WHERE kind=?1 ORDER BY hash", self.objects)
  }

  pub fn select_recipe_cache(&self) -> String {
    format!("SELECT file_hash, recipe_hash FROM {}", self.file_recipe_cache)
  }

  pub fn select_recipe_for_file(&self) -> String {
    format!("SELECT recipe_hash FROM {} WHERE file_hash=?1", self.file_recipe_cache)
  }

  pub fn select_objects(&self) -> String {
    format!("SELECT hash, kind, size, codec, content FROM {} ORDER BY hash", self.objects)
  }

  pub fn select_object_records(&self) -> String {
    format!(
      "SELECT hash, kind, size, codec, content FROM {} ORDER BY hash LIMIT ?1 OFFSET ?2",
      self.objects
    )
  }

  pub fn delete_merkle_leaves(&self) -> String {
    format!("DELETE FROM {}", self.merkle_leaves)
  }

  pub fn delete_merkle_nodes(&self) -> String {
    format!("DELETE FROM {}", self.merkle_nodes)
  }

  pub fn delete_merkle_meta(&self) -> String {
    format!("DELETE FROM {}", self.merkle_meta)
  }

  pub fn select_object_hashes(&self) -> String {
    format!("SELECT hash FROM {} ORDER BY hash", self.objects)
  }

  pub fn insert_merkle_leaf(&self) -> String {
    format!("INSERT INTO {} (hash, pos) VALUES (?1, ?2)", self.merkle_leaves)
  }

  pub fn insert_merkle_node(&self) -> String {
    format!("INSERT INTO {} (level, pos, hash) VALUES (?1, ?2, ?3)", self.merkle_nodes)
  }

  pub fn upsert_merkle_meta(&self) -> String {
    format!(
      "INSERT INTO {} (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
      self.merkle_meta
    )
  }

  pub fn select_merkle_hashes(&self) -> String {
    format!("SELECT hash FROM {} ORDER BY pos", self.merkle_leaves)
  }

  pub fn select_merkle_position(&self) -> String {
    format!("SELECT pos FROM {} WHERE hash=?1", self.merkle_leaves)
  }

  pub fn select_merkle_meta(&self) -> String {
    format!("SELECT value FROM {} WHERE key=?1", self.merkle_meta)
  }

  pub fn select_leaf_hash_at(&self) -> String {
    format!("SELECT hash FROM {} WHERE pos=?1", self.merkle_leaves)
  }

  pub fn select_node_hash_at(&self) -> String {
    format!("SELECT hash FROM {} WHERE level=?1 AND pos=?2", self.merkle_nodes)
  }
}
