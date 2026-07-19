use sqlx::{AssertSqlSafe, Row};

use super::{
  INTEGRITY_CHECK, MerkleMode, MerkleProof, MerkleSummary, SqlxStore, fetch_hash_by_pos, hash_pair, merkle_root_from_hashes, read_meta_u64,
  read_meta_value,
};
use crate::{Error, Hash32, Result};

impl SqlxStore {
  pub async fn recompute_merkle_summary(&self) -> Result<MerkleSummary> {
    self.ensure_merkle_enabled()?;
    let rows = sqlx::query(AssertSqlSafe(self.tables.select_merkle_hashes()))
      .fetch_all(&self.pool)
      .await?;
    let hashes = rows
      .into_iter()
      .map(|row| Hash32::from_bytes(&row.get::<Vec<u8>, _>("hash")))
      .collect::<Result<Vec<_>>>()?;
    Ok(merkle_root_from_hashes(&hashes))
  }

  pub async fn prove_memberships_batch(&self, hashes: &[Hash32]) -> Result<Vec<Option<MerkleProof>>> {
    let mut proofs = Vec::with_capacity(hashes.len());
    for hash in hashes {
      proofs.push(self.prove_membership(hash).await?);
    }
    Ok(proofs)
  }

  pub async fn verified_object_hashes(&self) -> Result<Vec<Hash32>> {
    Ok(self.all_objects().await?.into_iter().map(|object| object.hash).collect())
  }

  pub async fn integrity_check(&self) -> Result<()> {
    let row = sqlx::query(INTEGRITY_CHECK).fetch_one(&self.pool).await?;
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
    sqlx::query(AssertSqlSafe(self.tables.delete_merkle_leaves()))
      .execute(&mut *tx)
      .await?;
    sqlx::query(AssertSqlSafe(self.tables.delete_merkle_nodes()))
      .execute(&mut *tx)
      .await?;
    sqlx::query(AssertSqlSafe(self.tables.delete_merkle_meta()))
      .execute(&mut *tx)
      .await?;

    let rows = sqlx::query(AssertSqlSafe(self.tables.select_object_hashes()))
      .fetch_all(&mut *tx)
      .await?;
    let mut leaves = Vec::with_capacity(rows.len());
    for row in rows {
      let bytes: Vec<u8> = row.get("hash");
      leaves.push(Hash32::from_bytes(&bytes)?);
    }

    for (idx, hash) in leaves.iter().enumerate() {
      sqlx::query(AssertSqlSafe(self.tables.insert_merkle_leaf()))
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
        sqlx::query(AssertSqlSafe(self.tables.insert_merkle_node()))
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
      sqlx::query(AssertSqlSafe(self.tables.upsert_merkle_meta()))
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

    let leaf_count = read_meta_u64(&self.pool, &self.tables, "leaf_count").await?;
    let root_hex = read_meta_value(&self.pool, &self.tables, "root_hash")
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

    let row = sqlx::query(AssertSqlSafe(self.tables.select_merkle_position()))
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
          fetch_hash_by_pos(&self.pool, &self.tables, None, sibling_pos).await?
        }
      } else if sibling_pos >= count {
        current_hash
      } else {
        fetch_hash_by_pos(&self.pool, &self.tables, Some(node_level), sibling_pos).await?
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
