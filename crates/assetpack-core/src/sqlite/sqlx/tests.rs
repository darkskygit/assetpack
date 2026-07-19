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
  let store = SqlxStore::from_pool_with_namespace(pool.clone(), "ipg").await.unwrap();
  assert_eq!(store.namespace(), Some("ipg"));
  assert!(table_exists(&pool, "ipg_objects").await);
  assert!(table_exists(&pool, "ipg_file_recipe_cache").await);
  assert!(!table_exists(&pool, "objects").await);

  let data = b"hello embedded store".to_vec();
  let hash = Hash32::sha3_256(&data);
  store.put_chunk(hash, &data, Codec::Zstd).await.unwrap();
  let loaded = store.read_object(&hash).await.unwrap().unwrap();
  assert_eq!(loaded.hash, hash);
  assert_eq!(loaded.kind, ObjectKind::Chunk);
  assert_eq!(loaded.bytes, data);

  sqlx::query("UPDATE ipg_objects SET size = size + 1 WHERE hash = ?1")
    .bind(hash.as_bytes().as_ref())
    .execute(&pool)
    .await
    .unwrap();
  assert!(matches!(store.read_object(&hash).await, Err(Error::ObjectLengthMismatch { .. })));
  sqlx::query("UPDATE ipg_objects SET size = ?1, codec = 'raw', content = ?2 WHERE hash = ?3")
    .bind(data.len() as i64)
    .bind(vec![0_u8; data.len()])
    .bind(hash.as_bytes().as_ref())
    .execute(&pool)
    .await
    .unwrap();
  assert!(matches!(store.read_object(&hash).await, Err(Error::ObjectHashMismatch { expected, .. }) if expected == hash));
  sqlx::query("UPDATE ipg_objects SET kind = 99 WHERE hash = ?1")
    .bind(hash.as_bytes().as_ref())
    .execute(&pool)
    .await
    .unwrap();
  assert!(matches!(store.read_object(&hash).await, Err(Error::Integrity(_))));
}

#[tokio::test]
async fn store_batch_writes_can_share_host_transaction_boundary() {
  let pool = memory_pool().await;
  sqlx::query("CREATE TABLE app_history (id INTEGER PRIMARY KEY, label TEXT NOT NULL);")
    .execute(&pool)
    .await
    .unwrap();
  let store = SqlxStore::from_pool(pool.clone()).await.unwrap();

  let data = b"tx-object".to_vec();
  let hash = Hash32::sha3_256(&data);
  let object = ObjectRecord {
    hash,
    kind: ObjectKind::Chunk,
    decoded_len: data.len() as u64,
    codec: Codec::Raw,
    stored_bytes: data.clone(),
  };

  let mut tx = pool.begin().await.unwrap();
  sqlx::query("INSERT INTO app_history (label) VALUES (?1)")
    .bind("draft")
    .execute(&mut *tx)
    .await
    .unwrap();
  store.put_objects_batch_tx(&mut tx, std::slice::from_ref(&object)).await.unwrap();
  tx.rollback().await.unwrap();

  let app_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM app_history")
    .fetch_one(&pool)
    .await
    .unwrap();
  let object_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM objects").fetch_one(&pool).await.unwrap();
  assert_eq!(app_count, 0);
  assert_eq!(object_count, 0);

  let mut tx = pool.begin().await.unwrap();
  sqlx::query("INSERT INTO app_history (label) VALUES (?1)")
    .bind("published")
    .execute(&mut *tx)
    .await
    .unwrap();
  store.put_objects_batch_tx(&mut tx, &[object]).await.unwrap();
  tx.commit().await.unwrap();
  assert_eq!(
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM app_history")
      .fetch_one(&pool)
      .await
      .unwrap(),
    1
  );
  assert_eq!(
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM objects")
      .fetch_one(&pool)
      .await
      .unwrap(),
    1
  );
}

#[tokio::test]
async fn merkle_can_be_disabled_for_embedded_store() {
  let pool = memory_pool().await;
  let store = SqlxStore::from_pool_with_options(
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
  let store = SqlxStore::from_pool_with_options(
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
  assert!(SqlxStore::verify_proof(&target, &proof, &summary.root, summary.leaf_count));
}
