mod common;
#[cfg(feature = "sqlite-pack")]
mod pack;
#[cfg(any(feature = "sqlite-pack", feature = "rusqlite-store"))]
mod rusqlite;
#[cfg(feature = "sqlx-store")]
mod sqlx;
mod statements;

pub use common::{MerkleMode, MerkleProof, MerkleSummary, SqliteStoreOptions};
pub(in crate::sqlite) use common::{
  SqliteLayout, StoredObjectRow, codec_to_str, hash_pair, merkle_root_from_hashes, object_record_from_row, prepare_object,
  schema_statements, verified_object_from_row,
};
#[cfg(feature = "sqlite-pack")]
pub use pack::{SqlitePack, SqlitePackJournalMode};
#[cfg(any(feature = "sqlite-pack", feature = "rusqlite-store"))]
pub use rusqlite::RusqliteStore;
#[cfg(feature = "sqlx-store")]
pub use sqlx::SqlxStore;

#[cfg(all(test, feature = "rusqlite-store"))]
mod tests {
  use super::{RusqliteStore, SqliteStoreOptions};
  use crate::{Codec, Hash32, ObjectKind, ObjectRecord, ObjectSource};

  fn record(bytes: &[u8]) -> ObjectRecord {
    ObjectRecord {
      hash: Hash32::sha3_256(bytes),
      kind: ObjectKind::Chunk,
      decoded_len: bytes.len() as u64,
      codec: Codec::Raw,
      stored_bytes: bytes.to_vec(),
    }
  }

  #[test]
  fn rusqlite_store_joins_host_commit_and_rollback() {
    let mut connection = rusqlite::Connection::open_in_memory().unwrap();
    connection
      .execute("CREATE TABLE app_history (id INTEGER PRIMARY KEY, label TEXT NOT NULL)", [])
      .unwrap();
    RusqliteStore::ensure_schema(&connection).unwrap();
    let object = record(b"transaction-object");

    {
      let transaction = connection.transaction().unwrap();
      transaction
        .execute("INSERT INTO app_history (label) VALUES ('rollback')", [])
        .unwrap();
      RusqliteStore::from_connection(&transaction)
        .unwrap()
        .put_objects_batch(std::slice::from_ref(&object))
        .unwrap();
      transaction.rollback().unwrap();
    }
    assert_eq!(
      connection
        .query_row("SELECT COUNT(*) FROM app_history", [], |row| row.get::<_, i64>(0))
        .unwrap(),
      0
    );
    assert!(
      RusqliteStore::from_connection(&connection)
        .unwrap()
        .read_object(&object.hash)
        .unwrap()
        .is_none()
    );

    {
      let transaction = connection.transaction().unwrap();
      transaction
        .execute("INSERT INTO app_history (label) VALUES ('commit')", [])
        .unwrap();
      RusqliteStore::from_connection(&transaction)
        .unwrap()
        .put_objects_batch(std::slice::from_ref(&object))
        .unwrap();
      transaction.commit().unwrap();
    }
    assert_eq!(
      connection
        .query_row("SELECT COUNT(*) FROM app_history", [], |row| row.get::<_, i64>(0))
        .unwrap(),
      1
    );
    assert_eq!(
      RusqliteStore::from_connection(&connection)
        .unwrap()
        .read_object(&object.hash)
        .unwrap()
        .unwrap()
        .bytes,
      b"transaction-object"
    );
  }

  #[cfg(feature = "sqlx-store")]
  #[tokio::test]
  async fn sqlite_schema_and_objects_roundtrip_across_drivers_with_prefix() {
    use sqlx::{Row, sqlite::SqliteConnectOptions};

    use super::SqlxStore;
    use crate::AsyncObjectSource;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cross-driver.db");
    let first = record(b"written-by-rusqlite");
    {
      let connection = rusqlite::Connection::open(&path).unwrap();
      let store = RusqliteStore::from_connection_with_options(
        &connection,
        SqliteStoreOptions {
          namespace: Some("asset".into()),
          ..Default::default()
        },
      )
      .unwrap();
      store.put_objects_batch(std::slice::from_ref(&first)).unwrap();
      let summary = store.rebuild_merkle_index().unwrap();
      assert_eq!(summary.leaf_count, 1);
    }

    let pool = sqlx::SqlitePool::connect_with(SqliteConnectOptions::new().filename(&path))
      .await
      .unwrap();
    let store = SqlxStore::from_pool_with_options(
      pool.clone(),
      SqliteStoreOptions {
        namespace: Some("asset".into()),
        ..Default::default()
      },
    )
    .await
    .unwrap();
    assert_eq!(store.read_object(&first.hash).await.unwrap().unwrap().bytes, b"written-by-rusqlite");
    let schema = sqlx::query("SELECT name FROM sqlite_master WHERE type IN ('table', 'index') AND name LIKE 'asset_%' ORDER BY name")
      .fetch_all(&pool)
      .await
      .unwrap()
      .into_iter()
      .map(|row| row.get::<String, _>(0))
      .collect::<Vec<_>>();
    assert_eq!(
      schema,
      [
        "asset_file_recipe_cache",
        "asset_merkle_leaves",
        "asset_merkle_meta",
        "asset_merkle_nodes",
        "asset_objects",
      ]
    );
    let second = record(b"written-by-sqlx");
    let mut transaction = pool.begin().await.unwrap();
    store
      .put_objects_batch_tx(&mut transaction, std::slice::from_ref(&second))
      .await
      .unwrap();
    transaction.commit().await.unwrap();
    pool.close().await;

    let connection = rusqlite::Connection::open(&path).unwrap();
    let store = RusqliteStore::from_connection_with_options(
      &connection,
      SqliteStoreOptions {
        namespace: Some("asset".into()),
        ..Default::default()
      },
    )
    .unwrap();
    assert_eq!(store.read_object(&second.hash).unwrap().unwrap().bytes, b"written-by-sqlx");
    assert_eq!(store.merkle_summary().unwrap().leaf_count, 1);
  }
}
