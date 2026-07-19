use std::{
  collections::BTreeMap,
  io::{BufReader, Cursor},
};

use assetpack_core::{
  DEFAULT_FORMAT_TAG, FileHint, FileReadLimits, FileReader, FileTransformConfig, FileTransformPrecomp2Config, Hash32, ObjectKind,
  ObjectRecord, ObjectSource, Pack, PackOpenPolicy, ParsedSealedPack, SealedPackBuilder, SealedPackTag, SoftwareFrameKey, SqliteStore,
  TRANSFORM_ID_NONE, TRANSFORM_ID_PRECOMP2, TRANSFORM_ID_PRECOMP2_LZMA, TRANSFORM_ID_PRECOMP2_ZSTD, TransformDecoderRegistry,
  TransformSelector, VerifiedObject, build_recipe, file_transform::FileTransform,
};

const TINY_PNG: &[u8] = &[
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x01, 0x08, 0x04, 0x00, 0x00, 0x00, 0xb5, 0x1c, 0x0c, 0x02, 0x00, 0x00, 0x00, 0x0b, 0x49, 0x44, 0x41, 0x54, 0x78, 0xda, 0x63, 0xfc, 0xff,
  0x1f, 0x00, 0x03, 0x03, 0x02, 0x00, 0xee, 0x6a, 0x93, 0xa9, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
];

fn assert_roundtrip_keeps_hash(transform: &dyn FileTransform, data: &[u8]) {
  let original_hash = Hash32::sha3_256(data);
  let mut encoded = Vec::new();
  let mut reader = BufReader::new(Cursor::new(data));
  transform.encode(&mut reader, &mut encoded).unwrap();

  let mut decoded = Vec::new();
  let mut reader = BufReader::new(Cursor::new(encoded));
  transform.decode(&mut reader, &mut decoded).unwrap();

  assert_eq!(Hash32::sha3_256(&decoded), original_hash);
}

#[test]
fn transform_stored_stream_fixtures_are_stable_and_restore_original_bytes() {
  let config = FileTransformConfig::default();
  let precomp2 = crate::Precomp2Transform::new(&config);
  let precomp2_zstd = crate::Precomp2ZstdTransform::new(&config);
  let precomp2_lzma = crate::Precomp2LzmaTransform::new(&config);
  let transforms: [(Option<&dyn FileTransform>, usize, &str); 4] = [
    (None, 68, "176c814967ba8da2fef5938a7585a1c86b08a7a475514bfb540158aef65097d3"),
    (
      Some(&precomp2),
      143,
      "99cca30649070fdc348f6ef07df83cfef77aa1500e4efce7a3a95541ab100e1e",
    ),
    (
      Some(&precomp2_zstd),
      120,
      "9382c30307a03e67c707f746c8212f5985749c4949e4b106a38f315c3461d299",
    ),
    (
      Some(&precomp2_lzma),
      113,
      "8d8557ac3408ffce005f327a11c1a988a477f0bef10e924ff0c396c3e654b8e2",
    ),
  ];
  for (transform, expected_len, expected_hash) in transforms {
    let encoded = if let Some(transform) = transform {
      let mut encoded = Vec::new();
      transform.encode(&mut BufReader::new(Cursor::new(TINY_PNG)), &mut encoded).unwrap();
      encoded
    } else {
      TINY_PNG.to_vec()
    };
    assert_eq!(encoded.len(), expected_len);
    assert_eq!(Hash32::sha3_256(&encoded).to_string(), expected_hash);

    let mut restored = Vec::new();
    if let Some(transform) = transform {
      transform.decode(&mut BufReader::new(Cursor::new(encoded)), &mut restored).unwrap();
    } else {
      restored = encoded;
    }
    assert_eq!(restored, TINY_PNG);
  }
}

#[test]
fn decoder_registry_contains_every_persisted_precomp2_pair() {
  let config = FileTransformConfig {
    enabled: false,
    ..Default::default()
  };
  let registry = TransformDecoderRegistry::new(crate::default_decoders(&config)).unwrap();
  for (id, version) in [
    (TRANSFORM_ID_NONE, 0),
    (TRANSFORM_ID_PRECOMP2, 1),
    (TRANSFORM_ID_PRECOMP2_ZSTD, 1),
    (TRANSFORM_ID_PRECOMP2_LZMA, 1),
  ] {
    let decoder = registry.get(id, version).unwrap();
    assert_eq!((decoder.id(), decoder.version()), (id, version));
  }
}

#[derive(Default)]
struct MemorySource(BTreeMap<Hash32, VerifiedObject>);

impl ObjectSource for MemorySource {
  async fn read_object(&self, hash: &Hash32) -> assetpack_core::Result<Option<VerifiedObject>> {
    Ok(self.0.get(hash).cloned())
  }
}

async fn read_file<S: ObjectSource + ?Sized>(source: &S, registry: &TransformDecoderRegistry, recipe_hash: Hash32) -> Vec<u8> {
  FileReader::new(source, registry, FileReadLimits::default())
    .read_file(recipe_hash)
    .await
    .unwrap()
}

#[tokio::test]
async fn file_reader_restores_all_fixed_transform_recipes() {
  let config = FileTransformConfig::default();
  let precomp2 = crate::Precomp2Transform::new(&config);
  let precomp2_zstd = crate::Precomp2ZstdTransform::new(&config);
  let precomp2_lzma = crate::Precomp2LzmaTransform::new(&config);
  let transforms: Vec<(u16, u16, Option<&dyn FileTransform>)> = vec![
    (TRANSFORM_ID_NONE, 0, None),
    (TRANSFORM_ID_PRECOMP2, 1, Some(&precomp2)),
    (TRANSFORM_ID_PRECOMP2_ZSTD, 1, Some(&precomp2_zstd)),
    (TRANSFORM_ID_PRECOMP2_LZMA, 1, Some(&precomp2_lzma)),
  ];
  let expected_hash = Hash32::sha3_256(TINY_PNG);
  assert_eq!(
    expected_hash.to_string(),
    "176c814967ba8da2fef5938a7585a1c86b08a7a475514bfb540158aef65097d3"
  );
  let registry = TransformDecoderRegistry::new(crate::default_decoders(&config)).unwrap();
  for (id, version, transform) in transforms {
    let stored = if let Some(transform) = transform {
      let mut stored = Vec::new();
      transform.encode(&mut BufReader::new(Cursor::new(TINY_PNG)), &mut stored).unwrap();
      stored
    } else {
      TINY_PNG.to_vec()
    };
    let chunk_hash = Hash32::sha3_256(&stored);
    let recipe = build_recipe(
      TINY_PNG.len() as u64,
      &[(chunk_hash, stored.len() as u32)],
      expected_hash,
      id,
      version,
    );
    let recipe_hash = Hash32::sha3_256(&recipe);
    let source = MemorySource(BTreeMap::from([
      (
        chunk_hash,
        VerifiedObject {
          hash: chunk_hash,
          kind: ObjectKind::Chunk,
          bytes: stored,
        },
      ),
      (
        recipe_hash,
        VerifiedObject {
          hash: recipe_hash,
          kind: ObjectKind::Recipe,
          bytes: recipe,
        },
      ),
    ]));
    let reader = FileReader::new(&source, &registry, FileReadLimits::default());
    assert_eq!(reader.read_file(recipe_hash).await.unwrap(), TINY_PNG, "transform {id}:{version}");

    let objects = source
      .0
      .values()
      .map(|object| ObjectRecord {
        hash: object.hash,
        kind: object.kind,
        decoded_len: object.bytes.len() as u64,
        codec: assetpack_core::Codec::Raw,
        stored_bytes: object.bytes.clone(),
      })
      .collect::<Vec<_>>();
    let directory = tempfile::tempdir().unwrap();
    let pack = Pack::open(directory.path().join("pack.db")).await.unwrap();
    let mut tx = pack.begin_write_tx().await.unwrap();
    Pack::put_objects_batch_tx(&mut tx, &objects).await.unwrap();
    tx.commit().await.unwrap();
    let store = SqliteStore::open(directory.path().join("store.db")).await.unwrap();
    let mut tx = store.begin_write_tx().await.unwrap();
    store.put_objects_batch_tx(&mut tx, &objects).await.unwrap();
    tx.commit().await.unwrap();
    let plain_bytes = SealedPackBuilder::build_plain(DEFAULT_FORMAT_TAG, recipe_hash, objects.clone()).unwrap();
    let plain = ParsedSealedPack::open(&plain_bytes, DEFAULT_FORMAT_TAG, PackOpenPolicy::PlainAllowed)
      .unwrap()
      .open_plain()
      .unwrap();
    let tag = SealedPackTag(*b"precomp-parity!!");
    let key = SoftwareFrameKey::new([7; 32], [9; 16]);
    let encrypted_bytes = SealedPackBuilder::build_encrypted(tag, recipe_hash, objects, &key).unwrap();
    let parsed = ParsedSealedPack::open(&encrypted_bytes, tag, PackOpenPolicy::EncryptedRequired).unwrap();
    let encrypted = parsed.unlock(&key).unwrap();
    for restored in [
      read_file(&pack, &registry, recipe_hash).await,
      read_file(&store, &registry, recipe_hash).await,
      read_file(&plain, &registry, recipe_hash).await,
      read_file(&encrypted, &registry, recipe_hash).await,
    ] {
      assert_eq!(restored, TINY_PNG, "transform {id}:{version}");
    }
  }
}

#[test]
fn base_precomp2_config_defaults_match_precomp2_defaults() {
  let config = FileTransformPrecomp2Config::default();
  let encode = precomp2::EncodeConfig::default();
  let decode = precomp2::DecodeConfig::default();
  assert_eq!(config.max_depth, encode.max_depth);
  assert_eq!(config.max_expand_ratio, encode.max_expand_ratio);
  assert_eq!(config.max_total_output, encode.max_total_output);
  assert_eq!(config.recover, decode.recover);
}

#[test]
fn precomp2_encode_config_enables_features() {
  let config = FileTransformPrecomp2Config::default();
  let encode = crate::common::precomp2_encode_config(&config);
  assert!(encode.enable_png_webp);
  assert!(encode.enable_pdf_predictor);
  assert!(encode.enable_pdf_bmp_fallback);
}

#[test]
fn precomp2_roundtrip_keeps_hash() {
  let config = FileTransformConfig::default();
  let transform = crate::Precomp2Transform::new(&config);
  assert_roundtrip_keeps_hash(&transform, TINY_PNG);
}

#[test]
fn precomp2_zstd_roundtrip_keeps_hash() {
  let config = FileTransformConfig::default();
  let transform = crate::Precomp2ZstdTransform::new(&config);
  assert_roundtrip_keeps_hash(&transform, TINY_PNG);
}

#[test]
fn precomp2_lzma_roundtrip_keeps_hash() {
  let config = FileTransformConfig::default();
  let transform = crate::Precomp2LzmaTransform::new(&config);
  assert_roundtrip_keeps_hash(&transform, TINY_PNG);
}

#[test]
fn selector_accepts_with_negative_gain() {
  let config = FileTransformConfig {
    min_size: 0,
    min_gain: -10.0,
    allow_ext: vec!["bin".into()],
    ..Default::default()
  };
  let selector = TransformSelector::new(config, None, crate::default_specs());
  let data = b"preflate selector smoke test".repeat(8);
  let hint = FileHint {
    size: data.len() as u64,
    extension: Some("bin".into()),
    head: Some(data[..8].to_vec()),
  };
  let selection = selector.select_bytes(data.to_vec(), &hint, Hash32::sha3_256(&data)).unwrap();
  assert_ne!(selection.transform_id, TRANSFORM_ID_NONE);
  assert!(
    matches!(
      selection.transform_id,
      TRANSFORM_ID_PRECOMP2 | TRANSFORM_ID_PRECOMP2_ZSTD | TRANSFORM_ID_PRECOMP2_LZMA
    ),
    "unexpected transform id {}",
    selection.transform_id
  );
}

#[test]
fn selector_accepts_precomp2_family_with_negative_gain() {
  let config = FileTransformConfig {
    min_size: 0,
    min_gain: -10.0,
    allow_ext: vec!["png".into()],
    ..Default::default()
  };
  let selector = TransformSelector::new(config, None, crate::default_specs());
  let data = TINY_PNG.to_vec();
  let hint = FileHint {
    size: data.len() as u64,
    extension: Some("png".into()),
    head: Some(data[..8].to_vec()),
  };
  let selection = selector.select_bytes(data, &hint, Hash32::sha3_256(TINY_PNG)).unwrap();
  assert_ne!(selection.transform_id, TRANSFORM_ID_NONE);
  assert!(
    matches!(
      selection.transform_id,
      TRANSFORM_ID_PRECOMP2 | TRANSFORM_ID_PRECOMP2_ZSTD | TRANSFORM_ID_PRECOMP2_LZMA
    ),
    "unexpected transform id {}",
    selection.transform_id
  );
}
