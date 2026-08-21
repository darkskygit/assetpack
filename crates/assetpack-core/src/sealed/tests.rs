#[cfg(feature = "sealed-encryption")]
use std::collections::BTreeSet;

use super::*;
#[cfg(feature = "sealed-encryption")]
use crate::ObjectSource;
use crate::{Codec, Hash32, ObjectKind, ObjectRecord, TRANSFORM_ID_NONE, TRANSFORM_VERSION_NONE, build_recipe, codec::compress};

const PRODUCT_TAG: SealedPackTag = SealedPackTag(*b"some-product-v1!");
const OTHER_TAG: SealedPackTag = SealedPackTag(*b"other-product-v1");

struct Fixture {
  root: Hash32,
  objects: Vec<ObjectRecord>,
  file: Vec<u8>,
}

fn fixture(codec: Codec, size: usize) -> Fixture {
  let file = (0..size).map(|index| ((index * 31 + index / 17) % 251) as u8).collect::<Vec<_>>();
  let chunk_hash = Hash32::sha3_256(&file);
  let chunk = ObjectRecord {
    hash: chunk_hash,
    kind: ObjectKind::Chunk,
    decoded_len: file.len() as u64,
    codec,
    stored_bytes: compress(codec, &file).unwrap(),
  };
  let recipe = build_recipe(
    file.len() as u64,
    &[(chunk_hash, file.len() as u32)],
    chunk_hash,
    TRANSFORM_ID_NONE,
    TRANSFORM_VERSION_NONE,
  );
  let root = Hash32::sha3_256(&recipe);
  Fixture {
    root,
    objects: vec![
      chunk,
      ObjectRecord {
        hash: root,
        kind: ObjectKind::Recipe,
        decoded_len: recipe.len() as u64,
        codec: Codec::Raw,
        stored_bytes: recipe,
      },
    ],
    file,
  }
}

#[cfg(feature = "sealed-encryption")]
fn two_chunk_fixture(size: usize) -> Fixture {
  let first = (0..size).map(|index| (index % 251) as u8).collect::<Vec<_>>();
  let second = (0..size).map(|index| ((index + 97) % 251) as u8).collect::<Vec<_>>();
  let file = [first.as_slice(), second.as_slice()].concat();
  let first_hash = Hash32::sha3_256(&first);
  let second_hash = Hash32::sha3_256(&second);
  let recipe = build_recipe(
    file.len() as u64,
    &[(first_hash, size as u32), (second_hash, size as u32)],
    Hash32::sha3_256(&file),
    TRANSFORM_ID_NONE,
    TRANSFORM_VERSION_NONE,
  );
  let root = Hash32::sha3_256(&recipe);
  Fixture {
    root,
    objects: vec![
      ObjectRecord {
        hash: first_hash,
        kind: ObjectKind::Chunk,
        decoded_len: size as u64,
        codec: Codec::Raw,
        stored_bytes: first,
      },
      ObjectRecord {
        hash: second_hash,
        kind: ObjectKind::Chunk,
        decoded_len: size as u64,
        codec: Codec::Raw,
        stored_bytes: second,
      },
      ObjectRecord {
        hash: root,
        kind: ObjectKind::Recipe,
        decoded_len: recipe.len() as u64,
        codec: Codec::Raw,
        stored_bytes: recipe,
      },
    ],
    file,
  }
}

#[cfg(all(feature = "sqlite-pack", feature = "sealed-encryption"))]
struct SharedObjectGraphFixture {
  root: Hash32,
  contract_objects: Vec<ObjectRecord>,
  expected_objects: Vec<(Hash32, ObjectKind, Vec<u8>)>,
  file: Vec<u8>,
  corrupt_codec: Hash32,
  wrong_length: Hash32,
  wrong_hash: Hash32,
  wrong_kind: Hash32,
}

#[cfg(all(feature = "sqlite-pack", feature = "sealed-encryption"))]
fn shared_object_graph_fixture() -> SharedObjectGraphFixture {
  let chunks = [
    (
      Codec::Raw,
      b"raw-object-fixture".repeat(3),
      "e503ae889c22168a4ff191e6daa19567983914a879d25e708d01fc4f323bfb01",
    ),
    (
      Codec::Zstd,
      b"zstd-object-fixture".repeat(128),
      "bbd79c3ccc53c3524587c69e8a3d5ea01fcff5c1849cceeb46db5438ec86896b",
    ),
    (
      Codec::Brotli,
      b"brotli-object-fixture".repeat(128),
      "bfbeb6faf632fddfbd0bb17b05d09de266b1c24bf50201928e0c2cdb47ae1887",
    ),
  ];
  let mut objects = Vec::new();
  let mut expected_objects = Vec::new();
  let mut recipe_chunks = Vec::new();
  for (codec, bytes, expected_hash) in chunks {
    let hash = Hash32::sha3_256(&bytes);
    assert_eq!(hash.to_string(), expected_hash);
    recipe_chunks.push((hash, bytes.len() as u32));
    expected_objects.push((hash, ObjectKind::Chunk, bytes.clone()));
    objects.push(ObjectRecord {
      hash,
      kind: ObjectKind::Chunk,
      decoded_len: bytes.len() as u64,
      codec,
      stored_bytes: compress(codec, &bytes).unwrap(),
    });
  }
  recipe_chunks.push(recipe_chunks[0]);
  let file = [
    expected_objects[0].2.as_slice(),
    expected_objects[1].2.as_slice(),
    expected_objects[2].2.as_slice(),
    expected_objects[0].2.as_slice(),
  ]
  .concat();
  assert_eq!(
    Hash32::sha3_256(&file).to_string(),
    "5c6126efb4846be693311ea640bd2a69571bf499a1d8b9c9bfb9a3b6c3c482f4"
  );
  let recipe = build_recipe(
    file.len() as u64,
    &recipe_chunks,
    Hash32::sha3_256(&file),
    TRANSFORM_ID_NONE,
    TRANSFORM_VERSION_NONE,
  );
  let root = Hash32::sha3_256(&recipe);
  assert_eq!(root.to_string(), "37ff4a38084a11a23f2d990a768691109c7b6f6e8a6f6be5e8a8a3f75f3c5fb8");
  expected_objects.push((root, ObjectKind::Recipe, recipe.clone()));
  objects.push(ObjectRecord {
    hash: root,
    kind: ObjectKind::Recipe,
    decoded_len: recipe.len() as u64,
    codec: Codec::Raw,
    stored_bytes: recipe,
  });
  let corrupt_codec_bytes = b"corrupt-codec-fixture";
  let corrupt_codec = Hash32::sha3_256(corrupt_codec_bytes);
  let wrong_length_bytes = b"wrong-length-fixture";
  let wrong_length = Hash32::sha3_256(wrong_length_bytes);
  let wrong_hash = Hash32::sha3_256(b"expected-hash");
  let wrong_kind_bytes = b"wrong-kind-fixture";
  let wrong_kind = Hash32::sha3_256(wrong_kind_bytes);
  let mut contract_objects = objects.clone();
  contract_objects.extend([
    ObjectRecord {
      hash: corrupt_codec,
      kind: ObjectKind::Chunk,
      decoded_len: corrupt_codec_bytes.len() as u64,
      codec: Codec::Zstd,
      stored_bytes: b"not-zstd".to_vec(),
    },
    ObjectRecord {
      hash: wrong_length,
      kind: ObjectKind::Chunk,
      decoded_len: wrong_length_bytes.len() as u64 + 1,
      codec: Codec::Raw,
      stored_bytes: wrong_length_bytes.to_vec(),
    },
    ObjectRecord {
      hash: wrong_hash,
      kind: ObjectKind::Chunk,
      decoded_len: b"modified-hash".len() as u64,
      codec: Codec::Raw,
      stored_bytes: b"modified-hash".to_vec(),
    },
    ObjectRecord {
      hash: wrong_kind,
      kind: ObjectKind::Chunk,
      decoded_len: wrong_kind_bytes.len() as u64,
      codec: Codec::Raw,
      stored_bytes: wrong_kind_bytes.to_vec(),
    },
  ]);
  contract_objects.sort_by_key(|object| object.hash);
  SharedObjectGraphFixture {
    root,
    contract_objects,
    expected_objects,
    file,
    corrupt_codec,
    wrong_length,
    wrong_hash,
    wrong_kind,
  }
}

#[cfg(all(feature = "sqlite-pack", feature = "sealed-encryption"))]
fn assert_object_source_contract<S: crate::ObjectSource + ?Sized>(source: &S, fixture: &SharedObjectGraphFixture) {
  for (expected_hash, expected_kind, expected_bytes) in &fixture.expected_objects {
    let actual = source.read_object(expected_hash).unwrap().unwrap();
    assert_eq!(actual.hash, *expected_hash);
    assert_eq!(actual.kind, *expected_kind);
    assert_eq!(actual.bytes, *expected_bytes);
  }
  assert!(source.read_object(&Hash32::sha3_256(b"missing-object-fixture")).unwrap().is_none());
  assert!(matches!(
    source.read_object(&fixture.corrupt_codec),
    Err(crate::Error::Decompress(_))
  ));
  assert!(matches!(
    source.read_object(&fixture.wrong_length),
    Err(crate::Error::ObjectLengthMismatch { .. })
  ));
  assert!(matches!(
    source.read_object(&fixture.wrong_hash),
    Err(crate::Error::ObjectHashMismatch { .. })
  ));
  let wrong_kind = source.read_object(&fixture.wrong_kind).unwrap().unwrap();
  assert_eq!(wrong_kind.kind, ObjectKind::Chunk);
}

#[cfg(all(feature = "sqlite-pack", feature = "sealed-encryption"))]
fn backend_file_fixture(codec: Codec, shape: usize) -> (Hash32, Vec<ObjectRecord>, Vec<u8>) {
  let label = match codec {
    Codec::Raw => "raw",
    Codec::Zstd => "zstd",
    Codec::Brotli => "brotli",
  };
  let chunks = match shape {
    0 => vec![],
    1 => vec![format!("{label}-single-alpha").repeat(8).into_bytes()],
    2 | 3 => vec![
      format!("{label}-multi-alpha").repeat(8).into_bytes(),
      format!("{label}-multi-beta").repeat(8).into_bytes(),
    ],
    _ => unreachable!(),
  };
  let order: &[usize] = match shape {
    0 => &[],
    1 => &[0],
    2 => &[0, 1],
    3 => &[0, 1, 0],
    _ => unreachable!(),
  };
  let hashes = chunks.iter().map(Hash32::sha3_256).collect::<Vec<_>>();
  let expected = order.iter().flat_map(|index| chunks[*index].iter().copied()).collect::<Vec<_>>();
  let recipe_chunks = order
    .iter()
    .map(|index| (hashes[*index], chunks[*index].len() as u32))
    .collect::<Vec<_>>();
  let recipe = build_recipe(
    expected.len() as u64,
    &recipe_chunks,
    Hash32::sha3_256(&expected),
    TRANSFORM_ID_NONE,
    TRANSFORM_VERSION_NONE,
  );
  let root = Hash32::sha3_256(&recipe);
  let mut objects = chunks
    .into_iter()
    .zip(hashes)
    .map(|(bytes, hash)| ObjectRecord {
      hash,
      kind: ObjectKind::Chunk,
      decoded_len: bytes.len() as u64,
      codec,
      stored_bytes: compress(codec, &bytes).unwrap(),
    })
    .collect::<Vec<_>>();
  objects.push(ObjectRecord {
    hash: root,
    kind: ObjectKind::Recipe,
    decoded_len: recipe.len() as u64,
    codec,
    stored_bytes: compress(codec, &recipe).unwrap(),
  });
  (root, objects, expected)
}

#[cfg(all(feature = "sqlite-pack", feature = "sealed-encryption"))]
fn restore_from<S: crate::ObjectSource + ?Sized>(source: &S, root: Hash32) -> Vec<u8> {
  let registry = crate::TransformDecoderRegistry::default();
  crate::FileReader::new(source, &registry, crate::FileReadLimits::default())
    .read_file(root)
    .unwrap()
}

fn open_plain<'a>(bytes: &'a [u8], tag: SealedPackTag) -> SealedPackReader<'a> {
  ParsedSealedPack::open(bytes, tag, PackOpenPolicy::PlainAllowed)
    .unwrap()
    .open_plain()
    .unwrap()
}

#[test]
fn plain_payload_cursor_is_contiguous() {
  let fixture = fixture(Codec::Raw, 97);
  let bytes = SealedPackBuilder::build_plain(DEFAULT_FORMAT_TAG, fixture.root, fixture.objects).unwrap();
  let reader = open_plain(&bytes, DEFAULT_FORMAT_TAG);
  let mut cursor = HEADER_BYTES as u64 + reader.header.index_stored_length;
  for record in &reader.records {
    assert_eq!(record.payload_offset, cursor);
    cursor += record.stored_length;
  }
  assert_eq!(cursor, bytes.len() as u64);
}

#[test]
fn include_bytes_fixture_opens_as_a_borrowed_pack() {
  static PACK: &[u8] = include_bytes!("fixtures/plain_v1.aspk");
  let reader: SealedPackReader<'static> = open_plain(PACK, DEFAULT_FORMAT_TAG);
  reader.verify_all_objects().unwrap();
}

#[test]
fn plain_v1_golden_rebuilds_from_fixed_input() {
  static GOLDEN: &[u8] = include_bytes!("fixtures/plain_v1.aspk");
  let file = b"include-bytes-borrowed-open";
  let chunk_hash = Hash32::sha3_256(file);
  let recipe = build_recipe(
    file.len() as u64,
    &[(chunk_hash, file.len() as u32)],
    chunk_hash,
    TRANSFORM_ID_NONE,
    TRANSFORM_VERSION_NONE,
  );
  let root = Hash32::sha3_256(&recipe);
  let rebuilt = SealedPackBuilder::build_plain(
    DEFAULT_FORMAT_TAG,
    root,
    [
      ObjectRecord {
        hash: chunk_hash,
        kind: ObjectKind::Chunk,
        decoded_len: file.len() as u64,
        codec: Codec::Raw,
        stored_bytes: file.to_vec(),
      },
      ObjectRecord {
        hash: root,
        kind: ObjectKind::Recipe,
        decoded_len: recipe.len() as u64,
        codec: Codec::Raw,
        stored_bytes: recipe,
      },
    ],
  )
  .unwrap();
  assert_eq!(rebuilt, GOLDEN);
}

#[cfg(all(feature = "sqlite-pack", feature = "sealed-encryption"))]
#[test]
fn shared_object_graph_is_identical_across_mutable_and_sealed_backends() {
  let fixture = shared_object_graph_fixture();
  let directory = tempfile::tempdir().unwrap();
  let pack = crate::SqlitePack::open(directory.path().join("pack.db")).unwrap();
  pack.put_objects_batch(&fixture.contract_objects).unwrap();

  let connection = rusqlite::Connection::open(directory.path().join("store.db")).unwrap();
  let store = crate::RusqliteStore::from_connection(&connection).unwrap();
  store.put_objects_batch(&fixture.contract_objects).unwrap();

  let plain_bytes = build_plain_bytes(DEFAULT_FORMAT_TAG, fixture.root, fixture.contract_objects.clone()).unwrap();
  let plain = open_plain(&plain_bytes, DEFAULT_FORMAT_TAG);
  let key = software_key(41, 9);
  let encrypted_bytes = build_encrypted_bytes(PRODUCT_TAG, fixture.root, fixture.contract_objects.clone(), &key).unwrap();
  let parsed = ParsedSealedPack::open(&encrypted_bytes, PRODUCT_TAG, PackOpenPolicy::EncryptedRequired).unwrap();
  let encrypted = parsed.unlock(&key).unwrap();
  assert_object_source_contract(&pack, &fixture);
  assert_object_source_contract(&store, &fixture);
  assert_object_source_contract(&plain, &fixture);
  assert_object_source_contract(&encrypted, &fixture);

  let registry = crate::TransformDecoderRegistry::default();
  let pack_file = crate::FileReader::new(&pack, &registry, crate::FileReadLimits::default())
    .read_file(fixture.root)
    .unwrap();
  let store_file = crate::FileReader::new(&store, &registry, crate::FileReadLimits::default())
    .read_file(fixture.root)
    .unwrap();
  let plain_file = crate::FileReader::new(&plain, &registry, crate::FileReadLimits::default())
    .read_file(fixture.root)
    .unwrap();
  let encrypted_file = crate::FileReader::new(&encrypted, &registry, crate::FileReadLimits::default())
    .read_file(fixture.root)
    .unwrap();
  for file in [pack_file, store_file, plain_file, encrypted_file] {
    assert_eq!(file, fixture.file);
  }

  for (case, (codec, shape)) in [Codec::Raw, Codec::Zstd, Codec::Brotli]
    .into_iter()
    .flat_map(|codec| (0..4).map(move |shape| (codec, shape)))
    .enumerate()
  {
    let (root, objects, expected) = backend_file_fixture(codec, shape);
    let pack = crate::SqlitePack::open(directory.path().join(format!("matrix-pack-{case}.db"))).unwrap();
    pack.put_objects_batch(&objects).unwrap();
    let connection = rusqlite::Connection::open(directory.path().join(format!("matrix-store-{case}.db"))).unwrap();
    let store = crate::RusqliteStore::from_connection(&connection).unwrap();
    store.put_objects_batch(&objects).unwrap();
    let plain_bytes = SealedPackBuilder::build_plain(DEFAULT_FORMAT_TAG, root, objects.clone()).unwrap();
    let plain = open_plain(&plain_bytes, DEFAULT_FORMAT_TAG);
    let key = software_key(61, 12);
    let encrypted_bytes = SealedPackBuilder::build_encrypted(PRODUCT_TAG, root, objects, &key).unwrap();
    let parsed = ParsedSealedPack::open(&encrypted_bytes, PRODUCT_TAG, PackOpenPolicy::EncryptedRequired).unwrap();
    let encrypted = parsed.unlock(&key).unwrap();
    for actual in [
      restore_from(&pack, root),
      restore_from(&store, root),
      restore_from(&plain, root),
      restore_from(&encrypted, root),
    ] {
      assert_eq!(actual, expected, "codec {codec:?}, shape {shape}");
    }
  }
}

#[tokio::test]
async fn plain_build_is_deterministic_and_restores_with_file_reader() {
  let fixture = fixture(Codec::Zstd, 700_000);
  let first = SealedPackBuilder::build_plain(DEFAULT_FORMAT_TAG, fixture.root, fixture.objects.clone()).unwrap();
  let second = SealedPackBuilder::build_plain(DEFAULT_FORMAT_TAG, fixture.root, fixture.objects.clone()).unwrap();
  assert_eq!(first, second);

  let reader = open_plain(&first, DEFAULT_FORMAT_TAG);
  assert_eq!(reader.object_count(), 2);
  reader.verify_all_objects().unwrap();
  let registry = crate::TransformDecoderRegistry::default();
  let file = crate::FileReader::new(&reader, &registry, crate::FileReadLimits::default())
    .read_file(fixture.root)
    .unwrap();
  assert_eq!(file, fixture.file);
}

#[test]
fn large_directory_roundtrip_uses_the_same_builder_and_reader_limits() {
  let file_hash = Hash32::sha3_256([]);
  let recipe = build_recipe(0, &[], file_hash, TRANSFORM_ID_NONE, TRANSFORM_VERSION_NONE);
  let root = Hash32::sha3_256(&recipe);
  let mut objects = Vec::with_capacity(5_001);
  objects.push(ObjectRecord {
    hash: root,
    kind: ObjectKind::Recipe,
    decoded_len: recipe.len() as u64,
    codec: Codec::Raw,
    stored_bytes: recipe,
  });
  for value in 0..5_000_u64 {
    let content = value.to_le_bytes().to_vec();
    objects.push(ObjectRecord {
      hash: Hash32::sha3_256(&content),
      kind: ObjectKind::Chunk,
      decoded_len: content.len() as u64,
      codec: Codec::Raw,
      stored_bytes: content,
    });
  }
  let bytes = SealedPackBuilder::build_plain(DEFAULT_FORMAT_TAG, root, objects).unwrap();
  let reader = open_plain(&bytes, DEFAULT_FORMAT_TAG);
  assert_eq!(reader.object_count(), 5_001);
  reader.verify_all_objects().unwrap();
}

#[test]
fn logical_pack_id_excludes_tag_and_offsets() {
  let raw = fixture(Codec::Raw, 65_537);
  let zstd = fixture(Codec::Zstd, 65_537);
  assert_eq!(raw.root, zstd.root);
  let first = SealedPackBuilder::build_plain(DEFAULT_FORMAT_TAG, raw.root, raw.objects).unwrap();
  let second = SealedPackBuilder::build_plain(PRODUCT_TAG, zstd.root, zstd.objects).unwrap();
  let first = ParsedSealedPack::open(&first, DEFAULT_FORMAT_TAG, PackOpenPolicy::PlainAllowed).unwrap();
  let second = ParsedSealedPack::open(&second, PRODUCT_TAG, PackOpenPolicy::PlainAllowed).unwrap();
  assert_eq!(first.pack_id(), second.pack_id());
}

#[test]
fn wrong_tag_policy_and_plain_corruption_fail_closed() {
  let fixture = fixture(Codec::Brotli, 128_000);
  let bytes = SealedPackBuilder::build_plain(DEFAULT_FORMAT_TAG, fixture.root, fixture.objects).unwrap();
  assert!(ParsedSealedPack::open(&bytes, OTHER_TAG, PackOpenPolicy::PlainAllowed).is_err());
  assert!(ParsedSealedPack::open(&bytes, DEFAULT_FORMAT_TAG, PackOpenPolicy::EncryptedRequired).is_err());

  let mut corrupt_index = bytes.clone();
  corrupt_index[HEADER_BYTES] ^= 1;
  assert!(matches!(
    ParsedSealedPack::open(&corrupt_index, DEFAULT_FORMAT_TAG, PackOpenPolicy::PlainAllowed).and_then(|parsed| parsed.open_plain()),
    Err(crate::Error::InvalidSealed(_))
  ));

  let mut corrupt_payload = bytes.clone();
  corrupt_payload[bytes.len() - 1] ^= 1;
  let parsed = ParsedSealedPack::open(&corrupt_payload, DEFAULT_FORMAT_TAG, PackOpenPolicy::PlainAllowed).unwrap();
  let reader = parsed.open_plain().unwrap();
  let result = reader.verify_all_objects();
  assert!(matches!(result, Err(crate::Error::ObjectHashMismatch { .. })));

  for offset in [16, 22, 32, 40, 48, 56, 144, HEADER_BYTES, bytes.len() - 1] {
    let mut corrupted = bytes.clone();
    corrupted[offset] ^= 0x40;
    let result = ParsedSealedPack::open(&corrupted, DEFAULT_FORMAT_TAG, PackOpenPolicy::PlainAllowed)
      .and_then(|parsed| parsed.open_plain())
      .and_then(|reader| reader.verify_all_objects());
    assert!(result.is_err(), "corruption at offset {offset} was accepted");
  }
  for truncated in [0, 15, HEADER_BYTES - 1, HEADER_BYTES, bytes.len() - 1] {
    let result = ParsedSealedPack::open(&bytes[..truncated], DEFAULT_FORMAT_TAG, PackOpenPolicy::PlainAllowed)
      .and_then(|parsed| parsed.open_plain())
      .and_then(|reader| reader.verify_all_objects());
    assert!(result.is_err(), "truncation at {truncated} was accepted");
  }
}

#[test]
fn every_plain_pack_byte_mutation_and_truncation_fails_verification() {
  let fixture = fixture(Codec::Raw, 97);
  let bytes = SealedPackBuilder::build_plain(DEFAULT_FORMAT_TAG, fixture.root, fixture.objects).unwrap();

  for length in 0..bytes.len() {
    let result = ParsedSealedPack::open(&bytes[..length], DEFAULT_FORMAT_TAG, PackOpenPolicy::PlainAllowed)
      .and_then(|parsed| parsed.open_plain())
      .and_then(|reader| reader.verify_all_objects());
    assert!(result.is_err(), "truncation at {length} was accepted");
  }
  for offset in 0..bytes.len() {
    let mut corrupted = bytes.clone();
    corrupted[offset] ^= 0x80;
    let rejected = match ParsedSealedPack::open(&corrupted, DEFAULT_FORMAT_TAG, PackOpenPolicy::PlainAllowed) {
      Err(_) => true,
      Ok(parsed) => match parsed.open_plain() {
        Err(_) => true,
        Ok(reader) => reader.verify_all_objects().is_err(),
      },
    };
    assert!(rejected, "mutation at byte {offset} was accepted");
  }
  let mut extended = bytes;
  extended.extend_from_slice(b"trailing-garbage");
  let result = ParsedSealedPack::open(&extended, DEFAULT_FORMAT_TAG, PackOpenPolicy::PlainAllowed).and_then(|parsed| parsed.open_plain());
  assert!(result.is_err());
}

#[test]
fn brotli_payload_window_over_decoder_limit_is_rejected() {
  let file = b"large-window-brotli-payload".repeat(8);
  let mut encoder = brotli::CompressorWriter::new(Vec::new(), 4096, 11, 22);
  std::io::Write::write_all(&mut encoder, &file).unwrap();
  let stored = encoder.into_inner();
  let chunk_hash = Hash32::sha3_256(&file);
  let recipe = build_recipe(
    file.len() as u64,
    &[(chunk_hash, file.len() as u32)],
    chunk_hash,
    TRANSFORM_ID_NONE,
    TRANSFORM_VERSION_NONE,
  );
  let root = Hash32::sha3_256(&recipe);
  let bytes = SealedPackBuilder::build_plain(
    DEFAULT_FORMAT_TAG,
    root,
    [
      ObjectRecord {
        hash: chunk_hash,
        kind: ObjectKind::Chunk,
        decoded_len: file.len() as u64,
        codec: Codec::Brotli,
        stored_bytes: stored,
      },
      ObjectRecord {
        hash: root,
        kind: ObjectKind::Recipe,
        decoded_len: recipe.len() as u64,
        codec: Codec::Raw,
        stored_bytes: recipe,
      },
    ],
  )
  .unwrap();
  let reader = open_plain(&bytes, DEFAULT_FORMAT_TAG);
  let error = reader.verify_all_objects().unwrap_err();
  assert!(matches!(error, crate::Error::InvalidSealed(_)));
  assert!(error.to_string().contains("Brotli window exceeds sealed decoder limit"), "{error}");
}

fn mutate_plain_index(bytes: &mut Vec<u8>, mutate: impl FnOnce(&mut Vec<u8>)) {
  let header = parse_header(bytes, DEFAULT_FORMAT_TAG).unwrap();
  let range = checked_range(bytes.len(), HEADER_BYTES as u64, header.index_stored_length, "test index").unwrap();
  let mut decoded = zstd::stream::decode_all(&bytes[range.clone()]).unwrap();
  mutate(&mut decoded);
  let stored = index::compress_index(&decoded).unwrap();
  let mut header = header;
  header.index_stored_length = stored.len() as u64;
  bytes.splice(range, stored.iter().copied());
  header.index_digest = stored_index_digest(&header, &stored);
  bytes[..HEADER_BYTES].copy_from_slice(&header.encode());
}

#[test]
fn canonical_directory_semantics_reject_reordering_duplicates_partial_records_and_unknown_fields() {
  let fixture = fixture(Codec::Raw, 4097);
  let bytes = SealedPackBuilder::build_plain(DEFAULT_FORMAT_TAG, fixture.root, fixture.objects).unwrap();
  let mut cases = Vec::new();
  cases.push(Box::new(|index: &mut Vec<u8>| {
    let (first, second) = index[32..].split_at_mut(DIRECTORY_RECORD_BYTES);
    first.swap_with_slice(&mut second[..DIRECTORY_RECORD_BYTES]);
  }) as Box<dyn FnOnce(&mut Vec<u8>)>);
  cases.push(Box::new(|index: &mut Vec<u8>| {
    let first_hash = index[32..64].to_vec();
    index[82..114].copy_from_slice(&first_hash);
  }));
  cases.push(Box::new(|index: &mut Vec<u8>| index[32 + 32] = 99));
  cases.push(Box::new(|index: &mut Vec<u8>| index[32 + 33] = 99));
  cases.push(Box::new(|index: &mut Vec<u8>| index[..32].fill(0xA5)));
  cases.push(Box::new(|index: &mut Vec<u8>| {
    index.truncate(index.len() - 1);
  }));
  cases.push(Box::new(|index: &mut Vec<u8>| index.truncate(32)));
  for (case, mutate) in cases.into_iter().enumerate() {
    let mut corrupted = bytes.clone();
    mutate_plain_index(&mut corrupted, mutate);
    let result =
      ParsedSealedPack::open(&corrupted, DEFAULT_FORMAT_TAG, PackOpenPolicy::PlainAllowed).and_then(|parsed| parsed.open_plain());
    assert!(result.is_err(), "canonical corruption case {case} was accepted");
  }
}

#[test]
fn duplicate_missing_and_wrong_recipe_objects_are_rejected() {
  let fixture = fixture(Codec::Raw, 1024);
  let mut duplicate = fixture.objects.clone();
  duplicate.push(duplicate[0].clone());
  assert!(SealedPackBuilder::build_plain(DEFAULT_FORMAT_TAG, fixture.root, duplicate).is_err());
  assert!(SealedPackBuilder::build_plain(DEFAULT_FORMAT_TAG, fixture.root, fixture.objects[..1].iter().cloned()).is_err());
  assert!(SealedPackBuilder::build_plain(DEFAULT_FORMAT_TAG, fixture.objects[0].hash, fixture.objects.iter().cloned()).is_err());
}

#[cfg(feature = "sealed-encryption")]
fn software_key(secret: u8, slot: u8) -> SoftwareFrameKey {
  SoftwareFrameKey::new([secret; 32], [slot; 16])
}

#[cfg(feature = "sealed-encryption")]
#[tokio::test]
async fn encrypted_builds_are_random_but_keep_logical_identity() {
  let fixture = fixture(Codec::Raw, MAX_ENCRYPTED_FRAME_BYTES * 2 + 91);
  let key = software_key(7, 3);
  let first = SealedPackBuilder::build_encrypted(PRODUCT_TAG, fixture.root, fixture.objects.clone(), &key).unwrap();
  let second = SealedPackBuilder::build_encrypted(PRODUCT_TAG, fixture.root, fixture.objects, &key).unwrap();
  assert_ne!(first, second);
  let first_parsed = ParsedSealedPack::open(&first, PRODUCT_TAG, PackOpenPolicy::EncryptedRequired).unwrap();
  let second_parsed = ParsedSealedPack::open(&second, PRODUCT_TAG, PackOpenPolicy::EncryptedRequired).unwrap();
  assert_eq!(first_parsed.pack_id(), second_parsed.pack_id());
  let first_reader = first_parsed.unlock(&key).unwrap();
  let registry = crate::TransformDecoderRegistry::default();
  let decoded = crate::FileReader::new(&first_reader, &registry, crate::FileReadLimits::default())
    .read_file(fixture.root)
    .unwrap();
  assert_eq!(decoded, fixture.file);
}

#[cfg(feature = "sealed-encryption")]
fn rewrite_encrypted_header(bytes: &mut [u8], mut header: Header) {
  let range = checked_range(bytes.len(), HEADER_BYTES as u64, header.index_stored_length, "test index").unwrap();
  header.index_digest = stored_index_digest(&header, &bytes[range]);
  bytes[..HEADER_BYTES].copy_from_slice(&header.encode());
}

#[cfg(feature = "sealed-encryption")]
#[test]
fn encrypted_index_aad_rejects_header_tampering_and_cross_pack_replacement_after_digest_recompute() {
  let fixture = fixture(Codec::Raw, 8193);
  let key = software_key(23, 7);
  let first = SealedPackBuilder::build_encrypted(PRODUCT_TAG, fixture.root, fixture.objects.clone(), &key).unwrap();
  let second = SealedPackBuilder::build_encrypted(PRODUCT_TAG, fixture.root, fixture.objects, &key).unwrap();

  let mut pack_id_tamper = first.clone();
  let mut header = parse_header(&pack_id_tamper, PRODUCT_TAG).unwrap();
  header.pack_id = Hash32::new([0x5a; 32]);
  rewrite_encrypted_header(&mut pack_id_tamper, header);
  let parsed = ParsedSealedPack::open(&pack_id_tamper, PRODUCT_TAG, PackOpenPolicy::EncryptedRequired).unwrap();
  assert!(matches!(parsed.unlock(&key), Err(crate::Error::AuthenticationFailed)));

  let mut salt_tamper = first.clone();
  let mut header = parse_header(&salt_tamper, PRODUCT_TAG).unwrap();
  header.pack_salt[0] ^= 1;
  rewrite_encrypted_header(&mut salt_tamper, header);
  let parsed = ParsedSealedPack::open(&salt_tamper, PRODUCT_TAG, PackOpenPolicy::EncryptedRequired).unwrap();
  assert!(matches!(parsed.unlock(&key), Err(crate::Error::AuthenticationFailed)));

  let mut slot_tamper = first.clone();
  let mut header = parse_header(&slot_tamper, PRODUCT_TAG).unwrap();
  header.key_slot = [8; 16];
  rewrite_encrypted_header(&mut slot_tamper, header);
  let parsed = ParsedSealedPack::open(&slot_tamper, PRODUCT_TAG, PackOpenPolicy::EncryptedRequired).unwrap();
  assert!(matches!(
    parsed.unlock(&software_key(23, 8)),
    Err(crate::Error::AuthenticationFailed)
  ));

  let first_header = parse_header(&first, PRODUCT_TAG).unwrap();
  let second_header = parse_header(&second, PRODUCT_TAG).unwrap();
  assert_eq!(first_header.index_stored_length, second_header.index_stored_length);
  let range = checked_range(first.len(), HEADER_BYTES as u64, first_header.index_stored_length, "test index").unwrap();
  let mut substituted = first.clone();
  substituted[range.clone()].copy_from_slice(&second[range]);
  rewrite_encrypted_header(&mut substituted, first_header);
  let parsed = ParsedSealedPack::open(&substituted, PRODUCT_TAG, PackOpenPolicy::EncryptedRequired).unwrap();
  assert!(matches!(parsed.unlock(&key), Err(crate::Error::AuthenticationFailed)));
}

#[cfg(feature = "sealed-encryption")]
#[test]
fn encrypted_payload_boundaries_have_exact_contiguous_cursors() {
  let key = software_key(29, 9);
  for size in [0, 1, MAX_ENCRYPTED_FRAME_BYTES, MAX_ENCRYPTED_FRAME_BYTES + 1] {
    let fixture = fixture(Codec::Raw, size);
    let bytes = SealedPackBuilder::build_encrypted(PRODUCT_TAG, fixture.root, fixture.objects, &key).unwrap();
    let parsed = ParsedSealedPack::open(&bytes, PRODUCT_TAG, PackOpenPolicy::EncryptedRequired).unwrap();
    let reader = parsed.unlock(&key).unwrap();
    let mut cursor = HEADER_BYTES as u64 + reader.header.index_stored_length;
    for record in &reader.records {
      assert_eq!(record.payload_offset, cursor);
      cursor += record.stored_length + frame_count(record.stored_length) * 16;
    }
    assert_eq!(cursor, bytes.len() as u64);
  }
}

#[cfg(feature = "sealed-encryption")]
#[tokio::test]
async fn encrypted_open_rejects_default_tag_slot_key_and_frame_corruption() {
  let fixture = fixture(Codec::Raw, MAX_ENCRYPTED_FRAME_BYTES + 9);
  let key = software_key(9, 5);
  assert!(SealedPackBuilder::build_encrypted(DEFAULT_FORMAT_TAG, fixture.root, fixture.objects.clone(), &key).is_err());
  let bytes = SealedPackBuilder::build_encrypted(PRODUCT_TAG, fixture.root, fixture.objects, &key).unwrap();
  let parsed = ParsedSealedPack::open(&bytes, PRODUCT_TAG, PackOpenPolicy::EncryptedRequired).unwrap();
  assert!(matches!(
    parsed.unlock(&software_key(9, 6)),
    Err(crate::Error::AuthenticationFailed)
  ));
  assert!(matches!(
    parsed.unlock(&software_key(8, 5)),
    Err(crate::Error::AuthenticationFailed)
  ));

  let truncated = &bytes[..bytes.len() - 1];
  let truncated_parsed = ParsedSealedPack::open(truncated, PRODUCT_TAG, PackOpenPolicy::EncryptedRequired).unwrap();
  assert!(matches!(truncated_parsed.unlock(&key), Err(crate::Error::InvalidSealed(_))));

  let reader = parsed.unlock(&key).unwrap();
  let chunk = reader.records.iter().find(|record| record.kind == ObjectKind::Chunk).unwrap();
  let chunk_hash = chunk.hash;
  let payload_offset = chunk.payload_offset as usize;
  let mut corrupted = bytes.clone();
  corrupted[payload_offset] ^= 1;
  let parsed = ParsedSealedPack::open(&corrupted, PRODUCT_TAG, PackOpenPolicy::EncryptedRequired).unwrap();
  let reader = parsed.unlock(&key).unwrap();
  assert!(matches!(reader.read_object(&chunk_hash), Err(crate::Error::AuthenticationFailed)));
}

#[cfg(feature = "sealed-encryption")]
#[test]
fn encrypted_frames_reject_cross_pack_substitution_and_reordering() {
  let fixture = fixture(Codec::Raw, MAX_ENCRYPTED_FRAME_BYTES * 2 + 91);
  let key = software_key(13, 8);
  let first = SealedPackBuilder::build_encrypted(PRODUCT_TAG, fixture.root, fixture.objects.clone(), &key).unwrap();
  let second = SealedPackBuilder::build_encrypted(PRODUCT_TAG, fixture.root, fixture.objects, &key).unwrap();

  let first_parsed = ParsedSealedPack::open(&first, PRODUCT_TAG, PackOpenPolicy::EncryptedRequired).unwrap();
  let first_reader = first_parsed.unlock(&key).unwrap();
  let first_offset = first_reader
    .records
    .iter()
    .find(|record| record.kind == ObjectKind::Chunk)
    .unwrap()
    .payload_offset as usize;
  let second_parsed = ParsedSealedPack::open(&second, PRODUCT_TAG, PackOpenPolicy::EncryptedRequired).unwrap();
  let second_reader = second_parsed.unlock(&key).unwrap();
  let second_offset = second_reader
    .records
    .iter()
    .find(|record| record.kind == ObjectKind::Chunk)
    .unwrap()
    .payload_offset as usize;
  let physical_frame = MAX_ENCRYPTED_FRAME_BYTES + 16;

  let mut substituted = second.clone();
  substituted[second_offset..second_offset + physical_frame].copy_from_slice(&first[first_offset..first_offset + physical_frame]);
  let parsed = ParsedSealedPack::open(&substituted, PRODUCT_TAG, PackOpenPolicy::EncryptedRequired).unwrap();
  let reader = parsed.unlock(&key).unwrap();
  assert!(reader.verify_all_objects().is_err());

  let mut reordered = first.clone();
  let two_frames = &mut reordered[first_offset..first_offset + physical_frame * 2];
  let (first_frame, second_frame) = two_frames.split_at_mut(physical_frame);
  first_frame.swap_with_slice(second_frame);
  let parsed = ParsedSealedPack::open(&reordered, PRODUCT_TAG, PackOpenPolicy::EncryptedRequired).unwrap();
  let reader = parsed.unlock(&key).unwrap();
  assert!(reader.verify_all_objects().is_err());
}

#[cfg(feature = "sealed-encryption")]
#[test]
fn encrypted_frames_reject_cross_object_substitution() {
  let fixture = two_chunk_fixture(MAX_ENCRYPTED_FRAME_BYTES + 17);
  let key = software_key(17, 4);
  let mut bytes = SealedPackBuilder::build_encrypted(PRODUCT_TAG, fixture.root, fixture.objects, &key).unwrap();
  let offsets = {
    let parsed = ParsedSealedPack::open(&bytes, PRODUCT_TAG, PackOpenPolicy::EncryptedRequired).unwrap();
    let reader = parsed.unlock(&key).unwrap();
    reader
      .records
      .iter()
      .filter(|record| record.kind == ObjectKind::Chunk)
      .map(|record| record.payload_offset as usize)
      .collect::<Vec<_>>()
  };
  assert_eq!(offsets.len(), 2);
  let physical_frame = MAX_ENCRYPTED_FRAME_BYTES + 16;
  let (before_second, from_second) = bytes.split_at_mut(offsets[1]);
  before_second[offsets[0]..offsets[0] + physical_frame].copy_from_slice(&from_second[..physical_frame]);
  let parsed = ParsedSealedPack::open(&bytes, PRODUCT_TAG, PackOpenPolicy::EncryptedRequired).unwrap();
  let reader = parsed.unlock(&key).unwrap();
  assert!(reader.verify_all_objects().is_err());
}

#[cfg(feature = "sealed-encryption")]
#[test]
fn frame_contexts_are_unique() {
  let fixture = fixture(Codec::Raw, MAX_ENCRYPTED_FRAME_BYTES * 3 + 7);
  let key = software_key(11, 2);
  let bytes = SealedPackBuilder::build_encrypted(PRODUCT_TAG, fixture.root, fixture.objects, &key).unwrap();
  let parsed = ParsedSealedPack::open(&bytes, PRODUCT_TAG, PackOpenPolicy::EncryptedRequired).unwrap();
  let reader = parsed.unlock(&key).unwrap();
  let mut contexts = BTreeSet::from([SealedRecordContext::index(&reader.header).kdf_info().to_vec()]);
  let mut expected = 1_usize;
  for record in &reader.records {
    for index in 0..frame_count(record.stored_length) {
      let inserted = contexts.insert(
        SealedRecordContext::frame(
          &reader.header,
          record,
          index,
          frame_count(record.stored_length),
          (record.stored_length - index * MAX_ENCRYPTED_FRAME_BYTES as u64).min(MAX_ENCRYPTED_FRAME_BYTES as u64),
        )
        .kdf_info()
        .to_vec(),
      );
      assert!(inserted);
      expected += 1;
    }
  }
  assert_eq!(contexts.len(), expected);
}

#[cfg(feature = "sealed-encryption")]
#[test]
fn reseal_rejects_wrong_tags_and_encrypted_source() {
  let fixture = fixture(Codec::Raw, 1024);
  let key = software_key(31, 6);
  let plain = SealedPackBuilder::build_plain(DEFAULT_FORMAT_TAG, fixture.root, fixture.objects.clone()).unwrap();
  assert!(SealedPackBuilder::reseal_plain_as_encrypted(&plain, OTHER_TAG, PRODUCT_TAG, &key).is_err());
  assert!(SealedPackBuilder::reseal_plain_as_encrypted(&plain, DEFAULT_FORMAT_TAG, DEFAULT_FORMAT_TAG, &key).is_err());
  let encrypted = SealedPackBuilder::build_encrypted(PRODUCT_TAG, fixture.root, fixture.objects, &key).unwrap();
  assert!(SealedPackBuilder::reseal_plain_as_encrypted(&encrypted, PRODUCT_TAG, OTHER_TAG, &key).is_err());
}

#[cfg(feature = "sealed-encryption")]
#[test]
fn reseal_rejects_malformed_truncated_and_noncanonical_sources() {
  let fixture = fixture(Codec::Raw, 4097);
  let key = software_key(37, 11);
  let plain = SealedPackBuilder::build_plain(DEFAULT_FORMAT_TAG, fixture.root, fixture.objects).unwrap();
  assert!(SealedPackBuilder::reseal_plain_as_encrypted(&[], DEFAULT_FORMAT_TAG, PRODUCT_TAG, &key).is_err());
  for truncated in [HEADER_BYTES - 1, HEADER_BYTES, plain.len() - 1] {
    assert!(
      SealedPackBuilder::reseal_plain_as_encrypted(&plain[..truncated], DEFAULT_FORMAT_TAG, PRODUCT_TAG, &key).is_err(),
      "truncation at {truncated} was accepted"
    );
  }
  let mut corrupt_index = plain.clone();
  corrupt_index[HEADER_BYTES] ^= 1;
  assert!(SealedPackBuilder::reseal_plain_as_encrypted(&corrupt_index, DEFAULT_FORMAT_TAG, PRODUCT_TAG, &key).is_err());
  let mut trailing = plain.clone();
  trailing.extend_from_slice(b"trailing-garbage");
  assert!(SealedPackBuilder::reseal_plain_as_encrypted(&trailing, DEFAULT_FORMAT_TAG, PRODUCT_TAG, &key).is_err());
  let mut wrong_root = plain.clone();
  mutate_plain_index(&mut wrong_root, |index| index[..32].fill(0xA5));
  assert!(SealedPackBuilder::reseal_plain_as_encrypted(&wrong_root, DEFAULT_FORMAT_TAG, PRODUCT_TAG, &key).is_err());
  let mut gap = plain.clone();
  mutate_plain_index(&mut gap, |index| {
    let stored = u64::from_le_bytes(index[32 + 42..32 + 50].try_into().unwrap());
    index[32 + 42..32 + 50].copy_from_slice(&(stored - 1).to_le_bytes());
  });
  assert!(SealedPackBuilder::reseal_plain_as_encrypted(&gap, DEFAULT_FORMAT_TAG, PRODUCT_TAG, &key).is_err());
}

#[cfg(feature = "sealed-encryption")]
#[test]
fn reseal_preserves_identity_and_object_reads_across_frame_boundaries() {
  let key = software_key(47, 13);
  for size in [0, 1, MAX_ENCRYPTED_FRAME_BYTES, MAX_ENCRYPTED_FRAME_BYTES + 1] {
    let fixture = fixture(Codec::Raw, size);
    let plain = SealedPackBuilder::build_plain(DEFAULT_FORMAT_TAG, fixture.root, fixture.objects).unwrap();
    let source = open_plain(&plain, DEFAULT_FORMAT_TAG);
    let first = SealedPackBuilder::reseal_plain_as_encrypted(&plain, DEFAULT_FORMAT_TAG, PRODUCT_TAG, &key).unwrap();
    let second = SealedPackBuilder::reseal_plain_as_encrypted(&plain, DEFAULT_FORMAT_TAG, PRODUCT_TAG, &key).unwrap();
    assert_ne!(first, second, "size {size}");
    assert_eq!(
      ParsedSealedPack::open(&first, PRODUCT_TAG, PackOpenPolicy::EncryptedRequired)
        .unwrap()
        .pack_id(),
      source.pack_id(),
      "size {size}"
    );
    assert_eq!(
      ParsedSealedPack::open(&second, PRODUCT_TAG, PackOpenPolicy::EncryptedRequired)
        .unwrap()
        .pack_id(),
      source.pack_id(),
      "size {size}"
    );
    for packed in [&first, &second] {
      let reader = ParsedSealedPack::open(packed, PRODUCT_TAG, PackOpenPolicy::EncryptedRequired)
        .unwrap()
        .unlock(&key)
        .unwrap();
      assert_eq!(reader.root_recipe(), fixture.root, "size {size}");
      reader.verify_all_objects().unwrap();
      for record in &source.records {
        let expected = source.read_object(&record.hash).unwrap().unwrap();
        let actual = reader.read_object(&record.hash).unwrap().unwrap();
        assert_eq!(actual.hash, expected.hash, "size {size}");
        assert_eq!(actual.kind, expected.kind, "size {size}");
        assert_eq!(actual.bytes, expected.bytes, "size {size}");
      }
    }
  }
}

#[cfg(feature = "sealed-encryption")]
#[test]
fn reseal_copies_corrupt_stored_bytes_which_fail_object_verification() {
  let fixture = fixture(Codec::Raw, 4097);
  let key = software_key(53, 14);
  let mut plain = SealedPackBuilder::build_plain(DEFAULT_FORMAT_TAG, fixture.root, fixture.objects).unwrap();
  let last = plain.len() - 1;
  plain[last] ^= 1;
  let resealed = SealedPackBuilder::reseal_plain_as_encrypted(&plain, DEFAULT_FORMAT_TAG, PRODUCT_TAG, &key).unwrap();
  let reader = ParsedSealedPack::open(&resealed, PRODUCT_TAG, PackOpenPolicy::EncryptedRequired)
    .unwrap()
    .unlock(&key)
    .unwrap();
  assert!(matches!(reader.verify_all_objects(), Err(crate::Error::ObjectHashMismatch { .. })));
}
