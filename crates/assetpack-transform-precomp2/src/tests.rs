use std::{
  collections::BTreeMap,
  io::{BufReader, Cursor},
};

use assetpack_core::{
  AsyncFileReader, DEFAULT_FORMAT_TAG, FileHint, FileReadLimits, FileReader, FileTransformConfig, FileTransformPrecomp2Config, Hash32,
  ObjectKind, ObjectRecord, ObjectSource, PackOpenPolicy, ParsedSealedPack, SealedPackBuilder, SealedPackTag, SoftwareFrameKey, SqlitePack,
  SqlxStore, TRANSFORM_ID_NONE, TRANSFORM_ID_PRECOMP2, TRANSFORM_ID_PRECOMP2_LZMA, TRANSFORM_ID_PRECOMP2_ZSTD, TransformDecoderRegistry,
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
      "096f5d3ac56ddbbfff3496dc86ead0ab748edcdf887a56f946bdb87feab7ba11",
    ),
    (
      Some(&precomp2_zstd),
      121,
      "d1f83a4bb737fa8cb9a95700923818413a5ed1a7cf829fe4201f230c0dffbf5f",
    ),
    (
      Some(&precomp2_lzma),
      113,
      "992791cc4c1d2b855a7a71a7c1f3d273e541edbe23a1a893a077738d790d6c39",
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
    (TRANSFORM_ID_PRECOMP2, 2),
    (TRANSFORM_ID_PRECOMP2_ZSTD, 2),
    (TRANSFORM_ID_PRECOMP2_LZMA, 2),
  ] {
    let decoder = registry.get(id, version).unwrap();
    assert_eq!((decoder.id(), decoder.version()), (id, version));
  }
}

#[derive(Default)]
struct MemorySource(BTreeMap<Hash32, VerifiedObject>);

impl ObjectSource for MemorySource {
  fn read_object(&self, hash: &Hash32) -> assetpack_core::Result<Option<VerifiedObject>> {
    Ok(self.0.get(hash).cloned())
  }
}

fn read_file<S: ObjectSource + ?Sized>(source: &S, registry: &TransformDecoderRegistry, recipe_hash: Hash32) -> Vec<u8> {
  FileReader::new(source, registry, FileReadLimits::default())
    .read_file(recipe_hash)
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
    (TRANSFORM_ID_PRECOMP2, 2, Some(&precomp2)),
    (TRANSFORM_ID_PRECOMP2_ZSTD, 1, Some(&precomp2_zstd)),
    (TRANSFORM_ID_PRECOMP2_ZSTD, 2, Some(&precomp2_zstd)),
    (TRANSFORM_ID_PRECOMP2_LZMA, 1, Some(&precomp2_lzma)),
    (TRANSFORM_ID_PRECOMP2_LZMA, 2, Some(&precomp2_lzma)),
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
    assert_eq!(reader.read_file(recipe_hash).unwrap(), TINY_PNG, "transform {id}:{version}");

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
    let pack = SqlitePack::open(directory.path().join("pack.db")).unwrap();
    pack.put_objects_batch(&objects).unwrap();
    let store = SqlxStore::open(directory.path().join("store.db")).await.unwrap();
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
      read_file(&pack, &registry, recipe_hash),
      AsyncFileReader::new(&store, &registry, FileReadLimits::default())
        .read_file(recipe_hash)
        .await
        .unwrap(),
      read_file(&plain, &registry, recipe_hash),
      read_file(&encrypted, &registry, recipe_hash),
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
  assert_eq!(config.max_webp_pixels, encode.max_webp_pixels);
  assert_eq!(config.recover, decode.recover);
}

#[test]
fn precomp2_encode_config_enables_features() {
  let config = FileTransformPrecomp2Config::default();
  let encode = crate::common::precomp2_encode_config(&config);
  assert!(encode.enable_png_webp);
  assert_eq!(encode.max_webp_pixels, 16_777_216);
  assert!(encode.enable_pdf_predictor);
  assert!(encode.enable_pdf_dct);
  assert!(encode.enable_pdf_ascii);
  assert!(encode.enable_pdf_images);
  assert_eq!(encode.max_pdf_filters, config.max_pdf_filters);

  let custom = FileTransformPrecomp2Config {
    enable_png_webp: false,
    max_webp_pixels: 4096,
    ..Default::default()
  };
  let custom_encode = crate::common::precomp2_encode_config(&custom);
  assert!(!custom_encode.enable_png_webp);
  assert_eq!(custom_encode.max_webp_pixels, 4096);
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

#[test]
fn pdf_v2_shared_candidates_restore_from_plain_pack() {
  use assetpack_core::{
    Codec,
    file_transform::{TransformEncodeContext, TransformSelection},
    pipeline::{DefaultChunkCompressor, Pipeline},
  };
  let length = 8193usize;
  let mut pdf = format!("%PDF-1.7\n1 0 obj << /Length {length} /Filter /ASCIIHexDecode >> stream\n").into_bytes();
  pdf.extend_from_slice(&b"41".repeat(4096));
  pdf.extend_from_slice(b">\nendstream\nendobj\n%%EOF\n");
  let config = FileTransformConfig::default();
  let registry = TransformDecoderRegistry::new(crate::default_decoders(&config)).unwrap();
  let mut context = TransformEncodeContext::default();
  for spec in crate::default_specs() {
    let transform = (spec.build)(&config);
    let mut shared = Vec::new();
    transform.encode_with_context(&pdf, &mut shared, &mut context).unwrap();
    let mut standalone = Vec::new();
    transform.encode(&mut Cursor::new(&pdf), &mut standalone).unwrap();
    assert_eq!(shared, standalone);
    assert_eq!(transform.version(), 2);
    let original_hash = Hash32::sha3_256(&pdf);
    let selection = TransformSelection {
      transform_id: transform.id(),
      transform_version: transform.version(),
      original_size: pdf.len() as u64,
      original_hash,
      stored_stream: shared,
    };
    let plan = Pipeline::new(Default::default())
      .run_with_selection(selection, Some("pdf"), &DefaultChunkCompressor)
      .unwrap();
    let refs = plan.chunks.iter().map(|chunk| (chunk.hash, chunk.raw_len)).collect::<Vec<_>>();
    let recipe = build_recipe(pdf.len() as u64, &refs, original_hash, transform.id(), transform.version());
    let recipe_hash = Hash32::sha3_256(&recipe);
    let mut objects = BTreeMap::new();
    for chunk in plan.chunks {
      objects.insert(
        chunk.hash,
        ObjectRecord {
          hash: chunk.hash,
          kind: ObjectKind::Chunk,
          decoded_len: chunk.raw_len as u64,
          codec: chunk.codec,
          stored_bytes: chunk.payload.unwrap(),
        },
      );
    }
    objects.insert(
      recipe_hash,
      ObjectRecord {
        hash: recipe_hash,
        kind: ObjectKind::Recipe,
        decoded_len: recipe.len() as u64,
        codec: Codec::Raw,
        stored_bytes: recipe,
      },
    );
    let bytes = SealedPackBuilder::build_plain(DEFAULT_FORMAT_TAG, recipe_hash, objects.into_values()).unwrap();
    let parsed = ParsedSealedPack::open(&bytes, DEFAULT_FORMAT_TAG, PackOpenPolicy::PlainAllowed).unwrap();
    assert_eq!(read_file(&parsed.open_plain().unwrap(), &registry, recipe_hash), pdf);
  }
}

/// Minimal v6 UnityFS bundle with one LZ4HC storage block that the 1.10.0
/// compressor reproduces, so the container codec converts it.
fn build_unityfs_fixture() -> Vec<u8> {
  let payload = b"unityfs asset payload with some repetition; ".repeat(2000);
  let compressed = precomp2::codec::lz4::Compressor::V1_10_0_L12
    .compress(&payload, payload.len() + 16)
    .expect("compress fixture block");

  let mut info = Vec::new();
  info.extend_from_slice(&[0u8; 16]);
  info.extend_from_slice(&1u32.to_be_bytes());
  info.extend_from_slice(&(payload.len() as u32).to_be_bytes());
  info.extend_from_slice(&(compressed.len() as u32).to_be_bytes());
  info.extend_from_slice(&3u16.to_be_bytes());
  info.extend_from_slice(&0u32.to_be_bytes());

  let mut bundle = Vec::new();
  bundle.extend_from_slice(b"UnityFS\0");
  bundle.extend_from_slice(&6u32.to_be_bytes());
  bundle.extend_from_slice(b"6000.0.23f1");
  bundle.push(0);
  bundle.extend_from_slice(b"0.0.0f0");
  bundle.push(0);
  bundle.extend_from_slice(&0i64.to_be_bytes()); // size placeholder
  bundle.extend_from_slice(&(info.len() as u32).to_be_bytes());
  bundle.extend_from_slice(&(info.len() as u32).to_be_bytes());
  bundle.extend_from_slice(&0u32.to_be_bytes()); // flags: uncompressed info at start
  bundle.extend_from_slice(&info);
  bundle.extend_from_slice(&compressed);
  let size = bundle.len() as i64;
  let size_offset = 8 + 4 + b"6000.0.23f1".len() + 1 + 8;
  bundle[size_offset..size_offset + 8].copy_from_slice(&size.to_be_bytes());
  bundle
}

#[test]
fn unityfs_magic_selects_precomp2_and_roundtrips() {
  let config = FileTransformConfig {
    min_size: 0,
    ..Default::default()
  };
  let transform = crate::Precomp2Transform::new(&config);
  let bundle = build_unityfs_fixture();

  let hint = FileHint {
    size: bundle.len() as u64,
    extension: None,
    head: Some(bundle[..8].to_vec()),
  };
  assert!(transform.quick_check(&hint), "UnityFS magic must be recognized");

  assert_roundtrip_keeps_hash(&transform, &bundle);

  let mut encoded = Vec::new();
  transform.encode(&mut BufReader::new(Cursor::new(&bundle)), &mut encoded).unwrap();
  let pcf2 = precomp2::Pcf2File::decode(encoded.as_slice()).unwrap();
  assert!(
    pcf2
      .segments
      .iter()
      .any(|segment| segment.kind == precomp2::SegmentKind::UnityFs as u8),
    "bundle block should be converted to a UnityFs segment"
  );
}

#[test]
fn malformed_six_byte_input_returns_err_across_all_precomp2_decoders() {
  let bad_precomp: &[u8] = b"\x00\x05\x00\x00\x00\x00";
  let config = FileTransformConfig::default();
  let dict_size = crate::common::clamp_dict_size(config.precomp2_lzma.dict_size);
  let bad_zstd = crate::common::zstd_compress(bad_precomp, 1).unwrap();
  let bad_lzma = crate::common::lzma_compress(bad_precomp, 1, dict_size).unwrap();

  let precomp2 = crate::Precomp2Transform::new(&config);
  let precomp2_zstd = crate::Precomp2ZstdTransform::new(&config);
  let precomp2_lzma = crate::Precomp2LzmaTransform::new(&config);

  for (label, decoder, payload) in [
    ("raw-precomp2", &precomp2 as &dyn assetpack_core::TransformDecoder, bad_precomp),
    ("raw-zstd", &precomp2_zstd as &dyn assetpack_core::TransformDecoder, bad_precomp),
    (
      "wrapped-zstd",
      &precomp2_zstd as &dyn assetpack_core::TransformDecoder,
      bad_zstd.as_slice(),
    ),
    ("raw-lzma", &precomp2_lzma as &dyn assetpack_core::TransformDecoder, bad_precomp),
    (
      "wrapped-lzma",
      &precomp2_lzma as &dyn assetpack_core::TransformDecoder,
      bad_lzma.as_slice(),
    ),
  ] {
    let mut out = Vec::new();
    let err = decoder.decode(&mut BufReader::new(Cursor::new(payload)), &mut out);
    assert!(err.is_err(), "{label} must return Err, not panic or succeed");
  }
}

#[test]
fn compressed_zero_bombs_fail_bounded_without_full_decompression() {
  let config = FileTransformConfig {
    precomp2: FileTransformPrecomp2Config {
      max_total_output: 64 * 1024,
      ..Default::default()
    },
    ..Default::default()
  };
  let dict_size = crate::common::clamp_dict_size(config.precomp2_lzma.dict_size);
  let registry = TransformDecoderRegistry::new(crate::default_decoders(&config)).unwrap();

  // 1. 4 MiB all-zero zstd & lzma bombs claiming original_file_size = 64 fail
  //    cleanly on magic check.
  let raw_zeros = vec![0u8; 4 << 20];
  let zstd_zero_bomb = crate::common::zstd_compress(&raw_zeros, 3).unwrap();
  let lzma_zero_bomb = crate::common::lzma_compress(&raw_zeros, 1, dict_size).unwrap();
  assert!(zstd_zero_bomb.len() < 4096);
  assert!(lzma_zero_bomb.len() < 4096);

  // 2. 4 MiB valid PCF2 Lit container claiming 4 MiB wrapped in zstd & lzma,
  //    paired with a
  // recipe claiming original_file_size = 64 -> VerifyingWriter / decode budget
  // stops immediately.
  let lit_pcf2 = precomp2::encode_bytes(&raw_zeros, &precomp2::EncodeConfig::default()).unwrap();
  let zstd_lit_bomb = crate::common::zstd_compress(&lit_pcf2, 3).unwrap();
  let lzma_lit_bomb = crate::common::lzma_compress(&lit_pcf2, 1, dict_size).unwrap();

  // 3. Valid PCF2 header claiming original_size = 64, Dflt segment claiming
  //    data_len = 2 MiB of zeros.
  let mut forged_seg = Vec::new();
  precomp2::Pcf2Header::new(64).encode(&mut forged_seg).unwrap();
  forged_seg.push(precomp2::SegmentKind::Dflt as u8);
  forged_seg.push(0);
  precomp2::varint::write_varint(64, &mut forged_seg).unwrap();
  precomp2::varint::write_varint(0, &mut forged_seg).unwrap();
  precomp2::varint::write_varint(2 << 20, &mut forged_seg).unwrap();
  forged_seg.resize(forged_seg.len() + (2 << 20), 0);
  let zstd_seg_bomb = crate::common::zstd_compress(&forged_seg, 3).unwrap();
  let lzma_seg_bomb = crate::common::lzma_compress(&forged_seg, 1, dict_size).unwrap();

  for (label, transform_id, stored) in [
    ("zstd-zeros", TRANSFORM_ID_PRECOMP2_ZSTD, zstd_zero_bomb),
    ("lzma-zeros", TRANSFORM_ID_PRECOMP2_LZMA, lzma_zero_bomb),
    ("zstd-lit-4m", TRANSFORM_ID_PRECOMP2_ZSTD, zstd_lit_bomb),
    ("lzma-lit-4m", TRANSFORM_ID_PRECOMP2_LZMA, lzma_lit_bomb),
    ("zstd-seg-2m", TRANSFORM_ID_PRECOMP2_ZSTD, zstd_seg_bomb),
    ("lzma-seg-2m", TRANSFORM_ID_PRECOMP2_LZMA, lzma_seg_bomb),
  ] {
    let chunk_hash = Hash32::sha3_256(&stored);
    let recipe = build_recipe(
      64,
      &[(chunk_hash, stored.len() as u32)],
      Hash32::sha3_256([0u8; 64]),
      transform_id,
      2,
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
    assert!(reader.read_file(recipe_hash).is_err(), "{label} bomb must fail");
  }

  // 4. Even under default 4 GiB precomp2 decode budget: (a) a 4 MiB Lit bomb
  //    paired with recipe.original_file_size = 64 is rejected at the PCF2
  //    header via decode_for_size tightening (2 MiB cap); (b) a 128 KiB Lit
  //    bomb (within the 2 MiB floor, > 64 bytes) is stopped on the first
  //    streamed chunk by FileReader's VerifyingWriter.
  let default_cfg = FileTransformConfig::default();
  let default_registry = TransformDecoderRegistry::new(crate::default_decoders(&default_cfg)).unwrap();

  let stored_4m = crate::common::zstd_compress(&lit_pcf2, 3).unwrap();
  let chunk_hash_4m = Hash32::sha3_256(&stored_4m);
  let recipe_4m = build_recipe(
    64,
    &[(chunk_hash_4m, stored_4m.len() as u32)],
    Hash32::sha3_256([0u8; 64]),
    TRANSFORM_ID_PRECOMP2_ZSTD,
    2,
  );
  let recipe_hash_4m = Hash32::sha3_256(&recipe_4m);
  let source_4m = MemorySource(BTreeMap::from([
    (
      chunk_hash_4m,
      VerifiedObject {
        hash: chunk_hash_4m,
        kind: ObjectKind::Chunk,
        bytes: stored_4m,
      },
    ),
    (
      recipe_hash_4m,
      VerifiedObject {
        hash: recipe_hash_4m,
        kind: ObjectKind::Recipe,
        bytes: recipe_4m,
      },
    ),
  ]));
  let err_4m = FileReader::new(&source_4m, &default_registry, FileReadLimits::default())
    .read_file(recipe_hash_4m)
    .unwrap_err();
  assert!(err_4m.to_string().contains("budget"), "{err_4m:?}");

  let small_lit_pcf2 = precomp2::encode_bytes(&vec![0u8; 128 * 1024], &precomp2::EncodeConfig::default()).unwrap();
  let stored = crate::common::zstd_compress(&small_lit_pcf2, 3).unwrap();
  let chunk_hash = Hash32::sha3_256(&stored);
  let recipe = build_recipe(
    64,
    &[(chunk_hash, stored.len() as u32)],
    Hash32::sha3_256([0u8; 64]),
    TRANSFORM_ID_PRECOMP2_ZSTD,
    2,
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
  let err = FileReader::new(&source, &default_registry, FileReadLimits::default())
    .read_file(recipe_hash)
    .unwrap_err();
  assert!(matches!(err, assetpack_core::Error::OriginalFileMismatch { .. }), "{err:?}");
}

#[test]
fn default_specs_enable_quick_check_and_skip_non_matching_inputs() {
  use assetpack_core::{
    file_transform::{CandidateOutcome, SelectionReport},
    pipeline::{DefaultChunkCompressor, Pipeline},
  };

  let specs = crate::default_specs();
  assert_eq!(specs.len(), 3);
  assert!(specs.iter().all(|spec| spec.use_quick_check));

  let config = FileTransformConfig {
    min_size: 0,
    min_gain: -10.0,
    ..Default::default()
  };
  let selector = TransformSelector::new(config, None, specs);
  let pipeline = Pipeline::new(Default::default());

  for (ext, payload) in [
    (Some("txt"), b"plain text without any container magic header".repeat(16)),
    (None, vec![0xab; 512]),
  ] {
    let hint = FileHint {
      size: payload.len() as u64,
      extension: ext.map(str::to_string),
      head: Some(payload[..8].to_vec()),
    };
    let mut report = SelectionReport::default();
    let selection = selector
      .select_with_report(
        payload.clone(),
        &hint,
        Hash32::sha3_256(&payload),
        &pipeline,
        &DefaultChunkCompressor,
        &mut report,
      )
      .unwrap();
    assert_eq!(selection.transform_id, TRANSFORM_ID_NONE);
    assert_eq!(report.candidates.len(), 3);
    assert!(
      report.candidates.iter().all(|c| c.outcome == CandidateOutcome::Skipped),
      "expected all candidates skipped for ext={ext:?}, got {:?}",
      report.candidates
    );
  }
}

#[test]
fn fast_preset_bounds_encoding_while_decoding_historical_lzma() {
  let fast = FileTransformConfig::fast();
  assert_eq!(fast.max_in_memory_bytes, 32 * 1024 * 1024);
  assert_eq!(fast.max_transform_bytes, 32 * 1024 * 1024);
  assert_eq!(fast.eval.max_buffer_bytes, 64 * 1024 * 1024);
  assert_eq!(fast.precomp2.max_depth, 1);
  assert_eq!(fast.precomp2.max_total_output, 128 * 1024 * 1024);
  assert_eq!(fast.precomp2.max_webp_pixels, 8_388_608);
  assert_eq!(fast.precomp2_zstd.level, 3);
  assert!(!fast.precomp2_lzma.enabled);

  // Selector under fast() does not consider LZMA.
  use assetpack_core::{
    file_transform::SelectionReport,
    pipeline::{DefaultChunkCompressor, Pipeline},
  };
  let mut fast_selector_cfg = fast.clone();
  fast_selector_cfg.min_size = 0;
  fast_selector_cfg.min_gain = -10.0;
  let selector = TransformSelector::new(fast_selector_cfg, None, crate::default_specs());
  let mut report = SelectionReport::default();
  let hint = FileHint {
    size: TINY_PNG.len() as u64,
    extension: Some("png".into()),
    head: Some(TINY_PNG[..8].to_vec()),
  };
  selector
    .select_with_report(
      TINY_PNG.to_vec(),
      &hint,
      Hash32::sha3_256(TINY_PNG),
      &Pipeline::new(Default::default()),
      &DefaultChunkCompressor,
      &mut report,
    )
    .unwrap();
  assert!(
    report.candidates.iter().all(|c| c.transform_id != TRANSFORM_ID_PRECOMP2_LZMA),
    "fast() must disable LZMA candidate encoding"
  );

  // Historical LZMA objects still decode cleanly under default_decoders(&fast).
  let legacy_encoder = crate::Precomp2LzmaTransform::new(&FileTransformConfig::default());
  let mut stored = Vec::new();
  legacy_encoder
    .encode(&mut BufReader::new(Cursor::new(TINY_PNG)), &mut stored)
    .unwrap();
  let chunk_hash = Hash32::sha3_256(&stored);
  let recipe = build_recipe(
    TINY_PNG.len() as u64,
    &[(chunk_hash, stored.len() as u32)],
    Hash32::sha3_256(TINY_PNG),
    TRANSFORM_ID_PRECOMP2_LZMA,
    2,
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
  let fast_registry = TransformDecoderRegistry::new(crate::default_decoders(&fast)).unwrap();
  assert_eq!(read_file(&source, &fast_registry, recipe_hash), TINY_PNG);
}

#[test]
fn default_budget_file_reader_rejects_segbomb_via_decode_for_size() {
  let default_cfg = FileTransformConfig::default();
  let dict_size = crate::common::clamp_dict_size(default_cfg.precomp2_lzma.dict_size);
  let default_registry = TransformDecoderRegistry::new(crate::default_decoders(&default_cfg)).unwrap();

  // Valid PCF2 header claiming original_size = 64, single Dflt segment claiming
  // data_len = 4 MiB. Under FileTransformConfig::default() (4 GiB global
  // budget), decode_for_size tightens the per-recipe decode budget to max(64 *
  // 16, 2 MiB) = 2 MiB, so this fails at the segment header.
  let mut forged_seg = Vec::new();
  precomp2::Pcf2Header::new(64).encode(&mut forged_seg).unwrap();
  forged_seg.push(precomp2::SegmentKind::Dflt as u8);
  forged_seg.push(0);
  precomp2::varint::write_varint(64, &mut forged_seg).unwrap();
  precomp2::varint::write_varint(0, &mut forged_seg).unwrap();
  precomp2::varint::write_varint(4 << 20, &mut forged_seg).unwrap();
  forged_seg.resize(forged_seg.len() + (4 << 20), 0);

  let zstd_seg = crate::common::zstd_compress(&forged_seg, 3).unwrap();
  let lzma_seg = crate::common::lzma_compress(&forged_seg, 1, dict_size).unwrap();

  for (label, transform_id, stored) in [
    ("zstd-seg-4m-default-budget", TRANSFORM_ID_PRECOMP2_ZSTD, zstd_seg),
    ("lzma-seg-4m-default-budget", TRANSFORM_ID_PRECOMP2_LZMA, lzma_seg),
  ] {
    let chunk_hash = Hash32::sha3_256(&stored);
    let recipe = build_recipe(
      64,
      &[(chunk_hash, stored.len() as u32)],
      Hash32::sha3_256([0u8; 64]),
      transform_id,
      2,
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
    let err = FileReader::new(&source, &default_registry, FileReadLimits::default())
      .read_file(recipe_hash)
      .unwrap_err();
    assert!(
      err.to_string().contains("budget") || err.to_string().contains("exceeds"),
      "{label}: unexpected err: {err:?}"
    );
  }
}
