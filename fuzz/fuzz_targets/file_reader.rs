#![no_main]

mod support;

use std::collections::BTreeMap;

use assetpack_core::{
  build_recipe, compress, Codec, FileReadLimits, FileReader, Hash32, ObjectKind, ObjectRecord, ObjectSource, PackOpenPolicy,
  ParsedSealedPack, SealedPackBuilder, SealedPackTag, TransformDecoderRegistry, VerifiedObject, TRANSFORM_ID_NONE,
  TRANSFORM_VERSION_NONE,
};
use libfuzzer_sys::fuzz_target;

#[derive(Default)]
struct MemorySource(BTreeMap<Hash32, VerifiedObject>);

impl ObjectSource for MemorySource {
  async fn read_object(&self, hash: &Hash32) -> assetpack_core::Result<Option<VerifiedObject>> {
    Ok(self.0.get(hash).cloned())
  }
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
  Bytes(Vec<u8>),
  Unsupported,
  OriginalMismatch,
  Other,
}

fn outcome(result: assetpack_core::Result<Vec<u8>>) -> Outcome {
  match result {
    Ok(bytes) => Outcome::Bytes(bytes),
    Err(assetpack_core::Error::UnsupportedTransform { .. }) => Outcome::Unsupported,
    Err(assetpack_core::Error::OriginalFileMismatch { .. }) => Outcome::OriginalMismatch,
    Err(_) => Outcome::Other,
  }
}

fuzz_target!(|input: &[u8]| {
  let input = &input[..input.len().min(4096)];
  let control = input.first().copied().unwrap_or_default();
  let data = &input[input.len().min(1)..];
  let codec = match control % 3 {
    0 => Codec::Raw,
    1 => Codec::Zstd,
    _ => Codec::Brotli,
  };
  let chunk_size = data.len().div_ceil(8).max(1);
  let mut memory = MemorySource::default();
  let mut records = Vec::new();
  let mut chunks = Vec::new();
  let mut original = Vec::new();
  for bytes in data.chunks(chunk_size) {
    let hash = Hash32::sha3_256(bytes);
    let inserted = memory.0.insert(
      hash,
      VerifiedObject {
        hash,
        kind: ObjectKind::Chunk,
        bytes: bytes.to_vec(),
      },
    );
    if inserted.is_none() {
      records.push(ObjectRecord {
        hash,
        kind: ObjectKind::Chunk,
        decoded_len: bytes.len() as u64,
        codec,
        stored_bytes: compress(codec, bytes).expect("bounded compression succeeds"),
      });
    }
    chunks.push((hash, bytes.len() as u32));
    original.extend_from_slice(bytes);
  }
  if control & 4 != 0
    && let Some(first) = chunks.first().copied()
  {
    chunks.push(first);
    original.extend_from_slice(memory.0.get(&first.0).expect("the chunk exists").bytes.as_slice());
  }
  let transform = if control & 1 == 0 {
    (TRANSFORM_ID_NONE, TRANSFORM_VERSION_NONE)
  } else {
    (99, 7)
  };
  let original_hash = if control & 2 == 0 {
    Hash32::sha3_256(&original)
  } else {
    Hash32::sha3_256(b"wrong-original")
  };
  let recipe = build_recipe(original.len() as u64, &chunks, original_hash, transform.0, transform.1);
  let recipe_hash = Hash32::sha3_256(&recipe);
  memory.0.insert(
    recipe_hash,
    VerifiedObject {
      hash: recipe_hash,
      kind: ObjectKind::Recipe,
      bytes: recipe.clone(),
    },
  );
  records.push(ObjectRecord {
    hash: recipe_hash,
    kind: ObjectKind::Recipe,
    decoded_len: recipe.len() as u64,
    codec: Codec::Raw,
    stored_bytes: recipe,
  });
  let sealed = SealedPackBuilder::build_plain(SealedPackTag(*b"fuzz.reader.v1!!"), recipe_hash, records)
    .expect("the bounded object graph is valid");
  let parsed = ParsedSealedPack::open(&sealed, SealedPackTag(*b"fuzz.reader.v1!!"), PackOpenPolicy::PlainAllowed).unwrap();
  let sealed = parsed.open_plain().unwrap();
  let registry = TransformDecoderRegistry::default();
  let limits = FileReadLimits {
    max_chunk_count: 16,
    max_stored_stream_bytes: 8192,
    max_original_file_bytes: 8192,
  };
  let memory_outcome = outcome(support::block_on(FileReader::new(&memory, &registry, limits).read_file(recipe_hash)));
  let sealed_outcome = outcome(support::block_on(FileReader::new(&sealed, &registry, limits).read_file(recipe_hash)));
  assert_eq!(memory_outcome, sealed_outcome);
  if transform.0 == TRANSFORM_ID_NONE && control & 2 == 0 {
    assert_eq!(memory_outcome, Outcome::Bytes(original));
  }
});
