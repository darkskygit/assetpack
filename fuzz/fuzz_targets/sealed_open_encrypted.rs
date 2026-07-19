#![no_main]

mod support;

use std::sync::OnceLock;

use assetpack_core::{
  build_recipe, Codec, FileReadLimits, FileReader, Hash32, ObjectKind, ObjectRecord, PackOpenPolicy, ParsedSealedPack, SealedPackBuilder,
  SealedPackTag, SoftwareFrameKey, TransformDecoderRegistry, HEADER_BYTES, TRANSFORM_ID_NONE, TRANSFORM_VERSION_NONE,
};
use libfuzzer_sys::fuzz_target;

const TAG: SealedPackTag = SealedPackTag(*b"fuzz.encrypted!!");

struct Fixture {
  primary: Vec<u8>,
  donor: Vec<u8>,
  frames: [(usize, usize); 2],
}

fn fixture() -> &'static Fixture {
  static FIXTURE: OnceLock<Fixture> = OnceLock::new();
  FIXTURE.get_or_init(|| {
    let bytes = b"encrypted-fuzz-fixture".repeat(32);
    let chunk_hash = Hash32::sha3_256(&bytes);
    let recipe = build_recipe(
      bytes.len() as u64,
      &[(chunk_hash, bytes.len() as u32)],
      chunk_hash,
      TRANSFORM_ID_NONE,
      TRANSFORM_VERSION_NONE,
    );
    let recipe_hash = Hash32::sha3_256(&recipe);
    let objects = [
      ObjectRecord {
        hash: chunk_hash,
        kind: ObjectKind::Chunk,
        decoded_len: bytes.len() as u64,
        codec: Codec::Raw,
        stored_bytes: bytes,
      },
      ObjectRecord {
        hash: recipe_hash,
        kind: ObjectKind::Recipe,
        decoded_len: recipe.len() as u64,
        codec: Codec::Raw,
        stored_bytes: recipe,
      },
    ];
    let build = || {
      SealedPackBuilder::build_encrypted(TAG, recipe_hash, objects.clone(), &SoftwareFrameKey::new([7; 32], [3; 16]))
        .expect("the fixed encrypted fuzz fixture is valid")
    };
    let primary = build();
    let donor = build();
    let index_length = u64::from_le_bytes(primary[20..28].try_into().unwrap()) as usize;
    let payload_start = HEADER_BYTES + index_length;
    let lengths = if chunk_hash < recipe_hash {
      [objects[0].stored_bytes.len() + 16, objects[1].stored_bytes.len() + 16]
    } else {
      [objects[1].stored_bytes.len() + 16, objects[0].stored_bytes.len() + 16]
    };
    let second_start = payload_start + lengths[0];
    Fixture {
      primary,
      donor,
      frames: [(payload_start, second_start), (second_start, second_start + lengths[1])],
    }
  })
}

fn mutate_encrypted_fixture(bytes: &mut Vec<u8>, input: &[u8], fixture: &Fixture) {
  match input.first().map(|byte| byte & 7) {
    Some(3) => {
      let frame = fixture.frames[usize::from(input.get(1).copied().unwrap_or_default() & 1)];
      bytes[frame.0..frame.1].copy_from_slice(&fixture.donor[frame.0..frame.1]);
    }
    Some(4) => {
      let [first, second] = fixture.frames;
      let first_bytes = bytes[first.0..first.1].to_vec();
      let second_bytes = bytes[second.0..second.1].to_vec();
      bytes.splice(first.0..second.1, second_bytes.into_iter().chain(first_bytes));
    }
    _ => support::mutate_fixture(bytes, input),
  }
}

fuzz_target!(|input: &[u8]| {
  let fixture = fixture();
  let mut bytes = fixture.primary.clone();
  mutate_encrypted_fixture(&mut bytes, input, fixture);
  let key = if input.first().is_some_and(|byte| *byte == 2 || byte & 8 != 0) {
    SoftwareFrameKey::new([8; 32], [3; 16])
  } else {
    SoftwareFrameKey::new([7; 32], [3; 16])
  };
  if let Ok(parsed) = ParsedSealedPack::open(&bytes, TAG, PackOpenPolicy::EncryptedRequired)
    && let Ok(reader) = parsed.unlock(&key)
  {
    let _ = reader.verify_all_objects();
    let registry = TransformDecoderRegistry::default();
    let file_reader = FileReader::new(&reader, &registry, FileReadLimits {
      max_chunk_count: 64,
      max_stored_stream_bytes: 1024 * 1024,
      max_original_file_bytes: 1024 * 1024,
    });
    let _ = support::block_on(file_reader.read_file(reader.root_recipe()));
  }
});
