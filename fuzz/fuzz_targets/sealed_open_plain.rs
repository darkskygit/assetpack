#![no_main]

mod support;

use assetpack_core::{FileReadLimits, FileReader, PackOpenPolicy, ParsedSealedPack, SealedPackTag, TransformDecoderRegistry};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
  let mut fixture;
  let bytes = if input.first().is_some_and(|byte| byte & 1 != 0) {
    fixture = include_bytes!("../../crates/assetpack-core/src/sealed/fixtures/plain_v1.aspk").to_vec();
    support::mutate_fixture(&mut fixture, &input[1..]);
    fixture.as_slice()
  } else {
    input
  };
  let Some(tag) = bytes.get(..16).and_then(|tag| tag.try_into().ok()).map(SealedPackTag) else {
    return;
  };
  if let Ok(parsed) = ParsedSealedPack::open(bytes, tag, PackOpenPolicy::PlainAllowed)
    && let Ok(reader) = parsed.open_plain()
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
