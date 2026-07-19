use std::{
  collections::BTreeSet,
  io::{self, BufReader, Cursor, Write},
};

use sha3::{Digest, Sha3_256};

use crate::{
  AsyncObjectSource, Error, Hash32, ObjectKind, RecipeData, Result, TransformDecoderRegistry, parse_recipe, recipe::preflight_recipe_limits,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileReadLimits {
  pub max_chunk_count: u64,
  pub max_stored_stream_bytes: u64,
  pub max_original_file_bytes: u64,
}

impl Default for FileReadLimits {
  fn default() -> Self {
    Self {
      max_chunk_count: 1_000_000,
      max_stored_stream_bytes: 256 * 1024 * 1024,
      max_original_file_bytes: 256 * 1024 * 1024,
    }
  }
}

pub struct FileReader<'a, S: ?Sized> {
  source: &'a S,
  decoders: &'a TransformDecoderRegistry,
  limits: FileReadLimits,
}

impl<'a, S: crate::ObjectSource + ?Sized> FileReader<'a, S> {
  pub fn new(source: &'a S, decoders: &'a TransformDecoderRegistry, limits: FileReadLimits) -> Self {
    Self { source, decoders, limits }
  }

  pub fn resolve_closure(&self, recipe_hash: Hash32) -> Result<BTreeSet<Hash32>> {
    let recipe = self.load_recipe(recipe_hash)?;
    let mut hashes = BTreeSet::from([recipe_hash]);
    for (hash, expected_len) in &recipe.chunks {
      let object = self.source.read_object(hash)?.ok_or(Error::ObjectNotFound)?;
      validate_chunk(&object.hash, object.kind, object.bytes.len() as u64, u64::from(*expected_len))?;
      hashes.insert(*hash);
    }
    Ok(hashes)
  }

  pub fn read_stored_stream(&self, recipe_hash: Hash32) -> Result<Vec<u8>> {
    let recipe = self.load_recipe(recipe_hash)?;
    self.read_stored_for_recipe(&recipe)
  }

  pub fn restore_file(&self, recipe_hash: Hash32, output: &mut dyn Write) -> Result<()> {
    let recipe = self.load_recipe(recipe_hash)?;
    let stored = self.read_stored_for_recipe(&recipe)?;
    decode_recipe(self.decoders, &recipe, stored, output)
  }

  pub fn read_file(&self, recipe_hash: Hash32) -> Result<Vec<u8>> {
    let recipe = self.load_recipe(recipe_hash)?;
    let stored = self.read_stored_for_recipe(&recipe)?;
    read_decoded_file(self.decoders, &recipe, stored)
  }

  fn load_recipe(&self, recipe_hash: Hash32) -> Result<RecipeData> {
    let object = self.source.read_object(&recipe_hash)?.ok_or(Error::ObjectNotFound)?;
    load_recipe_from_object(object, recipe_hash, self.limits)
  }

  fn read_stored_for_recipe(&self, recipe: &RecipeData) -> Result<Vec<u8>> {
    let mut stored = Vec::new();
    for (hash, expected_len) in &recipe.chunks {
      let object = self.source.read_object(hash)?.ok_or(Error::ObjectNotFound)?;
      validate_chunk(&object.hash, object.kind, object.bytes.len() as u64, u64::from(*expected_len))?;
      append_chunk(&mut stored, &object.bytes, recipe.stored_stream_size)?;
    }
    Ok(stored)
  }
}

pub struct AsyncFileReader<'a, S: ?Sized> {
  source: &'a S,
  decoders: &'a TransformDecoderRegistry,
  limits: FileReadLimits,
}

impl<'a, S: AsyncObjectSource + ?Sized> AsyncFileReader<'a, S> {
  pub fn new(source: &'a S, decoders: &'a TransformDecoderRegistry, limits: FileReadLimits) -> Self {
    Self { source, decoders, limits }
  }

  pub async fn resolve_closure(&self, recipe_hash: Hash32) -> Result<BTreeSet<Hash32>> {
    let recipe = self.load_recipe(recipe_hash).await?;
    let mut hashes = BTreeSet::from([recipe_hash]);
    for (hash, expected_len) in &recipe.chunks {
      let object = self.source.read_object(hash).await?.ok_or(Error::ObjectNotFound)?;
      validate_chunk(&object.hash, object.kind, object.bytes.len() as u64, u64::from(*expected_len))?;
      hashes.insert(*hash);
    }
    Ok(hashes)
  }

  pub async fn read_stored_stream(&self, recipe_hash: Hash32) -> Result<Vec<u8>> {
    let recipe = self.load_recipe(recipe_hash).await?;
    self.read_stored_for_recipe(&recipe).await
  }

  pub async fn restore_file(&self, recipe_hash: Hash32, output: &mut dyn Write) -> Result<()> {
    let recipe = self.load_recipe(recipe_hash).await?;
    let stored = self.read_stored_for_recipe(&recipe).await?;
    decode_recipe(self.decoders, &recipe, stored, output)
  }

  pub async fn read_file(&self, recipe_hash: Hash32) -> Result<Vec<u8>> {
    let recipe = self.load_recipe(recipe_hash).await?;
    let stored = self.read_stored_for_recipe(&recipe).await?;
    read_decoded_file(self.decoders, &recipe, stored)
  }

  async fn load_recipe(&self, recipe_hash: Hash32) -> Result<RecipeData> {
    let object = self.source.read_object(&recipe_hash).await?.ok_or(Error::ObjectNotFound)?;
    load_recipe_from_object(object, recipe_hash, self.limits)
  }

  async fn read_stored_for_recipe(&self, recipe: &RecipeData) -> Result<Vec<u8>> {
    let mut stored = Vec::new();
    for (hash, expected_len) in &recipe.chunks {
      let object = self.source.read_object(hash).await?.ok_or(Error::ObjectNotFound)?;
      validate_chunk(&object.hash, object.kind, object.bytes.len() as u64, u64::from(*expected_len))?;
      append_chunk(&mut stored, &object.bytes, recipe.stored_stream_size)?;
    }
    Ok(stored)
  }
}

fn load_recipe_from_object(object: crate::VerifiedObject, recipe_hash: Hash32, limits: FileReadLimits) -> Result<RecipeData> {
  if object.kind != ObjectKind::Recipe {
    return Err(Error::ObjectKindMismatch {
      hash: recipe_hash,
      expected: ObjectKind::Recipe,
      actual: object.kind,
    });
  }
  let (original_file_size, chunk_count) =
    preflight_recipe_limits(&object.bytes).map_err(|error| Error::InvalidRecipe(error.to_string()))?;
  check_limit("chunk count", limits.max_chunk_count, u64::from(chunk_count))?;
  check_limit("original file bytes", limits.max_original_file_bytes, original_file_size)?;
  let recipe = parse_recipe(&object.bytes).map_err(|error| Error::InvalidRecipe(error.to_string()))?;
  check_limit("stored stream bytes", limits.max_stored_stream_bytes, recipe.stored_stream_size)?;
  Ok(recipe)
}

fn append_chunk(stored: &mut Vec<u8>, bytes: &[u8], expected_total: u64) -> Result<()> {
  let requested = stored
    .len()
    .checked_add(bytes.len())
    .and_then(|length| u64::try_from(length).ok())
    .ok_or(Error::FileReadAllocationFailed {
      buffer: "stored stream",
      requested: expected_total,
    })?;
  stored.try_reserve(bytes.len()).map_err(|_| Error::FileReadAllocationFailed {
    buffer: "stored stream",
    requested,
  })?;
  stored.extend_from_slice(bytes);
  Ok(())
}

fn validate_chunk(hash: &Hash32, kind: ObjectKind, actual_len: u64, expected_len: u64) -> Result<()> {
  if kind != ObjectKind::Chunk {
    return Err(Error::ObjectKindMismatch {
      hash: *hash,
      expected: ObjectKind::Chunk,
      actual: kind,
    });
  }
  if actual_len != expected_len {
    return Err(Error::RecipeChunkLengthMismatch {
      hash: *hash,
      expected: expected_len,
      actual: actual_len,
    });
  }
  Ok(())
}

fn check_limit(limit: &'static str, maximum: u64, actual: u64) -> Result<()> {
  if actual > maximum {
    return Err(Error::FileReadLimitExceeded { limit, maximum, actual });
  }
  Ok(())
}

fn read_decoded_file(decoders: &TransformDecoderRegistry, recipe: &RecipeData, stored: Vec<u8>) -> Result<Vec<u8>> {
  let mut output = FallibleVecWriter::default();
  let result = decode_recipe(decoders, recipe, stored, &mut output);
  if let Some(requested) = output.allocation_failure {
    return Err(Error::FileReadAllocationFailed {
      buffer: "original file",
      requested,
    });
  }
  result?;
  Ok(output.bytes)
}

fn decode_recipe(decoders: &TransformDecoderRegistry, recipe: &RecipeData, stored: Vec<u8>, output: &mut dyn Write) -> Result<()> {
  let decoder = decoders.get(recipe.transform_id, recipe.transform_version)?;
  let mut input = BufReader::new(Cursor::new(stored));
  let mut verified = VerifyingWriter::new(output, recipe.original_file_size);
  let result = decoder.decode(&mut input, &mut verified);
  if verified.exceeded {
    return Err(original_mismatch(recipe, &verified));
  }
  result?;
  let actual_hash = verified.hash();
  if verified.written != recipe.original_file_size || actual_hash != recipe.original_file_hash {
    return Err(Error::OriginalFileMismatch {
      expected_size: recipe.original_file_size,
      actual_size: verified.written,
      expected_hash: recipe.original_file_hash,
      actual_hash,
    });
  }
  Ok(())
}

fn original_mismatch(recipe: &RecipeData, writer: &VerifyingWriter<'_>) -> Error {
  Error::OriginalFileMismatch {
    expected_size: recipe.original_file_size,
    actual_size: writer.written,
    expected_hash: recipe.original_file_hash,
    actual_hash: writer.hash(),
  }
}

#[derive(Default)]
struct FallibleVecWriter {
  bytes: Vec<u8>,
  allocation_failure: Option<u64>,
}

impl Write for FallibleVecWriter {
  fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
    let requested = self
      .bytes
      .len()
      .checked_add(bytes.len())
      .and_then(|length| u64::try_from(length).ok())
      .ok_or_else(|| io::Error::new(io::ErrorKind::OutOfMemory, "original file length exceeds address space"))?;
    if self.bytes.try_reserve(bytes.len()).is_err() {
      self.allocation_failure = Some(requested);
      return Err(io::Error::new(
        io::ErrorKind::OutOfMemory,
        "unable to allocate original file buffer",
      ));
    }
    self.bytes.extend_from_slice(bytes);
    Ok(bytes.len())
  }

  fn flush(&mut self) -> io::Result<()> {
    Ok(())
  }
}

struct VerifyingWriter<'a> {
  output: &'a mut dyn Write,
  hasher: Sha3_256,
  maximum: u64,
  written: u64,
  exceeded: bool,
}

impl<'a> VerifyingWriter<'a> {
  fn new(output: &'a mut dyn Write, maximum: u64) -> Self {
    Self {
      output,
      hasher: Sha3_256::new(),
      maximum,
      written: 0,
      exceeded: false,
    }
  }

  fn hash(&self) -> Hash32 {
    Hash32::new(self.hasher.clone().finalize().into())
  }
}

impl Write for VerifyingWriter<'_> {
  fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
    let next = self.written.checked_add(bytes.len() as u64).ok_or_else(|| {
      self.exceeded = true;
      io::Error::new(io::ErrorKind::FileTooLarge, "decoded file length overflow")
    })?;
    if next > self.maximum {
      self.exceeded = true;
      return Err(io::Error::new(io::ErrorKind::FileTooLarge, "decoded file exceeds declared size"));
    }
    let written = self.output.write(bytes)?;
    self.hasher.update(&bytes[..written]);
    self.written += written as u64;
    Ok(written)
  }

  fn flush(&mut self) -> io::Result<()> {
    self.output.flush()
  }
}

#[cfg(test)]
mod tests {
  use std::{
    collections::BTreeMap,
    sync::{
      Arc,
      atomic::{AtomicUsize, Ordering},
    },
  };

  use super::*;
  use crate::{TRANSFORM_ID_NONE, TRANSFORM_VERSION_NONE, VerifiedObject, build_recipe};

  #[derive(Default)]
  struct MemorySource(BTreeMap<Hash32, VerifiedObject>);

  impl AsyncObjectSource for MemorySource {
    async fn read_object(&self, hash: &Hash32) -> Result<Option<VerifiedObject>> {
      Ok(self.0.get(hash).cloned())
    }
  }

  fn source_for(
    chunks: &[&[u8]],
    order: &[usize],
    original_size: u64,
    original_hash: Hash32,
    transform: (u16, u16),
  ) -> (MemorySource, Hash32) {
    let mut source = MemorySource::default();
    let hashes = chunks
      .iter()
      .map(|bytes| {
        let hash = Hash32::sha3_256(bytes);
        source.0.insert(
          hash,
          VerifiedObject {
            hash,
            kind: ObjectKind::Chunk,
            bytes: bytes.to_vec(),
          },
        );
        hash
      })
      .collect::<Vec<_>>();
    let recipe_chunks = order
      .iter()
      .map(|index| (hashes[*index], chunks[*index].len() as u32))
      .collect::<Vec<_>>();
    let recipe = build_recipe(original_size, &recipe_chunks, original_hash, transform.0, transform.1);
    let recipe_hash = Hash32::sha3_256(&recipe);
    source.0.insert(
      recipe_hash,
      VerifiedObject {
        hash: recipe_hash,
        kind: ObjectKind::Recipe,
        bytes: recipe,
      },
    );
    (source, recipe_hash)
  }

  #[tokio::test]
  async fn none_reader_handles_empty_single_multi_and_duplicate_chunks() {
    for (chunks, order) in [
      (vec![], vec![]),
      (vec![b"alpha".as_slice()], vec![0]),
      (vec![b"alpha".as_slice(), b"beta".as_slice()], vec![0, 1]),
      (vec![b"alpha".as_slice(), b"beta".as_slice()], vec![0, 1, 0]),
    ] {
      let expected = order.iter().flat_map(|index| chunks[*index]).copied().collect::<Vec<_>>();
      let (source, recipe_hash) = source_for(
        &chunks,
        &order,
        expected.len() as u64,
        Hash32::sha3_256(&expected),
        (TRANSFORM_ID_NONE, TRANSFORM_VERSION_NONE),
      );
      let registry = TransformDecoderRegistry::default();
      let reader = AsyncFileReader::new(&source, &registry, FileReadLimits::default());
      assert_eq!(reader.read_stored_stream(recipe_hash).await.unwrap(), expected);
      assert_eq!(reader.read_file(recipe_hash).await.unwrap(), expected);
      let mut restored = Vec::new();
      reader.restore_file(recipe_hash, &mut restored).await.unwrap();
      assert_eq!(restored, expected);
      assert_eq!(reader.resolve_closure(recipe_hash).await.unwrap().len(), chunks.len() + 1);
    }
  }

  #[tokio::test]
  async fn errors_are_classified_by_file_reader_boundary() {
    #[derive(Clone, Copy)]
    enum ExpectedError {
      NotFound,
      KindMismatch,
      InvalidRecipe,
      ChunkLengthMismatch,
    }

    let expected = b"alpha";
    type ErrorCase = (&'static str, fn(&mut MemorySource, Hash32, Hash32), ExpectedError);
    let cases: [ErrorCase; 6] = [
      (
        "missing recipe",
        |source, recipe_hash, _| {
          source.0.remove(&recipe_hash);
        },
        ExpectedError::NotFound,
      ),
      (
        "missing chunk",
        |source, _, chunk_hash| {
          source.0.remove(&chunk_hash);
        },
        ExpectedError::NotFound,
      ),
      (
        "recipe kind is chunk",
        |source, recipe_hash, _| {
          source.0.get_mut(&recipe_hash).unwrap().kind = ObjectKind::Chunk;
        },
        ExpectedError::KindMismatch,
      ),
      (
        "recipe bytes are invalid",
        |source, recipe_hash, _| {
          source.0.get_mut(&recipe_hash).unwrap().bytes = vec![0xff];
        },
        ExpectedError::InvalidRecipe,
      ),
      (
        "chunk kind is recipe",
        |source, _, chunk_hash| {
          source.0.get_mut(&chunk_hash).unwrap().kind = ObjectKind::Recipe;
        },
        ExpectedError::KindMismatch,
      ),
      (
        "chunk length mismatch",
        |source, _, chunk_hash| {
          source.0.get_mut(&chunk_hash).unwrap().bytes.push(0);
        },
        ExpectedError::ChunkLengthMismatch,
      ),
    ];
    let registry = TransformDecoderRegistry::default();
    for (label, mutate, expected_error) in cases {
      let (mut source, recipe_hash) = source_for(
        &[expected.as_slice()],
        &[0],
        expected.len() as u64,
        Hash32::sha3_256(expected),
        (TRANSFORM_ID_NONE, TRANSFORM_VERSION_NONE),
      );
      let chunk_hash = parse_recipe(&source.0[&recipe_hash].bytes).unwrap().chunks[0].0;
      mutate(&mut source, recipe_hash, chunk_hash);
      let reader = AsyncFileReader::new(&source, &registry, FileReadLimits::default());
      for result in [
        reader.read_file(recipe_hash).await.map(|_| ()),
        reader.resolve_closure(recipe_hash).await.map(|_| ()),
      ] {
        let error = result.unwrap_err();
        let matched = matches!(
          (&error, expected_error),
          (Error::ObjectNotFound, ExpectedError::NotFound)
            | (Error::ObjectKindMismatch { .. }, ExpectedError::KindMismatch)
            | (Error::InvalidRecipe(_), ExpectedError::InvalidRecipe)
            | (Error::RecipeChunkLengthMismatch { .. }, ExpectedError::ChunkLengthMismatch)
        );
        assert!(matched, "{label} returned unexpected error: {error}");
      }
    }
  }

  #[tokio::test]
  async fn limits_and_transform_or_original_mismatch_are_structured() {
    struct CountingDecoder(Arc<AtomicUsize>);
    impl crate::TransformDecoder for CountingDecoder {
      fn id(&self) -> u16 {
        88
      }
      fn version(&self) -> u16 {
        1
      }
      fn decode(&self, input: &mut dyn io::BufRead, output: &mut dyn Write) -> Result<()> {
        self.0.fetch_add(1, Ordering::Relaxed);
        io::copy(input, output)?;
        Ok(())
      }
    }

    let bytes = b"alpha";
    let original_hash = Hash32::sha3_256(bytes);
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = TransformDecoderRegistry::new([Arc::new(CountingDecoder(calls.clone())) as Arc<dyn crate::TransformDecoder>]).unwrap();
    let exact_limits = FileReadLimits {
      max_chunk_count: 1,
      max_stored_stream_bytes: bytes.len() as u64,
      max_original_file_bytes: bytes.len() as u64,
    };
    let (source, recipe_hash) = source_for(&[bytes], &[0], bytes.len() as u64, original_hash, (88, 1));
    let reader = AsyncFileReader::new(&source, &registry, exact_limits);
    assert_eq!(reader.read_file(recipe_hash).await.unwrap(), bytes);
    assert_eq!(calls.load(Ordering::Relaxed), 1);

    let declared_size = 8 * 1024 * 1024 * 1024;
    let (source, recipe_hash) = source_for(&[], &[], declared_size, Hash32::sha3_256([]), (0, 0));
    let reader = AsyncFileReader::new(&source, &registry, FileReadLimits::default());
    assert!(matches!(
      reader.read_file(recipe_hash).await,
      Err(Error::FileReadLimitExceeded {
        limit: "original file bytes",
        actual,
        ..
      }) if actual == declared_size
    ));
    let reader = AsyncFileReader::new(
      &source,
      &registry,
      FileReadLimits {
        max_original_file_bytes: declared_size,
        ..FileReadLimits::default()
      },
    );
    assert!(matches!(
      reader.read_file(recipe_hash).await,
      Err(Error::OriginalFileMismatch {
        expected_size,
        actual_size: 0,
        ..
      }) if expected_size == declared_size
    ));

    let cases = [
      (
        FileReadLimits {
          max_chunk_count: 0,
          ..FileReadLimits::default()
        },
        "chunk count",
      ),
      (
        FileReadLimits {
          max_stored_stream_bytes: 4,
          ..FileReadLimits::default()
        },
        "stored stream bytes",
      ),
      (
        FileReadLimits {
          max_original_file_bytes: 4,
          ..FileReadLimits::default()
        },
        "original file bytes",
      ),
    ];
    for (limits, expected_limit) in cases {
      let before = calls.load(Ordering::Relaxed);
      let (source, recipe_hash) = source_for(&[bytes], &[0], bytes.len() as u64, original_hash, (88, 1));
      let reader = AsyncFileReader::new(&source, &registry, limits);
      assert!(matches!(
        reader.read_file(recipe_hash).await,
        Err(Error::FileReadLimitExceeded { limit, .. }) if limit == expected_limit
      ));
      assert_eq!(calls.load(Ordering::Relaxed), before);
    }

    let (mut source, recipe_hash) = source_for(&[bytes], &[0], bytes.len() as u64, original_hash, (0, 0));
    source.0.get_mut(&recipe_hash).unwrap().bytes[45..49].copy_from_slice(&u32::MAX.to_le_bytes());
    let reader = AsyncFileReader::new(
      &source,
      &registry,
      FileReadLimits {
        max_chunk_count: 0,
        ..FileReadLimits::default()
      },
    );
    assert!(matches!(
      reader.read_file(recipe_hash).await,
      Err(Error::FileReadLimitExceeded { limit: "chunk count", actual, .. }) if actual == u64::from(u32::MAX)
    ));
    assert_eq!(calls.load(Ordering::Relaxed), 1);

    let (source, recipe_hash) = source_for(&[bytes], &[0], bytes.len() as u64, original_hash, (TRANSFORM_ID_NONE, 4));
    let reader = AsyncFileReader::new(&source, &registry, FileReadLimits::default());
    assert!(matches!(
      reader.read_file(recipe_hash).await,
      Err(Error::UnsupportedTransform {
        id: TRANSFORM_ID_NONE,
        version: 4
      })
    ));

    let (source, recipe_hash) = source_for(&[bytes], &[0], bytes.len() as u64, Hash32::sha3_256(b"other"), (0, 0));
    let none_registry = TransformDecoderRegistry::default();
    let reader = AsyncFileReader::new(&source, &none_registry, FileReadLimits::default());
    assert_eq!(reader.read_stored_stream(recipe_hash).await.unwrap(), bytes);
    assert!(matches!(
      reader.read_file(recipe_hash).await,
      Err(Error::OriginalFileMismatch { .. })
    ));
    let mut restored = Vec::new();
    assert!(matches!(
      reader.restore_file(recipe_hash, &mut restored).await,
      Err(Error::OriginalFileMismatch { .. })
    ));

    let (source, recipe_hash) = source_for(&[bytes], &[0], bytes.len() as u64 + 1, original_hash, (0, 0));
    let reader = AsyncFileReader::new(&source, &none_registry, FileReadLimits::default());
    assert!(matches!(
      reader.read_file(recipe_hash).await,
      Err(Error::OriginalFileMismatch { expected_size, actual_size, .. }) if expected_size == bytes.len() as u64 + 1 && actual_size == bytes.len() as u64
    ));
  }

  #[test]
  fn registry_accepts_decoder_trait_objects_without_writer_features() {
    struct Decoder;
    impl crate::TransformDecoder for Decoder {
      fn id(&self) -> u16 {
        91
      }
      fn version(&self) -> u16 {
        2
      }
      fn decode(&self, input: &mut dyn io::BufRead, output: &mut dyn Write) -> Result<()> {
        io::copy(input, output)?;
        Ok(())
      }
    }
    let registry = TransformDecoderRegistry::new([Arc::new(Decoder) as Arc<dyn crate::TransformDecoder>]).unwrap();
    assert_eq!(registry.get(91, 2).unwrap().version(), 2);
  }
}
