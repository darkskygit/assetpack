# assetpack

`assetpack` provides Rust crates for content-addressed asset packing. It focuses on splitting files into stable chunks, deduplicating payloads by SHA3-256, writing SQLite-backed/Sealed packs with content-addressed objects, and recording recipes that can rebuild the original bytes.

## Crates

- `assetpack-core`: core hashing, chunking, codec, recipe, `FileReader`, pipeline, and SQLite/Sealed pack primitives.
- `assetpack-transform-precomp2`: optional file transforms built on `precomp2`, with zstd and lzma wrapping variants.
- Core features `serde`, `sqlite-pack`, `rusqlite-store`, and `file-transform` are enabled by default. `sqlx-store`, `sealed`, and `sealed-encryption` are opt-in.

## Features

- SHA3-256 object identity and recipe integrity checks.
- FastCDC content-defined chunking with stable default bounds.
- Per-chunk raw, zstd, and Brotli storage with automatic fallback when compression is not worthwhile.
- SQLite object storage for chunks and recipes, plus optional namespaced stores for embedding.
- File transform selection with decode verification before accepting transformed output.
- Merkle index rebuilds, integrity checks, membership proofs, and batched proof lookup.
- Optional `precomp2`, `precomp2-zstd`, and `precomp2-lzma` transforms.

## Usage

### Choosing a store

The synchronous backends implement `ObjectSource`; SQLx implements `AsyncObjectSource`:

- SealedPack: an immutable single-file snapshot for distribution or archival. It is built once from a complete object set, can be encrypted, and is never updated in place — changing content means building a new pack.
- `SqlitePack`: owns a rusqlite connection and standalone database-file lifecycle.
- `RusqliteStore<'_>`: borrows an existing rusqlite connection or transaction and supports a table prefix.
- `SqlxStore`: owns an existing SQLx `SqlitePool`, supports a table prefix, and accepts caller-owned SQLx transactions.

`sqlite-pack` and `rusqlite-store` do not enable SQLx, Tokio, or futures. Async applications choose their own scheduling boundary when using a synchronous backend.

### Storing files

`Pipeline` splits an input into chunks, compresses each one, and computes everything needed to rebuild the file. Persist the plan and keep the returned recipe hash:

```rust
use assetpack_core::{Codec, FileHint, Hash32, ObjectKind, ObjectRecord, Pipeline, PipelineConfig, SqlitePack, build_recipe};

fn store_file(pack: &mut SqlitePack, data: Vec<u8>) -> assetpack_core::Result<Hash32> {
  let original_hash = Hash32::sha3_256(&data);
  let hint = FileHint { size: data.len() as u64, extension: None, head: None };
  let plan = Pipeline::new(PipelineConfig::default()).run(data, &hint, original_hash, None)?;

  let recipe_chunks: Vec<_> = plan.chunks.iter().map(|chunk| (chunk.hash, chunk.raw_len)).collect();
  let recipe = build_recipe(plan.original_size, &recipe_chunks, original_hash, plan.transform_id, plan.transform_version);
  let recipe_hash = Hash32::sha3_256(&recipe);

  let objects: Vec<_> = plan
    .chunks
    .into_iter()
    .map(|chunk| ObjectRecord {
      hash: chunk.hash,
      kind: ObjectKind::Chunk,
      decoded_len: u64::from(chunk.raw_len),
      codec: chunk.codec,
      stored_bytes: chunk.payload.expect("payload is kept unless discard_payload is set"),
    })
    .collect();
  pack.transaction(|store| {
    store.put_objects_batch(&objects)?;
    store.put_recipe(recipe_hash, &recipe, Codec::Raw)
  })?;
  Ok(recipe_hash)
}
```

To also try `precomp2`-family transforms during selection, build a `TransformSelector` from `assetpack_transform_precomp2::default_specs()` and pass it as the last argument of `run`.

### Building a SealedPack

```rust
use assetpack_core::{DEFAULT_FORMAT_TAG, SealedPackBuilder, SqlitePack};

fn export(pack: &SqlitePack, root_recipe: assetpack_core::Hash32) -> assetpack_core::Result<Vec<u8>> {
  let mut objects = Vec::new();
  loop {
    let page = pack.object_records(objects.len() as u64, 256)?;
    if page.is_empty() { break; }
    objects.extend(page);
  }
  SealedPackBuilder::build_plain(DEFAULT_FORMAT_TAG, root_recipe, objects)
}
```

### Restoring a file

Construct a `TransformDecoderRegistry` with every transform version you have ever written. Use `FileReader` with Sealed/rusqlite sources and `AsyncFileReader` with `SqlxStore`:

```rust
use assetpack_core::{FileReadLimits, FileReader, Hash32, ObjectSource, TransformDecoderRegistry};

fn restore<S: ObjectSource + ?Sized>(source: &S, root: Hash32) -> assetpack_core::Result<Vec<u8>> {
  let decoders = TransformDecoderRegistry::default();
  FileReader::new(source, &decoders, FileReadLimits::default()).read_file(root)
}
```

Decoders are selected by the exact `(transform_id, transform_version)` recorded in the recipe; unknown pairs fail with `UnsupportedTransform` instead of falling back silently. For precomp2 support, register `assetpack_transform_precomp2::default_decoders(&config)`. Restoration returns the complete file; seek or range decoding of transformed files is not supported.

## What a successful call proves

- `ObjectSource::read_object`: the returned bytes match the requested object hash.
- `AsyncObjectSource::read_object`: the same contract, with explicit asynchronous source scheduling.
- `SealedPackReader::verify_all_objects()`: every object in the container passes that same check.
- `FileReader::read_file` / `restore_file`: the restored bytes equal the original file, in size and SHA3-256.

## Compatibility

These crates are pre-1.0 and the public API may still change. The SealedPack v1 on-disk format is pinned by a byte-exact golden fixture; any format change requires a new revision. Parsers and the shared read path are fuzzed continuously in CI: curated seeds live in `fuzz/corpus`, dynamic corpus stays in CI caches, and every crash becomes a deterministic regression test.

## License

Licensed under the AGPL-3.0-or-later license.
