# assetpack

`assetpack` provides Rust crates for content-addressed asset packing. It focuses on splitting files into stable chunks, deduplicating payloads by SHA3-256, writing SQLite-backed packs with content-addressed objects, and recording recipes that can rebuild the original bytes.

## Crates

- `assetpack-core`: core hashing, chunking, codec, recipe, file-transform, pipeline, and SQLite pack primitives.
- `assetpack-transform-precomp2`: optional file transforms built on `precomp2`, with zstd and lzma wrapping variants.

## Usage

```rust
use assetpack_core::{ChunkCompressionPolicy, FastCdcSplitter, FileHint, Hash32, Pipeline, PipelineConfig};

fn main() -> assetpack_core::Result<()> {
  let data = b"asset payload".to_vec();
  let hash = Hash32::sha3_256(&data);
  let hint = FileHint {
    size: data.len() as u64,
    extension: Some("bin".into()),
    head: Some(data[..data.len().min(16)].to_vec()),
  };
  let pipeline = Pipeline::new(PipelineConfig {
    splitter: FastCdcSplitter::v1_defaults(),
    chunk_compression: ChunkCompressionPolicy::Auto,
    discard_payload: false,
  });

  let plan = pipeline.run(data, &hint, hash, None)?;
  assert_eq!(plan.original_hash, hash);
  Ok(())
}

```

To enable `precomp2` transforms during selection, pass the transform specs from `assetpack-transform-precomp2`.

```rust
use assetpack_core::{
  ChunkCompressionPolicy, FastCdcSplitter, FileHint, FileTransformConfig, Hash32, Pipeline, PipelineConfig, TransformSelector,
};

fn main() -> assetpack_core::Result<()> {
  let data = b"asset payload".repeat(8);
  let hash = Hash32::sha3_256(&data);
  let hint = FileHint {
    size: data.len() as u64,
    extension: Some("bin".into()),
    head: Some(data[..data.len().min(16)].to_vec()),
  };
  let selector = TransformSelector::new(FileTransformConfig::default(), None, assetpack_transform_precomp2::default_specs());
  let pipeline = Pipeline::new(PipelineConfig {
    splitter: FastCdcSplitter::v1_defaults(),
    chunk_compression: ChunkCompressionPolicy::Auto,
    discard_payload: false,
  });

  let plan = pipeline.run(data, &hint, hash, Some(&selector))?;
  assert_eq!(plan.original_hash, hash);
  Ok(())
}

```

## Status

These crates are early-stage and the public API and on-disk formats may change before a 1.0 release.

## License

Licensed under the AGPL-3.0-or-later license.
