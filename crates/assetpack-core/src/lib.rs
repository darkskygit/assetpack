pub mod cdc;
pub mod codec;
pub mod error;
pub mod file_reader;
#[cfg(feature = "file-transform")]
pub mod file_transform;
pub mod hash;
pub mod object;
#[cfg(feature = "file-transform")]
pub mod pipeline;
pub mod recipe;
#[cfg(feature = "sealed")]
pub mod sealed;
#[cfg(any(feature = "sqlite-pack", feature = "rusqlite-store", feature = "sqlx-store"))]
pub mod sqlite;
pub mod transform;

pub use cdc::{DEFAULT_AVG, DEFAULT_MAX, DEFAULT_MIN, FastCdcSplitter};
pub use codec::{Codec, EntropyEstimator, compress, compress_auto, decide_codec, decompress};
pub use error::{Error, Result};
pub use file_reader::{AsyncFileReader, FileReadLimits, FileReader};
#[cfg(feature = "file-transform")]
pub use file_transform::{
  FileHint, FileTransformConfig, FileTransformEvalConfig, FileTransformPrecomp2Config, FileTransformPrecomp2LzmaConfig,
  FileTransformPrecomp2ZstdConfig, StoredStreamSpool, TransformInfo, TransformSelection, TransformSelector, TransformSpec,
  enabled_transforms, selectable_transforms, transform_info,
};
pub use hash::{HASH_LEN, Hash32};
pub use object::{AsyncObjectSource, ObjectKind, ObjectRecord, ObjectSource, VerifiedObject};
#[cfg(feature = "file-transform")]
pub use pipeline::{ChunkCompressionPolicy, ChunkPlan, DefaultChunkCompressor, Pipeline, PipelineConfig, PipelinePlan};
pub use recipe::{RECIPE_VERSION_V1, RECIPE_VERSION_V2, RECIPE_VERSION_V3, RecipeData, build_recipe, parse_recipe, parse_recipe_checked};
#[cfg(feature = "sealed")]
pub use sealed::{
  DEFAULT_FORMAT_TAG, MAX_ENCRYPTED_FRAME_BYTES, PackOpenPolicy, ParsedSealedPack, SealedPackBuilder, SealedPackReader, SealedPackTag,
};
#[cfg(feature = "sealed-encryption")]
pub use sealed::{FrameSealer, FrameUnsealer, SealedRecordContext, SoftwareFrameKey};
#[cfg(feature = "rusqlite-store")]
pub use sqlite::RusqliteStore;
#[cfg(feature = "sqlx-store")]
pub use sqlite::SqlxStore;
#[cfg(any(feature = "sqlite-pack", feature = "rusqlite-store", feature = "sqlx-store"))]
pub use sqlite::{MerkleMode, MerkleProof, MerkleSummary, SqliteStoreOptions};
#[cfg(feature = "sqlite-pack")]
pub use sqlite::{SqlitePack, SqlitePackJournalMode};
pub use transform::{
  TRANSFORM_ID_NONE, TRANSFORM_ID_PRECOMP2, TRANSFORM_ID_PRECOMP2_LZMA, TRANSFORM_ID_PRECOMP2_ZSTD, TRANSFORM_VERSION_NONE,
  TRANSFORM_VERSION_PRECOMP2, TRANSFORM_VERSION_PRECOMP2_LZMA, TRANSFORM_VERSION_PRECOMP2_ZSTD, TransformDecoder, TransformDecoderRegistry,
};
