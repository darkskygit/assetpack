mod common;
mod guards;
mod precomp2;
mod precomp2_lzma;
mod precomp2_zstd;

#[cfg(test)]
mod tests;

use std::sync::Arc;

use assetpack_core::{
  TRANSFORM_ID_PRECOMP2, TRANSFORM_ID_PRECOMP2_LZMA, TRANSFORM_ID_PRECOMP2_ZSTD, TransformDecoder,
  file_transform::{FileTransform, FileTransformConfig, TransformSpec},
};
pub use precomp2::Precomp2Transform;
pub use precomp2_lzma::Precomp2LzmaTransform;
pub use precomp2_zstd::Precomp2ZstdTransform;

fn precomp2_enabled(config: &FileTransformConfig) -> bool {
  config.enabled && config.precomp2.enabled
}

fn precomp2_zstd_enabled(config: &FileTransformConfig) -> bool {
  config.enabled && config.precomp2.enabled && config.precomp2_zstd.enabled
}

fn precomp2_lzma_enabled(config: &FileTransformConfig) -> bool {
  config.enabled && config.precomp2.enabled && config.precomp2_lzma.enabled
}

fn build_precomp2(config: &FileTransformConfig) -> Arc<dyn FileTransform> {
  Arc::new(Precomp2Transform::new(config))
}

fn build_precomp2_zstd(config: &FileTransformConfig) -> Arc<dyn FileTransform> {
  Arc::new(Precomp2ZstdTransform::new(config))
}

fn build_precomp2_lzma(config: &FileTransformConfig) -> Arc<dyn FileTransform> {
  Arc::new(Precomp2LzmaTransform::new(config))
}

pub fn default_specs() -> Vec<TransformSpec> {
  vec![
    TransformSpec {
      id: TRANSFORM_ID_PRECOMP2,
      name: "precomp2",
      selectable: true,
      use_quick_check: false,
      enabled: precomp2_enabled,
      build: build_precomp2,
    },
    TransformSpec {
      id: TRANSFORM_ID_PRECOMP2_ZSTD,
      name: "precomp2-zstd",
      selectable: true,
      use_quick_check: false,
      enabled: precomp2_zstd_enabled,
      build: build_precomp2_zstd,
    },
    TransformSpec {
      id: TRANSFORM_ID_PRECOMP2_LZMA,
      name: "precomp2-lzma",
      selectable: true,
      use_quick_check: false,
      enabled: precomp2_lzma_enabled,
      build: build_precomp2_lzma,
    },
  ]
}

pub fn default_decoders(config: &FileTransformConfig) -> Vec<Arc<dyn TransformDecoder>> {
  vec![
    Arc::new(Precomp2Transform::new(config)),
    Arc::new(Precomp2ZstdTransform::new(config)),
    Arc::new(Precomp2LzmaTransform::new(config)),
  ]
}
