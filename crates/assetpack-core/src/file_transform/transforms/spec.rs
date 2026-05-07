use std::sync::Arc;

use super::none::NoneTransform;
use crate::file_transform::{FileTransform, FileTransformConfig, TRANSFORM_ID_NONE};

#[derive(Clone, Copy)]
pub struct TransformSpec {
  pub id: u16,
  pub name: &'static str,
  pub selectable: bool,
  pub use_quick_check: bool,
  pub enabled: fn(&FileTransformConfig) -> bool,
  pub build: fn(&FileTransformConfig) -> Arc<dyn FileTransform>,
}

fn always_enabled(_config: &FileTransformConfig) -> bool {
  true
}

fn build_none(_config: &FileTransformConfig) -> Arc<dyn FileTransform> {
  Arc::new(NoneTransform)
}

pub(crate) fn none_spec() -> TransformSpec {
  TransformSpec {
    id: TRANSFORM_ID_NONE,
    name: "none",
    selectable: false,
    use_quick_check: false,
    enabled: always_enabled,
    build: build_none,
  }
}
