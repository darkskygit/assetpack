use std::sync::Arc;

use crate::file_transform::{FileTransform, FileTransformConfig};

#[derive(Clone, Copy)]
pub struct TransformSpec {
  pub id: u16,
  pub name: &'static str,
  pub selectable: bool,
  pub use_quick_check: bool,
  pub enabled: fn(&FileTransformConfig) -> bool,
  pub build: fn(&FileTransformConfig) -> Arc<dyn FileTransform>,
}
