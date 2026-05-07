use std::{collections::HashMap, fmt, sync::Arc};

use super::{TransformSpec, none_spec};
use crate::file_transform::{FileTransform, FileTransformConfig, TRANSFORM_ID_NONE};

#[derive(Clone)]
pub struct TransformRegistry {
  transforms: HashMap<u16, Arc<dyn FileTransform>>,
}

impl TransformRegistry {
  pub fn new(config: &FileTransformConfig, mut specs: Vec<TransformSpec>) -> Self {
    if !specs.iter().any(|spec| spec.id == TRANSFORM_ID_NONE) {
      specs.push(none_spec());
    }
    let transforms = specs.into_iter().map(|spec| (spec.id, (spec.build)(config))).collect();
    Self { transforms }
  }

  pub fn get(&self, id: u16) -> Option<&dyn FileTransform> {
    self.transforms.get(&id).map(|t| t.as_ref())
  }
}

impl fmt::Debug for TransformRegistry {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let mut ids: Vec<u16> = self.transforms.keys().copied().collect();
    ids.sort_unstable();
    f.debug_struct("TransformRegistry").field("transform_ids", &ids).finish()
  }
}
