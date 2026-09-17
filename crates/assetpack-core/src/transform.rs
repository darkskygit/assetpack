use std::{collections::HashMap, fmt, io, sync::Arc};

use crate::{Error, Result};

pub const TRANSFORM_ID_NONE: u16 = 0;
pub const TRANSFORM_ID_PRECOMP2: u16 = 1;
pub const TRANSFORM_ID_PRECOMP2_ZSTD: u16 = 2;
pub const TRANSFORM_ID_PRECOMP2_LZMA: u16 = 3;
pub const TRANSFORM_VERSION_NONE: u16 = 0;
pub const TRANSFORM_VERSION_PRECOMP2: u16 = 2;
pub const TRANSFORM_VERSION_PRECOMP2_ZSTD: u16 = 2;
pub const TRANSFORM_VERSION_PRECOMP2_LZMA: u16 = 2;

pub trait TransformDecoder: Send + Sync {
  fn id(&self) -> u16;
  fn version(&self) -> u16;
  fn decode(&self, input: &mut dyn io::BufRead, output: &mut dyn io::Write) -> Result<()>;
}

struct NoneDecoder;

impl TransformDecoder for NoneDecoder {
  fn id(&self) -> u16 {
    TRANSFORM_ID_NONE
  }

  fn version(&self) -> u16 {
    TRANSFORM_VERSION_NONE
  }

  fn decode(&self, input: &mut dyn io::BufRead, output: &mut dyn io::Write) -> Result<()> {
    io::copy(input, output)?;
    Ok(())
  }
}

#[derive(Clone)]
pub struct TransformDecoderRegistry {
  decoders: HashMap<(u16, u16), Arc<dyn TransformDecoder>>,
}

impl TransformDecoderRegistry {
  pub fn new(decoders: impl IntoIterator<Item = Arc<dyn TransformDecoder>>) -> Result<Self> {
    let mut registry = Self { decoders: HashMap::new() };
    registry.insert(Arc::new(NoneDecoder))?;
    for decoder in decoders {
      registry.insert(decoder)?;
    }
    Ok(registry)
  }

  fn insert(&mut self, decoder: Arc<dyn TransformDecoder>) -> Result<()> {
    let key = (decoder.id(), decoder.version());
    if self.decoders.insert(key, decoder).is_some() {
      return Err(Error::DuplicateTransformDecoder { id: key.0, version: key.1 });
    }
    Ok(())
  }

  pub fn get(&self, id: u16, version: u16) -> Result<&dyn TransformDecoder> {
    self
      .decoders
      .get(&(id, version))
      .map(Arc::as_ref)
      .ok_or(Error::UnsupportedTransform { id, version })
  }
}

impl Default for TransformDecoderRegistry {
  fn default() -> Self {
    Self::new([]).expect("the built-in NONE decoder is unique")
  }
}

impl fmt::Debug for TransformDecoderRegistry {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    let mut keys = self.decoders.keys().copied().collect::<Vec<_>>();
    keys.sort_unstable();
    formatter
      .debug_struct("TransformDecoderRegistry")
      .field("transform_versions", &keys)
      .finish()
  }
}

#[cfg(test)]
mod tests {
  use std::io::{BufRead, Write};

  use super::*;

  struct TestDecoder(u16, u16);

  impl TransformDecoder for TestDecoder {
    fn id(&self) -> u16 {
      self.0
    }

    fn version(&self) -> u16 {
      self.1
    }

    fn decode(&self, _input: &mut dyn BufRead, _output: &mut dyn Write) -> Result<()> {
      Ok(())
    }
  }

  #[test]
  fn lookup_uses_exact_id_and_version() {
    let registry = TransformDecoderRegistry::new([Arc::new(TestDecoder(7, 3)) as Arc<dyn TransformDecoder>]).unwrap();
    assert_eq!((registry.get(0, 0).unwrap().id(), registry.get(0, 0).unwrap().version()), (0, 0));
    assert_eq!((registry.get(7, 3).unwrap().id(), registry.get(7, 3).unwrap().version()), (7, 3));
    for (id, version) in [(8, 3), (7, 4)] {
      assert!(matches!(
        registry.get(id, version),
        Err(Error::UnsupportedTransform { id: actual_id, version: actual_version })
          if actual_id == id && actual_version == version
      ));
    }
  }

  #[test]
  fn duplicate_pairs_are_rejected() {
    let result = TransformDecoderRegistry::new([
      Arc::new(TestDecoder(7, 3)) as Arc<dyn TransformDecoder>,
      Arc::new(TestDecoder(7, 3)) as Arc<dyn TransformDecoder>,
    ]);
    assert!(matches!(result, Err(Error::DuplicateTransformDecoder { id: 7, version: 3 })));
  }
}
