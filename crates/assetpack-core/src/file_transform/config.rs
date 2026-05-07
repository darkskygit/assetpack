use std::path::{Path, PathBuf};

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(default)]
pub struct FileTransformConfig {
  pub enabled: bool,
  pub min_size: u64,
  pub min_gain: f64,
  pub allow_ext: Vec<String>,
  pub max_in_memory_bytes: u64,
  pub max_transform_bytes: u64,
  pub spill_to_disk: bool,
  pub temp_dir: Option<PathBuf>,
  pub eval: FileTransformEvalConfig,
  pub precomp2: FileTransformPrecomp2Config,
  pub precomp2_zstd: FileTransformPrecomp2ZstdConfig,
  pub precomp2_lzma: FileTransformPrecomp2LzmaConfig,
}

impl Default for FileTransformConfig {
  fn default() -> Self {
    Self {
      enabled: true,
      min_size: 32 * 1024,
      min_gain: 0.01,
      allow_ext: vec![
        "png".into(),
        "zip".into(),
        "gz".into(),
        "pdf".into(),
        "docx".into(),
        "xlsx".into(),
        "pptx".into(),
        "svgz".into(),
      ],
      max_in_memory_bytes: 100 * 1024 * 1024,
      max_transform_bytes: 1024 * 1024 * 1024,
      spill_to_disk: true,
      temp_dir: Some(PathBuf::from(".assetcache/tmp")),
      eval: FileTransformEvalConfig::default(),
      precomp2: FileTransformPrecomp2Config::default(),
      precomp2_zstd: FileTransformPrecomp2ZstdConfig::default(),
      precomp2_lzma: FileTransformPrecomp2LzmaConfig::default(),
    }
  }
}

impl FileTransformConfig {
  pub fn resolved_temp_dir(&self, root: &Path) -> Option<PathBuf> {
    let dir = self.temp_dir.as_ref()?;
    if dir.as_os_str().is_empty() {
      return None;
    }
    if dir.is_absolute() {
      Some(dir.clone())
    } else {
      Some(root.join(dir))
    }
  }
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(default)]
pub struct FileTransformEvalConfig {
  pub max_buffer_bytes: u64,
  pub estimator_zstd_level: i32,
}

impl Default for FileTransformEvalConfig {
  fn default() -> Self {
    Self {
      max_buffer_bytes: 100 * 1024 * 1024,
      estimator_zstd_level: 5,
    }
  }
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(default)]
pub struct FileTransformPrecomp2Config {
  pub enabled: bool,
  pub max_depth: u32,
  pub max_expand_ratio: f64,
  pub max_total_output: u64,
  pub recover: bool,
}

impl Default for FileTransformPrecomp2Config {
  fn default() -> Self {
    Self {
      enabled: true,
      max_depth: 4,
      max_expand_ratio: 16.0,
      max_total_output: 1 << 32,
      recover: false,
    }
  }
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(default)]
pub struct FileTransformPrecomp2ZstdConfig {
  pub enabled: bool,
  pub level: i32,
}

impl Default for FileTransformPrecomp2ZstdConfig {
  fn default() -> Self {
    Self { enabled: true, level: 6 }
  }
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(default)]
pub struct FileTransformPrecomp2LzmaConfig {
  pub enabled: bool,
  pub preset: u8,
  pub dict_size: usize,
}

impl Default for FileTransformPrecomp2LzmaConfig {
  fn default() -> Self {
    Self {
      enabled: true,
      preset: 6,
      dict_size: 64 * 1024 * 1024,
    }
  }
}
