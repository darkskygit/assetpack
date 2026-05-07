use assetpack_core::error::{Error, Result};

pub(crate) fn magic_match(head: &[u8]) -> bool {
  const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";
  const GZIP_MAGIC: &[u8] = b"\x1f\x8b";
  const ZIP_MAGIC: &[u8] = b"PK\x03\x04";
  const PDF_MAGIC: &[u8] = b"%PDF";
  head.starts_with(PNG_MAGIC) || head.starts_with(GZIP_MAGIC) || head.starts_with(ZIP_MAGIC) || head.starts_with(PDF_MAGIC)
}

pub(crate) fn precomp2_guard<T>(context: &'static str, result: precomp2::Result<T>) -> Result<T> {
  result.map_err(|err| Error::Other(format!("precomp2 {context} failed: {err}")))
}
