use zstd::stream::raw::{DParameter, Decoder, InBuffer, Operation, OutBuffer};

use super::{
  DIRECTORY_RECORD_BYTES, DirectoryRecord, HEADER_BYTES, Header, MAX_DECODED_OBJECT_BYTES, MAX_INDEX_DECODED_BYTES, MAX_OBJECT_COUNT,
  MAX_STORED_OBJECT_BYTES, checked_range, codec_from_id, frame_count, invalid, logical_pack_id_records,
};
use crate::{Hash32, ObjectKind, Result};

const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
const INDEX_WINDOW_LOG: u32 = 20;

pub(super) fn encode_decoded_index(root: Hash32, records: &[DirectoryRecord]) -> Vec<u8> {
  let mut decoded = Vec::with_capacity(32 + records.len() * DIRECTORY_RECORD_BYTES);
  decoded.extend_from_slice(root.as_bytes());
  for record in records {
    decoded.extend_from_slice(record.hash.as_bytes());
    decoded.push(record.kind as u8);
    decoded.push(super::codec_id(record.codec));
    decoded.extend_from_slice(&record.decoded_length.to_le_bytes());
    decoded.extend_from_slice(&record.stored_length.to_le_bytes());
  }
  decoded
}

pub(super) fn compress_index(decoded: &[u8]) -> Result<Vec<u8>> {
  if decoded.len() > MAX_INDEX_DECODED_BYTES {
    return Err(invalid("decoded index exceeds hard limit"));
  }
  let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 19).map_err(|error| invalid(error.to_string()))?;
  encoder
    .set_parameter(zstd::zstd_safe::CParameter::WindowLog(INDEX_WINDOW_LOG))
    .map_err(|error| invalid(error.to_string()))?;
  encoder
    .set_parameter(zstd::zstd_safe::CParameter::NbWorkers(0))
    .map_err(|error| invalid(error.to_string()))?;
  encoder
    .set_parameter(zstd::zstd_safe::CParameter::EnableLongDistanceMatching(false))
    .map_err(|error| invalid(error.to_string()))?;
  encoder.include_checksum(false).map_err(|error| invalid(error.to_string()))?;
  encoder.include_dictid(false).map_err(|error| invalid(error.to_string()))?;
  encoder.include_contentsize(false).map_err(|error| invalid(error.to_string()))?;
  std::io::Write::write_all(&mut encoder, decoded).map_err(|error| invalid(error.to_string()))?;
  let compressed = encoder.finish().map_err(|error| invalid(error.to_string()))?;
  if compressed.len() > super::MAX_INDEX_COMPRESSED_BYTES {
    return Err(invalid("compressed index exceeds hard limit"));
  }
  Ok(compressed)
}

pub(super) fn decode_index(header: &Header, compressed: &[u8], pack_len: usize) -> Result<(Hash32, Vec<DirectoryRecord>)> {
  if compressed.get(..4) != Some(&ZSTD_MAGIC) {
    return Err(invalid("index is not a standard Zstandard frame"));
  }
  let frame_size = zstd::zstd_safe::find_frame_compressed_size(compressed).map_err(|error| invalid(error.to_string()))?;
  if frame_size != compressed.len() {
    return Err(invalid("index must contain exactly one Zstandard frame"));
  }
  let mut decoder = Decoder::new().map_err(|error| invalid(error.to_string()))?;
  decoder
    .set_parameter(DParameter::WindowLogMax(INDEX_WINDOW_LOG))
    .map_err(|error| invalid(error.to_string()))?;
  let mut input = InBuffer::around(compressed);
  let mut parser = IndexParser::new(header, pack_len);
  loop {
    let mut scratch = [0_u8; 8192];
    let mut output = OutBuffer::around(&mut scratch[..]);
    let remaining = decoder.run(&mut input, &mut output).map_err(|error| invalid(error.to_string()))?;
    let produced = output.pos();
    parser.push(&scratch[..produced])?;
    if remaining == 0 {
      if input.pos() != compressed.len() {
        return Err(invalid("index decoder did not consume the complete frame"));
      }
      break;
    }
    if produced == 0 && input.pos() == compressed.len() {
      return Err(invalid("truncated Zstandard index"));
    }
  }
  parser.finish()
}

struct IndexParser<'a> {
  header: &'a Header,
  pack_len: usize,
  decoded_bytes: usize,
  root: [u8; 32],
  root_bytes: usize,
  record: [u8; DIRECTORY_RECORD_BYTES],
  record_bytes: usize,
  records: Vec<DirectoryRecord>,
}

impl<'a> IndexParser<'a> {
  fn new(header: &'a Header, pack_len: usize) -> Self {
    Self {
      header,
      pack_len,
      decoded_bytes: 0,
      root: [0; 32],
      root_bytes: 0,
      record: [0; DIRECTORY_RECORD_BYTES],
      record_bytes: 0,
      records: Vec::new(),
    }
  }

  fn push(&mut self, mut bytes: &[u8]) -> Result<()> {
    self.decoded_bytes = self
      .decoded_bytes
      .checked_add(bytes.len())
      .filter(|length| *length <= MAX_INDEX_DECODED_BYTES)
      .ok_or_else(|| invalid("decoded index exceeds hard limit"))?;
    if self.root_bytes < self.root.len() {
      let count = bytes.len().min(self.root.len() - self.root_bytes);
      self.root[self.root_bytes..self.root_bytes + count].copy_from_slice(&bytes[..count]);
      self.root_bytes += count;
      bytes = &bytes[count..];
    }
    while !bytes.is_empty() {
      let count = bytes.len().min(DIRECTORY_RECORD_BYTES - self.record_bytes);
      self.record[self.record_bytes..self.record_bytes + count].copy_from_slice(&bytes[..count]);
      self.record_bytes += count;
      bytes = &bytes[count..];
      if self.record_bytes == DIRECTORY_RECORD_BYTES {
        self.emit_record()?;
        self.record_bytes = 0;
      }
    }
    Ok(())
  }

  fn emit_record(&mut self) -> Result<()> {
    if self.records.len() as u64 >= MAX_OBJECT_COUNT {
      return Err(invalid("object count exceeds hard limit"));
    }
    let record = DirectoryRecord {
      hash: Hash32::from_bytes(&self.record[..32])?,
      kind: ObjectKind::from_u8(self.record[32]).ok_or_else(|| invalid("unknown object kind"))?,
      codec: codec_from_id(self.record[33])?,
      decoded_length: u64::from_le_bytes(self.record[34..42].try_into().unwrap()),
      stored_length: u64::from_le_bytes(self.record[42..50].try_into().unwrap()),
      payload_offset: 0,
    };
    if record.decoded_length > MAX_DECODED_OBJECT_BYTES || record.stored_length > MAX_STORED_OBJECT_BYTES {
      return Err(invalid("non-canonical directory record"));
    }
    if self.records.last().is_some_and(|previous| previous.hash >= record.hash) {
      return Err(invalid("directory is not strictly hash sorted"));
    }
    self.records.push(record);
    Ok(())
  }

  fn finish(mut self) -> Result<(Hash32, Vec<DirectoryRecord>)> {
    if self.root_bytes != self.root.len() {
      return Err(invalid("decoded index is shorter than root hash"));
    }
    if self.record_bytes != 0 {
      return Err(invalid("decoded index ends with a partial directory record"));
    }
    if self.records.is_empty() {
      return Err(invalid("decoded index has no directory records"));
    }
    let root = Hash32::new(self.root);
    let root_record = self
      .records
      .binary_search_by_key(&root, |record| record.hash)
      .ok()
      .and_then(|index| self.records.get(index))
      .ok_or_else(|| invalid("root recipe is absent from directory"))?;
    if root_record.kind != ObjectKind::Recipe {
      return Err(invalid("root directory object is not a recipe"));
    }
    if logical_pack_id_records(root, &self.records) != self.header.pack_id {
      return Err(invalid("logical pack identity mismatch"));
    }
    let mut cursor = (HEADER_BYTES as u64)
      .checked_add(self.header.index_stored_length)
      .ok_or_else(|| invalid("payload cursor overflow"))?;
    for record in &mut self.records {
      record.payload_offset = cursor;
      let tag_bytes = if self.header.encrypted() {
        frame_count(record.stored_length)
          .checked_mul(16)
          .ok_or_else(|| invalid("payload tag length overflow"))?
      } else {
        0
      };
      let physical = record
        .stored_length
        .checked_add(tag_bytes)
        .ok_or_else(|| invalid("payload length overflow"))?;
      checked_range(self.pack_len, cursor, physical, "payload")?;
      cursor = cursor.checked_add(physical).ok_or_else(|| invalid("payload cursor overflow"))?;
    }
    if cursor != self.pack_len as u64 {
      return Err(invalid("non-canonical trailing bytes"));
    }
    Ok((root, self.records))
  }
}

#[cfg(test)]
mod tests {
  use std::io::Write;

  use super::*;
  use crate::Codec;

  fn record(hash: Hash32, kind: ObjectKind, decoded_length: u64, stored_length: u64) -> DirectoryRecord {
    DirectoryRecord {
      hash,
      kind,
      codec: Codec::Raw,
      decoded_length,
      stored_length,
      payload_offset: 0,
    }
  }

  fn root_and_records(count: usize) -> (Hash32, Vec<DirectoryRecord>) {
    let mut records = Vec::with_capacity(count);
    for value in 0..count as u64 {
      let mut bytes = [0_u8; 32];
      bytes[24..].copy_from_slice(&value.to_be_bytes());
      records.push(record(
        Hash32::new(bytes),
        if value == 0 { ObjectKind::Recipe } else { ObjectKind::Chunk },
        0,
        0,
      ));
    }
    (records[0].hash, records)
  }

  fn header(root: Hash32, records: &[DirectoryRecord], index_stored_length: u64) -> Header {
    Header {
      tag: super::super::DEFAULT_FORMAT_TAG,
      crypto_suite: super::super::CRYPTO_PLAIN_SHA3,
      index_stored_length,
      pack_id: super::super::logical_pack_id_records(root, records),
      pack_salt: [0; 32],
      key_slot: [0; 16],
      index_digest: Hash32::new([0; 32]),
    }
  }

  fn compress_unchecked(decoded: &[u8], window_log: u32) -> Vec<u8> {
    let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
    encoder.set_parameter(zstd::zstd_safe::CParameter::WindowLog(window_log)).unwrap();
    encoder.include_checksum(false).unwrap();
    encoder.include_dictid(false).unwrap();
    encoder.include_contentsize(false).unwrap();
    encoder.write_all(decoded).unwrap();
    encoder.finish().unwrap()
  }

  fn rejection(result: Result<(Hash32, Vec<DirectoryRecord>)>) -> crate::Error {
    match result {
      Ok(_) => panic!("index was accepted"),
      Err(error) => error,
    }
  }

  #[test]
  fn compact_directory_record_is_byte_exact() {
    assert_eq!(DIRECTORY_RECORD_BYTES, 50);
    let hash = Hash32::new([0x55; 32]);
    let record = DirectoryRecord {
      hash,
      kind: ObjectKind::Recipe,
      codec: Codec::Brotli,
      decoded_length: 0x1112_1314_1516_1718,
      stored_length: 0x2122_2324_2526_2728,
      payload_offset: 999,
    };
    let decoded = encode_decoded_index(hash, &[record]);
    let raw = &decoded[32..];
    assert_eq!(&raw[..32], &[0x55; 32]);
    assert_eq!(raw[32], ObjectKind::Recipe as u8);
    assert_eq!(raw[33], 2);
    assert_eq!(&raw[34..42], &0x1112_1314_1516_1718_u64.to_le_bytes());
    assert_eq!(&raw[42..50], &0x2122_2324_2526_2728_u64.to_le_bytes());
  }

  #[test]
  fn fixed_encoder_rejects_decoded_input_over_hard_limit() {
    let error = compress_index(&vec![0; MAX_INDEX_DECODED_BYTES + 1]).unwrap_err();
    assert!(error.to_string().contains("decoded index exceeds hard limit"));
  }

  #[test]
  fn fixed_encoder_rejects_compressed_output_over_hard_limit() {
    let mut state = 0x1234_5678_u32;
    let decoded = (0..super::super::MAX_INDEX_COMPRESSED_BYTES + 64 * 1024)
      .map(|_| {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        state as u8
      })
      .collect::<Vec<_>>();
    let error = compress_index(&decoded).unwrap_err();
    assert!(error.to_string().contains("compressed index exceeds hard limit"));
  }

  #[test]
  fn decoder_rejects_short_nonstandard_multiple_trailing_and_truncated_frames() {
    let (root, records) = root_and_records(1);
    let decoded = encode_decoded_index(root, &records);
    let stored = compress_index(&decoded).unwrap();
    let cases = [
      compress_unchecked(&decoded[..31], INDEX_WINDOW_LOG),
      vec![0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0],
      [stored.as_slice(), stored.as_slice()].concat(),
      [stored.as_slice(), &[0]].concat(),
      stored[..stored.len() - 1].to_vec(),
      [vec![0xff], stored[1..].to_vec()].concat(),
    ];
    for (case, replacement) in cases.into_iter().enumerate() {
      let header = header(root, &records, replacement.len() as u64);
      let result = decode_index(&header, &replacement, HEADER_BYTES + replacement.len());
      assert!(result.is_err(), "invalid frame case {case} was accepted");
    }
  }

  #[test]
  fn decoder_rejects_window_over_limit_before_directory_parse() {
    let oversized = compress_unchecked(&vec![0; 2 * 1024 * 1024], 21);
    let (root, records) = root_and_records(1);
    let header = header(root, &records, oversized.len() as u64);
    let error = rejection(decode_index(&header, &oversized, HEADER_BYTES + oversized.len()));
    assert!(error.to_string().contains("Frame requires too much memory for decoding"), "{error}");
  }

  #[test]
  fn decoder_rejects_semantically_valid_compression_bomb_at_decoded_limit() {
    let record_count = (MAX_INDEX_DECODED_BYTES - 32) / DIRECTORY_RECORD_BYTES + 1;
    let (root, records) = root_and_records(record_count);
    let decoded = encode_decoded_index(root, &records);
    assert!(decoded.len() > MAX_INDEX_DECODED_BYTES);
    let bomb = compress_unchecked(&decoded, INDEX_WINDOW_LOG);
    assert!(bomb.len() <= super::super::MAX_INDEX_COMPRESSED_BYTES);
    let header = header(root, &records, bomb.len() as u64);
    let error = rejection(decode_index(&header, &bomb, HEADER_BYTES + bomb.len()));
    assert!(error.to_string().contains("decoded index exceeds hard limit"), "{error}");
  }

  #[test]
  fn decoder_rejects_payload_cursor_overflow() {
    let (root, records) = root_and_records(1);
    let decoded = encode_decoded_index(root, &records);
    let stored = compress_index(&decoded).unwrap();
    let header = header(root, &records, u64::MAX);
    let error = rejection(decode_index(&header, &stored, HEADER_BYTES + stored.len()));
    assert!(error.to_string().contains("payload cursor overflow"), "{error}");
  }

  #[cfg(feature = "sealed-encryption")]
  #[test]
  fn encrypted_odd_length_payloads_have_consecutive_exact_cursors() {
    let (root, mut records) = root_and_records(4);
    for (record, stored_length) in records.iter_mut().zip([1, 3, 5, 7]) {
      record.stored_length = stored_length;
    }
    let decoded = encode_decoded_index(root, &records);
    let stored = compress_index(&decoded).unwrap();
    let mut header = header(root, &records, stored.len() as u64 + 16);
    header.crypto_suite = super::super::CRYPTO_CHACHA20_POLY1305_FRAMES;
    let payload_bytes = records.iter().map(|record| record.stored_length + 16).sum::<u64>();
    let pack_len = HEADER_BYTES + header.index_stored_length as usize + payload_bytes as usize;
    let (_, decoded_records) = decode_index(&header, &stored, pack_len).unwrap();
    let mut cursor = HEADER_BYTES as u64 + header.index_stored_length;
    for record in decoded_records {
      assert_eq!(record.payload_offset, cursor);
      cursor += record.stored_length + 16;
    }
    assert_eq!(cursor, pack_len as u64);
  }
}
