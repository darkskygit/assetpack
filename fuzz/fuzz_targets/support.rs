#[allow(dead_code)]
pub fn mutate_fixture(fixture: &mut Vec<u8>, mutations: &[u8]) {
  for mutation in mutations.chunks_exact(3) {
    if fixture.is_empty() {
      return;
    }
    let offset = usize::from(u16::from_le_bytes([mutation[0], mutation[1]])) % fixture.len();
    fixture[offset] ^= mutation[2];
  }
  if let Some(length) = mutations.first().map(|byte| usize::from(*byte) % (fixture.len() + 1))
    && mutations.get(1).is_some_and(|byte| byte & 1 != 0)
  {
    fixture.truncate(length);
  }
}
