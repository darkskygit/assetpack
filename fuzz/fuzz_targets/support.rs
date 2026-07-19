use std::{future::Future, sync::Arc, task::{Context, Poll, Wake, Waker}};

struct NoopWake;

impl Wake for NoopWake {
  fn wake(self: Arc<Self>) {}
}

pub fn block_on<F: Future>(future: F) -> F::Output {
  let waker = Waker::from(Arc::new(NoopWake));
  let mut context = Context::from_waker(&waker);
  let mut future = std::pin::pin!(future);
  loop {
    match future.as_mut().poll(&mut context) {
      Poll::Ready(output) => return output,
      Poll::Pending => std::thread::yield_now(),
    }
  }
}

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
