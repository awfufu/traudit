use crate::core::upstream::AsyncStream;
use std::io;

// Actual implementation below
// Spliceable trait and its implementations are removed as AsyncStream handles readiness internally.

async fn splice_loop(read: &AsyncStream, write: &AsyncStream) -> io::Result<u64> {
  let mut pipe = [0i32; 2];
  if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) } < 0 {
    return Err(io::Error::last_os_error());
  }
  let (pipe_rd, pipe_wr) = (pipe[0], pipe[1]);

  struct PipeGuard(i32, i32);
  impl Drop for PipeGuard {
    fn drop(&mut self) {
      unsafe {
        libc::close(self.0);
        libc::close(self.1);
      }
    }
  }
  let _guard = PipeGuard(pipe_rd, pipe_wr);

  let mut total_bytes = 0;

  loop {
    // src -> pipe
    // splice_read handles readiness internally with AsyncFd
    let len = match read.splice_read(pipe_wr, 65536).await {
      Ok(0) => return Ok(total_bytes), // EOF
      Ok(n) => n,
      Err(e) => return Err(e),
    };

    // pipe -> dst
    let mut written = 0;
    while written < len {
      let to_write = len - written;
      let n = write.splice_write(pipe_rd, to_write).await?;
      if n == 0 {
        return Err(io::Error::new(
          io::ErrorKind::WriteZero,
          "Zero write in splice logic",
        ));
      }
      written += n;
      total_bytes += n as u64;
    }
  }
}

pub async fn zero_copy_bidirectional(
  inbound: AsyncStream,
  outbound: AsyncStream,
) -> io::Result<()> {
  // We own the streams now, so we can split references to them for the join.
  let (c2s, s2c) = tokio::join!(
    splice_loop(&inbound, &outbound),
    splice_loop(&outbound, &inbound)
  );
  c2s?;
  s2c?;
  Ok(())
}
