use crate::core::upstream::AsyncStream;
use std::io;

async fn splice_loop(read: &AsyncStream, write: &AsyncStream) -> (u64, io::Result<()>) {
  let mut pipe = [0i32; 2];
  if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) } < 0 {
    return (0, Err(io::Error::last_os_error()));
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
    let len = match read.splice_read(pipe_wr, 65536).await {
      Ok(0) => return (total_bytes, Ok(())), // EOF
      Ok(n) => n,
      Err(e) => return (total_bytes, Err(e)),
    };

    // pipe -> dst
    let mut written = 0;
    while written < len {
      let to_write = len - written;
      match write.splice_write(pipe_rd, to_write).await {
        Ok(0) => {
          return (
            total_bytes,
            Err(io::Error::new(
              io::ErrorKind::WriteZero,
              "Zero write in splice logic",
            )),
          );
        }
        Ok(n) => {
          written += n;
          total_bytes += n as u64;
        }
        Err(e) => return (total_bytes, Err(e)),
      }
    }
  }
}

pub async fn zero_copy_bidirectional(
  inbound: AsyncStream,
  outbound: AsyncStream,
) -> (u64, io::Result<()>) {
  // We own the streams now, so we can split references to them for the join.
  let ((c2s_bytes, c2s_res), (s2c_bytes, s2c_res)) = tokio::join!(
    splice_loop(&inbound, &outbound),
    splice_loop(&outbound, &inbound)
  );

  let total = c2s_bytes + s2c_bytes;

  // Prefer returning the first error encountered, but prioritize keeping the bytes
  if let Err(e) = c2s_res {
    return (total, Err(e));
  }
  if let Err(e) = s2c_res {
    return (total, Err(e));
  }

  (total, Ok(()))
}
