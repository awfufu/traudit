use crate::core::upstream::AsyncStream;
use std::io;
use tokio::io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

async fn splice_loop(
  read: &AsyncStream,
  write: &AsyncStream,
  mut shutdown: pingora::server::ShutdownWatch,
) -> (u64, io::Result<()>) {
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
    if *shutdown.borrow() {
      return (total_bytes, Ok(()));
    }

    // src -> pipe
    let len = match read
      .splice_read_with_shutdown(pipe_wr, 65536, Some(&mut shutdown))
      .await
    {
      Ok(0) => return (total_bytes, Ok(())), // EOF
      Ok(n) => n,
      Err(e) => return (total_bytes, Err(e)),
    };

    // pipe -> dst
    let mut written = 0;
    while written < len {
      if *shutdown.borrow() {
        return (total_bytes, Ok(()));
      }

      let to_write = len - written;
      match write
        .splice_write_with_shutdown(pipe_rd, to_write, Some(&mut shutdown))
        .await
      {
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
  shutdown: pingora::server::ShutdownWatch,
) -> ((u64, u64), io::Result<()>) {
  let shutdown_c2s = shutdown.clone();
  let shutdown_s2c = shutdown.clone();

  // We own the streams now, so we can split references to them for the join.
  let ((c2s_bytes, c2s_res), (s2c_bytes, s2c_res)) = tokio::join!(
    async {
      let res = splice_loop(&inbound, &outbound, shutdown_c2s).await;
      let _ = outbound.shutdown_write();
      res
    },
    async {
      let res = splice_loop(&outbound, &inbound, shutdown_s2c).await;
      let _ = inbound.shutdown_write();
      res
    }
  );

  // s2c = sent (upstream -> client)
  // c2s = recv (client -> upstream)
  let metrics = (s2c_bytes, c2s_bytes);

  // Prefer returning the first error encountered, but prioritize keeping the bytes
  if let Err(e) = c2s_res {
    return (metrics, Err(e));
  }
  if let Err(e) = s2c_res {
    return (metrics, Err(e));
  }

  (metrics, Ok(()))
}

async fn copy_with_shutdown<R, W>(
  read: &mut R,
  write: &mut W,
  mut shutdown: pingora::server::ShutdownWatch,
) -> io::Result<u64>
where
  R: AsyncRead + Unpin,
  W: AsyncWrite + Unpin,
{
  let mut total = 0;
  let mut buf = [0u8; 16 * 1024];

  loop {
    let read_res = tokio::select! {
      res = read.read(&mut buf) => res,
      _ = async {
        if !*shutdown.borrow() {
          let _ = shutdown.changed().await;
        }
      } => {
        let _ = write.shutdown().await;
        return Ok(total);
      }
    }?;

    if read_res == 0 {
      write.shutdown().await?;
      return Ok(total);
    }

    write.write_all(&buf[..read_res]).await?;
    total += read_res as u64;
  }
}

pub async fn copy_bidirectional_with_shutdown<A, B>(
  a: &mut A,
  b: &mut B,
  shutdown: pingora::server::ShutdownWatch,
) -> ((u64, u64), io::Result<()>)
where
  A: AsyncRead + AsyncWrite + Unpin,
  B: AsyncRead + AsyncWrite + Unpin,
{
  let (mut a_read, mut a_write) = split(a);
  let (mut b_read, mut b_write) = split(b);
  let shutdown_a_to_b = shutdown.clone();
  let shutdown_b_to_a = shutdown.clone();

  let ((a_to_b, a_res), (b_to_a, b_res)) = tokio::join!(
    async {
      let res = copy_with_shutdown(&mut a_read, &mut b_write, shutdown_a_to_b).await;
      let _ = b_write.shutdown().await;
      (res.as_ref().copied().unwrap_or(0), res)
    },
    async {
      let res = copy_with_shutdown(&mut b_read, &mut a_write, shutdown_b_to_a).await;
      let _ = a_write.shutdown().await;
      (res.as_ref().copied().unwrap_or(0), res)
    }
  );

  let metrics = (b_to_a, a_to_b);

  if let Err(e) = a_res {
    return (metrics, Err(e));
  }
  if let Err(e) = b_res {
    return (metrics, Err(e));
  }

  (metrics, Ok(()))
}
