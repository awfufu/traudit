use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UnixStream};

#[derive(Debug)]
pub enum UpstreamStream {
  Tcp(TcpStream),
  Unix(UnixStream),
}

impl UpstreamStream {
  pub async fn connect(addr: &str) -> io::Result<Self> {
    if addr.starts_with('/') {
      let stream = UnixStream::connect(addr).await?;
      Ok(UpstreamStream::Unix(stream))
    } else {
      let stream = TcpStream::connect(addr).await?;
      stream.set_nodelay(true)?;
      Ok(UpstreamStream::Tcp(stream))
    }
  }
}

impl AsRawFd for UpstreamStream {
  fn as_raw_fd(&self) -> RawFd {
    match self {
      UpstreamStream::Tcp(s) => s.as_raw_fd(),
      UpstreamStream::Unix(s) => s.as_raw_fd(),
    }
  }
}

impl AsyncRead for UpstreamStream {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    match self.get_mut() {
      UpstreamStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
      UpstreamStream::Unix(s) => Pin::new(s).poll_read(cx, buf),
    }
  }
}

impl AsyncWrite for UpstreamStream {
  fn poll_write(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<Result<usize, io::Error>> {
    match self.get_mut() {
      UpstreamStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
      UpstreamStream::Unix(s) => Pin::new(s).poll_write(cx, buf),
    }
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
    match self.get_mut() {
      UpstreamStream::Tcp(s) => Pin::new(s).poll_flush(cx),
      UpstreamStream::Unix(s) => Pin::new(s).poll_flush(cx),
    }
  }

  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
    match self.get_mut() {
      UpstreamStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
      UpstreamStream::Unix(s) => Pin::new(s).poll_shutdown(cx),
    }
  }
}

impl UpstreamStream {
  pub fn into_async_stream(self) -> io::Result<AsyncStream> {
    match self {
      UpstreamStream::Tcp(s) => {
        let std = s.into_std()?;
        std.set_nonblocking(true)?;
        Ok(AsyncStream::Tcp(tokio::io::unix::AsyncFd::new(std)?))
      }
      UpstreamStream::Unix(s) => {
        let std = s.into_std()?;
        std.set_nonblocking(true)?;
        Ok(AsyncStream::Unix(tokio::io::unix::AsyncFd::new(std)?))
      }
    }
  }
}

pub enum AsyncStream {
  Tcp(tokio::io::unix::AsyncFd<std::net::TcpStream>),
  Unix(tokio::io::unix::AsyncFd<std::os::unix::net::UnixStream>),
}

impl AsyncStream {
  pub fn from_tokio_tcp(stream: tokio::net::TcpStream) -> io::Result<Self> {
    let std = stream.into_std()?;
    std.set_nonblocking(true)?;
    Ok(AsyncStream::Tcp(tokio::io::unix::AsyncFd::new(std)?))
  }

  pub async fn splice_read(&self, pipe_out: RawFd, len: usize) -> io::Result<usize> {
    match self {
      AsyncStream::Tcp(fd) => perform_splice_read(fd, pipe_out, len).await,
      AsyncStream::Unix(fd) => perform_splice_read(fd, pipe_out, len).await,
    }
  }

  pub async fn splice_write(&self, pipe_in: RawFd, len: usize) -> io::Result<usize> {
    match self {
      AsyncStream::Tcp(fd) => perform_splice_write(fd, pipe_in, len).await,
      AsyncStream::Unix(fd) => perform_splice_write(fd, pipe_in, len).await,
    }
  }
}

async fn perform_splice_read<T: AsRawFd>(
  fd: &tokio::io::unix::AsyncFd<T>,
  pipe_out: RawFd,
  len: usize,
) -> io::Result<usize> {
  loop {
    let mut guard = fd.readable().await?;
    match guard.try_io(|inner| unsafe {
      let res = libc::splice(
        inner.as_raw_fd(),
        std::ptr::null_mut(),
        pipe_out,
        std::ptr::null_mut(),
        len,
        libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
      );
      if res >= 0 {
        Ok(res as usize)
      } else {
        Err(io::Error::last_os_error())
      }
    }) {
      Ok(res) => return res,
      Err(_would_block) => continue, // try_io clears readiness
    }
  }
}

async fn perform_splice_write<T: AsRawFd>(
  fd: &tokio::io::unix::AsyncFd<T>,
  pipe_in: RawFd,
  len: usize,
) -> io::Result<usize> {
  loop {
    let mut guard = fd.writable().await?;
    match guard.try_io(|inner| unsafe {
      let res = libc::splice(
        pipe_in,
        std::ptr::null_mut(),
        inner.as_raw_fd(),
        std::ptr::null_mut(),
        len,
        libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
      );
      if res >= 0 {
        Ok(res as usize)
      } else {
        Err(io::Error::last_os_error())
      }
    }) {
      Ok(res) => return res,
      Err(_would_block) => continue,
    }
  }
}
