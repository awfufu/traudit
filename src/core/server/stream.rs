use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UnixStream};

#[derive(Debug)]
pub enum InboundStream {
  Tcp(TcpStream),
  Unix(UnixStream),
}

impl AsyncRead for InboundStream {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<std::io::Result<()>> {
    match self.get_mut() {
      InboundStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
      InboundStream::Unix(s) => Pin::new(s).poll_read(cx, buf),
    }
  }
}

impl AsyncWrite for InboundStream {
  fn poll_write(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<Result<usize, std::io::Error>> {
    match self.get_mut() {
      InboundStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
      InboundStream::Unix(s) => Pin::new(s).poll_write(cx, buf),
    }
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
    match self.get_mut() {
      InboundStream::Tcp(s) => Pin::new(s).poll_flush(cx),
      InboundStream::Unix(s) => Pin::new(s).poll_flush(cx),
    }
  }

  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
    match self.get_mut() {
      InboundStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
      InboundStream::Unix(s) => Pin::new(s).poll_shutdown(cx),
    }
  }
}
