use async_trait::async_trait;
use bytes::{Buf, BytesMut};
use pingora::protocols::l4::socket::SocketAddr;
use pingora::protocols::{
  GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown, SocketDigest, Ssl,
  TimingDigest, UniqueID, UniqueIDType,
};
use std::fmt::Debug;
use std::io;
use std::net::SocketAddr as InetSocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::core::server::stream::InboundStream;

#[derive(Debug)]
pub struct PingoraStream {
  inner: InboundStream,
  buffer: BytesMut,
  digest: Arc<SocketDigest>,
}

impl PingoraStream {
  pub fn new(
    inner: InboundStream,
    buffer: BytesMut,
    peer_addr: InetSocketAddr,
    local_addr: InetSocketAddr,
  ) -> Self {
    #[cfg(unix)]
    let digest = {
      use std::os::fd::AsRawFd;
      let fd = match &inner {
        InboundStream::Tcp(s) => s.as_raw_fd(),
        InboundStream::Unix(s) => s.as_raw_fd(),
      };
      let digest = SocketDigest::from_raw_fd(fd);
      let _ = digest.peer_addr.set(Some(SocketAddr::Inet(peer_addr)));
      let _ = digest.local_addr.set(Some(SocketAddr::Inet(local_addr)));
      Arc::new(digest)
    };

    // Windows support or non-unix fallback
    #[cfg(not(unix))]
    let digest = Arc::new(SocketDigest::default());

    Self {
      inner,
      buffer,
      digest,
    }
  }

  pub fn into_inner(self) -> (InboundStream, BytesMut) {
    (self.inner, self.buffer)
  }
}

impl AsyncRead for PingoraStream {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    if self.buffer.has_remaining() {
      let len = std::cmp::min(self.buffer.len(), buf.remaining());
      buf.put_slice(&self.buffer[..len]);
      self.buffer.advance(len);
      Poll::Ready(Ok(()))
    } else {
      Pin::new(&mut self.inner).poll_read(cx, buf)
    }
  }
}

impl AsyncWrite for PingoraStream {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<io::Result<usize>> {
    Pin::new(&mut self.inner).poll_write(cx, buf)
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Pin::new(&mut self.inner).poll_flush(cx)
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Pin::new(&mut self.inner).poll_shutdown(cx)
  }
}

#[async_trait]
impl Shutdown for PingoraStream {
  async fn shutdown(&mut self) -> () {
    let _ = <InboundStream as AsyncWriteExt>::shutdown(&mut self.inner).await;
  }
}

impl UniqueID for PingoraStream {
  fn id(&self) -> UniqueIDType {
    0
  }
}

impl Ssl for PingoraStream {}

impl GetTimingDigest for PingoraStream {
  fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> {
    vec![]
  }
}

impl GetProxyDigest for PingoraStream {
  fn get_proxy_digest(&self) -> Option<Arc<pingora::protocols::raw_connect::ProxyDigest>> {
    None
  }
}

impl GetSocketDigest for PingoraStream {
  fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> {
    Some(self.digest.clone())
  }
}

impl Peek for PingoraStream {}

#[derive(Debug)]
pub struct PingoraTlsStream {
  inner: tokio_openssl::SslStream<PingoraStream>,
}

impl PingoraTlsStream {
  pub fn new(inner: tokio_openssl::SslStream<PingoraStream>) -> Self {
    Self { inner }
  }
}

impl AsyncRead for PingoraTlsStream {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    Pin::new(&mut self.inner).poll_read(cx, buf)
  }
}

impl AsyncWrite for PingoraTlsStream {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<io::Result<usize>> {
    Pin::new(&mut self.inner).poll_write(cx, buf)
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Pin::new(&mut self.inner).poll_flush(cx)
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Pin::new(&mut self.inner).poll_shutdown(cx)
  }
}

#[async_trait]
impl Shutdown for PingoraTlsStream {
  async fn shutdown(&mut self) -> () {
    let _ =
      <tokio_openssl::SslStream<PingoraStream> as AsyncWriteExt>::shutdown(&mut self.inner).await;
  }
}

impl UniqueID for PingoraTlsStream {
  fn id(&self) -> UniqueIDType {
    0
  }
}

// Pingora TLS stream should report ALPN, etc if needed, but for now default is fine.
// We can expose the inner ssl if needed.
impl Ssl for PingoraTlsStream {}

impl GetTimingDigest for PingoraTlsStream {
  fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> {
    vec![]
  }
}

impl GetProxyDigest for PingoraTlsStream {
  fn get_proxy_digest(&self) -> Option<Arc<pingora::protocols::raw_connect::ProxyDigest>> {
    None
  }
}

impl GetSocketDigest for PingoraTlsStream {
  fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> {
    self.inner.get_ref().get_socket_digest()
  }
}

impl Peek for PingoraTlsStream {}

#[derive(Debug)]
pub enum UnifiedPingoraStream {
  Plain(PingoraStream),
  Tls(PingoraTlsStream),
}

impl UnifiedPingoraStream {
  pub fn into_plain(self) -> Option<PingoraStream> {
    match self {
      UnifiedPingoraStream::Plain(s) => Some(s),
      _ => None,
    }
  }
}

impl AsyncRead for UnifiedPingoraStream {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    match &mut *self {
      UnifiedPingoraStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
      UnifiedPingoraStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
    }
  }
}

impl AsyncWrite for UnifiedPingoraStream {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<io::Result<usize>> {
    match &mut *self {
      UnifiedPingoraStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
      UnifiedPingoraStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
    }
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    match &mut *self {
      UnifiedPingoraStream::Plain(s) => Pin::new(s).poll_flush(cx),
      UnifiedPingoraStream::Tls(s) => Pin::new(s).poll_flush(cx),
    }
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    match &mut *self {
      UnifiedPingoraStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
      UnifiedPingoraStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
    }
  }
}

#[async_trait]
impl Shutdown for UnifiedPingoraStream {
  async fn shutdown(&mut self) -> () {
    match self {
      UnifiedPingoraStream::Plain(s) => <PingoraStream as Shutdown>::shutdown(s).await,
      UnifiedPingoraStream::Tls(s) => <PingoraTlsStream as Shutdown>::shutdown(s).await,
    }
  }
}

impl UniqueID for UnifiedPingoraStream {
  fn id(&self) -> UniqueIDType {
    match self {
      UnifiedPingoraStream::Plain(s) => s.id(),
      UnifiedPingoraStream::Tls(s) => s.id(),
    }
  }
}

impl Ssl for UnifiedPingoraStream {}

impl GetTimingDigest for UnifiedPingoraStream {
  fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> {
    match self {
      UnifiedPingoraStream::Plain(s) => s.get_timing_digest(),
      UnifiedPingoraStream::Tls(s) => s.get_timing_digest(),
    }
  }
}

impl GetProxyDigest for UnifiedPingoraStream {
  fn get_proxy_digest(&self) -> Option<Arc<pingora::protocols::raw_connect::ProxyDigest>> {
    match self {
      UnifiedPingoraStream::Plain(s) => s.get_proxy_digest(),
      UnifiedPingoraStream::Tls(s) => s.get_proxy_digest(),
    }
  }
}

impl GetSocketDigest for UnifiedPingoraStream {
  fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> {
    match self {
      UnifiedPingoraStream::Plain(s) => s.get_socket_digest(),
      UnifiedPingoraStream::Tls(s) => s.get_socket_digest(),
    }
  }
}

impl Peek for UnifiedPingoraStream {}
