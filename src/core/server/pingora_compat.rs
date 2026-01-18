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
