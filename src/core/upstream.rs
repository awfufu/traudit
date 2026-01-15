use crate::config::ForwardType;
use monoio::io::AsyncWriteRentExt;
use monoio::net::{TcpStream, UnixStream};
use std::io;

#[derive(Debug)]
pub enum UpstreamStream {
  Tcp(TcpStream),
  Unix(UnixStream),
}

impl UpstreamStream {
  pub async fn connect(fw_type: ForwardType, addr: &str) -> io::Result<Self> {
    match fw_type {
      ForwardType::Tcp => {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        Ok(UpstreamStream::Tcp(stream))
      }
      ForwardType::Unix => {
        let stream = UnixStream::connect(addr).await?;
        Ok(UpstreamStream::Unix(stream))
      }
      ForwardType::Udp => Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "UDP forwarding not yet implemented in stream context",
      )),
    }
  }

  pub async fn write_all<T: monoio::buf::IoBuf>(&mut self, buf: T) -> (io::Result<usize>, T) {
    match self {
      UpstreamStream::Tcp(s) => s.write_all(buf).await,
      UpstreamStream::Unix(s) => s.write_all(buf).await,
    }
  }
}
