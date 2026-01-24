use crate::protocol::{Version, V2_PREFIX};
use std::io;
use std::net::SocketAddr;
use tokio::io::{AsyncWrite, AsyncWriteExt};

pub async fn write_proxy_header<T: AsyncWrite + Unpin>(
  stream: &mut T,
  version: Version,
  src_addr: SocketAddr,
  dst_addr: SocketAddr,
) -> io::Result<()> {
  match version {
    Version::V1 => write_v1(stream, src_addr, dst_addr).await,
    Version::V2 => write_v2(stream, src_addr, dst_addr).await,
  }
}

async fn write_v1<T: AsyncWrite + Unpin>(
  stream: &mut T,
  src: SocketAddr,
  dst: SocketAddr,
) -> io::Result<()> {
  // Format: PROXY TCP4/TCP6 src_ip dst_ip src_port dst_port\r\n
  let proto = match src {
    SocketAddr::V4(_) => "TCP4",
    SocketAddr::V6(_) => "TCP6",
  };

  let header = format!(
    "PROXY {} {} {} {} {}\r\n",
    proto,
    src.ip(),
    dst.ip(),
    src.port(),
    dst.port()
  );

  stream.write_all(header.as_bytes()).await
}

async fn write_v2<T: AsyncWrite + Unpin>(
  stream: &mut T,
  src: SocketAddr,
  dst: SocketAddr,
) -> io::Result<()> {
  let mut buffer = Vec::with_capacity(32);

  // Signature
  buffer.extend_from_slice(V2_PREFIX);

  // Version + Command (Ver=2, Cmd=1 Proxy) -> 0x21
  buffer.push(0x21);

  // Family + Protocol
  let (fam, len) = match (src, dst) {
    (SocketAddr::V4(_), SocketAddr::V4(_)) => {
      // AF_INET=1, STREAM=1 -> 0x11
      // Length: 4+4+2+2 = 12
      (0x11, 12u16)
    }
    (SocketAddr::V6(_), SocketAddr::V6(_)) => {
      // AF_INET6=2, STREAM=1 -> 0x21
      // Length: 16+16+2+2 = 36
      (0x21, 36u16)
    }
    _ => {
      // Mismatched families or unknown
      // Send UNSPEC (AF_UNSPEC=0, UNSPEC=0) -> 0x00 and len 0
      buffer.push(0x00);
      buffer.extend_from_slice(&0u16.to_be_bytes());
      return stream.write_all(&buffer).await;
    }
  };

  buffer.push(fam);
  buffer.extend_from_slice(&len.to_be_bytes());

  match (src, dst) {
    (SocketAddr::V4(s), SocketAddr::V4(d)) => {
      buffer.extend_from_slice(&s.ip().octets());
      buffer.extend_from_slice(&d.ip().octets());
      buffer.extend_from_slice(&s.port().to_be_bytes());
      buffer.extend_from_slice(&d.port().to_be_bytes());
    }
    (SocketAddr::V6(s), SocketAddr::V6(d)) => {
      buffer.extend_from_slice(&s.ip().octets());
      buffer.extend_from_slice(&d.ip().octets());
      buffer.extend_from_slice(&s.port().to_be_bytes());
      buffer.extend_from_slice(&d.port().to_be_bytes());
    }
    _ => {}
  }

  stream.write_all(&buffer).await
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::io::Cursor;
  use std::net::{IpAddr, Ipv4Addr};

  #[tokio::test]
  async fn test_write_v1() {
    let mut buf = Vec::new();
    let mut cursor = Cursor::new(&mut buf);
    let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 1000);
    let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)), 2000);

    write_proxy_header(&mut cursor, Version::V1, src, dst)
      .await
      .unwrap();

    let output = String::from_utf8(buf).unwrap();
    assert_eq!(output, "PROXY TCP4 1.1.1.1 2.2.2.2 1000 2000\r\n");
  }

  #[tokio::test]
  async fn test_write_v2_ipv4() {
    let mut buf = Vec::new();
    let mut cursor = Cursor::new(&mut buf);
    let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 1000);
    let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)), 2000);

    write_proxy_header(&mut cursor, Version::V2, src, dst)
      .await
      .unwrap();

    // Check signature
    assert!(buf.starts_with(V2_PREFIX));
    // Check Version/Command (0x21)
    assert_eq!(buf[12], 0x21);
    // Check Fam/Proto (0x11 for IPv4 TCP)
    assert_eq!(buf[13], 0x11);
    // Length (12 bytes)
    assert_eq!(buf[14], 0);
    assert_eq!(buf[15], 12);
    // Payload (src ip, dst ip, src port, dst port)
    // 1.1.1.1 = 01 01 01 01
    // 2.2.2.2 = 02 02 02 02
    // 1000 = 03 E8
    // 2000 = 07 D0
    let payload = &buf[16..];
    assert_eq!(payload, &[1, 1, 1, 1, 2, 2, 2, 2, 0x03, 0xE8, 0x07, 0xD0]);
  }

  #[tokio::test]
  async fn test_write_v2_unspecified_dst() {
    let mut buf = Vec::new();
    let mut cursor = Cursor::new(&mut buf);
    // Simulate what might be happening: 127.0.0.1 -> 0.0.0.0 (if physical addr is used as dst and it is 0.0.0.0)
    let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 42070);
    let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 2222);

    write_proxy_header(&mut cursor, Version::V2, src, dst)
      .await
      .unwrap();

    // Verify bytes manually
    // Sig: \x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A
    // Ver/Cmd: 0x21
    // Fam/Proto: 0x11
    // Len: 12 (0x000C)
    // Src: 7F 00 00 01
    // Dst: 00 00 00 00
    // SrcPort: A4 56 (42070)
    // DstPort: 08 AE (2222)

    let expected = vec![
      0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x11, 0x00,
      0x0C, 0x7F, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xA4, 0x56, 0x08, 0xAE,
    ];
    assert_eq!(buf, expected);
  }
}
