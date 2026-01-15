use bytes::BytesMut;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug, Clone)]
pub struct ProxyInfo {
  pub version: Version,
  pub source: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
  V1,
  V2,
}

const V1_PREFIX: &[u8] = b"PROXY ";
const V2_PREFIX: &[u8] = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"; // 12 bytes

pub async fn read_proxy_header<T: AsyncRead + Unpin>(
  stream: &mut T,
) -> io::Result<(Option<ProxyInfo>, BytesMut)> {
  let mut buf = BytesMut::with_capacity(512);

  loop {
    if !buf.is_empty() {
      // Check potential V2 match
      let v2_match = if buf.len() <= V2_PREFIX.len() {
        V2_PREFIX.starts_with(&buf)
      } else {
        buf.starts_with(V2_PREFIX)
      };

      // Check potential V1 match
      let v1_match = if buf.len() <= V1_PREFIX.len() {
        V1_PREFIX.starts_with(&buf)
      } else {
        buf.starts_with(V1_PREFIX)
      };

      // If matches neither, it's not a proxy header
      if !v2_match && !v1_match {
        return Ok((None, buf));
      }

      // If identified as V2 (full signature match)
      if buf.len() >= 12 && buf.starts_with(V2_PREFIX) {
        return parse_v2(stream, buf).await;
      }

      // If identified as V1 (full signature match)
      if buf.len() >= 6 && buf.starts_with(V1_PREFIX) {
        return parse_v1(stream, buf).await;
      }
    }

    // Need more data to decide
    let n = stream.read_buf(&mut buf).await?;
    if n == 0 {
      // EOF before header complete/identified
      return Ok((None, buf));
    }
  }
}

async fn parse_v1<T: AsyncRead + Unpin>(
  stream: &mut T,
  mut buf: BytesMut,
) -> io::Result<(Option<ProxyInfo>, BytesMut)> {
  // Read line until \r\n
  loop {
    if let Some(pos) = buf.windows(2).position(|w| w == b"\r\n") {
      // Found line end
      let line_bytes = buf.split_to(pos + 2); // Consumes line including \r\n
      let line = String::from_utf8_lossy(&line_bytes[..line_bytes.len() - 2]); // drop \r\n

      let parts: Vec<&str> = line.split(' ').collect();
      // PROXY TCP4 1.2.3.4 5.6.7.8 80 8080
      if parts.len() >= 6 && parts[0] == "PROXY" {
        let src_ip: IpAddr = parts[2]
          .parse()
          .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid src IP"))?;
        let _dst_ip: IpAddr = parts[3]
          .parse()
          .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid dst IP"))?;
        let src_port: u16 = parts[4]
          .parse()
          .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid src port"))?;
        let _dst_port: u16 = parts[5]
          .parse()
          .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid dst port"))?;

        return Ok((
          Some(ProxyInfo {
            version: Version::V1,
            source: SocketAddr::new(src_ip, src_port),
          }),
          buf,
        ));
      }
      return Ok((None, buf));
    }

    // Read more
    let n = stream.read_buf(&mut buf).await?;
    if n == 0 {
      return Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "Incomplete V1 header",
      ));
    }
    if buf.len() > 256 {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "V1 header too too long",
      ));
    }
  }
}

async fn parse_v2<T: AsyncRead + Unpin>(
  stream: &mut T,
  mut buf: BytesMut,
) -> io::Result<(Option<ProxyInfo>, BytesMut)> {
  // We already have at least 12 bytes.
  // 13th byte: ver_cmd (version 4 bits + command 4 bits)
  // 14th byte: fam (family 4 bits + proto 4 bits)
  // 15th-16th: len (u16 big endian)

  while buf.len() < 16 {
    let n = stream.read_buf(&mut buf).await?;
    if n == 0 {
      return Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "Incomplete V2 header",
      ));
    }
  }

  // Check version (should be 2) and command (0=Local, 1=Proxy)
  let ver_cmd = buf[12];
  if (ver_cmd >> 4) != 2 {
    return Err(io::Error::new(
      io::ErrorKind::InvalidData,
      "Invalid Proxy Protocol version",
    ));
  }

  // Length
  let len_bytes = [buf[14], buf[15]];
  let len = u16::from_be_bytes(len_bytes) as usize;

  // Read payload
  while buf.len() < 16 + len {
    let n = stream.read_buf(&mut buf).await?;
    if n == 0 {
      return Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "Incomplete V2 payload",
      ));
    }
  }

  // Consume header + payload
  let full_len = 16 + len;
  let header_bytes = buf.split_to(full_len); // Now buf has remaining data

  // Parse addresses from payload (header_bytes[16..])
  let fam = header_bytes[13];
  let payload = &header_bytes[16..];

  match fam {
    0x11 | 0x12 => {
      // TCP/UDP over IPv4
      if payload.len() >= 12 {
        let src_ip = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
        let _dst_ip = Ipv4Addr::new(payload[4], payload[5], payload[6], payload[7]);
        let src_port = u16::from_be_bytes([payload[8], payload[9]]);
        let _dst_port = u16::from_be_bytes([payload[10], payload[11]]);
        return Ok((
          Some(ProxyInfo {
            version: Version::V2,
            source: SocketAddr::new(IpAddr::V4(src_ip), src_port),
          }),
          buf,
        ));
      }
    }
    0x21 | 0x22 => {
      // TCP/UDP over IPv6
      if payload.len() >= 36 {
        // IPv6 parsing...
        // Keep it brief
        let mut src = [0u8; 16];
        src.copy_from_slice(&payload[0..16]);
        let mut _dst = [0u8; 16];
        _dst.copy_from_slice(&payload[16..32]);
        let src_port = u16::from_be_bytes([payload[32], payload[33]]);
        let _dst_port = u16::from_be_bytes([payload[34], payload[35]]);
        return Ok((
          Some(ProxyInfo {
            version: Version::V2,
            source: SocketAddr::new(IpAddr::V6(Ipv6Addr::from(src)), src_port),
          }),
          buf,
        ));
      }
    }
    _ => {}
  }

  // If unsupported family or LOCAL command, return Info with dummy/empty or just ignore
  // For now, if we can't parse addr, we return None but consume header.
  Ok((None, buf))
}
