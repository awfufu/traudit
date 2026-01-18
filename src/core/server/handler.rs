use super::stream::InboundStream;
use crate::config::{RealIpConfig, RealIpSource, ServiceConfig};
use crate::core::forwarder;
use crate::core::server::pingora_compat::PingoraStream;
use crate::core::upstream::UpstreamStream;
use crate::db::clickhouse::{ClickHouseLogger, ProxyProto};
use crate::protocol::{self, ProxyInfo};
use bytes::BytesMut;
use pingora::protocols::GetSocketDigest;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tracing::{error, info};

pub async fn handle_connection(
  stream: PingoraStream,
  proxy_info: Option<ProxyInfo>,
  service: ServiceConfig,
  db: Arc<ClickHouseLogger>,
  listen_addr: String,
) -> std::io::Result<u64> {
  let conn_ts = time::OffsetDateTime::now_utc();
  let start_instant = std::time::Instant::now();

  // Extract resolved IP from digest (injected by listener)
  let digest = stream.get_socket_digest();
  let (final_ip, final_port) = if let Some(d) = digest {
    if let Some(pingora::protocols::l4::socket::SocketAddr::Inet(addr)) = d.peer_addr() {
      (addr.ip(), addr.port())
    } else {
      // Should not match other types if logic is correct
      (std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 0)
    }
  } else {
    (std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 0)
  };

  // Unwrap stream
  let (inbound, mut read_buffer) = stream.into_inner();

  let is_unix = matches!(inbound, InboundStream::Unix(_));
  let remote_addr = match &inbound {
    InboundStream::Tcp(s) => s.peer_addr()?,
    InboundStream::Unix(_) => SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 0),
  };

  // skip redundant proxy/IP resolution (done by listener); determine ProxyProto for logging
  let proto_enum = if let Some(ref info) = proxy_info {
    match info.version {
      protocol::Version::V1 => ProxyProto::V1,
      protocol::Version::V2 => ProxyProto::V2,
    }
  } else {
    ProxyProto::None
  };

  // Log connection info
  let src_fmt = if is_unix && proto_enum == ProxyProto::None {
    "local".to_string()
  } else {
    final_ip.to_string()
  };
  let physical_fmt = if is_unix {
    "local".to_string()
  } else {
    remote_addr.to_string()
  };

  if src_fmt == physical_fmt {
    info!("[{}] {} <- {}", service.name, listen_addr, src_fmt);
  } else {
    info!(
      "[{}] {} <- {} ({})",
      service.name, listen_addr, src_fmt, physical_fmt
    );
  }

  // 3. Connect Upstream
  let mut upstream = UpstreamStream::connect(&service.forward_to).await?;

  // 4. Write buffered data
  if !read_buffer.is_empty() {
    upstream.write_all_buf(&mut read_buffer).await?;
  }

  // 5. Zero-copy forwarding
  let inbound_async = match inbound {
    InboundStream::Tcp(s) => crate::core::upstream::AsyncStream::from_tokio_tcp(s)?,
    InboundStream::Unix(s) => crate::core::upstream::AsyncStream::from_tokio_unix(s)?,
  };
  let upstream_async = upstream.into_async_stream()?;

  let (spliced_bytes, splice_res) =
    forwarder::zero_copy_bidirectional(inbound_async, upstream_async).await;

  if let Err(e) = splice_res {
    match e.kind() {
      std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe => {
        tracing::debug!("[{}] connection closed: {}", service.name, e);
      }
      _ => error!("[{}] connection error: {}", service.name, e),
    }
  }

  // Calculate total bytes
  let total_bytes = spliced_bytes + read_buffer.len() as u64;

  // Logging logic
  let duration = start_instant.elapsed().as_millis() as u32;

  // Handle Unix socket specifics for logging
  let (log_ip, log_port, log_family) = if is_unix && proto_enum == ProxyProto::None {
    (
      IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
      0,
      crate::db::clickhouse::AddrFamily::Unix,
    )
  } else {
    let family = match final_ip {
      IpAddr::V4(_) => crate::db::clickhouse::AddrFamily::Ipv4,
      IpAddr::V6(_) => crate::db::clickhouse::AddrFamily::Ipv6,
    };
    (final_ip, final_port, family)
  };

  let log_entry = crate::db::clickhouse::TcpLog {
    service: service.name.clone(),
    conn_ts,
    duration,
    addr_family: log_family,
    ip: log_ip,
    port: log_port,
    proxy_proto: proto_enum,
    bytes: total_bytes,
  };

  tokio::spawn(async move {
    if let Err(e) = db.insert_log(log_entry).await {
      error!("failed to insert tcp log: {}", e);
    }
  });

  Ok(total_bytes)
}

pub async fn resolve_real_ip(
  config: &Option<RealIpConfig>,
  remote_addr: SocketAddr,
  proxy_info: &Option<ProxyInfo>,
  inbound: &mut InboundStream,
  buffer: &mut BytesMut,
) -> io::Result<(IpAddr, u16)> {
  if let Some(cfg) = config {
    match cfg.source {
      RealIpSource::ProxyProtocol => {
        if let Some(info) = proxy_info {
          // Trust check: The PHYSICAL connection must be from a trusted source
          if cfg.is_trusted(remote_addr.ip()) {
            return Ok((info.source.ip(), info.source.port()));
          }
        }
      }
      RealIpSource::Xff => {
        let current_ip = if let Some(info) = proxy_info {
          info.source.ip()
        } else {
          remote_addr.ip()
        };

        if cfg.is_trusted(current_ip) {
          if let Some(ip) = peek_xff_ip(inbound, buffer, cfg.xff_trust_depth).await? {
            // XFF doesn't have port, use remote/proxy port
            let port = if let Some(info) = proxy_info {
              info.source.port()
            } else {
              remote_addr.port()
            };
            return Ok((ip, port));
          }
        }
      }
      RealIpSource::RemoteAddr => {
        return Ok((remote_addr.ip(), remote_addr.port()));
      }
    }
  }

  // Fallback to Remote Address if no config or strategy failed.
  Ok((remote_addr.ip(), remote_addr.port()))
}

pub(crate) async fn peek_xff_ip<T: AsyncRead + Unpin>(
  stream: &mut T,
  buffer: &mut BytesMut,
  _trust_depth: usize,
) -> io::Result<Option<IpAddr>> {
  let max_header = 4096;
  loop {
    if let Some(pos) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
      let header_bytes = &buffer[..pos + 4];
      let mut headers = [httparse::Header {
        name: "",
        value: &[],
      }; 32];
      let mut req = httparse::Request::new(&mut headers);
      if req.parse(header_bytes).is_ok() {
        for header in req.headers {
          if header.name.eq_ignore_ascii_case("x-forwarded-for") {
            if let Ok(val) = std::str::from_utf8(header.value) {
              let ips: Vec<&str> = val.split(',').map(|s| s.trim()).collect();
              if let Some(ip_str) = ips.last() {
                if let Ok(ip) = ip_str.parse() {
                  return Ok(Some(ip));
                }
              }
            }
          }
        }
      }
      return Ok(None);
    }

    if buffer.len() >= max_header {
      return Ok(None);
    }

    if stream.read_buf(buffer).await? == 0 {
      return Ok(None);
    }
  }
}
