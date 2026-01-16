use super::stream::InboundStream;
use crate::config::ServiceConfig;
use crate::core::forwarder;
use crate::core::upstream::UpstreamStream;
use crate::db::clickhouse::ClickHouseLogger;
use crate::protocol;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tracing::{error, info};

pub async fn handle_connection(
  mut inbound: InboundStream,
  service: ServiceConfig,
  proxy_cfg: Option<String>,
  db: Arc<ClickHouseLogger>,
  listen_addr: String,
) -> std::io::Result<u64> {
  let conn_ts = time::OffsetDateTime::now_utc();
  let start_instant = std::time::Instant::now();

  // Use this flag or inbound type to determine if it's a Unix socket
  let is_unix = matches!(inbound, InboundStream::Unix(_));

  let (mut final_ip, mut final_port) = match &inbound {
    InboundStream::Tcp(s) => {
      let addr = s.peer_addr()?;
      (addr.ip(), addr.port())
    }
    InboundStream::Unix(_) => (
      std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
      0,
    ),
  };
  let mut proto_enum = crate::db::clickhouse::ProxyProto::None;
  let mut skip_log = false;

  let result = async {
    // read proxy protocol (if configured)
    let mut buffer = bytes::BytesMut::new();

    if proxy_cfg.is_some() {
      // If configured, we attempt to read.
      match protocol::read_proxy_header(&mut inbound).await {
        Ok((proxy_info, buf)) => {
          buffer = buf;
          if let Some(info) = proxy_info {
            let physical = inbound.peer_addr_string()?;

            // Format: [ssh] unix://test.sock <- RealIP:Port (local) or [ssh] 0.0.0.0:2222 <- RealIP:Port (1.2.3.4:5678)
            let physical_fmt = if matches!(inbound, InboundStream::Unix(_)) {
              "local".to_string()
            } else {
              physical
            };

            info!(
              "[{}] {} <- {} ({})",
              service.name, listen_addr, info.source, physical_fmt
            );
            final_ip = info.source.ip();
            final_port = info.source.port();

            // Proxy info implies "proxied TCP" usually; rely on final_ip family later

            proto_enum = match info.version {
              protocol::Version::V1 => crate::db::clickhouse::ProxyProto::V1,
              protocol::Version::V2 => crate::db::clickhouse::ProxyProto::V2,
            };

            // Verify version matches config if required
            if let Some(ref required_ver) = proxy_cfg {
              match required_ver.as_str() {
                "v1" if info.version != protocol::Version::V1 => {
                  // warn mismatch?
                }
                "v2" if info.version != protocol::Version::V2 => {
                  // warn mismatch?
                }
                _ => {}
              }
            }
          } else {
            // Strict enforcement: config requires header
            let physical = inbound.peer_addr_string()?;
            let msg = format!("strict proxy protocol violation from {}", physical);
            error!("[{}] {}", service.name, msg);
            skip_log = true;
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, msg));
          }
        }
        Err(e) => {
          skip_log = true;
          return Err(e);
        }
      }
    } else {
      let addr = if matches!(inbound, InboundStream::Unix(_)) {
        // [ssh] unix://test.sock <- local
        "local".to_string()
      } else {
        inbound.peer_addr_string()?
      };
      info!("[{}] {} <- {}", service.name, listen_addr, addr);
    }

    // connect upstream
    let mut upstream = UpstreamStream::connect(&service.forward_to).await?;

    // write buffered data (peeked bytes)
    if !buffer.is_empty() {
      upstream.write_all_buf(&mut buffer).await?;
    }

    // zero-copy forwarding
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
          tracing::debug!("[{}] connection closed with error: {}", service.name, e);
        }
        _ => {
          error!("[{}] connection error: {}", service.name, e);
        }
      }
    } else {
      // Clean close logging removed
    }

    // Total bytes = initial peeked + filtered
    Ok(spliced_bytes + buffer.len() as u64)
  }
  .await;

  let duration = if result.is_ok() {
    start_instant.elapsed().as_millis() as u32
  } else {
    0
  };

  let bytes_transferred = *result.as_ref().unwrap_or(&0);

  // Finalize AddrFamily based on final_ip; Unix logic handled below

  let mut addr_family = match final_ip {
    std::net::IpAddr::V4(_) => crate::db::clickhouse::AddrFamily::Ipv4,
    std::net::IpAddr::V6(_) => crate::db::clickhouse::AddrFamily::Ipv6,
  };

  if is_unix && proto_enum == crate::db::clickhouse::ProxyProto::None {
    // Unix socket, direct connection (or no proxy header received)
    addr_family = crate::db::clickhouse::AddrFamily::Unix;
    // Store 0 (::)
    final_ip = std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED);
    final_port = 0;
  }

  let log_entry = crate::db::clickhouse::TcpLog {
    service: service.name.clone(),
    conn_ts,
    duration: duration as u32,
    addr_family,
    ip: final_ip,
    port: final_port,
    proxy_proto: proto_enum,
    bytes: bytes_transferred,
  };

  if !skip_log {
    tokio::spawn(async move {
      if let Err(e) = db.insert_log(log_entry).await {
        error!("failed to insert tcp log: {}", e);
      }
    });
  }

  result
}
