use crate::config::{BindType, Config, ServiceConfig};
use crate::core::forwarder;
use crate::core::upstream::UpstreamStream;
use crate::db::clickhouse::ClickHouseLogger;
use crate::protocol;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::signal;
use tracing::{error, info};

pub async fn run(config: Config) -> anyhow::Result<()> {
  let db = Arc::new(ClickHouseLogger::new(&config.database));

  // init db table
  if let Err(e) = db.init().await {
    error!("failed to init database: {}", e);
    return Err(e);
  }

  let mut join_set = tokio::task::JoinSet::new();

  for service in config.services {
    let db = db.clone();
    for bind in &service.binds {
      let service_config = service.clone();
      let bind_addr = bind.addr.clone();
      let proxy_protocol = bind.proxy_protocol.is_some();
      let bind_type = bind.bind_type;

      if bind_type == BindType::Tcp {
        let listener = TcpListener::bind(&bind_addr).await.map_err(|e| {
          error!(
            "[{}] failed to bind {}: {}",
            service_config.name, bind_addr, e
          );
          e
        })?;

        info!("[{}] listening on tcp {}", service_config.name, bind_addr);

        join_set.spawn(start_tcp_service(
          service_config,
          listener,
          proxy_protocol,
          db.clone(),
        ));
      } else {
        info!("skipping non-tcp bind for now: {:?}", bind_type);
      }
    }
  }

  info!("traudit started...");

  // notify systemd if NOTIFY_SOCKET is set
  if let Ok(notify_socket) = std::env::var("NOTIFY_SOCKET") {
    if let Ok(sock) = std::os::unix::net::UnixDatagram::unbound() {
      if let Err(e) = sock.send_to(b"READY=1", notify_socket) {
        error!("failed to notify systemd: {}", e);
      }
    }
  }

  match signal::ctrl_c().await {
    Ok(()) => {
      info!("shutdown signal received.");
    }
    Err(err) => {
      error!("unable to listen for shutdown signal: {}", err);
    }
  }

  join_set.shutdown().await;

  Ok(())
}

async fn start_tcp_service(
  service: ServiceConfig,
  listener: TcpListener,
  proxy_protocol: bool,
  db: Arc<ClickHouseLogger>,
) {
  loop {
    match listener.accept().await {
      Ok((inbound, _client_addr)) => {
        let service = service.clone();
        let db = db.clone();

        tokio::spawn(async move {
          if let Err(e) = handle_connection(inbound, service, proxy_protocol, db).await {
            match e.kind() {
              std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe => {
                // normal disconnects, debug log only
                tracing::debug!("connection closed: {}", e);
              }
              _ => {
                error!("connection error: {}", e);
              }
            }
          }
        });
      }
      Err(e) => {
        error!("accept error: {}", e);
      }
    }
  }
}

async fn handle_connection(
  mut inbound: tokio::net::TcpStream,
  service: ServiceConfig,
  proxy_protocol: bool,
  db: Arc<ClickHouseLogger>,
) -> std::io::Result<u64> {
  let conn_ts = time::OffsetDateTime::now_utc();
  let start_instant = std::time::Instant::now();

  // Default metadata
  let mut final_ip = inbound.peer_addr()?.ip();
  let mut final_port = inbound.peer_addr()?.port();
  let mut proto_enum = crate::db::clickhouse::ProxyProto::None;

  let result = async {
    // read proxy protocol (if configured)
    let mut buffer = bytes::BytesMut::new();

    if proxy_protocol {
      match protocol::read_proxy_header(&mut inbound).await {
        Ok((proxy_info, buf)) => {
          buffer = buf;
          if let Some(info) = proxy_info {
            let physical = inbound.peer_addr()?;
            info!("[{}] <- {} ({})", service.name, info.source, physical);
            final_ip = info.source.ip();
            final_port = info.source.port();
            proto_enum = match info.version {
              protocol::Version::V1 => crate::db::clickhouse::ProxyProto::V1,
              protocol::Version::V2 => crate::db::clickhouse::ProxyProto::V2,
            };
          } else {
            // Strict enforcement: if configured with proxy_protocol, MUST have a header
            let physical = inbound.peer_addr()?;
            let msg = format!("strict proxy protocol violation from {}", physical);
            error!("[{}] {}", service.name, msg);
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, msg));
          }
        }
        Err(e) => return Err(e),
      }
    } else {
      let addr = inbound.peer_addr()?;
      info!("[{}] <- {}", service.name, addr);
    }

    // connect upstream
    let mut upstream = UpstreamStream::connect(service.forward_type, &service.forward_addr).await?;

    // write buffered data (peeked bytes)
    if !buffer.is_empty() {
      upstream.write_all_buf(&mut buffer).await?;
    }

    // zero-copy forwarding
    let inbound_async = crate::core::upstream::AsyncStream::from_tokio_tcp(inbound)?;
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
      info!("[{}] connection closed cleanly", service.name);
    }

    // Total bytes = initial peeked/buffered payload + filtered bytes
    Ok(spliced_bytes + buffer.len() as u64)
  }
  .await;

  let duration = if result.is_ok() {
    start_instant.elapsed().as_millis() as u32
  } else {
    0
  };

  let bytes_transferred = result.as_ref().unwrap_or(&0).clone();

  let log_entry = crate::db::clickhouse::TcpLog {
    service: service.name.clone(),
    conn_ts,
    duration,
    port: final_port,
    ip: final_ip,
    proxy_proto: proto_enum,
    bytes: bytes_transferred,
  };

  tokio::spawn(async move {
    if let Err(e) = db.insert_log(log_entry).await {
      error!("failed to insert tcp log: {}", e);
    }
  });

  result
}
