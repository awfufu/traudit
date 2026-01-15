use crate::config::{BindType, Config, ServiceConfig};
use crate::core::forwarder;
use crate::core::upstream::UpstreamStream;
use crate::db::clickhouse::ClickHouseLogger;
use crate::protocol;
use monoio::net::TcpListener;
use std::sync::Arc;
use tracing::{error, info};

pub async fn run(config: Config) -> anyhow::Result<()> {
  let db = Arc::new(ClickHouseLogger::new(&config.database));

  let mut handles = Vec::new();

  for service in config.services {
    let db = db.clone();
    for bind in &service.binds {
      let service_config = service.clone();
      let bind_addr = bind.addr.clone();
      let proxy_protocol = bind.proxy_protocol.is_some();
      let bind_type = bind.bind_type;

      if bind_type == BindType::Tcp {
        let listener = TcpListener::bind(&bind_addr).map_err(|e| {
          error!(
            "[{}] failed to bind {}: {}",
            service_config.name, bind_addr, e
          );
          e
        })?;

        info!("[{}] listening on tcp {}", service_config.name, bind_addr);

        handles.push(monoio::spawn(start_tcp_service(
          service_config,
          listener,
          proxy_protocol,
          db.clone(),
        )));
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

  // Monoio doesn't have a signal::ctrl_c helper built-in effectively like tokio's
  // But we can just wait on the handles or use a simple waiting mechanism.
  // For now, we await the services. Since they loop forever, this runs forever.
  // TODO: Implement signal handling for graceful shutdown if needed.
  for h in handles {
    let _ = h.await;
  }

  Ok(())
}

async fn start_tcp_service(
  service: ServiceConfig,
  listener: TcpListener,
  proxy_protocol: bool,
  _db: Arc<ClickHouseLogger>,
) {
  loop {
    match listener.accept().await {
      Ok((inbound, _client_addr)) => {
        let service = service.clone();
        monoio::spawn(async move {
          if let Err(e) = handle_connection(inbound, service, proxy_protocol).await {
            match e.kind() {
              std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe => {
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
  mut inbound: monoio::net::TcpStream,
  service: ServiceConfig,
  proxy_protocol: bool,
) -> std::io::Result<()> {
  // read proxy protocol (if configured)
  let (_client_addr, buffer) = if proxy_protocol {
    let (proxy_info, buffer) = protocol::read_proxy_header(&mut inbound).await?;
    if let Some(info) = proxy_info {
      let physical = inbound.peer_addr()?;
      info!("[{}] <- {} ({})", service.name, info.source, physical);
      (info.source, buffer)
    } else {
      let addr = inbound.peer_addr()?;
      info!("[{}] <- {}", service.name, addr);
      (addr, buffer)
    }
  } else {
    let addr = inbound.peer_addr()?;
    info!("[{}] <- {}", service.name, addr);
    (addr, bytes::BytesMut::new())
  };

  // connect upstream
  let mut upstream = UpstreamStream::connect(service.forward_type, &service.forward_addr).await?;

  // write buffered data (peeked bytes)
  if !buffer.is_empty() {
    // UpstreamStream needs to support writing bytes directly
    // logic needs update in upstream.rs
    upstream.write_all(buffer).await.0?;
  }

  // zero-copy forwarding
  // Monoio's TcpStream is already compatible with splice if we access the fd,
  // but better to pass the stream itself to forwarder.

  forwarder::zero_copy_bidirectional(inbound, upstream).await?;

  Ok(())
}
