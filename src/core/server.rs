use crate::config::{BindType, Config, ServiceConfig};
use crate::core::forwarder;
use crate::core::upstream::UpstreamStream;
use crate::db::clickhouse::ClickHouseLogger;
use crate::protocol;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::signal;
use tracing::{error, info, instrument};

pub async fn run(config: Config) -> anyhow::Result<()> {
  let db = Arc::new(ClickHouseLogger::new(&config.database));

  let mut join_set = tokio::task::JoinSet::new();

  for service in config.services {
    let db = db.clone();
    for bind in &service.binds {
      let service_config = service.clone(); // Clone for the task
      let bind_addr = bind.addr.clone();
      let proxy_protocol = bind.proxy_protocol.is_some();
      let bind_type = bind.bind_type;

      if bind_type == BindType::Tcp {
        join_set.spawn(start_tcp_service(
          service_config,
          bind_addr,
          proxy_protocol,
          db.clone(),
        ));
      } else {
        info!("Skipping non-TCP bind for now: {:?}", bind_type);
      }
    }
  }

  info!("Traudit started.");

  match signal::ctrl_c().await {
    Ok(()) => {
      info!("Shutdown signal received.");
    }
    Err(err) => {
      error!("Unable to listen for shutdown signal: {}", err);
    }
  }

  join_set.shutdown().await;

  Ok(())
}

async fn start_tcp_service(
  service: ServiceConfig,
  addr: String,
  proxy_protocol: bool,
  _db: Arc<ClickHouseLogger>,
) {
  info!("Service {} listening on TCP {}", service.name, addr);
  let listener = match TcpListener::bind(&addr).await {
    Ok(l) => l,
    Err(e) => {
      error!("Failed to bind {}: {}", addr, e);
      return;
    }
  };

  loop {
    match listener.accept().await {
      Ok((mut inbound, client_addr)) => {
        info!("New connection from {}", client_addr);
        let service = service.clone();
        // let db = _db.clone();

        tokio::spawn(async move {
          if let Err(e) = handle_connection(inbound, service, proxy_protocol).await {
            error!("Connection error: {}", e);
          }
        });
      }
      Err(e) => {
        error!("Accept error: {}", e);
      }
    }
  }
}

#[instrument(skip(inbound, service), fields(service = %service.name))]
async fn handle_connection(
  mut inbound: tokio::net::TcpStream,
  service: ServiceConfig,
  proxy_protocol: bool,
) -> std::io::Result<()> {
  // 1. Read Proxy Protocol (if configured)
  let mut buffer = if proxy_protocol {
    let (_proxy_info, buffer) = protocol::read_proxy_header(&mut inbound).await?;
    buffer
  } else {
    bytes::BytesMut::new()
  };

  // 2. Connect Upstream
  let mut upstream = UpstreamStream::connect(service.forward_type, &service.forward_addr).await?;

  // 3. Forward Header (TODO: if configured)

  // 4. Write buffered data (peeked bytes)
  if !buffer.is_empty() {
    upstream.write_all_buf(&mut buffer).await?;
  }

  // 5. Zero-copy forwarding
  let inbound_async = crate::core::upstream::AsyncStream::from_tokio_tcp(inbound)?;
  let upstream_async = upstream.into_async_stream()?;

  forwarder::zero_copy_bidirectional(inbound_async, upstream_async).await?;

  Ok(())
}
