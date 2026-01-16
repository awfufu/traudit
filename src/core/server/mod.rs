use crate::config::{Config, ServiceConfig};
use crate::core::upstream::UpstreamStream;
use crate::db::clickhouse::ClickHouseLogger;
use std::sync::Arc;
use tokio::net::{TcpListener, UnixListener};
use tokio::signal;
use tracing::{error, info};

mod handler;
mod listener;
mod stream;

use self::handler::handle_connection;
use self::listener::bind_robust;
use self::stream::InboundStream;

pub async fn run(config: Config) -> anyhow::Result<()> {
  let db_logger = ClickHouseLogger::new(&config.database).map_err(|e| {
    error!("database: {}", e);
    e
  })?;
  let db = Arc::new(db_logger);

  // init db table
  if let Err(e) = db.init().await {
    let msg = e.to_string();
    if msg.len() > 200 {
      error!("failed to init database: {}... (truncated)", &msg[..200]);
    } else {
      error!("failed to init database: {}", msg);
    }
    return Err(e);
  }

  let mut join_set = tokio::task::JoinSet::new();
  let mut socket_guards = Vec::new();

  for service in config.services {
    let db = db.clone();

    // Only support TCP, skipping others

    for bind in &service.binds {
      let service_config = service.clone();
      let bind_addr = bind.addr.clone();
      // proxy is Option<String>
      let proxy_proto_config = bind.proxy.clone();
      let mode = bind.mode;

      if bind_addr.starts_with("unix://") {
        let path = bind_addr.trim_start_matches("unix://");

        // bind_robust handles cleanup and permission checks
        let (listener, guard) = bind_robust(path, mode, &service_config.name).await?;

        // Push guard to keep it alive
        socket_guards.push(guard);

        info!(
          "[{}] listening on unix {} (mode {:o})",
          service_config.name, path, mode
        );

        join_set.spawn(start_unix_service(
          service_config,
          listener,
          proxy_proto_config,
          db.clone(),
          bind.addr.clone(),
        ));
      } else {
        // BindType removed, assume TCP bind
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
          proxy_proto_config,
          db.clone(),
          bind.addr.clone(),
        ));
      }
    }
  }

  info!("traudit started...");

  // notify systemd if configured
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

  // socket_guards dropped here, cleaning up files
  Ok(())
}

async fn start_tcp_service(
  service: ServiceConfig,
  listener: TcpListener,
  proxy_cfg: Option<String>,
  db: Arc<ClickHouseLogger>,
  listen_addr: String,
) {
  // Startup liveness check
  if let Err(e) = UpstreamStream::connect(&service.forward_to).await {
    match e.kind() {
      std::io::ErrorKind::ConnectionRefused => {
        tracing::warn!("[{}] -> '{}': {}", service.name, service.forward_to, e);
      }
      std::io::ErrorKind::NotFound => {
        tracing::warn!("[{}] -> '{}': {}", service.name, service.forward_to, e);
      }
      _ => {
        // Log other startup errors as warnings
        tracing::warn!(
          "[{}] -> '{}': startup check failed: {}",
          service.name,
          service.forward_to,
          e
        );
      }
    }
  }

  loop {
    match listener.accept().await {
      Ok((inbound, _client_addr)) => {
        let service = service.clone();
        let db = db.clone();
        let proxy_cfg = proxy_cfg.clone();
        let listen_addr = listen_addr.clone();

        tokio::spawn(async move {
          let svc_name = service.name.clone();
          let svc_target = service.forward_to.clone();
          let inbound = InboundStream::Tcp(inbound);

          if let Err(e) = handle_connection(inbound, service, proxy_cfg, db, listen_addr).await {
            match e.kind() {
              std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe => {
                // normal disconnects, debug log only
                tracing::debug!("connection closed: {}", e);
              }
              std::io::ErrorKind::ConnectionRefused => {
                tracing::warn!("[{}] -> '{}': {}", svc_name, svc_target, e);
              }
              std::io::ErrorKind::NotFound => {
                tracing::warn!("[{}] -> '{}': {}", svc_name, svc_target, e);
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

async fn start_unix_service(
  service: ServiceConfig,
  listener: UnixListener,
  proxy_cfg: Option<String>,
  db: Arc<ClickHouseLogger>,
  listen_addr: String,
) {
  // Startup liveness check (same as TCP)
  if let Err(e) = UpstreamStream::connect(&service.forward_to).await {
    match e.kind() {
      std::io::ErrorKind::ConnectionRefused => {
        tracing::warn!("[{}] -> '{}': {}", service.name, service.forward_to, e);
      }
      std::io::ErrorKind::NotFound => {
        tracing::warn!("[{}] -> '{}': {}", service.name, service.forward_to, e);
      }
      _ => {
        tracing::warn!(
          "[{}] -> '{}': startup check failed: {}",
          service.name,
          service.forward_to,
          e
        );
      }
    }
  }

  loop {
    match listener.accept().await {
      Ok((inbound, _addr)) => {
        let service = service.clone();
        let db = db.clone();
        let proxy_cfg = proxy_cfg.clone();
        let listen_addr = listen_addr.clone();

        tokio::spawn(async move {
          let svc_name = service.name.clone();
          let svc_target = service.forward_to.clone();
          let inbound = InboundStream::Unix(inbound);

          if let Err(e) = handle_connection(inbound, service, proxy_cfg, db, listen_addr).await {
            match e.kind() {
              std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe => {
                tracing::debug!("connection closed: {}", e);
              }
              std::io::ErrorKind::ConnectionRefused => {
                tracing::warn!("[{}] -> '{}': {}", svc_name, svc_target, e);
              }
              std::io::ErrorKind::NotFound => {
                tracing::warn!("[{}] -> '{}': {}", svc_name, svc_target, e);
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
