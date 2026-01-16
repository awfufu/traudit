use crate::config::{Config, ServiceConfig};
use crate::core::forwarder;
use crate::core::upstream::UpstreamStream;
use crate::db::clickhouse::ClickHouseLogger;
use crate::protocol;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::signal;
use tracing::{error, info};

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

    // Only support TCP service type for now, as per user instructions implied context
    if service.service_type != "tcp" {
      info!("skipping non-tcp service: {}", service.name);
      continue;
    }

    for bind in &service.binds {
      let service_config = service.clone();
      let bind_addr = bind.addr.clone();
      // proxy is now Option<String>
      let proxy_proto_config = bind.proxy.clone();
      let mode = bind.mode;

      if bind_addr.starts_with("unix://") {
        let path = bind_addr.trim_start_matches("unix://");

        // bind_robust handles cleanup, existing file checks, and permission checks
        let (listener, guard) = bind_robust(path, mode, &service_config.name).await?;

        // Push guard to keep it alive until shutdown
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
        // BindType is removed, assume TCP bind for "tcp" service
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

  // socket_guards are dropped here, cleaning up files
  Ok(())
}

struct UnixSocketGuard {
  path: std::path::PathBuf,
}

impl Drop for UnixSocketGuard {
  fn drop(&mut self) {
    if let Err(e) = std::fs::remove_file(&self.path) {
      // It's possible the file is already gone or we lost permissions, just log debug.
      tracing::debug!("failed to remove socket file {:?}: {}", self.path, e);
    } else {
      tracing::debug!("removed socket file {:?}", self.path);
    }
  }
}

async fn bind_robust(
  path: &str,
  mode: u32,
  service_name: &str,
) -> anyhow::Result<(UnixListener, UnixSocketGuard)> {
  let path_buf = std::path::Path::new(path).to_path_buf();

  if path_buf.exists() {
    // Check permissions first: if we cannot write to it, we certainly cannot remove it.
    // metadata() follows symlinks, symlink_metadata() does not. Unix sockets are regular files-ish.
    match std::fs::symlink_metadata(&path_buf) {
      Ok(_meta) => {
        // We rely on subsequent operations (connect/remove) to fail with PermissionDenied if we lack access.
      }
      Err(e) => {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
          anyhow::bail!("Permission denied accessing existing socket: {}", path);
        }
      }
    }

    // Try to connect to check if it's active
    match UnixStream::connect(&path_buf).await {
      Ok(_) => {
        // Active!
        anyhow::bail!("Address already in use: {}", path);
      }
      Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
        // Stale! Remove it.
        info!("[{}] removing stale socket file: {}", service_name, path);
        if let Err(rm_err) = std::fs::remove_file(&path_buf) {
          anyhow::bail!("failed to remove stale socket {}: {}", path, rm_err);
        }
      }
      Err(e) => {
        // Other error (e.g. Permission Denied during connect?), bail
        anyhow::bail!("failed to check existing socket {}: {}", path, e);
      }
    }
  }

  // Now bind
  let listener = UnixListener::bind(&path_buf).map_err(|e| {
    error!("[{}] failed to bind {}: {}", service_name, path, e);
    e
  })?;

  // Set permissions
  use std::os::unix::fs::PermissionsExt;
  if let Ok(metadata) = std::fs::metadata(&path_buf) {
    let mut permissions = metadata.permissions();
    // Verify if we need to change it
    if permissions.mode() & 0o777 != mode & 0o777 {
      permissions.set_mode(mode);
      if let Err(e) = std::fs::set_permissions(&path_buf, permissions) {
        // This is not fatal but worth error log
        error!(
          "[{}] failed to set permissions on {}: {}",
          service_name, path, e
        );
      }
    }
  }

  Ok((listener, UnixSocketGuard { path: path_buf }))
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
        // For other startup errors, we might want to warn or just debug, but let's stick to user request for WARNING
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

async fn handle_connection(
  mut inbound: InboundStream,
  service: ServiceConfig,
  proxy_cfg: Option<String>,
  db: Arc<ClickHouseLogger>,
  listen_addr: String,
) -> std::io::Result<u64> {
  let conn_ts = time::OffsetDateTime::now_utc();
  let start_instant = std::time::Instant::now();

  // Default metadata
  // We use this flag to help decide addr_family logic later, or infer from inbound type
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
            // INFO [ssh] unix://./test.sock <- 192.168.1.1:12345 (unix_socket)
            // Or INFO [ssh] 0.0.0.0:2222 <- 1.2.3.4:5678 (1.2.3.4:5678)
            info!(
              "[{}] {} <- {} ({})",
              service.name, listen_addr, info.source, physical
            );
            final_ip = info.source.ip();
            final_port = info.source.port();

            // Note: If we get proxy info, it's effectively "proxied TCP" usually.
            // So we rely on the IP address family of final_ip later.

            proto_enum = match info.version {
              protocol::Version::V1 => crate::db::clickhouse::ProxyProto::V1,
              protocol::Version::V2 => crate::db::clickhouse::ProxyProto::V2,
            };

            // Optional: verify version matches config if strictly required
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
            // Strict enforcement: if configured with proxy_protocol, MUST have a header
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
        // If Unix socket without proxy, display 127.0.0.1:0 as per logic or ...
        // User requested: unix://... <- 127.0.0.1:port
        // But inbound.peer_addr_string() for unix is "unix_socket"
        // And we set final_ip to 127.0.0.1, final_port to 0
        format!("{}:{}", final_ip, final_port)
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
      // Clean close logging removed as per request
      // info!("[{}] connection closed cleanly", service.name);
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

  // Finalize AddrFamily based on final_ip
  // But if it was originally Unix AND no proxy info changed the IP (so it's still 127.0.0.1?)
  // Wait, if Unix without proxy, final_ip IS 127.0.0.1.
  // We want AddrFamily::Unix (1) for proper unix socket.
  // If Unix WITH proxy, final_ip is Real IP -> AddrFamily::Ipv4/6.

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

enum InboundStream {
  Tcp(TcpStream),
  Unix(UnixStream),
}

impl InboundStream {
  fn peer_addr_string(&self) -> std::io::Result<String> {
    match self {
      InboundStream::Tcp(s) => Ok(s.peer_addr()?.to_string()),
      InboundStream::Unix(_) => Ok("unix_socket".to_string()),
    }
  }
}

impl AsyncRead for InboundStream {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<std::io::Result<()>> {
    match self.get_mut() {
      InboundStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
      InboundStream::Unix(s) => Pin::new(s).poll_read(cx, buf),
    }
  }
}

impl AsyncWrite for InboundStream {
  fn poll_write(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<Result<usize, std::io::Error>> {
    match self.get_mut() {
      InboundStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
      InboundStream::Unix(s) => Pin::new(s).poll_write(cx, buf),
    }
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
    match self.get_mut() {
      InboundStream::Tcp(s) => Pin::new(s).poll_flush(cx),
      InboundStream::Unix(s) => Pin::new(s).poll_flush(cx),
    }
  }

  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
    match self.get_mut() {
      InboundStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
      InboundStream::Unix(s) => Pin::new(s).poll_shutdown(cx),
    }
  }
}
