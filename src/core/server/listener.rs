use crate::config::ServiceConfig;
use crate::core::server::pingora_compat::{PingoraStream, PingoraTlsStream, UnifiedPingoraStream};
use crate::core::server::stream::InboundStream;
use bytes::BytesMut;
use openssl::ssl::{Ssl, SslAcceptor};
use pingora::protocols::l4::socket::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio_openssl::SslStream;
use tracing::{error, info, warn};

fn normalize_ipv4_mapped_addr(addr: std::net::SocketAddr) -> std::net::SocketAddr {
  match addr {
    std::net::SocketAddr::V6(v6) => {
      if let Some(v4) = v6.ip().to_ipv4_mapped() {
        std::net::SocketAddr::new(std::net::IpAddr::V4(v4), v6.port())
      } else {
        std::net::SocketAddr::V6(v6)
      }
    }
    other => other,
  }
}

fn parse_tcp_bind_target(addr_str: &str) -> anyhow::Result<(std::net::SocketAddr, Option<bool>)> {
  let (normalized_addr, force_v6_only) = if let Some(port) = addr_str.strip_prefix(":::") {
    (format!("[::]:{}", port), Some(true))
  } else if let Some(port) = addr_str.strip_prefix(":") {
    (format!("[::]:{}", port), Some(false))
  } else if let Some(port) = addr_str.strip_prefix("*:") {
    (format!("[::]:{}", port), Some(false))
  } else {
    (addr_str.to_string(), None)
  };

  let addr: std::net::SocketAddr = normalized_addr.parse()?;
  Ok((addr, force_v6_only))
}

pub enum UnifiedListener {
  Tcp(TcpListener),
  Unix(UnixListener, PathBuf), // PathBuf for cleanup on Drop
}

impl Drop for UnifiedListener {
  fn drop(&mut self) {
    if let UnifiedListener::Unix(_, ref path) = self {
      let _ = std::fs::remove_file(path);
      tracing::debug!("removed socket file {:?}", path);
    }
  }
}

impl UnifiedListener {
  pub async fn accept(&self) -> std::io::Result<(InboundStream, std::net::SocketAddr)> {
    match self {
      UnifiedListener::Tcp(l) => {
        let (stream, addr) = l.accept().await?;
        Ok((InboundStream::Tcp(stream), normalize_ipv4_mapped_addr(addr)))
      }
      UnifiedListener::Unix(l, _) => {
        let (stream, _addr) = l.accept().await?;
        // Mock IPv4 loopback for Unix sockets
        let addr = std::net::SocketAddr::new(
          std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
          0,
        );
        Ok((InboundStream::Unix(stream), addr))
      }
    }
  }
}

// Global registry for FDs to be passed during reload
pub static FD_REGISTRY: std::sync::OnceLock<
  std::sync::Mutex<std::collections::HashMap<String, std::os::unix::io::RawFd>>,
> = std::sync::OnceLock::new();

pub fn get_fd_registry(
) -> &'static std::sync::Mutex<std::collections::HashMap<String, std::os::unix::io::RawFd>> {
  FD_REGISTRY.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

pub async fn bind_listener(
  addr_str: &str,
  mode: u32,
  service_name: &str,
) -> anyhow::Result<UnifiedListener> {
  use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

  // Check if we inherited an FD for this service
  let inherited_fds_json = std::env::var("TRAUDIT_INHERITED_FDS").ok();
  let mut inherited_fd: Option<RawFd> = None;

  if let Some(json) = inherited_fds_json {
    let map: std::collections::HashMap<String, RawFd> =
      serde_json::from_str(&json).unwrap_or_default();
    if let Some(&fd) = map.get(service_name) {
      info!("[{}] inherited fd: {}", service_name, fd);
      inherited_fd = Some(fd);
    }
  }

  let listener = if let Some(fd) = inherited_fd {
    // Determine type based on address string prefix
    if addr_str.starts_with("unix://") {
      let l = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
      // We must set it non-blocking as tokio expects
      l.set_nonblocking(true)?;
      let l = UnixListener::from_std(l)?;
      let path = std::path::PathBuf::from(addr_str.trim_start_matches("unix://"));
      UnifiedListener::Unix(l, path)
    } else {
      let l = unsafe { std::net::TcpListener::from_raw_fd(fd) };
      l.set_nonblocking(true)?;
      let l = TcpListener::from_std(l)?;
      UnifiedListener::Tcp(l)
    }
  } else if let Some(path) = addr_str.strip_prefix("unix://") {
    // Robust bind logic adapted from previous implementation
    let path_buf = std::path::Path::new(path).to_path_buf();

    if path_buf.exists() {
      // Check permissions
      if let Err(e) = std::fs::symlink_metadata(&path_buf) {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
          anyhow::bail!("Permission denied accessing existing socket: {}", path);
        }
      }

      // Check if active
      match UnixStream::connect(&path_buf).await {
        Ok(_) => anyhow::bail!("Address already in use: {}", path),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
          info!("[{}] removing stale socket file: {}", service_name, path);
          std::fs::remove_file(&path_buf)?;
        }
        Err(e) => anyhow::bail!("failed to check existing socket {}: {}", path, e),
      }
    }

    let listener = UnixListener::bind(&path_buf).map_err(|e| {
      error!("[{}] failed to bind {}: {}", service_name, path, e);
      e
    })?;

    // Permissions
    if let Ok(metadata) = std::fs::metadata(&path_buf) {
      let mut perms = metadata.permissions();
      if perms.mode() & 0o777 != mode & 0o777 {
        perms.set_mode(mode);
        if let Err(e) = std::fs::set_permissions(&path_buf, perms) {
          error!(
            "[{}] failed to set permissions on {}: {}",
            service_name, path, e
          );
        }
      }
    }

    UnifiedListener::Unix(listener, path_buf)
  } else {
    // TCP with SO_REUSEPORT
    use nix::sys::socket::{setsockopt, sockopt};
    // AsRawFd removed

    let (addr, force_v6_only) = parse_tcp_bind_target(addr_str).map_err(|e| {
      error!("[{}] invalid address {}: {}", service_name, addr_str, e);
      e
    })?;

    let domain = if addr.is_ipv4() {
      socket2::Domain::IPV4
    } else {
      socket2::Domain::IPV6
    };

    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, None).map_err(|e| {
      error!("[{}] failed to create socket: {}", service_name, e);
      e
    })?;

    #[cfg(unix)]
    {
      if let Err(e) = setsockopt(&socket, sockopt::ReusePort, &true) {
        warn!("[{}] failed to set SO_REUSEPORT: {}", service_name, e);
      }
      if let Err(e) = setsockopt(&socket, sockopt::ReuseAddr, &true) {
        warn!("[{}] failed to set SO_REUSEADDR: {}", service_name, e);
      }
    }

    if addr.is_ipv6() {
      if let Some(v6_only) = force_v6_only {
        socket.set_only_v6(v6_only).map_err(|e| {
          error!(
            "[{}] failed to configure IPV6_V6ONLY={} for {}: {}",
            service_name, v6_only, addr_str, e
          );
          e
        })?;
      }
    }

    socket.set_nonblocking(true)?;

    // Convert std::net::SocketAddr to socket2::SockAddr
    let sock_addr = socket2::SockAddr::from(addr);

    socket.bind(&sock_addr).map_err(|e| {
      error!("[{}] failed to bind {}: {}", service_name, addr_str, e);
      e
    })?;

    socket.listen(1024).map_err(|e| {
      error!("[{}] failed to listen {}: {}", service_name, addr_str, e);
      e
    })?;

    let std_listener: std::net::TcpListener = socket.into();
    let listener = TcpListener::from_std(std_listener).map_err(|e| {
      error!(
        "[{}] failed to convert to tokio listener: {}",
        service_name, e
      );
      e
    })?;

    UnifiedListener::Tcp(listener)
  };

  // Register duplicated FD for reload to pass to the next process.
  let raw_fd = match &listener {
    UnifiedListener::Tcp(l) => l.as_raw_fd(),
    UnifiedListener::Unix(l, _) => l.as_raw_fd(),
  };

  // Use libc for dup to avoid nix version issues
  let dup_fd = unsafe { libc::dup(raw_fd) };
  if dup_fd < 0 {
    let err = std::io::Error::last_os_error();
    error!("failed to dup fd: {}", err);
    return Err(anyhow::anyhow!(err));
  }

  // Set CLOEXEC on the dup_fd
  let flags = unsafe { libc::fcntl(dup_fd, libc::F_GETFD) };
  if flags < 0 {
    let _ = unsafe { libc::close(dup_fd) };
    return Err(anyhow::anyhow!(std::io::Error::last_os_error()));
  }

  if unsafe { libc::fcntl(dup_fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
    let _ = unsafe { libc::close(dup_fd) };
    return Err(anyhow::anyhow!(std::io::Error::last_os_error()));
  }

  get_fd_registry()
    .lock()
    .unwrap()
    .insert(service_name.to_string(), dup_fd);

  Ok(listener)
}

#[cfg(test)]
mod tests {
  use super::{normalize_ipv4_mapped_addr, parse_tcp_bind_target};
  use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

  #[test]
  fn test_parse_tcp_bind_target_rules() {
    let (a, v6_only) = parse_tcp_bind_target("0.0.0.0:80").unwrap();
    assert_eq!(a, "0.0.0.0:80".parse::<SocketAddr>().unwrap());
    assert_eq!(v6_only, None);

    let (a, v6_only) = parse_tcp_bind_target(":::80").unwrap();
    assert_eq!(a, "[::]:80".parse::<SocketAddr>().unwrap());
    assert_eq!(v6_only, Some(true));

    let (a, v6_only) = parse_tcp_bind_target(":80").unwrap();
    assert_eq!(a, "[::]:80".parse::<SocketAddr>().unwrap());
    assert_eq!(v6_only, Some(false));

    let (a, v6_only) = parse_tcp_bind_target("*:80").unwrap();
    assert_eq!(a, "[::]:80".parse::<SocketAddr>().unwrap());
    assert_eq!(v6_only, Some(false));
  }

  #[test]
  fn test_normalize_ipv4_mapped_addr() {
    let mapped = SocketAddr::new(
      IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xFFFF, 0xC000, 0x0280)),
      8080,
    );
    let normalized = normalize_ipv4_mapped_addr(mapped);
    assert_eq!(normalized, SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 128)), 8080));

    let normal_v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080);
    assert_eq!(normalize_ipv4_mapped_addr(normal_v6), normal_v6);
  }
}

pub async fn serve_listener_loop<F, Fut>(
  listener: UnifiedListener,
  service: ServiceConfig,
  real_ip_config: Option<crate::config::RealIpConfig>,
  proxy_cfg: Option<String>,
  tls_acceptor: Option<Arc<SslAcceptor>>,
  mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
  handler: F,
) where
  F: Fn(UnifiedPingoraStream, Option<crate::protocol::ProxyInfo>, std::net::SocketAddr) -> Fut
    + Send
    + Sync
    + 'static
    + Clone,
  Fut: std::future::Future<Output = ()> + Send,
{
  use std::sync::atomic::{AtomicUsize, Ordering};

  // Track active connections
  let active_connections = Arc::new(AtomicUsize::new(0));
  let notify_shutdown = Arc::new(tokio::sync::Notify::new());

  loop {
    tokio::select! {
      _ = shutdown_rx.recv() => {
        info!("[{}] shutdown signal received, stopping acceptance", service.name);
        break;
      }
      accept_res = listener.accept() => {
        match accept_res {
          Ok((mut stream, client_addr)) => {
            let proxy_cfg = proxy_cfg.clone();
            let service = service.clone();
            let real_ip_config = real_ip_config.clone();
            let handler = handler.clone();
            let tls_acceptor = tls_acceptor.clone();

            // Increment counter
            active_connections.fetch_add(1, Ordering::SeqCst);
            let active_connections = active_connections.clone();
            let notify_shutdown = notify_shutdown.clone();

            tokio::spawn(async move {
              // Ensure we decrement on drop
              struct ConnectionGuard {
                counter: Arc<AtomicUsize>,
                notify: Arc<tokio::sync::Notify>,
              }
              impl Drop for ConnectionGuard {
                fn drop(&mut self) {
                  let prev = self.counter.fetch_sub(1, Ordering::SeqCst);
                  if prev == 1 {
                    self.notify.notify_waiters();
                  }
                }
              }
              let _guard = ConnectionGuard {
                counter: active_connections,
                notify: notify_shutdown,
              };

              let mut buffer = BytesMut::new();
              let mut proxy_info = None;

              // 1. Read PROXY header
              if proxy_cfg.is_some() {
                match crate::protocol::read_proxy_header(&mut stream).await {
                  Ok((info, buf)) => {
                    buffer = buf;
                    if let Some(info) = info {
                      // Validate version
                      let valid = match proxy_cfg.as_deref() {
                        Some("v1") => info.version == crate::protocol::Version::V1,
                        Some("v2") => info.version == crate::protocol::Version::V2,
                        _ => true,
                      };
                      if !valid {
                        warn!("[{}] proxy protocol version mismatch", service.name);
                      }
                      proxy_info = Some(info);
                    } else {
                      let msg = format!("strict proxy protocol violation from {}", client_addr);
                      error!("[{}] {}", service.name, msg);
                      return; // Close connection
                    }
                  }
                  Err(e) => {
                    error!("failed to read proxy header: {}", e);
                    return;
                  }
                }
              }

              // 2. Resolve Real IP (consumes stream/buffer for XFF peeking if needed).
              // [FIX] If TLS is enabled, we CANNOT peek for XFF headers on the raw stream because it's encrypted.
              // In that case, we skip XFF resolution here and let the proxy application (Pingora) handle it
              // after decryption (though Pingora might need its own config for that).
              // For now, avoiding the deadlock is priority.
              let perform_xff = if tls_acceptor.is_some() {
                 if let Some(ref cfg) = real_ip_config {
                    // If source is Xff, we must skip.
                    // If source is ProxyProtocol, we can still do it (already done via proxy_info above).
                    cfg.source != crate::config::RealIpSource::Xff
                 } else {
                    true
                 }
              } else {
                 true
              };

              let (real_peer_ip, real_peer_port) = if perform_xff {
                  match crate::core::server::handler::resolve_real_ip(
                    &real_ip_config,
                    client_addr,
                    &proxy_info,
                    &mut stream,
                    &mut buffer,
                  )
                  .await
                  {
                    Ok((ip, port)) => (ip, port),
                    Err(e) => {
                      error!("[{}] real ip resolution failed: {}", service.name, e);
                      return;
                    }
                  }
              } else {
                 // Fallback to what we know (Proxy Protocol or Physical)
                 if let Some(info) = &proxy_info {
                   (info.source.ip(), info.source.port())
                 } else {
                   (client_addr.ip(), client_addr.port())
                 }
              };

              let local_addr = match &stream {
                InboundStream::Tcp(s) => s.local_addr().ok(),
                _ => None,
              }
              .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());

              // 3. Construct base PingoraStream
              let stream = PingoraStream::new(
                stream,
                buffer,
                match SocketAddr::from(std::net::SocketAddr::new(real_peer_ip, real_peer_port)) {
                  SocketAddr::Inet(addr) => addr,
                  _ => unreachable!(),
                },
                match SocketAddr::from(local_addr) {
                  SocketAddr::Inet(addr) => addr,
                  _ => unreachable!(),
                },
              );

              // 4. TLS Handshake if configured
              let stream: UnifiedPingoraStream = if let Some(acceptor) = tls_acceptor {
                match Ssl::new(acceptor.context()) {
                  Ok(ssl) => match SslStream::new(ssl, stream) {
                    Ok(mut ssl_stream) => match std::pin::Pin::new(&mut ssl_stream).accept().await {
                      Ok(_) => UnifiedPingoraStream::Tls(PingoraTlsStream::new(ssl_stream)),
                      Err(e) => {
                        error!("[{}] tls handshake failed: {}", service.name, e);
                        return;
                      }
                    },
                    Err(e) => {
                      error!("[{}] failed to create ssl stream: {}", service.name, e);
                      return;
                    }
                  },
                  Err(e) => {
                    error!("[{}] failed to create ssl object: {}", service.name, e);
                    return;
                  }
                }
              } else {
                UnifiedPingoraStream::Plain(stream)
              };

              // 5. Handler
              handler(stream, proxy_info, client_addr).await;
            });
          }
          Err(e) => {
            error!("accept error: {}", e);
          }
        }
      }
    }
  }

  // Graceful shutdown: wait for active connections
  drop(listener); // Close socket immediately

  if active_connections.load(Ordering::SeqCst) > 0 {
    info!(
      "[{}] waiting for {} active connections...",
      service.name,
      active_connections.load(Ordering::SeqCst)
    );
    notify_shutdown.notified().await;
  }
  info!("[{}] shutdown complete", service.name);
}
