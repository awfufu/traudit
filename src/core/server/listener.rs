use crate::config::ServiceConfig;
use crate::core::server::pingora_compat::{PingoraStream, PingoraTlsStream, UnifiedPingoraStream};
use crate::core::server::stream::InboundStream;
use bytes::BytesMut;
use openssl::ssl::{Ssl, SslAcceptor};
use pingora::protocols::l4::socket::SocketAddr;
use pingora::server::ShutdownWatch;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio_openssl::SslStream;
use tracing::{error, info, warn};

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
        Ok((InboundStream::Tcp(stream), addr))
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

pub async fn bind_listener(
  addr_str: &str,
  mode: u32,
  service_name: &str,
) -> anyhow::Result<UnifiedListener> {
  if let Some(path) = addr_str.strip_prefix("unix://") {
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

    Ok(UnifiedListener::Unix(listener, path_buf))
  } else {
    // TCP
    let listener = TcpListener::bind(addr_str).await.map_err(|e| {
      error!("[{}] failed to bind {}: {}", service_name, addr_str, e);
      e
    })?;
    Ok(UnifiedListener::Tcp(listener))
  }
}

pub async fn serve_listener_loop<F, Fut>(
  listener: UnifiedListener,
  service: ServiceConfig,
  real_ip_config: Option<crate::config::RealIpConfig>,
  proxy_cfg: Option<String>,
  tls_acceptor: Option<Arc<SslAcceptor>>,
  _shutdown: ShutdownWatch,
  handler: F,
) where
  F: Fn(UnifiedPingoraStream, Option<crate::protocol::ProxyInfo>, std::net::SocketAddr) -> Fut
    + Send
    + Sync
    + 'static
    + Clone,
  Fut: std::future::Future<Output = ()> + Send,
{
  loop {
    match listener.accept().await {
      Ok((mut stream, client_addr)) => {
        let proxy_cfg = proxy_cfg.clone();
        let service = service.clone();
        let real_ip_config = real_ip_config.clone();
        let handler = handler.clone();
        let tls_acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
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

          let (real_peer_ip, real_peer_port) = match crate::core::server::handler::resolve_real_ip(
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
              // Fallback or abort?
              // Abort is safer if I/O broken.
              return;
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
