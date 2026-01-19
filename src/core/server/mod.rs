use crate::config::Config;
use crate::core::upstream::UpstreamStream;
use crate::db::clickhouse::ClickHouseLogger;
use pingora::apps::ServerApp;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Barrier};
use tokio::signal;
use tracing::{error, info};

pub mod handler;
mod listener;
mod pingora_compat;
pub mod stream;

use self::handler::handle_connection;
use self::listener::{bind_listener, serve_listener_loop, UnifiedListener};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

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

  // Pingora server initialization (TLS only or Standard HTTP)
  let mut pingora_services = Vec::new();

  for service in config.services {
    let db = db.clone();
    for bind in &service.binds {
      let service_config = service.clone();
      let bind_addr = bind.addr.clone();
      let proxy_proto_config = bind.proxy.clone();
      let mode = bind.mode;
      let real_ip_config = bind.real_ip.clone();

      // Use custom loop for TCP services or HTTP services requiring PROXY protocol parsing (not fully supported by pingora standard loop).

      let is_tcp_service = service.service_type == "tcp";
      // Use custom loop if Proxy Protocol is enabled, even if TLS is used
      let is_http_proxy = service.service_type == "http" && bind.proxy.is_some();

      let use_custom_loop = is_tcp_service || is_http_proxy;

      if !use_custom_loop {
        // Use Standard Pingora Service (For TLS, or Pure HTTP, or Unix HTTP without PROXY)
        pingora_services.push((
          service_config,
          bind.clone(),
          bind.tls.clone(),
          real_ip_config,
        ));
        continue;
      }

      // --- Custom Loop Logic ---

      let mut tls_acceptor = None;
      if let Some(tls_config) = &bind.tls {
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).map_err(|e| {
          error!("failed to create ssl acceptor: {}", e);
          anyhow::anyhow!(e)
        })?;
        let key_path = tls_config.key.as_deref().unwrap_or(&tls_config.cert);
        acceptor
          .set_private_key_file(key_path, SslFiletype::PEM)
          .map_err(|e| {
            error!("failed to load private key {}: {}", key_path, e);
            anyhow::anyhow!(e)
          })?;
        acceptor
          .set_certificate_chain_file(&tls_config.cert)
          .map_err(|e| {
            error!("failed to load cert chain {}: {}", tls_config.cert, e);
            anyhow::anyhow!(e)
          })?;
        // ALPN support matching Pingora's defaults?
        acceptor.set_alpn_protos(b"\x02h2\x08http/1.1").ok();
        tls_acceptor = Some(Arc::new(acceptor.build()));
      }

      let listener_res = bind_listener(&bind_addr, mode, &service_config.name).await;

      let listener = match listener_res {
        Ok(l) => l,
        Err(e) => {
          return Err(e);
        }
      };

      let listen_type = match &listener {
        UnifiedListener::Unix(_, _) => "unix",
        UnifiedListener::Tcp(_) => "tcp",
      };

      if is_http_proxy {
        info!(
          "[{}] listening on http {} {} (PROXY support)",
          service_config.name, listen_type, bind_addr
        );
      } else {
        info!(
          "[{}] listening on {} {}",
          service_config.name, listen_type, bind_addr
        );
      }

      let shutdown_dummy =
        pingora::server::ShutdownWatch::from(tokio::sync::watch::channel(false).1);

      if is_tcp_service {
        // --- TCP Handler (with startup check) ---
        if let Err(e) = UpstreamStream::connect(&service_config.forward_to).await {
          tracing::warn!(
            "[{}] -> '{}': startup check failed: {}",
            service_config.name,
            service_config.forward_to,
            e
          );
        }

        let db = db.clone();
        let _proxy_cfg = proxy_proto_config.clone();
        let listen_addr_log = bind_addr.clone();
        let svc_cfg = service_config.clone();

        join_set.spawn(serve_listener_loop(
          listener,
          service_config,
          real_ip_config,
          proxy_proto_config,
          tls_acceptor,
          shutdown_dummy,
          move |stream, info| {
            let db = db.clone();
            let svc = svc_cfg.clone();
            let addr = listen_addr_log.clone();
            async move {
              if let Err(e) = handle_connection(stream, info, svc, db, addr).await {
                match e.kind() {
                  std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe => {
                    tracing::debug!("connection closed: {}", e);
                  }
                  _ => error!("connection error: {}", e),
                }
              }
            }
          },
        ));
      } else {
        // --- HTTP Proxy Handler ---
        use crate::core::pingora_proxy::TrauditProxy;
        use pingora::proxy::http_proxy_service;

        let conf = Arc::new(pingora::server::configuration::ServerConf::default());
        let inner_proxy = TrauditProxy {
          db: db.clone(),
          service_config: service_config.clone(),
          listen_addr: bind_addr.clone(),
          real_ip: real_ip_config.clone(),
        };
        let mut service_obj = http_proxy_service(&conf, inner_proxy);
        let app = unsafe {
          let app_ptr = service_obj.app_logic_mut().expect("app logic missing");
          std::ptr::read(app_ptr)
        };
        std::mem::forget(service_obj);
        let app = Arc::new(app);

        join_set.spawn(serve_listener_loop(
          listener,
          service_config,
          real_ip_config,
          proxy_proto_config,
          tls_acceptor,
          shutdown_dummy.clone(),
          move |stream, _info| {
            let app = app.clone();
            let shutdown = shutdown_dummy.clone();
            async move {
              // stream is UnifiedPingoraStream
              // Coerce to Box<dyn IO> (trait object implementation check)
              app.process_new(Box::new(stream), &shutdown).await;
            }
          },
        ));
      }
    }
  }

  // Run Pingora in a separate thread if needed
  if !pingora_services.is_empty() {
    let barrier = Arc::new(Barrier::new(2));
    let barrier_clone = barrier.clone();

    std::thread::spawn(move || {
      use crate::core::pingora_proxy::TrauditProxy;
      use pingora::proxy::http_proxy_service;
      use pingora::server::configuration::Opt;
      use pingora::server::Server;

      if let Err(e) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut server = Server::new(Some(Opt::default())).unwrap();
        server.bootstrap();

        for (svc_config, bind, tls, real_ip) in pingora_services {
          let proxy = TrauditProxy {
            db: db.clone(),
            service_config: svc_config.clone(),
            listen_addr: bind.addr.clone(),
            real_ip,
          };

          let mut service = http_proxy_service(&server.configuration, proxy);

          if let Some(tls_config) = tls {
            let key_path = tls_config.key.as_deref().unwrap_or(&tls_config.cert);
            service
              .add_tls(&bind.addr, &tls_config.cert, key_path)
              .unwrap();
            info!("[{}] listening on https {}", svc_config.name, bind.addr);
          } else if bind.addr.starts_with("unix://") {
            let path = bind.addr.trim_start_matches("unix://");
            service.add_uds(path, Some(std::fs::Permissions::from_mode(bind.mode)));
            info!("[{}] listening on http unix {}", svc_config.name, path);
          } else {
            service.add_tcp(&bind.addr);
            info!("[{}] listening on http {}", svc_config.name, bind.addr);
          }

          server.add_service(service);
        }

        barrier_clone.wait();
        server.run_forever();
      })) {
        error!("pingora server panicked: {:?}", e);
      }
      error!("pingora server exited unexpectedly!");
    });

    barrier.wait();
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
  Ok(())
}
