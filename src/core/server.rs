use crate::config::{BindType, Config};
use crate::db::clickhouse::ClickHouseLogger;
use crate::db::AuditLogger;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;
use tracing::{error, info};

pub async fn run(config: Config) -> anyhow::Result<()> {
  let db = Arc::new(ClickHouseLogger::new(&config.database));

  let mut join_set = tokio::task::JoinSet::new();

  for service in config.services {
    let db = db.clone();
    for bind in service.binds {
      let service_name = service.name.clone();
      let bind_addr = bind.addr.clone();
      let bind_type = bind.bind_type;

      // TODO: Handle UDP and Unix
      if bind_type == BindType::Tcp {
        let db = db.clone();
        join_set.spawn(start_tcp_service(service_name, bind_addr, db));
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

  // Abort all tasks
  join_set.shutdown().await;

  Ok(())
}

async fn start_tcp_service(name: String, addr: String, _db: Arc<ClickHouseLogger>) {
  info!("Service {} listening on TCP {}", name, addr);
  let listener = match TcpListener::bind(&addr).await {
    Ok(l) => l,
    Err(e) => {
      error!("Failed to bind {}: {}", addr, e);
      return;
    }
  };

  loop {
    match listener.accept().await {
      Ok((_socket, client_addr)) => {
        info!("New connection from {}", client_addr);
        // Spawn handler
        // tokio::spawn(handle_connection(_socket, ...));
      }
      Err(e) => {
        error!("Accept error: {}", e);
      }
    }
  }
}
