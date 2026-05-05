mod common;

use clickhouse::Client;
use common::{get_db_client, init_env, prepare_env, wait_for_clickhouse, TcpLogCount};
use std::process::Command;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

struct ManagedClickHouse {
  id: String,
  port: u16,
  db_name: String,
}

impl ManagedClickHouse {
  fn run_command(args: &[&str]) {
    let output = Command::new("docker")
      .args(args)
      .output()
      .expect("failed to run docker command");
    if !output.status.success() {
      panic!(
        "docker command failed: {:?}\nstdout: {}\nstderr: {}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
      );
    }
  }

  fn start_new(port: u16, db_name: &str) -> Self {
    let output = Command::new("docker")
      .args([
        "run",
        "-d",
        "-p",
        &format!("127.0.0.1:{}:8123", port),
        "-e",
        &format!("CLICKHOUSE_DB={}", db_name),
        "-e",
        "CLICKHOUSE_USER=traudit",
        "-e",
        "CLICKHOUSE_PASSWORD=traudit",
        "-e",
        "CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1",
        "clickhouse/clickhouse-server:latest",
      ])
      .output()
      .expect("failed to start clickhouse container");

    if !output.status.success() {
      panic!(
        "failed to start clickhouse container\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
      );
    }

    let id = String::from_utf8(output.stdout)
      .expect("invalid docker output")
      .trim()
      .to_string();

    Self {
      id,
      port,
      db_name: db_name.to_string(),
    }
  }

  async fn start_and_wait(&self) {
    Self::run_command(&["start", &self.id]);
    wait_for_clickhouse(self.port).await;
  }

  async fn create_running(port: u16, db_name: &str) -> Self {
    let container = Self::start_new(port, db_name);
    wait_for_clickhouse(port).await;
    container
  }

  fn stop(&self) {
    Self::run_command(&["stop", &self.id]);
  }

  fn client(&self) -> Client {
    get_db_client(self.port, &self.db_name)
  }
}

impl Drop for ManagedClickHouse {
  fn drop(&mut self) {
    let _ = Command::new("docker").args(["rm", "-f", &self.id]).output();
  }
}

struct RunningServer {
  proxy_addr: String,
  startup_probe_logs: u64,
  shutdown_tx: tokio::sync::broadcast::Sender<traudit::core::server::ShutdownReason>,
  handle: JoinHandle<()>,
}

impl RunningServer {
  async fn start(db_port: u16, db_name: &str, memory_cache_max_kib: usize) -> Self {
    let res = prepare_env(
      "tcp",
      None,
      false,
      None,
      false,
      false,
      db_port,
      db_name.to_string(),
    )
    .await;

    let mut config = res.config;
    config.database.batch_size = 512;
    config.database.reconnect_backoff_initial_secs = 1;
    config.database.reconnect_backoff_multiplier = 1.0;
    config.database.reconnect_backoff_max_secs = 1;
    config.database.memory_cache_max_kib = memory_cache_max_kib;

    let proxy_addr = res.proxy_addr;
    let (shutdown_tx, _shutdown_rx) = tokio::sync::broadcast::channel(1);
    let shutdown_tx_clone = shutdown_tx.clone();

    let handle = tokio::spawn(async move {
      let _ = traudit::core::server::run(config, shutdown_tx_clone).await;
    });

    wait_for_server(&proxy_addr).await;

    Self {
      proxy_addr,
      startup_probe_logs: 1,
      shutdown_tx,
      handle,
    }
  }

  async fn send_tcp_logs(&self, count: usize) {
    for _ in 0..count {
      let mut stream = TcpStream::connect(&self.proxy_addr)
        .await
        .expect("failed to connect to traudit");
      stream.write_all(b"ping").await.expect("failed to write ping");
      let mut buf = [0u8; 4];
      stream
        .read_exact(&mut buf)
        .await
        .expect("failed to read echo");
      assert_eq!(&buf, b"ping");
    }
  }

  async fn send_tcp_logs_concurrent(&self, count: usize, concurrency: usize) {
    let mut join_set = tokio::task::JoinSet::new();
    let mut started = 0usize;
    let mut finished = 0usize;

    while finished < count {
      while started < count && join_set.len() < concurrency {
        let addr = self.proxy_addr.clone();
        join_set.spawn(async move {
          let mut stream = TcpStream::connect(&addr)
            .await
            .expect("failed to connect to traudit");
          stream.write_all(b"ping").await.expect("failed to write ping");
          let mut buf = [0u8; 4];
          stream
            .read_exact(&mut buf)
            .await
            .expect("failed to read echo");
          assert_eq!(&buf, b"ping");
        });
        started += 1;
      }

      if let Some(result) = join_set.join_next().await {
        result.expect("tcp task panicked");
        finished += 1;
      }
    }
  }

  async fn shutdown(self) {
    let _ = self
      .shutdown_tx
      .send(traudit::core::server::ShutdownReason::Terminate);
    tokio::time::sleep(Duration::from_secs(1)).await;
    self.handle.abort();
  }
}

async fn wait_for_server(addr: &str) {
  for _ in 0..40 {
    if TcpStream::connect(addr).await.is_ok() {
      return;
    }
    tokio::time::sleep(Duration::from_millis(250)).await;
  }
  panic!("traudit failed to start on {}", addr);
}

async fn wait_for_count(client: &Client, expected: u64) {
  tokio::time::sleep(Duration::from_secs(5)).await;
  for _ in 0..5 {
    let count = client
      .query("SELECT count() as count FROM tcp_log WHERE service = 'test-svc'")
      .fetch_one::<TcpLogCount>()
      .await
      .expect("failed to query tcp_log count");
    if count.count == expected {
      return;
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
  }

  let count = client
    .query("SELECT count() as count FROM tcp_log WHERE service = 'test-svc'")
    .fetch_one::<TcpLogCount>()
    .await
    .expect("failed to query final tcp_log count");
  assert_eq!(count.count, expected);
}

async fn reserve_free_port() -> u16 {
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("failed to bind temp port");
  listener
    .local_addr()
    .expect("failed to read temp port")
    .port()
}

#[tokio::test]
async fn test_replay_logs_after_database_starts() {
  init_env();

  let db_port = reserve_free_port().await;
  let db_name = format!("replay_start_{}", rand::random::<u64>());
  let server = RunningServer::start(db_port, &db_name, 4096).await;

  server.send_tcp_logs(20).await;

  let db = ManagedClickHouse::create_running(db_port, &db_name).await;
  wait_for_count(&db.client(), 20 + server.startup_probe_logs).await;

  server.shutdown().await;
}

#[tokio::test]
async fn test_replay_logs_after_database_restarts() {
  init_env();

  let db_port = reserve_free_port().await;
  let db_name = format!("replay_restart_{}", rand::random::<u64>());
  let db = ManagedClickHouse::create_running(db_port, &db_name).await;
  let server = RunningServer::start(db_port, &db_name, 4096).await;

  server.send_tcp_logs(10).await;
  wait_for_count(&db.client(), 10 + server.startup_probe_logs).await;

  db.stop();
  tokio::time::sleep(Duration::from_secs(1)).await;

  server.send_tcp_logs(15).await;

  db.start_and_wait().await;
  wait_for_count(&db.client(), 25 + server.startup_probe_logs).await;

  server.shutdown().await;
}

#[tokio::test]
async fn test_replay_large_backlog_after_database_starts() {
  init_env();

  let db_port = reserve_free_port().await;
  let db_name = format!("replay_stress_{}", rand::random::<u64>());
  let server = RunningServer::start(db_port, &db_name, 8192).await;

  server.send_tcp_logs_concurrent(1200, 200).await;

  let db = ManagedClickHouse::create_running(db_port, &db_name).await;
  wait_for_count(&db.client(), 1200 + server.startup_probe_logs).await;

  server.shutdown().await;
}
