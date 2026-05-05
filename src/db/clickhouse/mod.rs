use crate::config::DatabaseConfig;
use crate::core::server::ShutdownReason;
use clickhouse::{Client, Row};
mod migration;
use serde::{Deserialize, Serialize};

use serde_repr::{Deserialize_repr, Serialize_repr};
use std::collections::hash_map::DefaultHasher;
use std::collections::VecDeque;
use std::hash::{Hash, Hasher};
use std::mem::size_of;
use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::{Mutex, Notify, RwLock};
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Serialize_repr, Deserialize_repr)]
#[repr(i8)]
pub enum ProxyProto {
  None = 0,
  V1 = 1,
  V2 = 2,
}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr)]
#[repr(i8)]
pub enum AddrFamily {
  Unix = 1,
  Ipv4 = 2,
  Ipv6 = 10,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpLog {
  pub service: String,
  pub conn_ts: time::OffsetDateTime,
  pub duration: u32,
  pub addr_family: AddrFamily,
  pub ip: IpAddr,
  pub port: u16,
  pub proxy_proto: ProxyProto,
  pub bytes: u64,
  pub bytes_sent: u64,
  pub bytes_recv: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Row)]
struct TcpLogNew {
  pub service: String,
  #[serde(with = "clickhouse::serde::time::datetime64::millis")]
  pub conn_ts: time::OffsetDateTime,
  pub duration: u32,
  pub addr_family: AddrFamily,
  pub ip: Ipv6Addr,
  pub port: u16,
  pub proxy_proto: ProxyProto,
  pub bytes: u64,
  pub bytes_sent: u64,
  pub bytes_recv: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
  Other,
  Get,
  Post,
  Put,
  Delete,
  Head,
  Patch,
  Options,
  Connect,
  Trace,
}

impl HttpMethod {
  pub fn as_str(&self) -> &'static str {
    match self {
      Self::Get => "GET",
      Self::Post => "POST",
      Self::Put => "PUT",
      Self::Delete => "DELETE",
      Self::Head => "HEAD",
      Self::Patch => "PATCH",
      Self::Options => "OPTIONS",
      Self::Connect => "CONNECT",
      Self::Trace => "TRACE",
      Self::Other => "OTHER",
    }
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpLog {
  pub service: String,
  pub conn_ts: time::OffsetDateTime,
  pub duration: u32,
  pub addr_family: AddrFamily,
  pub ip: IpAddr,
  pub proxy_proto: ProxyProto,
  pub resp_body_size: u64,
  pub req_body_size: u64,
  pub status_code: u16,
  pub method: HttpMethod,
  pub host: String,
  pub path: String,
  pub user_agent: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Row)]
struct HttpLogRow {
  pub service: String,
  #[serde(with = "clickhouse::serde::time::datetime64::millis")]
  pub conn_ts: time::OffsetDateTime,
  pub duration: u32,
  pub addr_family: AddrFamily,
  pub ip: Ipv6Addr,
  pub proxy_proto: ProxyProto,
  pub resp_body_size: u64,
  pub req_body_size: u64,
  pub status_code: u16,
  pub method: String,
  pub host: String,
  pub path: String,
  pub user_agent: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum PendingLog {
  Tcp(TcpLog),
  Http(HttpLog),
}

impl PendingLog {
  fn is_same_kind(&self, other: &Self) -> bool {
    matches!((self, other), (Self::Tcp(_), Self::Tcp(_)) | (Self::Http(_), Self::Http(_)))
  }

  fn estimated_size(&self) -> usize {
    match self {
      Self::Tcp(log) => size_of::<Self>() + log.service.len(),
      Self::Http(log) => {
        size_of::<Self>()
          + log.service.len()
          + log.host.len()
          + log.path.len()
          + log.user_agent.len()
      }
    }
  }
}

#[derive(Debug, Default)]
struct PendingQueue {
  logs: VecDeque<PendingLog>,
  total_bytes: usize,
}

pub struct ClickHouseLogger {
  config: DatabaseConfig,
  client: RwLock<Option<Client>>,
  queue: Mutex<PendingQueue>,
  reconnect_notify: Notify,
}

impl ClickHouseLogger {
  pub fn new(config: &DatabaseConfig) -> anyhow::Result<Self> {
    Self::build_client(config)?;

    Ok(Self {
      config: config.clone(),
      client: RwLock::new(None),
      queue: Mutex::new(PendingQueue::default()),
      reconnect_notify: Notify::new(),
    })
  }

  fn build_client(config: &DatabaseConfig) -> anyhow::Result<Client> {
    let mut url =
      url::Url::parse(&config.dsn).map_err(|e| anyhow::anyhow!("invalid dsn: {}", e))?;
    let db_name = url
      .path_segments()
      .and_then(|mut segments| segments.next())
      .filter(|db| !db.is_empty())
      .ok_or_else(|| anyhow::anyhow!("database name is required in dsn"))?
      .to_string();

    // Clear path so client doesn't append it
    url.set_path("");

    let mut client = Client::default().with_url(url.as_str());

    if let (Some(u), Some(p)) = (Some(url.username()), url.password()) {
      if !u.is_empty() {
        client = client.with_user(u).with_password(p);
      }
    } else if !url.username().is_empty() {
      client = client.with_user(url.username());
    }

    client = client.with_database(&db_name);

    Ok(client)
  }

  async fn init_client(client: &Client) -> anyhow::Result<()> {
    // Check migrations
    Self::check_migrations(client).await?;
    Self::ensure_http_table(client).await?;

    Ok(())
  }

  fn initial_backoff(&self) -> Duration {
    Duration::from_secs(self.config.reconnect_backoff_initial_secs)
  }

  fn next_backoff(&self, current: Duration) -> Duration {
    let max_backoff = Duration::from_secs(self.config.reconnect_backoff_max_secs);
    let next_backoff_ms =
      (current.as_secs_f64() * self.config.reconnect_backoff_multiplier * 1000.0).ceil() as u64;
    std::cmp::min(Duration::from_millis(next_backoff_ms), max_backoff)
  }

  fn max_cache_bytes(&self) -> usize {
    self.config.memory_cache_max_kib.saturating_mul(1024)
  }

  fn reload_buffer_path(&self) -> PathBuf {
    let mut url =
      url::Url::parse(&self.config.dsn).unwrap_or_else(|_| url::Url::parse("http://invalid/traudit").unwrap());
    let db_name = url
      .path_segments()
      .and_then(|mut segments| segments.next())
      .filter(|db| !db.is_empty())
      .unwrap_or("traudit")
      .to_string();
    url.set_password(None).ok();
    let mut hasher = DefaultHasher::new();
    format!("{}:{}", db_name, url.as_str()).hash(&mut hasher);
    PathBuf::from(format!(
      "/tmp/traudit-reload-buffer-{:x}.json",
      hasher.finish()
    ))
  }

  pub async fn import_reload_buffer(&self) {
    let path = self.reload_buffer_path();
    let content = match tokio::fs::read_to_string(&path).await {
      Ok(content) => content,
      Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
      Err(e) => {
        warn!("failed to read reload buffer {}: {}", path.display(), e);
        return;
      }
    };

    let logs: Vec<PendingLog> = match serde_json::from_str(&content) {
      Ok(logs) => logs,
      Err(e) => {
        warn!("failed to parse reload buffer {}: {}", path.display(), e);
        let _ = tokio::fs::remove_file(&path).await;
        return;
      }
    };

    let mut queue = self.queue.lock().await;
    for log in logs {
      queue.total_bytes = queue.total_bytes.saturating_add(log.estimated_size());
      queue.logs.push_back(log);
    }
    drop(queue);

    if let Err(e) = tokio::fs::remove_file(&path).await {
      warn!("failed to remove reload buffer {}: {}", path.display(), e);
    }

    self.reconnect_notify.notify_one();
  }

  async fn export_reload_buffer(&self) {
    let path = self.reload_buffer_path();
    let queue = self.queue.lock().await;
    if queue.logs.is_empty() {
      drop(queue);
      let _ = tokio::fs::remove_file(&path).await;
      return;
    }

    let logs: Vec<PendingLog> = queue.logs.iter().cloned().collect();
    drop(queue);

    let serialized = match serde_json::to_string(&logs) {
      Ok(serialized) => serialized,
      Err(e) => {
        warn!("failed to serialize reload buffer {}: {}", path.display(), e);
        return;
      }
    };

    if let Err(e) = tokio::fs::write(&path, serialized).await {
      warn!("failed to write reload buffer {}: {}", path.display(), e);
    }
  }

  async fn enqueue_log(&self, log: PendingLog) {
    let mut queue = self.queue.lock().await;
    let log_size = log.estimated_size();
    let max_bytes = self.max_cache_bytes();

    while !queue.logs.is_empty() && queue.total_bytes.saturating_add(log_size) > max_bytes {
      if let Some(oldest) = queue.logs.pop_front() {
        queue.total_bytes = queue.total_bytes.saturating_sub(oldest.estimated_size());
      }
    }

    if log_size > max_bytes {
      warn!(
        "dropping oversized audit log entry estimated at {} bytes because cache limit is {} bytes",
        log_size,
        max_bytes
      );
      return;
    }

    queue.total_bytes = queue.total_bytes.saturating_add(log_size);
    queue.logs.push_back(log);
    drop(queue);
    self.reconnect_notify.notify_one();
  }

  async fn has_pending_logs(&self) -> bool {
    !self.queue.lock().await.logs.is_empty()
  }

  async fn pop_batch(&self) -> Vec<PendingLog> {
    let mut queue = self.queue.lock().await;
    let Some(first) = queue.logs.pop_front() else {
      return Vec::new();
    };

    queue.total_bytes = queue.total_bytes.saturating_sub(first.estimated_size());

    let mut batch = Vec::with_capacity(self.config.batch_size);
    batch.push(first);

    while batch.len() < self.config.batch_size {
      let Some(next) = queue.logs.front() else {
        break;
      };

      if !batch[0].is_same_kind(next) {
        break;
      }

      let next = queue.logs.pop_front().expect("front element disappeared");
      queue.total_bytes = queue.total_bytes.saturating_sub(next.estimated_size());
      batch.push(next);
    }

    batch
  }

  async fn requeue_batch_front(&self, mut logs: Vec<PendingLog>) {
    if logs.is_empty() {
      return;
    }

    let mut queue = self.queue.lock().await;
    while let Some(log) = logs.pop() {
      queue.total_bytes = queue.total_bytes.saturating_add(log.estimated_size());
      queue.logs.push_front(log);
    }
  }

  async fn flush_pending_logs(&self) -> anyhow::Result<()> {
    loop {
      let batch = self.pop_batch().await;
      if batch.is_empty() {
        return Ok(());
      }

      if let Err(e) = self.write_pending_batch(&batch).await {
        self.requeue_batch_front(batch).await;
        return Err(e);
      }
    }
  }

  async fn write_pending_batch(&self, logs: &[PendingLog]) -> anyhow::Result<()> {
    let Some(client) = self.get_client().await else {
      anyhow::bail!("database client is not connected");
    };

    match logs.first() {
      Some(PendingLog::Tcp(_)) => {
        let tcp_logs = logs
          .iter()
          .map(|log| match log {
            PendingLog::Tcp(log) => Ok(log),
            PendingLog::Http(_) => Err(anyhow::anyhow!("mixed log kinds in tcp batch")),
          })
          .collect::<anyhow::Result<Vec<_>>>()?;
        Self::write_tcp_logs(&client, &tcp_logs).await
      }
      Some(PendingLog::Http(_)) => {
        let http_logs = logs
          .iter()
          .map(|log| match log {
            PendingLog::Http(log) => Ok(log),
            PendingLog::Tcp(_) => Err(anyhow::anyhow!("mixed log kinds in http batch")),
          })
          .collect::<anyhow::Result<Vec<_>>>()?;
        Self::write_http_logs(&client, &http_logs).await
      }
      None => Ok(()),
    }
  }

  pub async fn shutdown(&self, reason: ShutdownReason) {
    self.reconnect_notify.notify_waiters();

    if self.client.read().await.is_none() {
      match Self::build_client(&self.config) {
        Ok(client) => match Self::init_client(&client).await {
          Ok(()) => {
            *self.client.write().await = Some(client);
            info!("connected to database during shutdown drain");
          }
          Err(e) => {
            warn!("failed to connect database during shutdown drain: {}", e);
            return;
          }
        },
        Err(e) => {
          warn!("failed to build database client during shutdown drain: {}", e);
          return;
        }
      }
    }

    if let Err(e) = self.flush_pending_logs().await {
      warn!("failed to flush pending audit logs during shutdown: {}", e);
    }

    if reason == ShutdownReason::Reload && self.has_pending_logs().await {
      self.export_reload_buffer().await;
    }
  }

  pub fn spawn_reconnector(self: std::sync::Arc<Self>) {
    tokio::spawn(async move {
      let initial_backoff = self.initial_backoff();
      let mut backoff = initial_backoff;
      info!("starting database connector in background");

      loop {
        let notified = self.reconnect_notify.notified();

        if self.client.read().await.is_some() && !self.has_pending_logs().await {
          notified.await;
          continue;
        }

        if self.client.read().await.is_none() {
          match Self::build_client(&self.config) {
            Ok(client) => match Self::init_client(&client).await {
              Ok(()) => {
                *self.client.write().await = Some(client);
                info!("connected to database");
                backoff = initial_backoff;
              }
              Err(e) => {
                warn!(
                  "database unavailable, retrying in {}s: {}",
                  backoff.as_secs(),
                  e
                );
                tokio::time::sleep(backoff).await;
                backoff = self.next_backoff(backoff);
                continue;
              }
            },
            Err(e) => {
              warn!(
                "database unavailable, retrying in {}s: {}",
                backoff.as_secs(),
                e
              );
              tokio::time::sleep(backoff).await;
              backoff = self.next_backoff(backoff);
              continue;
            }
          }
        }

        if let Err(e) = self.flush_pending_logs().await {
          self.mark_disconnected().await;
          warn!(
            "database unavailable, retrying in {}s: {}",
            backoff.as_secs(),
            e
          );
          tokio::time::sleep(backoff).await;
          backoff = self.next_backoff(backoff);
          continue;
        }

        backoff = initial_backoff;
      }
    });
  }

  async fn get_client(&self) -> Option<Client> {
    self.client.read().await.clone()
  }

  async fn mark_disconnected(&self) {
    let mut guard = self.client.write().await;
    if guard.take().is_some() {
      warn!("database connection lost, switching to background reconnect");
    }
    drop(guard);
    self.reconnect_notify.notify_one();
  }

  pub async fn init(&self) -> anyhow::Result<()> {
    let client = Self::build_client(&self.config)?;
    Self::init_client(&client).await?;
    *self.client.write().await = Some(client);

    info!("connected to database");
    Ok(())
  }

  async fn ensure_http_table(client: &Client) -> anyhow::Result<()> {
    let sql_create = r#"
    CREATE TABLE IF NOT EXISTS http_log (
        service     LowCardinality(String) CODEC(ZSTD(1)),
        conn_ts     DateTime64(3) CODEC(Delta, ZSTD(1)),
        duration    UInt32,
        addr_family LowCardinality(String),
        ip          IPv6,
        proxy_proto LowCardinality(String),
        bytes_sent  UInt64,
        bytes_recv  UInt64,
        status_code UInt16,
        method      LowCardinality(String),
        host        LowCardinality(String),
        path        String CODEC(ZSTD(1)),
        user_agent  String CODEC(ZSTD(1))
    ) ENGINE = MergeTree()
    PARTITION BY toYYYYMM(conn_ts)
    ORDER BY (conn_ts, service, host);
    "#;
    client
      .query(sql_create)
      .execute()
      .await
      .map_err(|e| anyhow::anyhow!("failed to create http_log table: {}", e))?;
    Ok(())
  }

  async fn check_migrations(client: &Client) -> anyhow::Result<()> {
    let migrator = migration::Migrator::new(client.clone());
    migrator.run().await
  }

  async fn write_tcp_logs(client: &Client, logs: &[&TcpLog]) -> anyhow::Result<()> {
    let mut insert = client.insert::<TcpLogNew>("tcp_log").await?;

    for log in logs {
      let ipv6 = match log.ip {
        IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        IpAddr::V6(ip) => ip,
      };

      let row = TcpLogNew {
        service: log.service.clone(),
        conn_ts: log.conn_ts,
        duration: log.duration,
        addr_family: log.addr_family,
        ip: ipv6,
        port: log.port,
        proxy_proto: log.proxy_proto,
        bytes: log.bytes,
        bytes_sent: log.bytes_sent,
        bytes_recv: log.bytes_recv,
      };

      insert.write(&row).await?;
    }

    insert.end().await?;

    Ok(())
  }

  async fn write_http_logs(client: &Client, logs: &[&HttpLog]) -> anyhow::Result<()> {
    let mut insert = client.insert::<HttpLogRow>("http_log").await?;

    for log in logs {
      let ipv6 = match log.ip {
        IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        IpAddr::V6(ip) => ip,
      };

      let row = HttpLogRow {
        service: log.service.clone(),
        conn_ts: log.conn_ts,
        duration: log.duration,
        addr_family: log.addr_family,
        ip: ipv6,
        proxy_proto: log.proxy_proto,
        resp_body_size: log.resp_body_size,
        req_body_size: log.req_body_size,
        status_code: log.status_code,
        method: log.method.as_str().to_string(),
        host: log.host.clone(),
        path: log.path.clone(),
        user_agent: log.user_agent.clone(),
      };

      insert.write(&row).await?;
    }

    insert.end().await?;

    Ok(())
  }

  pub async fn insert_log(&self, log: TcpLog) -> anyhow::Result<()> {
    self.enqueue_log(PendingLog::Tcp(log)).await;
    Ok(())
  }

  pub async fn insert_http_log(&self, log: HttpLog) -> anyhow::Result<()> {
    self.enqueue_log(PendingLog::Http(log)).await;

    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn test_db_config() -> DatabaseConfig {
    DatabaseConfig {
      db_type: "clickhouse".to_string(),
      dsn: "http://127.0.0.1:8123/test".to_string(),
      batch_size: 1,
      batch_timeout_secs: 1,
      reconnect_backoff_initial_secs: 3,
      reconnect_backoff_multiplier: 2.0,
      reconnect_backoff_max_secs: 10,
      memory_cache_max_kib: 4,
    }
  }

  #[test]
  fn test_backoff_progression_respects_multiplier_and_max() {
    let logger = ClickHouseLogger::new(&test_db_config()).unwrap();

    let first = logger.initial_backoff();
    let second = logger.next_backoff(first);
    let third = logger.next_backoff(second);

    assert_eq!(first, Duration::from_secs(3));
    assert_eq!(second, Duration::from_secs(6));
    assert_eq!(third, Duration::from_secs(10));
  }

  #[test]
  fn test_backoff_can_stay_fixed_after_disconnect() {
    let mut config = test_db_config();
    config.reconnect_backoff_multiplier = 1.0;
    let logger = ClickHouseLogger::new(&config).unwrap();

    let initial = logger.initial_backoff();
    let after_disconnect_retry = logger.next_backoff(initial);

    assert_eq!(initial, Duration::from_secs(3));
    assert_eq!(after_disconnect_retry, Duration::from_secs(3));
  }

  #[tokio::test]
  async fn test_queue_drops_oldest_when_cache_is_full() {
    let mut config = test_db_config();
    config.memory_cache_max_kib = 1;
    let logger = ClickHouseLogger::new(&config).unwrap();

    let first = PendingLog::Http(HttpLog {
      service: "svc-1".to_string(),
      conn_ts: time::OffsetDateTime::now_utc(),
      duration: 1,
      addr_family: AddrFamily::Ipv4,
      ip: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
      proxy_proto: ProxyProto::None,
      resp_body_size: 1,
      req_body_size: 1,
      status_code: 200,
      method: HttpMethod::Get,
      host: "example.com".repeat(10),
      path: "/first".repeat(20),
      user_agent: "agent-a".repeat(20),
    });

    let second = PendingLog::Http(HttpLog {
      service: "svc-2".to_string(),
      conn_ts: time::OffsetDateTime::now_utc(),
      duration: 1,
      addr_family: AddrFamily::Ipv4,
      ip: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
      proxy_proto: ProxyProto::None,
      resp_body_size: 1,
      req_body_size: 1,
      status_code: 200,
      method: HttpMethod::Get,
      host: "example.org".repeat(10),
      path: "/second".repeat(20),
      user_agent: "agent-b".repeat(20),
    });

    logger.enqueue_log(first).await;
    logger.enqueue_log(second).await;

    let queued = logger.pop_batch().await;
    assert_eq!(queued.len(), 1);
    match queued.into_iter().next().unwrap() {
      PendingLog::Http(log) => assert_eq!(log.service, "svc-2"),
      PendingLog::Tcp(_) => panic!("expected http log"),
    }
    assert!(logger.pop_batch().await.is_empty());
  }

  #[tokio::test]
  async fn test_oversized_entry_is_dropped() {
    let mut config = test_db_config();
    config.memory_cache_max_kib = 1;
    let logger = ClickHouseLogger::new(&config).unwrap();

    let oversized = PendingLog::Http(HttpLog {
      service: "svc".to_string(),
      conn_ts: time::OffsetDateTime::now_utc(),
      duration: 1,
      addr_family: AddrFamily::Ipv4,
      ip: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
      proxy_proto: ProxyProto::None,
      resp_body_size: 1,
      req_body_size: 1,
      status_code: 200,
      method: HttpMethod::Get,
      host: "h".repeat(600),
      path: "p".repeat(600),
      user_agent: "u".repeat(600),
    });

    logger.enqueue_log(oversized).await;

    assert!(logger.pop_batch().await.is_empty());
  }

  #[tokio::test]
  async fn test_pop_batch_keeps_fifo_and_kind_boundaries() {
    let mut config = test_db_config();
    config.batch_size = 2;
    let logger = ClickHouseLogger::new(&config).unwrap();

    logger
      .enqueue_log(PendingLog::Tcp(TcpLog {
        service: "tcp-1".to_string(),
        conn_ts: time::OffsetDateTime::now_utc(),
        duration: 1,
        addr_family: AddrFamily::Ipv4,
        ip: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        port: 22,
        proxy_proto: ProxyProto::None,
        bytes: 1,
        bytes_sent: 1,
        bytes_recv: 1,
      }))
      .await;
    logger
      .enqueue_log(PendingLog::Tcp(TcpLog {
        service: "tcp-2".to_string(),
        conn_ts: time::OffsetDateTime::now_utc(),
        duration: 1,
        addr_family: AddrFamily::Ipv4,
        ip: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        port: 22,
        proxy_proto: ProxyProto::None,
        bytes: 1,
        bytes_sent: 1,
        bytes_recv: 1,
      }))
      .await;
    logger
      .enqueue_log(PendingLog::Http(HttpLog {
        service: "http-1".to_string(),
        conn_ts: time::OffsetDateTime::now_utc(),
        duration: 1,
        addr_family: AddrFamily::Ipv4,
        ip: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        proxy_proto: ProxyProto::None,
        resp_body_size: 1,
        req_body_size: 1,
        status_code: 200,
        method: HttpMethod::Get,
        host: "example.com".to_string(),
        path: "/".to_string(),
        user_agent: "ua".to_string(),
      }))
      .await;

    let first_batch = logger.pop_batch().await;
    assert_eq!(first_batch.len(), 2);
    match &first_batch[0] {
      PendingLog::Tcp(log) => assert_eq!(log.service, "tcp-1"),
      PendingLog::Http(_) => panic!("expected tcp log"),
    }
    match &first_batch[1] {
      PendingLog::Tcp(log) => assert_eq!(log.service, "tcp-2"),
      PendingLog::Http(_) => panic!("expected tcp log"),
    }

    let second_batch = logger.pop_batch().await;
    assert_eq!(second_batch.len(), 1);
    match &second_batch[0] {
      PendingLog::Http(log) => assert_eq!(log.service, "http-1"),
      PendingLog::Tcp(_) => panic!("expected http log"),
    }
  }
}
