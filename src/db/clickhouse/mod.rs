use crate::config::DatabaseConfig;
use clickhouse::{Client, Row};
mod migration;
use serde::{Deserialize, Serialize};

use serde_repr::{Deserialize_repr, Serialize_repr};
use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;
use tokio::sync::{Notify, RwLock};
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

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
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

pub struct ClickHouseLogger {
  config: DatabaseConfig,
  client: RwLock<Option<Client>>,
  reconnect_notify: Notify,
}

impl ClickHouseLogger {
  pub fn new(config: &DatabaseConfig) -> anyhow::Result<Self> {
    Self::build_client(config)?;

    Ok(Self {
      config: config.clone(),
      client: RwLock::new(None),
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

  pub fn spawn_reconnector(self: std::sync::Arc<Self>) {
    tokio::spawn(async move {
      let initial_backoff = Duration::from_secs(self.config.reconnect_backoff_initial_secs);
      let mut backoff = initial_backoff;
      let backoff_multiplier = self.config.reconnect_backoff_multiplier;
      let max_backoff = Duration::from_secs(self.config.reconnect_backoff_max_secs);
      info!("starting database connector in background");

      loop {
        let notified = self.reconnect_notify.notified();

        if self.client.read().await.is_some() {
          notified.await;
          continue;
        }

        match Self::build_client(&self.config) {
          Ok(client) => match Self::init_client(&client).await {
            Ok(()) => {
              *self.client.write().await = Some(client);
              info!("connected to database");
              backoff = initial_backoff;
              continue;
            }
            Err(e) => {
              warn!(
                "database unavailable, retrying in {}s: {}",
                backoff.as_secs(),
                e
              );
            }
          },
          Err(e) => {
            warn!(
              "database unavailable, retrying in {}s: {}",
              backoff.as_secs(),
              e
            );
          }
        }

        tokio::time::sleep(backoff).await;
        let next_backoff_ms = (backoff.as_secs_f64() * backoff_multiplier * 1000.0).ceil() as u64;
        backoff = std::cmp::min(Duration::from_millis(next_backoff_ms), max_backoff);
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

  pub async fn insert_log(&self, log: TcpLog) -> anyhow::Result<()> {
    let Some(client) = self.get_client().await else {
      return Ok(());
    };

    let ipv6 = match log.ip {
      IpAddr::V4(ip) => ip.to_ipv6_mapped(),
      IpAddr::V6(ip) => ip,
    };

    let row = TcpLogNew {
      service: log.service,
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

    let mut insert = match client.insert::<TcpLogNew>("tcp_log").await {
      Ok(insert) => insert,
      Err(e) => {
        self.mark_disconnected().await;
        return Err(e.into());
      }
    };

    if let Err(e) = insert.write(&row).await {
      self.mark_disconnected().await;
      return Err(e.into());
    }

    if let Err(e) = insert.end().await {
      self.mark_disconnected().await;
      return Err(e.into());
    }

    Ok(())
  }

  pub async fn insert_http_log(&self, log: HttpLog) -> anyhow::Result<()> {
    let Some(client) = self.get_client().await else {
      return Ok(());
    };

    let ipv6 = match log.ip {
      IpAddr::V4(ip) => ip.to_ipv6_mapped(),
      IpAddr::V6(ip) => ip,
    };

    let row = HttpLogRow {
      service: log.service,
      conn_ts: log.conn_ts,
      duration: log.duration,
      addr_family: log.addr_family,
      ip: ipv6,
      proxy_proto: log.proxy_proto,
      resp_body_size: log.resp_body_size,
      req_body_size: log.req_body_size,
      status_code: log.status_code,
      method: log.method.as_str().to_string(),
      host: log.host,
      path: log.path,
      user_agent: log.user_agent,
    };

    let mut insert = match client.insert::<HttpLogRow>("http_log").await {
      Ok(insert) => insert,
      Err(e) => {
        self.mark_disconnected().await;
        return Err(e.into());
      }
    };

    if let Err(e) = insert.write(&row).await {
      self.mark_disconnected().await;
      return Err(e.into());
    }

    if let Err(e) = insert.end().await {
      self.mark_disconnected().await;
      return Err(e.into());
    }

    Ok(())
  }
}
