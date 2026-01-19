use crate::config::DatabaseConfig;
use clickhouse::{Client, Row};
mod migration;
use serde::{Deserialize, Serialize};

use serde_repr::{Deserialize_repr, Serialize_repr};
use std::net::{IpAddr, Ipv6Addr};
use tracing::info;

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
  client: Client,
}

impl ClickHouseLogger {
  pub fn new(config: &DatabaseConfig) -> anyhow::Result<Self> {
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

    Ok(Self { client })
  }

  pub async fn init(&self) -> anyhow::Result<()> {
    // Check migrations
    self.check_migrations().await?;
    self.ensure_http_table().await?;

    info!("connected to database");
    Ok(())
  }

  async fn ensure_http_table(&self) -> anyhow::Result<()> {
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
    self
      .client
      .query(sql_create)
      .execute()
      .await
      .map_err(|e| anyhow::anyhow!("failed to create http_log table: {}", e))?;
    Ok(())
  }

  async fn check_migrations(&self) -> anyhow::Result<()> {
    let migrator = migration::Migrator::new(self.client.clone());
    migrator.run().await
  }

  pub async fn insert_log(&self, log: TcpLog) -> anyhow::Result<()> {
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

    let mut insert = self.client.insert::<TcpLogNew>("tcp_log").await?;
    insert.write(&row).await?;
    insert.end().await?;

    Ok(())
  }

  pub async fn insert_http_log(&self, log: HttpLog) -> anyhow::Result<()> {
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

    let mut insert = self.client.insert::<HttpLogRow>("http_log").await?;
    insert.write(&row).await?;
    insert.end().await?;

    Ok(())
  }
}
