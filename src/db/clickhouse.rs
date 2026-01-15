use crate::config::DatabaseConfig;
use clickhouse::{Client, Row};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::net::{IpAddr, Ipv6Addr};
use tracing::info;

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum ProxyProto {
  None = 0,
  V1 = 1,
  V2 = 2,
}

#[derive(Debug, Clone)]
pub struct TcpLog {
  pub service: String,
  pub conn_ts: time::OffsetDateTime,
  pub duration: u32,
  pub port: u16,
  pub ip: IpAddr,
  pub proxy_proto: ProxyProto,
  pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Row)]
struct TcpLogV4 {
  pub service: String,
  #[serde(with = "clickhouse::serde::time::datetime")]
  pub conn_ts: time::OffsetDateTime,
  pub duration: u32,
  pub port: u16,
  pub ip: u32,
  pub proxy_proto: ProxyProto,
  pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Row)]
struct TcpLogV6 {
  pub service: String,
  #[serde(with = "clickhouse::serde::time::datetime")]
  pub conn_ts: time::OffsetDateTime,
  pub duration: u32,
  pub port: u16,
  pub ip: Ipv6Addr,
  pub proxy_proto: ProxyProto,
  pub bytes: u64,
}

pub struct ClickHouseLogger {
  client: Client,
}

impl ClickHouseLogger {
  pub fn new(config: &DatabaseConfig) -> Self {
    let url = url::Url::parse(&config.dsn).expect("invalid dsn");
    let mut client = Client::default().with_url(url.as_str());

    if let (Some(u), Some(p)) = (Some(url.username()), url.password()) {
      if !u.is_empty() {
        client = client.with_user(u).with_password(p);
      }
    } else if !url.username().is_empty() {
      client = client.with_user(url.username());
    }

    if let Some(path) = url.path_segments().map(|c| c.collect::<Vec<_>>()) {
      if let Some(db) = path.first() {
        if !db.is_empty() {
          client = client.with_database(*db);
        }
      }
    }

    Self { client }
  }

  pub async fn init(&self) -> anyhow::Result<()> {
    let sql_v4 = r#"
      CREATE TABLE IF NOT EXISTS tcp_log_v4 (
          service     LowCardinality(String),
          conn_ts     DateTime('UTC'),
          duration    UInt32,
          port        UInt16,
          ip          IPv4,
          proxy_proto Enum8('None' = 0, 'V1' = 1, 'V2' = 2),
          bytes       UInt64
      ) ENGINE = MergeTree() 
      ORDER BY (service, conn_ts);
      "#;

    let sql_v6 = r#"
      CREATE TABLE IF NOT EXISTS tcp_log_v6 (
          service     LowCardinality(String),
          conn_ts     DateTime('UTC'),
          duration    UInt32,
          port        UInt16,
          ip          IPv6,
          proxy_proto Enum8('None' = 0, 'V1' = 1, 'V2' = 2),
          bytes       UInt64
      ) ENGINE = MergeTree() 
      ORDER BY (service, conn_ts);
      "#;

    let drop_view = "DROP VIEW IF EXISTS tcp_log";

    let sql_view = r#"
      CREATE VIEW tcp_log AS
      SELECT 
          service, conn_ts, duration, port,
          IPv4NumToString(ip) AS ip_str, 
          proxy_proto,
          formatReadableSize(bytes) AS traffic
      FROM tcp_log_v4
      UNION ALL
      SELECT 
          service, conn_ts, duration, port,
          IPv6NumToString(ip) AS ip_str, 
          proxy_proto,
          formatReadableSize(bytes) AS traffic
      FROM tcp_log_v6;
      "#;

    self
      .client
      .query(sql_v4)
      .execute()
      .await
      .map_err(|e| anyhow::anyhow!("failed to create v4 table: {}", e))?;

    // Migrations
    let _ = self
      .client
      .query("ALTER TABLE tcp_log_v4 RENAME COLUMN IF EXISTS bytes_transferred TO bytes")
      .execute()
      .await;
    let _ = self
      .client
      .query("ALTER TABLE tcp_log_v4 RENAME COLUMN IF EXISTS traffic TO bytes")
      .execute()
      .await;
    let _ = self
      .client
      .query("ALTER TABLE tcp_log_v4 ADD COLUMN IF NOT EXISTS bytes UInt64")
      .execute()
      .await;

    self
      .client
      .query(sql_v6)
      .execute()
      .await
      .map_err(|e| anyhow::anyhow!("failed to create v6 table: {}", e))?;

    let _ = self
      .client
      .query("ALTER TABLE tcp_log_v6 RENAME COLUMN IF EXISTS bytes_transferred TO bytes")
      .execute()
      .await;
    let _ = self
      .client
      .query("ALTER TABLE tcp_log_v6 RENAME COLUMN IF EXISTS traffic TO bytes")
      .execute()
      .await;
    let _ = self
      .client
      .query("ALTER TABLE tcp_log_v6 ADD COLUMN IF NOT EXISTS bytes UInt64")
      .execute()
      .await;

    self
      .client
      .query(drop_view)
      .execute()
      .await
      .map_err(|e| anyhow::anyhow!("failed to drop view: {}", e))?;
    self
      .client
      .query(sql_view)
      .execute()
      .await
      .map_err(|e| anyhow::anyhow!("failed to create view: {}", e))?;

    info!("ensured tables and view exist");
    Ok(())
  }

  pub async fn insert_log(&self, log: TcpLog) -> anyhow::Result<()> {
    match log.ip {
      IpAddr::V4(ip) => {
        let row = TcpLogV4 {
          service: log.service,
          conn_ts: log.conn_ts,
          duration: log.duration,
          port: log.port,
          ip: u32::from(ip),
          proxy_proto: log.proxy_proto,
          bytes: log.bytes,
        };
        let mut insert = self.client.insert("tcp_log_v4")?;
        insert.write(&row).await?;
        insert.end().await?;
      }
      IpAddr::V6(ip) => {
        let row = TcpLogV6 {
          service: log.service,
          conn_ts: log.conn_ts,
          duration: log.duration,
          port: log.port,
          ip,
          proxy_proto: log.proxy_proto,
          bytes: log.bytes,
        };
        let mut insert = self.client.insert("tcp_log_v6")?;
        insert.write(&row).await?;
        insert.end().await?;
      }
    }
    Ok(())
  }
}
