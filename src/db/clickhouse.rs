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
  table_base: String,
}

impl ClickHouseLogger {
  pub fn new(config: &DatabaseConfig) -> anyhow::Result<Self> {
    let url = url::Url::parse(&config.dsn).map_err(|e| anyhow::anyhow!("invalid dsn: {}", e))?;
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

    // Config table name, default to "tcp_log" if missing
    // We expect config.tables to contain "tcp" -> "tablename"
    let table_base = config
      .tables
      .get("tcp")
      .cloned()
      .unwrap_or_else(|| "tcp_log".to_string());

    Ok(Self { client, table_base })
  }

  pub async fn init(&self) -> anyhow::Result<()> {
    let table_v4 = format!("{}_v4", self.table_base);
    let table_v6 = format!("{}_v6", self.table_base);
    let view_name = &self.table_base;

    let sql_v4 = format!(
      r#"
      CREATE TABLE IF NOT EXISTS {} (
          service     LowCardinality(String),
          conn_ts     DateTime('UTC'),
          duration    UInt32,
          port        UInt16,
          ip          IPv4,
          proxy_proto Enum8('None' = 0, 'V1' = 1, 'V2' = 2),
          bytes       UInt64
      ) ENGINE = MergeTree() 
      ORDER BY (service, conn_ts);
      "#,
      table_v4
    );

    let sql_v6 = format!(
      r#"
      CREATE TABLE IF NOT EXISTS {} (
          service     LowCardinality(String),
          conn_ts     DateTime('UTC'),
          duration    UInt32,
          port        UInt16,
          ip          IPv6,
          proxy_proto Enum8('None' = 0, 'V1' = 1, 'V2' = 2),
          bytes       UInt64
      ) ENGINE = MergeTree() 
      ORDER BY (service, conn_ts);
      "#,
      table_v6
    );

    let sql_view = format!(
      r#"
      CREATE VIEW IF NOT EXISTS {} AS
      SELECT 
          service, conn_ts, duration, port,
          IPv4NumToString(ip) AS ip_str, 
          proxy_proto,
          formatReadableSize(bytes) AS traffic
      FROM {}
      UNION ALL
      SELECT 
          service, conn_ts, duration, port,
          IPv6NumToString(ip) AS ip_str, 
          proxy_proto,
          formatReadableSize(bytes) AS traffic
      FROM {};
      "#,
      view_name, table_v4, table_v6
    );

    self
      .client
      .query(&sql_v4)
      .execute()
      .await
      .map_err(|e| anyhow::anyhow!("failed to create v4 table: {}", e))?;

    self
      .client
      .query(&sql_v6)
      .execute()
      .await
      .map_err(|e| anyhow::anyhow!("failed to create v6 table: {}", e))?;

    // Schema Check / Migration
    for (table, is_v6) in [(&table_v4, false), (&table_v6, true)] {
      let ip_type = if is_v6 { "IPv6" } else { "IPv4" };
      let columns = [
        ("service", "LowCardinality(String)"),
        ("conn_ts", "DateTime('UTC')"),
        ("duration", "UInt32"),
        ("port", "UInt16"),
        ("ip", ip_type),
        ("proxy_proto", "Enum8('None' = 0, 'V1' = 1, 'V2' = 2)"),
        ("bytes", "UInt64"),
      ];
      for (name, type_def) in columns {
        self
          .client
          .query(&format!(
            "ALTER TABLE {} ADD COLUMN IF NOT EXISTS {} {}",
            table, name, type_def
          ))
          .execute()
          .await
          .map_err(|e| anyhow::anyhow!("failed to add column {} to {}: {}", name, table, e))?;
      }
    }

    self
      .client
      .query(&sql_view)
      .execute()
      .await
      .map_err(|e| anyhow::anyhow!("failed to create view: {}", e))?;

    info!("connected to database");
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
        let table = format!("{}_v4", self.table_base);
        let mut insert = self.client.insert(&table)?;
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
        let table = format!("{}_v6", self.table_base);
        let mut insert = self.client.insert(&table)?;
        insert.write(&row).await?;
        insert.end().await?;
      }
    }
    Ok(())
  }
}
