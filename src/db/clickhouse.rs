use crate::config::DatabaseConfig;
use clickhouse::{Client, Row};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::net::{IpAddr, Ipv6Addr};
use tracing::{error, info};

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr, PartialEq)]
#[repr(u8)]
pub enum ProxyProto {
  None = 0,
  V1 = 1,
  V2 = 2,
}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
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

    // Clear path from URL so client doesn't append it to requests
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

    info!("connected to database");
    Ok(())
  }

  async fn check_migrations(&self) -> anyhow::Result<()> {
    // Create migrations table
    self
      .client
      .query(
        "
      CREATE TABLE IF NOT EXISTS db_migrations (
        version String,
        success UInt8,
        apply_ts DateTime64 DEFAULT now()
      ) ENGINE = ReplacingMergeTree(apply_ts)
      ORDER BY version
    ",
      )
      .execute()
      .await
      .map_err(|e| anyhow::anyhow!("failed to create migrations table: {}", e))?;

    // Get current DB version
    #[derive(Row, Deserialize)]
    struct MigrationRow {
      version: String,
      success: u8,
    }

    let last_migration = self
      .client
      .query("SELECT version, success FROM db_migrations ORDER BY apply_ts DESC LIMIT 1")
      .fetch_optional::<MigrationRow>()
      .await
      .map_err(|e| anyhow::anyhow!("failed to fetch last migration: {}", e))?;

    let (current_db_version, success) = last_migration
      .map(|r| (r.version, r.success == 1))
      .unwrap_or_else(|| ("v0.0.0".to_string(), true));

    if current_db_version == crate::VERSION && success {
      return Ok(());
    }

    if !success {
      error!(
        "previous migration to {} failed. retrying...",
        current_db_version
      );
    } else {
      info!(
        "migrating database from {} to {}",
        current_db_version,
        crate::VERSION
      );
    }
    self.run_migrations(&current_db_version, success).await?;

    Ok(())
  }

  async fn run_migrations(&self, from_version: &str, last_success: bool) -> anyhow::Result<()> {
    if from_version < "v0.0.1" || (from_version == "v0.0.1" && !last_success) {
      info!("applying migration v0.0.1...");
      if let Err(e) = self.apply_v0_0_1().await {
        error!("migration v0.0.1 failed: {}", e);
        // Record failure
        let _ = self
          .client
          .query("INSERT INTO db_migrations (version, success) VALUES (?, 0)")
          .bind(crate::VERSION)
          .execute()
          .await;
        return Err(e);
      }
      // Record success
      self
        .client
        .query("INSERT INTO db_migrations (version, success) VALUES (?, 1)")
        .bind(crate::VERSION)
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("failed to record migration success: {}", e))?;
      info!("migration v0.0.1 applied successfully");
    }
    Ok(())
  }

  async fn apply_v0_0_1(&self) -> anyhow::Result<()> {
    // 1. Create table (tcp_log)
    let sql_create = r#"
    CREATE TABLE IF NOT EXISTS tcp_log (
        service     LowCardinality(String),
        conn_ts     DateTime64(3),
        duration    UInt32,
        addr_family Enum8('unix'=1, 'ipv4'=2, 'ipv6'=10),
        ip          IPv6,
        port        UInt16,
        proxy_proto Enum8('None' = 0, 'V1' = 1, 'V2' = 2),
        bytes       UInt64
    ) ENGINE = MergeTree() 
    ORDER BY (service, conn_ts);
    "#;
    self.client.query(sql_create).execute().await?;

    // 2. Create View
    let sql_view_refined = r#"
      CREATE VIEW IF NOT EXISTS tcp_log_view AS
      SELECT 
          service, conn_ts, duration, addr_family,
          multiIf(
            addr_family = 1, 'unix socket',
            addr_family = 2, IPv4NumToString(toIPv4(ip)),
            IPv6NumToString(ip)
          ) as ip_str,
          port,
          proxy_proto,
          formatReadableSize(bytes) AS traffic
      FROM tcp_log
      "#;

    self.client.query(sql_view_refined).execute().await?;

    Ok(())
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
    };

    let mut insert = self.client.insert("tcp_log")?;
    insert.write(&row).await?;
    insert.end().await?;

    Ok(())
  }
}
