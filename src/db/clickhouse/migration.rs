use anyhow::Result;
use clickhouse::Client;
use tracing::info;

pub const VERSION_LIST: &[&str] = &[
  "v0.0.2", // add http_log table
  "v0.0.3", // add bytes_sent/bytes_recv for tcp_log
];

pub struct Migrator {
  client: Client,
}

impl Migrator {
  pub fn new(client: Client) -> Self {
    Self { client }
  }

  pub async fn run(&self) -> Result<()> {
    self.ensure_migration_table().await?;

    let current_version = self.get_current_version().await?;
    let target_version = VERSION_LIST.last().unwrap();

    if current_version.is_none() {
      // Fresh install: Bootstrap directly to latest
      info!(
        "fresh install detected, bootstrapping to {}",
        target_version
      );
      self.bootstrap_latest().await?;
      self.record_migration(target_version).await?;
      return Ok(());
    }

    let current_ver_str = current_version.unwrap();

    // Iterative upgrade
    for &version in VERSION_LIST {
      if version > current_ver_str.as_str() {
        info!("migrating database from {} to {}", current_ver_str, version);
        match version {
          "v0.0.2" => self.migrate_v0_0_2().await?,
          "v0.0.3" => self.migrate_v0_0_3().await?,
          _ => {}
        }
        self.record_migration(version).await?;
      }
    }

    Ok(())
  }

  async fn ensure_migration_table(&self) -> Result<()> {
    self
      .client
      .query(
        "CREATE TABLE IF NOT EXISTS db_migrations (
                    version String,
                    success UInt8,
                    apply_ts DateTime64 DEFAULT now()
                ) ENGINE = ReplacingMergeTree(apply_ts)
                ORDER BY version",
      )
      .execute()
      .await
      .map_err(|e| anyhow::anyhow!("failed to create migrations table: {}", e))
  }

  async fn get_current_version(&self) -> Result<Option<String>> {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct MigrationRow {
      version: String,
      success: u8,
    }

    let row = self
      .client
      .query("SELECT version, success FROM db_migrations ORDER BY apply_ts DESC LIMIT 1")
      .fetch_optional::<MigrationRow>()
      .await
      .map_err(|e| anyhow::anyhow!("failed to fetch version: {}", e))?;

    if let Some(r) = row {
      if r.success == 1 {
        return Ok(Some(r.version));
      }
    }
    Ok(None)
  }

  async fn record_migration(&self, version: &str) -> Result<()> {
    self
      .client
      .query("INSERT INTO db_migrations (version, success) VALUES (?, 1)")
      .bind(version)
      .execute()
      .await
      .map_err(|e| anyhow::anyhow!("failed to record migration: {}", e))
  }

  // ==========================================
  // Bootstrap (Create Latest Schema directly)
  // ==========================================
  async fn bootstrap_latest(&self) -> Result<()> {
    // v0.0.3 Schema
    let sql_create_tcp = r#"
        CREATE TABLE IF NOT EXISTS tcp_log (
            service     LowCardinality(String),
            conn_ts     DateTime64(3),
            duration    UInt32,
            addr_family Enum8('unix'=1, 'ipv4'=2, 'ipv6'=10),
            ip          IPv6,
            port        UInt16,
            proxy_proto Enum8('None' = 0, 'V1' = 1, 'V2' = 2),
            bytes       UInt64,
            bytes_sent  UInt64, 
            bytes_recv  UInt64
        ) ENGINE = MergeTree() 
        ORDER BY (service, conn_ts);
        "#;
    self.client.query(sql_create_tcp).execute().await?;

    let sql_view_tcp = r#"
        CREATE OR REPLACE VIEW tcp_log_view AS
        SELECT 
            service, conn_ts, duration, addr_family,
            multiIf(
                addr_family = 'unix', 'unix socket',
                addr_family = 'ipv4', IPv4NumToString(toIPv4(ip)),
                IPv6NumToString(ip)
            ) as ip_str,
            port,
            proxy_proto,
            formatReadableSize(bytes) AS traffic,
            formatReadableSize(bytes_sent) AS traffic_sent,
            formatReadableSize(bytes_recv) AS traffic_recv
        FROM tcp_log
        "#;
    self.client.query(sql_view_tcp).execute().await?;

    // HTTP Table (Unchanged from v0.0.2 plan but good to include)
    let sql_create_http = r#"
        CREATE TABLE IF NOT EXISTS http_log (
            service     LowCardinality(String) CODEC(ZSTD(1)),
            conn_ts     DateTime64(3) CODEC(Delta, ZSTD(1)),
            duration    UInt32,
            addr_family Enum8('unix'=1, 'ipv4'=2, 'ipv6'=10),
            ip          IPv6,
            proxy_proto Enum8('None' = 0, 'V1' = 1, 'V2' = 2),
            resp_body_size  UInt64,
            req_body_size   UInt64,
            status_code UInt16,
            method      LowCardinality(String),
            host        LowCardinality(String),
            path        String CODEC(ZSTD(1)),
            user_agent  String CODEC(ZSTD(1))
        ) ENGINE = MergeTree()
        PARTITION BY toYYYYMM(conn_ts)
        ORDER BY (conn_ts, service, host);
        "#;
    self.client.query(sql_create_http).execute().await?;

    Ok(())
  }

  // Individual Migrations

  async fn migrate_v0_0_2(&self) -> Result<()> {
    // Baseline schema (tcp_log, http_log)
    let sql_create_tcp = r#"
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
    self.client.query(sql_create_tcp).execute().await?;

    // ... HTTP table etc normally goes here
    Ok(())
  }

  async fn migrate_v0_0_3(&self) -> Result<()> {
    // ADD columns
    let _ = self
      .client
      .query("ALTER TABLE tcp_log ADD COLUMN IF NOT EXISTS bytes_sent UInt64 DEFAULT 0")
      .execute()
      .await;
    let _ = self
      .client
      .query("ALTER TABLE tcp_log ADD COLUMN IF NOT EXISTS bytes_recv UInt64 DEFAULT 0")
      .execute()
      .await;

    // Update View
    let sql_view_tcp = r#"
        CREATE OR REPLACE VIEW tcp_log_view AS
        SELECT 
            service, conn_ts, duration, addr_family,
            multiIf(
                addr_family = 'unix', 'unix socket',
                addr_family = 'ipv4', IPv4NumToString(toIPv4(ip)),
                IPv6NumToString(ip)
            ) as ip_str,
            port,
            proxy_proto,
            formatReadableSize(bytes) AS traffic,
            formatReadableSize(bytes_sent) AS traffic_sent,
            formatReadableSize(bytes_recv) AS traffic_recv
        FROM tcp_log
        "#;
    self.client.query(sql_view_tcp).execute().await?;

    Ok(())
  }
}
