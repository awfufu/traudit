use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use tokio::fs;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
  pub database: DatabaseConfig,
  pub services: Vec<ServiceConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
  #[serde(rename = "type")]
  #[allow(dead_code)]
  pub db_type: String,
  pub dsn: String,
  pub tables: HashMap<String, String>,
  #[serde(default = "default_batch_size")]
  #[allow(dead_code)]
  pub batch_size: usize,
  #[serde(default = "default_timeout_secs")]
  #[allow(dead_code)]
  pub batch_timeout_secs: u64,
}

fn default_batch_size() -> usize {
  1000
}

fn default_timeout_secs() -> u64 {
  5
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServiceConfig {
  pub name: String,
  #[serde(rename = "type")]
  pub service_type: String,
  pub binds: Vec<BindEntry>,
  #[serde(rename = "forward_to")]
  pub forward_to: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BindEntry {
  pub addr: String,
  #[serde(alias = "proxy_protocol", rename = "proxy")]
  pub proxy: Option<String>,
}

impl Config {
  pub async fn load<P: AsRef<Path>>(path: P) -> Result<Self, anyhow::Error> {
    let content = fs::read_to_string(path).await?;
    let config: Config = serde_yaml::from_str(&content)?;
    Ok(config)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::io::Write;

  #[tokio::test]
  async fn test_load_config() {
    let config_str = r#"
database:
  type: clickhouse
  dsn: "clickhouse://admin:password@127.0.0.1:8123/audit_db"
  batch_size: 50
  batch_timeout_secs: 5
  tables:
    tcp: tcp_log

services:
  - name: "ssh-prod"
    type: "tcp"
    binds:
      - addr: "0.0.0.0:22222"
        proxy: "v2"
    forward_to: "127.0.0.1:22"
"#;
    let mut file = tempfile::NamedTempFile::new().unwrap();
    write!(file, "{}", config_str).unwrap();
    let path = file.path().to_path_buf();

    let config = Config::load(&path).await.expect("Failed to load config");

    assert_eq!(
      config.database.dsn,
      "clickhouse://admin:password@127.0.0.1:8123/audit_db"
    );
    assert_eq!(config.services.len(), 1);
    assert_eq!(config.services[0].name, "ssh-prod");
    assert_eq!(config.services[0].binds[0].addr, "0.0.0.0:22222");
    assert_eq!(config.services[0].binds[0].proxy, Some("v2".to_string()));
    assert_eq!(config.services[0].forward_to, "127.0.0.1:22");
  }
}
