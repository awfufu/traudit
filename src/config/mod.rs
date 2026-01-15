use serde::Deserialize;
use std::path::Path;
use tokio::fs;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
  pub database: DatabaseConfig,
  pub services: Vec<ServiceConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
  pub dsn: String,
  #[allow(dead_code)]
  pub batch: BatchConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BatchConfig {
  #[allow(dead_code)]
  pub size: usize,
  #[allow(dead_code)]
  pub timeout_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServiceConfig {
  pub name: String,
  #[allow(dead_code)]
  pub db_table: String,
  pub binds: Vec<BindConfig>,
  pub forward_type: ForwardType,
  pub forward_addr: String,
  #[allow(dead_code)]
  pub forward_proxy_protocol: Option<ProxyProtocolVersion>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BindConfig {
  #[serde(rename = "type")]
  pub bind_type: BindType,
  pub addr: String,
  #[serde(alias = "proxy")]
  pub proxy_protocol: Option<ProxyProtocolVersion>,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BindType {
  Tcp,
  Udp,
  Unix,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ForwardType {
  Tcp,
  Udp,
  Unix,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocolVersion {
  V1,
  V2,
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
  dsn: "clickhouse://admin:password@127.0.0.1:8123/audit_db"
  batch:
    size: 50
    timeout_secs: 5

services:
  - name: "ssh-prod"
    db_table: "ssh_audit_logs"
    binds:
      - type: "tcp"
        addr: "0.0.0.0:22222"
        proxy_protocol: "v2"
    forward_type: "tcp"
    forward_addr: "127.0.0.1:22"
"#;
    let mut file = tempfile::NamedTempFile::new().unwrap();
    write!(file, "{}", config_str).unwrap();
    let path = file.path().to_path_buf();
    // Close the file handle so tokio can read it, or just keep it open and read by path?
    // tempfile deletes on drop. We need to keep `file` alive.

    let config = Config::load(&path).await.expect("Failed to load config");

    assert_eq!(
      config.database.dsn,
      "clickhouse://admin:password@127.0.0.1:8123/audit_db"
    );
    assert_eq!(config.services.len(), 1);
    assert_eq!(config.services[0].name, "ssh-prod");
    assert_eq!(config.services[0].binds[0].bind_type, BindType::Tcp);
    assert_eq!(
      config.services[0].binds[0].proxy_protocol,
      Some(ProxyProtocolVersion::V2)
    );
  }
}
