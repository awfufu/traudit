use serde::{Deserialize, Deserializer};
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
  #[serde(default = "default_socket_mode", deserialize_with = "deserialize_mode")]
  pub mode: u32,
}

fn default_socket_mode() -> u32 {
  0o600
}

fn deserialize_mode<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
  D: Deserializer<'de>,
{
  #[derive(Deserialize)]
  #[serde(untagged)]
  enum ModeValue {
    Integer(u32),
    String(String),
  }

  let value = ModeValue::deserialize(deserializer)?;
  match value {
    ModeValue::Integer(i) => {
      // If user provides 666, they likely mean octal 0666.
      // But in YAML `mode: 666` is decimal 666.
      // The requirement says: "if user wrote integer (e.g. 666), process as octal"
      // So we interpret the decimal value as a sequence of octal digits.
      // e.g. decimal 666 -> octal 666 (which is decimal 438)
      let s = i.to_string();
      u32::from_str_radix(&s, 8).map_err(serde::de::Error::custom)
    }
    ModeValue::String(s) => {
      // If string, parse as octal
      u32::from_str_radix(&s, 8).map_err(serde::de::Error::custom)
    }
  }
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

  #[test]
  fn test_mode_deserialization() {
    #[derive(Deserialize)]
    struct TestBind {
      #[serde(default = "default_socket_mode", deserialize_with = "deserialize_mode")]
      mode: u32,
    }

    let yaml_int = "mode: 666";
    let bind_int: TestBind = serde_yaml::from_str(yaml_int).unwrap();
    assert_eq!(bind_int.mode, 0o666); // 438 decimal

    let yaml_str = "mode: '600'";
    let bind_str: TestBind = serde_yaml::from_str(yaml_str).unwrap();
    assert_eq!(bind_str.mode, 0o600); // 384 decimal

    // Test default
    let yaml_empty = "{}";
    let bind_empty: TestBind = serde_yaml::from_str(yaml_empty).unwrap();
    assert_eq!(bind_empty.mode, 0o600);
  }
}
