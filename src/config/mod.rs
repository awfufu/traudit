use serde::{Deserialize, Deserializer};
use std::net::IpAddr;
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
  #[allow(dead_code)]
  pub service_type: String,
  pub binds: Vec<BindEntry>,
  #[serde(rename = "forward_to")]
  pub forward_to: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RealIpConfig {
  #[serde(default, rename = "from")]
  pub source: RealIpSource,
  #[serde(default, deserialize_with = "deserialize_trusted_proxies")]
  pub trusted_proxies: Vec<ipnet::IpNet>,
  #[serde(default)]
  pub trust_private_ranges: bool,
  #[serde(default)]
  pub xff_trust_depth: usize,
}

impl RealIpConfig {
  pub fn is_trusted(&self, ip: IpAddr) -> bool {
    // Check explicit trusted proxies
    for net in &self.trusted_proxies {
      if net.contains(&ip) {
        return true;
      }
    }

    if self.trust_private_ranges && is_private(&ip) {
      return true;
    }

    false
  }
}

fn is_private(ip: &IpAddr) -> bool {
  match ip {
    IpAddr::V4(addr) => addr.is_loopback() || addr.is_link_local() || addr.is_private(),
    IpAddr::V6(addr) => {
      addr.is_loopback() ||
            // addr.is_unique_local() is unstable, check ranges manually
            // fc00::/7
            (addr.segments()[0] & 0xfe00) == 0xfc00 ||
            // fe80::/10
            (addr.segments()[0] & 0xffc0) == 0xfe80
    }
  }
}

#[derive(Debug, Deserialize, Clone, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RealIpSource {
  ProxyProtocol,
  Xff,
  #[default]
  RemoteAddr,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BindEntry {
  pub addr: String,
  #[serde(alias = "proxy_protocol", rename = "proxy")]
  pub proxy: Option<String>,
  #[serde(default = "default_socket_mode", deserialize_with = "deserialize_mode")]
  pub mode: u32,
  pub tls: Option<TlsConfig>,
  pub real_ip: Option<RealIpConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TlsConfig {
  pub cert: String,
  pub key: Option<String>,
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
      // Interpret decimal integer as octal (e.g., 666 -> 0666) per requirements.
      let s = i.to_string();
      u32::from_str_radix(&s, 8).map_err(serde::de::Error::custom)
    }
    ModeValue::String(s) => {
      // If string, parse as octal
      u32::from_str_radix(&s, 8).map_err(serde::de::Error::custom)
    }
  }
}

fn deserialize_trusted_proxies<'de, D>(deserializer: D) -> Result<Vec<ipnet::IpNet>, D::Error>
where
  D: Deserializer<'de>,
{
  let strings: Vec<String> = Vec::deserialize(deserializer)?;
  let mut nets = Vec::with_capacity(strings.len());
  for s in strings {
    if let Ok(net) = s.parse::<ipnet::IpNet>() {
      nets.push(net);
    } else if let Ok(ip) = s.parse::<std::net::IpAddr>() {
      nets.push(ipnet::IpNet::from(ip));
    } else {
      return Err(serde::de::Error::custom(format!(
        "invalid IP address or CIDR: {}",
        s
      )));
    }
  }
  Ok(nets)
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
