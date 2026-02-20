use serde::{Deserialize, Deserializer};
use std::collections::HashSet;
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
  pub forward_to: Option<String>,
  #[serde(rename = "upstream_proxy")]
  pub upstream_proxy: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RedirectHttpsConfig {
  pub enabled: bool,
  pub code: u16,
  pub port: u16,
}

#[derive(Debug, Deserialize)]
struct RedirectHttpsConfigObject {
  enabled: bool,
  #[serde(default = "default_redirect_code")]
  code: u16,
  #[serde(default = "default_redirect_port")]
  port: u16,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RedirectHttpsConfigRaw {
  Bool(bool),
  Object(RedirectHttpsConfigObject),
}

impl Default for RedirectHttpsConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      code: default_redirect_code(),
      port: default_redirect_port(),
    }
  }
}

impl<'de> Deserialize<'de> for RedirectHttpsConfig {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    let raw = RedirectHttpsConfigRaw::deserialize(deserializer)?;
    Ok(match raw {
      RedirectHttpsConfigRaw::Bool(enabled) => Self {
        enabled,
        code: default_redirect_code(),
        port: default_redirect_port(),
      },
      RedirectHttpsConfigRaw::Object(obj) => Self {
        enabled: obj.enabled,
        code: obj.code,
        port: obj.port,
      },
    })
  }
}

fn default_redirect_code() -> u16 {
  308
}

fn default_redirect_port() -> u16 {
  443
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
            // fc00::/7 (unique local) and fe80::/10 (link-local)
            (addr.segments()[0] & 0xfe00) == 0xfc00 || (addr.segments()[0] & 0xffc0) == 0xfe80
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
  #[serde(default)]
  pub add_xff_header: bool,
  #[serde(default)]
  pub redirect_https: RedirectHttpsConfig,
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
      // Interpret decimal integer as octal (e.g., 666 -> 0666)
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
    let content = fs::read_to_string(&path).await?;
    let deserializer = serde_yaml::Deserializer::from_str(&content);

    // Track unknown fields
    let mut unused = Vec::new();
    let config: Config = serde_ignored::deserialize(deserializer, |path| {
      unused.push(path.to_string());
    })
    .map_err(|e| anyhow::anyhow!("failed to parse config: {}", e))?;

    if !unused.is_empty() {
      let fields = unused.join(", ");
      anyhow::bail!(
        "configuration contains unknown or misplaced fields: [{}] in {}",
        fields,
        path.as_ref().display()
      );
    }

    // Semantic validation
    config.validate()?;

    Ok(config)
  }

  pub fn validate(&self) -> anyhow::Result<()> {
    let mut seen_service_names = HashSet::new();
    for service in &self.services {
      if !seen_service_names.insert(service.name.as_str()) {
        anyhow::bail!(
          "duplicate service name '{}' found. Service names must be unique.",
          service.name
        );
      }

      let needs_backend = match service.service_type.as_str() {
        "tcp" => true,
        "http" => service.binds.iter().any(|b| !b.redirect_https.enabled),
        _ => true,
      };

      if needs_backend && service.forward_to.is_none() {
        anyhow::bail!(
          "Service '{}' requires 'forward_to'. For type '{}' this is required unless all HTTP binds are redirect-only.",
          service.name,
          service.service_type
        );
      }

      for bind in &service.binds {
        if bind.redirect_https.enabled {
          if service.service_type != "http" {
            anyhow::bail!(
              "Service '{}' bind '{}' enables 'redirect_https', but this is only valid for type 'http'.",
              service.name,
              bind.addr
            );
          }

          if bind.tls.is_some() {
            anyhow::bail!(
              "Service '{}' bind '{}' enables 'redirect_https' and 'tls' together. Redirect-to-HTTPS must be configured on non-TLS HTTP binds.",
              service.name,
              bind.addr
            );
          }

          if !(300..=399).contains(&bind.redirect_https.code) {
            anyhow::bail!(
              "Service '{}' bind '{}' has invalid 'redirect_https.code' {}. Expected 3xx status code.",
              service.name,
              bind.addr,
              bind.redirect_https.code
            );
          }
        }

        if let Some(real_ip) = &bind.real_ip {
          // Rule 1: TCP services cannot use XFF as they don't parse HTTP headers
          if service.service_type == "tcp" && real_ip.source == RealIpSource::Xff {
            anyhow::bail!(
               "Service '{}' is type 'tcp', but bind '{}' is configured to use 'xff' for real_ip. TCP services cannot parse HTTP headers.",
               service.name,
               bind.addr
             );
          }

          // Rule 2: ProxyProtocol requires proxy protocol support enabled
          if bind.proxy.is_none() && real_ip.source == RealIpSource::ProxyProtocol {
            anyhow::bail!(
               "Service '{}' bind '{}' requests real_ip from 'proxy_protocol', but proxy protocol support is not enabled (missing 'proxy: v1/v2').",
               service.name,
               bind.addr
             );
          }
        }

        // Rule 3: Avoid XFF loops (adding header + using header as source)
        if bind.add_xff_header {
          if let Some(real_ip) = &bind.real_ip {
            if real_ip.source == RealIpSource::Xff {
              anyhow::bail!(
                 "Service '{}' bind '{}' has 'add_xff_header: true' but 'real_ip.from' is 'xff'. This is not allowed as it would duplicate the IP.",
                 service.name,
                 bind.addr
               );
            }
          }
        }
      }

      if let Some(upstream_proxy) = &service.upstream_proxy {
        if service.forward_to.is_none() {
          anyhow::bail!(
            "Service '{}' sets 'upstream_proxy' but has no 'forward_to'.",
            service.name
          );
        }

        match upstream_proxy.as_str() {
          "v1" | "v2" => {},
          other => anyhow::bail!(
            "Service '{}' has invalid 'upstream_proxy' value '{}'. Allowed values are 'v1' or 'v2'.",
            service.name,
            other
          ),
        }
      }
    }
    Ok(())
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
    assert_eq!(config.services[0].forward_to, Some("127.0.0.1:22".to_string()));
    assert_eq!(config.services[0].upstream_proxy, None);
  }

  #[test]
  fn test_redirect_https_bool_and_object() {
    #[derive(Deserialize)]
    struct TestBind {
      #[serde(default)]
      redirect_https: RedirectHttpsConfig,
    }

    let yaml_bool = "redirect_https: true";
    let bind_bool: TestBind = serde_yaml::from_str(yaml_bool).unwrap();
    assert!(bind_bool.redirect_https.enabled);
    assert_eq!(bind_bool.redirect_https.code, 308);
    assert_eq!(bind_bool.redirect_https.port, 443);

    let yaml_obj = "redirect_https:\n  enabled: true\n  code: 301\n  port: 8443\n";
    let bind_obj: TestBind = serde_yaml::from_str(yaml_obj).unwrap();
    assert!(bind_obj.redirect_https.enabled);
    assert_eq!(bind_obj.redirect_https.code, 301);
    assert_eq!(bind_obj.redirect_https.port, 8443);
  }

  #[tokio::test]
  async fn test_http_redirect_only_can_omit_forward_to() {
    let config_str = r#"
database:
  type: clickhouse
  dsn: "clickhouse://admin:password@127.0.0.1:8123/audit_db"

services:
  - name: "redirect-only"
    type: "http"
    binds:
      - addr: "0.0.0.0:80"
        redirect_https: true
"#;
    let mut file = tempfile::NamedTempFile::new().unwrap();
    write!(file, "{}", config_str).unwrap();
    let path = file.path().to_path_buf();

    let config = Config::load(&path).await.expect("Failed to load config");
    assert_eq!(config.services[0].forward_to, None);
  }

  #[tokio::test]
  async fn test_http_non_redirect_bind_requires_forward_to() {
    let config_str = r#"
database:
  type: clickhouse
  dsn: "clickhouse://admin:password@127.0.0.1:8123/audit_db"

services:
  - name: "http-no-backend"
    type: "http"
    binds:
      - addr: "0.0.0.0:8080"
"#;
    let mut file = tempfile::NamedTempFile::new().unwrap();
    write!(file, "{}", config_str).unwrap();
    let path = file.path().to_path_buf();

    let err = Config::load(&path).await.unwrap_err();
    assert!(err.to_string().contains("requires 'forward_to'"));
  }

  #[tokio::test]
  async fn test_redirect_https_rejects_tls_same_bind() {
    let config_str = r#"
database:
  type: clickhouse
  dsn: "clickhouse://admin:password@127.0.0.1:8123/audit_db"

services:
  - name: "bad-redirect-tls"
    type: "http"
    binds:
      - addr: "0.0.0.0:443"
        tls:
          cert: "/tmp/cert.pem"
          key: "/tmp/key.pem"
        redirect_https: true
    forward_to: "127.0.0.1:8080"
"#;
    let mut file = tempfile::NamedTempFile::new().unwrap();
    write!(file, "{}", config_str).unwrap();
    let path = file.path().to_path_buf();

    let err = Config::load(&path).await.unwrap_err();
    assert!(err.to_string().contains("'redirect_https' and 'tls' together"));
  }

  #[tokio::test]
  async fn test_redirect_https_requires_http_service() {
    let config_str = r#"
database:
  type: clickhouse
  dsn: "clickhouse://admin:password@127.0.0.1:8123/audit_db"

services:
  - name: "bad-redirect-tcp"
    type: "tcp"
    binds:
      - addr: "0.0.0.0:2222"
        redirect_https: true
    forward_to: "127.0.0.1:22"
"#;
    let mut file = tempfile::NamedTempFile::new().unwrap();
    write!(file, "{}", config_str).unwrap();
    let path = file.path().to_path_buf();

    let err = Config::load(&path).await.unwrap_err();
    assert!(err.to_string().contains("only valid for type 'http'"));
  }

  #[tokio::test]
  async fn test_redirect_https_code_must_be_3xx() {
    let config_str = r#"
database:
  type: clickhouse
  dsn: "clickhouse://admin:password@127.0.0.1:8123/audit_db"

services:
  - name: "bad-redirect-code"
    type: "http"
    binds:
      - addr: "0.0.0.0:80"
        redirect_https:
          enabled: true
          code: 200
"#;
    let mut file = tempfile::NamedTempFile::new().unwrap();
    write!(file, "{}", config_str).unwrap();
    let path = file.path().to_path_buf();

    let err = Config::load(&path).await.unwrap_err();
    assert!(err.to_string().contains("Expected 3xx status code"));
  }

  #[tokio::test]
  async fn test_duplicate_service_names_not_allowed() {
    let config_str = r#"
database:
  type: clickhouse
  dsn: "clickhouse://admin:password@127.0.0.1:8123/audit_db"

services:
  - name: "dup"
    type: "tcp"
    forward_to: "127.0.0.1:22"
    binds:
      - addr: "0.0.0.0:2201"

  - name: "dup"
    type: "tcp"
    forward_to: "127.0.0.1:22"
    binds:
      - addr: "0.0.0.0:2202"
"#;
    let mut file = tempfile::NamedTempFile::new().unwrap();
    write!(file, "{}", config_str).unwrap();
    let path = file.path().to_path_buf();

    let err = Config::load(&path).await.unwrap_err();
    assert!(err.to_string().contains("duplicate service name"));
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
