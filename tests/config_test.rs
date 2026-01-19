use std::io::Write;
use traudit::config::{Config, RealIpConfig};

#[tokio::test]
async fn test_error_on_unknown_fields() {
  let config_str = r#"
database:
  type: clickhouse
  dsn: "http://127.0.0.1:8123"
  unknown_db_field: "should_error"
services: []
unknown_root_field: "should_also_error"
"#;
  let mut file = tempfile::NamedTempFile::new().unwrap();
  write!(file, "{}", config_str).unwrap();
  let path = file.path().to_path_buf();

  // Init tracing optional
  let _ = tracing_subscriber::fmt::try_init();

  // Expect ERROR
  let res = Config::load(&path).await;
  assert!(res.is_err());
  let err = res.err().unwrap().to_string();
  assert!(err.contains("unknown or misplaced fields"));
  assert!(err.contains("unknown_db_field"));
  assert!(err.contains("unknown_root_field"));
}

#[tokio::test]
async fn test_error_tcp_xff() {
  let config_str = r#"
database:
  type: clickhouse
  dsn: "http://127.0.0.1:8123"
services:
  - name: "bad-service"
    type: "tcp"
    forward_to: "127.0.0.1:22"
    binds:
      - addr: "0.0.0.0:8000"
        real_ip:
          from: "xff"
"#;
  let mut file = tempfile::NamedTempFile::new().unwrap();
  write!(file, "{}", config_str).unwrap();
  let path = file.path().to_path_buf();

  let res = Config::load(&path).await;
  assert!(res.is_err());
  let err = res.err().unwrap().to_string();
  assert!(err.contains("TCP services cannot parse HTTP headers"));
}

#[tokio::test]
async fn test_error_proxy_mismatch() {
  let config_str = r#"
database:
  type: clickhouse
  dsn: "http://127.0.0.1:8123"
services:
  - name: "bad-proxy"
    type: "tcp"
    forward_to: "127.0.0.1:22"
    binds:
      - addr: "0.0.0.0:8000"
        # proxy: v2 IS MISSING
        real_ip:
          from: "proxy_protocol"
"#;
  let mut file = tempfile::NamedTempFile::new().unwrap();
  write!(file, "{}", config_str).unwrap();
  let path = file.path().to_path_buf();

  let res = Config::load(&path).await;
  assert!(res.is_err());
  let err = res.err().unwrap().to_string();
  assert!(err.contains("proxy protocol support is not enabled"));
}

#[test]
fn test_trusted_proxies_mixed_formats() {
  let yaml = r#"
        from: "xff"
        trusted_proxies:
          - "1.2.3.4"
          - "10.0.0.0/24"
          - "2001:db8::/32"
    "#;

  let config: RealIpConfig = serde_yaml::from_str(yaml).expect("Failed to parse config");

  // 1. Exact IP match
  assert!(config.is_trusted("1.2.3.4".parse().unwrap()));

  // 2. CIDR Range match (10.0.0.1 is in 10.0.0.0/24)
  assert!(config.is_trusted("10.0.0.1".parse().unwrap()));
  assert!(config.is_trusted("10.0.0.254".parse().unwrap()));

  // 3. IPv6 CIDR match
  assert!(config.is_trusted("2001:db8::1".parse().unwrap()));

  // 4. Negative cases
  assert!(!config.is_trusted("1.2.3.5".parse().unwrap())); // Wrong IP
  assert!(!config.is_trusted("10.0.1.1".parse().unwrap())); // Outside /24
  assert!(!config.is_trusted("2001:db9::1".parse().unwrap())); // Outside /32
}

#[tokio::test]
async fn test_error_xff_loop() {
  let config_str = r#"
database:
  type: clickhouse
  dsn: "http://127.0.0.1:8123"
services:
  - name: "loop-service"
    type: "http"
    forward_to: "127.0.0.1:8080"
    binds:
      - addr: "0.0.0.0:443"
        proxy: v2
        add_xff_header: true
        real_ip:
          from: "xff"
"#;
  let mut file = tempfile::NamedTempFile::new().unwrap();
  write!(file, "{}", config_str).unwrap();
  let path = file.path().to_path_buf();

  let res = Config::load(&path).await;
  assert!(res.is_err());
  let err = res.err().unwrap().to_string();
  assert!(err.contains("duplicate the IP"));
}
