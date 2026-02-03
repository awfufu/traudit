use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use traudit::config::{
  BindEntry, Config, DatabaseConfig, RealIpConfig, RealIpSource, ServiceConfig,
};

mod common;
use common::*;

#[tokio::test]
async fn test_tcp_proxy_v1() {
  run_tcp_test("test_tcp_proxy_v1", Some("v1"), false).await;
}
#[tokio::test]
async fn test_tcp_proxy_v2() {
  run_tcp_test("test_tcp_proxy_v2", Some("v2"), false).await;
}

#[tokio::test]
async fn test_http_proxy_v1() {
  run_http_test(
    "test_http_proxy_v1",
    Some("v1"),
    false,
    Some(RealIpSource::ProxyProtocol),
    false,
    None,
  )
  .await;
}
#[tokio::test]
async fn test_http_proxy_v2() {
  run_http_test(
    "test_http_proxy_v2",
    Some("v2"),
    false,
    Some(RealIpSource::ProxyProtocol),
    false,
    None,
  )
  .await;
}
#[tokio::test]
async fn test_http_xff_source() {
  run_http_test(
    "test_http_xff_source",
    None,
    false,
    Some(RealIpSource::Xff),
    false,
    None,
  )
  .await;
}
#[tokio::test]
async fn test_http_append_xff() {
  run_http_test(
    "test_http_append_xff",
    None,
    false,
    None,
    true,
    Some("X-Forwarded-For: 127.0.0.1"),
  )
  .await;
}
#[tokio::test]
async fn test_http_v1_append_xff() {
  run_http_test(
    "test_http_v1_append_xff",
    Some("v1"),
    false,
    Some(RealIpSource::ProxyProtocol),
    true,
    Some("X-Forwarded-For: 1.1.1.1"),
  )
  .await;
}
#[tokio::test]
async fn test_http_v2_append_xff() {
  run_http_test(
    "test_http_v2_append_xff",
    Some("v2"),
    false,
    Some(RealIpSource::ProxyProtocol),
    true,
    Some("X-Forwarded-For: 1.1.1.1"),
  )
  .await;
}

#[tokio::test]
async fn test_https_proxy_v1() {
  run_http_test(
    "test_https_proxy_v1",
    Some("v1"),
    true,
    Some(RealIpSource::ProxyProtocol),
    false,
    None,
  )
  .await;
}
#[tokio::test]
async fn test_https_proxy_v2() {
  run_http_test(
    "test_https_proxy_v2",
    Some("v2"),
    true,
    Some(RealIpSource::ProxyProtocol),
    false,
    None,
  )
  .await;
}
#[tokio::test]
async fn test_https_xff_source() {
  run_http_test(
    "test_https_xff_source",
    None,
    true,
    Some(RealIpSource::Xff),
    false,
    None,
  )
  .await;
}
#[tokio::test]
async fn test_https_append_xff() {
  run_http_test(
    "test_https_append_xff",
    None,
    true,
    None,
    true,
    Some("X-Forwarded-For: 127.0.0.1"),
  )
  .await;
}
#[tokio::test]
async fn test_https_v1_append_xff() {
  run_http_test(
    "test_https_v1_append_xff",
    Some("v1"),
    true,
    Some(RealIpSource::ProxyProtocol),
    true,
    Some("X-Forwarded-For: 1.1.1.1"),
  )
  .await;
}
#[tokio::test]
async fn test_https_v2_append_xff() {
  run_http_test(
    "test_https_v2_append_xff",
    Some("v2"),
    true,
    Some(RealIpSource::ProxyProtocol),
    true,
    Some("X-Forwarded-For: 1.1.1.1"),
  )
  .await;
}

// Helper for Chain Test
// Helper for Chain Test
struct ChainTestResources {
  config: Config,
  e1_addr: String,
  #[allow(dead_code)]
  e4_upstream_addr: SocketAddr,
}

async fn prepare_chain_env() -> ChainTestResources {
  // E4 Upstream (Mock Server)
  let (e4_upstream_addr, _) = spawn_mock_upstream().await;

  // Use Unix sockets to avoid port collisions/stealing
  let suffix = rand::random::<u64>();
  let addr1 = format!("unix:///tmp/traudit_e1_{}.sock", suffix);
  let addr2 = format!("unix:///tmp/traudit_e2_{}.sock", suffix);
  let addr3 = format!("unix:///tmp/traudit_e3_{}.sock", suffix);
  let addr4 = format!("unix:///tmp/traudit_e4_{}.sock", suffix);

  // DB Config
  let db_port = get_shared_db_port().await;
  let db_config = DatabaseConfig {
    db_type: "clickhouse".to_string(),
    dsn: format!("http://traudit:traudit@127.0.0.1:{}/chain_test", db_port),
    batch_size: 1,
    batch_timeout_secs: 1,
  };

  // Create DB
  let system_client = get_db_client(db_port, "default");
  let _ = system_client
    .query("CREATE DATABASE IF NOT EXISTS chain_test")
    .execute()
    .await;

  // REAL IP CONFIG (Trust Proxy Protocol)
  let real_ip_pp = Some(RealIpConfig {
    source: RealIpSource::ProxyProtocol,
    trusted_proxies: vec![],
    trust_private_ranges: true, // Trusted because test runs on loopback
    xff_trust_depth: 0,
  });

  // Services
  let services = vec![
    // E1: Entry (No Proxy In, Upstream Proxy V1)
    ServiceConfig {
      name: "e1".to_string(),
      service_type: "tcp".to_string(),
      binds: vec![BindEntry {
        addr: addr1.clone(),
        mode: 0o777,
        proxy: None,
        tls: None,
        add_xff_header: false,
        real_ip: None,
      }],
      forward_to: addr2.clone(),
      upstream_proxy: Some("v1".to_string()),
    },
    // E2: (Proxy V1 In, Upstream Proxy V2)
    ServiceConfig {
      name: "e2".to_string(),
      service_type: "tcp".to_string(),
      binds: vec![BindEntry {
        addr: addr2.clone(),
        mode: 0o777,
        proxy: Some("v1".to_string()),
        tls: None,
        add_xff_header: false,
        real_ip: real_ip_pp.clone(),
      }],
      forward_to: addr3.clone(),
      upstream_proxy: Some("v2".to_string()),
    },
    // E3: (Proxy V2 In, Upstream Proxy V1)
    ServiceConfig {
      name: "e3".to_string(),
      service_type: "tcp".to_string(),
      binds: vec![BindEntry {
        addr: addr3.clone(),
        mode: 0o777,
        proxy: Some("v2".to_string()),
        tls: None,
        add_xff_header: false,
        real_ip: real_ip_pp.clone(),
      }],
      forward_to: addr4.clone(),
      upstream_proxy: Some("v1".to_string()),
    },
    // E4: (Proxy V1 In, No Upstream Proxy -> Mock Server)
    ServiceConfig {
      name: "e4".to_string(),
      service_type: "tcp".to_string(),
      binds: vec![BindEntry {
        addr: addr4.clone(),
        mode: 0o777,
        proxy: Some("v1".to_string()),
        tls: None,
        add_xff_header: false,
        real_ip: real_ip_pp.clone(),
      }],
      forward_to: e4_upstream_addr.to_string(),
      upstream_proxy: None,
    },
  ];

  let config = Config {
    database: db_config,
    services,
  };

  ChainTestResources {
    config,
    e1_addr: addr1,
    e4_upstream_addr,
  }
}

#[tokio::test]
async fn test_proxy_chain() {
  let res = prepare_chain_env().await;

  tokio::spawn(async move {
    let (tx, _rx) = tokio::sync::broadcast::channel(1);
    let _ = traudit::core::server::run(res.config, tx).await;
  });
  tokio::time::sleep(Duration::from_millis(2000)).await;

  // Connect to E1 (Unix)
  let path = res.e1_addr.strip_prefix("unix://").unwrap();
  let mut stream = tokio::net::UnixStream::connect(path)
    .await
    .expect("Failed to connect to E1");

  // Send data
  stream.write_all(b"chain_test_ping").await.unwrap();

  // Read response
  let mut buf = [0u8; 1024];
  let n = stream.read(&mut buf).await.unwrap();
  let response = &buf[..n];

  // The mock upstream echoes "chain_test_ping" (since it doesn't match GET/POST)
  assert_eq!(
    response, b"chain_test_ping",
    "Chain test failed: response mismatch"
  );

  // Cleanup E1 socket (others are cleaned up by server, but E1 we explicitly connected to)
  // Actually all are cleaned up by server::run when it drops listener.
  // We don't need manual cleanup here unless we want to be pedantic.
}
