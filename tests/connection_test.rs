use std::io::Write;
use std::net::SocketAddr;
use std::sync::Once;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::sync::OnceCell;
use tokio::task::JoinHandle;

use clickhouse::Client;
use serde::Deserialize;
use traudit::config::{
  BindEntry, Config, DatabaseConfig, RealIpConfig, RealIpSource, ServiceConfig, TlsConfig,
};

// Testcontainers
use ctor::dtor;
use std::sync::Mutex;
use testcontainers::{clients, GenericImage};

// TLS Dependencies
use rcgen::generate_simple_self_signed;

use std::os::unix::fs::PermissionsExt;

static INIT: Once = Once::new();

// Shared Container Singleton
struct SharedDb {
  port: u16,
}

static SHARED_DB: OnceCell<SharedDb> = OnceCell::const_new();

// Cleanup Info used by dtor
struct CleanupInfo {
  container_id: Option<String>,
  temp_dir: Option<std::path::PathBuf>,
}
static CLEANUP_INFO: Mutex<CleanupInfo> = Mutex::new(CleanupInfo {
  container_id: None,
  temp_dir: None,
});

async fn get_shared_db_port() -> u16 {
  let db = SHARED_DB
    .get_or_init(|| async {
      init_env();

      // Blocking docker interactions
      let port = tokio::task::spawn_blocking(|| {
        let docker = Box::leak(Box::new(clients::Cli::default()));
        let image = GenericImage::new("clickhouse/clickhouse-server", "latest")
          .with_env_var("CLICKHOUSE_DB", "traudit")
          .with_env_var("CLICKHOUSE_USER", "traudit")
          .with_env_var("CLICKHOUSE_PASSWORD", "traudit")
          .with_env_var("CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT", "1");

        let container = docker.run(image);
        let port = container.get_host_port_ipv4(8123);

        // Save ID for cleanup
        if let Ok(mut info) = CLEANUP_INFO.lock() {
          info.container_id = Some(container.id().to_string());
        }

        Box::leak(Box::new(container));
        port
      })
      .await
      .unwrap();

      // Async wait
      wait_for_clickhouse(port).await;

      SharedDb { port }
    })
    .await;

  db.port
}

#[dtor]
fn cleanup() {
  if let Ok(info) = CLEANUP_INFO.lock() {
    // Cleanup Container
    if let Some(id) = &info.container_id {
      // We use standard process command to clean up attached container
      // Try docker first, then podman
      let _ = std::process::Command::new("docker")
        .args(["rm", "-f", id])
        .output();
      let _ = std::process::Command::new("podman")
        .args(["rm", "-f", id])
        .output();
    }

    // Cleanup Temp Dir (shim)
    if let Some(path) = &info.temp_dir {
      let _ = std::fs::remove_dir_all(path);
    }
  }
}

fn init_env() {
  INIT.call_once(|| {
    // Initialize tracing
    tracing_subscriber::fmt()
      .with_env_filter("info")
      .with_test_writer()
      .try_init()
      .ok();

    // Create docker shim for podman if docker is missing
    if std::process::Command::new("docker")
      .arg("-v")
      .output()
      .is_err()
    {
      let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
      let temp_path = temp_dir.path().to_owned();
      let docker_shim = temp_path.join("docker");
      let mut file = std::fs::File::create(&docker_shim).expect("failed to create docker shim");
      file
        .write_all(b"#!/bin/sh\nexec podman \"$@\"")
        .expect("failed to write shim");

      let mut perms = file.metadata().unwrap().permissions();
      perms.set_mode(0o755);
      file.set_permissions(perms).unwrap();

      let path = std::env::var("PATH").unwrap_or_default();
      let new_path = format!("{}:{}", temp_path.display(), path);
      std::env::set_var("PATH", new_path);

      // Persist the temp dir
      let _ = temp_dir.keep();

      // Save for cleanup
      if let Ok(mut info) = CLEANUP_INFO.lock() {
        info.temp_dir = Some(temp_path);
      }
    }
  });
}

// Stream Trait Alias
trait TestStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TestStream for T {}

// Database Helpers

fn get_db_client(port: u16, db_name: &str) -> Client {
  let url = format!("http://127.0.0.1:{}", port);
  Client::default()
    .with_url(&url)
    .with_user("traudit")
    .with_password("traudit")
    .with_database(db_name)
}

async fn wait_for_clickhouse(port: u16) {
  let client = get_db_client(port, "default");
  let mut attempts = 0;
  while attempts < 30 {
    if client.query("SELECT 1").execute().await.is_ok() {
      return;
    }
    tokio::time::sleep(Duration::from_millis(1000)).await;
    attempts += 1;
  }
  panic!("ClickHouse failed to start on port {}", port);
}

#[derive(Debug, Deserialize, clickhouse::Row)]
struct TcpLogCount {
  count: u64,
}

#[derive(Debug, Deserialize, clickhouse::Row)]
struct HttpLogCount {
  count: u64,
}

// Mock Upstream

async fn spawn_mock_upstream() -> (SocketAddr, JoinHandle<()>) {
  let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let addr = listener.local_addr().unwrap();

  let handle = tokio::spawn(async move {
    loop {
      if let Ok((mut socket, _)) = listener.accept().await {
        tokio::spawn(async move {
          let mut buf = [0u8; 4096];
          loop {
            let n = match socket.read(&mut buf).await {
              Ok(n) if n == 0 => return,
              Ok(n) => n,
              Err(_) => return,
            };
            let data = &buf[..n];

            if data.starts_with(b"GET") || data.starts_with(b"POST") {
              let req = String::from_utf8_lossy(data);
              let body = format!("Headers:\n{}", req);
              let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
              );
              let _ = socket.write_all(response.as_bytes()).await;
              return;
            } else {
              let _ = socket.write_all(data).await;
            }
          }
        });
      }
    }
  });

  (addr, handle)
}

// Protocol Helpers

fn build_proxy_v1_header() -> Vec<u8> {
  b"PROXY TCP4 1.1.1.1 2.2.2.2 1234 443\r\n".to_vec()
}

fn build_proxy_v2_header() -> Vec<u8> {
  let mut header = vec![
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x11, 0x00, 0x0C,
  ];
  header.extend_from_slice(&[1, 1, 1, 1]);
  header.extend_from_slice(&[2, 2, 2, 2]);
  header.extend_from_slice(&[0x04, 0xD2]);
  header.extend_from_slice(&[0x01, 0xBB]);
  header
}

// TLS Helpers

struct CertBundle {
  cert_pem: String,
  key_pem: String,
}

fn generate_cert() -> CertBundle {
  let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
  let cert = generate_simple_self_signed(subject_alt_names).unwrap();
  CertBundle {
    cert_pem: cert.serialize_pem().unwrap(),
    key_pem: cert.serialize_private_key_pem(),
  }
}

// Config Builder

struct TestResources {
  config: Config,
  proxy_addr: String,
  #[allow(dead_code)]
  upstream_addr: SocketAddr,
  _cert_file: Option<tempfile::NamedTempFile>,
  _key_file: Option<tempfile::NamedTempFile>,
}

async fn prepare_env(
  service_type: &str,
  proxy_proto: Option<&str>,
  bind_tls: bool,
  real_ip_source: Option<RealIpSource>,
  add_xff: bool,
  is_unix: bool,
  db_port: u16,
  db_name: String,
) -> TestResources {
  let (upstream_addr, _) = spawn_mock_upstream().await;

  let (bind_addr, port_guard, socket_path) = if is_unix {
    let path = format!("/tmp/traudit_test_{}.sock", rand::random::<u64>());
    let _ = std::fs::remove_file(&path);
    (format!("unix://{}", path), None, Some(path))
  } else {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = l.local_addr().unwrap().port();
    (format!("127.0.0.1:{}", p), Some(l), None)
  };
  drop(port_guard);

  let (tls_config, cert_f, key_f) = if bind_tls {
    let bundle = generate_cert();
    let mut cf = tempfile::NamedTempFile::new().unwrap();
    cf.write_all(bundle.cert_pem.as_bytes()).unwrap();
    let mut kf = tempfile::NamedTempFile::new().unwrap();
    kf.write_all(bundle.key_pem.as_bytes()).unwrap();
    (
      Some(TlsConfig {
        cert: cf.path().to_str().unwrap().to_string(),
        key: Some(kf.path().to_str().unwrap().to_string()),
      }),
      Some(cf),
      Some(kf),
    )
  } else {
    (None, None, None)
  };

  let real_ip = real_ip_source.map(|s| RealIpConfig {
    source: s,
    trusted_proxies: vec![],
    trust_private_ranges: true,
    xff_trust_depth: 0,
  });

  let config = Config {
    database: DatabaseConfig {
      db_type: "clickhouse".to_string(),
      dsn: format!("http://traudit:traudit@127.0.0.1:{}/{}", db_port, db_name),
      batch_size: 1,
      batch_timeout_secs: 1,
    },
    services: vec![ServiceConfig {
      name: "test-svc".to_string(),
      service_type: service_type.to_string(),
      forward_to: upstream_addr.to_string(),
      binds: vec![BindEntry {
        addr: bind_addr.clone(),
        mode: 0o777,
        proxy: proxy_proto.map(|s| s.to_string()),
        tls: tls_config,
        real_ip,
        add_xff_header: add_xff,
      }],
    }],
  };

  let proxy_addr_clean = if is_unix {
    socket_path.unwrap()
  } else {
    bind_addr
  };

  TestResources {
    config,
    proxy_addr: proxy_addr_clean,
    upstream_addr,
    _cert_file: cert_f,
    _key_file: key_f,
  }
}

// Scenarios

async fn run_tcp_test(test_name: &str, proxy_proto: Option<&str>, is_unix: bool) {
  // init_env called inside Lazy
  let db_port = get_shared_db_port().await;
  let db_name = test_name.to_string();

  // Create DB
  let system_client = get_db_client(db_port, "default");
  system_client
    .query(&format!("CREATE DATABASE IF NOT EXISTS {}", db_name))
    .execute()
    .await
    .unwrap();

  let client = get_db_client(db_port, &db_name);

  let res = prepare_env(
    "tcp",
    proxy_proto,
    false,
    proxy_proto.map(|_| RealIpSource::ProxyProtocol),
    false,
    is_unix,
    db_port,
    db_name,
  )
  .await;

  tokio::spawn(async move {
    let _ = traudit::core::server::run(res.config).await;
  });
  // Wait for traudit startup and DB connect
  tokio::time::sleep(Duration::from_millis(1000)).await;

  let mut stream: Box<dyn TestStream> = if is_unix {
    Box::new(
      UnixStream::connect(&res.proxy_addr)
        .await
        .expect("Unix connect failed"),
    )
  } else {
    Box::new(
      TcpStream::connect(&res.proxy_addr)
        .await
        .expect("Tcp connect failed"),
    )
  };

  if let Some(p) = proxy_proto {
    if p == "v1" {
      stream.write_all(&build_proxy_v1_header()).await.unwrap();
    } else {
      stream.write_all(&build_proxy_v2_header()).await.unwrap();
    }
  }

  stream.write_all(b"ping").await.unwrap();
  let mut buf = [0u8; 1024];
  let n = stream.read(&mut buf).await.unwrap();
  assert_eq!(&buf[..n], b"ping");

  drop(stream);
  tokio::time::sleep(Duration::from_millis(2000)).await;

  let count = client
    .query("SELECT count() as count FROM tcp_log WHERE service = 'test-svc'")
    .fetch_one::<TcpLogCount>()
    .await
    .unwrap();
  assert_eq!(count.count, 1);

  if is_unix {
    let _ = std::fs::remove_file(&res.proxy_addr);
  }
}

#[tokio::test]
async fn test_tcp_normal() {
  run_tcp_test("test_tcp_normal", None, false).await;
}
#[tokio::test]
async fn test_tcp_proxy_v1() {
  run_tcp_test("test_tcp_proxy_v1", Some("v1"), false).await;
}
#[tokio::test]
async fn test_tcp_proxy_v2() {
  run_tcp_test("test_tcp_proxy_v2", Some("v2"), false).await;
}

#[tokio::test]
async fn test_unix_suite() {
  #[cfg(unix)]
  {
    run_tcp_test("test_unix_normal", None, true).await;
    run_tcp_test("test_unix_proxy_v1", Some("v1"), true).await;
    run_tcp_test("test_unix_proxy_v2", Some("v2"), true).await;
  }
}

async fn run_http_test(
  test_name: &str,
  proxy_proto: Option<&str>,
  use_tls: bool,
  real_ip_source: Option<RealIpSource>,
  add_xff: bool,
  expected_xff_in_upstream: Option<&str>,
) {
  let db_port = get_shared_db_port().await;
  let db_name = test_name.to_string();

  let system_client = get_db_client(db_port, "default");
  system_client
    .query(&format!("CREATE DATABASE IF NOT EXISTS {}", db_name))
    .execute()
    .await
    .unwrap();

  let client = get_db_client(db_port, &db_name);

  let res = prepare_env(
    "http",
    proxy_proto,
    use_tls,
    real_ip_source.clone(),
    add_xff,
    false,
    db_port,
    db_name,
  )
  .await;

  tokio::spawn(async move {
    let _ = traudit::core::server::run(res.config).await;
  });
  tokio::time::sleep(Duration::from_millis(1000)).await;

  if proxy_proto.is_some() {
    let mut stream = TcpStream::connect(&res.proxy_addr).await.unwrap();
    if proxy_proto == Some("v1") {
      stream.write_all(&build_proxy_v1_header()).await.unwrap();
    } else {
      stream.write_all(&build_proxy_v2_header()).await.unwrap();
    }

    if use_tls {
      let mut root_store = rustls::RootCertStore::empty();
      let cert_bytes = tokio::fs::read(res._cert_file.as_ref().unwrap().path())
        .await
        .unwrap();
      let mut pem = std::io::BufReader::new(&cert_bytes[..]);
      let certs = rustls_pemfile::certs(&mut pem)
        .unwrap()
        .into_iter()
        .map(rustls::Certificate)
        .collect::<Vec<_>>();
      root_store.add(&certs[0]).unwrap();

      let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
      let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
      let domain = rustls::ServerName::try_from("localhost").unwrap();
      let mut tls_stream = connector
        .connect(domain, stream)
        .await
        .expect("TLS handshake failed");

      let request = if add_xff || real_ip_source == Some(RealIpSource::Xff) {
        if real_ip_source == Some(RealIpSource::Xff) {
          "GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 8.8.8.8\r\nConnection: close\r\n\r\n"
        } else {
          "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        }
      } else {
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
      };
      tls_stream.write_all(request.as_bytes()).await.unwrap();

      let mut buf = Vec::new();
      tls_stream.read_to_end(&mut buf).await.unwrap();
      let body = String::from_utf8_lossy(&buf).to_string();

      if let Some(expected) = expected_xff_in_upstream {
        assert!(body.contains(expected), "Body: {}", body);
      }
      assert!(body.contains("200 OK"));
    } else {
      let request = if real_ip_source == Some(RealIpSource::Xff) {
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 8.8.8.8\r\nConnection: close\r\n\r\n"
      } else {
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
      };
      stream.write_all(request.as_bytes()).await.unwrap();
      let mut buf = Vec::new();
      stream.read_to_end(&mut buf).await.unwrap();
      let body = String::from_utf8_lossy(&buf).to_string();
      if let Some(expected) = expected_xff_in_upstream {
        assert!(body.contains(expected));
      }
      assert!(body.contains("200 OK"));
    }
  } else {
    let client_builder = reqwest::Client::builder();
    let client_http = if use_tls {
      let cert_bytes = tokio::fs::read(res._cert_file.as_ref().unwrap().path())
        .await
        .unwrap();
      let cert = reqwest::Certificate::from_pem(&cert_bytes).unwrap();
      client_builder
        .add_root_certificate(cert)
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
    } else {
      client_builder.build().unwrap()
    };
    let protocol = if use_tls { "https" } else { "http" };
    let url = format!("{}://{}/", protocol, res.proxy_addr);
    let resp = if real_ip_source == Some(RealIpSource::Xff) {
      client_http
        .get(&url)
        .header("X-Forwarded-For", "8.8.8.8")
        .send()
        .await
        .expect("Req failed")
    } else {
      client_http.get(&url).send().await.expect("Req failed")
    };
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    if let Some(expected) = expected_xff_in_upstream {
      assert!(body.contains(expected));
    }
  }

  tokio::time::sleep(Duration::from_millis(2000)).await;
  let count = client
    .query("SELECT count() as count FROM http_log WHERE service = 'test-svc'")
    .fetch_one::<HttpLogCount>()
    .await
    .unwrap();
  assert_eq!(count.count, 1);
}

#[tokio::test]
async fn test_http_normal() {
  run_http_test("test_http_normal", None, false, None, false, None).await;
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
async fn test_https_normal() {
  run_http_test("test_https_normal", None, true, None, false, None).await;
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
