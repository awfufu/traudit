use bytes::BytesMut;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use traudit::config::{RealIpConfig, RealIpSource};
use traudit::core::server::handler::resolve_real_ip;
use traudit::core::server::stream::InboundStream;
use traudit::protocol::{ProxyInfo, Version};

async fn setup_pair() -> (InboundStream, TcpStream, SocketAddr) {
  let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let addr = listener.local_addr().unwrap();

  let client_join = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });

  let (server_stream, remote_addr) = listener.accept().await.unwrap();
  let client_stream = client_join.await.unwrap();

  (
    InboundStream::Tcp(server_stream),
    client_stream,
    remote_addr,
  )
}

#[tokio::test]
async fn test_resolve_remote_addr() {
  let (mut inbound, _client, remote_addr) = setup_pair().await;
  let mut buffer = BytesMut::new();

  let config = Some(RealIpConfig {
    source: RealIpSource::RemoteAddr,
    trusted_proxies: vec![],
    trust_private_ranges: false,
    xff_trust_depth: 0,
  });

  let (ip, _) = resolve_real_ip(&config, remote_addr, &None, &mut inbound, &mut buffer)
    .await
    .unwrap();
  assert_eq!(ip, remote_addr.ip());
}

#[tokio::test]
async fn test_resolve_proxy_protocol_trusted() {
  let (mut inbound, _client, remote_addr) = setup_pair().await;
  let mut buffer = BytesMut::new();

  // Config trusting 127.0.0.1 (which is the remote_addr here)
  let config = Some(RealIpConfig {
    source: RealIpSource::ProxyProtocol,
    trusted_proxies: vec!["127.0.0.1/32".parse().unwrap()],
    trust_private_ranges: false,
    xff_trust_depth: 0,
  });

  let proxy_info = Some(ProxyInfo {
    version: Version::V2,
    source: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 12345),
  });

  let (ip, port) = resolve_real_ip(&config, remote_addr, &proxy_info, &mut inbound, &mut buffer)
    .await
    .unwrap();
  assert_eq!(ip, Ipv4Addr::new(10, 0, 0, 1));
  assert_eq!(port, 12345);
}

#[tokio::test]
async fn test_resolve_proxy_protocol_untrusted() {
  let (mut inbound, _client, remote_addr) = setup_pair().await;
  let mut buffer = BytesMut::new();

  // Config NOT trusting localhost
  let config = Some(RealIpConfig {
    source: RealIpSource::ProxyProtocol,
    trusted_proxies: vec!["1.2.3.4/32".parse().unwrap()],
    trust_private_ranges: false,
    xff_trust_depth: 0,
  });

  let proxy_info = Some(ProxyInfo {
    version: Version::V2,
    source: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 12345),
  });

  // Should fallback to remote_addr because physical connection is not trusted
  let (ip, _) = resolve_real_ip(&config, remote_addr, &proxy_info, &mut inbound, &mut buffer)
    .await
    .unwrap();
  assert_eq!(ip, remote_addr.ip());
}

#[tokio::test]
async fn test_resolve_xff() {
  let (mut inbound, mut client, remote_addr) = setup_pair().await;
  let mut buffer = BytesMut::new();

  let config = Some(RealIpConfig {
    source: RealIpSource::Xff,
    trusted_proxies: vec!["127.0.0.1/32".parse().unwrap()],
    trust_private_ranges: false,
    xff_trust_depth: 0,
  });

  // Send HTTP Request with XFF
  client
    .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 203.0.113.195\r\n\r\n")
    .await
    .unwrap();

  let (ip, _) = resolve_real_ip(&config, remote_addr, &None, &mut inbound, &mut buffer)
    .await
    .unwrap();
  assert_eq!(ip, "203.0.113.195".parse::<IpAddr>().unwrap());
}

#[tokio::test]
async fn test_resolve_xff_multi() {
  let (mut inbound, mut client, remote_addr) = setup_pair().await;
  let mut buffer = BytesMut::new();

  let config = Some(RealIpConfig {
    source: RealIpSource::Xff,
    trusted_proxies: vec!["127.0.0.1/32".parse().unwrap()],
    trust_private_ranges: false,
    xff_trust_depth: 0,
  });

  // Last one should be picked
  client
    .write_all(b"GET / HTTP/1.1\r\nX-Forwarded-For: 10.0.0.1, 203.0.113.195\r\n\r\n")
    .await
    .unwrap();

  let (ip, _) = resolve_real_ip(&config, remote_addr, &None, &mut inbound, &mut buffer)
    .await
    .unwrap();
  assert_eq!(ip, "203.0.113.195".parse::<IpAddr>().unwrap());
}

#[tokio::test]
async fn test_resolve_combined_proxy_protocol_and_xff() {
  let (mut inbound, mut client, remote_addr) = setup_pair().await;
  let mut buffer = BytesMut::new();

  let config = Some(RealIpConfig {
    source: RealIpSource::Xff,
    trusted_proxies: vec!["10.0.0.2/32".parse().unwrap()], // Trust the Proxy Protocol IP
    trust_private_ranges: false,
    xff_trust_depth: 0,
  });

  // Proxy Protocol says source is 10.0.0.2
  let proxy_info = Some(ProxyInfo {
    version: Version::V2,
    source: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 12345),
  });

  // Send HTTP Request with XFF
  client
    .write_all(b"GET / HTTP/1.1\r\nX-Forwarded-For: 192.168.1.100\r\n\r\n")
    .await
    .unwrap();

  // Logic:
  // 1. Check if current source (10.0.0.2 via ProxyInfo) is trusted? Yes.
  // 2. Peek XFF.
  // 3. Return XFF IP.

  let (ip, _) = resolve_real_ip(&config, remote_addr, &proxy_info, &mut inbound, &mut buffer)
    .await
    .unwrap();
  assert_eq!(ip, "192.168.1.100".parse::<IpAddr>().unwrap());
}

#[tokio::test]
async fn test_resolve_xff_ignore_proxy_ip() {
  let (mut inbound, mut client, remote_addr) = setup_pair().await;
  let mut buffer = BytesMut::new();

  // User wants Real IP from XFF
  let config = Some(RealIpConfig {
    source: RealIpSource::Xff,
    // We trust the IP asserted by the Proxy Protocol (e.g. valid Load Balancer)
    trusted_proxies: vec!["10.0.0.100/32".parse().unwrap()],
    trust_private_ranges: false,
    xff_trust_depth: 0,
  });

  // Simulate Listener claiming it parsed a Proxy V2 Header from 10.0.0.100
  let proxy_info = Some(ProxyInfo {
    version: Version::V2,
    source: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100)), 443),
  });

  // Stream contains HTTP with XFF
  // "Discard" the proxy IP (10.0.0.100), use the XFF IP (1.1.1.1)
  client
    .write_all(b"GET / HTTP/1.1\r\nX-Forwarded-For: 1.1.1.1\r\n\r\n")
    .await
    .unwrap();

  let (ip, _) = resolve_real_ip(&config, remote_addr, &proxy_info, &mut inbound, &mut buffer)
    .await
    .unwrap();
  assert_eq!(ip, "1.1.1.1".parse::<IpAddr>().unwrap());
}
