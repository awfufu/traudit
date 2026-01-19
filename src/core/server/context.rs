use crate::protocol::ProxyInfo;
use std::net::SocketAddr;

#[derive(Clone, Debug)]
pub struct ConnectionMetadata {
  pub physical_addr: SocketAddr,
  pub proxy_info: Option<ProxyInfo>,
}

tokio::task_local! {
  pub static CONNECTION_META: ConnectionMetadata;
}
