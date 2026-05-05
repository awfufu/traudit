use crate::protocol::{self, ProxyInfo};

pub fn format_connection_log(
  service_name: &str,
  listen_addr: &str,
  src_addr: Option<&str>,
  real_ip_detail: Option<&str>,
  is_untrusted: bool,
  host: Option<&str>,
) -> String {
  let mut extras = Vec::new();

  if let Some(real_ip_detail) = real_ip_detail {
    if !real_ip_detail.is_empty() {
      extras.push(real_ip_detail.to_string());
    }
  }

  if let Some(host) = host {
    if !host.is_empty() {
      extras.push(host.to_string());
    }
  }

  let mut suffix = String::new();
  if is_untrusted {
    suffix.push_str("(untrusted) ");
  }
  if !extras.is_empty() {
    suffix.push('(');
    suffix.push_str(&extras.join(", "));
    suffix.push(')');
  }

  if let Some(src_addr) = src_addr {
    if suffix.is_empty() {
      format!("[{}] {} <- {}", service_name, listen_addr, src_addr)
    } else {
      format!("[{}] {} <- {} {}", service_name, listen_addr, src_addr, suffix)
    }
  } else {
    if suffix.is_empty() {
      format!("[{}] {} <-", service_name, listen_addr)
    } else {
      format!("[{}] {} <- {}", service_name, listen_addr, suffix)
    }
  }
}

pub fn format_proxy_protocol_detail(info: &ProxyInfo) -> String {
  let version = match info.version {
    protocol::Version::V1 => "proxy.v1",
    protocol::Version::V2 => "proxy.v2",
  };
  format!("{}: {}", version, info.source)
}
