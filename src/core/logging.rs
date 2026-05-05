use crate::protocol::{self, ProxyInfo};

pub fn format_connection_log(
  service_name: &str,
  listen_addr: &str,
  src_addr: &str,
  proxy_info: Option<&ProxyInfo>,
  is_untrusted: bool,
  host: Option<&str>,
) -> String {
  let mut extras = Vec::new();

  if let Some(info) = proxy_info {
    let version = match info.version {
      protocol::Version::V1 => "proxy.v1",
      protocol::Version::V2 => "proxy.v2",
    };
    extras.push(format!("{}: {}", version, info.source));
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

  if suffix.is_empty() {
    format!("[{}] {} <- {}", service_name, listen_addr, src_addr)
  } else {
    format!("[{}] {} <- {} {}", service_name, listen_addr, src_addr, suffix)
  }
}
