use crate::config::{RealIpSource, ServiceConfig};
use crate::db::clickhouse::{ClickHouseLogger, HttpLog, HttpMethod};
use async_trait::async_trait;
use pingora::prelude::*;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

pub struct TrauditProxy {
  pub db: Arc<ClickHouseLogger>,
  pub service_config: ServiceConfig,
  pub listen_addr: String,
  pub real_ip: Option<crate::config::RealIpConfig>,
  pub add_xff_header: bool,
}

pub struct HttpContext {
  pub src_ip: IpAddr,
  pub method: HttpMethod,
  pub host: String,
  pub path: String,
  pub user_agent: String,
  pub status_code: u16,
  pub resp_body_size: u64,
  pub req_body_size: u64,
  pub start_ts: Option<Instant>,
}

#[async_trait]
impl ProxyHttp for TrauditProxy {
  type CTX = HttpContext;
  fn new_ctx(&self) -> Self::CTX {
    HttpContext {
      start_ts: None,
      method: HttpMethod::Other,
      path: String::new(),
      host: String::new(),
      src_ip: IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
      user_agent: "unknown".to_string(),
      status_code: 0,
      resp_body_size: 0,
      req_body_size: 0,
    }
  }

  async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
    ctx.start_ts = Some(Instant::now());

    // 1. Determine Source IP
    let peer_addr = session
      .client_addr()
      .and_then(|a| a.as_inet())
      .map(|a| a.ip())
      .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)));

    let mut resolved_ip = peer_addr;

    if let Some(cfg) = &self.real_ip {
      match cfg.source {
        RealIpSource::ProxyProtocol => {
          // If custom listener was used, peer_addr is already the injected Real IP.
          resolved_ip = peer_addr;
        }
        RealIpSource::RemoteAddr => {
          resolved_ip = peer_addr;
        }
        RealIpSource::Xff => {
          // Check trust on current peer/proxy IP
          if cfg.is_trusted(peer_addr) {
            if let Some(xff) = session.req_header().headers.get("x-forwarded-for") {
              if let Ok(xff_str) = xff.to_str() {
                let ips: Vec<&str> = xff_str.split(',').map(|s| s.trim()).collect();

                if !ips.is_empty() {
                  // Recursive trust (0) vs Fixed Depth
                  if cfg.xff_trust_depth == 0 {
                    // Recursive: walk backwards until first untrusted
                    let mut candidate = None;
                    for ip_str in ips.iter().rev() {
                      if let Ok(ip) = ip_str.parse() {
                        if cfg.is_trusted(ip) {
                          continue;
                        } else {
                          candidate = Some(ip);
                          break;
                        }
                      }
                    }
                    // If all trusted, take the first one (leftmost)
                    if let Some(ip) = candidate {
                      resolved_ip = ip;
                    } else if let Some(first_str) = ips.first() {
                      if let Ok(ip) = first_str.parse() {
                        resolved_ip = ip;
                      }
                    }
                  } else {
                    // Fixed depth
                    let idx = if ips.len() >= cfg.xff_trust_depth {
                      ips.len() - cfg.xff_trust_depth
                    } else {
                      0
                    };

                    if let Some(val) = ips.get(idx) {
                      if let Ok(ip) = val.parse() {
                        resolved_ip = ip;
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }

    ctx.src_ip = resolved_ip;

    // 1.5. Inject X-Forwarded-For if configured
    if self.add_xff_header {
      let src_ip_str = resolved_ip.to_string();

      // Collect existing headers to avoid double borrow
      let mut owned_values: Vec<String> = session
        .req_header()
        .headers
        .get_all("X-Forwarded-For")
        .iter()
        .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
        .collect();

      owned_values.push(src_ip_str);
      let new_val = owned_values.join(", ");

      if let Ok(valid_header) = http::header::HeaderValue::from_str(&new_val) {
        // insert_header replaces all existing headers with this name
        let _ = session
          .req_header_mut()
          .insert_header("X-Forwarded-For", valid_header);
      }
    }

    // Log connection info
    let (physical_addr, proxy_info) = crate::core::server::context::CONNECTION_META
      .try_with(|meta| (meta.physical_addr, meta.proxy_info.clone()))
      .unwrap_or((std::net::SocketAddr::new(peer_addr, 0), None));
    let physical_fmt = physical_addr.to_string();

    let mut extras = Vec::new();
    let is_untrusted = self
      .real_ip
      .as_ref()
      .map_or(false, |cfg| !cfg.is_trusted(physical_addr.ip()));

    if let Some(info) = proxy_info {
      let v = match info.version {
        crate::protocol::Version::V1 => "proxy.v1",
        _ => "proxy.v2",
      };
      extras.push(format!("{}: {}", v, info.source));
    }

    if let Some(xff) = session.req_header().headers.get("x-forwarded-for") {
      if let Ok(v) = xff.to_str() {
        if resolved_ip != peer_addr {
          extras.push(format!("xff: {}", resolved_ip));
        } else if self
          .real_ip
          .as_ref()
          .map_or(false, |cfg| !cfg.is_trusted(peer_addr))
        {
          extras.push(format!("xff: {}", v));
        }
      }
    }
    let mut extra_str = String::new();
    if is_untrusted {
      extra_str.push_str("(untrusted) ");
    }
    for (i, e) in extras.iter().enumerate() {
      extra_str.push_str(&format!("({})", e));
      if i < extras.len() - 1 {
        extra_str.push_str(" ");
      }
    }

    if extra_str.is_empty() {
      tracing::info!(
        "[{}] {} <- {}",
        self.service_config.name,
        self.listen_addr,
        physical_fmt
      );
    } else {
      tracing::info!(
        "[{}] {} <- {} {}",
        self.service_config.name,
        self.listen_addr,
        physical_fmt,
        extra_str
      );
    }

    // 2. Audit Info
    ctx.method = match session.req_header().method.as_str() {
      "GET" => HttpMethod::Get,
      "POST" => HttpMethod::Post,
      "PUT" => HttpMethod::Put,
      "DELETE" => HttpMethod::Delete,
      "HEAD" => HttpMethod::Head,
      "PATCH" => HttpMethod::Patch,
      "OPTIONS" => HttpMethod::Options,
      "CONNECT" => HttpMethod::Connect,
      "TRACE" => HttpMethod::Trace,
      _ => HttpMethod::Other,
    };
    ctx.path = session.req_header().uri.path().to_string();
    ctx.host = session
      .req_header()
      .uri
      .host()
      .map(|h| h.to_string())
      .unwrap_or_default();
    if ctx.host.is_empty() {
      if let Some(h) = session.req_header().headers.get("host") {
        ctx.host = h.to_str().unwrap_or("").to_string();
      }
    }

    ctx.user_agent = session
      .req_header()
      .headers
      .get("user-agent")
      .and_then(|v| v.to_str().ok())
      .unwrap_or("")
      .to_string();

    Ok(false) // false to continue processing
  }

  async fn upstream_peer(
    &self,
    _session: &mut Session,
    _ctx: &mut Self::CTX,
  ) -> Result<Box<HttpPeer>> {
    let addr = &self.service_config.forward_to;
    let peer = Box::new(HttpPeer::new(addr, false, "".to_string()));
    Ok(peer)
  }

  fn response_body_filter(
    &self,
    _session: &mut Session,
    body: &mut Option<bytes::Bytes>,
    _end_of_stream: bool,
    ctx: &mut Self::CTX,
  ) -> Result<Option<std::time::Duration>> {
    if let Some(b) = body {
      ctx.resp_body_size += b.len() as u64;
    }
    Ok(None)
  }

  async fn logging(&self, session: &mut Session, _e: Option<&Error>, ctx: &mut Self::CTX) {
    let duration = if let Some(start) = ctx.start_ts {
      start.elapsed().as_millis() as u32
    } else {
      0
    };

    // Status code
    if let Some(header) = session.response_written() {
      ctx.status_code = header.status.as_u16();
    }

    ctx.req_body_size = session.body_bytes_read() as u64;

    let addr_family = if ctx.src_ip.is_ipv4() {
      crate::db::clickhouse::AddrFamily::Ipv4
    } else {
      crate::db::clickhouse::AddrFamily::Ipv6
    };

    let log = HttpLog {
      service: self.service_config.name.clone(),
      conn_ts: time::OffsetDateTime::now_utc(),
      duration,
      addr_family,
      ip: ctx.src_ip,
      proxy_proto: crate::db::clickhouse::ProxyProto::None,
      resp_body_size: ctx.resp_body_size,
      req_body_size: ctx.req_body_size,
      status_code: ctx.status_code,
      method: ctx.method,
      host: ctx.host.clone(),
      path: ctx.path.clone(),
      user_agent: ctx.user_agent.clone(),
    };

    let db = self.db.clone();
    tokio::spawn(async move {
      if let Err(e) = db.insert_http_log(log).await {
        tracing::error!("failed to insert http log: {}", e);
      }
    });
  }
}
