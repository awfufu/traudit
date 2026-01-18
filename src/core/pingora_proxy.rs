use crate::config::ServiceConfig;
use crate::db::clickhouse::{ClickHouseLogger, HttpLog, HttpMethod};
use async_trait::async_trait;
use pingora::prelude::*;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

pub struct TrauditProxy {
  pub db: Arc<ClickHouseLogger>,
  pub service_config: ServiceConfig,
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
    // IP Priority: Proxy Protocol > XFF > X-Real-IP > Peer
    let mut client_ip: Option<IpAddr> = session
      .client_addr()
      .and_then(|a| a.as_inet())
      .map(|a| a.ip());

    // Check headers for overrides
    if let Some(xff) = session.req_header().headers.get("x-forwarded-for") {
      if let Ok(xff_str) = xff.to_str() {
        if let Some(first_ip) = xff_str.split(',').next() {
          if let Ok(parsed_ip) = first_ip.trim().parse::<IpAddr>() {
            client_ip = Some(parsed_ip); // Overwrite
          }
        }
      }
    }

    if let Some(ip) = client_ip {
      ctx.src_ip = ip;
    } else {
      // fallback to 0.0.0.0 if entirely missing (unlikely)
      ctx.src_ip = IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
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

    // Bytes (resp_body_size accumulated in filter)

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
        // log error
        tracing::error!("failed to insert http log: {}", e);
      }
    });
  }
}
