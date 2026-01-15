use async_trait::async_trait;

pub mod clickhouse;

#[derive(Debug, Clone)]
pub struct AuditEvent {
  // TODO: Define audit event fields (src, dst, timestamp, etc.)
}

#[async_trait]
pub trait AuditLogger: Send + Sync {
  // TODO: Finalize log interface
  async fn log(&self, event: AuditEvent) -> anyhow::Result<()>;
}
