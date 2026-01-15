use super::{AuditEvent, AuditLogger};
use crate::config::DatabaseConfig;
use async_trait::async_trait;

pub struct ClickHouseLogger;

impl ClickHouseLogger {
  pub fn new(_config: &DatabaseConfig) -> Self {
    // TODO: Initialize ClickHouse client
    ClickHouseLogger
  }
}

#[async_trait]
impl AuditLogger for ClickHouseLogger {
  async fn log(&self, _event: AuditEvent) -> anyhow::Result<()> {
    // TODO: Implement insertion logic
    Ok(())
  }
}
