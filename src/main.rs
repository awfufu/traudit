mod config;
mod core;
mod db;
mod protocol;

use crate::config::Config;
use std::env;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  tracing_subscriber::fmt::init();

  let args: Vec<String> = env::args().collect();
  let config_path = args.get(1).map(|s| s.as_str()).unwrap_or("config.yaml");

  println!("Loading config from {}", config_path);

  // Check if config exists, if not warn (for dev purposes)
  if !std::path::Path::new(config_path).exists() {
    println!("Warning: Config file '{}' not found.", config_path);
    // In a real run we might want to exit, but for init check we proceed or return
  } else {
    let config = Config::load(config_path).await?;
    core::server::run(config).await?;
  }

  Ok(())
}
