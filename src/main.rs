mod config;
mod core;
mod db;
mod protocol;

use crate::config::Config;
use anyhow::bail;
use std::env;
use std::path::Path;
use tracing::{error, info};

fn print_help() {
  println!("traudit - a reverse proxy with auditing capabilities");
  println!();
  println!("usage:");
  println!("  traudit -f <config_file>");
  println!();
  println!("options:");
  println!("  -f <config_file>  path to the yaml configuration file");
  println!("  -h, --help        print this help message");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  let args: Vec<String> = env::args().collect();

  let mut config_path = None;

  let mut i = 1;
  while i < args.len() {
    match args[i].as_str() {
      "-f" => {
        if i + 1 < args.len() {
          config_path = Some(args[i + 1].clone());
          i += 2;
        } else {
          bail!("missing value for -f");
        }
      }
      "-h" | "--help" => {
        print_help();
        return Ok(());
      }
      _ => {
        bail!("unknown argument: {}\n\nuse -h for help", args[i]);
      }
    }
  }

  let config_path = match config_path {
    Some(p) => {
      let path = Path::new(&p);
      if !path.exists() {
        bail!("config file '{}' not found", p);
      }
      std::fs::canonicalize(path)?
    }
    None => {
      print_help();
      return Ok(());
    }
  };

  tracing_subscriber::fmt()
    .with_target(false)
    .with_thread_ids(false)
    .with_file(false)
    .with_line_number(false)
    .init();

  info!("loading config from {}", config_path.display());

  let config = Config::load(&config_path).await.map_err(|e| {
    error!("failed to load config: {}", e);
    e
  })?;

  core::server::run(config).await?;

  Ok(())
}
