use traudit::config::Config;
use traudit::core;

use anyhow::bail;
use std::env;
use std::path::Path;
use tracing::{error, info};

pub const VERSION: &str = concat!("v", env!("CARGO_PKG_VERSION"));

fn print_help() {
  println!("traudit - a reverse proxy with auditing capabilities");
  println!();
  println!("usage:");
  println!("  traudit -f <config_file>");
  println!();
  println!("options:");
  println!("  -f <config_file>  path to the yaml configuration file");
  println!("  -t, --test        test configuration and exit");
  println!("  -v, --version     print version");
  println!("  -h, --help        print this help message");
  println!();
  println!("project: https://github.com/awfufu/traudit");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
    .unwrap_or_else(|_| "info,pingora=error".into());

  tracing_subscriber::fmt()
    .with_env_filter(env_filter)
    .with_target(false)
    .with_thread_ids(false)
    .with_file(false)
    .with_line_number(false)
    .init();

  let args: Vec<String> = env::args().collect();

  let mut config_path = None;
  let mut test_config = false;

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
      "-t" | "--test" => {
        test_config = true;
        i += 1;
      }
      "-h" | "--help" => {
        print_help();
        return Ok(());
      }
      "-v" | "--version" => {
        println!("{}", VERSION);
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
        error!("config file '{}' not found", p);
        std::process::exit(1);
      }
      std::fs::canonicalize(path)?
    }
    None => {
      print_help();
      return Ok(());
    }
  };

  info!("loading config from {}", config_path.display());

  let config = match Config::load(&config_path).await {
    Ok(c) => c,
    Err(e) => {
      error!("failed to load config: {}", e);
      std::process::exit(1);
    }
  };

  if test_config {
    // Validate database config
    if let Err(e) = traudit::db::clickhouse::ClickHouseLogger::new(&config.database) {
      error!("configuration check failed: {}", e);
      std::process::exit(1);
    }

    info!("configuration ok");
    return Ok(());
  }

  if let Err(_e) = core::server::run(config).await {
    std::process::exit(1);
  }

  Ok(())
}
