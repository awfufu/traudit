use traudit::config::Config;
use traudit::core;

use anyhow::bail;
use std::env;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::signal;
use tracing::{error, info};

pub const VERSION: &str = concat!("v", env!("CARGO_PKG_VERSION"));
const RELOAD_READY_TIMEOUT: Duration = Duration::from_secs(30);

async fn drain_pending_sighups(sighup: &mut signal::unix::Signal) -> usize {
  let mut drained = 0;
  while let Ok(Some(_)) = tokio::time::timeout(Duration::ZERO, sighup.recv()).await {
    drained += 1;
  }
  drained
}

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
    .without_time()
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

  // Create a channel to signal shutdown to the server component
  let (shutdown_tx, _shutdown_rx) =
    tokio::sync::broadcast::channel::<traudit::core::server::ShutdownReason>(1);
  let shutdown_tx_clone = shutdown_tx.clone();

  // Run server in a separate task
  let server_handle = tokio::spawn(async move {
    if let Err(e) = core::server::run(config, shutdown_tx_clone).await {
      error!("server error: {}", e);
      std::process::exit(1);
    }
  });

  // Signal handling loop
  let mut sighup = signal::unix::signal(signal::unix::SignalKind::hangup())?;
  let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())?;
  let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;

  loop {
    tokio::select! {
      _ = sighup.recv() => {
        info!("received SIGHUP (reload). spawning new process...");

        // Prepare FDs to pass
        let fd_map = {
            match traudit::core::server::listener::get_fd_registry().lock() {
              Ok(registry) => registry.clone(),
              Err(poisoned) => {
                error!("fd registry lock poisoned during reload, continuing with current state");
                poisoned.into_inner().clone()
              }
            }
        };

        let fd_json = serde_json::to_string(&fd_map).unwrap_or_default();
        info!("passing fds: {}", fd_json);

        // Spawn new process
        let args: Vec<String> = env::args().collect();
        let mut cmd = std::process::Command::new(&args[0]);
        cmd.args(&args[1..]);
        cmd.env("TRAUDIT_INHERITED_FDS", fd_json);

        let (ready_parent, ready_child) = std::os::unix::net::UnixStream::pair()?;
        ready_parent.set_nonblocking(true)?;
        let ready_fd = ready_child.as_raw_fd();
        cmd.env("TRAUDIT_RELOAD_READY_FD", ready_fd.to_string());

        unsafe {
            // Use pre_exec to clear CLOEXEC on the FDs to be inherited.
            let fd_map_for_closure = fd_map.clone();

            use std::os::unix::process::CommandExt;
             cmd.pre_exec(move || {
                 for (_, &fd) in &fd_map_for_closure {
                     // Clear FD_CLOEXEC flag
                     let flags = libc::fcntl(fd, libc::F_GETFD);
                     if flags >= 0 {
                         libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
                     }
                 }

                 let ready_flags = libc::fcntl(ready_fd, libc::F_GETFD);
                 if ready_flags >= 0 {
                     libc::fcntl(ready_fd, libc::F_SETFD, ready_flags & !libc::FD_CLOEXEC);
                 }
                 Ok(())
             });
         }

         match cmd.spawn() {
            Ok(child) => {
              let child_pid = child.id();
              info!("spawned new process with pid: {}", child_pid);
              drop(ready_child);

              let mut ready_stream = tokio::net::UnixStream::from_std(ready_parent)?;
              let mut ready_buf = [0u8; 1];
              match tokio::time::timeout(RELOAD_READY_TIMEOUT, ready_stream.read_exact(&mut ready_buf)).await {
                Ok(Ok(_)) => {
                  info!("new process reported ready; starting graceful handoff");

                  // Notify systemd of NEW main PID so it doesn't kill the service when we exit
                  if let Ok(notify_socket) = std::env::var("NOTIFY_SOCKET") {
                    if let Ok(sock) = std::os::unix::net::UnixDatagram::unbound() {
                      let msg = format!("MAINPID={}\n", child_pid);
                      if let Err(e) = sock.send_to(msg.as_bytes(), notify_socket) {
                          error!("failed to send MAINPID to systemd: {}", e);
                      }
                    }
                  }

                  info!("shutting down old process gracefully (draining connections)...");
                  let _ = shutdown_tx.send(traudit::core::server::ShutdownReason::Reload);
                  let _ = server_handle.await;
                  break;
                }
                Ok(Err(e)) => {
                  error!("new process exited before reporting ready: {}", e);
                }
                Err(_) => {
                  error!(
                    "new process did not report ready within {}s; keeping current process active",
                    RELOAD_READY_TIMEOUT.as_secs()
                  );
                }
              }
            },
            Err(e) => {
              drop(ready_child);
              error!("failed to spawn new process: {}", e);
            }
          }

          let drained = drain_pending_sighups(&mut sighup).await;
          if drained > 0 {
            info!("ignored {} queued SIGHUP signal(s) after reload attempt", drained);
          }
      }
      _ = sigint.recv() => {
        info!("received SIGINT, terminating immediately...");
        let _ = shutdown_tx.send(traudit::core::server::ShutdownReason::Terminate);
        let _ = server_handle.await;
        break;
      }
      _ = sigterm.recv() => {
        info!("received SIGTERM, terminating immediately...");
        let _ = shutdown_tx.send(traudit::core::server::ShutdownReason::Terminate);
        let _ = server_handle.await;
        break;
      }
    }
  }

  Ok(())
}
