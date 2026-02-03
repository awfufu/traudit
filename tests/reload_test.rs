mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::process::Command;
use warp::Filter;

// Shared stats
static BYTES_SENT: AtomicUsize = AtomicUsize::new(0);

#[tokio::test]
async fn test_reload_stress() -> anyhow::Result<()> {
  // Setup Environment: Initialize DB and clear tables
  let host_port = common::get_shared_db_port().await;

  // Create tables using system client if needed, or rely on Traudit
  let system_client = common::get_db_client(host_port, "default");
  let _ = system_client
    .query("CREATE DATABASE IF NOT EXISTS traudit")
    .execute()
    .await;

  let client = common::get_db_client(host_port, "traudit");
  // Clean start
  let _ = client.query("DROP TABLE IF EXISTS tcp_log").execute().await;
  let _ = client
    .query("DROP TABLE IF EXISTS http_log")
    .execute()
    .await;
  let tcp_backend = TcpListener::bind("127.0.0.1:0").await?;
  let tcp_backend_port = tcp_backend.local_addr()?.port();

  tokio::spawn(async move {
    loop {
      if let Ok((mut socket, _)) = tcp_backend.accept().await {
        tokio::spawn(async move {
          let (mut rd, mut wr) = socket.split();
          let _ = tokio::io::copy(&mut rd, &mut wr).await;
        });
      }
    }
  });

  // HTTP Backend
  let http_backend_port = {
    let (addr, server) = warp::serve(
      warp::any().map(|| "ok"), // Fix: closure taking 0 args
    )
    .bind_ephemeral(([127, 0, 0, 1], 0));
    let port: u16 = addr.port(); // Fix: explicit type
    tokio::spawn(server);
    port
  };

  // Config: Use fixed random high ports to ensure reloading works on same port
  let t_tcp_port = 30000 + (rand::random::<u16>() % 1000);
  // Ensure unique manually if conflict, but probability low for test.
  let t_http_port = t_tcp_port + 1;
  let t_unix_path = format!("/tmp/traudit_test_{}.sock", rand::random::<u32>());

  // Write Config
  let config_content = format!(
    r#"
database:
  type: clickhouse
  dsn: http://traudit:traudit@127.0.0.1:{}/traudit
  batch_size: 1
  batch_timeout_secs: 1

services:
  - name: tcp-bench
    type: tcp
    forward_to: 127.0.0.1:{}
    binds:
      - addr: 127.0.0.1:{}
  
  - name: unix-bench
    type: tcp
    forward_to: 127.0.0.1:{}
    binds:
      - addr: unix://{}
        mode: 666

  - name: http-bench
    type: http
    forward_to: 127.0.0.1:{}
    binds:
      - addr: 127.0.0.1:{}
"#,
    host_port,
    tcp_backend_port,
    t_tcp_port,
    tcp_backend_port,
    t_unix_path,
    http_backend_port,
    t_http_port
  );

  let config_path = std::env::temp_dir().join("stress_test.yaml");
  std::fs::write(&config_path, config_content)?;

  // Start Traudit using cargo run to ensure correct binary execution
  let mut _child = Command::new("cargo")
    .arg("run")
    .arg("--bin")
    .arg("traudit")
    .arg("--")
    .arg("-f")
    .arg(&config_path)
    .stdout(std::process::Stdio::null())
    .stderr(std::process::Stdio::null())
    .spawn()?;

  // Give it time to start
  tokio::time::sleep(Duration::from_secs(5)).await;

  // Run Test Loop for 10 seconds generating mixed traffic

  let running = Arc::new(std::sync::atomic::AtomicBool::new(true));

  // Task: Staggered Connections
  let r_stagger = running.clone(); // Clone for staggered task loop
  let staggered_handle = tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    for _ in 0..10 {
      // 0 to 9
      interval.tick().await;
      if !r_stagger.load(Ordering::Relaxed) {
        break;
      }

      // TCP Client
      let t_addr = format!("127.0.0.1:{}", t_tcp_port);
      let r_inner = r_stagger.clone();
      tokio::spawn(async move {
        // Retry connect logic
        for _ in 0..5 {
          if let Ok(mut stream) = TcpStream::connect(&t_addr).await {
            let mut buf = [0u8; 1024];
            while r_inner.load(Ordering::Relaxed) {
              if stream.write_all(b"PING").await.is_ok() {
                BYTES_SENT.fetch_add(4, Ordering::SeqCst);
                let _ = stream.read(&mut buf).await;
              }
              tokio::time::sleep(Duration::from_millis(100)).await;
            }
            break;
          }
          tokio::time::sleep(Duration::from_millis(100)).await;
        }
      });

      // Unix Client
      let u_path = t_unix_path.clone(); // Clone path string for new task
      let r_inner = r_stagger.clone();
      tokio::spawn(async move {
        for _ in 0..5 {
          if let Ok(mut stream) = UnixStream::connect(&u_path).await {
            let mut buf = [0u8; 1024];
            while r_inner.load(Ordering::Relaxed) {
              if stream.write_all(b"PING").await.is_ok() {
                BYTES_SENT.fetch_add(4, Ordering::SeqCst);
                let _ = stream.read(&mut buf).await;
              }
              tokio::time::sleep(Duration::from_millis(100)).await;
            }
            break;
          }
          tokio::time::sleep(Duration::from_millis(100)).await;
        }
      });

      // HTTP Keep-Alive Client
      let h_url = format!("http://127.0.0.1:{}", t_http_port);
      let r_inner = r_stagger.clone();
      tokio::spawn(async move {
        let client = reqwest::Client::builder().build().unwrap();
        while r_inner.load(Ordering::Relaxed) {
          if let Ok(_) = client.post(&h_url).body("PING").send().await {
            BYTES_SENT.fetch_add(4, Ordering::SeqCst);
          }
          tokio::time::sleep(Duration::from_millis(100)).await;
        }
      });
    }
  });

  // Task: High Freq HTTP
  let r_high = running.clone();
  let high_freq_url = format!("http://127.0.0.1:{}", t_http_port);
  let high_handle = tokio::spawn(async move {
    let client = reqwest::Client::new();
    while r_high.load(Ordering::Relaxed) {
      if let Ok(_) = client.post(&high_freq_url).body("FAST").send().await {
        BYTES_SENT.fetch_add(4, Ordering::SeqCst);
      }
      // Slight delay to not overwhelm test runner completely
      tokio::time::sleep(Duration::from_millis(10)).await;
    }
  });

  // Reload Sequence: Trigger SIGHUP at T=5s
  tokio::time::sleep(Duration::from_secs(5)).await;

  // Send SIGHUP
  let output = Command::new("pgrep")
    .arg("-f")
    .arg(&config_path.to_string_lossy().to_string())
    .output()
    .await?;
  let pid_str = String::from_utf8(output.stdout)?;
  println!("Found PIDs for Reload: {}", pid_str);

  for line in pid_str.lines() {
    if let Ok(pid) = line.trim().parse::<i32>() {
      let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid),
        nix::sys::signal::Signal::SIGHUP,
      );
    }
  }

  // Wait remaining time
  tokio::time::sleep(Duration::from_secs(5)).await;

  // Stop Sequence: Stop generators and signal shutdown
  running.store(false, Ordering::Relaxed);
  let _ = staggered_handle.await;
  let _ = high_handle.await;

  // Wait for clients to actually disconnect and server to process logs
  tokio::time::sleep(Duration::from_secs(3)).await;

  // Kill traudit
  let output = Command::new("pgrep")
    .arg("-f")
    .arg(&config_path.to_string_lossy().to_string())
    .output()
    .await?;
  let pid_str = String::from_utf8(output.stdout)?;
  for line in pid_str.lines() {
    if let Ok(pid) = line.trim().parse::<i32>() {
      let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid),
        nix::sys::signal::Signal::SIGINT,
      );
    }
  }

  // Wait for buffered records to flush (batch_timeout_secs: 1)
  tokio::time::sleep(Duration::from_secs(3)).await;

  // Verify: Aggregated DB logs must cover Client payload (DB >= Client due to headers)
  let client_sent = BYTES_SENT.load(Ordering::SeqCst) as u64;

  let tcp_res = client
    .query("SELECT sum(bytes_recv) FROM tcp_log")
    .fetch_one::<u64>()
    .await;

  let tcp_bytes = match tcp_res {
    Ok(n) => n,
    Err(e) => {
      println!("TCP Query Error: {}", e);
      0
    }
  };

  let http_res = client
    .query("SELECT sum(req_body_size) FROM http_log")
    .fetch_one::<u64>()
    .await;

  let http_bytes = match http_res {
    Ok(n) => n,
    Err(e) => {
      println!("HTTP Query Error: {}", e);
      0
    }
  };

  let db_sent = tcp_bytes + http_bytes;

  println!(
    "Client Sent Payload: {}, DB Recorded (TCP Recv + HTTP Req Body): {}",
    client_sent, db_sent
  );

  assert!(
    db_sent > 0,
    "DB recorded 0 bytes! Queries failed or no data."
  );

  // Ensure DB recorded at least as many bytes as the client sent.
  assert!(
    db_sent >= client_sent,
    "Data loss detected! DB {} < Client {}",
    db_sent,
    client_sent
  );

  Ok(())
}
