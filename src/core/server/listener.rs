use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use tokio::net::{UnixListener, UnixStream};
use tracing::{error, info};

pub struct UnixSocketGuard {
  pub path: PathBuf,
}

impl Drop for UnixSocketGuard {
  fn drop(&mut self) {
    if let Err(_e) = std::fs::remove_file(&self.path) {
      // File potentially gone or no permissions, debug log only
    } else {
      tracing::debug!("removed socket file {:?}", self.path);
    }
  }
}

pub async fn bind_robust(
  path: &str,
  mode: u32,
  service_name: &str,
) -> anyhow::Result<(UnixListener, UnixSocketGuard)> {
  let path_buf = std::path::Path::new(path).to_path_buf();

  if path_buf.exists() {
    // Check permissions; we need write access to remove it
    match std::fs::symlink_metadata(&path_buf) {
      Ok(_meta) => {
        // We rely on subsequent operations (connect/remove) to fail with PermissionDenied if we lack access.
      }
      Err(e) => {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
          anyhow::bail!("Permission denied accessing existing socket: {}", path);
        }
      }
    }

    // Try to connect to check if it's active
    match UnixStream::connect(&path_buf).await {
      Ok(_) => {
        // Active!
        anyhow::bail!("Address already in use: {}", path);
      }
      Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
        // Stale socket, remove it
        info!("[{}] removing stale socket file: {}", service_name, path);
        if let Err(rm_err) = std::fs::remove_file(&path_buf) {
          anyhow::bail!("failed to remove stale socket {}: {}", path, rm_err);
        }
      }
      Err(e) => {
        // Other error, bail
        anyhow::bail!("failed to check existing socket {}: {}", path, e);
      }
    }
  }

  // Now bind
  let listener = UnixListener::bind(&path_buf).map_err(|e| {
    error!("[{}] failed to bind {}: {}", service_name, path, e);
    e
  })?;

  // Set permissions
  if let Ok(metadata) = std::fs::metadata(&path_buf) {
    let mut permissions = metadata.permissions();
    // Verify if we need to change it
    if permissions.mode() & 0o777 != mode & 0o777 {
      permissions.set_mode(mode);
      if let Err(e) = std::fs::set_permissions(&path_buf, permissions) {
        // Non-fatal error, log only
        error!(
          "[{}] failed to set permissions on {}: {}",
          service_name, path, e
        );
      }
    }
  }

  Ok((listener, UnixSocketGuard { path: path_buf }))
}
