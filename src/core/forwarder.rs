use crate::core::upstream::UpstreamStream;
use monoio::fs::File;
use monoio::io::splice::{SpliceDestination, SpliceSource};
use monoio::io::Splitable;
use monoio::net::unix::new_pipe;
use monoio::net::TcpStream;
use std::io;
use std::os::unix::io::AsRawFd;

const SPLICE_SIZE: u32 = 1024 * 1024; // 1MB

async fn transfer<R, W>(mut read: R, mut write: W) -> io::Result<()>
where
  R: SpliceSource,
  W: SpliceDestination,
{
  // Double buffering: Create two pipes
  let (mut p1_r, mut p1_w) = new_pipe()?;
  let (mut p2_r, mut p2_w) = new_pipe()?;

  // Resize both pipes
  unsafe {
    let f1_r: &File = std::mem::transmute(&p1_r);
    let f1_w: &File = std::mem::transmute(&p1_w);
    let f2_r: &File = std::mem::transmute(&p2_r);
    let f2_w: &File = std::mem::transmute(&p2_w);

    libc::fcntl(f1_r.as_raw_fd(), 1031, SPLICE_SIZE as libc::c_int);
    libc::fcntl(f1_w.as_raw_fd(), 1031, SPLICE_SIZE as libc::c_int);
    libc::fcntl(f2_r.as_raw_fd(), 1031, SPLICE_SIZE as libc::c_int);
    libc::fcntl(f2_w.as_raw_fd(), 1031, SPLICE_SIZE as libc::c_int);
  }

  // Prime the first pipe
  let n = read.splice_to_pipe(&mut p1_w, SPLICE_SIZE).await?;
  if n == 0 {
    return Ok(());
  }

  loop {
    // Write from p1_r -> write AND Read from read -> p2_w
    let (res_w, res_r) = monoio::join!(
      write.splice_from_pipe(&mut p1_r, SPLICE_SIZE),
      read.splice_to_pipe(&mut p2_w, SPLICE_SIZE)
    );

    let _w = res_w?;
    let r = res_r?;

    if r == 0 {
      return Ok(());
    }

    // Swap pipes so p2 becomes the source for next write, and p1 becomes available for read
    std::mem::swap(&mut p1_r, &mut p2_r);
    std::mem::swap(&mut p1_w, &mut p2_w);
  }
}

fn set_busy_poll(fd: std::os::unix::io::RawFd, us: libc::c_int) {
  unsafe {
    let val = us;
    libc::setsockopt(
      fd,
      libc::SOL_SOCKET,
      50, // SO_BUSY_POLL is 50 on Linux
      &val as *const _ as *const libc::c_void,
      std::mem::size_of::<libc::c_int>() as libc::socklen_t,
    );
  }
}

pub async fn zero_copy_bidirectional(
  inbound: TcpStream,
  outbound: UpstreamStream,
) -> io::Result<()> {
  set_busy_poll(inbound.as_raw_fd(), 50);

  let (in_r, in_w) = inbound.into_split();
  match outbound {
    UpstreamStream::Tcp(s) => {
      set_busy_poll(s.as_raw_fd(), 50);
      let (out_r, out_w) = s.into_split();
      let (r1, r2) = monoio::join!(transfer(in_r, out_w), transfer(out_r, in_w));
      r1?;
      r2?;
    }
    UpstreamStream::Unix(s) => {
      let (out_r, out_w) = s.into_split();
      let (r1, r2) = monoio::join!(transfer(in_r, out_w), transfer(out_r, in_w));
      r1?;
      r2?;
    }
  }
  Ok(())
}
