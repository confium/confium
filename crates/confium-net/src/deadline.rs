//! Deadline-bounded reads and writes over a `TcpStream`, implemented
//! with non-blocking polling instead of `SO_RCVTIMEO`.
//!
//! Why not [`std::net::TcpStream::set_read_timeout`]: inside the MRI
//! Ruby process on `x86_64-pc-windows-gnu`, the first `recv` on a
//! socket that carries a receive timeout fails `WSAENOTSOCK` (os
//! error 10038) — every other winsock operation (bind, connect,
//! write, the setsockopt itself, reads WITHOUT the option) succeeds,
//! and the same code passes in a plain Rust process. Root-caused
//! empirically across five probe rounds on the gem's Windows CI (see
//! the audit ledger; gem PRs #97-#101). Polling sidesteps the option
//! entirely while keeping the deadlines that prevent the
//! hang-forever failure class.

use std::io;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Write;
use std::net::TcpStream;
use std::time::Duration;
use std::time::Instant;

/// A deadline-bounded view over a connected [`TcpStream`].
///
/// Entering ([`Self::new`]) switches the stream to non-blocking;
/// dropping it restores blocking mode for the established session.
/// Reads and writes poll with a short sleep while the peer is not
/// ready and fail with [`ErrorKind::TimedOut`] once the deadline
/// passes.
pub struct DeadlineStream<'a> {
    stream: &'a mut TcpStream,
    deadline: Instant,
    poll: Duration,
}

impl<'a> DeadlineStream<'a> {
    /// Bound the stream for `timeout`. The stream is switched to
    /// non-blocking until the adapter is dropped.
    pub fn new(stream: &'a mut TcpStream, timeout: Duration) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self {
            stream,
            deadline: Instant::now() + timeout,
            poll: Duration::from_millis(2),
        })
    }

    fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }
}

impl Read for DeadlineStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.stream.read(buf) {
                Ok(n) => return Ok(n),
                Err(ref e)
                    if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut =>
                {
                    if self.expired() {
                        return Err(io::Error::new(
                            ErrorKind::TimedOut,
                            "read deadline exceeded",
                        ));
                    }
                    std::thread::sleep(self.poll);
                }
                Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }
}

impl Write for DeadlineStream<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        loop {
            match self.stream.write(buf) {
                Ok(n) => return Ok(n),
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    if self.expired() {
                        return Err(io::Error::new(
                            ErrorKind::TimedOut,
                            "write deadline exceeded",
                        ));
                    }
                    std::thread::sleep(self.poll);
                }
                Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl Drop for DeadlineStream<'_> {
    fn drop(&mut self) {
        // Restore blocking mode for the established session. Drop
        // cannot surface errors; a failure here leaves the socket
        // non-blocking, which misbehaves visibly on the next blocking
        // operation rather than silently.
        let _ = self.stream.set_nonblocking(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Local-socket tests flake when run in parallel (the known
    // port/handler race class); serialize them.
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn round_trip_within_deadline() {
        let _guard = LOCK.lock().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let echo = std::thread::spawn(move || {
            use std::io::{Read as _, Write as _};
            let (mut peer, _) = listener.accept().unwrap();
            let mut buf = [0u8; 16];
            let n = peer.read(&mut buf).unwrap();
            peer.write_all(&buf[..n]).unwrap();
        });
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        {
            let mut bounded = DeadlineStream::new(&mut stream, Duration::from_secs(5)).unwrap();
            bounded.write_all(b"ping").unwrap();
            let mut got = [0u8; 4];
            bounded.read_exact(&mut got).unwrap();
            assert_eq!(&got, b"ping");
        }
        // Blocking mode restored: a plain write on the underlying
        // stream behaves normally.
        assert!(stream.set_nonblocking(false).is_ok());
        echo.join().unwrap();
    }

    #[test]
    fn read_deadline_fires_on_silent_peer() {
        let _guard = LOCK.lock().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let silent = std::thread::spawn(move || {
            let (_peer, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_secs(1));
        });
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let start = Instant::now();
        let mut bounded = DeadlineStream::new(&mut stream, Duration::from_millis(150)).unwrap();
        let mut buf = [0u8; 8];
        let err = bounded.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::TimedOut);
        assert!(start.elapsed() >= Duration::from_millis(140));
        drop(bounded);
        silent.join().unwrap();
    }
}
