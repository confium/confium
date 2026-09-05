//! Adapter from message-framed [`Transport`]s to byte-stream
//! `Read`/`Write` callers.
//!
//! Length-prefix protocols (the coordinator's message framing) are
//! written against `Read + Write` streams. The registry transports
//! are message-framed: one `send` is one `recv` payload.
//! [`TransportIo`] bridges the two worlds:
//!
//! - `write` buffers; `flush` emits exactly one transport message
//!   (so `write_all(prefix); write_all(body); flush()` becomes a
//!   single frame, preserving the caller's framing).
//! - `read` serves from an internal buffer refilled one transport
//!   message at a time; a clean close yields `Ok(0)` (EOF).

use std::io::Read;
use std::io::Write;

use crate::Transport;

pub struct TransportIo {
    transport: Box<dyn Transport>,
    wbuf: Vec<u8>,
    rbuf: Vec<u8>,
    rpos: usize,
    closed: bool,
}

impl TransportIo {
    pub fn new(transport: Box<dyn Transport>) -> Self {
        Self {
            transport,
            wbuf: Vec::new(),
            rbuf: Vec::new(),
            rpos: 0,
            closed: false,
        }
    }
}

impl Write for TransportIo {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.wbuf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.wbuf.is_empty() {
            return Ok(());
        }
        let frame = std::mem::take(&mut self.wbuf);
        self.transport.send(&frame).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "transport send failed",
            )
        })
    }
}

impl Read for TransportIo {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.rpos >= self.rbuf.len() {
            if self.closed {
                return Ok(0);
            }
            // Refill with the next whole transport message.
            let mut next = vec![0u8; 16 * 1024 * 1024];
            match self.transport.recv(&mut next) {
                Ok(0) => {
                    self.closed = true;
                    return Ok(0);
                }
                Ok(n) => {
                    next.truncate(n);
                    self.rbuf = next;
                    self.rpos = 0;
                }
                Err(_) => {
                    self.closed = true;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        "transport recv failed",
                    ));
                }
            }
        }
        let avail = &self.rbuf[self.rpos..];
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        self.rpos += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Result;
    use std::sync::mpsc;

    /// Minimal in-memory Transport: a channel pair.
    struct ChanTransport {
        out: mpsc::Sender<Vec<u8>>,
        inp: mpsc::Receiver<Vec<u8>>,
        pending: Vec<u8>,
    }

    fn pair() -> (ChanTransport, ChanTransport) {
        let (a2b_tx, a2b_rx) = mpsc::channel();
        let (b2a_tx, b2a_rx) = mpsc::channel();
        (
            ChanTransport {
                out: a2b_tx,
                inp: b2a_rx,
                pending: Vec::new(),
            },
            ChanTransport {
                out: b2a_tx,
                inp: a2b_rx,
                pending: Vec::new(),
            },
        )
    }

    impl Transport for ChanTransport {
        fn send(&mut self, data: &[u8]) -> Result<()> {
            self.out.send(data.to_vec()).expect("channel pair alive");
            Ok(())
        }
        fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
            if self.pending.is_empty() {
                let msg = self
                    .inp
                    .recv()
                    .map_err(|_| crate::error::ClosedSnafu.build())?;
                self.pending = msg;
            }
            let n = self.pending.len().min(buf.len());
            buf[..n].copy_from_slice(&self.pending[..n]);
            self.pending.drain(..n);
            Ok(n)
        }
        fn close(&mut self) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn write_flush_is_one_message() {
        let (a, mut b) = pair();
        let mut io = TransportIo::new(Box::new(a));
        io.write_all(&4u32.to_be_bytes()).unwrap();
        io.write_all(b"body").unwrap();
        io.flush().unwrap();
        let mut buf = [0u8; 16];
        let n = b.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], &[0, 0, 0, 4, b'b', b'o', b'd', b'y']);
    }

    #[test]
    fn read_serves_partial_then_refills() {
        let (mut a, b) = pair();
        a.send(b"hello world").unwrap();
        let mut io = TransportIo::new(Box::new(b));
        let mut five = [0u8; 5];
        io.read_exact(&mut five).unwrap();
        assert_eq!(&five, b"hello");
        let mut rest = [0u8; 6];
        io.read_exact(&mut rest).unwrap();
        assert_eq!(&rest, b" world");
    }
}
