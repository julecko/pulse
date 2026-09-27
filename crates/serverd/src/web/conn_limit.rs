//! Caps on open connections, in total and per client IP (IPv6: per /64,
//! like [`super::rate_limit`]), so one client can't hold every socket (and
//! file descriptor) the server has. Checked when a connection is accepted,
//! before the TLS handshake; connections over a cap are closed right away.
//!
//! Timeouts (see [`super::serve`]) make each connection end eventually;
//! these caps bound how many a client can hold open meanwhile.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use axum_server::accept::Accept;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// The server config's `[web.connections]` section. `0` disables a cap.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConnectionLimits {
    /// Open connections in total.
    pub max: usize,
    /// Open connections per client IP. Each agent keeps about one open, so
    /// this also caps how many agents can share one public IP (e.g. NAT).
    pub max_per_ip: usize,
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self {
            max: 4096,
            max_per_ip: 64,
        }
    }
}

#[derive(Default)]
struct Counts {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
}

/// Inner acceptor for [`axum_server::tls_rustls::RustlsAcceptor`]: admits
/// a TCP connection only while it's under the caps.
#[derive(Clone)]
pub struct ConnLimitAcceptor {
    limits: ConnectionLimits,
    counts: Arc<Mutex<Counts>>,
}

impl ConnLimitAcceptor {
    pub fn new(limits: ConnectionLimits) -> Self {
        Self {
            limits,
            counts: Arc::default(),
        }
    }

    /// Counts a new connection from `ip`, or `None` if it's over a cap.
    fn admit(&self, ip: IpAddr) -> Option<ConnGuard> {
        let key = super::rate_limit::client_key(ip);
        // Nothing in here can panic mid-update, so a poisoned lock is fine.
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        let from_ip = counts.per_ip.get(&key).copied().unwrap_or(0);
        if (self.limits.max > 0 && counts.total >= self.limits.max)
            || (self.limits.max_per_ip > 0 && from_ip >= self.limits.max_per_ip)
        {
            return None;
        }
        counts.total += 1;
        counts.per_ip.insert(key, from_ip + 1);
        Some(ConnGuard {
            key,
            counts: Arc::clone(&self.counts),
        })
    }
}

impl<S: Send + 'static> Accept<TcpStream, S> for ConnLimitAcceptor {
    type Stream = Limited<TcpStream>;
    type Service = S;
    type Future = std::future::Ready<io::Result<(Self::Stream, S)>>;

    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        let result = stream.peer_addr().and_then(|peer| {
            match self.admit(peer.ip()) {
                Some(guard) => Ok((
                    Limited {
                        inner: stream,
                        _guard: guard,
                    },
                    service,
                )),
                None => {
                    tracing::warn!(peer = %peer.ip(), "connection limit reached; dropping connection");
                    Err(io::Error::other("connection limit reached"))
                }
            }
        });
        std::future::ready(result)
    }
}

/// Releases its connection's slot when dropped, i.e. when the connection
/// closes.
struct ConnGuard {
    key: IpAddr,
    counts: Arc<Mutex<Counts>>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        counts.total = counts.total.saturating_sub(1);
        if let Some(n) = counts.per_ip.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                counts.per_ip.remove(&self.key);
            }
        }
    }
}

/// A stream that holds its connection's slot for as long as it's open.
pub struct Limited<S> {
    inner: S,
    _guard: ConnGuard,
}

impl<S: AsyncRead + Unpin> AsyncRead for Limited<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Limited<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_per_ip_and_total_and_frees_on_drop() {
        let acceptor = ConnLimitAcceptor::new(ConnectionLimits {
            max: 3,
            max_per_ip: 2,
        });
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        let c: IpAddr = "192.0.2.3".parse().unwrap();

        let a1 = acceptor.admit(a).unwrap();
        let _a2 = acceptor.admit(a).unwrap();
        assert!(acceptor.admit(a).is_none(), "per-IP cap");
        let _b1 = acceptor.admit(b).unwrap();
        assert!(acceptor.admit(c).is_none(), "total cap");

        drop(a1);
        assert!(acceptor.admit(c).is_some(), "slot freed on drop");
    }

    #[test]
    fn zero_disables() {
        let acceptor = ConnLimitAcceptor::new(ConnectionLimits {
            max: 0,
            max_per_ip: 0,
        });
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let _guards: Vec<_> = (0..100).map(|_| acceptor.admit(a).unwrap()).collect();
    }
}
