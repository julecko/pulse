use std::io::{self, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

use protocol::Report;
use pulse_config::tls::PIN_SERVER_NAME;

use crate::config::Config;

/// Ships reports to the server, plaintext or TLS-pinned depending on config.
/// Built once so the pinned client config / PEM parse happens a single time.
pub struct Sender {
    server: String,
    tls: Option<Arc<ClientConfig>>,
}

impl Sender {
    pub fn from_config(cfg: &Config) -> io::Result<Self> {
        let tls = match &cfg.tls {
            Some(t) => {
                Some(pulse_config::tls::pinned_client_config(&t.cert).map_err(io::Error::other)?)
            }
            None => None,
        };
        Ok(Self {
            server: cfg.server.clone(),
            tls,
        })
    }

    pub fn is_tls(&self) -> bool {
        self.tls.is_some()
    }

    /// Open a fresh connection, send one framed report, close.
    pub fn send(&self, report: &Report) -> io::Result<()> {
        let tcp = TcpStream::connect(&self.server)?;
        match &self.tls {
            None => {
                let mut stream = tcp;
                protocol::write_report(&mut stream, report).map_err(io::Error::other)
            }
            Some(config) => {
                let name = ServerName::try_from(PIN_SERVER_NAME).expect("valid pin name");
                let conn =
                    ClientConnection::new(Arc::clone(config), name).map_err(io::Error::other)?;
                let mut stream = StreamOwned::new(conn, tcp);
                protocol::write_report(&mut stream, report).map_err(io::Error::other)?;
                // Signal a clean end-of-stream so the server doesn't see the
                // close as a truncation attack.
                stream.conn.send_close_notify();
                stream.flush()
            }
        }
    }
}
