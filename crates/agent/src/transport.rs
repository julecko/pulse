use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

use protocol::Report;
use pulse_config::tls::PIN_SERVER_NAME;

use crate::config::Config;

/// Ships reports to the server, plaintext or mutual-TLS depending on config.
/// Built once so the pinned client config / PEM parse happens a single time.
pub struct Sender {
    server: String,
    tls: Option<Arc<ClientConfig>>,
}

impl Sender {
    pub fn from_config(cfg: &Config) -> io::Result<Self> {
        let tls = if cfg.tls {
            let dir = pulse_config::tls_dir("agent");
            Some(
                pulse_config::tls::pinned_client_config(
                    &dir.join("trusted-server.crt"),
                    &dir.join("agent.crt"),
                    &dir.join("agent.key"),
                )
                .map_err(io::Error::other)?,
            )
        } else {
            None
        };
        Ok(Self {
            server: cfg.server.clone(),
            tls,
        })
    }

    pub fn is_tls(&self) -> bool {
        self.tls.is_some()
    }

    /// Open a fresh connection, send one framed report, wait for the server to
    /// close. Returns an error if the server rejected us (e.g. our client
    /// certificate is not approved) — the rejection alert surfaces on read.
    pub fn send(&self, report: &Report) -> io::Result<()> {
        let tcp = TcpStream::connect(&self.server)?;
        tcp.set_read_timeout(Some(Duration::from_secs(10)))?;

        match &self.tls {
            None => {
                let mut stream = tcp;
                protocol::write_report(&mut stream, report).map_err(io::Error::other)?;
                // Half-close so the server's read loop sees EOF after this one
                // report (the TLS path does the same with close_notify). Without
                // it both ends block until our read timeout fires.
                stream.shutdown(std::net::Shutdown::Write)?;
                drain_to_eof(&mut stream)
            }
            Some(config) => {
                let name = ServerName::try_from(PIN_SERVER_NAME).expect("valid pin name");
                let conn =
                    ClientConnection::new(Arc::clone(config), name).map_err(io::Error::other)?;
                let mut stream = StreamOwned::new(conn, tcp);
                protocol::write_report(&mut stream, report).map_err(io::Error::other)?;
                stream.conn.send_close_notify();
                stream.flush()?;
                drain_to_eof(&mut stream)
            }
        }
    }
}

/// Read until the peer closes. A clean EOF (or TLS close_notify) => the report
/// was accepted; any other error => it was not.
fn drain_to_eof<S: Read>(stream: &mut S) -> io::Result<()> {
    let mut sink = [0u8; 256];
    loop {
        match stream.read(&mut sink) {
            Ok(0) => return Ok(()),
            Ok(_) => continue,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
    }
}
