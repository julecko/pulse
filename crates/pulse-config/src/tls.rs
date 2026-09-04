//! Shared TLS material for the encrypted, mutually-authenticated agent -> server
//! link.
//!
//! TLS 1.3 with certificate pinning in *both* directions:
//!
//! - the agent pins the server's self-signed certificate — it only talks to a
//!   server presenting exactly that cert;
//! - the server pins a set of approved agent certificates — it only accepts a
//!   client presenting one of them.
//!
//! A wrong/missing certificate on either side aborts the handshake. There is no
//! CA and no name checking; the pin *is* the trust decision. TLS 1.3 signatures
//! are still verified, so a cert can't be used without its private key.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, ring};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, Error as RustlsError, ServerConfig,
    SignatureScheme,
};
use sha2::{Digest, Sha256};

/// Logical name the agent uses for the `ServerName` argument. The pinning
/// verifier ignores it, but rustls still requires *a* name.
pub const PIN_SERVER_NAME: &str = "pulse";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("reading {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("{0}: no certificate found in PEM file")]
    NoCerts(String),
    #[error("{0}: no private key found in PEM file")]
    NoKey(String),
    #[error("{0}: no approved agent certificates (run `pulse-server cert approve ...`)")]
    NoTrustedAgents(String),
    #[error("tls: {0}")]
    Rustls(#[from] RustlsError),
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring::default_provider())
}

/// Read every certificate from a PEM file (leaf first).
pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, Error> {
    let pem = fs::read(path).map_err(|source| Error::Read {
        path: path.display().to_string(),
        source,
    })?;
    let certs = rustls_pemfile::certs(&mut pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| Error::Read {
            path: path.display().to_string(),
            source,
        })?;
    if certs.is_empty() {
        return Err(Error::NoCerts(path.display().to_string()));
    }
    Ok(certs)
}

/// Read the first private key (PKCS#8, SEC1, or RSA) from a PEM file.
pub fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, Error> {
    let pem = fs::read(path).map_err(|source| Error::Read {
        path: path.display().to_string(),
        source,
    })?;
    rustls_pemfile::private_key(&mut pem.as_slice())
        .map_err(|source| Error::Read {
            path: path.display().to_string(),
            source,
        })?
        .ok_or_else(|| Error::NoKey(path.display().to_string()))
}

/// Every leaf certificate from every `*.crt` file in `dir`.
fn load_certs_dir(dir: &Path) -> Result<Vec<CertificateDer<'static>>, Error> {
    let entries = fs::read_dir(dir).map_err(|source| Error::Read {
        path: dir.display().to_string(),
        source,
    })?;
    let mut out = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|source| Error::Read {
                path: dir.display().to_string(),
                source,
            })?
            .path();
        if path.extension().is_some_and(|e| e == "crt") {
            out.extend(load_certs(&path)?);
        }
    }
    Ok(out)
}

/// `sha256:AA:BB:...` over a certificate's DER encoding.
pub fn fingerprint(cert: &CertificateDer<'_>) -> String {
    let digest = Sha256::digest(cert.as_ref());
    let hex: Vec<String> = digest.iter().map(|b| format!("{b:02X}")).collect();
    format!("sha256:{}", hex.join(":"))
}

/// Server side: TLS 1.3, presents `cert_path`/`key_path`, and requires a client
/// certificate byte-matching one of the `*.crt` files in `trusted_agents`.
pub fn server_config(
    cert_path: &Path,
    key_path: &Path,
    trusted_agents: &Path,
) -> Result<Arc<ServerConfig>, Error> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;

    let trusted = load_certs_dir(trusted_agents)?;
    if trusted.is_empty() {
        return Err(Error::NoTrustedAgents(trusted_agents.display().to_string()));
    }
    let verifier = Arc::new(PinnedPeers { trusted });

    let config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;
    Ok(Arc::new(config))
}

/// TLS config for the **public HTTP API** listener: server authentication only
/// (no client certificate), TLS 1.3, ALPN `h2` + `http/1.1`.
///
/// Unlike [`server_config`] this is ordinary one-way TLS — supply a CA-issued
/// cert, or a self-signed one (`pulse-server cert generate-api`) whose
/// fingerprint the mobile app pins.
pub fn api_server_config(cert_path: &Path, key_path: &Path) -> Result<Arc<ServerConfig>, Error> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Agent side: TLS 1.3, pins the server cert in `server_cert`, and presents
/// `cert_path`/`key_path` as its client identity.
pub fn pinned_client_config(
    server_cert: &Path,
    cert_path: &Path,
    key_path: &Path,
) -> Result<Arc<ClientConfig>, Error> {
    let mut server = load_certs(server_cert)?;
    let verifier = Arc::new(PinnedServer {
        pinned: server.swap_remove(0),
    });
    let client_certs = load_certs(cert_path)?;
    let client_key = load_key(key_path)?;

    let config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(client_certs, client_key)?;
    Ok(Arc::new(config))
}

fn tls13_signature(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, RustlsError> {
    rustls::crypto::verify_tls13_signature(
        message,
        cert,
        dss,
        &provider().signature_verification_algorithms,
    )
}

fn tls12_not_offered() -> RustlsError {
    RustlsError::PeerIncompatible(rustls::PeerIncompatible::Tls12NotOffered)
}

fn schemes() -> Vec<SignatureScheme> {
    provider()
        .signature_verification_algorithms
        .supported_schemes()
}

/// Agent-side verifier: accepts exactly the pinned server leaf.
#[derive(Debug)]
struct PinnedServer {
    pinned: CertificateDer<'static>,
}

impl ServerCertVerifier for PinnedServer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        if end_entity.as_ref() == self.pinned.as_ref() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(RustlsError::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Err(tls12_not_offered())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        schemes()
    }
}

/// Server-side verifier: accepts any client leaf byte-matching one of the
/// approved certs.
#[derive(Debug)]
struct PinnedPeers {
    trusted: Vec<CertificateDer<'static>>,
}

impl ClientCertVerifier for PinnedPeers {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        if self
            .trusted
            .iter()
            .any(|t| t.as_ref() == end_entity.as_ref())
        {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(RustlsError::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Err(tls12_not_offered())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        schemes()
    }
}
