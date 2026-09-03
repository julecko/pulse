//! Shared TLS material for the encrypted agent -> server link.
//!
//! The link is TLS 1.3. The server presents a self-signed certificate; the
//! agent *pins* it — the handshake succeeds only if the server's leaf
//! certificate is byte-for-byte the one the agent was given
//! (`pulse-agent cert trust ...`). A wrong or missing pin => the agent cannot
//! connect, i.e. it is rejected.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, ring};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, ServerConfig, SignatureScheme,
};
use sha2::{Digest, Sha256};

/// Logical name the agent uses for SNI / the `ServerName` argument. The pinning
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

/// `sha256:AA:BB:...` over a certificate's DER encoding — stable identity you
/// can eyeball-compare between `pulse-server cert fingerprint` and
/// `pulse-agent cert fingerprint`.
pub fn fingerprint(cert: &CertificateDer<'_>) -> String {
    let digest = Sha256::digest(cert.as_ref());
    let hex: Vec<String> = digest.iter().map(|b| format!("{b:02X}")).collect();
    format!("sha256:{}", hex.join(":"))
}

/// Server side: TLS 1.3 config presenting `cert_path` / `key_path`.
pub fn server_config(cert_path: &Path, key_path: &Path) -> Result<Arc<ServerConfig>, Error> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(Arc::new(config))
}

/// Agent side: TLS 1.3 config that trusts exactly the certificate in
/// `server_cert_path` and nothing else.
pub fn pinned_client_config(server_cert_path: &Path) -> Result<Arc<ClientConfig>, Error> {
    let mut certs = load_certs(server_cert_path)?;
    let verifier = Arc::new(PinnedServer {
        pinned: certs.swap_remove(0),
    });
    let config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Verifier that accepts one specific leaf certificate. The TLS 1.3 signature is
/// still checked, so presenting the pinned cert without its private key fails.
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
        Err(RustlsError::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
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

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
