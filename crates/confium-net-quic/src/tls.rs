//! TLS material for the QUIC transport.
//!
//! QUIC requires TLS 1.3. The Confium transport is intentionally
//! transport-unauthenticated — TC sessions sign every round message at
//! the application layer (see `TODO.roadmap/05-networking-primitives.md`,
//! "Application-layer signatures"). To keep the transport usable without
//! a real PKI, this module generates a fresh self-signed certificate per
//! process and configures clients to accept any server certificate.
//!
//! The certificate / key live only in memory; they are never persisted.

use std::sync::Arc;
use std::sync::OnceLock;

use quinn::crypto::rustls::QuicClientConfig;
use quinn::crypto::rustls::QuicServerConfig;
use rcgen::CertificateParams;
use rcgen::KeyPair;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::ServerName;
use rustls::pki_types::UnixTime;

/// In-memory self-signed certificate + key, generated once and reused.
struct SelfSigned {
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
}

static SELF_SIGNED: OnceLock<SelfSigned> = OnceLock::new();

/// Return the lazily-generated process-wide self-signed certificate and
/// private key (in DER form). First call pays the generation cost;
/// subsequent calls reuse the cached values. Panics on failure —
/// generation from a fixed, in-tree algorithm cannot fail in practice,
/// and propagating an error up through `register_transport!` /
/// `block_on` adds complexity for no benefit.
fn self_signed() -> &'static SelfSigned {
    SELF_SIGNED.get_or_init(|| {
        let params = CertificateParams::new(vec!["localhost".to_string()]).expect("valid SAN list");
        let key_pair = KeyPair::generate().expect("generate ECDSA key pair");
        let cert = params
            .self_signed(&key_pair)
            .expect("self-sign certificate");
        SelfSigned {
            cert_der: cert.der().to_vec(),
            key_der: key_pair.serialize_der(),
        }
    })
}

/// Build a Quinn server configuration using the in-memory self-signed
/// certificate. Used by [`crate::listener::QuicListener`].
pub(crate) fn server_config() -> std::result::Result<quinn::ServerConfig, String> {
    let signed = self_signed();
    let cert = CertificateDer::from(signed.cert_der.clone());
    let key = PrivateKeyDer::try_from(signed.key_der.clone())
        .map_err(|e| format!("decode private key: {e}"))?;
    let rustls_cfg = rustls::server::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| format!("build rustls server config: {e}"))?;
    let quic_cfg = QuicServerConfig::try_from(rustls_cfg)
        .map_err(|e| format!("wrap rustls server config for quinn: {e}"))?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(quic_cfg)))
}

/// Build a Quinn client configuration that accepts any server
/// certificate. The TC protocol authenticates peers at the application
/// layer; transport-level verification is intentionally disabled.
pub(crate) fn client_config() -> std::result::Result<quinn::ClientConfig, String> {
    // Skip server certificate verification entirely. This is safe in
    // Confium's model because every TC round message carries an
    // application-layer signature from the sender's long-term key; a
    // MITM without that key cannot forge protocol messages.
    let rustls_cfg = rustls::client::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    let quic_cfg = QuicClientConfig::try_from(rustls_cfg)
        .map_err(|e| format!("wrap rustls client config for quinn: {e}"))?;
    Ok(quinn::ClientConfig::new(Arc::new(quic_cfg)))
}

/// A certificate verifier that approves everything. See
/// [`client_config`] for the rationale.
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}
