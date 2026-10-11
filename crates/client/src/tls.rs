//! Server certificate pinning (trust on first use).
//!
//! The server uses a self-signed certificate. On first contact the client records its SHA-256
//! fingerprint; afterwards a different certificate is refused. Session content does not rely on
//! this (it is end-to-end encrypted), but it protects bearer tokens and metadata.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub struct PinningVerifier {
    pin: Option<[u8; 32]>,
    seen: Mutex<Option<[u8; 32]>>,
    provider: Arc<CryptoProvider>,
}

impl PinningVerifier {
    pub fn new(pin: Option<[u8; 32]>, provider: Arc<CryptoProvider>) -> Self {
        Self { pin, seen: Mutex::new(None), provider }
    }

    /// Fingerprint of the certificate presented in the last handshake.
    pub fn seen(&self) -> Option<[u8; 32]> {
        *self.seen.lock().unwrap()
    }
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fp: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        *self.seen.lock().unwrap() = Some(fp);
        match self.pin {
            Some(pin) if pin != fp => Err(rustls::Error::General(
                "the server's certificate changed since the first connection (possible interception)".into(),
            )),
            _ => Ok(ServerCertVerified::assertion()),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}
