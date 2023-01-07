//! QUIC/TLS setup. The server uses a self-signed certificate that clients pin on first use.
//! Confidentiality of sessions does not depend on it (they are end-to-end encrypted with Noise),
//! it protects the control channel metadata and bearer tokens.

use anyhow::Context;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

pub struct TlsIdentity {
    pub cert: CertificateDer<'static>,
    pub key: PrivatePkcs8KeyDer<'static>,
}

impl TlsIdentity {
    pub fn fingerprint(&self) -> [u8; 32] {
        Sha256::digest(self.cert.as_ref()).into()
    }
}

/// Loads `server.crt`/`server.key` (DER) from `dir`, generating them if absent.
pub fn load_or_create(dir: &Path) -> anyhow::Result<TlsIdentity> {
    let cert_path = dir.join("server.crt.der");
    let key_path = dir.join("server.key.der");
    if cert_path.exists() && key_path.exists() {
        return Ok(TlsIdentity {
            cert: CertificateDer::from(std::fs::read(&cert_path)?),
            key: PrivatePkcs8KeyDer::from(std::fs::read(&key_path)?),
        });
    }
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let ck = rcgen::generate_simple_self_signed(vec!["somedesk".to_string(), "localhost".to_string()])?;
    let cert = ck.cert.der().to_vec();
    let key = ck.key_pair.serialize_der();
    std::fs::write(&cert_path, &cert)?;
    write_private(&key_path, &key)?;
    Ok(TlsIdentity { cert: CertificateDer::from(cert), key: PrivatePkcs8KeyDer::from(key) })
}

fn write_private(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    opts.open(path)?.write_all(data)?;
    Ok(())
}

pub fn quinn_server_config(id: &TlsIdentity) -> anyhow::Result<quinn::ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![id.cert.clone()], PrivateKeyDer::Pkcs8(id.key.clone_key()))?;
    tls.alpn_protocols = vec![somedesk_proto::ALPN.to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_secs(30).try_into()?));
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    transport.max_concurrent_bidi_streams(64u32.into());
    cfg.transport_config(Arc::new(transport));
    Ok(cfg)
}
