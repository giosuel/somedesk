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

/// Loads `server.crt`/`server.key` (DER) from `dir`, generating them if neither is there.
///
/// Clients pin the certificate, so a new one locks every one of them out: with only one of the
/// two files there, this fails instead of quietly making a new pair.
pub fn load_or_create(dir: &Path) -> anyhow::Result<TlsIdentity> {
    let cert_path = dir.join("server.crt.der");
    let key_path = dir.join("server.key.der");
    match (cert_path.exists(), key_path.exists()) {
        (true, true) => {
            return Ok(TlsIdentity {
                cert: CertificateDer::from(std::fs::read(&cert_path)?),
                key: PrivatePkcs8KeyDer::from(std::fs::read(&key_path)?),
            });
        }
        (false, false) => {}
        (cert, _) => anyhow::bail!(
            "{} is there but {} is missing. Restore it from a backup: a new certificate would lock out every \
             client that knows this server. To start over with a new one anyway, delete {} too.",
            if cert { cert_path.display() } else { key_path.display() },
            if cert { key_path.display() } else { cert_path.display() },
            if cert { cert_path.display() } else { key_path.display() },
        ),
    }
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let ck = rcgen::generate_simple_self_signed(vec!["somedesk".to_string(), "localhost".to_string()])?;
    let cert = ck.cert.der().to_vec();
    let key = ck.key_pair.serialize_der();
    // The key first: a certificate on its own would make the next start fail above.
    write_atomic(&key_path, &key, true)?;
    write_atomic(&cert_path, &cert, false)?;
    Ok(TlsIdentity { cert: CertificateDer::from(cert), key: PrivatePkcs8KeyDer::from(key) })
}

/// Writes `path` as a whole or not at all (a temporary file renamed over it); readable by the
/// owner only if `private`.
fn write_atomic(path: &Path, data: &[u8], private: bool) -> anyhow::Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(if private { 0o600 } else { 0o644 });
    #[cfg(not(unix))]
    let _ = private;
    let mut f = opts.open(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))?;
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
    // Clients send keep-alives; the server sends none, so a connection nobody uses times out.
    transport.max_idle_timeout(Some(Duration::from_secs(30).try_into()?));
    transport.max_concurrent_bidi_streams(64u32.into());
    cfg.transport_config(Arc::new(transport));
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_half_is_an_error_not_a_new_identity() {
        let dir = std::env::temp_dir().join(format!("somedesk-tls-{}-{}", std::process::id(), rand::random::<u32>()));
        let first = load_or_create(&dir).unwrap();
        assert_eq!(load_or_create(&dir).unwrap().fingerprint(), first.fingerprint(), "kept");
        std::fs::remove_file(dir.join("server.key.der")).unwrap();
        let e = load_or_create(&dir).err().expect("refuses").to_string();
        assert!(e.contains("server.key.der is missing"), "{e}");
        assert!(dir.join("server.crt.der").exists(), "nothing replaced");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
