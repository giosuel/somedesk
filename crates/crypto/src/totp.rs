//! Time-based one-time passwords (RFC 6238): the 6-digit codes of authenticator apps.
//!
//! HMAC-SHA1, 30-second steps, 6 digits: what every authenticator app understands. A code is
//! accepted one step early or late (clocks drift), and each step only once.

use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha1::Sha1;
use zeroize::Zeroizing;

const STEP_SECONDS: u64 = 30;
const DIGITS: u32 = 6;
const SECRET_LEN: usize = 20;

/// A TOTP secret, shared with the authenticator app once (as a QR code or text).
#[derive(Clone, PartialEq, Eq)]
pub struct TotpSecret(Zeroizing<Vec<u8>>);

impl std::fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TotpSecret(..)")
    }
}

impl TotpSecret {
    pub fn generate() -> Self {
        let mut bytes = vec![0u8; SECRET_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self(Zeroizing::new(bytes))
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(Zeroizing::new(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The secret as authenticator apps take it when typed in: base32, e.g. `JBSW Y3DP …`.
    pub fn base32(&self) -> String {
        base32_encode(&self.0)
    }

    pub fn from_base32(text: &str) -> Option<Self> {
        base32_decode(text).filter(|b| !b.is_empty()).map(|b| Self(Zeroizing::new(b)))
    }

    /// The `otpauth://` link authenticator apps read from a QR code.
    pub fn uri(&self, issuer: &str, account: &str) -> String {
        format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}",
            percent(issuer),
            percent(account),
            self.base32(),
            percent(issuer)
        )
    }

    /// The code for the 30-second step `step`.
    pub fn code_at(&self, step: u64) -> String {
        let mut mac = Hmac::<Sha1>::new_from_slice(&self.0).expect("HMAC takes any key length");
        mac.update(&step.to_be_bytes());
        let hash = mac.finalize().into_bytes();
        let offset = (hash[19] & 0x0f) as usize;
        let value = u32::from_be_bytes([hash[offset] & 0x7f, hash[offset + 1], hash[offset + 2], hash[offset + 3]]);
        format!("{:0width$}", value % 10u32.pow(DIGITS), width = DIGITS as usize)
    }

    /// Checks `code` at `unix_seconds`. `last_step` is the step of the last accepted code: that
    /// one and earlier ones are refused, so a code can't be used twice. Returns the step to
    /// remember on success.
    pub fn verify(&self, code: &str, unix_seconds: u64, last_step: Option<u64>) -> Option<u64> {
        let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        if code.len() != DIGITS as usize || !code.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let now = unix_seconds / STEP_SECONDS;
        [now, now.saturating_sub(1), now + 1].into_iter().find(|&step| {
            last_step.is_none_or(|last| step > last)
                && subtle::ConstantTimeEq::ct_eq(self.code_at(step).as_bytes(), code.as_bytes()).into()
        })
    }
}

/// The current Unix time in seconds.
pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut buffer, mut bits) = (0u32, 0);
    for &byte in data {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buffer, mut bits) = (0u32, 0);
    for c in text.chars().filter(|c| !c.is_whitespace() && *c != '-' && *c != '=') {
        let value = ALPHABET.iter().position(|&a| a as char == c.to_ascii_uppercase())? as u32;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

fn percent(text: &str) -> String {
    text.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The RFC 6238 test vectors for SHA1 (8 digits there; the last 6 here).
    #[test]
    fn rfc_6238_vectors() {
        let secret = TotpSecret::from_bytes(b"12345678901234567890");
        for (time, code) in
            [(59u64, "94287082"), (1111111109, "07081804"), (1234567890, "89005924"), (2000000000, "69279037")]
        {
            assert_eq!(secret.code_at(time / 30), code[2..], "at {time}");
        }
    }

    #[test]
    fn codes_are_accepted_once_and_with_some_drift() {
        let secret = TotpSecret::generate();
        let t = 1_700_000_000;
        let code = secret.code_at(t / 30);
        let step = secret.verify(&code, t, None).unwrap();
        assert_eq!(secret.verify(&code, t, Some(step)), None, "not twice");
        assert!(secret.verify(&code, t + 30, None).is_some(), "a step late is fine");
        assert!(secret.verify(&code, t + 90, None).is_none(), "three steps late is not");
        assert!(secret.verify("12345", t, None).is_none());
        assert!(secret.verify(&format!("{} {}", &code[..3], &code[3..]), t, None).is_some(), "spaces are ignored");
    }

    #[test]
    fn base32_roundtrip_and_uri() {
        let secret = TotpSecret::from_bytes(b"Hello!\xde\xad\xbe\xef");
        assert_eq!(secret.base32(), "JBSWY3DPEHPK3PXP");
        assert_eq!(TotpSecret::from_base32("jbsw y3dp ehpk 3pxp").unwrap(), secret);
        assert!(TotpSecret::from_base32("not base32!").is_none());
        let uri = secret.uri("SomeDesk", "123 456 789");
        assert_eq!(
            uri,
            "otpauth://totp/SomeDesk:123%20456%20789?secret=JBSWY3DPEHPK3PXP&issuer=SomeDesk&algorithm=SHA1&digits=6&period=30"
        );
    }
}
