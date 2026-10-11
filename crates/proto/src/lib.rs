//! Wire protocol shared by the SomeDesk server and clients.
//!
//! * [`control`] — the client ⇄ server control channel (accounts, devices, presence).
//! * [`session`] — messages exchanged end-to-end between two clients. These are only
//!   ever sent inside the Noise channel; the server never sees them.
//! * [`frame`] — length-prefixed framing used on every QUIC stream.

pub mod control;
pub mod frame;
pub mod session;

/// ALPN of direct QUIC connections between two devices.
pub const P2P_ALPN: &[u8] = b"somedesk-p2p/1";

/// ALPN identifier negotiated on the QUIC connection.
pub const ALPN: &[u8] = b"somedesk/1";

/// Bumped whenever the control protocol changes incompatibly.
pub const PROTOCOL_VERSION: u32 = 1;

/// Default UDP port of the server.
pub const DEFAULT_PORT: u16 = 21116;

/// Smallest and largest device id handed out by the server (9 digits, AnyDesk style).
pub const DEVICE_ID_MIN: u64 = 100_000_000;
pub const DEVICE_ID_MAX: u64 = 999_999_999;

/// Formats a device id as `123 456 789`.
pub fn format_device_id(id: u64) -> String {
    let s = id.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

/// Parses user input such as `123 456 789` or `123-456-789` into a device id.
pub fn parse_device_id(input: &str) -> Option<u64> {
    let digits: String = input.chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let id: u64 = digits.parse().ok()?;
    (DEVICE_ID_MIN..=DEVICE_ID_MAX).contains(&id).then_some(id)
}

/// Canonical form of a username: trimmed, lowercase, 3-32 chars of `a-z 0-9 . _ -`.
/// Client and server must agree on this exactly, because it is bound into the OPAQUE transcript.
pub fn normalize_username(name: &str) -> Option<String> {
    let n = name.trim().to_lowercase();
    let valid_chars = n.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    ((3..=32).contains(&n.len()) && valid_chars).then_some(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames_are_normalized_and_validated() {
        assert_eq!(normalize_username("  Alice ").as_deref(), Some("alice"));
        assert_eq!(normalize_username("bob.smith-2_x").as_deref(), Some("bob.smith-2_x"));
        assert_eq!(normalize_username("ab"), None);
        assert_eq!(normalize_username("has space"), None);
        assert_eq!(normalize_username("ünïcode"), None);
        assert_eq!(normalize_username(&"x".repeat(33)), None);
    }

    #[test]
    fn device_id_formatting_roundtrips() {
        assert_eq!(format_device_id(123456789), "123 456 789");
        assert_eq!(parse_device_id("123 456 789"), Some(123456789));
        assert_eq!(parse_device_id("123-456-789"), Some(123456789));
        assert_eq!(parse_device_id(" 123456789 "), Some(123456789));
    }

    #[test]
    fn device_id_rejects_garbage() {
        assert_eq!(parse_device_id(""), None);
        assert_eq!(parse_device_id("12345"), None);
        assert_eq!(parse_device_id("abc456789"), None);
        assert_eq!(parse_device_id("1234567890"), None);
    }
}
