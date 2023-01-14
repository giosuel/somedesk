# SomeDesk

Self-hosted remote desktop (in the spirit of AnyDesk/TeamViewer) written in Rust, with
end-to-end encrypted sessions and zero-knowledge password login.

**Status:** Linux (X11) ↔ Linux remote control with clipboard sharing and password recovery works
end to end through the relay. Wayland, Windows and macOS backends, file transfer and P2P are next.

## Architecture

```
 viewer (Slint UI)                                     host (Slint UI)
 decode ← Noise ←─┐                               ┌─→ Noise → capture/encode
 input  → Noise →─┤  QUIC        server    QUIC   ├─← Noise ← inject (XTest)
                  └──────→ blind relay ←──────────┘
                           accounts · devices · presence (PostgreSQL)
```

| Crate | Purpose |
|---|---|
| `proto` | Wire types and length-prefixed framing |
| `crypto` | OPAQUE login, password-sealed identity key, device certificates, Noise channel |
| `server` | QUIC control protocol, device registry, presence, blind relay (PostgreSQL via sqlx) |
| `client` | Server connection, account flows, host and viewer session pipelines |
| `codec` | H.264 encode/decode (OpenH264) |
| `platform` | Screen capture and input injection (Linux/X11 today) |
| `app` | Desktop client (Slint) |
| `e2e-tests` | Integration tests: real server + PostgreSQL + relay + clients |

## Security model

* **Login:** OPAQUE (RFC 9807). The server never receives the password or anything that allows
  an offline dictionary attack without its OPRF key. Usernames are bound into the transcript.
* **Identity key:** each user has an Ed25519 identity key. It is stored on the server only as an
  XChaCha20-Poly1305 blob under a key derived (HKDF) from OPAQUE's export key — i.e. from the
  password. A server compromise does not reveal it.
* **Devices:** every device has its own X25519 key, certified by the user's identity key.
  Devices come online with a bearer token (stored hashed on the server); the identity private key
  is not kept on disk.
* **Sessions:** `Noise_XX_25519_ChaChaPoly_BLAKE2s` between the two devices, bound to the session
  id, with certificates exchanged inside the encrypted handshake. Each side checks the peer's
  certificate chain itself. The relay forwards ciphertext only (verified by tests that tap it).
* **Interception check:** both sides display identity fingerprints. Connections from your own
  account are marked as verified; the host must accept every connection unless
  “unattended access for my own devices” is enabled.
* **Clipboard:** text is shared inside the encrypted session in both directions (switchable in
  the app). The host's clipboard is only sent after someone copies something during the
  session, never what it held before.
* **What the server does see:** who connects to whom, when, and how much data flows.
* **Recovery key:** a second copy of the identity key is sealed under a 160-bit recovery key that
  is shown once at sign-up (`XXXX-XXXX-…`, with a checksum that catches typos). To reset a
  forgotten password, the client proves it holds the recovery key by signing a server challenge
  with a key derived from it, opens the recovery copy and re-seals it under the new password.
  The server can't open either copy or reset a password without the key. Recovery keys are
  single-use: a reset issues a new one. Without the password *and* the recovery key, the identity
  is lost by design.

## Building and running

Requirements (Debian/Ubuntu): `build-essential pkg-config libfontconfig1-dev libxkbcommon-dev
libxkbcommon-x11-dev libxcb1-dev libx11-dev postgresql` (tests: `xvfb xsel`).

```sh
cargo build --release

# Server (creates its schema and a self-signed certificate on first start)
DATABASE_URL=postgres://user:pass@localhost/somedesk \
  target/release/somedesk-server --listen 0.0.0.0:21116 --data-dir ./data

# Client (pins the server certificate on first use)
target/release/somedesk --server your.server.example
```

`--profile NAME` runs independent client instances side by side (separate credentials).

## Tests

```sh
scripts/test.sh          # everything: unit tests, X11 tests on a private Xvfb, server + E2E tests
```

The clipboard test also needs `xsel`. Database tests need `SOMEDESK_TEST_DATABASE_URL` (an admin connection used to create throwaway
databases; `scripts/test.sh` defaults to the local dev role). X11 tests need `Xvfb`.

`scripts/demo-env.sh` starts a server and two virtual displays for manual testing.
