# SomeDesk

Self-hosted remote desktop (in the spirit of AnyDesk/TeamViewer) written in Rust, with
end-to-end encrypted sessions and zero-knowledge password login.

**Status:** remote control works end to end on Linux (X11, and Wayland via the desktop portal),
with Windows and macOS backends written and compile-checked (see *Platforms*), with clipboard sharing, file transfer in both
directions, a choice of which monitor to view, direct peer-to-peer connections with relay
fallback, and password recovery.

![SomeDesk: a remote session](docs/media/session.webp)

▶ [Watch a 25-second demo](docs/media/somedesk-demo.mp4): connecting, remote control,
monitors and file transfer.

## Screenshots

| | |
|---|---|
| ![Home](docs/media/home.webp) | ![Incoming request](docs/media/incoming.webp) |
| **Home:** this computer's ID and identity fingerprint | **Incoming request:** the host sees who is calling and their fingerprint |
| ![File offer](docs/media/file-offer.webp) | ![Identity changed](docs/media/identity-changed.webp) |
| **Files both ways:** files from the host are only saved once accepted | **Identity changed:** SomeDesk stops and warns if a contact's key changes |
| ![Contacts](docs/media/contacts.webp) | ![Create an account](docs/media/sign-up.webp) |
| **Contacts:** remembered identities and unattended access | **Sign-up:** the password never leaves the computer |

## Architecture

```
 viewer (Slint UI)                                     host (Slint UI)
 decode ← Noise ←─┐                               ┌─→ Noise → capture/encode
 input  → Noise →─┤  QUIC        server    QUIC   ├─← Noise ← inject (XTest / portal)
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
| `platform` | Screen capture, input injection and clipboard (Linux: X11, and Wayland via the desktop portal + PipeWire) |
| `app` | Desktop client (Slint); fonts: Geist / Geist Mono (OFL) |
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
* **Interception check:** both sides display identity fingerprints. Each client also remembers
  the identity key of everyone it has connected with (trust on first use, like SSH) and warns
  loudly if it changes, which is what a malicious server would have to do to get in between.
  The viewer stops before connecting; the host's prompt turns into a warning.
* **Who may connect:** the host accepts every connection unless it comes from one of its own
  account's devices with “unattended access” on, or from a device the user ticked “let this device
  connect without asking” for. That permission is tied to the device key *and* the user's identity
  key, and can be revoked under Contacts.
* **Clipboard:** text is shared inside the encrypted session in both directions (switchable in
  the app). The host's clipboard is only sent after someone copies something during the
  session, never what it held before.
* **File transfer:** files travel inside the encrypted session. The receiver writes to a hidden
  partial file and only keeps it if size and SHA-256 match; names are sanitized so a peer cannot
  write outside `~/Downloads/SomeDesk`. The host saves files from the viewer directly (the viewer
  controls it anyway); the viewer is asked before accepting each file from the host.
* **Direct connections:** when both devices allow it, they exchange candidate addresses through
  the server and connect straight to each other over QUIC (hole punching through NATs, with
  low-TTL punch packets so stray first packets don't spoil the NAT mapping). Whichever path the
  viewer's first Noise message arrives on wins; if nothing direct works within 2.5 s, the relay is
  used. The QUIC layer of a direct connection uses throwaway certificates; authenticity comes from
  the Noise handshake as always. Turning direct connections off keeps a device's IP addresses from
  being shared with peers.
* **What the server does see:** who connects to whom, when, and how much data flows.
* **Recovery key:** a second copy of the identity key is sealed under a 160-bit recovery key that
  is shown once at sign-up (`XXXX-XXXX-…`, with a checksum that catches typos). To reset a
  forgotten password, the client proves it holds the recovery key by signing a server challenge
  with a key derived from it, opens the recovery copy and re-seals it under the new password.
  The server can't open either copy or reset a password without the key. Recovery keys are
  single-use: a reset issues a new one. Without the password *and* the recovery key, the identity
  is lost by design.

## Building and running

Requirements (Debian/Ubuntu): `build-essential pkg-config clang libfontconfig1-dev libxkbcommon-dev
libxkbcommon-x11-dev libxcb1-dev libx11-dev libpipewire-0.3-dev libspa-0.2-dev postgresql`
(tests: `xvfb xsel`, and for the Wayland test `gnome-shell xdg-desktop-portal-gnome pipewire
wireplumber`).

```sh
cargo build --release

# Server (creates its schema and a self-signed certificate on first start)
DATABASE_URL=postgres://user:pass@localhost/somedesk \
  target/release/somedesk-server --listen 0.0.0.0:21116 --data-dir ./data

# Client (pins the server certificate on first use)
target/release/somedesk --server your.server.example
```

`--profile NAME` runs independent client instances side by side (separate credentials).

## Platforms

| Host platform | Capture | Input | Verified |
|---|---|---|---|
| Linux X11 | XGetImage, RandR monitors | XTest | end to end (tests + manual) |
| Linux Wayland | xdg-desktop-portal + PipeWire | portal RemoteDesktop | end to end in headless GNOME |
| Windows | GDI BitBlt, all monitors | SendInput | backend tests pass under Wine; app UI runs under Wine; networking needs real Windows (Wine lacks `IP_RECVECN`, which QUIC uses) |
| macOS | CoreGraphics display images | CGEvent | compile-checked only |

Windows builds use the MinGW toolchain (`x86_64-pc-windows-gnu`); ship `libstdc++-6.dll`,
`libgcc_s_seh-1.dll` and `libwinpthread-1.dll` next to `somedesk.exe`. On macOS the user must allow
*Screen Recording* (required) and *Accessibility* (for control; otherwise view-only). Neither
covers the login screen or UAC prompts yet; that needs a system service / launch daemon.

## Linux desktops

The host picks its backend from the session: **X11** (XGetImage + XTest; RandR monitors can be
viewed one at a time), or on **Wayland** the
**xdg-desktop-portal** (`RemoteDesktop` + `ScreenCast`, frames over PipeWire).
`SOMEDESK_BACKEND=x11|portal` overrides the choice.

On Wayland the desktop itself asks the person at the host for permission the first time someone
connects (after they accepted in SomeDesk). They choose *Share* and switch on *Allow Remote
Interaction*; SomeDesk tells them so. The portal's restore token is stored next to the device
credentials, so later sessions start without asking again. If remote interaction is not allowed,
or the desktop has no remote-input portal (wlroots compositors such as sway), the screen is shared
view-only and the viewer is told.

Known gaps: the view-only path on wlroots is untested (xdg-desktop-portal-wlr cannot capture a
GPU-less headless sway); clipboard sharing on GNOME Wayland goes through XWayland, since GNOME
does not offer the Wayland data-control protocol.

## Packaging

| What | How | Output |
|---|---|---|
| Server container | `podman build -f packaging/server/Dockerfile -t somedesk-server .` (or `docker build`) | image (≈95 MB) |
| Server + PostgreSQL | `SOMEDESK_DB_PASSWORD=… podman compose -f packaging/server/compose.yaml up -d` | two containers |
| Server on a host | `cargo deb -p somedesk-server` (systemd unit, `somedesk` user, `/etc/somedesk/server.env`) or `packaging/server/somedesk-server.service` | `.deb` |
| Linux client | `cargo deb -p somedesk-app` (desktop entry, icons) | `.deb` |
| Windows client | `packaging/windows/build-zip.sh` (cross-built with MinGW; icon embedded) | `.zip` with `somedesk.exe` and runtime DLLs |
| macOS client | `packaging/macos/make-app.sh` on a Mac (unsigned) | `SomeDesk.app` + `.zip` |

The `.deb`s depend on the glibc of the machine that built them: build release packages on the
oldest distribution you want to support. Install `cargo-deb` with `cargo install cargo-deb`.

## Brand

`assets/brand/` holds the logo (`logo.svg`, `mark.svg`) and the app icon (`app-icon.svg` plus PNG
renders). `assets/icons/` is the icon set: 24 px, 2 px round strokes. Icons are defined once in
`scripts/gen-icons.py`, which writes both the SVGs and `crates/app/ui/icons.slint`.

## Tests

```sh
scripts/test.sh          # everything: unit tests, X11 tests on a private Xvfb, server + E2E tests
```

The clipboard test also needs `xsel`. Database tests need `SOMEDESK_TEST_DATABASE_URL` (an admin connection used to create throwaway
databases; `scripts/test.sh` defaults to the local dev role). X11 tests need `Xvfb`.

`.github/workflows/ci.yml` runs on GitHub Actions: formatting and clippy, the Linux suite with
PostgreSQL and Xvfb plus the NAT test, unit tests and app builds on real Windows and macOS
runners (uploaded as artifacts), and the `.deb` packages and server image.

`scripts/nat-test.sh` (needs sudo) builds two private networks behind real Linux NATs with
network namespaces and checks that peers connect directly behind ordinary NATs and fall back to the
relay behind symmetric ones.

`scripts/demo-env.sh` starts a server and two virtual displays for manual testing.
`scripts/wayland-env.sh` starts a headless GNOME Wayland session (with PipeWire and the portal);
`scripts/gnome-input.sh` drives it like `xdotool`, and `scripts/wayland-grant.sh` answers the
portal's permission dialog once. `scripts/test.sh` uses them for the Wayland end-to-end test.
