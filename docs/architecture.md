# Architecture

SomeDesk is a Rust workspace: a server, a desktop client, and the libraries they share.

## Overview

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
