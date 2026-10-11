# Self-hosting

Run your own SomeDesk server and build the clients.

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

## Packaging

| What | How | Output |
|---|---|---|
| Server container | `podman build -f packaging/server/Dockerfile -t somedesk-server .` (or `docker build`) | image (≈95 MB) |
| Server + PostgreSQL | `SOMEDESK_DB_PASSWORD=… podman compose -f packaging/server/compose.yaml up -d` | two containers |
| Server on a host | `cargo deb -p somedesk-server` (systemd unit, `somedesk` user, `/etc/somedesk/server.env`) or `packaging/server/somedesk-server.service` | `.deb` |
| Linux client | `cargo deb -p somedesk-app` (desktop entry, icons) | `.deb` |
| Linux client, any distribution | `packaging/linux/build-appimage.sh` (bundles its libraries except glibc, graphics and PipeWire; build on an old distribution such as Debian 12) | `.AppImage` |
| Windows client | `packaging/windows/build-zip.sh` (cross-built with MinGW; icon embedded) | `.zip` with `somedesk.exe` and runtime DLLs |
| macOS client | `packaging/macos/make-app.sh` on a Mac (unsigned) | `SomeDesk.app` + `.zip` |

The `.deb`s depend on the glibc of the machine that built them: build release packages on the
oldest distribution you want to support. Install `cargo-deb` with `cargo install cargo-deb`.
