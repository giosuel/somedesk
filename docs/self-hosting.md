# Self-hosting

Run your own SomeDesk server and build the clients. The server is the whole product, not a
trial of it: there's no licence key and no limit on devices or users, and there never will be
([free, forever](free.md)).

## Who may use your server

By default, any installation that reaches the server gets an ID and can connect by ID; accounts
are optional. That suits a server for friends and family, since nobody has to sign up.

To keep the server to people you know, start it with `--accounts-only` (or
`SOMEDESK_ACCOUNTS_ONLY=true`). Devices then have to sign in to an account on the server before
they come online. Account creation itself stays open, so put the server where only your people
reach it, or create the accounts yourself and then firewall it.

The server never decides who may *control* a computer. That's always up to the computer itself
(see [Ways to connect](connecting.md)).

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

`--profile NAME` runs independent client instances side by side (separate credentials), and
`--background` starts the client in the tray without a window.

`target/release/somedesk-agent` is the agent for machines enrolled into an
[organisation](organisations.md). Every client package includes it.

## Packaging

| What | How | Output |
|---|---|---|
| Server container | Published as `ghcr.io/giosuel/somedesk-server` for x86-64 and ARM64: `latest` and `<version>` for releases, `main` for the latest code on main. To build it: `podman build -f packaging/server/Dockerfile -t somedesk-server .` (or `docker build`) | image (≈95 MB) |
| Server + PostgreSQL | `SOMEDESK_DB_PASSWORD=… podman compose -f packaging/server/compose.yaml up -d` (uses the published image; `SOMEDESK_IMAGE` picks another) | two containers |
| Server on a host | `cargo deb -p somedesk-server` (systemd unit, `somedesk` user, `/etc/somedesk/server.env`) or `packaging/server/somedesk-server.service` | `.deb` |
| Linux client | `cargo deb -p somedesk-app` (desktop entry, icons, `somedesk-agent`) | `.deb` |
| Linux client, any distribution | `packaging/linux/build-appimage.sh` (bundles its libraries except glibc, graphics and PipeWire; build on an old distribution such as Debian 12) | `.AppImage` |
| Arch Linux client | `packaging/aur/test.sh` (builds the AUR packages `somedesk` and `somedesk-bin` in an Arch container) | `.pkg.tar.zst` |
| Windows client | `packaging/windows/build-zip.sh` (cross-built with MinGW; icon embedded) | `.zip` with `somedesk.exe`, `somedesk-agent.exe` and runtime DLLs |
| macOS client | `packaging/macos/make-app.sh` on a Mac (unsigned) | `SomeDesk.app` + `.zip` |
| Android app | `packaging/android/build-apk.sh` (needs the Android SDK and NDK; see the script) | `.apk` for phones and emulators |

The `.deb`s depend on the glibc of the machine that built them: build release packages on the
oldest distribution you want to support. Install `cargo-deb` with `cargo install cargo-deb`.
