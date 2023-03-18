#!/usr/bin/env bash
# Builds the Linux client as an AppImage:
#   packaging/linux/build-appimage.sh   →   target/dist/SomeDesk-<version>-x86_64.AppImage
#
# An AppImage only runs where glibc is at least as new as on the build machine, so build it on
# an old distribution. The release workflow uses Debian 12: the result runs on Debian 12 and
# Ubuntu 22.04 and later. (Ubuntu 22.04 itself can't build it: its PipeWire headers are too old
# for the bindings.) Needs the same system libraries as a normal build, plus curl.
set -euo pipefail
cd "$(dirname "$0")/../.."
export PATH="$HOME/.cargo/bin:$PATH"

LINUXDEPLOY_VERSION=1-alpha-20251107-1
LINUXDEPLOY_SHA256=c20cd71e3a4e3b80c3483cef793cda3f4e990aca14014d23c544ca3ce1270b4d

cargo build --release --locked -p somedesk-app
VERSION=$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "somedesk-app"))')

# linuxdeploy collects the libraries the binary links against and packs the AppImage.
TOOLS=target/appimage-tools
LINUXDEPLOY="$TOOLS/linuxdeploy-$LINUXDEPLOY_VERSION-x86_64.AppImage"
if [ ! -x "$LINUXDEPLOY" ]; then
    mkdir -p "$TOOLS"
    curl -sSfL -o "$LINUXDEPLOY.part" \
        "https://github.com/linuxdeploy/linuxdeploy/releases/download/$LINUXDEPLOY_VERSION/linuxdeploy-x86_64.AppImage"
    echo "$LINUXDEPLOY_SHA256  $LINUXDEPLOY.part" | sha256sum -c --quiet
    chmod +x "$LINUXDEPLOY.part"
    mv "$LINUXDEPLOY.part" "$LINUXDEPLOY"
fi

APPDIR=target/appimage/SomeDesk.AppDir
rm -rf "$APPDIR"
install -Dm755 target/release/somedesk "$APPDIR/usr/bin/somedesk"
install -Dm644 packaging/linux/somedesk.desktop "$APPDIR/usr/share/applications/somedesk.desktop"
install -Dm644 assets/brand/app-icon.svg "$APPDIR/usr/share/icons/hicolor/scalable/apps/somedesk.svg"
for size in 16 32 48 64 128 256 512; do
    install -Dm644 "assets/brand/app-icon-$size.png" "$APPDIR/usr/share/icons/hicolor/${size}x${size}/apps/somedesk.png"
done

mkdir -p target/dist
OUT="target/dist/SomeDesk-$VERSION-x86_64.AppImage"
rm -f "$OUT"
# Run linuxdeploy without FUSE (containers and CI runners often lack it).
export APPIMAGE_EXTRACT_AND_RUN=1
export LDAI_OUTPUT="$OUT" OUTPUT="$OUT"
# PipeWire's client library has to match the PipeWire running on the user's system (its
# plugins are loaded from there), so it is not bundled; every current desktop provides it.
"$LINUXDEPLOY" --appdir "$APPDIR" \
    --desktop-file "$APPDIR/usr/share/applications/somedesk.desktop" \
    --icon-file "$APPDIR/usr/share/icons/hicolor/256x256/apps/somedesk.png" \
    --exclude-library 'libpipewire-0.3.so*' \
    --output appimage
echo "$OUT"
