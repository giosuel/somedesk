#!/usr/bin/env bash
# Builds SomeDesk.app on macOS (needs Xcode command line tools):
#   packaging/macos/make-app.sh   →   target/dist/SomeDesk.app and SomeDesk-<version>-macos.zip
# The app is not signed or notarized; sign it with your Developer ID before distributing:
#   codesign --deep --options runtime --sign "Developer ID Application: …" target/dist/SomeDesk.app
set -euo pipefail
cd "$(dirname "$0")/../.."
cargo build --release --locked -p somedesk-app
VERSION=$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "somedesk-app"))')
APP=target/dist/SomeDesk.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp target/release/somedesk "$APP/Contents/MacOS/SomeDesk"

ICONSET=target/dist/SomeDesk.iconset
rm -rf "$ICONSET"; mkdir -p "$ICONSET"
for s in 16 32 128 256 512; do
    sips -z $s $s assets/brand/app-icon-512.png --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
    sips -z $((s * 2)) $((s * 2)) assets/brand/app-icon-512.png --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/SomeDesk.icns"
rm -rf "$ICONSET"

sed "s/@VERSION@/$VERSION/g" packaging/macos/Info.plist >"$APP/Contents/Info.plist"
(cd target/dist && ditto -c -k --keepParent SomeDesk.app "SomeDesk-$VERSION-macos.zip")
echo "$APP"
