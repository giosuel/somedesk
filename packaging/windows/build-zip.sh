#!/usr/bin/env bash
# Cross-builds the Windows client with MinGW and packs it with the runtime DLLs it needs:
#   packaging/windows/build-zip.sh   →   target/dist/SomeDesk-<version>-windows-x64.zip
set -euo pipefail
cd "$(dirname "$0")/../.."
export PATH="$HOME/.cargo/bin:$PATH"
TARGET=x86_64-pc-windows-gnu
cargo build --release --locked --target "$TARGET" -p somedesk-app
VERSION=$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "somedesk-app"))')
OUT="target/dist/SomeDesk-$VERSION-windows-x64"
rm -rf "$OUT" "$OUT.zip"
mkdir -p "$OUT"
cp "target/$TARGET/release/somedesk.exe" "target/$TARGET/release/somedesk-agent.exe" "$OUT/"
x86_64-w64-mingw32-strip "$OUT/somedesk.exe" "$OUT/somedesk-agent.exe"
# The video codec links the C++ runtime dynamically; ship it (and what it needs) alongside.
for dll in libstdc++-6.dll libgcc_s_seh-1.dll libwinpthread-1.dll; do
    path=$(x86_64-w64-mingw32-g++ -print-file-name="$dll")
    [ -f "$path" ] || path=$(find /usr/x86_64-w64-mingw32 -name "$dll" | head -1)
    cp "$path" "$OUT/"
    x86_64-w64-mingw32-strip --strip-unneeded "$OUT/$dll"
done
cp README.md "$OUT/README.md"
(cd target/dist && rm -f "$(basename "$OUT").zip" && python3 -m zipfile -c "$(basename "$OUT").zip" "$(basename "$OUT")")
echo "$OUT.zip"
