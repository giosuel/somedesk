#!/usr/bin/env bash
# Builds the Android app:
#   packaging/android/build-apk.sh   →   target/dist/SomeDesk-<version>.apk
#
# One APK for phones (arm64-v8a) and emulators (x86_64); ABIS="arm64-v8a" builds fewer.
#
# Needs the Android SDK (ANDROID_HOME, with platforms;android-35, build-tools;35.0.0 and an
# NDK, r28 or newer), a JDK, the Rust targets aarch64-linux-android and x86_64-linux-android,
# and cargo-ndk (cargo install cargo-ndk).
#
# Signing: with SOMEDESK_KEYSTORE (a keystore file), SOMEDESK_KEYSTORE_PASSWORD and optionally
# SOMEDESK_KEY_ALIAS (default "somedesk"). Without them the APK is signed with the Android debug
# key, which is fine for trying it out; updates must always be signed with the same key.
set -euo pipefail
cd "$(dirname "$0")/../.."
export PATH="$HOME/.cargo/bin:$PATH"

: "${ANDROID_HOME:?set ANDROID_HOME to the Android SDK}"
MIN_SDK=26
TARGET_SDK=35
ABIS=${ABIS:-"arm64-v8a x86_64"}
BUILD_TOOLS="$ANDROID_HOME/build-tools/35.0.0"
PLATFORM="$ANDROID_HOME/platforms/android-$TARGET_SDK/android.jar"
if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    ANDROID_NDK_HOME=$(ls -d "$ANDROID_HOME"/ndk/* | sort -V | tail -1)
fi
export ANDROID_NDK_HOME
# Slint compiles a small Java helper against this; C++ code (openh264) links its runtime
# statically so no libc++_shared.so has to be shipped.
export ANDROID_JAR="$PLATFORM" CXXSTDLIB=c++_static

OUT=target/apk
rm -rf "$OUT"
mkdir -p "$OUT/lib" target/dist

targets=()
for abi in $ABIS; do targets+=(-t "$abi"); done
cargo ndk -P "$MIN_SDK" "${targets[@]}" -o "$OUT/lib" build --release --locked -p somedesk-android
# The symbol table is a third of the library's size and not needed on the phone.
"$ANDROID_NDK_HOME"/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip --strip-unneeded "$OUT"/lib/*/libsomedesk.so

VERSION=$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "somedesk-android"))')
# 1.2.3 → 10203: increases with every release.
VERSION_CODE=$(echo "$VERSION" | awk -F'[.-]' '{print $1 * 10000 + $2 * 100 + $3}')
sed -e "s/@VERSION@/$VERSION/" -e "s/@VERSION_CODE@/$VERSION_CODE/" packaging/android/AndroidManifest.xml \
    >"$OUT/AndroidManifest.xml"

"$BUILD_TOOLS/aapt2" compile --dir packaging/android/res -o "$OUT/res.zip"
"$BUILD_TOOLS/aapt2" link -o "$OUT/unaligned.apk" -I "$PLATFORM" --manifest "$OUT/AndroidManifest.xml" \
    --min-sdk-version "$MIN_SDK" --target-sdk-version "$TARGET_SDK" "$OUT/res.zip"
# The native libraries: lib/<abi>/libsomedesk.so
python3 - "$OUT" <<'PY'
import pathlib, sys, zipfile
out = pathlib.Path(sys.argv[1])
with zipfile.ZipFile(out / "unaligned.apk", "a", zipfile.ZIP_DEFLATED) as apk:
    for lib in sorted((out / "lib").rglob("*.so")):
        apk.write(lib, lib.relative_to(out).as_posix())
PY
"$BUILD_TOOLS/zipalign" -f -P 16 4 "$OUT/unaligned.apk" "$OUT/aligned.apk"

if [ -n "${SOMEDESK_KEYSTORE:-}" ]; then
    KEYSTORE=$SOMEDESK_KEYSTORE
    ALIAS=${SOMEDESK_KEY_ALIAS:-somedesk}
    PASS="env:SOMEDESK_KEYSTORE_PASSWORD"
else
    KEYSTORE="$HOME/.android/debug.keystore"
    ALIAS=androiddebugkey
    export DEBUG_KEY_PASSWORD=android
    PASS="env:DEBUG_KEY_PASSWORD"
    if [ ! -f "$KEYSTORE" ]; then
        mkdir -p "$(dirname "$KEYSTORE")"
        keytool -genkeypair -keystore "$KEYSTORE" -storepass android -keypass android -alias "$ALIAS" \
            -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Android Debug,O=Android,C=US" >/dev/null
    fi
    echo "warning: SOMEDESK_KEYSTORE is not set; signing with the debug key ($KEYSTORE)" >&2
fi
APK="target/dist/SomeDesk-$VERSION.apk"
"$BUILD_TOOLS/apksigner" sign --ks "$KEYSTORE" --ks-key-alias "$ALIAS" --ks-pass "$PASS" --key-pass "$PASS" \
    --out "$APK" "$OUT/aligned.apk"
"$BUILD_TOOLS/apksigner" verify "$APK"
echo "$APK"
