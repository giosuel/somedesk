#!/usr/bin/env bash
# Runs the full test suite: unit tests, X11 backend tests on a private Xvfb, the
# server/end-to-end integration tests against PostgreSQL, and (if GNOME is installed) a
# Wayland end-to-end test in a headless GNOME session.
#
#   SOMEDESK_TEST_DATABASE_URL  admin connection used to create throwaway databases
#                               (default: postgres://sysadmin:devpass@localhost/postgres)
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
export SOMEDESK_TEST_DATABASE_URL="${SOMEDESK_TEST_DATABASE_URL:-postgres://sysadmin:devpass@localhost/postgres}"

DISPLAY_NUM=":$(( 90 + RANDOM % 100 ))"
Xvfb "$DISPLAY_NUM" -screen 0 1024x768x24 -nolisten tcp -noreset >/dev/null 2>&1 &
XVFB_PID=$!
trap 'kill $XVFB_PID 2>/dev/null || true' EXIT
for _ in $(seq 50); do xdpyinfo -display "$DISPLAY_NUM" >/dev/null 2>&1 && break; sleep 0.1; done
export SOMEDESK_TEST_DISPLAY="$DISPLAY_NUM"

# X11 tests share one display, so run test binaries single-threaded where they touch it.
cargo test --workspace "$@" -- --test-threads=1

# Wayland: a headless GNOME session with the desktop portal, if GNOME is installed.
if command -v gnome-shell >/dev/null && [ -x /usr/libexec/xdg-desktop-portal-gnome ]; then
    export WL_DIR="/tmp/somedesk-wayland-test-$$"
    # The document portal mounts run/doc and may still hold it while the session stops.
    trap 'kill $XVFB_PID 2>/dev/null || true; scripts/wayland-env.sh stop >/dev/null 2>&1 || true
          fusermount3 -u "$WL_DIR/run/doc" 2>/dev/null || fusermount -u "$WL_DIR/run/doc" 2>/dev/null || true
          rm -rf "$WL_DIR" 2>/dev/null || true' EXIT
    scripts/wayland-env.sh start >/dev/null
    state=$(scripts/wayland-grant.sh)
    (
        . "$WL_DIR/env"
        unset SOMEDESK_TEST_DISPLAY
        # --workspace: the same dependency features as above, so nothing is rebuilt.
        SOMEDESK_TEST_WAYLAND_STATE="$state" cargo test --workspace --test session wayland "$@"
    )
else
    echo "gnome-shell / xdg-desktop-portal-gnome not installed: skipping the Wayland test"
fi
