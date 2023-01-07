#!/usr/bin/env bash
# Runs the full test suite: unit tests, X11 backend tests on a private Xvfb, and the
# server/end-to-end integration tests against PostgreSQL.
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
