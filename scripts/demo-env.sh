#!/usr/bin/env bash
# Starts a local demo environment: a SomeDesk server on a fresh database and two virtual
# X displays (:50 = viewer "alice", :51 = host "bob"), each with a window manager.
# State is kept in $DEMO_DIR; run scripts/demo-env.sh stop to tear it down.
set -euo pipefail
cd "$(dirname "$0")/.."
DEMO_DIR="${DEMO_DIR:-/tmp/somedesk-demo}"
ADMIN_URL="${SOMEDESK_TEST_DATABASE_URL:-postgres://sysadmin:devpass@localhost/postgres}"
DB_URL="${ADMIN_URL%/*}/somedesk_demo"

stop() {
    for f in "$DEMO_DIR"/*.pid; do [ -e "$f" ] && kill "$(cat "$f")" 2>/dev/null || true; rm -f "$f"; done
}

if [ "${1:-start}" = stop ]; then stop; exit 0; fi

stop
mkdir -p "$DEMO_DIR"
psql "$ADMIN_URL" -qc "DROP DATABASE IF EXISTS somedesk_demo WITH (FORCE)" -c "CREATE DATABASE somedesk_demo"
rm -rf "$DEMO_DIR/server-data" "$DEMO_DIR/home-alice" "$DEMO_DIR/home-bob"

for d in 50 51; do
    Xvfb ":$d" -screen 0 1440x900x24 -nolisten tcp -noreset >"$DEMO_DIR/xvfb$d.log" 2>&1 &
    echo $! >"$DEMO_DIR/xvfb$d.pid"
done
sleep 1
for d in 50 51; do
    DISPLAY=":$d" openbox >"$DEMO_DIR/openbox$d.log" 2>&1 &
    echo $! >"$DEMO_DIR/openbox$d.pid"
done

target/debug/somedesk-server --listen 127.0.0.1:21116 --database-url "$DB_URL" --data-dir "$DEMO_DIR/server-data" \
    >"$DEMO_DIR/server.log" 2>&1 &
echo $! >"$DEMO_DIR/server.pid"
sleep 1
echo "server log: $DEMO_DIR/server.log"
