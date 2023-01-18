#!/usr/bin/env bash
# Starts a headless GNOME Wayland session for testing the Wayland backend: a private D-Bus
# session bus, PipeWire + WirePlumber, and gnome-shell with a virtual monitor. The portal
# (xdg-desktop-portal + the GNOME backend) is started on demand through D-Bus activation.
#
#   scripts/wayland-env.sh start   # prints the environment to `eval`
#   scripts/wayland-env.sh stop
#
# gnome-shell runs with --unsafe-mode so tests can drive it over D-Bus (Shell.Eval, screenshots).
set -euo pipefail
WL_DIR="${WL_DIR:-/tmp/somedesk-wayland}"
SIZE="${SIZE:-1440x900}"

stop() {
    for f in "$WL_DIR"/*.pid; do [ -e "$f" ] && kill "$(cat "$f")" 2>/dev/null || true; rm -f "$f"; done
    # Portal processes were started by D-Bus activation; they exit with the bus, but make sure.
    if [ -e "$WL_DIR/bus.pid" ]; then kill "$(cat "$WL_DIR/bus.pid")" 2>/dev/null || true; fi
}

case "${1:-start}" in
stop) stop; exit 0 ;;
start) ;;
*) echo "usage: $0 start|stop" >&2; exit 2 ;;
esac

stop
rm -rf "$WL_DIR"
mkdir -p "$WL_DIR/run" "$WL_DIR/config" "$WL_DIR/data" "$WL_DIR/cache"
chmod 700 "$WL_DIR/run"
export XDG_RUNTIME_DIR="$WL_DIR/run" XDG_CONFIG_HOME="$WL_DIR/config" XDG_DATA_HOME="$WL_DIR/data" \
    XDG_CACHE_HOME="$WL_DIR/cache" XDG_CURRENT_DESKTOP=GNOME XDG_SESSION_TYPE=wayland
unset DISPLAY WAYLAND_DISPLAY

eval "$(dbus-daemon --session --fork --print-address=1 --print-pid=1 | {
    read -r addr; read -r pid; echo "DBUS_SESSION_BUS_ADDRESS='$addr'; echo $pid > '$WL_DIR/bus.pid'"; })"
export DBUS_SESSION_BUS_ADDRESS

pipewire >"$WL_DIR/pipewire.log" 2>&1 & echo $! >"$WL_DIR/pipewire.pid"
sleep 0.5
wireplumber >"$WL_DIR/wireplumber.log" 2>&1 & echo $! >"$WL_DIR/wireplumber.pid"
gnome-shell --headless --unsafe-mode --virtual-monitor "$SIZE" --no-x11 >"$WL_DIR/gnome-shell.log" 2>&1 &
echo $! >"$WL_DIR/gnome-shell.pid"
for _ in $(seq 100); do [ -S "$XDG_RUNTIME_DIR/wayland-0" ] && break; sleep 0.1; done
[ -S "$XDG_RUNTIME_DIR/wayland-0" ] || { echo "gnome-shell did not start, see $WL_DIR/gnome-shell.log" >&2; exit 1; }
# Wait until the shell is up, then leave the overview so the desktop is visible.
for _ in $(seq 100); do
    gdbus call --session --dest org.gnome.Shell --object-path /org/gnome/Shell --method org.gnome.Shell.Eval \
        'Main.overview.hide(); Main.messageTray._bannerBin.hide(); "ok"' 2>/dev/null | grep -q true && break
    sleep 0.2
done

env_file="$WL_DIR/env"
cat >"$env_file" <<ENV
export XDG_RUNTIME_DIR='$XDG_RUNTIME_DIR' XDG_CONFIG_HOME='$XDG_CONFIG_HOME' XDG_DATA_HOME='$XDG_DATA_HOME'
export XDG_CACHE_HOME='$XDG_CACHE_HOME' XDG_CURRENT_DESKTOP=GNOME XDG_SESSION_TYPE=wayland
export DBUS_SESSION_BUS_ADDRESS='$DBUS_SESSION_BUS_ADDRESS' WAYLAND_DISPLAY=wayland-0
unset DISPLAY
ENV
cat "$env_file"
