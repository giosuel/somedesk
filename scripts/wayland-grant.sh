#!/usr/bin/env bash
# In the headless GNOME session from wayland-env.sh: asks the portal for screen sharing and
# remote control once, answers GNOME's dialog, and leaves the restore token in
# $WL_DIR/state/portal-restore-token so tests can start sessions without a dialog.
#
# The dialog is answered by clicking relative to its window (GNOME 48 layout).
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
WL_DIR="${WL_DIR:-/tmp/somedesk-wayland}"
. "$WL_DIR/env"
STATE="$WL_DIR/state"
mkdir -p "$STATE"
rm -f "$STATE/portal-restore-token"
cargo build -q -p somedesk-platform --example screen_probe
"${CARGO_TARGET_DIR:-target}/debug/examples/screen_probe" "$WL_DIR/probe.ppm" "$STATE" >"$WL_DIR/grant.log" 2>&1 &
probe=$!

# Wait for the portal's dialog to be placed on screen and find where it is.
rect=""
for _ in $(seq 100); do
    rect=$(gdbus call --session --dest org.gnome.Shell --object-path /org/gnome/Shell --method org.gnome.Shell.Eval \
        'const w = global.get_window_actors().map(a => a.meta_window)
            .find(w => w.get_wm_class() === "xdg-desktop-portal-gnome");
         w && w.get_frame_rect().x > 0 ? [w.get_frame_rect().x, w.get_frame_rect().y].join(" ") : ""' |
        sed -E "s/^\(true, '\"(.*)\"'\)$/\1/")
    [ -n "$rect" ] && break
    sleep 0.2
done
[ -n "$rect" ] || { echo "the portal dialog did not appear" >&2; kill "$probe" 2>/dev/null; exit 1; }
read -r x y <<<"$rect"
sleep 1 # let it finish drawing

# The first click into the freshly opened dialog only focuses it, so click its text first.
scripts/gnome-input.sh click $((x + 330)) $((y + 216)); sleep 0.3
scripts/gnome-input.sh move $((x + 570)) $((y + 156)); sleep 0.3
scripts/gnome-input.sh click $((x + 579)) $((y + 156)); sleep 0.5   # "Allow Remote Interaction"
scripts/gnome-input.sh click $((x + 617)) $((y + 22))               # "Share"
if ! wait "$probe" || [ ! -s "$STATE/portal-restore-token" ]; then
    echo "could not obtain portal permission, see $WL_DIR/grant.log" >&2
    exit 1
fi
if ! grep -q "can control: true" "$WL_DIR/grant.log"; then
    echo "remote interaction was not granted, see $WL_DIR/grant.log" >&2
    exit 1
fi
echo "$STATE"
