#!/usr/bin/env bash
# Drives the headless GNOME session from scripts/wayland-env.sh like xdotool does for X11.
# Needs gnome-shell --unsafe-mode (Shell.Eval) and the environment from wayland-env.sh.
#
#   gnome-input.sh click X Y        # move the pointer and left-click
#   gnome-input.sh move X Y
#   gnome-input.sh key KEYVAL...    # press and release keys (X keysym numbers or names)
#   gnome-input.sh type TEXT
#   gnome-input.sh screenshot FILE
set -euo pipefail

eval_js() {
    local out
    out=$(gdbus call --session --dest org.gnome.Shell --object-path /org/gnome/Shell \
        --method org.gnome.Shell.Eval "$1")
    case "$out" in "(true,"*) ;; *) echo "Shell.Eval failed: $out" >&2; exit 1 ;; esac
}

PRELUDE='const {Clutter, GLib} = imports.gi;
const seat = global.stage.context.get_backend().get_default_seat();
if (!global._sdPtr) global._sdPtr = seat.create_virtual_device(Clutter.InputDeviceType.POINTER_DEVICE);
if (!global._sdKbd) global._sdKbd = seat.create_virtual_device(Clutter.InputDeviceType.KEYBOARD_DEVICE);
const ptr = global._sdPtr, kbd = global._sdKbd;
const now = () => GLib.get_monotonic_time();'

cmd="${1:?command}"; shift
case "$cmd" in
move)
    eval_js "$PRELUDE ptr.notify_absolute_motion(now(), $1, $2); 'ok'" ;;
click)
    # Hover first and pause between steps: clients ignore a press that arrives together with the
    # pointer entering their window.
    eval_js "$PRELUDE ptr.notify_absolute_motion(now(), $(($1 - 3)), $(($2 - 3))); 'ok'"
    sleep 0.15
    eval_js "$PRELUDE ptr.notify_absolute_motion(now(), $1, $2); 'ok'"
    sleep 0.15
    eval_js "$PRELUDE ptr.notify_button(now(), Clutter.BUTTON_PRIMARY, Clutter.ButtonState.PRESSED); 'ok'"
    sleep 0.05
    eval_js "$PRELUDE ptr.notify_button(now(), Clutter.BUTTON_PRIMARY, Clutter.ButtonState.RELEASED); 'ok'" ;;
key)
    js=""
    for k in "$@"; do
        case "$k" in [0-9]*|0x*) v="$k" ;; *) v="Clutter.KEY_$k" ;; esac
        js+="kbd.notify_keyval(now(), $v, Clutter.KeyState.PRESSED); kbd.notify_keyval(now(), $v, Clutter.KeyState.RELEASED);"
    done
    eval_js "$PRELUDE $js 'ok'" ;;
type)
    text="$1"; js=""
    for ((i = 0; i < ${#text}; i++)); do
        c="${text:i:1}"
        printf -v code '%d' "'$c"
        js+="kbd.notify_keyval(now(), Clutter.unicode_to_keysym($code), Clutter.KeyState.PRESSED);"
        js+="kbd.notify_keyval(now(), Clutter.unicode_to_keysym($code), Clutter.KeyState.RELEASED);"
    done
    eval_js "$PRELUDE $js 'ok'" ;;
screenshot)
    gdbus call --session --dest org.gnome.Shell.Screenshot --object-path /org/gnome/Shell/Screenshot \
        --method org.gnome.Shell.Screenshot.Screenshot false false "$(realpath -m "$1")" >/dev/null ;;
*) echo "unknown command $cmd" >&2; exit 2 ;;
esac
