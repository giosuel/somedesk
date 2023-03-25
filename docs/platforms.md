# Platforms

## Support

| Host platform | Capture | Input | Verified |
|---|---|---|---|
| Linux X11 | XGetImage, RandR monitors | XTest | end to end (tests + manual) |
| Linux Wayland | xdg-desktop-portal + PipeWire | portal RemoteDesktop | end to end in headless GNOME |
| Windows | GDI BitBlt, all monitors | SendInput | backend tests pass under Wine; app UI runs under Wine; networking needs real Windows (Wine lacks `IP_RECVECN`, which QUIC uses) |
| macOS | CoreGraphics display images | CGEvent | compile-checked only |

Windows builds use the MinGW toolchain (`x86_64-pc-windows-gnu`); ship `libstdc++-6.dll`,
`libgcc_s_seh-1.dll` and `libwinpthread-1.dll` next to `somedesk.exe`. On macOS the user must allow
*Screen Recording* (required) and *Accessibility* (for control; otherwise view-only). Neither
covers the login screen or UAC prompts yet; that needs a system service / launch daemon.

## Android

The Android app (Android 8 and newer) connects to computers; it does not share the phone's
screen. It uses the phone layout of the same UI: bottom navigation, and a full-screen session
where a tap clicks, a long press right-clicks and dragging drags. A scroll mode turns dragging
into the mouse wheel, and the keyboard button opens the soft keyboard with a row of Esc, Tab,
Ctrl, Alt, arrows, Delete, Home, End and Super. A hardware keyboard works as on the desktop.
Back ends a session, and leaves the app from the home screen.

The clipboard is shared through Android's clipboard manager. Android only lets the app read it
while it is in front, so text copied on the phone reaches the computer once SomeDesk is open again.
Sending files from the phone isn't supported yet; received files are saved to *Download/SomeDesk*
(not yet tested).

Verified on the Android 15 emulator (x86_64): sign-in, sessions over a direct connection, touch
input, typing through Gboard, scrolling, rotation and the clipboard from the computer. Not yet
tried on a physical phone.

## Linux desktops

The host picks its backend from the session: **X11** (XGetImage + XTest; RandR monitors can be
viewed one at a time), or on **Wayland** the
**xdg-desktop-portal** (`RemoteDesktop` + `ScreenCast`, frames over PipeWire).
`SOMEDESK_BACKEND=x11|portal` overrides the choice.

On Wayland the desktop itself asks the person at the host for permission the first time someone
connects (after they accepted in SomeDesk). They choose *Share* and switch on *Allow Remote
Interaction*; SomeDesk tells them so. The portal's restore token is stored next to the device
credentials, so later sessions start without asking again. If remote interaction is not allowed,
or the desktop has no remote-input portal (wlroots compositors such as sway), the screen is shared
view-only and the viewer is told.

Known gaps: the view-only path on wlroots is untested (xdg-desktop-portal-wlr cannot capture a
GPU-less headless sway); clipboard sharing on GNOME Wayland goes through XWayland, since GNOME
does not offer the Wayland data-control protocol.
