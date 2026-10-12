# Getting started

You need a SomeDesk server that both computers can reach, and the app on each computer. You
don't need an account, and nothing costs money, now or later: every feature is
[free, for good](free.md).
If nobody has set up a server for you yet, see [Self-hosting](self-hosting.md). It takes one
command with Docker Compose.

## Install the app

Download the package for your system from the
[releases](https://github.com/giosuel/somedesk/releases).

=== "Linux"

    **Any distribution:** the AppImage runs without installing. It needs glibc 2.35 or newer
    (for example Ubuntu 22.04 or Debian 12 and later) and PipeWire, which current desktops include.

    ```sh
    chmod +x SomeDesk-*-x86_64.AppImage
    ./SomeDesk-*-x86_64.AppImage
    ```

    If it doesn't start because FUSE is missing (as in some containers), run it with
    `--appimage-extract-and-run`.

    **Debian and Ubuntu:** the `.deb` adds SomeDesk to your application menu.

    ```sh
    sudo apt install ./somedesk-app_*.deb
    ```

    **Arch Linux:** from the AUR, built from source ([`somedesk`](https://aur.archlinux.org/packages/somedesk))
    or prebuilt ([`somedesk-bin`](https://aur.archlinux.org/packages/somedesk-bin)).

    ```sh
    yay -S somedesk
    ```

    On X11 it works out of the box. On Wayland, the desktop asks for permission the first time
    someone connects: choose **Share** and switch on **Allow Remote Interaction**. See [Linux desktops](platforms.md#linux-desktops).

=== "Windows"

    Unzip `SomeDesk-<version>-windows-x64.zip` anywhere and run `somedesk.exe`.

=== "macOS"

    Unzip `SomeDesk-<version>-macos.zip` and move **SomeDesk** to *Applications*. The app isn't
    signed yet, so open it the first time with right-click › **Open**. To be controlled remotely,
    allow it under *System Settings › Privacy & Security*:

    - **Screen Recording** is required to share the screen.
    - **Accessibility** is needed for remote control. Without it, the screen is shared view-only.

=== "Android"

    Install `SomeDesk-<version>.apk` (Android 8 or newer): open it on the phone and allow
    installing apps from that source when asked. The phone connects to your computers; it doesn't
    share its own screen.

    In a session, **tap** to click, **long-press** for a right click and **drag** to drag. The
    scroll button turns dragging into scrolling, and the keyboard button opens the keyboard,
    with a row for Esc, Tab, Ctrl, Alt and the arrow keys. Turn the phone sideways for a bigger
    picture.

## First start

1. Open SomeDesk and enter your server's address and a name for this computer.
2. That's it. The computer gets its own nine-digit **ID** on your server, shown on the home
   screen. It keeps that ID for as long as it's installed, with or without an account.

The ID belongs to a key that SomeDesk creates on this computer and never sends anywhere: the
server only ever sees its public half. Others remember your computer by that key, so nobody can
take over its ID.

!!! tip "Check the server's identity"
    The app pins the server's certificate the first time it connects, and from then on only
    trusts that certificate.

<div class="sd-note-mascot" markdown>
<img src="../assets/mascot/wave.svg" alt="Desi waving">
<div markdown>
**Desi's welcome tour** starts after the first start. It shows where everything is, and you can
take it again from **Settings**.
</div>
</div>

## Connect to a computer

Enter the other computer's ID under **Connect**. The person there sees who is calling (the
computer's name and, if you're signed in, your account and its fingerprint) and accepts or
declines.

While connected you can:

- **Control the computer** with your mouse and keyboard.
- **Share the clipboard:** copy on one side and paste on the other.
- **Send files** in either direction. Files you receive land in `Downloads/SomeDesk`, and files
  from the computer you're viewing are only saved once you accept them.
- **Pick a monitor** when the other computer has several.

The toolbar shows whether the session is **direct** or **relayed**, along with latency and frame
rate. The host always shows who is connected, with **Stop sharing** to end the session.

There are three more ways to connect, for when nobody is at the other computer. They're all
explained in [Ways to connect](connecting.md).

## The address book

Keep the computers you connect to in the **Address book**: add one by its ID, or keep it after a
session. Each entry remembers the computer's key, and SomeDesk warns you before connecting if it
ever changes.

When you're signed in, the address book syncs to your other devices, encrypted on your device
first: the server only stores a blob it can't read.

## Leave nobody at the other computer

To reach a computer with nobody there, open **Settings › Getting in without someone here** on
*that* computer:

- **Unattended access:** choose **Set up**, pick a password for this computer, and scan the QR code
  with an authenticator app (any app that shows six-digit codes, such as Aegis, 2FAS or Google
  Authenticator). To connect, others then need the password *and* the current code.
- **My own devices:** with an account that has two-factor authentication, your other devices
  signed in to the same account connect without asking. It's off until you switch it on.

When you connect with a password, SomeDesk offers to save it: **on this device** (in your
system's keychain), **in your account** (encrypted, synced with your address book) or not at all.
The code from the authenticator app is never saved.

## Runs in the background

Closing the window leaves SomeDesk running in the tray (or the taskbar's notification area on
Windows), so the computer stays reachable. Click the icon to open the window again, or choose
**Quit** there. **Settings › Start when I log in** starts it in the background after you log in, and
**Settings › Keep running in the background** turns all of this off.

On GNOME, the tray icon needs the
[AppIndicator extension](https://extensions.gnome.org/extension/615/appindicator-support/),
which Ubuntu's desktop includes. Without a tray, SomeDesk still keeps running when you close
the window: open it from your applications again to bring the window back.

## Accounts

Accounts are optional. With one, you get:

- your address book and saved passwords on every device you sign in on,
- your own devices listed under **My devices**, and reaching each other when you allow it,
- organisations, for teams that manage many machines (see [Organisations](organisations.md)).

To create one, go to **Settings › Account › Create an account**. Save the **recovery key** that
appears, in a password manager or on paper: it's the only way back in if you forget the password.
Nobody else can reset it for you, not even the server's administrator.

<div class="sd-note-mascot" markdown>
<img src="../assets/mascot/key.svg" alt="Desi holding the recovery key">
<div markdown>
**Keep that key safe!** Then turn on **two-factor authentication** in the same place. You need
it to let your own devices in without asking, and new devices you sign in on ask for a code.
</div>
</div>

### Forgot your password?

In the sign-in dialog, choose **Forgot?** and enter your username, your recovery key and a new
password. Your identity and address book are kept, and you get a new recovery key. The old one
stops working.
