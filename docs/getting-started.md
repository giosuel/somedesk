# Getting started

You need a SomeDesk server that both computers can reach, and the app on each computer.
If nobody has set up a server for you yet, see [Self-hosting](self-hosting.md). It takes one
command with Docker Compose.

## Install the app

Download the package for your system from the
[releases](https://github.com/giosuel/somedesk/releases).

=== "Linux"

    ```sh
    sudo apt install ./somedesk-app_*.deb
    ```

    SomeDesk then appears in your application menu. On X11 it works out of the box. On Wayland,
    the desktop asks for permission the first time someone connects: choose **Share** and switch
    on **Allow Remote Interaction**. See [Linux desktops](platforms.md#linux-desktops).

=== "Windows"

    Unzip `SomeDesk-<version>-windows-x64.zip` anywhere and run `somedesk.exe`.

=== "macOS"

    Unzip `SomeDesk-<version>-macos.zip` and move **SomeDesk** to *Applications*. The app isn't
    signed yet, so open it the first time with right-click › **Open**. To be controlled remotely,
    allow it under *System Settings › Privacy & Security*:

    - **Screen Recording** is required to share the screen.
    - **Accessibility** is needed for remote control. Without it, the screen is shared view-only.

## Create an account

1. Open SomeDesk and choose **Create an account**.
2. Enter your server's address, a username, a password and a name for this computer.
3. Save the **recovery key** that appears, in a password manager or on paper. It's the only way
   back into your account if you forget the password. Nobody else can reset it for you, not
   even the server's administrator.

On another computer, sign in with the same account to add it to **Devices**.

!!! tip "Check the server's identity"
    The app pins the server's certificate the first time it connects, and from then on only
    trusts that certificate.

## Connect to a computer

Every computer has a nine-digit ID, shown on the home screen. Enter the other computer's ID under
**Connect to a computer**.

The person at the other computer sees who is calling, with their identity fingerprint, and
accepts or declines. To rule out interception, you can compare the fingerprint they see with the
one on your home screen.

While connected you can:

- **Control the computer** with your mouse and keyboard.
- **Share the clipboard:** copy on one side and paste on the other.
- **Send files** in either direction. Files you receive land in `Downloads/SomeDesk`, and files
  from the computer you're viewing are only saved once you accept them.
- **Pick a monitor** when the other computer has several.

The toolbar shows whether the session is **direct** or **relayed**, along with latency and frame
rate.

## Connect without asking

- **Your own devices:** turn on **Settings › Unattended access** on the computer you want to
  reach. Your other devices can then connect without anyone accepting, which is useful for your
  home or office machine.
- **Someone else's device:** when they call, tick **Let … connect without asking next time**
  before accepting. You can revoke it any time under **Contacts**.

## Forgot your password?

On the sign-in screen, choose **Forgot?** and enter your username, your recovery key and a new
password. Your identity and contacts are kept, and you get a new recovery key. The old one stops
working.
