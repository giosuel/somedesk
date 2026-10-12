//! The tray icon, so the app can keep running with its window closed: "Show SomeDesk" and
//! "Quit" (Slint's `SystemTrayIcon`: a StatusNotifierItem on Linux, the notification area on
//! Windows, the menu bar on macOS).
//!
//! Where the desktop has no tray (GNOME without the AppIndicator extension), closing the window
//! still leaves the app running, and starting it again shows the window (see
//! [`crate::background`]).

use crate::AppTray;

/// Shows the tray icon; it stays while the returned handle lives.
pub fn start(show: impl Fn() + 'static, quit: impl Fn() + 'static) -> Option<AppTray> {
    match AppTray::new() {
        Ok(tray) => {
            tray.on_show(show);
            tray.on_quit(quit);
            Some(tray)
        }
        Err(e) => {
            tracing::info!("no tray icon: {e}");
            None
        }
    }
}
