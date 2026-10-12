//! SomeDesk client app: the Slint UI and the controller that drives it. The desktop binary
//! (`src/main.rs`) and the Android library (`crates/android`) both start it with [`run`].

mod controller;
mod keymap;

#[cfg(target_os = "android")]
pub mod android;

use std::path::PathBuf;

slint::include_modules!();

/// How the app starts.
pub struct Options {
    /// Where credentials and settings live.
    pub data_dir: PathBuf,
    /// Pre-fill the server address on the sign-in screen.
    pub server: Option<String>,
    /// Use the phone layout: one column, bottom navigation, touch controls in sessions.
    pub mobile: bool,
}

/// The app ID of the desktop file, AppStream metainfo and Flatpak (packaging/linux).
pub const APP_ID: &str = "ch.giosuel.SomeDesk";

/// Runs the app until its window closes.
pub fn run(options: Options) -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    // The Wayland app ID (X11 WM_CLASS): matches the desktop file, so desktops show the right
    // name and icon for the window.
    #[cfg(not(target_os = "android"))]
    {
        slint::BackendSelector::new().select()?;
        slint::set_xdg_app_id(APP_ID)?;
    }
    let ui = AppWindow::new()?;
    ui.set_mobile(options.mobile);
    let controller = controller::Controller::new(&ui, runtime.handle().clone(), options.data_dir, options.server);
    controller.start();
    ui.run()?;
    controller.shutdown();
    runtime.shutdown_timeout(std::time::Duration::from_secs(2));
    Ok(())
}
