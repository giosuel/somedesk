//! SomeDesk client app: the Slint UI and the controller that drives it. The desktop binary
//! (`src/main.rs`) and the Android library (`crates/android`) both start it with [`run`].

#[cfg(not(target_os = "android"))]
pub mod agent;
#[cfg(not(target_os = "android"))]
mod background;
mod controller;
mod keymap;
#[cfg(not(target_os = "android"))]
mod tray;

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
    /// Start without showing the window (when started at login); it lives in the tray.
    pub background: bool,
}

/// The app ID of the desktop file, AppStream metainfo and Flatpak (packaging/linux).
pub const APP_ID: &str = "ch.giosuel.SomeDesk";

/// Runs the app until it is quit: on the desktop that is from the tray (or by closing the window,
/// when it isn't set to keep running in the background); on the phone, by leaving it.
pub fn run(options: Options) -> anyhow::Result<()> {
    // One instance per profile: a second start shows the running one's window.
    #[cfg(not(target_os = "android"))]
    let instance = match background::claim(&options.data_dir) {
        background::Instance::Other => {
            tracing::info!("SomeDesk is running already; showing its window");
            return Ok(());
        }
        background::Instance::First(listener) => listener,
    };
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

    #[cfg(target_os = "android")]
    {
        let _ = options.background;
        ui.run()?;
    }
    #[cfg(not(target_os = "android"))]
    {
        let show = {
            let weak = ui.as_weak();
            std::sync::Arc::new(move || {
                let _ = weak.upgrade_in_event_loop(|ui| {
                    let _ = ui.show();
                    ui.window().set_minimized(false);
                });
            })
        };
        instance.on_show({
            let show = show.clone();
            move || show()
        });
        let _tray = tray::start(
            {
                let show = show.clone();
                move || show()
            },
            || {
                let _ = slint::quit_event_loop();
            },
        );
        let c = controller.clone();
        ui.window().on_close_requested(move || {
            if !c.keep_running_in_background() {
                let _ = slint::quit_event_loop();
            }
            slint::CloseRequestResponse::HideWindow
        });
        if !options.background || !controller.keep_running_in_background() {
            ui.show()?;
        }
        slint::run_event_loop_until_quit()?;
    }
    controller.shutdown();
    runtime.shutdown_timeout(std::time::Duration::from_secs(2));
    Ok(())
}
