//! Android entry point, called from `android_main` in `crates/android`.

use std::ffi::CString;
use std::io::Write;
use std::path::PathBuf;

pub use slint::android::AndroidApp;

/// Runs the app inside the activity `app` until the activity is finished (Back on the home
/// screen), then ends the process: Slint can only be set up once per process, and Android would
/// otherwise reuse the process for the next launch.
pub fn main(app: AndroidApp) {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("info"))
        .with_writer(Logcat::default)
        .with_ansi(false)
        .without_time()
        .init();
    std::panic::set_hook(Box::new(|info| tracing::error!("{info}")));

    let data_dir = app.internal_data_path().unwrap_or_else(|| PathBuf::from("/data/local/tmp")).join("default");
    // Received files go to the shared Download folder, which apps may write to without any
    // permission since Android 11; on older versions, to the app's own folder on the storage.
    let public = PathBuf::from("/storage/emulated/0/Download/SomeDesk");
    let downloads = if std::fs::create_dir_all(&public).is_ok() {
        public
    } else {
        app.external_data_path().unwrap_or_else(|| data_dir.clone()).join("Download")
    };
    crate::controller::set_download_dir(downloads);

    if let Err(e) = slint::android::init(app) {
        tracing::error!("cannot start the UI: {e}");
        std::process::exit(1);
    }
    if let Err(e) = crate::run(crate::Options { data_dir, server: None, mobile: true }) {
        tracing::error!("{e:#}");
    }
    std::process::exit(0);
}

/// Writes formatted log lines to logcat under the tag "somedesk".
#[derive(Default)]
struct Logcat(Vec<u8>);

impl Write for Logcat {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for Logcat {
    fn drop(&mut self) {
        let line = String::from_utf8_lossy(&self.0);
        let line = line.trim_end();
        let priority = if line.starts_with("ERROR") {
            android_log_sys::LogPriority::ERROR
        } else if line.starts_with(" WARN") {
            android_log_sys::LogPriority::WARN
        } else {
            android_log_sys::LogPriority::INFO
        };
        let (Ok(tag), Ok(text)) = (CString::new("somedesk"), CString::new(line.replace('\0', ""))) else {
            return;
        };
        // SAFETY: both arguments are valid NUL-terminated strings.
        unsafe { android_log_sys::__android_log_write(priority as _, tag.as_ptr(), text.as_ptr()) };
    }
}
