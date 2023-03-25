//! The SomeDesk Android app: `android_main` is called by the activity glue on its own thread.

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
fn android_main(app: somedesk_app::android::AndroidApp) {
    somedesk_app::android::main(app);
}
