//! Android: the clipboard, through `ClipboardManager` over JNI. Screen sharing is not available.
//!
//! Needs the JVM and activity context registered in `ndk_context`, which the activity glue
//! (android-activity, through Slint) does before the app starts.

use crate::Clipboard;
use anyhow::Context as _;
use jni::objects::{JObject, JString};
use jni::{JNIEnv, JavaVM};

pub struct AndroidClipboard {
    vm: JavaVM,
}

impl AndroidClipboard {
    pub fn open() -> anyhow::Result<Self> {
        let ctx = ndk_context::android_context();
        // SAFETY: ndk_context holds the process's JavaVM pointer for the lifetime of the app.
        let vm = unsafe { JavaVM::from_raw(ctx.vm().cast()) }.context("no Java VM")?;
        Ok(Self { vm })
    }

    /// Runs `f` with the clipboard manager, on this thread attached to the VM.
    fn with_manager<T>(&self, f: impl FnOnce(&mut JNIEnv, &JObject) -> jni::errors::Result<T>) -> anyhow::Result<T> {
        let mut env = self.vm.attach_current_thread().context("attaching to the Java VM")?;
        // SAFETY: a global reference to the activity, valid while the app runs.
        let context = unsafe { JObject::from_raw(ndk_context::android_context().context().cast()) };
        let result = env.with_local_frame(16, |env| {
            let service = env.new_string("clipboard")?;
            let manager = env
                .call_method(
                    &context,
                    "getSystemService",
                    "(Ljava/lang/String;)Ljava/lang/Object;",
                    &[(&service).into()],
                )?
                .l()?;
            f(env, &manager)
        });
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_describe();
            let _ = env.exception_clear();
        }
        result.context("clipboard")
    }
}

impl Clipboard for AndroidClipboard {
    fn get_text(&mut self) -> anyhow::Result<Option<String>> {
        self.with_manager(|env, manager| {
            let clip = env.call_method(manager, "getPrimaryClip", "()Landroid/content/ClipData;", &[])?.l()?;
            // Null while another app has focus (Android 10 and later) or when the clipboard is empty.
            if clip.is_null() || env.call_method(&clip, "getItemCount", "()I", &[])?.i()? == 0 {
                return Ok(None);
            }
            let item = env.call_method(&clip, "getItemAt", "(I)Landroid/content/ClipData$Item;", &[0.into()])?.l()?;
            let text = env.call_method(&item, "getText", "()Ljava/lang/CharSequence;", &[])?.l()?;
            if text.is_null() {
                return Ok(None);
            }
            let text: JString = env.call_method(&text, "toString", "()Ljava/lang/String;", &[])?.l()?.into();
            let text: String = env.get_string(&text)?.into();
            Ok(Some(text))
        })
    }

    fn set_text(&mut self, text: &str) -> anyhow::Result<()> {
        self.with_manager(|env, manager| {
            let label = env.new_string("SomeDesk")?;
            let text = env.new_string(text)?;
            let clip = env
                .call_static_method(
                    "android/content/ClipData",
                    "newPlainText",
                    "(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Landroid/content/ClipData;",
                    &[(&label).into(), (&text).into()],
                )?
                .l()?;
            env.call_method(manager, "setPrimaryClip", "(Landroid/content/ClipData;)V", &[(&clip).into()])?;
            Ok(())
        })
    }
}
