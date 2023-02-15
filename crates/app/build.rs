fn main() {
    slint_build::compile("ui/app.slint").expect("compiling the Slint UI");

    // Windows: embed the app icon and version info in somedesk.exe.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("../../assets/brand/app-icon.ico");
        res.set("ProductName", "SomeDesk");
        res.set("FileDescription", "SomeDesk remote desktop");
        if let Err(e) = res.compile() {
            println!("cargo:warning=could not embed the Windows icon: {e}");
        }
    }
}
