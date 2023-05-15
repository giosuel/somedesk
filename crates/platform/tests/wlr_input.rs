//! Remote input on a wlroots compositor: starts a headless sway, opens a window in it and checks
//! that what `WlrInjector` sends arrives there, with keys decoded through the keymap the
//! injector uploads. Skipped where sway isn't installed.
#![cfg(target_os = "linux")]

use somedesk_platform::linux::wlr::WlrInjector;
use somedesk_platform::Injector;
use std::os::fd::{AsFd, OwnedFd};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use wayland_client::globals::{registry_queue_init, GlobalListContents};
use wayland_client::protocol::{
    wl_buffer, wl_compositor, wl_keyboard, wl_pointer, wl_registry, wl_seat, wl_shm, wl_shm_pool, wl_surface,
};
use wayland_client::{delegate_noop, Connection, Dispatch, EventQueue, QueueHandle, WEnum};
use wayland_protocols::xdg::shell::client::{xdg_surface, xdg_toplevel, xdg_wm_base};
use xkbcommon::xkb;

const WIDTH: u32 = 1280;
const HEIGHT: u32 = 800;

struct Sway {
    child: Child,
    dir: std::path::PathBuf,
}

impl Drop for Sway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A headless sway with one 1280x800 output, in its own runtime directory.
fn start_sway() -> Option<Sway> {
    if Command::new("sway").arg("--version").output().is_err() {
        eprintln!("sway not installed, skipping");
        return None;
    }
    let dir = std::env::temp_dir().join(format!("somedesk-wlr-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let display_file = dir.join("display");
    std::fs::write(
        dir.join("config"),
        format!(
            "output HEADLESS-1 resolution {WIDTH}x{HEIGHT} position 0 0\n\
             default_border none\n\
             exec printenv WAYLAND_DISPLAY > {}\n",
            display_file.display()
        ),
    )
    .unwrap();
    let child = Command::new("sway")
        .arg("-c")
        .arg(dir.join("config"))
        .env("XDG_RUNTIME_DIR", &dir)
        .env("WLR_BACKENDS", "headless")
        .env("WLR_LIBINPUT_NO_DEVICES", "1")
        .env("WLR_RENDERER", "pixman")
        .env_remove("WAYLAND_DISPLAY")
        .env_remove("DISPLAY")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let sway = Sway { child, dir: dir.clone() };
    let deadline = Instant::now() + Duration::from_secs(10);
    while std::fs::read_to_string(&display_file).map_or(true, |s| s.trim().is_empty()) {
        assert!(Instant::now() < deadline, "sway did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
    let display = std::fs::read_to_string(&display_file).unwrap().trim().to_owned();
    // SAFETY: this test binary has a single test, so nothing else reads the environment now.
    unsafe {
        std::env::set_var("XDG_RUNTIME_DIR", &dir);
        std::env::set_var("WAYLAND_DISPLAY", display);
    }
    Some(sway)
}

#[derive(Debug, Clone, PartialEq)]
enum Seen {
    Pointer(f64, f64),
    Button(u32, bool),
    Scroll(f64),
    /// Keysym, pressed, whether Control was active.
    Key(u32, bool, bool),
}

/// A plain window that records the input it receives.
#[derive(Default)]
struct Window {
    configured: Option<u32>,
    seen: Vec<Seen>,
    xkb: Option<(xkb::Keymap, xkb::State)>,
}

impl Window {
    fn open(conn: &Connection) -> (Self, EventQueue<Self>, wl_surface::WlSurface) {
        let (globals, mut queue) = registry_queue_init::<Window>(conn).unwrap();
        let qh = queue.handle();
        let compositor: wl_compositor::WlCompositor = globals.bind(&qh, 4..=4, ()).unwrap();
        let shm: wl_shm::WlShm = globals.bind(&qh, 1..=1, ()).unwrap();
        let wm_base: xdg_wm_base::XdgWmBase = globals.bind(&qh, 1..=1, ()).unwrap();
        // The seat's pointer and keyboard are the injector's virtual devices (headless sway has
        // no others), so they exist by now.
        let seat: wl_seat::WlSeat = globals.bind(&qh, 5..=5, ()).unwrap();
        seat.get_pointer(&qh, ());
        seat.get_keyboard(&qh, ());

        let surface = compositor.create_surface(&qh, ());
        let xdg = wm_base.get_xdg_surface(&surface, &qh, ());
        xdg.get_toplevel(&qh, ()).set_title("somedesk wlr test".into());
        surface.commit();
        let mut window = Window::default();
        while window.configured.is_none() {
            queue.blocking_dispatch(&mut window).unwrap();
        }
        xdg.ack_configure(window.configured.unwrap());

        // A white buffer the size of the output (sway tiles the only window over all of it).
        let size = (WIDTH * HEIGHT * 4) as usize;
        let fd: OwnedFd = rustix::fs::memfd_create("buffer", rustix::fs::MemfdFlags::CLOEXEC).unwrap();
        std::fs::File::from(fd.try_clone().unwrap()).set_len(size as u64).unwrap();
        let pool = shm.create_pool(fd.as_fd(), size as i32, &qh, ());
        let buffer =
            pool.create_buffer(0, WIDTH as i32, HEIGHT as i32, (WIDTH * 4) as i32, wl_shm::Format::Xrgb8888, &qh, ());
        surface.attach(Some(&buffer), 0, 0);
        surface.commit();
        queue.roundtrip(&mut window).unwrap();
        (window, queue, surface)
    }
}

/// Dispatches the window's events until `done` holds for what it has seen.
fn wait_until(queue: &mut EventQueue<Window>, window: &mut Window, what: &str, done: impl Fn(&[Seen]) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !done(&window.seen) {
        assert!(Instant::now() < deadline, "{what}: saw only {:?}", window.seen);
        queue.roundtrip(window).unwrap();
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn input_reaches_a_window_on_sway() {
    let Some(_sway) = start_sway() else { return };
    assert!(somedesk_platform::linux::wlr::available(), "sway offers virtual input");
    let mut injector = WlrInjector::open(None, None).expect("virtual input devices");
    assert_eq!(injector.screen_size().unwrap(), (WIDTH, HEIGHT));

    let conn = Connection::connect_to_env().unwrap();
    let (mut window, mut queue, _surface) = Window::open(&conn);

    injector.pointer_move(300, 200).unwrap();
    wait_until(&mut queue, &mut window, "pointer motion", |s| s.contains(&Seen::Pointer(300.0, 200.0)));

    injector.button(1, true).unwrap();
    injector.button(1, false).unwrap();
    injector.button(3, true).unwrap();
    injector.button(3, false).unwrap();
    wait_until(&mut queue, &mut window, "buttons", |s| s.contains(&Seen::Button(0x111, false)));
    let buttons: Vec<_> = window.seen.iter().filter(|e| matches!(e, Seen::Button(..))).cloned().collect();
    assert_eq!(
        buttons,
        [Seen::Button(0x110, true), Seen::Button(0x110, false), Seen::Button(0x111, true), Seen::Button(0x111, false)]
    );

    injector.scroll(0, 2).unwrap();
    wait_until(&mut queue, &mut window, "scrolling", |s| s.iter().any(|e| matches!(e, Seen::Scroll(v) if *v > 0.0)));

    // Typing: a letter, a character that's on no usual layout, Ctrl+C, and Ctrl with a key that
    // isn't in the keymap yet (the keymap changes while Ctrl is held).
    for (keysym, down) in [(0x61, true), (0x61, false), (0x0100_263a, true), (0x0100_263a, false)] {
        injector.key(keysym, down).unwrap();
    }
    for (keysym, down) in [(0xffe3, true), (0x63, true), (0x63, false), (0xe9, true), (0xe9, false), (0xffe3, false)] {
        injector.key(keysym, down).unwrap();
    }
    wait_until(&mut queue, &mut window, "keys", |s| s.contains(&Seen::Key(0xe9, false, true)));
    let keys: Vec<_> = window.seen.iter().filter(|e| matches!(e, Seen::Key(..))).cloned().collect();
    assert!(keys.contains(&Seen::Key(0x61, true, false)), "{keys:?}");
    assert!(keys.contains(&Seen::Key(0x0100_263a, true, false)), "{keys:?}");
    assert!(keys.contains(&Seen::Key(0x63, true, true)), "Ctrl+C: {keys:?}");
    assert!(keys.contains(&Seen::Key(0xe9, true, true)), "Ctrl+é: {keys:?}");
}

impl Dispatch<wl_registry::WlRegistry, GlobalListContents> for Window {
    fn event(
        _: &mut Self,
        _: &wl_registry::WlRegistry,
        _: wl_registry::Event,
        _: &GlobalListContents,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<xdg_wm_base::XdgWmBase, ()> for Window {
    fn event(
        _: &mut Self,
        base: &xdg_wm_base::XdgWmBase,
        event: xdg_wm_base::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let xdg_wm_base::Event::Ping { serial } = event {
            base.pong(serial);
        }
    }
}

impl Dispatch<xdg_surface::XdgSurface, ()> for Window {
    fn event(
        w: &mut Self,
        _: &xdg_surface::XdgSurface,
        event: xdg_surface::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let xdg_surface::Event::Configure { serial } = event {
            w.configured = Some(serial);
        }
    }
}

impl Dispatch<wl_pointer::WlPointer, ()> for Window {
    fn event(
        w: &mut Self,
        _: &wl_pointer::WlPointer,
        event: wl_pointer::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            wl_pointer::Event::Enter { surface_x, surface_y, .. }
            | wl_pointer::Event::Motion { surface_x, surface_y, .. } => {
                w.seen.push(Seen::Pointer(surface_x, surface_y))
            }
            wl_pointer::Event::Button { button, state, .. } => {
                w.seen.push(Seen::Button(button, state == WEnum::Value(wl_pointer::ButtonState::Pressed)))
            }
            wl_pointer::Event::Axis { axis: WEnum::Value(wl_pointer::Axis::VerticalScroll), value, .. } => {
                w.seen.push(Seen::Scroll(value))
            }
            _ => {}
        }
    }
}

impl Dispatch<wl_keyboard::WlKeyboard, ()> for Window {
    fn event(
        w: &mut Self,
        _: &wl_keyboard::WlKeyboard,
        event: wl_keyboard::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            wl_keyboard::Event::Keymap { fd, size, .. } => {
                let mut text = vec![0; size as usize];
                let file = std::fs::File::from(fd);
                std::os::unix::fs::FileExt::read_exact_at(&file, &mut text, 0).unwrap();
                let text = String::from_utf8_lossy(&text).trim_end_matches('\0').to_owned();
                let context = xkb::Context::new(xkb::CONTEXT_NO_FLAGS);
                let keymap =
                    xkb::Keymap::new_from_string(&context, text, xkb::KEYMAP_FORMAT_TEXT_V1, xkb::COMPILE_NO_FLAGS)
                        .expect("the keymap compiles");
                let state = xkb::State::new(&keymap);
                w.xkb = Some((keymap, state));
            }
            wl_keyboard::Event::Modifiers { mods_depressed, mods_latched, mods_locked, group, .. } => {
                if let Some((_, state)) = &mut w.xkb {
                    state.update_mask(mods_depressed, mods_latched, mods_locked, 0, 0, group);
                }
            }
            wl_keyboard::Event::Key { key, state, .. } => {
                let (_, xkb_state) = w.xkb.as_ref().expect("a keymap before keys");
                let keysym = xkb_state.key_get_one_sym((key + 8).into()).raw();
                let ctrl = xkb_state.mod_name_is_active(xkb::MOD_NAME_CTRL, xkb::STATE_MODS_EFFECTIVE);
                w.seen.push(Seen::Key(keysym, state == WEnum::Value(wl_keyboard::KeyState::Pressed), ctrl));
            }
            _ => {}
        }
    }
}

delegate_noop!(Window: ignore wl_seat::WlSeat);
delegate_noop!(Window: wl_compositor::WlCompositor);
delegate_noop!(Window: ignore wl_surface::WlSurface);
delegate_noop!(Window: ignore wl_shm::WlShm);
delegate_noop!(Window: wl_shm_pool::WlShmPool);
delegate_noop!(Window: ignore wl_buffer::WlBuffer);
delegate_noop!(Window: ignore xdg_toplevel::XdgToplevel);
