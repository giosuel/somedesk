//! Opens the screen with the detected backend, saves one frame as a PPM image and moves the
//! pointer. Handy for checking a desktop environment by hand:
//!
//!     cargo run -p somedesk-platform --example screen_probe -- /tmp/frame.ppm [state-dir]

use std::io::Write;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let mut args = std::env::args().skip(1);
    let out = args.next().unwrap_or_else(|| "frame.ppm".into());
    let state = args.next().map(std::path::PathBuf::from);
    let mut screen = somedesk_platform::open_screen(state.as_deref())?;
    println!("backend: {}", screen.backend);
    println!("can control: {}", screen.can_control);
    let frame = screen.capturer.capture()?;
    println!("frame: {}x{} stride {}", frame.width, frame.height, frame.stride);
    let mut f = std::io::BufWriter::new(std::fs::File::create(&out)?);
    write!(f, "P6\n{} {}\n255\n", frame.width, frame.height)?;
    for row in frame.data.chunks(frame.stride).take(frame.height as usize) {
        for px in row[..frame.width as usize * 4].as_chunks::<4>().0 {
            f.write_all(&[px[2], px[1], px[0]])?;
        }
    }
    let size = screen.injector.screen_size()?;
    println!("input size: {size:?}");
    screen.injector.pointer_move(size.0 / 2, size.1 / 2)?;
    std::thread::sleep(std::time::Duration::from_millis(500));
    drop(screen);
    // A second session in the same process must work too (and, with a stored token, without
    // asking again).
    let mut screen = somedesk_platform::open_screen(state.as_deref())?;
    let frame = screen.capturer.capture()?;
    println!("second session frame: {}x{}", frame.width, frame.height);
    Ok(())
}
