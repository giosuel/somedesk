# Vendored i-slint-backend-winit 1.18.1

Unmodified upstream source except for one line in `frame_throttle.rs`: a monitor that reports a
refresh rate of 0 Hz (some virtual machines and remote displays, Wine) made Slint divide by zero
and panic at startup; such a rate is now treated as unknown (60 Hz). Drop this copy and the
`[patch.crates-io]` entry in the workspace `Cargo.toml` once upstream handles it.
