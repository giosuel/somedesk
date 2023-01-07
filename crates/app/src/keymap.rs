//! Maps Slint key events (which carry text) to X11 keysyms for the remote side.

/// Returns the X11 keysym for the text of a Slint key event.
pub fn keysym_for(text: &str) -> Option<u32> {
    let mut chars = text.chars();
    let c = chars.next()?;
    if chars.next().is_some() {
        return None;
    }
    let code = c as u32;
    Some(match c {
        '\u{0008}' => 0xff08,                                // BackSpace
        '\u{0009}' => 0xff09,                                // Tab
        '\u{000a}' | '\u{000d}' => 0xff0d,                   // Return
        '\u{001b}' => 0xff1b,                                // Escape
        '\u{0019}' => 0xff09,                                // Backtab (Shift is sent separately)
        '\u{007f}' => 0xffff,                                // Delete
        '\u{0010}' => 0xffe1,                                // Shift_L
        '\u{0011}' => 0xffe3,                                // Control_L
        '\u{0012}' => 0xffe9,                                // Alt_L
        '\u{0013}' => 0xfe03,                                // ISO_Level3_Shift (AltGr)
        '\u{0014}' => 0xffe5,                                // Caps_Lock
        '\u{0015}' => 0xffe2,                                // Shift_R
        '\u{0016}' => 0xffe4,                                // Control_R
        '\u{0017}' => 0xffeb,                                // Super_L
        '\u{0018}' => 0xffec,                                // Super_R
        '\u{F700}' => 0xff52,                                // Up
        '\u{F701}' => 0xff54,                                // Down
        '\u{F702}' => 0xff51,                                // Left
        '\u{F703}' => 0xff53,                                // Right
        '\u{F704}'..='\u{F71B}' => 0xffbe + (code - 0xF704), // F1..F24
        '\u{F727}' => 0xff63,                                // Insert
        '\u{F729}' => 0xff50,                                // Home
        '\u{F72B}' => 0xff57,                                // End
        '\u{F72C}' => 0xff55,                                // Prior
        '\u{F72D}' => 0xff56,                                // Next
        '\u{F72F}' => 0xff14,                                // Scroll_Lock
        '\u{F730}' => 0xff13,                                // Pause
        '\u{F731}' => 0xff15,                                // Sys_Req
        '\u{F735}' => 0xff67,                                // Menu
        _ if code < 0x20 || (0x7f..0xa0).contains(&code) => return None,
        _ if (0xF700..=0xF8FF).contains(&code) => return None, // other private-use keys
        _ if code < 0x100 => code,                             // Latin-1 keysyms equal the code point
        _ => 0x0100_0000 + code,                               // Unicode keysyms
    })
}

#[cfg(test)]
mod tests {
    use super::keysym_for;
    use slint::platform::Key;

    fn k(key: Key) -> Option<u32> {
        keysym_for(&slint::SharedString::from(key))
    }

    #[test]
    fn printable_characters() {
        assert_eq!(keysym_for("a"), Some(0x61));
        assert_eq!(keysym_for("A"), Some(0x41));
        assert_eq!(keysym_for(" "), Some(0x20));
        assert_eq!(keysym_for("é"), Some(0xe9));
        assert_eq!(keysym_for("€"), Some(0x0100_20ac));
        assert_eq!(keysym_for("ж"), Some(0x0100_0436));
    }

    #[test]
    fn special_keys_from_slint() {
        assert_eq!(k(Key::Return), Some(0xff0d));
        assert_eq!(k(Key::Backspace), Some(0xff08));
        assert_eq!(k(Key::Escape), Some(0xff1b));
        assert_eq!(k(Key::Shift), Some(0xffe1));
        assert_eq!(k(Key::Control), Some(0xffe3));
        assert_eq!(k(Key::Alt), Some(0xffe9));
        assert_eq!(k(Key::Meta), Some(0xffeb));
        assert_eq!(k(Key::LeftArrow), Some(0xff51));
        assert_eq!(k(Key::F1), Some(0xffbe));
        assert_eq!(k(Key::F12), Some(0xffc9));
        assert_eq!(k(Key::PageDown), Some(0xff56));
        assert_eq!(k(Key::Delete), Some(0xffff));
    }

    #[test]
    fn ignored_inputs() {
        assert_eq!(keysym_for(""), None);
        assert_eq!(keysym_for("ab"), None);
        assert_eq!(keysym_for("\u{1}"), None);
        assert_eq!(keysym_for("\u{F8FF}"), None);
    }
}
