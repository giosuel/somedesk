//! H.264 video encoding and decoding (OpenH264, software).
//!
//! The decoder reads video from the peer, so what it accepts is limited: access units of at most
//! [`MAX_ACCESS_UNIT`] bytes, and pictures of at most [`MAX_DIMENSION`] pixels a side and
//! [`MAX_PIXELS`] in all, before any RGB buffer is made for them. OpenH264 itself still parses
//! the bitstream in this process.

use anyhow::{ensure, Context};
use openh264::decoder::Decoder;
use openh264::encoder::{BitRate, Encoder, EncoderConfig, FrameRate, FrameType, RateControlMode, UsageType};
use openh264::formats::{BgraSliceU8, YUVBuffer, YUVSource};
use openh264::OpenH264API;

/// The largest access unit the decoder takes.
pub const MAX_ACCESS_UNIT: usize = 16 * 1024 * 1024;
/// The largest picture side the decoder takes (three 4K screens side by side fit).
pub const MAX_DIMENSION: usize = 16384;
/// The most pixels a decoded picture may have (about 120 MB as RGB).
pub const MAX_PIXELS: usize = 40_000_000;

/// A decoded frame, tightly packed RGB8.
#[derive(Clone)]
pub struct RgbFrame {
    pub width: u32,
    pub height: u32,
    pub data: Vec<u8>,
}

pub struct EncodedFrame {
    pub data: Vec<u8>,
    pub keyframe: bool,
    pub width: u32,
    pub height: u32,
}

pub struct EncoderSettings {
    pub bitrate_bps: u32,
    pub max_fps: f32,
}

impl Default for EncoderSettings {
    fn default() -> Self {
        Self { bitrate_bps: 6_000_000, max_fps: 30.0 }
    }
}

/// Encodes BGRA screen captures. Odd dimensions are cropped to even (an H.264 requirement).
pub struct H264Encoder {
    enc: Encoder,
    width: u32,
    height: u32,
    yuv: YUVBuffer,
    scratch: Vec<u8>,
}

impl H264Encoder {
    pub fn new(width: u32, height: u32, settings: &EncoderSettings) -> anyhow::Result<Self> {
        let (w, h) = (width & !1, height & !1);
        ensure!(w >= 16 && h >= 16, "frame too small to encode: {width}x{height}");
        let config = EncoderConfig::new()
            .usage_type(UsageType::ScreenContentRealTime)
            .rate_control_mode(RateControlMode::Bitrate)
            .bitrate(BitRate::from_bps(settings.bitrate_bps))
            .max_frame_rate(FrameRate::from_hz(settings.max_fps))
            .adaptive_quantization(false)
            .background_detection(false)
            .skip_frames(true);
        let enc = Encoder::with_api_config(OpenH264API::from_source(), config).context("creating H.264 encoder")?;
        Ok(Self { enc, width: w, height: h, yuv: YUVBuffer::new(w as usize, h as usize), scratch: Vec::new() })
    }

    /// Dimensions of the encoded video (even).
    pub fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    /// Encodes one frame. `bgra` has `stride` bytes per row and must cover the source
    /// dimensions passed to [`H264Encoder::new`]. Returns `None` when the rate controller
    /// decided to skip this frame.
    pub fn encode_bgra(
        &mut self,
        bgra: &[u8],
        stride: usize,
        force_keyframe: bool,
    ) -> anyhow::Result<Option<EncodedFrame>> {
        let (w, h) = (self.width as usize, self.height as usize);
        ensure!(stride >= w * 4 && bgra.len() >= stride * (h - 1) + w * 4, "frame buffer too small");
        let packed: &[u8] = if stride == w * 4 {
            &bgra[..w * h * 4]
        } else {
            self.scratch.clear();
            for row in bgra.chunks(stride).take(h) {
                self.scratch.extend_from_slice(&row[..w * 4]);
            }
            &self.scratch
        };
        self.yuv.read_bgra8(BgraSliceU8::new(packed, (w, h)));
        if force_keyframe {
            self.enc.force_intra_frame();
        }
        let bs = self.enc.encode(&self.yuv).context("H.264 encode")?;
        let keyframe = matches!(bs.frame_type(), FrameType::IDR | FrameType::I);
        if matches!(bs.frame_type(), FrameType::Skip | FrameType::Invalid) {
            return Ok(None);
        }
        Ok(Some(EncodedFrame { data: bs.to_vec(), keyframe, width: self.width, height: self.height }))
    }
}

pub struct H264Decoder {
    dec: Decoder,
}

impl H264Decoder {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self { dec: Decoder::new().context("creating H.264 decoder")? })
    }

    /// Decodes one access unit. Returns `None` if the decoder needs more data.
    pub fn decode(&mut self, data: &[u8]) -> anyhow::Result<Option<RgbFrame>> {
        ensure!(data.len() <= MAX_ACCESS_UNIT, "access unit of {} bytes is too large", data.len());
        let Some(yuv) = self.dec.decode(data).context("H.264 decode")? else {
            return Ok(None);
        };
        let (w, h) = yuv.dimensions();
        check_dimensions(w, h)?;
        let mut rgb = vec![0u8; w * h * 3];
        yuv.write_rgb8(&mut rgb);
        Ok(Some(RgbFrame { width: w as u32, height: h as u32, data: rgb }))
    }
}

/// Whether a decoded picture of `w`×`h` is one we make an RGB frame of.
fn check_dimensions(w: usize, h: usize) -> anyhow::Result<()> {
    ensure!(
        (1..=MAX_DIMENSION).contains(&w) && (1..=MAX_DIMENSION).contains(&h) && w * h <= MAX_PIXELS,
        "decoded picture of {w}x{h} is out of bounds"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic "desktop": colored quadrants plus a moving white box.
    fn test_frame(w: usize, h: usize, t: usize) -> Vec<u8> {
        let mut f = vec![0u8; w * h * 4];
        for y in 0..h {
            for x in 0..w {
                let (b, g, r) = match (x < w / 2, y < h / 2) {
                    (true, true) => (40, 40, 200),
                    (false, true) => (40, 180, 40),
                    (true, false) => (200, 60, 30),
                    (false, false) => (230, 230, 230),
                };
                let in_box = (x + 400 - t * 8) % 400 < 40 && (y / 40) % 3 == 1;
                let px = &mut f[(y * w + x) * 4..][..4];
                px.copy_from_slice(&if in_box { [255, 255, 255, 255] } else { [b, g, r, 255] });
            }
        }
        f
    }

    fn psnr(bgra: &[u8], rgb: &RgbFrame) -> f64 {
        let n = (rgb.width * rgb.height) as usize;
        let mut se = 0f64;
        for i in 0..n {
            for c in 0..3 {
                let orig = bgra[i * 4 + 2 - c] as f64;
                let got = rgb.data[i * 3 + c] as f64;
                se += (orig - got).powi(2);
            }
        }
        let mse = se / (n as f64 * 3.0);
        10.0 * (255f64.powi(2) / mse.max(1e-9)).log10()
    }

    #[test]
    fn roundtrip_preserves_image() {
        let (w, h) = (320, 240);
        let mut enc = H264Encoder::new(w, h, &EncoderSettings::default()).unwrap();
        let mut dec = H264Decoder::new().unwrap();
        for t in 0..10 {
            let src = test_frame(w as usize, h as usize, t);
            let e = enc.encode_bgra(&src, w as usize * 4, false).unwrap().unwrap();
            if t == 0 {
                assert!(e.keyframe, "first frame must be a keyframe");
            }
            let out = dec.decode(&e.data).unwrap().expect("decoder produced a frame");
            assert_eq!((out.width, out.height), (w, h));
            let q = psnr(&src, &out);
            assert!(q > 30.0, "frame {t}: PSNR {q:.1} dB too low");
        }
    }

    #[test]
    fn forced_keyframe() {
        let mut enc = H264Encoder::new(64, 64, &EncoderSettings::default()).unwrap();
        let f = test_frame(64, 64, 0);
        enc.encode_bgra(&f, 256, false).unwrap();
        assert!(!enc.encode_bgra(&f, 256, false).unwrap().is_some_and(|e| e.keyframe));
        assert!(enc.encode_bgra(&f, 256, true).unwrap().unwrap().keyframe);
    }

    #[test]
    fn decoder_can_join_at_a_keyframe() {
        // A viewer that missed earlier frames recovers from a forced keyframe.
        let mut enc = H264Encoder::new(128, 96, &EncoderSettings::default()).unwrap();
        for t in 0..3 {
            enc.encode_bgra(&test_frame(128, 96, t), 512, false).unwrap();
        }
        let key = enc.encode_bgra(&test_frame(128, 96, 3), 512, true).unwrap().unwrap();
        let mut dec = H264Decoder::new().unwrap();
        let out = dec.decode(&key.data).unwrap().unwrap();
        assert_eq!((out.width, out.height), (128, 96));
    }

    #[test]
    fn odd_sizes_and_padded_strides_are_cropped() {
        let (w, h, stride) = (101usize, 75usize, 128 * 4);
        let mut buf = vec![128u8; stride * h];
        for y in 0..h {
            for x in 0..w {
                buf[y * stride + x * 4..][..4].copy_from_slice(&[10, 20, 250, 255]);
            }
        }
        let mut enc = H264Encoder::new(w as u32, h as u32, &EncoderSettings::default()).unwrap();
        assert_eq!(enc.dimensions(), (100, 74));
        let e = enc.encode_bgra(&buf, stride, false).unwrap().unwrap();
        let out = H264Decoder::new().unwrap().decode(&e.data).unwrap().unwrap();
        assert_eq!((out.width, out.height), (100, 74));
        let mid = &out.data[(37 * 100 + 50) * 3..][..3];
        assert!(mid[0] > 200 && mid[2] < 60, "expected red-ish pixel, got {mid:?}");
    }

    #[test]
    fn picture_size_limits() {
        assert!(check_dimensions(3840, 2160).is_ok());
        assert!(check_dimensions(11520, 2160).is_ok(), "three 4K screens");
        assert!(check_dimensions(MAX_DIMENSION + 1, 16).is_err());
        assert!(check_dimensions(16, MAX_DIMENSION + 1).is_err());
        assert!(check_dimensions(MAX_DIMENSION, MAX_DIMENSION).is_err(), "too many pixels");
        assert!(check_dimensions(0, 16).is_err());
        assert!(H264Decoder::new().unwrap().decode(&vec![0; MAX_ACCESS_UNIT + 1]).is_err());
    }

    #[test]
    fn malformed_bitstreams_are_errors_not_crashes() {
        let mut enc = H264Encoder::new(128, 96, &EncoderSettings::default()).unwrap();
        let key = enc.encode_bgra(&test_frame(128, 96, 0), 512, true).unwrap().unwrap().data;
        let next = enc.encode_bgra(&test_frame(128, 96, 1), 512, false).unwrap().unwrap().data;
        // A small deterministic generator, so failures can be reproduced.
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut rand = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut inputs: Vec<Vec<u8>> = vec![
            vec![],
            vec![0, 0, 0, 1],
            vec![0, 0, 1, 0x67, 0xff, 0xff, 0xff, 0xff],
            (0..4096).map(|_| rand() as u8).collect(),
            key[..key.len() / 2].to_vec(),
            next.clone(),
        ];
        for _ in 0..200 {
            let mut damaged = if rand() % 2 == 0 { key.clone() } else { next.clone() };
            for _ in 0..1 + rand() % 8 {
                let i = rand() as usize % damaged.len();
                damaged[i] = rand() as u8;
            }
            if rand() % 4 == 0 {
                damaged.truncate(rand() as usize % damaged.len());
            }
            inputs.push(damaged);
        }
        let mut dec = H264Decoder::new().unwrap();
        for input in &inputs {
            if let Ok(Some(frame)) = dec.decode(input) {
                assert_eq!(frame.data.len(), frame.width as usize * frame.height as usize * 3);
            }
        }
        // And it still decodes good video afterwards, from a keyframe.
        let mut fresh = H264Encoder::new(128, 96, &EncoderSettings::default()).unwrap();
        let good = fresh.encode_bgra(&test_frame(128, 96, 2), 512, true).unwrap().unwrap();
        let frame = (0..3).find_map(|_| dec.decode(&good.data).ok().flatten()).expect("decodes again");
        assert_eq!((frame.width, frame.height), (128, 96));
    }

    #[test]
    fn rejects_short_buffer() {
        let mut enc = H264Encoder::new(64, 64, &EncoderSettings::default()).unwrap();
        assert!(enc.encode_bgra(&[0u8; 100], 256, false).is_err());
    }
}
