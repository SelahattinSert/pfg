use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ImageFormat {
    Jpeg,
    Png,
    WebP,
}

pub fn detect_format(buffer: &[u8]) -> Option<ImageFormat> {
    if buffer.len() >= 2 && buffer[0] == 0xFF && buffer[1] == 0xD8 {
        return Some(ImageFormat::Jpeg);
    }
    if buffer.len() >= 8 && buffer.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Some(ImageFormat::Png);
    }
    if buffer.len() >= 12 && buffer.starts_with(b"RIFF") && &buffer[8..12] == b"WEBP" {
        return Some(ImageFormat::WebP);
    }
    None
}
