#![forbid(unsafe_code)]

pub mod detector;
pub mod exif;
pub mod jpeg;
pub mod xmp;

pub use detector::{detect_format, ImageFormat};
pub use jpeg::{scan_jpeg_metadata, ImageParseError};
