#![forbid(unsafe_code)]

pub mod detector;
pub mod exif;
pub mod jpeg;
pub mod jpeg_clean;
pub mod png;
pub mod png_clean;
pub mod webp;
pub mod webp_clean;
pub mod xmp;

pub use detector::{detect_format, ImageFormat};
pub use jpeg::{scan_jpeg_metadata, ImageParseError};
pub use jpeg_clean::sanitize_jpeg;
pub use pfg_policy::CleanProfile;
pub use png::scan_png_metadata;
pub use png_clean::sanitize_png;
pub use webp::scan_webp_metadata;
pub use webp_clean::sanitize_webp;

pub fn sanitize_image(
    buffer: &[u8],
    format: ImageFormat,
    profile: CleanProfile,
) -> Result<Vec<u8>, ImageParseError> {
    match format {
        ImageFormat::Jpeg => sanitize_jpeg(buffer, profile),
        ImageFormat::Png => sanitize_png(buffer),
        ImageFormat::WebP => sanitize_webp(buffer),
    }
}
