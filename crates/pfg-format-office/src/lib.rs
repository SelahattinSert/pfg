#![forbid(unsafe_code)]

pub mod detector;
pub mod sanitizer;
pub mod scanner;

pub use detector::{detect_office_format, OfficeFormat};
pub use sanitizer::sanitize_office;
pub use scanner::{scan_office_metadata, OfficeParseError};
