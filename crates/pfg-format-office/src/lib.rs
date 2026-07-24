#![forbid(unsafe_code)]

pub mod detector;
pub mod scanner;

pub use detector::{detect_office_format, OfficeFormat};
pub use scanner::{scan_office_metadata, OfficeParseError};
