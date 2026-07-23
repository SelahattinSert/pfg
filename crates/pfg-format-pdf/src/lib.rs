#![forbid(unsafe_code)]

pub mod detector;
pub mod scanner;

pub use detector::detect_pdf_format;
pub use scanner::{scan_pdf_metadata, PdfParseError};
