#![forbid(unsafe_code)]

pub mod detector;
pub mod sanitizer;
pub mod scanner;

pub use detector::detect_pdf_format;
pub use sanitizer::{sanitize_pdf, validate_pdf_structure, PdfStructureReport};
pub use scanner::{scan_pdf_metadata, PdfParseError};
