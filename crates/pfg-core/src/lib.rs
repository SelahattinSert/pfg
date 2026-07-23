#![forbid(unsafe_code)]

pub mod masking;
pub mod scanner;

pub use scanner::{scan_file, CoreError, ScanOptions};
