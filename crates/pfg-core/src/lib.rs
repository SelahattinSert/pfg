#![forbid(unsafe_code)]

pub mod cleaner;
pub mod masking;
pub mod scanner;
pub mod verifier;

pub use cleaner::{clean_file, CleanOptions};
pub use scanner::{scan_file, CoreError, ScanOptions};
pub use verifier::{verify_files, VerificationReport};

