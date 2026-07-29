#![forbid(unsafe_code)]

pub mod cleaner;
pub mod masking;
pub mod scanner;
pub mod verifier;
pub mod batch;

pub use masking::mask_sensitive_value;
pub use scanner::{scan_file, CoreError, ScanOptions};
pub use cleaner::{clean_file, CleanOptions};
pub use verifier::{verify_files, verify_files_with_profile, VerificationReport};
pub use batch::{BatchScanOptions, BatchCleanOptions, BatchScanReport, BatchCleanReport, scan_directory, clean_directory};
pub use pfg_policy::CleanProfile;
