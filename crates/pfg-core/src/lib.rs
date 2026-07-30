#![forbid(unsafe_code)]

pub mod batch;
pub mod cleaner;
pub mod limits;
pub mod masking;
pub mod scanner;
pub mod verifier;

pub use batch::{
    clean_directory, scan_directory, BatchCleanOptions, BatchCleanReport, BatchScanOptions,
    BatchScanReport,
};
pub use cleaner::{clean_file, CleanOptions};
pub use limits::ResourceLimits;
pub use masking::mask_sensitive_value;
pub use pfg_policy::CleanProfile;
pub use scanner::{scan_file, CoreError, ScanOptions};
pub use verifier::{verify_files, verify_files_with_profile, VerificationReport};
