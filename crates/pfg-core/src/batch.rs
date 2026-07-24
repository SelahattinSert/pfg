use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use pfg_model::{FindingSummary, ScanReport};
use pfg_policy::CleanProfile;
use crate::VerificationReport;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchScanOptions {
    pub recursive: bool,
    pub jobs: Option<usize>,
    pub include_values: bool,
    pub ignore_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchCleanOptions {
    pub recursive: bool,
    pub jobs: Option<usize>,
    pub profile: CleanProfile,
    pub output_dir: Option<PathBuf>,
    pub in_place: bool,
    pub safe_name: bool,
    pub overwrite: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchScanReport {
    pub target_path: PathBuf,
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub total_findings: usize,
    pub reports: Vec<ScanReport>,
    pub summary: FindingSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchCleanReport {
    pub target_path: PathBuf,
    pub total_files: usize,
    pub cleaned_files: usize,
    pub skipped_files: usize,
    pub failed_files: usize,
    pub verified_clean_count: usize,
    pub file_reports: Vec<VerificationReport>,
}
