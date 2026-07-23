use std::path::Path;
use serde::{Deserialize, Serialize};
use crate::scanner::{scan_file, CoreError, ScanOptions};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReport {
    pub original_sha256: String,
    pub cleaned_sha256: String,
    pub original_findings_count: usize,
    pub cleaned_findings_count: usize,
    pub verified_clean: bool,
    pub assurance_level: String,
}

pub fn verify_files(original_path: &Path, cleaned_path: &Path) -> Result<VerificationReport, CoreError> {
    let original_scan = scan_file(original_path, &ScanOptions { include_values: true })?;
    let cleaned_scan = scan_file(cleaned_path, &ScanOptions { include_values: true })?;

    let verified = cleaned_scan.findings.is_empty();

    Ok(VerificationReport {
        original_sha256: original_scan.input.sha256,
        cleaned_sha256: cleaned_scan.input.sha256,
        original_findings_count: original_scan.findings.len(),
        cleaned_findings_count: cleaned_scan.findings.len(),
        verified_clean: verified,
        assurance_level: if verified {
            "Container Rebuilt".to_string()
        } else {
            "Verification Failed".to_string()
        },
    })
}
