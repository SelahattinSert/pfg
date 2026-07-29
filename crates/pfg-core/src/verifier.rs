use std::fs;
use std::path::Path;
pub use pfg_model::{
    AssuranceLevel, VerificationCheck, VerificationReport, VerificationStatus,
};
use pfg_policy::{CleanProfile, PolicyAction, PolicyEngine};
use crate::scanner::{scan_file, CoreError, ScanOptions};

pub fn verify_files(original_path: &Path, cleaned_path: &Path) -> Result<VerificationReport, CoreError> {
    verify_files_with_profile(original_path, cleaned_path, CleanProfile::Balanced)
}

pub fn verify_files_with_profile(
    original_path: &Path,
    cleaned_path: &Path,
    profile: CleanProfile,
) -> Result<VerificationReport, CoreError> {
    let original_scan = scan_file(original_path, &ScanOptions { include_values: true })?;
    let cleaned_scan = scan_file(cleaned_path, &ScanOptions { include_values: true })?;
    let cleaned_bytes = fs::read(cleaned_path)?;

    let policy = PolicyEngine::for_profile(profile);
    let mut checks = Vec::new();
    let mut warnings = Vec::new();

    // Check 1: Decode & Format Integrity Check
    let mut decode_passed = true;
    let format_str = &cleaned_scan.detected_format;
    match format_str.as_str() {
        "jpeg" | "png" | "webp" => {
            if pfg_format_image::detect_format(&cleaned_bytes).is_none() {
                decode_passed = false;
            }
        }
        "pdf" => {
            if pfg_format_pdf::validate_pdf_structure(&cleaned_bytes).is_err() {
                decode_passed = false;
            }
        }
        "docx" | "xlsx" | "pptx" => {
            if zip::ZipArchive::new(std::io::Cursor::new(&cleaned_bytes)).is_err() {
                decode_passed = false;
            }
        }
        _ => {}
    }

    checks.push(VerificationCheck {
        name: "Decode Validation".to_string(),
        status: if decode_passed {
            VerificationStatus::Passed
        } else {
            VerificationStatus::Failed
        },
        message: if decode_passed {
            Some("Cleaned file decoded cleanly".to_string())
        } else {
            Some("Cleaned file structure could not be parsed".to_string())
        },
    });

    // Check 2: Policy Removal Check
    let mut required_removals_remaining = 0;
    for finding in &cleaned_scan.findings {
        match policy.action_for(finding) {
            PolicyAction::Remove => {
                required_removals_remaining += 1;
            }
            PolicyAction::Preserve | PolicyAction::Warn => {
                warnings.push(format!(
                    "Policy preserved finding: {} ({:?})",
                    finding.key, finding.category
                ));
            }
        }
    }

    let policy_passed = required_removals_remaining == 0;
    checks.push(VerificationCheck {
        name: "Policy Verification".to_string(),
        status: if policy_passed {
            VerificationStatus::Passed
        } else {
            VerificationStatus::Failed
        },
        message: if policy_passed {
            Some("All policy-required removals succeeded".to_string())
        } else {
            Some(format!(
                "{} required removals still present",
                required_removals_remaining
            ))
        },
    });

    let verified = decode_passed && policy_passed;
    let assurance_level = if verified {
        if format_str == "pdf" || format_str == "docx" || format_str == "xlsx" || format_str == "pptx" {
            AssuranceLevel::StructurallyVerified
        } else {
            AssuranceLevel::MetadataRemoved
        }
    } else {
        AssuranceLevel::VerificationFailed
    };

    Ok(VerificationReport {
        original_sha256: original_scan.input.sha256,
        cleaned_sha256: cleaned_scan.input.sha256,
        original_findings_count: original_scan.findings.len(),
        remaining_findings_count: cleaned_scan.findings.len(),
        required_removals_remaining,
        verified,
        assurance_level,
        checks,
        warnings,
    })
}
