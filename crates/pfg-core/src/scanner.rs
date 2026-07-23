use std::fs;
use std::path::Path;
use pfg_format_image::{detect_format, scan_jpeg_metadata, ImageFormat};
use pfg_model::{FindingSummary, InputFileMetadata, ScanReport, Severity};
use pfg_policy::PolicyEngine;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::masking;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanOptions {
    pub include_values: bool,
}

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Symlink access denied")]
    SymlinkDenied,
    #[error("Unsupported file format")]
    UnsupportedFormat,
    #[error("Parse error: {0}")]
    ParseError(String),
}

pub fn scan_file(path: &Path, options: &ScanOptions) -> Result<ScanReport, CoreError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(CoreError::SymlinkDenied);
    }

    let buffer = fs::read(path)?;

    let mut hasher = Sha256::new();
    hasher.update(&buffer);
    let hash_hex = format!("{:x}", hasher.finalize());

    let format = detect_format(&buffer).ok_or(CoreError::UnsupportedFormat)?;
    let policy = PolicyEngine::balanced();

    let mut findings = match format {
        ImageFormat::Jpeg => {
            scan_jpeg_metadata(&buffer, &policy).map_err(|e| CoreError::ParseError(e.to_string()))?
        }
        _ => return Err(CoreError::UnsupportedFormat),
    };

    let mut summary = FindingSummary::default();
    for finding in &mut findings {
        match finding.severity {
            Severity::Critical => summary.critical += 1,
            Severity::High => summary.high += 1,
            Severity::Medium => summary.medium += 1,
            Severity::Low => summary.low += 1,
            Severity::Informational => summary.informational += 1,
        }

        if !options.include_values {
            if let Some(ref val) = finding.display_value {
                finding.display_value = Some(masking::mask_sensitive_value(val));
            }
        }
    }

    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    Ok(ScanReport {
        schema_version: 1,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        operation: "scan".to_string(),
        input: InputFileMetadata {
            name: filename,
            size: buffer.len() as u64,
            sha256: hash_hex,
        },
        detected_format: match format {
            ImageFormat::Jpeg => "jpeg".to_string(),
            ImageFormat::Png => "png".to_string(),
            ImageFormat::WebP => "webp".to_string(),
        },
        support_level: "full".to_string(),
        findings,
        summary,
    })
}
