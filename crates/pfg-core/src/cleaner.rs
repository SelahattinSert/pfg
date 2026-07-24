use std::fs;
use std::path::{Path, PathBuf};
use pfg_format_image::{detect_format, sanitize_image, ImageFormat};
use pfg_format_office::{detect_office_format, sanitize_office, OfficeFormat};
use pfg_format_pdf::{detect_pdf_format, sanitize_pdf};
use pfg_policy::CleanProfile;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::scanner::{scan_file, CoreError, ScanOptions};
use crate::verifier::VerificationReport;

#[derive(Debug, Clone)]
pub struct CleanOptions {
    pub profile: CleanProfile,
    pub output_dir: Option<PathBuf>,
    pub safe_name: bool,
    pub overwrite: bool,
}

pub fn clean_file(path: &Path, options: &CleanOptions) -> Result<VerificationReport, CoreError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(CoreError::SymlinkDenied);
    }

    let buffer = fs::read(path)?;

    let (sanitized_bytes, default_ext) = if detect_pdf_format(&buffer) {
        let bytes = sanitize_pdf(&buffer, options.profile)
            .map_err(|e| CoreError::ParseError(e.to_string()))?;
        (bytes, Some("pdf"))
    } else if let Some(office_fmt) = detect_office_format(&buffer) {
        let bytes = sanitize_office(&buffer, options.profile)
            .map_err(|e| CoreError::ParseError(e.to_string()))?;
        let ext = match office_fmt {
            OfficeFormat::Docx => "docx",
            OfficeFormat::Xlsx => "xlsx",
            OfficeFormat::Pptx => "pptx",
        };
        (bytes, Some(ext))
    } else if let Some(format) = detect_format(&buffer) {
        let bytes = sanitize_image(&buffer, format, options.profile)
            .map_err(|e| CoreError::ParseError(e.to_string()))?;
        let ext = match format {
            ImageFormat::Jpeg => "jpg",
            ImageFormat::Png => "png",
            ImageFormat::WebP => "webp",
        };
        (bytes, Some(ext))
    } else {
        return Err(CoreError::UnsupportedFormat);
    };

    let original_scan = scan_file(path, &ScanOptions { include_values: true })?;

    let file_stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
    let ext_str = path.extension().and_then(|e| e.to_str());

    let output_name = if options.safe_name {
        let mut hasher = Sha256::new();
        hasher.update(&sanitized_bytes);
        let hash_str = &format!("{:x}", hasher.finalize())[..12];
        match ext_str {
            Some(ext) => format!("{}.{}", hash_str, ext),
            None => {
                if let Some(ext) = default_ext {
                    format!("{}.{}", hash_str, ext)
                } else {
                    hash_str.to_string()
                }
            }
        }
    } else {
        match ext_str {
            Some(ext) => format!("{}.pfg.{}", file_stem, ext),
            None => {
                if let Some(ext) = default_ext {
                    format!("{}.pfg.{}", file_stem, ext)
                } else {
                    format!("{}.pfg", file_stem)
                }
            }
        }
    };

    let target_dir = options
        .output_dir
        .clone()
        .unwrap_or_else(|| path.parent().unwrap_or_else(|| Path::new(".")).to_path_buf());
    let target_path = target_dir.join(output_name);

    if target_path.exists() && !options.overwrite {
        return Err(CoreError::IoError(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "Target file already exists",
        )));
    }

    let tmp_path = target_dir.join(format!(".pfg_{}.tmp", Uuid::new_v4()));

    // Write to atomic temp file
    fs::write(&tmp_path, &sanitized_bytes)?;

    // Rescan temporary output to verify clean status
    let cleaned_scan = match scan_file(&tmp_path, &ScanOptions { include_values: true }) {
        Ok(scan) => scan,
        Err(e) => {
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }
    };

    if !cleaned_scan.findings.is_empty() {
        let _ = fs::remove_file(&tmp_path);
        return Err(CoreError::ParseError(
            "Post-clean verification failed: findings still present".to_string(),
        ));
    }

    // Atomic move to final target path
    if let Err(e) = fs::rename(&tmp_path, &target_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(CoreError::IoError(e));
    }

    Ok(VerificationReport {
        original_sha256: original_scan.input.sha256,
        cleaned_sha256: cleaned_scan.input.sha256,
        original_findings_count: original_scan.findings.len(),
        cleaned_findings_count: cleaned_scan.findings.len(),
        verified_clean: true,
        assurance_level: "Container Rebuilt".to_string(),
    })
}

