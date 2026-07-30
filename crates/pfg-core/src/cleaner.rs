use pfg_format_image::{detect_format, sanitize_image, ImageFormat};
use pfg_format_office::{detect_office_format, sanitize_office, OfficeFormat};
use pfg_format_pdf::{detect_pdf_format, sanitize_pdf};
use pfg_policy::CleanProfile;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::scanner::CoreError;
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

    let limits = crate::ResourceLimits::default();
    if metadata.len() > limits.max_file_size {
        return Err(CoreError::ResourceLimitExceeded(format!(
            "File size {} bytes exceeds limit of {} bytes",
            metadata.len(),
            limits.max_file_size
        )));
    }

    let buffer = fs::read(path)?;

    let (sanitized_bytes, default_ext) = if detect_pdf_format(&buffer) {
        let bytes = sanitize_pdf(&buffer, options.profile)
            .map_err(|e| CoreError::ParseError(e.to_string()))?;
        (bytes, "pdf")
    } else if let Some(office_fmt) = detect_office_format(&buffer) {
        let bytes = sanitize_office(&buffer, options.profile)
            .map_err(|e| CoreError::ParseError(e.to_string()))?;
        let ext = match office_fmt {
            OfficeFormat::Docx => "docx",
            OfficeFormat::Xlsx => "xlsx",
            OfficeFormat::Pptx => "pptx",
        };
        (bytes, ext)
    } else if let Some(format) = detect_format(&buffer) {
        let bytes = sanitize_image(&buffer, format, options.profile)
            .map_err(|e| CoreError::ParseError(e.to_string()))?;
        let ext = match format {
            ImageFormat::Jpeg => "jpg",
            ImageFormat::Png => "png",
            ImageFormat::WebP => "webp",
        };
        (bytes, ext)
    } else {
        return Err(CoreError::UnsupportedFormat);
    };

    let file_stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("file");

    let output_name = if options.safe_name {
        let mut hasher = Sha256::new();
        hasher.update(&sanitized_bytes);
        let hash_str = &format!("{:x}", hasher.finalize())[..12];
        format!("{}.{}", hash_str, default_ext)
    } else {
        format!("{}.pfg.{}", file_stem, default_ext)
    };

    let target_dir = options.output_dir.clone().unwrap_or_else(|| {
        path.parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    });
    let target_path = target_dir.join(output_name);

    if target_path.exists() && !options.overwrite && target_path != *path {
        return Err(CoreError::IoError(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "Target file already exists",
        )));
    }

    let tmp_path = target_dir.join(format!(".pfg_{}.tmp", Uuid::new_v4()));

    // 1. Write to atomic temp file and flush/sync_all to disk
    {
        let mut file = File::create(&tmp_path)?;
        file.write_all(&sanitized_bytes)?;
        file.sync_all()?;
    }

    // 2. Rescan temporary output to verify clean status
    let ver_report =
        match crate::verifier::verify_files_with_profile(path, &tmp_path, options.profile) {
            Ok(report) => report,
            Err(e) => {
                let _ = fs::remove_file(&tmp_path);
                return Err(e);
            }
        };

    if !ver_report.verified {
        let _ = fs::remove_file(&tmp_path);
        return Err(CoreError::ParseError(
            "Post-clean verification failed: required policy removals still present or decode error".to_string(),
        ));
    }

    // 3. Transactional atomic replacement with backup and rollback support
    perform_transactional_replace(&tmp_path, &target_path, path, options.profile, &ver_report)?;

    Ok(ver_report)
}

pub fn perform_transactional_replace(
    tmp_path: &Path,
    target_path: &Path,
    original_path: &Path,
    profile: CleanProfile,
    _expected_report: &VerificationReport,
) -> Result<(), CoreError> {
    let parent = target_path.parent().unwrap_or_else(|| Path::new("."));

    if target_path.exists() {
        let backup_path = parent.join(format!(".pfg_bak_{}.tmp", Uuid::new_v4()));

        if let Err(_e) = fs::rename(target_path, &backup_path) {
            if let Err(copy_err) = fs::copy(target_path, &backup_path) {
                let _ = fs::remove_file(tmp_path);
                return Err(CoreError::IoError(copy_err));
            }
            let _ = fs::remove_file(target_path);
        }

        let replace_res = if fs::rename(tmp_path, target_path).is_err() {
            fs::copy(tmp_path, target_path).map(|_| {
                let _ = fs::remove_file(tmp_path);
            })
        } else {
            Ok(())
        };

        if let Err(replace_err) = replace_res {
            let _ = fs::rename(&backup_path, target_path)
                .or_else(|_| fs::copy(&backup_path, target_path).map(|_| ()));
            let _ = fs::remove_file(&backup_path);
            let _ = fs::remove_file(tmp_path);
            return Err(CoreError::IoError(replace_err));
        }

        let final_verify =
            crate::verifier::verify_files_with_profile(original_path, target_path, profile);
        match final_verify {
            Ok(rep) if rep.verified => {
                let _ = fs::remove_file(&backup_path);
                Ok(())
            }
            _ => {
                let _ = fs::rename(&backup_path, target_path)
                    .or_else(|_| fs::copy(&backup_path, target_path).map(|_| ()));
                let _ = fs::remove_file(&backup_path);
                let _ = fs::remove_file(tmp_path);
                Err(CoreError::ParseError(
                    "Final path post-replace verification failed".to_string(),
                ))
            }
        }
    } else {
        if let Err(_e) = fs::rename(tmp_path, target_path) {
            if let Err(copy_err) = fs::copy(tmp_path, target_path) {
                let _ = fs::remove_file(tmp_path);
                return Err(CoreError::IoError(copy_err));
            }
            let _ = fs::remove_file(tmp_path);
        }

        let final_verify =
            crate::verifier::verify_files_with_profile(original_path, target_path, profile);
        match final_verify {
            Ok(rep) if rep.verified => Ok(()),
            _ => {
                let _ = fs::remove_file(target_path);
                Err(CoreError::ParseError(
                    "Final path post-replace verification failed".to_string(),
                ))
            }
        }
    }
}
