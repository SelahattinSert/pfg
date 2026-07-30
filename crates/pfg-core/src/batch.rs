use crate::cleaner::{clean_file, perform_transactional_replace, CleanOptions};
use crate::scanner::{scan_file, CoreError, ScanOptions};
use pfg_model::{FindingSummary, ScanReport, VerificationReport};
use pfg_policy::CleanProfile;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BatchFileStatus {
    Success,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchFileScanResult {
    pub file_path: PathBuf,
    pub status: BatchFileStatus,
    pub report: Option<ScanReport>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchFileResult {
    pub file_path: PathBuf,
    pub status: BatchFileStatus,
    pub report: Option<VerificationReport>,
    pub error: Option<String>,
}

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
    pub files_failed: usize,
    pub total_findings: usize,
    pub reports: Vec<ScanReport>,
    pub file_results: Vec<BatchFileScanResult>,
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
    pub file_results: Vec<BatchFileResult>,
}

pub fn scan_directory(
    path: &Path,
    options: &BatchScanOptions,
) -> Result<BatchScanReport, CoreError> {
    if !path.exists() {
        return Err(CoreError::IoError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Target path does not exist",
        )));
    }

    if options.jobs == Some(0) {
        return Err(CoreError::ResourceLimitExceeded(
            "Jobs count cannot be 0".to_string(),
        ));
    }

    let mut walker = WalkDir::new(path);
    if !options.recursive {
        walker = walker.max_depth(1);
    }

    let scan_opts = ScanOptions {
        include_values: options.include_values,
    };

    let target_files: Vec<PathBuf> = walker
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            if e.file_type().is_symlink() || e.file_type().is_dir() {
                return false;
            }
            let name = e.file_name().to_string_lossy();
            if name.starts_with('.') || name == "node_modules" || name == ".git" {
                return false;
            }
            for pattern in &options.ignore_patterns {
                if name.contains(pattern) {
                    return false;
                }
            }
            true
        })
        .map(|e| e.path().to_path_buf())
        .collect();

    let pool = if let Some(jobs) = options.jobs {
        rayon::ThreadPoolBuilder::new()
            .num_threads(jobs)
            .build()
            .ok()
    } else {
        None
    };

    let scan_action = || {
        target_files
            .par_iter()
            .map(|file_path| match scan_file(file_path, &scan_opts) {
                Ok(report) => BatchFileScanResult {
                    file_path: file_path.clone(),
                    status: BatchFileStatus::Success,
                    report: Some(report),
                    error: None,
                },
                Err(err) => BatchFileScanResult {
                    file_path: file_path.clone(),
                    status: BatchFileStatus::Failed,
                    report: None,
                    error: Some(err.to_string()),
                },
            })
            .collect::<Vec<BatchFileScanResult>>()
    };

    let file_results = if let Some(p) = pool {
        p.install(scan_action)
    } else {
        scan_action()
    };

    let mut reports = Vec::new();
    let mut overall_summary = FindingSummary::default();
    let mut total_findings = 0;
    let mut files_scanned = 0;
    let mut files_failed = 0;

    for res in &file_results {
        match &res.report {
            Some(rep) => {
                files_scanned += 1;
                overall_summary.critical += rep.summary.critical;
                overall_summary.high += rep.summary.high;
                overall_summary.medium += rep.summary.medium;
                overall_summary.low += rep.summary.low;
                overall_summary.informational += rep.summary.informational;
                total_findings += rep.findings.len();
                reports.push(rep.clone());
            }
            None => {
                files_failed += 1;
            }
        }
    }

    let files_skipped = target_files
        .len()
        .saturating_sub(files_scanned + files_failed);

    Ok(BatchScanReport {
        target_path: path.to_path_buf(),
        files_scanned,
        files_skipped,
        files_failed,
        total_findings,
        reports,
        file_results,
        summary: overall_summary,
    })
}

pub fn clean_directory(
    path: &Path,
    options: &BatchCleanOptions,
) -> Result<BatchCleanReport, CoreError> {
    if !path.exists() {
        return Err(CoreError::IoError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Target path does not exist",
        )));
    }

    if options.jobs == Some(0) {
        return Err(CoreError::ResourceLimitExceeded(
            "Jobs count cannot be 0".to_string(),
        ));
    }

    let mut walker = WalkDir::new(path);
    if !options.recursive {
        walker = walker.max_depth(1);
    }

    let target_files: Vec<PathBuf> = walker
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            if e.file_type().is_symlink() || e.file_type().is_dir() {
                return false;
            }
            let name = e.file_name().to_string_lossy();
            if name.starts_with('.') || name == "node_modules" || name == ".git" {
                return false;
            }
            true
        })
        .map(|e| e.path().to_path_buf())
        .collect();

    let pool = if let Some(jobs) = options.jobs {
        rayon::ThreadPoolBuilder::new()
            .num_threads(jobs)
            .build()
            .ok()
    } else {
        None
    };

    let clean_action = || {
        target_files
            .par_iter()
            .map(|file_path| {
                let clean_opts = CleanOptions {
                    profile: options.profile,
                    output_dir: options.output_dir.clone(),
                    safe_name: options.safe_name,
                    overwrite: options.overwrite,
                };
                let res = clean_file(file_path, &clean_opts);
                match res {
                    Ok(rep) => {
                        if options.in_place && options.output_dir.is_none() {
                            // Detect actual format from report to avoid extension mismatch
                            let ext_str = match rep.assurance_level {
                                pfg_model::AssuranceLevel::MetadataRemoved => "jpg",
                                pfg_model::AssuranceLevel::StructurallyVerified => "pdf",
                                _ => file_path.extension().and_then(|e| e.to_str()).unwrap_or(""),
                            };
                            let file_stem = file_path
                                .file_stem()
                                .and_then(|s| s.to_str())
                                .unwrap_or("file");
                            let generated_name = if options.safe_name {
                                format!("{}.{}", &rep.cleaned_sha256[..12], ext_str)
                            } else if ext_str.is_empty() {
                                format!("{}.pfg", file_stem)
                            } else {
                                format!("{}.pfg.{}", file_stem, ext_str)
                            };
                            let parent = file_path.parent().unwrap_or_else(|| Path::new("."));
                            let generated_path = parent.join(generated_name);

                            if generated_path.exists() && generated_path != *file_path {
                                let tmp_inplace =
                                    parent.join(format!(".pfg_inp_{}.tmp", uuid::Uuid::new_v4()));
                                if fs::rename(&generated_path, &tmp_inplace).is_ok() {
                                    if let Err(tx_err) = perform_transactional_replace(
                                        &tmp_inplace,
                                        file_path,
                                        file_path,
                                        options.profile,
                                        &rep,
                                    ) {
                                        return BatchFileResult {
                                            file_path: file_path.clone(),
                                            status: BatchFileStatus::Failed,
                                            report: None,
                                            error: Some(format!(
                                                "Transactional replace failed: {}",
                                                tx_err
                                            )),
                                        };
                                    }
                                }
                            }
                        }

                        BatchFileResult {
                            file_path: file_path.clone(),
                            status: BatchFileStatus::Success,
                            report: Some(rep),
                            error: None,
                        }
                    }
                    Err(e) => BatchFileResult {
                        file_path: file_path.clone(),
                        status: BatchFileStatus::Failed,
                        report: None,
                        error: Some(e.to_string()),
                    },
                }
            })
            .collect::<Vec<BatchFileResult>>()
    };

    let file_results = if let Some(p) = pool {
        p.install(clean_action)
    } else {
        clean_action()
    };

    let mut file_reports = Vec::new();
    let mut cleaned_files = 0;
    let mut failed_files = 0;
    let mut verified_clean_count = 0;

    for result in &file_results {
        match &result.report {
            Some(rep) => {
                cleaned_files += 1;
                if rep.verified {
                    verified_clean_count += 1;
                }
                file_reports.push(rep.clone());
            }
            None => {
                failed_files += 1;
            }
        }
    }

    Ok(BatchCleanReport {
        target_path: path.to_path_buf(),
        total_files: target_files.len(),
        cleaned_files,
        skipped_files: 0,
        failed_files,
        verified_clean_count,
        file_reports,
        file_results,
    })
}
