use crate::{clean_file, scan_file, CleanOptions, CoreError, ScanOptions, VerificationReport};
use pfg_model::{FindingSummary, ScanReport};
use pfg_policy::CleanProfile;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

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
            .filter_map(|file_path| scan_file(file_path, &scan_opts).ok())
            .collect::<Vec<ScanReport>>()
    };

    let reports = if let Some(p) = pool {
        p.install(scan_action)
    } else {
        scan_action()
    };

    let mut overall_summary = FindingSummary::default();
    let mut total_findings = 0;
    for rep in &reports {
        overall_summary.critical += rep.summary.critical;
        overall_summary.high += rep.summary.high;
        overall_summary.medium += rep.summary.medium;
        overall_summary.low += rep.summary.low;
        overall_summary.informational += rep.summary.informational;
        total_findings += rep.findings.len();
    }

    let files_scanned = reports.len();
    let files_skipped = target_files.len().saturating_sub(files_scanned);

    Ok(BatchScanReport {
        target_path: path.to_path_buf(),
        files_scanned,
        files_skipped,
        total_findings,
        reports,
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
            .filter_map(|file_path| {
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
                            let ext_str =
                                file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
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
                                let _ = fs::rename(&generated_path, file_path);
                            }
                        }
                        Some(rep)
                    }
                    Err(e) => {
                        eprintln!("Error cleaning {:?}: {:?}", file_path, e);
                        None
                    }
                }
            })
            .collect::<Vec<VerificationReport>>()
    };

    let file_reports = if let Some(p) = pool {
        p.install(clean_action)
    } else {
        clean_action()
    };

    let cleaned_files = file_reports.len();
    let verified_clean_count = file_reports.iter().filter(|r| r.verified).count();
    let failed_files = target_files.len().saturating_sub(cleaned_files);

    Ok(BatchCleanReport {
        target_path: path.to_path_buf(),
        total_files: target_files.len(),
        cleaned_files,
        skipped_files: 0,
        failed_files,
        verified_clean_count,
        file_reports,
    })
}
