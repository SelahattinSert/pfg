# Phase 5 Design Specification: Batch Processing & Directory Handling (`v0.5`)

**Document Version:** 1.0  
**Date:** 2026-07-24  
**Project:** Privacy File Guard (PFG)  
**Location:** `privacy-file-guard-source`  

---

## 1. Overview & Objective

Phase 5 introduces **Batch Processing & Recursive Directory Handling** (`v0.5`), matching Section 10.5, 11, and 18 of the Product & Engineering Plan.

Key deliverables for Phase 5:
1. **`pfg-core` Batch Engine (`batch.rs`)**:
   - `scan_directory(path: &Path, options: &BatchScanOptions) -> Result<BatchScanReport, CoreError>`
   - `clean_directory(path: &Path, options: &BatchCleanOptions) -> Result<BatchCleanReport, CoreError>`
   - Multithreaded parallel processing using `rayon`.
   - Recursive directory traversal with symlink safety.
   - Filtering via `.pfgignore`, default exclusions (`.git`, `node_modules`, `.tmp`, hidden files).
   - Aggregated `BatchScanReport` & `BatchCleanReport` with per-file status and summary statistics.
2. **`pfg-cli` Directory Subcommands & Options**:
   - `pfg scan <PATH>` automatically detects directory targets and performs recursive batch scanning.
   - `pfg clean <PATH>` automatically detects directory targets and performs recursive batch cleaning.
   - CLI flags: `-r, --recursive`, `-j, --jobs <N>`, `--in-place`, `--output-dir <DIR>`, `--ignore <PATTERN>`.
   - Terminal progress rendering for directory operations.

---

## 2. Data Models & API Interface

```rust
pub struct BatchScanOptions {
    pub recursive: bool,
    pub jobs: Option<usize>,
    pub include_values: bool,
    pub ignore_patterns: Vec<String>,
}

pub struct BatchCleanOptions {
    pub recursive: bool,
    pub jobs: Option<usize>,
    pub profile: CleanProfile,
    pub output_dir: Option<PathBuf>,
    pub in_place: bool,
    pub safe_name: bool,
    pub overwrite: bool,
}

pub struct BatchScanReport {
    pub target_path: PathBuf,
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub total_findings: usize,
    pub reports: Vec<ScanReport>,
    pub summary: FindingSummary,
}

pub struct BatchCleanReport {
    pub target_path: PathBuf,
    pub total_files: usize,
    pub cleaned_files: usize,
    pub skipped_files: usize,
    pub failed_files: usize,
    pub verified_clean_count: usize,
    pub file_reports: Vec<VerificationReport>,
}
```

---

## 3. Security Invariants & Testing

1. **Memory Safety**: `#![forbid(unsafe_code)]` in all crates.
2. **Symlink Safety**: Symlink directories and files are safely skipped or rejected with explicit symlink errors.
3. **In-Place Cleaning Safety**: Atomic writing to `.pfg_<uuid>.tmp` before replacing original file when `--in-place` is specified.
4. **Post-Clean Rescan**: Every cleaned file in batch mode undergoes individual rescan verification before being reported clean.
