# Phase 5: Batch Processing & Directory Handling Implementation Plan (`v0.5`)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Phase 5 Multithreaded Batch Scanning & Cleaning (`v0.5`), supporting directory traversal, rayon thread pool execution, `.pfgignore` pattern filtering, `BatchScanReport` aggregation, `BatchCleanReport` aggregation, in-place cleaning, and CLI directory processing.

**Architecture:** Extend `pfg-core` with `batch.rs` using `rayon` and `walkdir` / `ignore` crates, integrating into `pfg-cli`.

**Tech Stack:** Rust (edition 2021), `pfg-model`, `pfg-policy`, `rayon`, `walkdir`, `serde`.

## Global Constraints

- **Workspace Root:** `privacy-file-guard-source/`
- **Edition:** 2021
- **Unsafe Code:** `#![forbid(unsafe_code)]`
- **License:** MPL-2.0

---

### Task 1: Batch Options & Data Models (`pfg-core`)

**Files:**
- Modify: `privacy-file-guard-source/crates/pfg-core/Cargo.toml` (add `rayon = "1.8"`, `walkdir = "2.4"`)
- Create: `privacy-file-guard-source/crates/pfg-core/src/batch.rs`
- Modify: `privacy-file-guard-source/crates/pfg-core/src/lib.rs`
- Test: `privacy-file-guard-source/crates/pfg-core/tests/batch_models_tests.rs`

**Interfaces:**
- Consumes: Nothing
- Produces: `BatchScanOptions`, `BatchCleanOptions`, `BatchScanReport`, `BatchCleanReport`

- [ ] **Step 1: Write failing test for batch data models**

```rust
// crates/pfg-core/tests/batch_models_tests.rs
use std::path::PathBuf;
use pfg_core::{BatchScanOptions, BatchCleanOptions};

#[test]
fn test_batch_options_instantiation() {
    let scan_opts = BatchScanOptions {
        recursive: true,
        jobs: Some(4),
        include_values: false,
        ignore_patterns: vec![".git".to_string()],
    };
    assert!(scan_opts.recursive);

    let clean_opts = BatchCleanOptions {
        recursive: true,
        jobs: Some(4),
        profile: pfg_policy::CleanProfile::Balanced,
        output_dir: Some(PathBuf::from("/tmp")),
        in_place: false,
        safe_name: false,
        overwrite: true,
    };
    assert!(clean_opts.overwrite);
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test -p pfg-core`
Expected: FAIL due to missing batch options.

- [ ] **Step 3: Implement batch models and options**

Update `crates/pfg-core/Cargo.toml` to include dependencies:
```toml
rayon = "1.8"
walkdir = "2.4"
```

Create `crates/pfg-core/src/batch.rs`:
```rust
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
```

Update `crates/pfg-core/src/lib.rs`: export batch models.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p pfg-core`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/pfg-core
git commit -m "feat(core): add batch processing data models and options"
```

---

### Task 2: Multithreaded Batch Scanner (`scan_directory` in `pfg-core`)

**Files:**
- Modify: `privacy-file-guard-source/crates/pfg-core/src/batch.rs`
- Test: `privacy-file-guard-source/crates/pfg-core/tests/batch_scanner_tests.rs`

**Interfaces:**
- Consumes: `BatchScanOptions`
- Produces: `scan_directory(path: &Path, options: &BatchScanOptions) -> Result<BatchScanReport, CoreError>`

- [ ] **Step 1: Write failing test for batch scanner**

```rust
// crates/pfg-core/tests/batch_scanner_tests.rs
use std::fs;
use pfg_core::{scan_directory, BatchScanOptions};

#[test]
fn test_batch_directory_scanning() {
    let temp_dir = std::env::temp_dir().join("pfg_batch_scan_test");
    fs::create_dir_all(&temp_dir).unwrap();

    let img1 = temp_dir.join("test1.jpg");
    fs::copy("fixtures/images/sample.jpg", &img1).unwrap();

    let opts = BatchScanOptions {
        recursive: true,
        jobs: Some(2),
        include_values: false,
        ignore_patterns: vec![],
    };

    let report = scan_directory(&temp_dir, &opts).unwrap();
    assert!(report.files_scanned >= 1);

    fs::remove_dir_all(&temp_dir).ok();
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test -p pfg-core`
Expected: FAIL due to missing `scan_directory`.

- [ ] **Step 3: Implement `scan_directory`**

Implement `scan_directory` in `crates/pfg-core/src/batch.rs`:
- Collect file entries using `walkdir::WalkDir`.
- Filter out symlinks, hidden files, `.git`, `node_modules`.
- Execute parallel scans using `rayon::prelude::*`.
- Aggregate summary and returns `BatchScanReport`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p pfg-core`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/pfg-core
git commit -m "feat(core): implement multithreaded scan_directory engine"
```

---

### Task 3: Multithreaded Batch Cleaner (`clean_directory` in `pfg-core`)

**Files:**
- Modify: `privacy-file-guard-source/crates/pfg-core/src/batch.rs`
- Test: `privacy-file-guard-source/crates/pfg-core/tests/batch_cleaner_tests.rs`

**Interfaces:**
- Consumes: `BatchCleanOptions`
- Produces: `clean_directory(path: &Path, options: &BatchCleanOptions) -> Result<BatchCleanReport, CoreError>`

- [ ] **Step 1: Write failing test for batch cleaner**

```rust
// crates/pfg-core/tests/batch_cleaner_tests.rs
use std::fs;
use pfg_core::{clean_directory, BatchCleanOptions};
use pfg_policy::CleanProfile;

#[test]
fn test_batch_directory_cleaning() {
    let temp_dir = std::env::temp_dir().join("pfg_batch_clean_test");
    fs::create_dir_all(&temp_dir).unwrap();

    let img1 = temp_dir.join("test1.jpg");
    fs::copy("fixtures/images/sample.jpg", &img1).unwrap();

    let opts = BatchCleanOptions {
        recursive: true,
        jobs: Some(2),
        profile: CleanProfile::Balanced,
        output_dir: None,
        in_place: false,
        safe_name: false,
        overwrite: true,
    };

    let report = clean_directory(&temp_dir, &opts).unwrap();
    assert!(report.cleaned_files >= 1);
    assert_eq!(report.verified_clean_count, report.cleaned_files);

    fs::remove_dir_all(&temp_dir).ok();
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test -p pfg-core`
Expected: FAIL due to missing `clean_directory`.

- [ ] **Step 3: Implement `clean_directory`**

Implement `clean_directory` in `crates/pfg-core/src/batch.rs`:
- Collect target files.
- Execute parallel clean and rescan verification using `rayon::prelude::*`.
- Support `--in-place` replacing original file atomically via `.pfg_<uuid>.tmp`.
- Aggregate `BatchCleanReport`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p pfg-core`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/pfg-core
git commit -m "feat(core): implement multithreaded clean_directory engine"
```

---

### Task 4: CLI Directory Auto-Detection & Batch Commands (`pfg-cli`)

**Files:**
- Modify: `privacy-file-guard-source/crates/pfg-cli/src/main.rs`
- Modify: `privacy-file-guard-source/crates/pfg-cli/tests/cli_tests.rs`

**Interfaces:**
- Consumes: Batch API in `pfg-core`
- Produces: Directory target handling in `pfg scan <DIR>` and `pfg clean <DIR>`

- [ ] **Step 1: Write failing CLI test for directory targets**

```rust
// In crates/pfg-cli/tests/cli_tests.rs
#[test]
fn test_cli_batch_scan_directory() {
    let temp_dir = std::env::temp_dir().join("pfg_cli_batch_scan_test");
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::copy("fixtures/images/sample.jpg", temp_dir.join("sample.jpg")).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_pfg"))
        .arg("scan")
        .arg(&temp_dir)
        .arg("-r")
        .output()
        .unwrap();

    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("Files Scanned:"));

    std::fs::remove_dir_all(&temp_dir).ok();
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test -p pfg-cli`
Expected: FAIL due to directory scan returning error.

- [ ] **Step 3: Implement CLI directory dispatching**

Update `crates/pfg-cli/src/main.rs`:
- Check if target path `is_dir()`.
- If directory, dispatch to `scan_directory` or `clean_directory`.
- Add flags `-r, --recursive`, `-j, --jobs`, `--in-place`.
- Render clean summary table for batch reports.

- [ ] **Step 4: Run workspace tests**

Run: `cargo test --workspace`
Expected: PASS across all workspace crates.

- [ ] **Step 5: Commit**

```bash
git add crates/pfg-cli
git commit -m "feat(cli): add recursive directory batch scanning and cleaning support"
```
