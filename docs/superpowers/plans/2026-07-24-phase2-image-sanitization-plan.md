# Phase 2: Image Metadata Sanitization & Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Phase 2 Image Metadata Sanitization Engine (`v0.2`), supporting JPEG, PNG, and WebP metadata stripping (`pfg clean`), verification rescan (`pfg verify`), `Balanced` and `Strict` clean profiles, and safe atomic file writing.

**Architecture:** Extend Cargo workspace crates: `pfg-policy` (CleanProfile), `pfg-format-image` (`sanitize_image` for JPEG, PNG, WebP), `pfg-core` (`clean_file` pipeline & verification), and `pfg-cli` (`pfg clean` and `pfg verify` subcommands).

**Tech Stack:** Rust (edition 2021), `crc32fast` (for PNG CRC calculation), `serde`, `clap`, `sha2`, `thiserror`.

## Global Constraints

- **Workspace Root:** `privacy-file-guard-source/`
- **Edition:** 2021
- **Unsafe Code:** `#![forbid(unsafe_code)]`
- **License:** MPL-2.0
- **Default Output Extension:** `.pfg.<ext>`

---

### Task 1: Clean Profile & Policy Rules (`pfg-policy`)

**Files:**
- Modify: `privacy-file-guard-source/crates/pfg-policy/src/lib.rs`
- Modify: `privacy-file-guard-source/crates/pfg-policy/src/rules.rs`
- Create: `privacy-file-guard-source/crates/pfg-policy/src/profile.rs`
- Test: `privacy-file-guard-source/crates/pfg-policy/tests/profile_tests.rs`

**Interfaces:**
- Consumes: Nothing
- Produces: `CleanProfile::Balanced`, `CleanProfile::Strict`

- [ ] **Step 1: Write failing test for CleanProfile**

```rust
// crates/pfg-policy/tests/profile_tests.rs
use pfg_policy::CleanProfile;

#[test]
fn test_clean_profile_serde() {
    let profile = CleanProfile::Balanced;
    let json = serde_json::to_string(&profile).unwrap();
    assert_eq!(json, "\"balanced\"");

    let strict: CleanProfile = serde_json::from_str("\"strict\"").unwrap();
    assert_eq!(strict, CleanProfile::Strict);
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test -p pfg-policy`
Expected: FAIL due to missing `CleanProfile`.

- [ ] **Step 3: Implement `CleanProfile` enum**

Create `crates/pfg-policy/src/profile.rs`:
```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CleanProfile {
    Balanced,
    Strict,
}

impl Default for CleanProfile {
    fn default() -> Self {
        Self::Balanced
    }
}
```

Update `crates/pfg-policy/src/lib.rs`:
```rust
#![forbid(unsafe_code)]

pub mod profile;
pub mod rules;

pub use profile::CleanProfile;
pub use rules::PolicyEngine;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p pfg-policy`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/pfg-policy
git commit -m "feat(policy): add CleanProfile enum and tests to pfg-policy"
```

---

### Task 2: JPEG Metadata Sanitizer (`pfg-format-image`)

**Files:**
- Modify: `privacy-file-guard-source/crates/pfg-format-image/Cargo.toml`
- Modify: `privacy-file-guard-source/crates/pfg-format-image/src/lib.rs`
- Create: `privacy-file-guard-source/crates/pfg-format-image/src/sanitizer.rs`
- Create: `privacy-file-guard-source/crates/pfg-format-image/src/jpeg_clean.rs`
- Test: `privacy-file-guard-source/crates/pfg-format-image/tests/jpeg_clean_tests.rs`

**Interfaces:**
- Consumes: `pfg_policy::CleanProfile`
- Produces: `sanitize_jpeg(buffer: &[u8], profile: CleanProfile) -> Result<Vec<u8>, ImageSanitizeError>`

- [ ] **Step 1: Write failing test for JPEG sanitizer**

```rust
// crates/pfg-format-image/tests/jpeg_clean_tests.rs
use pfg_format_image::{scan_jpeg_metadata, sanitize_jpeg};
use pfg_policy::{CleanProfile, PolicyEngine};

#[test]
fn test_jpeg_sanitization_removes_com_and_app1() {
    let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xFE, 0x00, 0x14];
    jpeg.extend_from_slice(b"Secret comment\0");
    jpeg.extend_from_slice(&[0xFF, 0xD9]);

    let cleaned = sanitize_jpeg(&jpeg, CleanProfile::Balanced).unwrap();
    let policy = PolicyEngine::balanced();
    let findings = scan_jpeg_metadata(&cleaned, &policy).unwrap();

    assert!(findings.is_empty());
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test -p pfg-format-image`
Expected: FAIL due to missing `sanitize_jpeg`.

- [ ] **Step 3: Implement JPEG Sanitizer**

Create `crates/pfg-format-image/src/jpeg_clean.rs`:
```rust
use crate::jpeg::ImageParseError;
use pfg_policy::CleanProfile;

pub fn sanitize_jpeg(buffer: &[u8], profile: CleanProfile) -> Result<Vec<u8>, ImageParseError> {
    if buffer.len() < 3 || buffer[0] != 0xFF || buffer[1] != 0xD8 || buffer[2] != 0xFF {
        return Err(ImageParseError::InvalidSoi);
    }

    let mut output = Vec::with_capacity(buffer.len());
    output.push(0xFF);
    output.push(0xD8);

    let mut cursor = 2;

    while cursor < buffer.len() {
        if buffer[cursor] != 0xFF {
            cursor += 1;
            continue;
        }

        while cursor < buffer.len() && buffer[cursor] == 0xFF {
            cursor += 1;
        }

        if cursor >= buffer.len() {
            break;
        }

        let marker = buffer[cursor];
        cursor += 1;

        if marker == 0xD9 { // EOI
            output.push(0xFF);
            output.push(0xD9);
            break;
        }

        if cursor + 2 > buffer.len() {
            return Err(ImageParseError::UnexpectedEof);
        }

        let length = u16::from_be_bytes([buffer[cursor], buffer[cursor + 1]]) as usize;
        if length < 2 || cursor + length > buffer.len() {
            return Err(ImageParseError::UnexpectedEof);
        }

        let segment_data = &buffer[cursor + 2..cursor + length];
        let mut strip = false;

        match marker {
            0xE1 => strip = true, // APP1 (EXIF / XMP)
            0xED => strip = true, // APP13 (Photoshop / IPTC)
            0xFE => strip = true, // COM
            0xE2..=0xEE if profile == CleanProfile::Strict => strip = true,
            _ => {}
        }

        if !strip {
            output.push(0xFF);
            output.push(marker);
            output.push(buffer[cursor]);
            output.push(buffer[cursor + 1]);
            output.extend_from_slice(segment_data);
        }

        cursor += length;
    }

    Ok(output)
}
```

Update `crates/pfg-format-image/src/lib.rs`:
```rust
#![forbid(unsafe_code)]

pub mod detector;
pub mod exif;
pub mod jpeg;
pub mod jpeg_clean;
pub mod xmp;

pub use detector::{detect_format, ImageFormat};
pub use jpeg::{scan_jpeg_metadata, ImageParseError};
pub use jpeg_clean::sanitize_jpeg;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p pfg-format-image`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/pfg-format-image
git commit -m "feat(image): implement JPEG metadata sanitizer in pfg-format-image"
```

---

### Task 3: PNG & WebP Sanitizers (`pfg-format-image`)

**Files:**
- Modify: `privacy-file-guard-source/crates/pfg-format-image/Cargo.toml` (add `crc32fast = "1.3"`)
- Create: `privacy-file-guard-source/crates/pfg-format-image/src/png_clean.rs`
- Create: `privacy-file-guard-source/crates/pfg-format-image/src/webp_clean.rs`
- Test: `privacy-file-guard-source/crates/pfg-format-image/tests/png_webp_clean_tests.rs`

**Interfaces:**
- Consumes: `ImageFormat`, `CleanProfile`
- Produces: `sanitize_png`, `sanitize_webp`, `sanitize_image`

- [ ] **Step 1: Write failing test for PNG & WebP sanitizers**

```rust
// crates/pfg-format-image/tests/png_webp_clean_tests.rs
use pfg_format_image::{detect_format, sanitize_image, ImageFormat};
use pfg_policy::CleanProfile;

#[test]
fn test_png_sanitization() {
    let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    // Dummy tEXt chunk
    let chunk_type = b"tEXt";
    let chunk_data = b"Comment\0Test comment";
    let len = chunk_data.len() as u32;
    png.extend_from_slice(&len.to_be_bytes());
    png.extend_from_slice(chunk_type);
    png.extend_from_slice(chunk_data);
    png.extend_from_slice(&[0, 0, 0, 0]); // CRC placeholder

    let cleaned = sanitize_image(&png, ImageFormat::Png, CleanProfile::Balanced).unwrap();
    assert_eq!(detect_format(&cleaned), Some(ImageFormat::Png));
    assert!(!cleaned.windows(4).any(|w| w == b"tEXt"));
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test -p pfg-format-image`
Expected: FAIL due to missing `sanitize_png` / `sanitize_image`.

- [ ] **Step 3: Implement PNG and WebP sanitizers**

Add `crc32fast = "1.3"` to `crates/pfg-format-image/Cargo.toml`.

Create `crates/pfg-format-image/src/png_clean.rs`:
```rust
use crc32fast::Hasher;
use crate::jpeg::ImageParseError;

pub fn sanitize_png(buffer: &[u8]) -> Result<Vec<u8>, ImageParseError> {
    if buffer.len() < 8 || &buffer[0..8] != b"\x89PNG\r\n\x1a\n" {
        return Err(ImageParseError::InvalidSoi);
    }

    let mut output = Vec::with_capacity(buffer.len());
    output.extend_from_slice(&buffer[0..8]);

    let mut cursor = 8;
    while cursor + 12 <= buffer.len() {
        let length = u32::from_be_bytes([buffer[cursor], buffer[cursor + 1], buffer[cursor + 2], buffer[cursor + 3]]) as usize;
        let chunk_type = &buffer[cursor + 4..cursor + 8];
        let chunk_end = cursor + 12 + length;

        if chunk_end > buffer.len() {
            return Err(ImageParseError::UnexpectedEof);
        }

        let is_removable = matches!(chunk_type, b"eXIf" | b"tEXt" | b"zTXt" | b"iTXt" | b"tIME" | b"iCCP" | b"pHYs" | b"sPLT");

        if !is_removable {
            output.extend_from_slice(&buffer[cursor..cursor + 8 + length]);
            let mut hasher = Hasher::new();
            hasher.update(&buffer[cursor + 4..cursor + 8 + length]);
            let crc = hasher.finalize();
            output.extend_from_slice(&crc.to_be_bytes());
        }

        cursor = chunk_end;
    }

    Ok(output)
}
```

Create `crates/pfg-format-image/src/webp_clean.rs`:
```rust
use crate::jpeg::ImageParseError;

pub fn sanitize_webp(buffer: &[u8]) -> Result<Vec<u8>, ImageParseError> {
    if buffer.len() < 12 || &buffer[0..4] != b"RIFF" || &buffer[8..12] != b"WEBP" {
        return Err(ImageParseError::InvalidSoi);
    }

    let mut output = Vec::with_capacity(buffer.len());
    output.extend_from_slice(&buffer[0..12]);

    let mut cursor = 12;
    while cursor + 8 <= buffer.len() {
        let chunk_type = &buffer[cursor..cursor + 4];
        let length = u32::from_le_bytes([buffer[cursor + 4], buffer[cursor + 5], buffer[cursor + 6], buffer[cursor + 7]]) as usize;
        let padded_len = if length % 2 != 0 { length + 1 } else { length };
        let chunk_end = cursor + 8 + padded_len;

        if chunk_end > buffer.len() {
            return Err(ImageParseError::UnexpectedEof);
        }

        if chunk_type != b"EXIF" && chunk_type != b"XMP " {
            output.extend_from_slice(&buffer[cursor..cursor + 8 + length]);
            if length % 2 != 0 {
                output.push(0);
            }
        }

        cursor = chunk_end;
    }

    // Update RIFF payload length
    let riff_size = (output.len() - 8) as u32;
    output[4..8].copy_from_slice(&riff_size.to_le_bytes());

    Ok(output)
}
```

Update `crates/pfg-format-image/src/lib.rs`:
```rust
#![forbid(unsafe_code)]

pub mod detector;
pub mod exif;
pub mod jpeg;
pub mod jpeg_clean;
pub mod png_clean;
pub mod webp_clean;
pub mod xmp;

pub use detector::{detect_format, ImageFormat};
pub use jpeg::{scan_jpeg_metadata, ImageParseError};
pub use jpeg_clean::sanitize_jpeg;
pub use png_clean::sanitize_png;
pub use webp_clean::sanitize_webp;
pub use pfg_policy::CleanProfile;

pub fn sanitize_image(buffer: &[u8], format: ImageFormat, profile: CleanProfile) -> Result<Vec<u8>, ImageParseError> {
    match format {
        ImageFormat::Jpeg => sanitize_jpeg(buffer, profile),
        ImageFormat::Png => sanitize_png(buffer),
        ImageFormat::WebP => sanitize_webp(buffer),
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p pfg-format-image`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/pfg-format-image
git commit -m "feat(image): implement PNG and WebP metadata sanitizers"
```

---

### Task 4: Core Sanitization Pipeline & Verifier (`pfg-core`)

**Files:**
- Modify: `privacy-file-guard-source/crates/pfg-core/src/lib.rs`
- Modify: `privacy-file-guard-source/crates/pfg-core/src/scanner.rs`
- Create: `privacy-file-guard-source/crates/pfg-core/src/cleaner.rs`
- Create: `privacy-file-guard-source/crates/pfg-core/src/verifier.rs`
- Test: `privacy-file-guard-source/crates/pfg-core/tests/cleaner_tests.rs`

**Interfaces:**
- Consumes: `pfg_policy::CleanProfile`, `pfg_format_image::sanitize_image`
- Produces: `CleanOptions`, `VerificationReport`, `clean_file(path: &Path, options: &CleanOptions) -> Result<VerificationReport, CoreError>`, `verify_files(original_path: &Path, cleaned_path: &Path) -> Result<VerificationReport, CoreError>`

- [ ] **Step 1: Write failing test for core cleaner and verifier**

```rust
// crates/pfg-core/tests/cleaner_tests.rs
use std::fs;
use pfg_core::{clean_file, verify_files, CleanOptions};
use pfg_policy::CleanProfile;

#[test]
fn test_clean_file_atomic_and_verification() {
    let temp_dir = std::env::temp_dir().join("pfg_clean_tests");
    fs::create_dir_all(&temp_dir).unwrap();
    let test_file = temp_dir.join("photo.jpg");

    let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xFE, 0x00, 0x14];
    jpeg.extend_from_slice(b"Secret comment\0");
    jpeg.extend_from_slice(&[0xFF, 0xD9]);
    fs::write(&test_file, &jpeg).unwrap();

    let options = CleanOptions {
        profile: CleanProfile::Balanced,
        output_dir: None,
        safe_name: false,
        overwrite: false,
    };

    let report = clean_file(&test_file, &options).unwrap();
    assert!(report.verified_clean);
    assert_eq!(report.cleaned_findings_count, 0);

    let cleaned_file = temp_dir.join("photo.pfg.jpg");
    assert!(cleaned_file.exists());

    let v_report = verify_files(&test_file, &cleaned_file).unwrap();
    assert!(v_report.verified_clean);

    fs::remove_dir_all(&temp_dir).ok();
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test -p pfg-core`
Expected: FAIL due to missing `clean_file` & `verify_files`.

- [ ] **Step 3: Implement Cleaner and Verifier**

Create `crates/pfg-core/src/cleaner.rs`:
```rust
use std::fs;
use std::path::{Path, PathBuf};
use sha2::{Digest, Sha256};
use pfg_format-image::{detect_format, sanitize_image};
use pfg_model::ScanReport;
use pfg_policy::CleanProfile;
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
    let format = detect_format(&buffer).ok_or(CoreError::UnsupportedFormat)?;

    let original_scan = scan_file(path, &ScanOptions { include_values: true })?;
    let sanitized_bytes = sanitize_image(&buffer, format, options.profile)
        .map_err(|e| CoreError::ParseError(e.to_string()))?;

    // Determine target output filename
    let file_stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
    let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("jpg");

    let output_name = if options.safe_name {
        let mut hasher = Sha256::new();
        hasher.update(&sanitized_bytes);
        format!("{}.{}", &format!("{:x}", hasher.finalize())[..12], extension)
    } else {
        format!("{}.pfg.{}", file_stem, extension)
    };

    let target_dir = options.output_dir.clone().unwrap_or_else(|| path.parent().unwrap_or_else(|| Path::new(".")).to_pathBuf());
    let target_path = target_dir.join(output_name);
    let tmp_path = target_dir.join(format!(".pfg_{}.tmp", uuid::Uuid::new_v4()));

    // Write to atomic temp file
    fs::write(&tmp_path, &sanitized_bytes)?;

    // Rescan temporary output to verify clean status
    let cleaned_scan = scan_file(&tmp_path, &ScanOptions { include_values: true })?;
    let verified = cleaned_scan.findings.is_empty();

    if !verified {
        fs::remove_file(&tmp_path).ok();
        return Err(CoreError::ParseError("Post-clean verification failed: findings still present".to_string()));
    }

    // Atomic move to final target path
    fs::rename(&tmp_path, &target_path)?;

    Ok(VerificationReport {
        original_sha256: original_scan.input.sha256,
        cleaned_sha256: cleaned_scan.input.sha256,
        original_findings_count: original_scan.findings.len(),
        cleaned_findings_count: cleaned_scan.findings.len(),
        verified_clean: true,
        assurance_level: "Container Rebuilt".to_string(),
    })
}
```

Create `crates/pfg-core/src/verifier.rs`:
```rust
use std::path::Path;
use serde::{Deserialize, Serialize};
use crate::scanner::{scan_file, CoreError, ScanOptions};

#[derive(Debug, Clone, Serialize, Deserialize)]
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
        assurance_level: if verified { "Metadata Sanitized".to_string() } else { "Verification Failed".to_string() },
    })
}
```

Add `uuid = { version = "1.4", features = ["v4"] }` to `crates/pfg-core/Cargo.toml`.

Update `crates/pfg-core/src/lib.rs`:
```rust
#![forbid(unsafe_code)]

pub mod cleaner;
pub mod masking;
pub mod scanner;
pub mod verifier;

pub use cleaner::{clean_file, CleanOptions};
pub use scanner::{scan_file, CoreError, ScanOptions};
pub use verifier::{verify_files, VerificationReport};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p pfg-core`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/pfg-core
git commit -m "feat(core): implement clean_file pipeline and verify_files verifier"
```

---

### Task 5: CLI Commands `pfg clean` & `pfg verify` (`pfg-cli`)

**Files:**
- Modify: `privacy-file-guard-source/crates/pfg-cli/src/main.rs`
- Modify: `privacy-file-guard-source/crates/pfg-cli/tests/cli_tests.rs`

**Interfaces:**
- Consumes: `pfg_core::{clean_file, verify_files, CleanOptions}`
- Produces: CLI commands `pfg clean` and `pfg verify`

- [ ] **Step 1: Write failing integration test for `pfg clean` and `pfg verify`**

```rust
// In crates/pfg-cli/tests/cli_tests.rs
#[test]
fn test_cli_clean_and_verify() {
    let temp_dir = std::env::temp_dir().join("pfg_cli_clean_test");
    std::fs::create_dir_all(&temp_dir).unwrap();
    let sample = temp_dir.join("photo.jpg");
    std::fs::copy("fixtures/images/sample.jpg", &sample).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_pfg"))
        .arg("clean")
        .arg(&sample)
        .output()
        .unwrap();

    assert!(output.status.success());
    let cleaned = temp_dir.join("photo.pfg.jpg");
    assert!(cleaned.exists());

    let verify_output = Command::new(env!("CARGO_BIN_EXE_pfg"))
        .arg("verify")
        .arg(&sample)
        .arg(&cleaned)
        .output()
        .unwrap();

    assert!(verify_output.status.success());
    std::fs::remove_dir_all(&temp_dir).ok();
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test -p pfg-cli`
Expected: FAIL due to missing `clean` and `verify` subcommands.

- [ ] **Step 3: Implement `pfg clean` and `pfg verify` CLI handlers**

Update `crates/pfg-cli/src/main.rs`:
```rust
use std::fs;
use std::path::PathBuf;
use std::process;
use clap::{Parser, Subcommand, ValueEnum};
use pfg_core::{clean_file, scan_file, verify_files, CleanOptions, ScanOptions};
use pfg_model::Severity;
use pfg_policy::CleanProfile;

#[derive(Parser)]
#[command(name = "pfg", about = "Privacy File Guard - Local metadata scanner and cleaner")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a file for privacy-sensitive metadata
    Scan {
        path: PathBuf,
        #[arg(short, long, default_value = "text")]
        format: OutputFormat,
        #[arg(short, long)]
        report: Option<PathBuf>,
        #[arg(long)]
        fail_on: Option<SeverityArg>,
        #[arg(long)]
        include_values: bool,
    },
    /// Remove hidden metadata and create a sanitized output file
    Clean {
        path: PathBuf,
        #[arg(long, default_value = "balanced")]
        profile: ProfileArg,
        #[arg(short, long)]
        output_dir: Option<PathBuf>,
        #[arg(long)]
        safe_name: bool,
    },
    /// Verify that metadata has been removed from a sanitized file
    Verify {
        original: PathBuf,
        cleaned: PathBuf,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum ProfileArg {
    Balanced,
    Strict,
}

impl From<ProfileArg> for CleanProfile {
    fn from(arg: ProfileArg) -> Self {
        match arg {
            ProfileArg::Balanced => CleanProfile::Balanced,
            ProfileArg::Strict => CleanProfile::Strict,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum SeverityArg {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl From<SeverityArg> for Severity {
    fn from(arg: SeverityArg) -> Self {
        match arg {
            SeverityArg::Informational => Severity::Informational,
            SeverityArg::Low => Severity::Low,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::High => Severity::High,
            SeverityArg::Critical => Severity::Critical,
        }
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            format,
            report,
            fail_on,
            include_values,
        } => {
            let options = ScanOptions { include_values };
            match scan_file(&path, &options) {
                Ok(scan_report) => {
                    let json_output = serde_json::to_string_pretty(&scan_report).unwrap();

                    if let Some(ref report_path) = report {
                        if let Err(e) = fs::write(report_path, &json_output) {
                            eprintln!("Error writing report file: {}", e);
                            process::exit(4);
                        }
                    }

                    match format {
                        OutputFormat::Json => println!("{}", json_output),
                        OutputFormat::Text => {
                            println!("Privacy File Guard Scan Report");
                            println!("==============================");
                            println!("File: {}", scan_report.input.name);
                            println!("Format: {}", scan_report.detected_format);
                            println!("Size: {} bytes", scan_report.input.size);
                            println!("Findings: {}\n", scan_report.findings.len());

                            for finding in &scan_report.findings {
                                println!("[{:?}] {} (Source: {:?})", finding.severity, finding.key, finding.source);
                                if let Some(ref val) = finding.display_value {
                                    println!("  Value: {}", val);
                                }
                                println!("  Risk: {}", finding.risk_explanation);
                            }
                        }
                    }

                    if let Some(threshold) = fail_on {
                        let target_severity: Severity = threshold.into();
                        let max_found = scan_report.findings.iter().map(|f| f.severity).max();
                        if let Some(max) = max_found {
                            if max >= target_severity {
                                process::exit(1);
                            }
                        }
                    }

                    process::exit(0);
                }
                Err(e) => {
                    eprintln!("Scan error: {}", e);
                    process::exit(3);
                }
            }
        }
        Commands::Clean { path, profile, output_dir, safe_name } => {
            let options = CleanOptions {
                profile: profile.into(),
                output_dir,
                safe_name,
                overwrite: false,
            };

            match clean_file(&path, &options) {
                Ok(report) => {
                    println!("Sanitization Completed");
                    println!("======================");
                    println!("✓ Original file untouched");
                    println!("✓ Original findings removed: {}", report.original_findings_count);
                    println!("✓ Verified clean status: {}", report.verified_clean);
                    println!("✓ Assurance level: {}", report.assurance_level);
                    process::exit(0);
                }
                Err(e) => {
                    eprintln!("Sanitization failed: {}", e);
                    process::exit(5);
                }
            }
        }
        Commands::Verify { original, cleaned } => {
            match verify_files(&original, &cleaned) {
                Ok(report) => {
                    println!("Verification Report");
                    println!("===================");
                    println!("Original SHA256: {}", report.original_sha256);
                    println!("Cleaned SHA256:  {}", report.cleaned_sha256);
                    println!("Original Findings: {}", report.original_findings_count);
                    println!("Cleaned Findings:  {}", report.cleaned_findings_count);
                    println!("Verified Clean: {}", report.verified_clean);

                    if report.verified_clean {
                        process::exit(0);
                    } else {
                        process::exit(6);
                    }
                }
                Err(e) => {
                    eprintln!("Verification error: {}", e);
                    process::exit(6);
                }
            }
        }
    }
}
```

- [ ] **Step 4: Run tests across workspace**

Run: `cargo test --workspace`
Expected: PASS across all crates.

- [ ] **Step 5: Commit**

```bash
git add crates/pfg-cli
git commit -m "feat(cli): add pfg clean and pfg verify commands and integration tests"
```
