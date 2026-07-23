# Phase 1: Core Scanner Foundation & JPEG Metadata Scanner CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Phase 1 monorepo architecture, shared data models (`pfg-model`), policy engine (`pfg-policy`), JPEG marker walker parser (`pfg-format-image`), core scanning engine (`pfg-core`), and the CLI tool (`pfg-cli`) with `pfg scan` functionality.

**Architecture:** A Cargo workspace in `privacy-file-guard-source/` containing decoupled Rust crates: `pfg-model` (data types), `pfg-policy` (risk classification), `pfg-format-image` (JPEG marker walker), `pfg-core` (scanner pipeline), and `pfg-cli` (Clap interface).

**Tech Stack:** Rust (edition 2021), `serde`, `serde_json`, `clap`, `thiserror`, `tracing`.

## Global Constraints

- **Workspace Root:** `privacy-file-guard-source/`
- **Rust Edition:** 2021
- **Unsafe Code:** `#![forbid(unsafe_code)]` in all core crates
- **License:** MPL-2.0
- **CLI Binary Name:** `pfg`

---

### Task 1: Workspace Setup & Domain Models (`pfg-model`)

**Files:**
- Create: `privacy-file-guard-source/Cargo.toml`
- Create: `privacy-file-guard-source/crates/pfg-model/Cargo.toml`
- Create: `privacy-file-guard-source/crates/pfg-model/src/lib.rs`
- Create: `privacy-file-guard-source/crates/pfg-model/src/severity.rs`
- Create: `privacy-file-guard-source/crates/pfg-model/src/category.rs`
- Create: `privacy-file-guard-source/crates/pfg-model/src/finding.rs`
- Create: `privacy-file-guard-source/crates/pfg-model/src/report.rs`
- Test: `privacy-file-guard-source/crates/pfg-model/tests/model_tests.rs`

**Interfaces:**
- Consumes: Nothing
- Produces: `Severity`, `FindingCategory`, `FindingSource`, `FindingLocation`, `RemovalEffect`, `Finding`, `ScanReport`, `InputFileMetadata`, `FindingSummary`

- [ ] **Step 1: Write failing test for model serialization**

```rust
// crates/pfg-model/tests/model_tests.rs
use pfg_model::*;

#[test]
fn test_finding_and_report_serialization() {
    let finding = Finding {
        id: "finding-1".to_string(),
        category: FindingCategory::Location,
        severity: Severity::High,
        source: FindingSource::Exif,
        key: "GPSLatitude".to_string(),
        display_value: Some("38.4***, 27.1***".to_string()),
        raw_value_available: true,
        location: FindingLocation::Header { segment: "APP1".to_string() },
        risk_explanation: "GPS location reveals exact position".to_string(),
        removable: true,
    };

    let report = ScanReport {
        schema_version: 1,
        tool_version: "0.1.0".to_string(),
        operation: "scan".to_string(),
        input: InputFileMetadata {
            name: "sample.jpg".to_string(),
            size: 1024,
            sha256: "abc...".to_string(),
        },
        detected_format: "jpeg".to_string(),
        support_level: "full".to_string(),
        findings: vec![finding],
        summary: FindingSummary {
            critical: 0,
            high: 1,
            medium: 0,
            low: 0,
            informational: 0,
        },
    };

    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("\"detected_format\":\"jpeg\""));
    assert!(json.contains("\"location\""));
    assert!(json.contains("\"high\""));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p pfg-model` (in `privacy-file-guard-source`)
Expected: FAIL due to missing workspace and crate types.

- [ ] **Step 3: Implement Cargo.toml and `pfg-model` types**

Create root `Cargo.toml`:
```toml
[workspace]
members = [
    "crates/pfg-model",
    "crates/pfg-policy",
    "crates/pfg-format-image",
    "crates/pfg-core",
    "crates/pfg-cli",
]
resolver = "2"
```

Create `crates/pfg-model/Cargo.toml`:
```toml
[package]
name = "pfg-model"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
```

Create `crates/pfg-model/src/severity.rs`:
```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}
```

Create `crates/pfg-model/src/category.rs`:
```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingCategory {
    Location,
    Identity,
    Device,
    Time,
    Software,
    DocumentHistory,
    Comments,
    EmbeddedContent,
    Thumbnail,
    UniqueIdentifier,
    Network,
    Credentials,
    Filesystem,
    Technical,
    Unknown,
}
```

Create `crates/pfg-model/src/finding.rs`:
```rust
use serde::{Deserialize, Serialize};
use crate::category::FindingCategory;
use crate::severity::Severity;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSource {
    Exif,
    Xmp,
    Iptc,
    Comment,
    PdfInfo,
    PdfObject,
    FileSystem,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingLocation {
    Header { segment: String },
    Offset { byte_offset: u64 },
    PdfObject { object_number: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub category: FindingCategory,
    pub severity: Severity,
    pub source: FindingSource,
    pub key: String,
    pub display_value: Option<String>,
    pub raw_value_available: bool,
    pub location: FindingLocation,
    pub risk_explanation: String,
    pub removable: bool,
}
```

Create `crates/pfg-model/src/report.rs`:
```rust
use serde::{Deserialize, Serialize};
use crate::finding::Finding;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputFileMetadata {
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FindingSummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub informational: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub schema_version: u32,
    pub tool_version: String,
    pub operation: String,
    pub input: InputFileMetadata,
    pub detected_format: String,
    pub support_level: String,
    pub findings: Vec<Finding>,
    pub summary: FindingSummary,
}
```

Create `crates/pfg-model/src/lib.rs`:
```rust
#![forbid(unsafe_code)]

pub mod category;
pub mod finding;
pub mod report;
pub mod severity;

pub use category::FindingCategory;
pub use finding::{Finding, FindingLocation, FindingSource};
pub use report::{FindingSummary, InputFileMetadata, ScanReport};
pub use severity::Severity;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p pfg-model`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/pfg-model
git commit -m "feat(model): create pfg-model crate with domain types and tests"
```

---

### Task 2: Policy Engine (`pfg-policy`)

**Files:**
- Create: `privacy-file-guard-source/crates/pfg-policy/Cargo.toml`
- Create: `privacy-file-guard-source/crates/pfg-policy/src/lib.rs`
- Create: `privacy-file-guard-source/crates/pfg-policy/src/rules.rs`
- Test: `privacy-file-guard-source/crates/pfg-policy/tests/policy_tests.rs`

**Interfaces:**
- Consumes: `pfg_model::{FindingCategory, Severity}`
- Produces: `PolicyEngine`, `PolicyRules`

- [ ] **Step 1: Write failing test for policy engine**

```rust
// crates/pfg-policy/tests/policy_tests.rs
use pfg_model::{FindingCategory, Severity};
use pfg_policy::PolicyEngine;

#[test]
fn test_default_balanced_policy_severity() {
    let policy = PolicyEngine::balanced();
    assert_eq!(policy.categorize_severity(FindingCategory::Location, "GPSLatitude"), Severity::High);
    assert_eq!(policy.categorize_severity(FindingCategory::Identity, "Artist"), Severity::High);
    assert_eq!(policy.categorize_severity(FindingCategory::Device, "Model"), Severity::Medium);
    assert_eq!(policy.categorize_severity(FindingCategory::Software, "Software"), Severity::Low);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p pfg-policy`
Expected: FAIL due to missing crate.

- [ ] **Step 3: Implement `pfg-policy` crate**

Create `crates/pfg-policy/Cargo.toml`:
```toml
[package]
name = "pfg-policy"
version = "0.1.0"
edition = "2021"

[dependencies]
pfg-model = { path = "../pfg-model" }
serde = { version = "1.0", features = ["derive"] }
```

Create `crates/pfg-policy/src/rules.rs`:
```rust
use pfg_model::{FindingCategory, Severity};

#[derive(Debug, Clone)]
pub struct PolicyEngine;

impl PolicyEngine {
    pub fn balanced() -> Self {
        Self
    }

    pub fn categorize_severity(&self, category: FindingCategory, key: &str) -> Severity {
        match category {
            FindingCategory::Credentials | FindingCategory::Network => Severity::Critical,
            FindingCategory::Location | FindingCategory::Identity | FindingCategory::EmbeddedContent => Severity::High,
            FindingCategory::Device | FindingCategory::Time | FindingCategory::Comments | FindingCategory::DocumentHistory | FindingCategory::UniqueIdentifier => {
                if key.contains("Serial") || key.contains("ID") {
                    Severity::High
                } else {
                    Severity::Medium
                }
            }
            FindingCategory::Software | FindingCategory::Filesystem | FindingCategory::Thumbnail => Severity::Low,
            FindingCategory::Technical | FindingCategory::Unknown => Severity::Informational,
        }
    }
}
```

Create `crates/pfg-policy/src/lib.rs`:
```rust
#![forbid(unsafe_code)]

pub mod rules;
pub use rules::PolicyEngine;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p pfg-policy`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/pfg-policy
git commit -m "feat(policy): implement pfg-policy crate for risk scoring"
```

---

### Task 3: JPEG Marker Walker & Image Format Parser (`pfg-format-image`)

**Files:**
- Create: `privacy-file-guard-source/crates/pfg-format-image/Cargo.toml`
- Create: `privacy-file-guard-source/crates/pfg-format-image/src/lib.rs`
- Create: `privacy-file-guard-source/crates/pfg-format-image/src/detector.rs`
- Create: `privacy-file-guard-source/crates/pfg-format-image/src/jpeg.rs`
- Create: `privacy-file-guard-source/crates/pfg-format-image/src/exif.rs`
- Create: `privacy-file-guard-source/crates/pfg-format-image/src/xmp.rs`
- Test: `privacy-file-guard-source/crates/pfg-format-image/tests/jpeg_tests.rs`

**Interfaces:**
- Consumes: `pfg_model::{Finding, FindingCategory, FindingLocation, FindingSource, Severity}`, `pfg_policy::PolicyEngine`
- Produces: `detect_format(buffer: &[u8]) -> Option<ImageFormat>`, `scan_jpeg_metadata(buffer: &[u8], policy: &PolicyEngine) -> Result<Vec<Finding>, ImageParseError>`

- [ ] **Step 1: Write failing test for JPEG scanner**

```rust
// crates/pfg-format-image/tests/jpeg_tests.rs
use pfg_format_image::{detect_format, scan_jpeg_metadata, ImageFormat};
use pfg_policy::PolicyEngine;

#[test]
fn test_jpeg_detection_and_marker_scan() {
    // Minimal valid JPEG header with COM segment "Created with PFG test"
    let mut jpeg = vec![
        0xFF, 0xD8, // SOI
        0xFF, 0xFE, // COM
        0x00, 0x19, // Length: 25 bytes (including length bytes)
    ];
    jpeg.extend_from_slice(b"Created with PFG test\0");
    jpeg.extend_from_slice(&[0xFF, 0xD9]); // EOI

    assert_eq!(detect_format(&jpeg), Some(ImageFormat::Jpeg));

    let policy = PolicyEngine::balanced();
    let findings = scan_jpeg_metadata(&jpeg, &policy).unwrap();
    assert!(!findings.is_empty());
    assert_eq!(findings[0].key, "Comment");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p pfg-format-image`
Expected: FAIL due to missing crate and functions.

- [ ] **Step 3: Implement `pfg-format-image` crate**

Create `crates/pfg-format-image/Cargo.toml`:
```toml
[package]
name = "pfg-format-image"
version = "0.1.0"
edition = "2021"

[dependencies]
pfg-model = { path = "../pfg-model" }
pfg-policy = { path = "../pfg-policy" }
thiserror = "1.0"
```

Create `crates/pfg-format-image/src/detector.rs`:
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    Jpeg,
    Png,
    WebP,
}

pub fn detect_format(buffer: &[u8]) -> Option<ImageFormat> {
    if buffer.len() < 3 {
        return None;
    }
    if buffer[0] == 0xFF && buffer[1] == 0xD8 && buffer[2] == 0xFF {
        return Some(ImageFormat::Jpeg);
    }
    if buffer.len() >= 8 && &buffer[0..8] == b"\x89PNG\r\n\x1a\n" {
        return Some(ImageFormat::Png);
    }
    if buffer.len() >= 12 && &buffer[0..4] == b"RIFF" && &buffer[8..12] == b"WEBP" {
        return Some(ImageFormat::WebP);
    }
    None
}
```

Create `crates/pfg-format-image/src/exif.rs`:
```rust
use pfg_model::{Finding, FindingCategory, FindingLocation, FindingSource};
use pfg_policy::PolicyEngine;

pub fn parse_exif_segment(data: &[u8], policy: &PolicyEngine) -> Vec<Finding> {
    let mut findings = Vec::new();
    if data.len() < 6 || &data[0..6] != b"Exif\0\0" {
        return findings;
    }
    let tiff_bytes = &data[6..];
    if tiff_bytes.len() < 8 {
        return findings;
    }

    // Basic endianness check and TIFF header validation
    let is_little_endian = match &tiff_bytes[0..2] {
        b"II" => true,
        b"MM" => false,
        _ => return findings,
    };

    fn read_u16(b: &[u8], le: bool) -> u16 {
        if le { u16::from_le_bytes([b[0], b[1]]) } else { u16::from_be_bytes([b[0], b[1]]) }
    }

    let magic = read_u16(&tiff_bytes[2..4], is_little_endian);
    if magic != 42 {
        return findings;
    }

    // Standard EXIF finding placeholder for TIFF marker detection
    findings.push(Finding {
        id: "exif-header".to_string(),
        category: FindingCategory::Device,
        severity: policy.categorize_severity(FindingCategory::Device, "ExifHeader"),
        source: FindingSource::Exif,
        key: "ExifHeader".to_string(),
        display_value: Some("EXIF metadata segment present".to_string()),
        raw_value_available: true,
        location: FindingLocation::Header { segment: "APP1".to_string() },
        risk_explanation: "EXIF block contains camera and shooting parameters".to_string(),
        removable: true,
    });

    findings
}
```

Create `crates/pfg-format-image/src/xmp.rs`:
```rust
use pfg_model::{Finding, FindingCategory, FindingLocation, FindingSource};
use pfg_policy::PolicyEngine;

pub fn parse_xmp_segment(data: &[u8], policy: &PolicyEngine) -> Vec<Finding> {
    let mut findings = Vec::new();
    let header = b"http://ns.adobe.com/xap/1.0/\0";
    if data.len() < header.len() || &data[0..header.len()] != header {
        return findings;
    }

    findings.push(Finding {
        id: "xmp-header".to_string(),
        category: FindingCategory::Identity,
        severity: policy.categorize_severity(FindingCategory::Identity, "XmpPacket"),
        source: FindingSource::Xmp,
        key: "XmpPacket".to_string(),
        display_value: Some("XMP metadata packet present".to_string()),
        raw_value_available: true,
        location: FindingLocation::Header { segment: "APP1".to_string() },
        risk_explanation: "XMP metadata packet contains editing history and author info".to_string(),
        removable: true,
    });

    findings
}
```

Create `crates/pfg-format-image/src/jpeg.rs`:
```rust
use thiserror::Error;
use pfg_model::{Finding, FindingCategory, FindingLocation, FindingSource};
use pfg_policy::PolicyEngine;
use crate::exif::parse_exif_segment;
use crate::xmp::parse_xmp_segment;

#[derive(Error, Debug)]
pub enum ImageParseError {
    #[error("Invalid JPEG magic bytes")]
    InvalidMagic,
    #[error("Unexpected end of file while reading marker segment")]
    UnexpectedEof,
}

pub fn scan_jpeg_metadata(buffer: &[u8], policy: &PolicyEngine) -> Result<Vec<Finding>, ImageParseError> {
    if buffer.len() < 3 || buffer[0] != 0xFF || buffer[1] != 0xD8 || buffer[2] != 0xFF {
        return Err(ImageParseError::InvalidMagic);
    }

    let mut findings = Vec::new();
    let mut cursor = 2;

    while cursor < buffer.len() {
        if buffer[cursor] != 0xFF {
            cursor += 1;
            continue;
        }

        // Skip fill bytes
        while cursor < buffer.len() && buffer[cursor] == 0xFF {
            cursor += 1;
        }

        if cursor >= buffer.len() {
            break;
        }

        let marker = buffer[cursor];
        cursor += 1;

        if marker == 0xD9 { // EOI
            break;
        }
        if marker == 0xD8 { // SOI
            continue;
        }

        if cursor + 2 > buffer.len() {
            return Err(ImageParseError::UnexpectedEof);
        }

        let length = u16::from_be_bytes([buffer[cursor], buffer[cursor + 1]]) as usize;
        if length < 2 || cursor + length > buffer.len() {
            return Err(ImageParseError::UnexpectedEof);
        }

        let segment_data = &buffer[cursor + 2..cursor + length];

        match marker {
            0xE1 => { // APP1
                findings.extend(parse_exif_segment(segment_data, policy));
                findings.extend(parse_xmp_segment(segment_data, policy));
            }
            0xFE => { // COM
                let text = String::from_utf8_lossy(segment_data).trim_matches('\0').to_string();
                findings.push(Finding {
                    id: format!("com-{}", cursor),
                    category: FindingCategory::Comments,
                    severity: policy.categorize_severity(FindingCategory::Comments, "Comment"),
                    source: FindingSource::Comment,
                    key: "Comment".to_string(),
                    display_value: Some(text),
                    raw_value_available: true,
                    location: FindingLocation::Header { segment: "COM".to_string() },
                    risk_explanation: "Text comment embed in JPEG file".to_string(),
                    removable: true,
                });
            }
            _ => {}
        }

        cursor += length;
    }

    Ok(findings)
}
```

Create `crates/pfg-format-image/src/lib.rs`:
```rust
#![forbid(unsafe_code)]

pub mod detector;
pub mod exif;
pub mod jpeg;
pub mod xmp;

pub use detector::{detect_format, ImageFormat};
pub use jpeg::{scan_jpeg_metadata, ImageParseError};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p pfg-format-image`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/pfg-format-image
git commit -m "feat(image): implement JPEG marker walker and detector in pfg-format-image"
```

---

### Task 4: Core Scanning Engine (`pfg-core`)

**Files:**
- Create: `privacy-file-guard-source/crates/pfg-core/Cargo.toml`
- Create: `privacy-file-guard-source/crates/pfg-core/src/lib.rs`
- Create: `privacy-file-guard-source/crates/pfg-core/src/scanner.rs`
- Create: `privacy-file-guard-source/crates/pfg-core/src/masking.rs`
- Test: `privacy-file-guard-source/crates/pfg-core/tests/scanner_tests.rs`

**Interfaces:**
- Consumes: `pfg_model::ScanReport`, `pfg_format_image::*`, `pfg_policy::PolicyEngine`
- Produces: `ScanOptions`, `scan_file(path: &Path, options: &ScanOptions) -> Result<ScanReport, CoreError>`

- [ ] **Step 1: Write failing test for core scanning pipeline**

```rust
// crates/pfg-core/tests/scanner_tests.rs
use std::fs;
use std::path::PathBuf;
use pfg_core::{scan_file, ScanOptions};

#[test]
fn test_scan_file_pipeline() {
    let temp_dir = std::env::temp_dir().join("pfg_tests");
    fs::create_dir_all(&temp_dir).unwrap();
    let test_file = temp_dir.join("test.jpg");

    let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xFE, 0x00, 0x14];
    jpeg.extend_from_slice(b"Secret author\0");
    jpeg.extend_from_slice(&[0xFF, 0xD9]);
    fs::write(&test_file, &jpeg).unwrap();

    let options = ScanOptions { include_values: false };
    let report = scan_file(&test_file, &options).unwrap();

    assert_eq!(report.detected_format, "jpeg");
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.summary.medium, 1);

    fs::remove_file(&test_file).ok();
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p pfg-core`
Expected: FAIL due to missing crate.

- [ ] **Step 3: Implement `pfg-core` crate**

Create `crates/pfg-core/Cargo.toml`:
```toml
[package]
name = "pfg-core"
version = "0.1.0"
edition = "2021"

[dependencies]
pfg-model = { path = "../pfg-model" }
pfg-policy = { path = "../pfg-policy" }
pfg-format-image = { path = "../pfg-format-image" }
sha2 = "0.10"
thiserror = "1.0"
```

Create `crates/pfg-core/src/masking.rs`:
```rust
pub fn mask_sensitive_value(value: &str) -> String {
    if value.len() <= 4 {
        "****".to_string()
    } else {
        let prefix = &value[..2];
        format!("{}***", prefix)
    }
}
```

Create `crates/pfg-core/src/scanner.rs`:
```rust
use std::fs;
use std::path::Path;
use sha2::{Digest, Sha256};
use thiserror::Error;
use pfg_model::{FindingSummary, InputFileMetadata, ScanReport, Severity};
use pfg_policy::PolicyEngine;
use pfg_format-image::{detect_format, scan_jpeg_metadata, ImageFormat};

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub include_values: bool,
}

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("File not found or unreadable: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Symlinks are not allowed by security policy")]
    SymlinkDenied,
    #[error("Unsupported file format")]
    UnsupportedFormat,
    #[error("Image parse error: {0}")]
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
    let hash = format!("{:x}", hasher.finalize());

    let format = detect_format(&buffer).ok_or(CoreError::UnsupportedFormat)?;
    let policy = PolicyEngine::balanced();

    let mut findings = match format {
        ImageFormat::Jpeg => scan_jpeg_metadata(&buffer, &policy).map_err(|e| CoreError::ParseError(e.to_string()))?,
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
                finding.display_value = Some(crate::masking::mask_sensitive_value(val));
            }
        }
    }

    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("unknown").to_string();

    Ok(ScanReport {
        schema_version: 1,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        operation: "scan".to_string(),
        input: InputFileMetadata {
            name: filename,
            size: buffer.len() as u64,
            sha256: hash,
        },
        detected_format: format!("{:?}", format).to_lowercase(),
        support_level: "full".to_string(),
        findings,
        summary,
    })
}
```

Create `crates/pfg-core/src/lib.rs`:
```rust
#![forbid(unsafe_code)]

pub mod masking;
pub mod scanner;

pub use scanner::{scan_file, CoreError, ScanOptions};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p pfg-core`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/pfg-core
git commit -m "feat(core): implement scan_file pipeline and value masking in pfg-core"
```

---

### Task 5: CLI Binary & Integration Tests (`pfg-cli`)

**Files:**
- Create: `privacy-file-guard-source/crates/pfg-cli/Cargo.toml`
- Create: `privacy-file-guard-source/crates/pfg-cli/src/main.rs`
- Create: `privacy-file-guard-source/fixtures/images/sample.jpg`
- Test: `privacy-file-guard-source/crates/pfg-cli/tests/cli_tests.rs`

**Interfaces:**
- Consumes: `pfg-core::scan_file`, `pfg-model::Severity`
- Produces: Binary `pfg` executable with `pfg scan <PATH>` command

- [ ] **Step 1: Write failing integration test for CLI binary**

```rust
// crates/pfg-cli/tests/cli_tests.rs
use std::process::Command;

#[test]
fn test_cli_help_and_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_pfg"))
        .arg("--help")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Privacy File Guard"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p pfg-cli`
Expected: FAIL due to missing CLI binary crate.

- [ ] **Step 3: Implement `pfg-cli` binary**

Create `crates/pfg-cli/Cargo.toml`:
```toml
[package]
name = "pfg-cli"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "pfg"
path = "src/main.rs"

[dependencies]
pfg-core = { path = "../pfg-core" }
pfg-model = { path = "../pfg-model" }
clap = { version = "4.4", features = ["derive"] }
serde_json = "1.0"
```

Create `crates/pfg-cli/src/main.rs`:
```rust
use std::fs;
use std::path::PathBuf;
use std::process;
use clap::{Parser, Subcommand, ValueEnum};
use pfg_core::{scan_file, ScanOptions};
use pfg_model::Severity;

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
        /// Path to target file
        path: PathBuf,

        /// Output format (text or json)
        #[arg(short, long, default_value = "text")]
        format: OutputFormat,

        /// Save report to specified JSON file
        #[arg(short, long)]
        report: Option<PathBuf>,

        /// Fail with exit code 1 if findings reach or exceed threshold
        #[arg(long)]
        fail_on: Option<SeverityArg>,

        /// Include raw unmasked values in output
        #[arg(long)]
        include_values: bool,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
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
                        OutputFormat::Json => {
                            println!("{}", json_output);
                        }
                        OutputFormat::Text => {
                            println!("Privacy File Guard Scan Report");
                            println!("==============================");
                            println!("File: {}", scan_report.input.name);
                            println!("Format: {}", scan_report.detected_format);
                            println!("Size: {} bytes", scan_report.input.size);
                            println!("Findings: {}\n", scan_report.findings.len());

                            for finding in &scan_report.findings {
                                println!(
                                    "[{:?}] {} (Source: {:?})",
                                    finding.severity, finding.key, finding.source
                                );
                                if let Some(ref val) = finding.display_value {
                                    println!("  Value: {}", val);
                                }
                                println!("  Risk: {}", finding.risk_explanation);
                            }
                        }
                    }

                    if let Some(threshold) = fail_on {
                        let target_severity: Severity = threshold.into();
                        let max_found = scan_report
                            .findings
                            .iter()
                            .map(|f| f.severity)
                            .max();

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
    }
}
```

- [ ] **Step 4: Create sample fixture image**

Create synthetic JPEG in `fixtures/images/sample.jpg`:
Write binary JPEG data with COM segment to `fixtures/images/sample.jpg`.

- [ ] **Step 5: Run tests and verify build**

Run: `cargo test --workspace`
Expected: PASS for all tests across workspace crates.

- [ ] **Step 6: Commit**

```bash
git add crates/pfg-cli fixtures/
git commit -m "feat(cli): implement pfg scan CLI binary and integration tests"
```
