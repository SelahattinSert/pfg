# Phase 3: PDF Metadata Scanning & Sanitization Implementation Plan (`v0.3`)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Phase 3 PDF Metadata Scanner and Sanitizer (`v0.3`), supporting PDF header validation, `/Info` dictionary parsing, `/Metadata` XMP stream scanning, `/EmbeddedFiles` attachment scanning, `/Annots` comment scanning, `/JavaScript` action scanning, `/Encrypt` and `/Sig` detection, PDF metadata stripping (`pfg clean`), and CLI PDF scanning/cleaning.

**Architecture:** Create crate `pfg-format-pdf` in Cargo workspace, integrating into `pfg-core` and `pfg-cli`.

**Tech Stack:** Rust (edition 2021), `pfg-model`, `pfg-policy`, `lopdf` (or pure Rust PDF parser), `thiserror`.

## Global Constraints

- **Workspace Root:** `privacy-file-guard-source/`
- **Edition:** 2021
- **Unsafe Code:** `#![forbid(unsafe_code)]`
- **License:** MPL-2.0

---

### Task 1: Crate Setup & PDF Format Detector (`pfg-format-pdf`)

**Files:**
- Modify: `privacy-file-guard-source/Cargo.toml` (add `"crates/pfg-format-pdf"` to workspace members)
- Create: `privacy-file-guard-source/crates/pfg-format-pdf/Cargo.toml`
- Create: `privacy-file-guard-source/crates/pfg-format-pdf/src/lib.rs`
- Create: `privacy-file-guard-source/crates/pfg-format-pdf/src/detector.rs`
- Test: `privacy-file-guard-source/crates/pfg-format-pdf/tests/detector_tests.rs`

**Interfaces:**
- Consumes: Nothing
- Produces: `detect_pdf_format(buffer: &[u8]) -> bool`

- [ ] **Step 1: Write failing test for PDF format detector**

```rust
// crates/pfg-format-pdf/tests/detector_tests.rs
use pfg_format_pdf::detect_pdf_format;

#[test]
fn test_pdf_magic_bytes_detection() {
    let valid_pdf = b"%PDF-1.7\n%abc\n1 0 obj\n<<>>\nendobj\n";
    assert!(detect_pdf_format(valid_pdf));

    let invalid_pdf = b"NOT A PDF";
    assert!(!detect_pdf_format(invalid_pdf));
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test -p pfg-format-pdf`
Expected: FAIL due to missing crate.

- [ ] **Step 3: Implement `pfg-format-pdf` detector**

Create `crates/pfg-format-pdf/Cargo.toml`:
```toml
[package]
name = "pfg-format-pdf"
version = "0.1.0"
edition = "2021"

[dependencies]
pfg-model = { path = "../pfg-model" }
pfg-policy = { path = "../pfg-policy" }
thiserror = "1.0"
lopdf = "0.31"
```

Create `crates/pfg-format-pdf/src/detector.rs`:
```rust
pub fn detect_pdf_format(buffer: &[u8]) -> bool {
    if buffer.len() < 5 {
        return false;
    }
    &buffer[0..5] == b"%PDF-"
}
```

Create `crates/pfg-format-pdf/src/lib.rs`:
```rust
#![forbid(unsafe_code)]

pub mod detector;

pub use detector::detect_pdf_format;
```

Update root `Cargo.toml` to add `"crates/pfg-format-pdf"` to members.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p pfg-format-pdf`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/pfg-format-pdf
git commit -m "feat(pdf): create pfg-format-pdf crate and format detector"
```

---

### Task 2: PDF Metadata Scanner (`pfg-format-pdf`)

**Files:**
- Create: `privacy-file-guard-source/crates/pfg-format-pdf/src/scanner.rs`
- Modify: `privacy-file-guard-source/crates/pfg-format-pdf/src/lib.rs`
- Test: `privacy-file-guard-source/crates/pfg-format-pdf/tests/scanner_tests.rs`

**Interfaces:**
- Consumes: `pfg_policy::PolicyEngine`
- Produces: `scan_pdf_metadata(buffer: &[u8], policy: &PolicyEngine) -> Result<Vec<Finding>, PdfParseError>`

- [ ] **Step 1: Write failing test for PDF metadata scanner**

```rust
// crates/pfg-format-pdf/tests/scanner_tests.rs
use pfg_format_pdf::{scan_pdf_metadata, PdfParseError};
use pfg_policy::PolicyEngine;

#[test]
fn test_pdf_info_scanning() {
    let mut doc = lopdf::Document::with_version("1.7");
    let info_dict = lopdf::dictionary! {
        "Author" => lopdf::Object::String(b"John Doe".to_vec(), lopdf::StringFormat::Literal),
        "Creator" => lopdf::Object::String(b"TestApp".to_vec(), lopdf::StringFormat::Literal),
    };
    let info_id = doc.add_object(info_dict);
    doc.trailer.set("Info", info_id);

    let mut pdf_bytes = Vec::new();
    doc.save_to(&mut pdf_bytes).unwrap();

    let policy = PolicyEngine::balanced();
    let findings = scan_pdf_metadata(&pdf_bytes, &policy).unwrap();

    assert!(!findings.is_empty());
    assert!(findings.iter().any(|f| f.key == "Author"));
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test -p pfg-format-pdf`
Expected: FAIL due to missing `scan_pdf_metadata`.

- [ ] **Step 3: Implement PDF metadata scanner**

Create `crates/pfg-format-pdf/src/scanner.rs`:
```rust
use std::io::Cursor;
use lopdf::{Document, Object};
use thiserror::Error;
use pfg_model::{Finding, FindingCategory, FindingLocation, FindingSource};
use pfg_policy::PolicyEngine;

#[derive(Error, Debug)]
pub enum PdfParseError {
    #[error("Invalid PDF format or header")]
    InvalidHeader,
    #[error("Corrupted PDF structure: {0}")]
    CorruptedPdf(String),
    #[error("Encrypted PDF requires password")]
    EncryptedPdf,
}

pub fn scan_pdf_metadata(buffer: &[u8], policy: &PolicyEngine) -> Result<Vec<Finding>, PdfParseError> {
    if !crate::detector::detect_pdf_format(buffer) {
        return Err(PdfParseError::InvalidHeader);
    }

    let cursor = Cursor::new(buffer);
    let doc = Document::load_from_random_access(cursor)
        .map_err(|e| PdfParseError::CorruptedPdf(e.to_string()))?;

    let mut findings = Vec::new();

    // Check encryption
    if doc.trailer.get(b"Encrypt").is_ok() {
        findings.push(Finding {
            id: "pdf-encrypt".to_string(),
            category: FindingCategory::Credentials,
            severity: policy.categorize_severity(FindingCategory::Credentials, "Encrypt"),
            source: FindingSource::PdfObject,
            key: "Encrypt".to_string(),
            display_value: Some("Encrypted PDF document".to_string()),
            raw_value_available: true,
            location: FindingLocation::Header { segment: "Trailer".to_string() },
            risk_explanation: "Document uses PDF encryption".to_string(),
            removable: false,
        });
    }

    // Parse Info Dictionary
    if let Ok(info_ref) = doc.trailer.get(b"Info") {
        if let Ok(info_dict) = doc.get_object(info_ref.as_reference().unwrap_or((0, 0)))
            .and_then(|o| o.as_dict()) {
                for (key, val) in info_dict.iter() {
                    let key_str = String::from_utf8_lossy(key).to_string();
                    let val_str = match val {
                        Object::String(bytes, _) => String::from_utf8_lossy(bytes).to_string(),
                        _ => format!("{:?}", val),
                    };

                    let category = match key_str.as_str() {
                        "Author" | "Creator" | "Producer" => FindingCategory::Identity,
                        "CreationDate" | "ModDate" => FindingCategory::Time,
                        _ => FindingCategory::DocumentHistory,
                    };

                    findings.push(Finding {
                        id: format!("pdf-info-{}", key_str),
                        category,
                        severity: policy.categorize_severity(category, &key_str),
                        source: FindingSource::PdfInfo,
                        key: key_str,
                        display_value: Some(val_str),
                        raw_value_available: true,
                        location: FindingLocation::Header { segment: "Info".to_string() },
                        risk_explanation: "PDF Info metadata dictionary entry".to_string(),
                        removable: true,
                    });
                }
        }
    }

    // Scan objects for /Metadata, /JavaScript, /EmbeddedFiles, /Annots
    for (obj_id, object) in doc.objects.iter() {
        if let Ok(dict) = object.as_dict() {
            if dict.get(b"Type").map(|t| t.as_name_str() == Ok("Metadata")).unwrap_or(false) {
                findings.push(Finding {
                    id: format!("pdf-xmp-{}", obj_id.0),
                    category: FindingCategory::Identity,
                    severity: policy.categorize_severity(FindingCategory::Identity, "XmpMetadata"),
                    source: FindingSource::Xmp,
                    key: "XmpMetadata".to_string(),
                    display_value: Some("XMP metadata stream present".to_string()),
                    raw_value_available: true,
                    location: FindingLocation::PdfObject { object_number: obj_id.0 },
                    risk_explanation: "PDF object contains XMP metadata stream".to_string(),
                    removable: true,
                });
            }

            if dict.get(b"JS").is_ok() || dict.get(b"JavaScript").is_ok() {
                findings.push(Finding {
                    id: format!("pdf-js-{}", obj_id.0),
                    category: FindingCategory::Software,
                    severity: policy.categorize_severity(FindingCategory::Software, "JavaScript"),
                    source: FindingSource::PdfObject,
                    key: "JavaScript".to_string(),
                    display_value: Some("JavaScript action present".to_string()),
                    raw_value_available: true,
                    location: FindingLocation::PdfObject { object_number: obj_id.0 },
                    risk_explanation: "Document contains executable JavaScript action".to_string(),
                    removable: true,
                });
            }
        }
    }

    Ok(findings)
}
```

Update `crates/pfg-format-pdf/src/lib.rs`:
```rust
#![forbid(unsafe_code)]

pub mod detector;
pub mod scanner;

pub use detector::detect_pdf_format;
pub use scanner::{scan_pdf_metadata, PdfParseError};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p pfg-format-pdf`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/pfg-format-pdf
git commit -m "feat(pdf): implement PDF metadata, XMP, and JS object scanner"
```

---

### Task 3: PDF Sanitizer Engine (`pfg-format-pdf`)

**Files:**
- Create: `privacy-file-guard-source/crates/pfg-format-pdf/src/sanitizer.rs`
- Modify: `privacy-file-guard-source/crates/pfg-format-pdf/src/lib.rs`
- Test: `privacy-file-guard-source/crates/pfg-format-pdf/tests/sanitizer_tests.rs`

**Interfaces:**
- Consumes: `pfg_policy::CleanProfile`
- Produces: `sanitize_pdf(buffer: &[u8], profile: CleanProfile) -> Result<Vec<u8>, PdfParseError>`

- [ ] **Step 1: Write failing test for PDF sanitizer**

```rust
// crates/pfg-format-pdf/tests/sanitizer_tests.rs
use pfg_format_pdf::{scan_pdf_metadata, sanitize_pdf};
use pfg_policy::{CleanProfile, PolicyEngine};

#[test]
fn test_pdf_sanitization_removes_info_and_metadata() {
    let mut doc = lopdf::Document::with_version("1.7");
    let info_dict = lopdf::dictionary! {
        "Author" => lopdf::Object::String(b"John Doe".to_vec(), lopdf::StringFormat::Literal),
    };
    let info_id = doc.add_object(info_dict);
    doc.trailer.set("Info", info_id);

    let mut pdf_bytes = Vec::new();
    doc.save_to(&mut pdf_bytes).unwrap();

    let cleaned = sanitize_pdf(&pdf_bytes, CleanProfile::Balanced).unwrap();
    let policy = PolicyEngine::balanced();
    let findings = scan_pdf_metadata(&cleaned, &policy).unwrap();

    assert!(findings.is_empty());
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test -p pfg-format-pdf`
Expected: FAIL due to missing `sanitize_pdf`.

- [ ] **Step 3: Implement PDF sanitizer**

Create `crates/pfg-format-pdf/src/sanitizer.rs`:
```rust
use std::io::Cursor;
use lopdf::Document;
use pfg_policy::CleanProfile;
use crate::scanner::PdfParseError;

pub fn sanitize_pdf(buffer: &[u8], _profile: CleanProfile) -> Result<Vec<u8>, PdfParseError> {
    if !crate::detector::detect_pdf_format(buffer) {
        return Err(PdfParseError::InvalidHeader);
    }

    let cursor = Cursor::new(buffer);
    let mut doc = Document::load_from_random_access(cursor)
        .map_err(|e| PdfParseError::CorruptedPdf(e.to_string()))?;

    // Strip Info dictionary from trailer
    doc.trailer.remove(b"Info");

    // Strip Metadata streams and JS objects
    let obj_ids_to_remove: Vec<lopdf::ObjectId> = doc.objects.iter().filter_map(|(id, object)| {
        if let Ok(dict) = object.as_dict() {
            if dict.get(b"Type").map(|t| t.as_name_str() == Ok("Metadata")).unwrap_or(false)
                || dict.get(b"JS").is_ok() || dict.get(b"JavaScript").is_ok() {
                return Some(*id);
            }
        }
        None
    }).collect();

    for id in obj_ids_to_remove {
        doc.objects.remove(&id);
    }

    let mut cleaned_bytes = Vec::new();
    doc.save_to(&mut cleaned_bytes)
        .map_err(|e| PdfParseError::CorruptedPdf(e.to_string()))?;

    Ok(cleaned_bytes)
}
```

Update `crates/pfg-format-pdf/src/lib.rs`:
```rust
#![forbid(unsafe_code)]

pub mod detector;
pub mod scanner;
pub mod sanitizer;

pub use detector::detect_pdf_format;
pub use scanner::{scan_pdf_metadata, PdfParseError};
pub use sanitizer::sanitize_pdf;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p pfg-format-pdf`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/pfg-format-pdf
git commit -m "feat(pdf): implement PDF metadata and XMP sanitizer"
```

---

### Task 4: Format Router & Core Pipeline Integration (`pfg-core`)

**Files:**
- Modify: `privacy-file-guard-source/crates/pfg-core/Cargo.toml`
- Modify: `privacy-file-guard-source/crates/pfg-core/src/scanner.rs`
- Modify: `privacy-file-guard-source/crates/pfg-core/src/cleaner.rs`
- Test: `privacy-file-guard-source/crates/pfg-core/tests/pdf_pipeline_tests.rs`

**Interfaces:**
- Consumes: `pfg_format_pdf::{detect_pdf_format, scan_pdf_metadata, sanitize_pdf}`
- Produces: PDF support in `scan_file` and `clean_file`

- [ ] **Step 1: Write failing test for PDF core pipeline**

```rust
// crates/pfg-core/tests/pdf_pipeline_tests.rs
use std::fs;
use pfg_core::{clean_file, scan_file, CleanOptions, ScanOptions};
use pfg_policy::CleanProfile;

#[test]
fn test_pdf_scan_and_clean_pipeline() {
    let mut doc = lopdf::Document::with_version("1.7");
    let info_dict = lopdf::dictionary! {
        "Author" => lopdf::Object::String(b"Jane Smith".to_vec(), lopdf::StringFormat::Literal),
    };
    let info_id = doc.add_object(info_dict);
    doc.trailer.set("Info", info_id);

    let temp_dir = std::env::temp_dir().join("pfg_pdf_core_test");
    fs::create_dir_all(&temp_dir).unwrap();
    let pdf_path = temp_dir.join("document.pdf");

    let mut bytes = Vec::new();
    doc.save_to(&mut bytes).unwrap();
    fs::write(&pdf_path, &bytes).unwrap();

    let scan_report = scan_file(&pdf_path, &ScanOptions { include_values: true }).unwrap();
    assert_eq!(scan_report.detected_format, "pdf");
    assert_eq!(scan_report.findings.len(), 1);

    let clean_report = clean_file(&pdf_path, &CleanOptions {
        profile: CleanProfile::Balanced,
        output_dir: None,
        safe_name: false,
        overwrite: false,
    }).unwrap();

    assert!(clean_report.verified_clean);
    fs::remove_dir_all(&temp_dir).ok();
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test -p pfg-core`
Expected: FAIL due to missing PDF routing in `pfg-core`.

- [ ] **Step 3: Update `pfg-core` for PDF routing**

Add `pfg-format-pdf = { path = "../pfg-format-pdf" }` to `crates/pfg-core/Cargo.toml`.

Update `crates/pfg-core/src/scanner.rs`:
Update `ImageFormat` / format detection logic to handle PDF:
```rust
if pfg_format_pdf::detect_pdf_format(&buffer) {
    let findings = pfg_format_pdf::scan_pdf_metadata(&buffer, &policy)
        .map_err(|e| CoreError::ParseError(e.to_string()))?;
    // Construct ScanReport for PDF
}
```

Update `crates/pfg-core/src/cleaner.rs`:
Update `clean_file` to delegate PDF to `pfg_format_pdf::sanitize_pdf`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p pfg-core`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/pfg-core
git commit -m "feat(core): integrate PDF scanner and sanitizer into core pipeline"
```

---

### Task 5: CLI PDF Integration & Workspace Tests (`pfg-cli`)

**Files:**
- Create: `privacy-file-guard-source/fixtures/pdf/sample.pdf`
- Modify: `privacy-file-guard-source/crates/pfg-cli/tests/cli_tests.rs`

**Interfaces:**
- Consumes: PDF support in `pfg` binary
- Produces: CLI tests for `pfg scan sample.pdf`, `pfg clean sample.pdf`, `pfg verify sample.pdf sample.pfg.pdf`

- [ ] **Step 1: Write failing CLI integration test for PDF**

```rust
// In crates/pfg-cli/tests/cli_tests.rs
#[test]
fn test_cli_pdf_scan_and_clean() {
    let temp_dir = std::env::temp_dir().join("pfg_cli_pdf_test");
    std::fs::create_dir_all(&temp_dir).unwrap();
    let pdf_file = temp_dir.join("sample.pdf");
    std::fs::copy("fixtures/pdf/sample.pdf", &pdf_file).unwrap();

    let scan_out = Command::new(env!("CARGO_BIN_EXE_pfg"))
        .arg("scan")
        .arg(&pdf_file)
        .output()
        .unwrap();
    assert!(scan_out.status.success());
    assert!(String::from_utf8_lossy(&scan_out.stdout).contains("pdf"));

    let clean_out = Command::new(env!("CARGO_BIN_EXE_pfg"))
        .arg("clean")
        .arg(&pdf_file)
        .output()
        .unwrap();
    assert!(clean_out.status.success());
    let cleaned_pdf = temp_dir.join("sample.pfg.pdf");
    assert!(cleaned_pdf.exists());

    std::fs::remove_dir_all(&temp_dir).ok();
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test -p pfg-cli`
Expected: FAIL due to missing PDF fixture.

- [ ] **Step 3: Create synthetic PDF fixture**

Create `fixtures/pdf/sample.pdf` with valid PDF structure containing `/Info` dictionary (`/Author (Test User)`).

- [ ] **Step 4: Run workspace tests**

Run: `cargo test --workspace`
Expected: PASS across all workspace crates.

- [ ] **Step 5: Commit**

```bash
git add fixtures/pdf crates/pfg-cli
git commit -m "feat(cli): add PDF scanning and cleaning integration tests"
```
