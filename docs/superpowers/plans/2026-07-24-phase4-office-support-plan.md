# Phase 4: Office Documents Support Implementation Plan (`v0.4`)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Phase 4 Office Open XML (DOCX, XLSX, PPTX) Metadata Scanner and Sanitizer (`v0.4`), supporting ZIP container format detection, `docProps/core.xml` property scanning, `docProps/app.xml` scanning, `docProps/custom.xml` scanning, comments scanning, VBA macro (`vbaProject.bin`) detection, thumbnail removal, metadata clearing (`pfg clean`), and CLI integration.

**Architecture:** Create crate `pfg-format-office` in Cargo workspace, integrating into `pfg-core` and `pfg-cli`.

**Tech Stack:** Rust (edition 2021), `pfg-model`, `pfg-policy`, `zip`, `quick-xml` or regex XML parsing, `thiserror`.

## Global Constraints

- **Workspace Root:** `privacy-file-guard-source/`
- **Edition:** 2021
- **Unsafe Code:** `#![forbid(unsafe_code)]`
- **License:** MPL-2.0

---

### Task 1: Crate Setup & Office Container Detector (`pfg-format-office`)

**Files:**
- Modify: `privacy-file-guard-source/Cargo.toml` (add `"crates/pfg-format-office"` to workspace members)
- Create: `privacy-file-guard-source/crates/pfg-format-office/Cargo.toml`
- Create: `privacy-file-guard-source/crates/pfg-format-office/src/lib.rs`
- Create: `privacy-file-guard-source/crates/pfg-format-office/src/detector.rs`
- Test: `privacy-file-guard-source/crates/pfg-format-office/tests/detector_tests.rs`

**Interfaces:**
- Consumes: Nothing
- Produces: `detect_office_format(buffer: &[u8]) -> Option<OfficeFormat>` (Docx, Xlsx, Pptx)

- [ ] **Step 1: Write failing test for Office format detector**

```rust
// crates/pfg-format-office/tests/detector_tests.rs
use pfg_format_office::{detect_office_format, OfficeFormat};

#[test]
fn test_office_format_detection() {
    let mut zip_bytes = Vec::new();
    {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut zip_bytes));
        zip.start_file("[Content_Types].xml", zip::write::SimpleFileOptions::default()).unwrap();
        use std::io::Write;
        zip.write_all(b"<Types></Types>").unwrap();
        zip.start_file("word/document.xml", zip::write::SimpleFileOptions::default()).unwrap();
        zip.write_all(b"<w:document></w:document>").unwrap();
        zip.finish().unwrap();
    }

    assert_eq!(detect_office_format(&zip_bytes), Some(OfficeFormat::Docx));
    assert_eq!(detect_office_format(b"NOT A ZIP"), None);
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test -p pfg-format-office`
Expected: FAIL due to missing crate.

- [ ] **Step 3: Implement `pfg-format-office` detector**

Create `crates/pfg-format-office/Cargo.toml`:
```toml
[package]
name = "pfg-format-office"
version = "0.1.0"
edition = "2021"

[dependencies]
pfg-model = { path = "../pfg-model" }
pfg-policy = { path = "../pfg-policy" }
thiserror = "1.0"
zip = { version = "2.1", default-features = false, features = ["deflate"] }
serde = { version = "1.0", features = ["derive"] }
```

Create `crates/pfg-format-office/src/detector.rs`:
```rust
use std::io::Cursor;
use zip::ZipArchive;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfficeFormat {
    Docx,
    Xlsx,
    Pptx,
}

pub fn detect_office_format(buffer: &[u8]) -> Option<OfficeFormat> {
    if buffer.len() < 4 || &buffer[0..4] != b"PK\x03\x04" {
        return None;
    }

    let cursor = Cursor::new(buffer);
    let mut archive = ZipArchive::new(cursor).ok()?;

    if archive.by_name("[Content_Types].xml").is_err() {
        return None;
    }

    if archive.by_name("word/document.xml").is_ok() {
        Some(OfficeFormat::Docx)
    } else if archive.by_name("xl/workbook.xml").is_ok() {
        Some(OfficeFormat::Xlsx)
    } else if archive.by_name("ppt/presentation.xml").is_ok() {
        Some(OfficeFormat::Pptx)
    } else {
        None
    }
}
```

Create `crates/pfg-format-office/src/lib.rs`:
```rust
#![forbid(unsafe_code)]

pub mod detector;

pub use detector::{detect_office_format, OfficeFormat};
```

Update root `Cargo.toml` to add `"crates/pfg-format-office"` to members.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p pfg-format-office`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/pfg-format-office
git commit -m "feat(office): create pfg-format-office crate and format detector"
```

---

### Task 2: Office Metadata & Structure Scanner (`pfg-format-office`)

**Files:**
- Create: `privacy-file-guard-source/crates/pfg-format-office/src/scanner.rs`
- Modify: `privacy-file-guard-source/crates/pfg-format-office/src/lib.rs`
- Test: `privacy-file-guard-source/crates/pfg-format-office/tests/scanner_tests.rs`

**Interfaces:**
- Consumes: `pfg_policy::PolicyEngine`
- Produces: `scan_office_metadata(buffer: &[u8], policy: &PolicyEngine) -> Result<Vec<Finding>, OfficeParseError>`

- [ ] **Step 1: Write failing test for Office metadata scanner**

```rust
// crates/pfg-format-office/tests/scanner_tests.rs
use pfg_format_office::scan_office_metadata;
use pfg_policy::PolicyEngine;

#[test]
fn test_office_core_props_scanning() {
    let mut zip_bytes = Vec::new();
    {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut zip_bytes));
        zip.start_file("[Content_Types].xml", zip::write::SimpleFileOptions::default()).unwrap();
        use std::io::Write;
        zip.write_all(b"<Types></Types>").unwrap();
        zip.start_file("word/document.xml", zip::write::SimpleFileOptions::default()).unwrap();
        zip.write_all(b"<w:document></w:document>").unwrap();
        zip.start_file("docProps/core.xml", zip::write::SimpleFileOptions::default()).unwrap();
        zip.write_all(b"<cp:coreProperties xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\"><dc:creator>Alice</dc:creator></cp:coreProperties>").unwrap();
        zip.finish().unwrap();
    }

    let policy = PolicyEngine::balanced();
    let findings = scan_office_metadata(&zip_bytes, &policy).unwrap();

    assert!(!findings.is_empty());
    assert!(findings.iter().any(|f| f.key == "dc:creator" && f.display_value.as_deref() == Some("Alice")));
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test -p pfg-format-office`
Expected: FAIL due to missing `scan_office_metadata`.

- [ ] **Step 3: Implement Office metadata scanner**

Create `crates/pfg-format-office/src/scanner.rs`:
```rust
use std::io::{Cursor, Read};
use thiserror::Error;
use zip::ZipArchive;
use pfg_model::{Finding, FindingCategory, FindingLocation, FindingSource};
use pfg_policy::PolicyEngine;

#[derive(Error, Debug)]
pub enum OfficeParseError {
    #[error("Invalid Office container or ZIP structure")]
    InvalidContainer,
    #[error("Corrupted Office ZIP file: {0}")]
    CorruptedZip(String),
}

pub fn scan_office_metadata(buffer: &[u8], policy: &PolicyEngine) -> Result<Vec<Finding>, OfficeParseError> {
    let format = crate::detector::detect_office_format(buffer)
        .ok_or(OfficeParseError::InvalidContainer)?;

    let cursor = Cursor::new(buffer);
    let mut archive = ZipArchive::new(cursor)
        .map_err(|e| OfficeParseError::CorruptedZip(e.to_string()))?;

    let mut findings = Vec::new();

    // 1. Scan docProps/core.xml
    if let Ok(mut file) = archive.by_name("docProps/core.xml") {
        let mut xml_str = String::new();
        if file.read_to_string(&mut xml_str).is_ok() {
            parse_xml_properties(&xml_str, "docProps/core.xml", policy, &mut findings);
        }
    }

    // 2. Scan docProps/app.xml
    if let Ok(mut file) = archive.by_name("docProps/app.xml") {
        let mut xml_str = String::new();
        if file.read_to_string(&mut xml_str).is_ok() {
            parse_xml_properties(&xml_str, "docProps/app.xml", policy, &mut findings);
        }
    }

    // 3. Scan docProps/custom.xml
    if archive.by_name("docProps/custom.xml").is_ok() {
        findings.push(Finding {
            id: "office-custom-props".to_string(),
            category: FindingCategory::DocumentHistory,
            severity: policy.categorize_severity(FindingCategory::DocumentHistory, "CustomProperties"),
            source: FindingSource::XmlPart,
            key: "CustomProperties".to_string(),
            display_value: Some("Custom document properties present".to_string()),
            raw_value_available: true,
            location: FindingLocation::Header { segment: "docProps/custom.xml".to_string() },
            risk_explanation: "Document contains custom document property metadata".to_string(),
            removable: true,
        });
    }

    // 4. Scan VBA Macros & Comments & Thumbnails across ZIP entries
    for i in 0..archive.len() {
        if let Ok(file) = archive.by_index(i) {
            let name = file.name().to_string();
            if name.ends_with("vbaProject.bin") {
                findings.push(Finding {
                    id: format!("office-vba-{}", name),
                    category: FindingCategory::Software,
                    severity: policy.categorize_severity(FindingCategory::Software, "VbaProject"),
                    source: FindingSource::ZipEntry,
                    key: "VbaProject".to_string(),
                    display_value: Some("VBA Macro binary file present".to_string()),
                    raw_value_available: true,
                    location: FindingLocation::Header { segment: name },
                    risk_explanation: "Document contains executable VBA macro binary".to_string(),
                    removable: true,
                });
            } else if name.contains("comments") {
                findings.push(Finding {
                    id: format!("office-comments-{}", name),
                    category: FindingCategory::Comments,
                    severity: policy.categorize_severity(FindingCategory::Comments, "CommentsPart"),
                    source: FindingSource::XmlPart,
                    key: "CommentsPart".to_string(),
                    display_value: Some("Document comments part present".to_string()),
                    raw_value_available: true,
                    location: FindingLocation::Header { segment: name },
                    risk_explanation: "Document contains reviewer comments".to_string(),
                    removable: true,
                });
            } else if name == "docProps/thumbnail.jpeg" {
                findings.push(Finding {
                    id: "office-thumbnail".to_string(),
                    category: FindingCategory::Thumbnail,
                    severity: policy.categorize_severity(FindingCategory::Thumbnail, "Thumbnail"),
                    source: FindingSource::ZipEntry,
                    key: "Thumbnail".to_string(),
                    display_value: Some("Embedded document thumbnail image".to_string()),
                    raw_value_available: true,
                    location: FindingLocation::Header { segment: name },
                    risk_explanation: "Cached document thumbnail image".to_string(),
                    removable: true,
                });
            }
        }
    }

    Ok(findings)
}

fn parse_xml_properties(xml: &str, part_name: &str, policy: &PolicyEngine, findings: &mut Vec<Finding>) {
    let target_tags = [
        ("dc:creator", FindingCategory::Identity),
        ("cp:lastModifiedBy", FindingCategory::Identity),
        ("dcterms:created", FindingCategory::Time),
        ("dcterms:modified", FindingCategory::Time),
        ("Company", FindingCategory::Identity),
        ("Manager", FindingCategory::Identity),
        ("Application", FindingCategory::Software),
    ];

    for (tag, category) in target_tags {
        let open_tag = format!("<{}>", tag);
        let close_tag = format!("</{}>", tag);
        if let Some(start) = xml.find(&open_tag) {
            if let Some(end) = xml[start..].find(&close_tag) {
                let val = &xml[start + open_tag.len()..start + end];
                if !val.trim().is_empty() {
                    findings.push(Finding {
                        id: format!("office-xml-{}-{}", part_name, tag),
                        category,
                        severity: policy.categorize_severity(category, tag),
                        source: FindingSource::XmlPart,
                        key: tag.to_string(),
                        display_value: Some(val.to_string()),
                        raw_value_available: true,
                        location: FindingLocation::Header { segment: part_name.to_string() },
                        risk_explanation: format!("XML metadata tag <{}> in {}", tag, part_name),
                        removable: true,
                    });
                }
            }
        }
    }
}
```

Update `crates/pfg-format-office/src/lib.rs`:
```rust
#![forbid(unsafe_code)]

pub mod detector;
pub mod scanner;

pub use detector::{detect_office_format, OfficeFormat};
pub use scanner::{scan_office_metadata, OfficeParseError};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p pfg-format-office`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/pfg-format-office
git commit -m "feat(office): implement Office metadata, XML parts, and macro scanner"
```

---

### Task 3: Office Sanitizer Engine (`pfg-format-office`)

**Files:**
- Create: `privacy-file-guard-source/crates/pfg-format-office/src/sanitizer.rs`
- Modify: `privacy-file-guard-source/crates/pfg-format-office/src/lib.rs`
- Test: `privacy-file-guard-source/crates/pfg-format-office/tests/sanitizer_tests.rs`

**Interfaces:**
- Consumes: `pfg_policy::CleanProfile`
- Produces: `sanitize_office(buffer: &[u8], profile: CleanProfile) -> Result<Vec<u8>, OfficeParseError>`

- [ ] **Step 1: Write failing test for Office sanitizer**

```rust
// crates/pfg-format-office/tests/sanitizer_tests.rs
use pfg_format_office::{scan_office_metadata, sanitize_office};
use pfg_policy::{CleanProfile, PolicyEngine};

#[test]
fn test_office_sanitization_removes_core_props_and_macros() {
    let mut zip_bytes = Vec::new();
    {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut zip_bytes));
        zip.start_file("[Content_Types].xml", zip::write::SimpleFileOptions::default()).unwrap();
        use std::io::Write;
        zip.write_all(b"<Types></Types>").unwrap();
        zip.start_file("word/document.xml", zip::write::SimpleFileOptions::default()).unwrap();
        zip.write_all(b"<w:document></w:document>").unwrap();
        zip.start_file("docProps/core.xml", zip::write::SimpleFileOptions::default()).unwrap();
        zip.write_all(b"<cp:coreProperties xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\"><dc:creator>Alice</dc:creator></cp:coreProperties>").unwrap();
        zip.finish().unwrap();
    }

    let cleaned = sanitize_office(&zip_bytes, CleanProfile::Balanced).unwrap();
    let policy = PolicyEngine::balanced();
    let findings = scan_office_metadata(&cleaned, &policy).unwrap();

    assert!(findings.is_empty());
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test -p pfg-format-office`
Expected: FAIL due to missing `sanitize_office`.

- [ ] **Step 3: Implement Office sanitizer**

Create `crates/pfg-format-office/src/sanitizer.rs`:
```rust
use std::io::{Cursor, Read, Write};
use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};
use pfg_policy::CleanProfile;
use crate::scanner::OfficeParseError;

pub fn sanitize_office(buffer: &[u8], _profile: CleanProfile) -> Result<Vec<u8>, OfficeParseError> {
    let _format = crate::detector::detect_office_format(buffer)
        .ok_or(OfficeParseError::InvalidContainer)?;

    let cursor = Cursor::new(buffer);
    let mut archive = ZipArchive::new(cursor)
        .map_err(|e| OfficeParseError::CorruptedZip(e.to_string()))?;

    let mut cleaned_bytes = Vec::new();
    let mut writer = ZipWriter::new(Cursor::new(&mut cleaned_bytes));

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)
