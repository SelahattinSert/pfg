# Phase 4 Design Specification: Office Documents Support (`v0.4`)

**Document Version:** 1.0  
**Date:** 2026-07-24  
**Project:** Privacy File Guard (PFG)  
**Location:** `privacy-file-guard-source`  

---

## 1. Overview & Objective

Phase 4 introduces full **Office Open XML (OOXML) Metadata Scanning & Sanitization** (`v0.4`) for `.docx`, `.xlsx`, and `.pptx` documents, matching Section 10.4, 11, and 18 of the Product & Engineering Plan.

OOXML documents are ZIP containers containing structured XML parts, embedded OLE objects, VBA macro binaries, thumbnails, and revision tracking data.

Key deliverables for Phase 4:
1. **New Crate `pfg-format-office`**:
   - Magic bytes `PK\x03\x04` ZIP container & OOXML part detector (`[Content_Types].xml`).
   - `docProps/core.xml` metadata scanner (`dc:creator`, `cp:lastModifiedBy`, `cp:revision`, `dcterms:created`, `dcterms:modified`, `dc:title`, `dc:subject`, `cp:keywords`).
   - `docProps/app.xml` metadata scanner (`Company`, `Manager`, `Application`, `AppVersion`, `TotalTime`).
   - `docProps/custom.xml` custom properties scanner.
   - Comments & tracked changes scanner (`word/comments.xml`, `xl/comments*.xml`, `ppt/comments/*.xml`).
   - VBA Macros & Embedded Objects scanner (`vbaProject.bin`, `embeddings/*`, `oleObject`).
   - Thumbnails scanner (`docProps/thumbnail.jpeg`).
2. **Office Sanitization Engine**:
   - `sanitize_office(buffer: &[u8], profile: CleanProfile) -> Result<Vec<u8>, OfficeParseError>`
   - Modifies ZIP entries in-memory using `zip` and `quick-xml` or regex XML element rewriting.
   - Clears sensitive elements in `docProps/core.xml` and `docProps/app.xml`.
   - Removes `docProps/custom.xml`, `word/comments.xml`, `word/vbaProject.bin`, `docProps/thumbnail.jpeg`.
   - Re-compresses valid ZIP container structure.
3. **Core & CLI Integration**:
   - Integration into `pfg-core` (`scan_file`, `clean_file`, `verify_files`).
   - CLI support for `.docx`, `.xlsx`, `.pptx` in `pfg scan`, `pfg clean`, `pfg verify`.

---

## 2. Architecture & Module Design

```text
crates/pfg-format-office/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── detector.rs      # PK\x03\x04 & [Content_Types].xml detector
│   ├── scanner.rs       # OOXML XML & ZIP part scanner
│   ├── sanitizer.rs     # ZIP entry filter & XML property sanitizing rebuilder
│   └── xml_utils.rs     # Core/App XML value redactor
└── tests/
    └── office_tests.rs
```

---

## 3. Data Models & Finding Mappings

OOXML Finding mappings:
- `dc:creator`, `cp:lastModifiedBy` -> `FindingCategory::Identity`, `Severity::High`
- `dcterms:created`, `dcterms:modified` -> `FindingCategory::Time`, `Severity::Medium`
- `Company`, `Manager` -> `FindingCategory::Identity`, `Severity::High`
- `Application`, `AppVersion`, `TotalTime` -> `FindingCategory::Software`, `Severity::Low`
- `word/comments.xml` -> `FindingCategory::Comments`, `Severity::Medium`
- `vbaProject.bin` (VBA Macro) -> `FindingCategory::Software`, `Severity::Critical`
- `docProps/custom.xml` -> `FindingCategory::DocumentHistory`, `Severity::Medium`
- `docProps/thumbnail.jpeg` -> `FindingCategory::Thumbnail`, `Severity::Low`

---

## 4. Security Invariants & Testing

1. **Memory Safety**: `#![forbid(unsafe_code)]` in `pfg-format-office`.
2. **Symlink & Path Safety**: Inherited from `pfg-core`.
3. **Atomic Clean & Rescan Verification**: Post-clean verification rescans output ZIP file, confirming 0 target findings remain.
4. **Valid ZIP Container**: Re-compressed output opens natively as valid OOXML document.
