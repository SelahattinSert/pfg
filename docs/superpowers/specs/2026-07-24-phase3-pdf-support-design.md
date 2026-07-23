# Phase 3 Design Specification: PDF Metadata Scanning & Sanitization (`v0.3`)

**Document Version:** 1.0  
**Date:** 2026-07-24  
**Project:** Privacy File Guard (PFG)  
**Location:** `privacy-file-guard-source`  

---

## 1. Overview & Objective

Phase 3 introduces full **PDF Metadata Scanning & Sanitization** (`v0.3`), matching Section 10.3, 11, and 18 of the Product & Engineering Plan.

PDF is the most risk-dense format in the project due to embedded files, hidden annotations, JavaScript actions, XMP metadata streams, and Info dictionaries.

Key deliverables for Phase 3:
1. **New Crate `pfg-format-pdf`**:
   - `%PDF-` magic byte structure validation.
   - PDF `/Info` dictionary scanner (`Author`, `Creator`, `Producer`, `CreationDate`, `ModDate`, `Title`, `Subject`, `Keywords`).
   - XMP `/Metadata` stream scanner.
   - Embedded files & attachments scanner (`/EmbeddedFiles`, `/EF`, `/Type /Filespec`).
   - Annotations & comments scanner (`/Annots`).
   - JavaScript & automatic actions scanner (`/JavaScript`, `/JS`, `/OpenAction`, `/AA`, `/Launch`).
   - Encrypted PDF detection (`/Encrypt`).
   - Digital signature detection (`/Sig`, `/ByteRange`, `/Contents`) + user warning generation.
2. **PDF Sanitization Pipeline**:
   - Object/dictionary removal & structure rebuilder (`sanitize_pdf`).
   - Stripping `/Info` metadata, `/Metadata` XMP stream, `/JavaScript` actions, `/OpenAction`, and `/EmbeddedFiles`.
   - Annotations: Preserved in `Balanced` mode if non-sensitive, stripped in `Strict` mode.
   - Encrypted PDF handling (detects encryption and returns typed error requiring passphrase).
   - Signed PDF warning (emits warning that cleaning invalidates digital signature).
3. **Core & CLI Integration**:
   - Format detection delegating `.pdf` / `%PDF-` files to `pfg-format-pdf`.
   - `pfg scan document.pdf`
   - `pfg clean document.pdf`
   - `pfg verify document.pdf document.pfg.pdf`

---

## 2. Architecture & Module Design

```text
crates/pfg-format-pdf/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── detector.rs      # %PDF- header detector
│   ├── scanner.rs       # PDF object & dictionary scanner
│   ├── sanitizer.rs     # PDF object filter & structure rebuilder
│   ├── info.rs          # /Info dictionary parser
│   ├── xmp.rs           # /Metadata XMP stream parser
│   └── crypto_sig.rs    # /Encrypt and /Sig detector
└── tests/
    └── pdf_tests.rs
```

---

## 3. Data Models & Finding Categories

PDF finding mappings:
- `/Author`, `/Creator`, `/Producer` -> `FindingCategory::Identity`, `Severity::High`
- `/CreationDate`, `/ModDate` -> `FindingCategory::Time`, `Severity::Medium`
- `/Metadata` (XMP Stream) -> `FindingCategory::Identity`, `Severity::High`
- `/EmbeddedFiles`, `/Filespec` -> `FindingCategory::EmbeddedContent`, `Severity::High`
- `/Annots` (Comments/Markup) -> `FindingCategory::Comments`, `Severity::Medium`
- `/JavaScript`, `/JS`, `/Launch` -> `FindingCategory::Software`, `Severity::Critical`
- `/Sig` (Digital Signature) -> `FindingCategory::Technical`, `Severity::Informational` (with Warning)

---

## 4. Security Invariants & Testing

1. **Memory Safety**: `#![forbid(unsafe_code)]` in `pfg-format-pdf`.
2. **Symlink & Path Safety**: Inherited from `pfg-core`.
3. **Atomic Clean & Rescan Verification**: Post-clean verification rescans generated PDF, confirming 0 target findings remain.
4. **Signed Document Warning**: Emits explicit warning when sanitizing digitally signed PDFs.
