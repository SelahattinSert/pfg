# Phase 1 Design: Core Scanner Foundation & JPEG Metadata Scanner CLI (`pfg scan`)

**Document Version:** 1.0  
**Date:** 2026-07-24  
**Project:** Privacy File Guard (PFG)  
**Location:** `privacy-file-guard-source`  

---

## 1. Overview & Objective

The primary objective of Phase 1 is to establish the core monorepo architecture, shared data models, policy engine, and the initial CLI tool (`pfg`) capable of scanning JPEG files for hidden privacy-sensitive metadata (`pfg scan image.jpg`).

Key deliverables for Phase 1:
1. Monorepo setup with Cargo workspace in `privacy-file-guard-source/`.
2. Safe byte-level format detection (magic bytes).
3. Pure Rust JPEG Marker Walker (`0xFFE1` EXIF & XMP, `0xFF13` IPTC, `0xFFFE` COM).
4. Finding data models, risk classification (Critical, High, Medium, Low, Informational).
5. Value masking for sensitive fields in CLI output (e.g. GPS coordinates, serial numbers, timestamps, usernames).
6. Machine-readable JSON report output conforming to `report.schema.json`.
7. Fuzz and malformed file handling guarantees (no panics, typed error hierarchy).

---

## 2. Directory Structure & Monorepo Layout

The repository root is located at `privacy-file-guard-source/`:

```text
privacy-file-guard-source/
├── .github/
│   └── workflows/
│       └── ci.yml
├── crates/
│   ├── pfg-model/          # Common domain models, findings, severity, report schema
│   ├── pfg-policy/         # Risk classification and rules
│   ├── pfg-format-image/   # Format detection & JPEG marker walker (EXIF/XMP/IPTC/COM)
│   ├── pfg-core/           # Scanning pipeline, path validation, report engine
│   └── pfg-cli/            # Clap binary interface (`pfg`)
├── docs/
│   └── superpowers/
│       └── specs/
│           └── 2026-07-24-phase1-jpeg-scanner-design.md
├── fixtures/
│   ├── images/             # Synthetic test JPEG images with EXIF/XMP
│   └── malformed/          # Corrupted & truncated test files
├── schemas/
│   └── report.schema.json  # JSON schema for scan report
├── Cargo.toml              # Workspace manifest
├── LICENSE                 # MPL-2.0
└── README.md
```

---

## 3. Data Models (`pfg-model`)

### 3.1 Severity
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}
```

### 3.2 FindingCategory
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

### 3.3 Finding
```rust
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

### 3.4 Scan Report
```rust
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

---

## 4. JPEG Parser & Marker Walker (`pfg-format-image`)

1. **Magic Bytes Validation**:
   - Check `0xFF 0xD8 0xFF` (SOI - Start of Image). Reject immediately if missing.
2. **Marker Loop**:
   - Iterate through JPEG segments reading `0xFF XX` markers and segment lengths.
   - Handled markers:
     - `0xFFE1` (APP1): Test for `"Exif\0\0"` header for TIFF/EXIF parsing (TIFF header endianness `II` or `MM`, IFD0, Exif IFD, GPS IFD). Test for `"http://ns.adobe.com/xap/1.0/\0"` for XMP XML parsing.
     - `0xFFED` (APP13): Test for Photoshop / IPTC header.
     - `0xFFFE` (COM): JPEG textual comments.
     - `0xFFD9` (EOI): End of Image.
3. **Field Extraction & Classification**:
   - GPS IFD tags (Latitude, Longitude, Altitude) -> `FindingCategory::Location`, `Severity::High`.
   - Make, Model, Serial Number -> `FindingCategory::Device`, `Severity::Medium` / `Severity::High`.
   - DateTimeOriginal, CreateDate, ModifyDate -> `FindingCategory::Time`, `Severity::Medium`.
   - Artist, Copyright, XPAuthor -> `FindingCategory::Identity`, `Severity::High`.
   - Software -> `FindingCategory::Software`, `Severity::Low`.
   - Comments -> `FindingCategory::Comments`, `Severity::Medium`.
4. **Value Masking**:
   - By default, `display_value` masks exact GPS coordinates (e.g. `38.4***, 27.1***`) and user credentials/names unless `--include-values` flag is explicitly set.

---

## 5. CLI Interface (`pfg-cli`)

Command syntax:
```bash
pfg scan <PATH> [OPTIONS]
```

Options:
- `-f, --format <FORMAT>`: Output format (`text` [default] or `json`).
- `-o, --report <PATH>`: Write output report to JSON file.
- `--fail-on <SEVERITY>`: Exit code 1 if findings meet or exceed severity (`critical`, `high`, `medium`, `low`).
- `--include-values`: Unmask sensitive values in output.
- `-r, --recursive`: Scan directory recursively.

Exit Codes:
- `0`: Scan successful, no threshold breached.
- `1`: Risk findings detected meeting/exceeding `--fail-on` threshold.
- `2`: Invalid CLI parameters.
- `3`: Unsupported format.
- `4`: File read / IO error.
- `10`: Unexpected internal error.

---

## 6. Testing Strategy

1. **Synthetic Fixtures**: Generate clean JPEG images with known EXIF, XMP, IPTC, and COM fields in `fixtures/images/`.
2. **Malformed & Fuzzing**: Test truncated JPEGs, invalid TIFF headers, cyclic IFD pointers, zero-length markers to guarantee zero panics.
3. **Integration Tests**: Verify end-to-end CLI scanning, JSON report generation, exit codes, and mask enforcement.
