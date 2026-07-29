![Privacy File Guard Banner](docs/privacy_file_guard_banner.jpg)

# Privacy File Guard (PFG)

[![Rust](https://img.shields.io/badge/Rust-2021-orange.svg)](https://www.rust-lang.org/)
[![Tauri](https://img.shields.io/badge/Tauri-2.0-blue.svg)](https://tauri.app/)
[![License](https://img.shields.io/badge/License-MPL--2.0-brightgreen.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Unsafe-Forbidden-success.svg)](crates/pfg-core/src/lib.rs)

> **Privacy File Guard is a local, zero-cloud metadata audit and sanitization tool designed to detect and scrub hidden location data, device serial numbers, author attributes, and embedded metadata from images, PDFs, and Office Open XML documents.**

---

## Executive Summary & Architecture

Privacy File Guard helps prevent accidental privacy exposure when sharing or publishing documents and images. Built with a modular Rust workspace architecture (`#![forbid(unsafe_code)]`), PFG processes files entirely on your local device without external network connections.

### Format Support Matrix

| Format Category | Formats | Metadata Scanned & Cleaned |
| :--- | :--- | :--- |
| **Raster Images** | `.jpg`, `.jpeg`, `.png`, `.webp` | EXIF, GPS, camera model, lens serials, XMP streams, PNG `tEXt`/`iTXt`/`zTXt` chunks, WebP EXIF/XMP chunks. |
| **PDF Documents** | `.pdf` | `/Info` dictionary (Author, Creator, Producer, Title), `/Metadata` XMP streams, `/OpenAction` JavaScript, `/Annots` (in Strict mode). Preserves Catalog & Page tree. |
| **Office Documents** | `.docx`, `.xlsx`, `.pptx` | `docProps/core.xml` (Author, LastModifiedBy, Dates), `docProps/app.xml` (Company, Manager), custom properties, thumbnails, VBA macros (`vbaProject.bin`), and comments. |

---

## Profiles & Privacy Guarantees

### Sanitization Profiles

- **Balanced Profile (Default)**: Purges PII, location data, camera serial numbers, author identity, comments, and high-risk metadata properties while preserving essential rendering attributes such as color profiles (`iCCP`) and physical dimensions (`pHYs`).
- **Strict Profile**: Strips all non-essential metadata properties, custom attributes, comments, thumbnails, and annotations for maximum privacy reduction.

### Realistic Assurance Guarantees

Privacy File Guard performs local metadata scrubbing and post-clean verification checks on supported file formats. It does not provide absolute guarantees regarding human-readable text content within documents, hidden steganography, or unrecognized proprietary stream formats.

---

## Prerequisites & Building

### Prerequisites

Privacy File Guard requires **Rust** (`rustup`) and **Node.js**.

#### Fedora / RHEL Linux:
```bash
sudo dnf install -y webkit2gtk4.1-devel libsoup3-devel gtk3-devel libappindicator-gtk3-devel librsvg2-devel
```

#### Ubuntu / Debian Linux:
```bash
sudo apt-get update
sudo apt-get install -y libwebkit2gtk-4.1-dev libsoup-3.0-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev
```

#### Windows / macOS:
Standard Rust toolchain (`cargo`).

---

### Building & Testing

```bash
git clone https://github.com/SelahattinSert/pfg.git
cd pfg

# Execute full workspace unit & integration test suite
cargo test --workspace
```

---

## Usage Guide

### 1. Desktop Graphical User Interface (GUI)

Launch the desktop application:

```bash
cargo run -p pfg-desktop
```

- **Single File Mode**: Drag and drop any supported image or document to inspect findings, toggle raw unmasked values, and execute profile-based sanitization.
- **Batch Directory Mode**: Select a folder to run parallel multi-core auditing and in-place transactional cleaning.

---

### 2. Command Line Interface (CLI)

```bash
# Scan a single file
cargo run -p pfg-cli -- scan /path/to/document.pdf

# Clean a file with Balanced profile (outputs document.pfg.pdf)
cargo run -p pfg-cli -- clean /path/to/document.pdf

# Clean a file with Strict profile to a custom output directory
cargo run -p pfg-cli -- clean /path/to/image.jpg --profile strict --output-dir /path/to/output

# Verify clean status between original and cleaned file
cargo run -p pfg-cli -- verify /path/to/original.jpg /path/to/image.pfg.jpg

# Multithreaded batch directory scan
cargo run -p pfg-cli -- scan /path/to/folder -r -j 8

# Multithreaded batch in-place cleaning
cargo run -p pfg-cli -- clean /path/to/folder -r --in-place
```

### CLI Exit Codes

- `0`: Operation succeeded cleanly / verification passed.
- `1`: Threshold met or exceeded (when using `--fail-on`).
- `2`: Target file or directory not found / IO error.
- `3`: Unsupported file format.
- `4`: Target file corrupted or unparseable.
- `5`: Clean operation failed.
- `6`: Verification failed.

---

## Workspace Architecture

```text
privacy-file-guard-source/
├── docs/
│   └── privacy_file_guard_banner.jpg
├── crates/
│   ├── pfg-model/           # Privacy-safe domain models & finding structures
│   ├── pfg-policy/          # Profile policy engine & severity categorization
│   ├── pfg-format-image/    # JPEG, PNG, WebP parsers & EXIF orientation engine
│   ├── pfg-format-pdf/      # PDF redactors & structural validators
│   ├── pfg-format-office/   # DOCX, XLSX, PPTX OOXML ZIP sanitizers
│   ├── pfg-core/            # Rayon parallel batch engine & policy verifier
│   ├── pfg-cli/             # Command Line Interface (CLI) application
│   └── pfg-desktop/         # Tauri 2 + React desktop GUI application
└── Cargo.toml
```

---

## Security Policy & License

- **Safety**: Every crate in this workspace enforces `#![forbid(unsafe_code)]` at top-level crate roots.
- **License**: Distributed under the [Mozilla Public License 2.0 (MPL-2.0)](LICENSE).
