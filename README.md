![Privacy File Guard Banner](docs/privacy_file_guard_banner.jpg)

# Privacy File Guard (PFG)

[![Rust](https://img.shields.io/badge/Rust-2021-orange.svg)](https://www.rust-lang.org/)
[![Tauri](https://img.shields.io/badge/Tauri-2.0-blue.svg)](https://tauri.app/)
[![License](https://img.shields.io/badge/License-MPL--2.0-brightgreen.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Unsafe-Forbidden-success.svg)](crates/pfg-core/src/lib.rs)

> **Privacy File Guard is a 100% local, zero-cloud metadata audit and sanitization tool that prevents privacy leaks by scanning and removing hidden location data, device identifiers, and security risks from images, PDFs, and Office documents.**

---

## Executive Summary & Architecture

Privacy File Guard addresses the risk of accidental exposure of confidential metadata when sharing or publishing documents and images. It features a multi-crate modular Rust architecture, zero-cloud execution, and safe multithreaded directory processing.

### Key Capabilities

- **100% Offline Local Engine**: Zero network connectivity required. Files are processed entirely in memory and local storage.
- **Lossless Image Sanitization (JPEG, PNG, WebP)**: Purges EXIF, GPS coordinates, camera serial numbers, and XMP streams while retaining pristine image quality (High Quality 92% JPEG encoding) and original file size (~2.3 MB).
- **Physical Auto-Orientation Matrix**: Automatically rotates pixel arrays (`2062 x 3664`) to prevent portrait photos (e.g., iPhone 13 images) from rendering sideways or inverted across Linux, Windows, macOS, Android, and iOS image viewers.
- **PDF Security Redaction**: Cleans XMP metadata streams, Document Info dictionaries, embedded files, and potentially malicious JavaScript actions.
- **Office Document Sanitization (.docx, .xlsx, .pptx)**: Redacts author metadata (`docProps/core.xml`), custom properties, hidden comments, and macro (`.bin`) binaries.
- **Parallel Multi-Core Batch Processing**: Utilizes Rust `rayon` concurrency to audit and sanitize thousands of files across all available CPU threads.
- **Post-Clean Verification Check**: Automatically re-audits every output file post-sanitization to ensure zero residual privacy findings before committing writes to disk.

---

## Prerequisites & Installation

### 1. Prerequisites

Privacy File Guard requires **Rust** (`rustup`) and **Node.js**. Install the required OS system dependencies:

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
No additional system libraries required. Standard Rust toolchain is sufficient.

---

### 2. Building the Project

Clone the repository and compile the workspace:

```bash
git clone https://github.com/user/privacy-file-guard.git
cd privacy-file-guard/privacy-file-guard-source

# Execute full workspace unit & integration test suite
cargo test --workspace --exclude pfg-desktop
```

---

## Usage Guide

### 1. Desktop Graphical User Interface (GUI)

To launch the cross-platform native desktop application:

```bash
cargo run -p pfg-desktop
```

#### Single File Inspection & Sanitization
1. **File Selection**: Drag and drop a file onto the drop zone or click **Browse File** to open native system file dialogs (`rfd`).
2. **Privacy Audit**: Review findings grouped by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`).
3. **Value Inspection**: Use the **Mask Raw Values** toggle to inspect exact unmasked strings.
4. **Sanitization**: Select your profile (`Balanced` or `Strict`) and click **Clean File**. PFG writes `filename.pfg.ext` and confirms with a **100% Verified Clean** status badge.

#### Batch Directory Mode
1. Switch to the **Batch Directory** tab in the main view.
2. Click **Browse Folder** to select a target directory.
3. Configure batch options:
   - **Recursive**: Traverses all subdirectories.
   - **Jobs**: Sets worker thread pool size (e.g., 8 threads).
   - **In-Place**: Replaces original files in-place atomically.
4. Click **Clean All Files** to process the directory.

---

### 2. Command Line Interface (CLI)

For terminal automation and scripting, use `pfg-cli`.

#### Audit a Single File
```bash
cargo run -p pfg-cli -- scan /path/to/document.pdf
```

#### Sanitize a Single File
```bash
cargo run -p pfg-cli -- clean /path/to/image.jpg
```
*Outputs `image.pfg.jpg` after post-clean verification.*

Specify custom output directories or profiles:
```bash
cargo run -p pfg-cli -- clean /path/to/image.jpg --output-dir /path/to/output --profile strict
```

#### Verify Clean Status
```bash
cargo run -p pfg-cli -- verify /path/to/original.jpg /path/to/image.pfg.jpg
```

#### Batch Directory Audit & Sanitization
Audit an entire folder recursively using 8 CPU cores:
```bash
cargo run -p pfg-cli -- scan /path/to/folder -r -j 8
```

Sanitize an entire folder in-place:
```bash
cargo run -p pfg-cli -- clean /path/to/folder -r --in-place
```

---

## Workspace Architecture

```text
privacy-file-guard-source/
├── docs/
│   └── privacy_file_guard_banner.jpg  # Visual architecture banner
├── crates/
│   ├── pfg-model/           # Core domain models & finding definitions
│   ├── pfg-policy/          # Compliance profiles (Balanced/Strict) & policy rules
│   ├── pfg-format-image/    # JPEG, PNG, WebP parsers & auto-orientation engine
│   ├── pfg-format-pdf/      # PDF XMP, JavaScript, and annotation redactors
│   ├── pfg-format-office/   # DOCX, XLSX, PPTX OOXML ZIP sanitizers
│   ├── pfg-core/            # Rayon multithreaded batch pipeline & verifier
│   ├── pfg-cli/             # Command Line Interface (CLI) application
│   └── pfg-desktop/         # Tauri 2 + React native desktop GUI application
└── Cargo.toml
```

---

## Security Policy & License

- **Safety Guarantee**: Every crate in this workspace enforces `#![forbid(unsafe_code)]` at top-level crate roots, eliminating memory safety vulnerabilities.
- **License**: Distributed under the [Mozilla Public License 2.0 (MPL-2.0)](LICENSE).
