# Phase 6: Tauri 2 Desktop Application Implementation Plan (`v0.6`)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Phase 6 Privacy File Guard Desktop Application (`v0.6`), introducing `pfg-desktop` Tauri 2 backend crate with IPC commands (`scan_file_cmd`, `clean_file_cmd`, `verify_files_cmd`, `scan_directory_cmd`, `clean_directory_cmd`), and React + TypeScript + Glassmorphism UI frontend with Drag & Drop, Findings Viewer, Masking Toggle, Clean Action Panel, Verification Badge, and Batch Dashboard.

**Architecture:** Create crate `crates/pfg-desktop` wrapping `pfg-core`, containing frontend assets in `crates/pfg-desktop/ui/`.

**Tech Stack:** Rust (edition 2021), `pfg-model`, `pfg-policy`, `pfg-core`, `tauri` (v2), React 18, TypeScript, Vite, CSS design system.

## Global Constraints

- **Workspace Root:** `privacy-file-guard-source/`
- **Edition:** 2021
- **Unsafe Code:** `#![forbid(unsafe_code)]`
- **License:** MPL-2.0

---

### Task 1: Tauri 2 Backend Crate Setup & Commands (`pfg-desktop`)

**Files:**
- Modify: `privacy-file-guard-source/Cargo.toml` (add `"crates/pfg-desktop"` to workspace members)
- Create: `privacy-file-guard-source/crates/pfg-desktop/Cargo.toml`
- Create: `privacy-file-guard-source/crates/pfg-desktop/src/main.rs`
- Create: `privacy-file-guard-source/crates/pfg-desktop/src/commands.rs`
- Create: `privacy-file-guard-source/crates/pfg-desktop/tauri.conf.json`
- Test: `privacy-file-guard-source/crates/pfg-desktop/src/commands.rs` (unit tests for commands)

**Interfaces:**
- Consumes: `pfg_core::{scan_file, clean_file, verify_files, scan_directory, clean_directory}`
- Produces: Tauri IPC commands for frontend

- [ ] **Step 1: Write failing test for Tauri backend commands**

```rust
// In crates/pfg-desktop/src/commands.rs unit tests
#[test]
fn test_scan_file_cmd_wrapper() {
    let sample = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/images/sample.jpg");
    let result = scan_file_cmd(sample.to_str().unwrap().to_string(), false);
    assert!(result.is_ok());
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `cargo test -p pfg-desktop`
Expected: FAIL due to missing crate.

- [ ] **Step 3: Implement `pfg-desktop` backend**

Create `crates/pfg-desktop/Cargo.toml`:
```toml
[package]
name = "pfg-desktop"
version = "0.1.0"
edition = "2021"

[dependencies]
pfg-model = { path = "../pfg-model" }
pfg-policy = { path = "../pfg-policy" }
pfg-core = { path = "../pfg-core" }
tauri = { version = "2.0", features = [] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
```

Create `crates/pfg-desktop/src/commands.rs`:
```rust
use pfg_core::{
    clean_directory, clean_file, scan_directory, scan_file, verify_files, BatchCleanOptions,
    BatchCleanReport, BatchScanOptions, BatchScanReport, CleanOptions, CleanProfile, ScanOptions,
    VerificationReport,
};
use pfg_model::ScanReport;

#[tauri::command]
pub fn scan_file_cmd(path: String, include_values: bool) -> Result<ScanReport, String> {
    let p = std::path::Path::new(&path);
    let opts = ScanOptions { include_values };
    scan_file(p, &opts).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn clean_file_cmd(
    path: String,
    profile: String,
    output_dir: Option<String>,
    safe_name: bool,
) -> Result<VerificationReport, String> {
    let p = std::path::Path::new(&path);
    let prof = match profile.to_lowercase().as_str() {
        "strict" => CleanProfile::Strict,
        _ => CleanProfile::Balanced,
    };
    let opts = CleanOptions {
        profile: prof,
        output_dir: output_dir.map(std::path::PathBuf::from),
        safe_name,
        overwrite: true,
    };
    clean_file(p, &opts).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn verify_files_cmd(original_path: String, cleaned_path: String) -> Result<VerificationReport, String> {
    let orig = std::path::Path::new(&original_path);
    let clean = std::path::Path::new(&cleaned_path);
    verify_files(orig, clean).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn scan_directory_cmd(
    path: String,
    recursive: bool,
    jobs: Option<usize>,
    ignore_patterns: Vec<String>,
) -> Result<BatchScanReport, String> {
    let p = std::path::Path::new(&path);
    let opts = BatchScanOptions {
        recursive,
        jobs,
        include_values: false,
        ignore_patterns,
    };
    scan_directory(p, &opts).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn clean_directory_cmd(
    path: String,
    recursive: bool,
    jobs: Option<usize>,
    profile: String,
    in_place: bool,
) -> Result<BatchCleanReport, String> {
    let p = std::path::Path::new(&path);
    let prof = match profile.to_lowercase().as_str() {
        "strict" => CleanProfile::Strict,
        _ => CleanProfile::Balanced,
    };
    let opts = BatchCleanOptions {
        recursive,
        jobs,
        profile: prof,
        output_dir: None,
        in_place,
        safe_name: false,
        overwrite: true,
    };
    clean_directory(p, &opts).map_err(|e| e.to_string())
}
```

Create `crates/pfg-desktop/src/main.rs`:
```rust
#![forbid(unsafe_code)]

mod commands;

use commands::*;

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            scan_file_cmd,
            clean_file_cmd,
            verify_files_cmd,
            scan_directory_cmd,
            clean_directory_cmd
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

Update root `Cargo.toml` to add `"crates/pfg-desktop"` to members.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p pfg-desktop`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/pfg-desktop
git commit -m "feat(desktop): create pfg-desktop Tauri 2 backend crate and IPC commands"
```

---

### Task 2: UI Frontend Design System & TypeScript Types (`ui/`)

**Files:**
- Create: `privacy-file-guard-source/crates/pfg-desktop/ui/package.json`
- Create: `privacy-file-guard-source/crates/pfg-desktop/ui/index.html`
- Create: `privacy-file-guard-source/crates/pfg-desktop/ui/src/index.css`
- Create: `privacy-file-guard-source/crates/pfg-desktop/ui/src/types/pfg.ts`

- [ ] **Step 1: Create TypeScript type definitions (`pfg.ts`)**

Matching domain models: `Finding`, `ScanReport`, `VerificationReport`, `BatchScanReport`, `BatchCleanReport`, `Severity`.

- [ ] **Step 2: Create CSS Design System (`index.css`)**

Dark mode variables, glassmorphism card containers, severity badge styles, dynamic glow animations, modern typography.

- [ ] **Step 3: Commit**

```bash
git add crates/pfg-desktop/ui
git commit -m "feat(desktop): add UI frontend design system and TypeScript types"
```

---

### Task 3: DropZone & Findings Viewer Components (`ui/`)

**Files:**
- Create: `privacy-file-guard-source/crates/pfg-desktop/ui/src/components/DropZone.tsx`
- Create: `privacy-file-guard-source/crates/pfg-desktop/ui/src/components/FindingsList.tsx`
- Modify: `privacy-file-guard-source/crates/pfg-desktop/ui/src/App.tsx`

**Interfaces:**
- Drag & Drop zone handling file selection & directory drop.
- Findings List displaying severity badges, risk explanations, and raw value masking toggle.

- [ ] **Step 1: Implement DropZone component**
- [ ] **Step 2: Implement FindingsList component with unmasked value toggle**
- [ ] **Step 3: Commit**

```bash
git add crates/pfg-desktop/ui/src
git commit -m "feat(desktop): implement DropZone and FindingsList UI components"
```

---

### Task 4: Clean Action Panel & Verification Badge Components (`ui/`)

**Files:**
- Create: `privacy-file-guard-source/crates/pfg-desktop/ui/src/components/CleanPanel.tsx`
- Create: `privacy-file-guard-source/crates/pfg-desktop/ui/src/components/VerificationBadge.tsx`
- Modify: `privacy-file-guard-source/crates/pfg-desktop/ui/src/App.tsx`

**Interfaces:**
- Clean Panel with Profile selector (`Balanced` vs `Strict`), Output options, and "Clean File" trigger.
- Verification Badge displaying SHA256 comparison and "Verified Clean (0 findings remaining)".

- [ ] **Step 1: Implement CleanPanel component**
- [ ] **Step 2: Implement VerificationBadge component**
- [ ] **Step 3: Commit**

```bash
git add crates/pfg-desktop/ui/src
git commit -m "feat(desktop): implement CleanPanel and VerificationBadge UI components"
```

---

### Task 5: Batch Dashboard Component & Integration (`ui/` & workspace)

**Files:**
- Create: `privacy-file-guard-source/crates/pfg-desktop/ui/src/components/BatchDashboard.tsx`
- Modify: `privacy-file-guard-source/crates/pfg-desktop/ui/src/App.tsx`

**Interfaces:**
- Batch Dashboard showing total files scanned, total findings, clean status counts, and directory table.
- Workspace test verification.

- [ ] **Step 1: Implement BatchDashboard component**
- [ ] **Step 2: Assemble main App layout in App.tsx**
- [ ] **Step 3: Run workspace tests and build validation**

Run: `cargo test --workspace`
Expected: PASS across all 7 workspace crates.

- [ ] **Step 4: Commit**

```bash
git add crates/pfg-desktop
git commit -m "feat(desktop): assemble desktop UI application MVP and verify workspace build"
```
