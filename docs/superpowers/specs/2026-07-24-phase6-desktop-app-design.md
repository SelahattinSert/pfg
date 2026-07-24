# Phase 6 Design Specification: Tauri 2 Desktop Application (`v0.6`)

**Document Version:** 1.0  
**Date:** 2026-07-24  
**Project:** Privacy File Guard (PFG)  
**Location:** `privacy-file-guard-source`  

---

## 1. Overview & Objective

Phase 6 introduces the **Privacy File Guard Desktop Application** (`v0.6`) powered by **Tauri 2 + React + TypeScript**, matching Section 10.6, 12, 13, and 18 of the Product & Engineering Plan.

Key deliverables for Phase 6:
1. **`crates/pfg-desktop` (Tauri 2 Backend Crate)**:
   - Exposes Rust core functionality to the frontend via Tauri Commands:
     - `scan_file_cmd`
     - `clean_file_cmd`
     - `verify_files_cmd`
     - `scan_directory_cmd`
     - `clean_directory_cmd`
   - Zero unsafe code (`#![forbid(unsafe_code)]`).
2. **Modern Web Frontend (`ui/`)**:
   - Built with Vite, React, TypeScript, and modern CSS design system.
   - Sleek dark mode palette, glassmorphism card layouts, dynamic animations.
   - Interactive Drag & Drop zone for files and folders.
   - Real-time Findings Viewer with severity color coding (Critical: Crimson, High: Orange, Medium: Amber, Low: Slate, Informational: Cyan).
   - Sensitive Value Masking toggle ("Show / Hide Raw Value").
   - Clean Action Panel with Profile selector (`Balanced` vs `Strict`) and Output options.
   - Verification Badge ("✅ Verified Clean: 0 findings remaining").
   - Batch Directory Summary Dashboard.

---

## 2. Architecture & Tauri Command Mapping

```text
crates/pfg-desktop/
├── Cargo.toml
├── tauri.conf.json
├── src/
│   ├── main.rs
│   └── commands.rs     # Tauri IPC command wrappers for pfg-core
└── ui/
    ├── package.json
    ├── index.html
    ├── src/
    │   ├── App.tsx
    │   ├── components/
    │   │   ├── DropZone.tsx
    │   │   ├── FindingsList.tsx
    │   │   ├── CleanPanel.tsx
    │   │   ├── VerificationBadge.tsx
    │   │   └── BatchDashboard.tsx
    │   ├── types/
    │   │   └── pfg.ts
    │   └── index.css
```

---

## 3. UI Aesthetics & Experience

- **Theme**: Deep slate/charcoal background (`#0b0f19`), vibrant indigo/teal accents (`#6366f1` / `#14b8a6`), frosted glass containers (`backdrop-filter: blur(12px)`).
- **Typography**: Inter / Outfit modern sans-serif fonts.
- **Interactions**: Smooth hover effects, micro-animations on scan completion, badge glow on verified clean status.
- **Zero Placeholders**: Full functional UI components communicating directly with Rust commands.

---

## 4. Security Invariants

1. **Local-Only Execution**: 100% offline, zero network requests, zero telemetry.
2. **Memory Safety**: `#![forbid(unsafe_code)]` enforced in `pfg-desktop`.
3. **Atomic Writes & Rescan**: Backend maintains exact atomic write and post-clean verification rescan rules.
