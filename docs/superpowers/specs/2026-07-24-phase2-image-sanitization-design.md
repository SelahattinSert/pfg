# Phase 2 Design Specification: Image Metadata Sanitization & Verification (`pfg clean` / `pfg verify`)

**Document Version:** 1.0  
**Date:** 2026-07-24  
**Project:** Privacy File Guard (PFG)  
**Location:** `privacy-file-guard-source`  

---

## 1. Overview & Objective

Phase 2 focuses on delivering the **Image Sanitizer Engine** (`v0.2`), matching Section 10.2, 16, 17, and 20 of the Product & Engineering Plan.

Key deliverables for Phase 2:
1. **Clean Profiles**: `Balanced` (default - removes GPS, serial numbers, user identity, comments, thumbnails while preserving image dimensions, orientation, and ICC color profile) and `Strict` (strips all non-essential APP/chunk metadata).
2. **JPEG Sanitization**: Segment filter removing/rebuilding `APP1` EXIF, `APP1` XMP, `APP13` IPTC, and `COM` segments while keeping image entropy payload untouched.
3. **PNG Sanitization**: Chunk filter stripping `eXIf`, `tEXt`, `zTXt`, `iTXt`, `tIME`, `iCCP`, `pHYs`, `sPLT` chunks and recalculating chunk CRC32 checksums.
4. **WebP Sanitization**: RIFF chunk filter stripping `EXIF` and `XMP` chunks and updating `VP8X` flag bits.
5. **Atomic Output & Invariant Protection**:
   - Original file is **never modified** by default. Output defaults to `filename.pfg.ext`.
   - Writes to an isolated temporary file (`.tmp`).
   - Executes automatic post-clean verification (independent rescan of output).
   - Replaces target atomically (`rename`) only upon successful verification.
6. **CLI Commands**:
   - `pfg clean <PATH> [--profile balanced|strict] [--output-dir <DIR>] [--safe-name]`
   - `pfg verify <ORIGINAL> <CLEANED>`

---

## 2. Architecture & Module Design

```text
pfg-cli (`pfg clean` / `pfg verify`)
   │
   ▼
pfg-core (`clean_file` & `verify_file`)
   │  ├─► AtomicTempWriter (.tmp -> atomic rename)
   │  ├─► Post-Clean Rescan Verifier
   │  └─► Safe Filename Generator
   │
   ▼
pfg-format-image (`sanitize_jpeg`, `sanitize_png`, `sanitize_webp`)
   │
   ▼
pfg-policy (`CleanProfile::Balanced`, `CleanProfile::Strict`)
```

---

## 3. Data Models & API Extensions

### 3.1 `pfg-policy` Extensions
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CleanProfile {
    Balanced,
    Strict,
}
```

### 3.2 `pfg-format-image` Extensions
```rust
#[derive(Error, Debug)]
pub enum ImageSanitizeError {
    #[error("Unsupported image format for sanitization")]
    UnsupportedFormat,
    #[error("Corrupted marker/chunk structure: {0}")]
    CorruptedStructure(String),
    #[error("IO error during sanitization: {0}")]
    IoError(String),
}

pub fn sanitize_image(
    buffer: &[u8],
    format: ImageFormat,
    profile: CleanProfile,
) -> Result<Vec<u8>, ImageSanitizeError>;
```

### 3.3 `pfg-core` Extensions
```rust
#[derive(Debug, Clone)]
pub struct CleanOptions {
    pub profile: CleanProfile,
    pub output_dir: Option<PathBuf>,
    pub safe_name: bool,
    pub overwrite: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub original_sha256: String,
    pub cleaned_sha256: String,
    pub original_findings_count: usize,
    pub cleaned_findings_count: usize,
    pub verified_clean: bool,
    pub assurance_level: String,
}

pub fn clean_file(path: &Path, options: &CleanOptions) -> Result<VerificationReport, CoreError>;
pub fn verify_files(original_path: &Path, cleaned_path: &Path) -> Result<VerificationReport, CoreError>;
```

---

## 4. Format Sanitization Rules

### 4.1 JPEG
- **Balanced**:
  - Filter `0xFFE1` (APP1): Remove EXIF tags matching GPS, Device Serial, Artist/Software while keeping Orientation (if non-destructive). Strip XMP packets.
  - Filter `0xFFFE` (COM): Remove all comment segments.
  - Filter `0xFFED` (APP13): Remove Photoshop/IPTC blocks.
  - Preserve `0xFFE2` (ICC profile) and `0xFFE0` (JFIF).
- **Strict**:
  - Strip all `0xFFE1`–`0xFFEF` (except essential `0xFFE0` / `0xFFE2` if valid) and `0xFFFE`.

### 4.2 PNG
- Filter non-essential chunks: `eXIf`, `tEXt`, `zTXt`, `iTXt`, `tIME`, `iCCP`, `pHYs`, `sPLT`.
- Keep essential chunks: `IHDR`, `PLTE`, `IDAT`, `IEND`.
- Recalculate CRC32 for every written chunk.

### 4.3 WebP
- Walk RIFF header & chunks.
- Strip `EXIF` and `XMP` chunks.
- If `VP8X` is present, zero out EXIF (bit 3) and XMP (bit 2) flag bits in `VP8X` chunk payload and recalculate payload length.

---

## 5. Security Invariants & Testing

1. **Atomic File Safety**: Orijinal dosya asla bozulmaz. Geçici dosya yazılıp doğrulama başarmadıkça orijinal veya hedef dosyanın üzerine yazılmaz.
2. **Verification Loop**: `clean_file` sonrası oluşturulan temiz dosya tekrar taranır (`scan_file`). Kalan hassas veri `> 0` ise işlem iptal edilir ve hata dönülür.
3. **Automated Integration Tests**: Golden fixture testleri (JPEG, PNG, WebP) ile temizleme öncesi ve sonrası bulgu sayısı doğrulaması.
