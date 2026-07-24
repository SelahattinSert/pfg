use std::io::Cursor;
use zip::ZipArchive;

/// Supported Office Open XML formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OfficeFormat {
    Docx,
    Xlsx,
    Pptx,
}

/// Detects whether a byte slice represents an Office Open XML document
/// (DOCX, XLSX, or PPTX).
///
/// It verifies:
/// 1. The `PK\x03\x04` magic bytes at the beginning of the buffer.
/// 2. The presence of `[Content_Types].xml` in the ZIP archive.
/// 3. The presence of specific OOXML root part files (`word/document.xml`,
///    `xl/workbook.xml`, or `ppt/presentation.xml`).
pub fn detect_office_format(buffer: &[u8]) -> Option<OfficeFormat> {
    // 1. Check PK\x03\x04 magic bytes
    if buffer.len() < 4 || &buffer[0..4] != b"PK\x03\x04" {
        return None;
    }

    // 2. Parse ZIP archive
    let cursor = Cursor::new(buffer);
    let mut archive = ZipArchive::new(cursor).ok()?;

    // 3. Check for [Content_Types].xml
    if archive.by_name("[Content_Types].xml").is_err() {
        return None;
    }

    // 4. Check specific part paths
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
