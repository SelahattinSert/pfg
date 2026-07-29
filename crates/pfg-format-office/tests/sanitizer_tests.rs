use pfg_format_office::{sanitize_office, scan_office_metadata, OfficeParseError};
use pfg_policy::{CleanProfile, PolicyEngine};
use std::io::Write;
use zip::write::FileOptions;
use zip::ZipWriter;

fn create_test_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let cursor = std::io::Cursor::new(Vec::new());
    let mut zip = ZipWriter::new(cursor);
    let options = FileOptions::default();
    for (name, data) in files {
        zip.start_file(*name, options).unwrap();
        zip.write_all(data).unwrap();
    }
    let cursor = zip.finish().unwrap();
    cursor.into_inner()
}

#[test]
fn test_sanitize_office_invalid_container() {
    let res = sanitize_office(b"not a zip file", CleanProfile::Balanced);
    assert_eq!(res, Err(OfficeParseError::InvalidContainer));
}

#[test]
fn test_sanitize_office_corrupted_zip() {
    let corrupted_buf = b"PK\x03\x04corrupted zip payload data that is invalid";
    let res = sanitize_office(corrupted_buf, CleanProfile::Balanced);
    match res {
        Err(OfficeParseError::CorruptedZip(_)) => {}
        other => panic!("Expected CorruptedZip error, got {:?}", other),
    }
}

#[test]
fn test_sanitize_office_non_office_zip() {
    let zip_data = create_test_zip(&[("hello.txt", b"world")]);
    let res = sanitize_office(&zip_data, CleanProfile::Balanced);
    assert_eq!(res, Err(OfficeParseError::InvalidContainer));
}

#[test]
fn test_sanitize_office_redacts_metadata_and_strips_files() {
    let policy = PolicyEngine::balanced();
    let core_xml = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
                   xmlns:dc="http://purl.org/dc/elements/1.1/"
                   xmlns:dcterms="http://purl.org/dc/terms/">
    <dc:creator>Alice Developer</dc:creator>
    <cp:lastModifiedBy>Bob Reviewer</cp:lastModifiedBy>
    <dcterms:created>2026-01-01T10:00:00Z</dcterms:created>
    <dcterms:modified>2026-01-02T12:00:00Z</dcterms:modified>
    <dc:title>Project Architecture</dc:title>
    <dc:subject>Design Specs</dc:subject>
    <cp:keywords>privacy, security</cp:keywords>
</cp:coreProperties>"#;

    let app_xml = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
    <Company>Acme Corp</Company>
    <Manager>Carol Boss</Manager>
    <Application>Microsoft Office Word</Application>
    <AppVersion>16.0000</AppVersion>
    <TotalTime>120</TotalTime>
</Properties>"#;

    let zip_data = create_test_zip(&[
        ("[Content_Types].xml", b"<Types></Types>"),
        ("word/document.xml", b"<document></document>"),
        ("docProps/core.xml", core_xml.as_bytes()),
        ("docProps/app.xml", app_xml.as_bytes()),
        ("docProps/custom.xml", b"<Properties></Properties>"),
        ("docProps/thumbnail.jpeg", b"JPEG data"),
        ("word/vbaProject.bin", b"VBA binary"),
        ("word/comments.xml", b"<comments></comments>"),
    ]);

    // Initial scan should find metadata, custom properties, thumbnail, vba macro, and comments
    let initial_findings = scan_office_metadata(&zip_data, &policy).expect("Scan should succeed");
    assert!(!initial_findings.is_empty());

    // Sanitize with Balanced profile
    let sanitized_bytes = sanitize_office(&zip_data, CleanProfile::Balanced)
        .expect("Sanitization in Balanced mode should succeed");

    // Scan sanitized file
    let post_findings =
        scan_office_metadata(&sanitized_bytes, &policy).expect("Scan should succeed");

    // Core and app metadata should be redacted
    assert!(post_findings.iter().all(|f| f.key != "dc:creator"));
    assert!(post_findings.iter().all(|f| f.key != "cp:lastModifiedBy"));
    assert!(post_findings.iter().all(|f| f.key != "dcterms:created"));
    assert!(post_findings.iter().all(|f| f.key != "dcterms:modified"));
    assert!(post_findings.iter().all(|f| f.key != "dc:title"));
    assert!(post_findings.iter().all(|f| f.key != "dc:subject"));
    assert!(post_findings.iter().all(|f| f.key != "cp:keywords"));
    assert!(post_findings.iter().all(|f| f.key != "Company"));
    assert!(post_findings.iter().all(|f| f.key != "Manager"));
    assert!(post_findings.iter().all(|f| f.key != "Application"));
    assert!(post_findings.iter().all(|f| f.key != "AppVersion"));
    assert!(post_findings.iter().all(|f| f.key != "TotalTime"));

    // Stripped entries must not be present
    assert!(post_findings.iter().all(|f| f.key != "docProps/custom.xml"));
    assert!(post_findings
        .iter()
        .all(|f| f.key != "docProps/thumbnail.jpeg"));
    assert!(post_findings.iter().all(|f| f.key != "word/vbaProject.bin"));

    // Comments should remain in Balanced profile
    assert!(post_findings.iter().any(|f| f.key == "word/comments.xml"));
}

#[test]
fn test_sanitize_office_strict_strips_comments() {
    let policy = PolicyEngine::balanced();
    let zip_data = create_test_zip(&[
        ("[Content_Types].xml", b"<Types></Types>"),
        ("word/document.xml", b"<document></document>"),
        ("word/comments.xml", b"<comments></comments>"),
        ("xl/comments1.xml", b"<comments></comments>"),
        ("ppt/comments/comment1.xml", b"<comments></comments>"),
    ]);

    let initial_findings = scan_office_metadata(&zip_data, &policy).expect("Scan should succeed");
    assert_eq!(initial_findings.len(), 3);

    // Sanitize with Strict profile
    let sanitized_bytes = sanitize_office(&zip_data, CleanProfile::Strict)
        .expect("Sanitization in Strict mode should succeed");

    let post_findings =
        scan_office_metadata(&sanitized_bytes, &policy).expect("Scan should succeed");

    // All comment files must be stripped in Strict mode
    assert!(post_findings.is_empty());
}
