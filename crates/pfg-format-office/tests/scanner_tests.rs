use pfg_format_office::{scan_office_metadata, OfficeParseError};
use pfg_model::{FindingCategory, FindingSource};
use pfg_policy::PolicyEngine;
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
fn test_scan_office_invalid_container() {
    let policy = PolicyEngine::balanced();
    let res = scan_office_metadata(b"not a zip file", &policy);
    assert_eq!(res, Err(OfficeParseError::InvalidContainer));
}

#[test]
fn test_scan_office_corrupted_zip() {
    let policy = PolicyEngine::balanced();
    let corrupted_buf = b"PK\x03\x04corrupted zip payload data that is invalid";
    let res = scan_office_metadata(corrupted_buf, &policy);
    match res {
        Err(OfficeParseError::CorruptedZip(_)) => {}
        other => panic!("Expected CorruptedZip error, got {:?}", other),
    }
}

#[test]
fn test_scan_office_non_office_zip() {
    let policy = PolicyEngine::balanced();
    let zip_data = create_test_zip(&[("hello.txt", b"world")]);
    let res = scan_office_metadata(&zip_data, &policy);
    assert_eq!(res, Err(OfficeParseError::InvalidContainer));
}

#[test]
fn test_scan_office_core_and_app_metadata() {
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
    ]);

    let findings = scan_office_metadata(&zip_data, &policy).expect("Scan should succeed");
    assert!(!findings.is_empty());

    // Check core findings
    let creator = findings.iter().find(|f| f.key == "dc:creator").unwrap();
    assert_eq!(creator.category, FindingCategory::Identity);
    assert_eq!(creator.display_value.as_deref(), Some("Alice Developer"));
    assert_eq!(creator.source, FindingSource::OfficeXml);

    let last_modified = findings.iter().find(|f| f.key == "cp:lastModifiedBy").unwrap();
    assert_eq!(last_modified.category, FindingCategory::Identity);
    assert_eq!(last_modified.display_value.as_deref(), Some("Bob Reviewer"));

    let created = findings.iter().find(|f| f.key == "dcterms:created").unwrap();
    assert_eq!(created.category, FindingCategory::Time);
    assert_eq!(created.display_value.as_deref(), Some("2026-01-01T10:00:00Z"));

    let modified = findings.iter().find(|f| f.key == "dcterms:modified").unwrap();
    assert_eq!(modified.category, FindingCategory::Time);

    let title = findings.iter().find(|f| f.key == "dc:title").unwrap();
    assert_eq!(title.category, FindingCategory::DocumentHistory);

    let subject = findings.iter().find(|f| f.key == "dc:subject").unwrap();
    assert_eq!(subject.category, FindingCategory::DocumentHistory);

    let keywords = findings.iter().find(|f| f.key == "cp:keywords").unwrap();
    assert_eq!(keywords.category, FindingCategory::DocumentHistory);

    // Check app findings
    let company = findings.iter().find(|f| f.key == "Company").unwrap();
    assert_eq!(company.category, FindingCategory::Identity);
    assert_eq!(company.display_value.as_deref(), Some("Acme Corp"));

    let manager = findings.iter().find(|f| f.key == "Manager").unwrap();
    assert_eq!(manager.category, FindingCategory::Identity);
    assert_eq!(manager.display_value.as_deref(), Some("Carol Boss"));

    let app = findings.iter().find(|f| f.key == "Application").unwrap();
    assert_eq!(app.category, FindingCategory::Software);
    assert_eq!(app.display_value.as_deref(), Some("Microsoft Office Word"));

    let app_version = findings.iter().find(|f| f.key == "AppVersion").unwrap();
    assert_eq!(app_version.category, FindingCategory::Software);

    let total_time = findings.iter().find(|f| f.key == "TotalTime").unwrap();
    assert_eq!(total_time.category, FindingCategory::DocumentHistory);
    assert_eq!(total_time.display_value.as_deref(), Some("120"));
}

#[test]
fn test_scan_office_custom_vba_comments_thumbnail() {
    let policy = PolicyEngine::balanced();
    let zip_data = create_test_zip(&[
        ("[Content_Types].xml", b"<Types></Types>"),
        ("xl/workbook.xml", b"<workbook></workbook>"),
        ("docProps/custom.xml", b"<Properties></Properties>"),
        ("xl/vbaProject.bin", b"VBA macro binary"),
        ("xl/embeddings/oleObject1.bin", b"OLE data"),
        ("xl/comments1.xml", b"<comments></comments>"),
        ("docProps/thumbnail.jpeg", b"JPEG thumbnail data"),
    ]);

    let findings = scan_office_metadata(&zip_data, &policy).expect("Scan should succeed");

    let custom = findings.iter().find(|f| f.key == "docProps/custom.xml").unwrap();
    assert_eq!(custom.category, FindingCategory::DocumentHistory);

    let vba = findings.iter().find(|f| f.key == "xl/vbaProject.bin").unwrap();
    assert_eq!(vba.category, FindingCategory::EmbeddedContent);

    let ole = findings.iter().find(|f| f.key == "xl/embeddings/oleObject1.bin").unwrap();
    assert_eq!(ole.category, FindingCategory::EmbeddedContent);

    let comments = findings.iter().find(|f| f.key == "xl/comments1.xml").unwrap();
    assert_eq!(comments.category, FindingCategory::Comments);

    let thumb = findings.iter().find(|f| f.key == "docProps/thumbnail.jpeg").unwrap();
    assert_eq!(thumb.category, FindingCategory::Thumbnail);
}
