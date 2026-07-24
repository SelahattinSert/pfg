use std::fs;
use std::io::Write;
use zip::write::FileOptions;
use zip::ZipWriter;
use pfg_core::{clean_file, scan_file, verify_files, CleanOptions, CleanProfile, ScanOptions};

fn create_sample_office_zip(format_entry: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut zip = ZipWriter::new(std::io::Cursor::new(&mut buf));
        let options = FileOptions::default();

        let core_xml = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
                   xmlns:dc="http://purl.org/dc/elements/1.1/">
    <dc:creator>Jane Doe</dc:creator>
</cp:coreProperties>"#;

        zip.start_file("[Content_Types].xml", options).unwrap();
        zip.write_all(b"<Types></Types>").unwrap();

        zip.start_file(format_entry, options).unwrap();
        zip.write_all(b"<document></document>").unwrap();

        zip.start_file("docProps/core.xml", options).unwrap();
        zip.write_all(core_xml.as_bytes()).unwrap();

        zip.finish().unwrap();
    }
    buf
}

#[test]
fn test_scan_docx_file_pipeline() {
    let temp_dir = std::env::temp_dir().join("pfg_core_docx_scan_test");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let file_path = temp_dir.join("sample.docx");
    fs::write(&file_path, create_sample_office_zip("word/document.xml")).unwrap();

    let options = ScanOptions { include_values: true };
    let report = scan_file(&file_path, &options).expect("scan_file for DOCX should succeed");

    assert_eq!(report.detected_format, "docx");
    assert!(!report.findings.is_empty());
    assert!(report.findings.iter().any(|f| f.key == "dc:creator"));

    fs::remove_dir_all(&temp_dir).ok();
}

#[test]
fn test_scan_xlsx_file_pipeline() {
    let temp_dir = std::env::temp_dir().join("pfg_core_xlsx_scan_test");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let file_path = temp_dir.join("sample.xlsx");
    fs::write(&file_path, create_sample_office_zip("xl/workbook.xml")).unwrap();

    let options = ScanOptions { include_values: true };
    let report = scan_file(&file_path, &options).expect("scan_file for XLSX should succeed");

    assert_eq!(report.detected_format, "xlsx");
    assert!(!report.findings.is_empty());

    fs::remove_dir_all(&temp_dir).ok();
}

#[test]
fn test_scan_pptx_file_pipeline() {
    let temp_dir = std::env::temp_dir().join("pfg_core_pptx_scan_test");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let file_path = temp_dir.join("sample.pptx");
    fs::write(&file_path, create_sample_office_zip("ppt/presentation.xml")).unwrap();

    let options = ScanOptions { include_values: true };
    let report = scan_file(&file_path, &options).expect("scan_file for PPTX should succeed");

    assert_eq!(report.detected_format, "pptx");
    assert!(!report.findings.is_empty());

    fs::remove_dir_all(&temp_dir).ok();
}

#[test]
fn test_clean_office_file_pipeline() {
    let temp_dir = std::env::temp_dir().join("pfg_core_office_clean_test");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let docx_path = temp_dir.join("document.docx");
    fs::write(&docx_path, create_sample_office_zip("word/document.xml")).unwrap();

    let options = CleanOptions {
        profile: CleanProfile::Balanced,
        output_dir: None,
        safe_name: false,
        overwrite: false,
    };

    let report = clean_file(&docx_path, &options).expect("clean_file for DOCX should succeed");

    assert!(report.verified_clean);
    assert!(report.original_findings_count > 0);
    assert_eq!(report.cleaned_findings_count, 0);

    let cleaned_file = temp_dir.join("document.pfg.docx");
    assert!(cleaned_file.exists(), "Cleaned DOCX file document.pfg.docx should exist");

    let v_report = verify_files(&docx_path, &cleaned_file).expect("verify_files should succeed for DOCX");
    assert!(v_report.verified_clean);
    assert_eq!(v_report.original_findings_count, report.original_findings_count);
    assert_eq!(v_report.cleaned_findings_count, 0);

    fs::remove_dir_all(&temp_dir).ok();
}
