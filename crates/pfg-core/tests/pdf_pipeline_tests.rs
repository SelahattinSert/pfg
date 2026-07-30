use lopdf::{dictionary, Document, Object, StringFormat};
use pfg_core::{clean_file, scan_file, verify_files, CleanOptions, CleanProfile, ScanOptions};
use std::fs;

fn create_sample_pdf_with_metadata() -> Vec<u8> {
    let mut doc = Document::with_version("1.5");

    let info_id = doc.add_object(dictionary! {
        "Title" => Object::String(b"Confidential Report".to_vec(), StringFormat::Literal),
        "Author" => Object::String(b"Alice Smith".to_vec(), StringFormat::Literal),
        "Creator" => Object::String(b"PDFWriter 1.0".to_vec(), StringFormat::Literal),
        "CreationDate" => Object::String(b"D:20260724120000Z".to_vec(), StringFormat::Literal),
    });

    doc.trailer.set("Info", info_id);

    let mut pdf_bytes = Vec::new();
    doc.save_to(&mut pdf_bytes).unwrap();
    pdf_bytes
}

#[test]
fn test_scan_pdf_file_pipeline() {
    let temp_dir = std::env::temp_dir().join("pfg_core_pdf_scan_test");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let pdf_path = temp_dir.join("sample.pdf");
    fs::write(&pdf_path, create_sample_pdf_with_metadata()).unwrap();

    let options = ScanOptions {
        include_values: true,
    };
    let report = scan_file(&pdf_path, &options).expect("scan_file for PDF should succeed");

    assert_eq!(report.detected_format, "pdf");
    assert!(!report.findings.is_empty());
    assert!(report.findings.iter().any(|f| f.key == "Author"));

    fs::remove_dir_all(&temp_dir).ok();
}

#[test]
fn test_clean_pdf_file_pipeline() {
    let temp_dir = std::env::temp_dir().join("pfg_core_pdf_clean_test");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let pdf_path = temp_dir.join("document.pdf");
    fs::write(&pdf_path, create_sample_pdf_with_metadata()).unwrap();

    let options = CleanOptions {
        profile: CleanProfile::Balanced,
        output_dir: None,
        safe_name: false,
        overwrite: false,
    };

    let res = clean_file(&pdf_path, &options).expect("clean_file for PDF should succeed");
    let report = res.verification;

    assert!(report.verified);
    assert!(report.original_findings_count > 0);
    assert_eq!(report.remaining_findings_count, 0);

    let cleaned_file = temp_dir.join("document.pfg.pdf");
    assert!(
        cleaned_file.exists(),
        "Cleaned PDF file document.pfg.pdf should exist"
    );

    let v_report =
        verify_files(&pdf_path, &cleaned_file).expect("verify_files should succeed for PDF");
    assert!(v_report.verified);
    assert_eq!(
        v_report.original_findings_count,
        report.original_findings_count
    );
    assert_eq!(v_report.remaining_findings_count, 0);

    fs::remove_dir_all(&temp_dir).ok();
}
