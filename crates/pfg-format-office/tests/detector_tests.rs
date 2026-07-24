use pfg_format_office::{detect_office_format, OfficeFormat};
use std::io::Write;

fn create_mock_zip(entries: &[&str]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let options = zip::write::FileOptions::default();
        for entry in entries {
            zip.start_file(*entry, options).unwrap();
            zip.write_all(b"<xml></xml>").unwrap();
        }
        zip.finish().unwrap();
    }
    buf
}

#[test]
fn test_detect_docx() {
    let bytes = create_mock_zip(&["[Content_Types].xml", "word/document.xml"]);
    assert_eq!(detect_office_format(&bytes), Some(OfficeFormat::Docx));
}

#[test]
fn test_detect_xlsx() {
    let bytes = create_mock_zip(&["[Content_Types].xml", "xl/workbook.xml"]);
    assert_eq!(detect_office_format(&bytes), Some(OfficeFormat::Xlsx));
}

#[test]
fn test_detect_pptx() {
    let bytes = create_mock_zip(&["[Content_Types].xml", "ppt/presentation.xml"]);
    assert_eq!(detect_office_format(&bytes), Some(OfficeFormat::Pptx));
}

#[test]
fn test_detect_non_office_zip() {
    let bytes = create_mock_zip(&["some/file.txt"]);
    assert_eq!(detect_office_format(&bytes), None);
}

#[test]
fn test_detect_missing_content_types() {
    let bytes = create_mock_zip(&["word/document.xml"]);
    assert_eq!(detect_office_format(&bytes), None);
}

#[test]
fn test_detect_invalid_bytes() {
    assert_eq!(detect_office_format(b"not a zip file"), None);
    assert_eq!(detect_office_format(b""), None);
}
