use pfg_format_pdf::detect_pdf_format;

#[test]
fn test_detect_pdf_valid_magic_bytes() {
    assert!(detect_pdf_format(b"%PDF-1.4\n1 0 obj\n"));
    assert!(detect_pdf_format(b"%PDF-1.7 header"));
    assert!(detect_pdf_format(b"%PDF-2.0 header"));
    assert!(detect_pdf_format(b"%PDF-"));
}

#[test]
fn test_detect_pdf_invalid_magic_bytes() {
    assert!(!detect_pdf_format(b""));
    assert!(!detect_pdf_format(b"%PDF"));
    assert!(!detect_pdf_format(b"PDF-1.4"));
    assert!(!detect_pdf_format(b"\x89PNG\r\n\x1a\n"));
    assert!(!detect_pdf_format(b"\xFF\xD8\xFF\xE0"));
}
