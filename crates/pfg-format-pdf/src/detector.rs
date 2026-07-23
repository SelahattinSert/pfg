pub fn detect_pdf_format(buffer: &[u8]) -> bool {
    buffer.starts_with(b"%PDF-")
}
