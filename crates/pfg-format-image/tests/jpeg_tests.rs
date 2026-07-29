use pfg_format_image::{detect_format, scan_jpeg_metadata, ImageFormat, ImageParseError};
use pfg_model::{FindingCategory, FindingSource, Severity};
use pfg_policy::PolicyEngine;

fn build_jpeg_with_segments(segments: &[(u8, &[u8])]) -> Vec<u8> {
    let mut buf = vec![0xFF, 0xD8]; // SOI
    for &(marker, payload) in segments {
        buf.push(0xFF);
        buf.push(marker);
        let len = (payload.len() + 2) as u16;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(payload);
    }
    buf.extend_from_slice(&[0xFF, 0xD9]); // EOI
    buf
}

#[test]
fn test_detect_format() {
    let jpeg_bytes = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
    assert_eq!(detect_format(&jpeg_bytes), Some(ImageFormat::Jpeg));

    let png_bytes = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00];
    assert_eq!(detect_format(&png_bytes), Some(ImageFormat::Png));

    let webp_bytes = b"RIFF1234WEBPVP8 ";
    assert_eq!(detect_format(webp_bytes), Some(ImageFormat::WebP));

    let unknown_bytes = [0x00, 0x01, 0x02, 0x03];
    assert_eq!(detect_format(&unknown_bytes), None);
}

#[test]
fn test_scan_jpeg_invalid_soi() {
    let policy = PolicyEngine::balanced();
    let invalid_bytes = [0x00, 0x00, 0xFF, 0xD8];
    assert_eq!(
        scan_jpeg_metadata(&invalid_bytes, &policy),
        Err(ImageParseError::InvalidSoi)
    );
}

#[test]
fn test_scan_jpeg_com_segment() {
    let policy = PolicyEngine::balanced();
    let comment_text = "Privacy Test Comment";
    let jpeg_bytes = build_jpeg_with_segments(&[(0xFE, comment_text.as_bytes())]);

    let findings = scan_jpeg_metadata(&jpeg_bytes, &policy).expect("Should parse metadata");
    assert!(!findings.is_empty(), "Should find COM comment finding");

    let com_finding = findings
        .iter()
        .find(|f| f.source == FindingSource::Comment)
        .expect("FindingSource::Comment should be present");

    assert_eq!(com_finding.category, FindingCategory::Comments);
    assert_eq!(
        com_finding.display_value.as_deref(),
        Some("Privacy Test Comment")
    );
    assert_eq!(com_finding.severity, Severity::Medium);
}

#[test]
fn test_scan_jpeg_exif_segment() {
    let policy = PolicyEngine::balanced();

    // Construct valid EXIF payload starting with "Exif\0\0" followed by TIFF header (Little Endian)
    let mut exif_payload = Vec::new();
    exif_payload.extend_from_slice(b"Exif\0\0");

    // TIFF Header (8 bytes)
    exif_payload.extend_from_slice(b"II"); // Little endian
    exif_payload.extend_from_slice(&42u16.to_le_bytes()); // Magic
    exif_payload.extend_from_slice(&8u32.to_le_bytes()); // IFD0 offset

    // IFD0 at offset 8 relative to tiff_start
    let num_entries: u16 = 1;
    exif_payload.extend_from_slice(&num_entries.to_le_bytes());

    // Entry 1: Make (Tag 0x010F), Type ASCII (2), Count 10, Value Offset = 8 + 2 + 12 + 4 = 26
    let tag_make: u16 = 0x010F;
    let type_ascii: u16 = 2;
    let count: u32 = 10;
    let val_offset: u32 = 26; // relative to tiff_start

    exif_payload.extend_from_slice(&tag_make.to_le_bytes());
    exif_payload.extend_from_slice(&type_ascii.to_le_bytes());
    exif_payload.extend_from_slice(&count.to_le_bytes());
    exif_payload.extend_from_slice(&val_offset.to_le_bytes());

    // Next IFD offset: 0
    exif_payload.extend_from_slice(&0u32.to_le_bytes());

    // Value at offset 26
    exif_payload.extend_from_slice(b"TestBrand\0");

    let jpeg_bytes = build_jpeg_with_segments(&[(0xE1, &exif_payload)]);
    let findings = scan_jpeg_metadata(&jpeg_bytes, &policy).expect("Should parse EXIF metadata");

    let make_finding = findings
        .iter()
        .find(|f| f.key == "Make")
        .expect("Make EXIF tag should be found");

    assert_eq!(make_finding.category, FindingCategory::Device);
    assert_eq!(make_finding.source, FindingSource::Exif);
    assert_eq!(make_finding.display_value.as_deref(), Some("TestBrand"));
}

#[test]
fn test_scan_jpeg_xmp_segment() {
    let policy = PolicyEngine::balanced();

    let mut xmp_payload = Vec::new();
    xmp_payload.extend_from_slice(b"http://ns.adobe.com/xap/1.0/\0");
    xmp_payload.extend_from_slice(
        b"<x:xmpmeta><rdf:RDF><rdf:Description dc:creator=\"Alice\"/></rdf:RDF></x:xmpmeta>",
    );

    let jpeg_bytes = build_jpeg_with_segments(&[(0xE1, &xmp_payload)]);
    let findings = scan_jpeg_metadata(&jpeg_bytes, &policy).expect("Should parse XMP metadata");

    assert!(!findings.is_empty(), "Should return XMP findings");
    let xmp_finding = findings
        .iter()
        .find(|f| f.source == FindingSource::Xmp)
        .expect("FindingSource::Xmp should be present");

    assert_eq!(xmp_finding.source, FindingSource::Xmp);
}

#[test]
fn test_scan_jpeg_unexpected_eof() {
    let policy = PolicyEngine::balanced();
    // SOI followed by truncated APP1 marker (missing payload)
    let truncated_bytes = [0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0xFF];
    assert_eq!(
        scan_jpeg_metadata(&truncated_bytes, &policy),
        Err(ImageParseError::UnexpectedEof)
    );
}
