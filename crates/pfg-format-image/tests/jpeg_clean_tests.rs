use pfg_format_image::{scan_jpeg_metadata, ImageParseError, sanitize_jpeg};
use pfg_policy::{CleanProfile, PolicyEngine};

fn create_test_jpeg(include_com: bool, include_app1: bool, include_app2: bool, include_app13: bool) -> Vec<u8> {
    let mut jpeg = vec![0xFF, 0xD8]; // SOI

    // APP0 (JFIF)
    let app0_payload = b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0";
    let app0_len = (app0_payload.len() + 2) as u16;
    jpeg.extend_from_slice(&[0xFF, 0xE0]);
    jpeg.extend_from_slice(&app0_len.to_be_bytes());
    jpeg.extend_from_slice(app0_payload);

    if include_app1 {
        // APP1 (EXIF)
        let app1_payload = b"Exif\0\0DummyExifDataHere";
        let app1_len = (app1_payload.len() + 2) as u16;
        jpeg.extend_from_slice(&[0xFF, 0xE1]);
        jpeg.extend_from_slice(&app1_len.to_be_bytes());
        jpeg.extend_from_slice(app1_payload);
    }

    if include_app2 {
        // APP2 (ICC profile)
        let app2_payload = b"ICC_PROFILE\0\x01\x01";
        let app2_len = (app2_payload.len() + 2) as u16;
        jpeg.extend_from_slice(&[0xFF, 0xE2]);
        jpeg.extend_from_slice(&app2_len.to_be_bytes());
        jpeg.extend_from_slice(app2_payload);
    }

    if include_app13 {
        // APP13 (Photoshop/IPTC)
        let app13_payload = b"Photoshop 3.0\0";
        let app13_len = (app13_payload.len() + 2) as u16;
        jpeg.extend_from_slice(&[0xFF, 0xED]);
        jpeg.extend_from_slice(&app13_len.to_be_bytes());
        jpeg.extend_from_slice(app13_payload);
    }

    if include_com {
        // COM (Comment)
        let com_payload = b"Secret comment\0";
        let com_len = (com_payload.len() + 2) as u16;
        jpeg.extend_from_slice(&[0xFF, 0xFE]);
        jpeg.extend_from_slice(&com_len.to_be_bytes());
        jpeg.extend_from_slice(com_payload);
    }

    // SOS (Start of Scan)
    let sos_payload = b"\x01\x01\x00\x00\x3f\x00";
    let sos_len = (sos_payload.len() + 2) as u16;
    jpeg.extend_from_slice(&[0xFF, 0xDA]);
    jpeg.extend_from_slice(&sos_len.to_be_bytes());
    jpeg.extend_from_slice(sos_payload);

    // Image Entropy Data
    jpeg.extend_from_slice(&[0x12, 0x34, 0x56, 0x78, 0x90, 0xAB]);

    // EOI (End of Image)
    jpeg.extend_from_slice(&[0xFF, 0xD9]);

    jpeg
}

#[test]
fn test_jpeg_sanitization_removes_com_and_app1() {
    let jpeg = create_test_jpeg(true, true, true, true);

    let cleaned = sanitize_jpeg(&jpeg, CleanProfile::Balanced).expect("Sanitization failed");
    let policy = PolicyEngine::balanced();
    let findings = scan_jpeg_metadata(&cleaned, &policy).expect("Scan failed");

    assert!(findings.is_empty(), "Expected 0 findings after sanitization, found {}", findings.len());

    // In Balanced mode:
    // APP0 (0xFFE0) should be present
    assert!(cleaned.windows(2).any(|w| w == [0xFF, 0xE0]));
    // APP2 (0xFFE2) should be present
    assert!(cleaned.windows(2).any(|w| w == [0xFF, 0xE2]));
    // APP1 (0xFFE1) should be stripped
    assert!(!cleaned.windows(2).any(|w| w == [0xFF, 0xE1]));
    // APP13 (0xFFED) should be stripped
    assert!(!cleaned.windows(2).any(|w| w == [0xFF, 0xED]));
    // COM (0xFFFE) should be stripped
    assert!(!cleaned.windows(2).any(|w| w == [0xFF, 0xFE]));
    // SOS (0xFFDA) and EOI (0xFFD9) should be present
    assert!(cleaned.windows(2).any(|w| w == [0xFF, 0xDA]));
    assert!(cleaned.windows(2).any(|w| w == [0xFF, 0xD9]));
}

#[test]
fn test_jpeg_sanitization_strict_profile() {
    let jpeg = create_test_jpeg(true, true, true, true);

    let cleaned = sanitize_jpeg(&jpeg, CleanProfile::Strict).expect("Sanitization failed");
    let policy = PolicyEngine::balanced();
    let findings = scan_jpeg_metadata(&cleaned, &policy).expect("Scan failed");

    assert!(findings.is_empty(), "Expected 0 findings in strict mode");

    // In Strict mode:
    // APP0 (0xFFE0) should be present
    assert!(cleaned.windows(2).any(|w| w == [0xFF, 0xE0]));
    // APP1, APP2, APP13, COM should all be stripped
    assert!(!cleaned.windows(2).any(|w| w == [0xFF, 0xE1]));
    assert!(!cleaned.windows(2).any(|w| w == [0xFF, 0xE2]));
    assert!(!cleaned.windows(2).any(|w| w == [0xFF, 0xED]));
    assert!(!cleaned.windows(2).any(|w| w == [0xFF, 0xFE]));
    // SOS and EOI present
    assert!(cleaned.windows(2).any(|w| w == [0xFF, 0xDA]));
    assert!(cleaned.windows(2).any(|w| w == [0xFF, 0xD9]));
}

#[test]
fn test_jpeg_sanitization_invalid_soi() {
    let invalid_jpeg = vec![0x00, 0x00, 0xFF, 0xD8];
    let err = sanitize_jpeg(&invalid_jpeg, CleanProfile::Balanced).unwrap_err();
    assert_eq!(err, ImageParseError::InvalidSoi);
}

#[test]
fn test_jpeg_sanitization_unexpected_eof() {
    let truncated = vec![0xFF, 0xD8, 0xFF, 0xE1, 0x00];
    let err = sanitize_jpeg(&truncated, CleanProfile::Balanced).unwrap_err();
    assert_eq!(err, ImageParseError::UnexpectedEof);
}

#[test]
fn test_jpeg_exif_orientation_extraction() {
    // Little-endian TIFF header with IFD0 containing Tag 0x0112 (Orientation) set to 6
    let mut exif_payload = Vec::new();
    exif_payload.extend_from_slice(b"Exif\0\0");
    exif_payload.extend_from_slice(b"II"); // Little-endian
    exif_payload.extend_from_slice(&42u16.to_le_bytes()); // Magic 42
    exif_payload.extend_from_slice(&8u32.to_le_bytes()); // IFD0 offset 8
    exif_payload.extend_from_slice(&1u16.to_le_bytes()); // 1 entry

    // Tag 0x0112, type 3 (SHORT), count 1, value 6
    exif_payload.extend_from_slice(&0x0112u16.to_le_bytes());
    exif_payload.extend_from_slice(&3u16.to_le_bytes());
    exif_payload.extend_from_slice(&1u32.to_le_bytes());
    exif_payload.extend_from_slice(&6u16.to_le_bytes());
    exif_payload.extend_from_slice(&[0, 0]); // Pad value field to 4 bytes

    let extracted = pfg_format_image::exif::extract_orientation(&exif_payload[6..]);
    assert_eq!(extracted, Some(6));
}
