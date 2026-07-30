use pfg_core::{scan_file, CoreError, ScanOptions};
use std::fs;

#[test]
fn test_scan_file_pipeline_with_masking() {
    let temp_dir = std::env::temp_dir().join("pfg_core_tests_masking");
    fs::create_dir_all(&temp_dir).unwrap();
    let test_file = temp_dir.join("test_sample.jpg");

    // JPEG SOI + COM marker with text
    // "Secret author\0" is 14 bytes. Length = 2 + 14 = 16 (0x00, 0x10)
    let payload = b"Secret author\0";
    let len = (payload.len() + 2) as u16;
    let [l1, l2] = len.to_be_bytes();

    let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xFE, l1, l2];
    jpeg.extend_from_slice(payload);
    jpeg.extend_from_slice(&[0xFF, 0xD9]);
    fs::write(&test_file, &jpeg).unwrap();

    // 1. Scan with include_values = false -> display_value should be masked
    let options_masked = ScanOptions {
        include_values: false,
    };
    let report_masked = scan_file(&test_file, &options_masked).expect("Scan should succeed");

    assert_eq!(report_masked.detected_format, "jpeg");
    assert_eq!(report_masked.findings.len(), 1);
    assert_eq!(report_masked.summary.medium, 1);
    assert_eq!(
        report_masked.findings[0].display_value,
        Some("Se***".to_string())
    );

    // 2. Scan with include_values = true -> display_value should NOT be masked
    let options_unmasked = ScanOptions {
        include_values: true,
    };
    let report_unmasked = scan_file(&test_file, &options_unmasked).expect("Scan should succeed");

    assert_eq!(
        report_unmasked.findings[0].display_value,
        Some("Secret author".to_string())
    );

    fs::remove_file(&test_file).ok();
}

#[test]
fn test_scan_file_symlink_denied() {
    let temp_dir = std::env::temp_dir().join("pfg_core_tests_symlink");
    fs::create_dir_all(&temp_dir).unwrap();
    let target_file = temp_dir.join("target.jpg");
    let symlink_file = temp_dir.join("link.jpg");

    let _ = fs::remove_file(&symlink_file);
    let _ = fs::remove_file(&target_file);

    fs::write(&target_file, b"test content").unwrap();

    #[cfg(unix)]
    std::os::unix::fs::symlink(&target_file, &symlink_file).unwrap();

    #[cfg(unix)]
    {
        let options = ScanOptions {
            include_values: false,
        };
        let result = scan_file(&symlink_file, &options);
        assert!(matches!(result, Err(CoreError::SymlinkDenied)));
    }

    let _ = fs::remove_file(&symlink_file);
    let _ = fs::remove_file(&target_file);
}

#[test]
fn test_scan_file_unsupported_format() {
    let temp_dir = std::env::temp_dir().join("pfg_core_tests_unsupported");
    fs::create_dir_all(&temp_dir).unwrap();
    let txt_file = temp_dir.join("hello.txt");
    fs::write(&txt_file, b"Plain text file").unwrap();

    let options = ScanOptions {
        include_values: false,
    };
    let result = scan_file(&txt_file, &options);
    assert!(matches!(result, Err(CoreError::UnsupportedFormat)));

    fs::remove_file(&txt_file).ok();
}

#[test]
fn test_scan_file_io_error() {
    let non_existent = std::env::temp_dir().join("does_not_exist_pfg_12345.jpg");
    let options = ScanOptions {
        include_values: false,
    };
    let result = scan_file(&non_existent, &options);
    assert!(matches!(result, Err(CoreError::IoError(_))));
}

#[test]
fn test_scan_file_parse_error() {
    let temp_dir = std::env::temp_dir().join("pfg_core_tests_parse_error");
    fs::create_dir_all(&temp_dir).unwrap();
    let corrupt_jpeg = temp_dir.join("corrupt.jpg");

    // JPEG SOI followed by invalid marker length
    let jpeg = vec![0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x01]; // invalid length < 2 or EOF
    fs::write(&corrupt_jpeg, &jpeg).unwrap();

    let options = ScanOptions {
        include_values: false,
    };
    let result = scan_file(&corrupt_jpeg, &options);
    assert!(matches!(result, Err(CoreError::ParseError(_))));

    fs::remove_file(&corrupt_jpeg).ok();
}
