use pfg_core::{clean_file, verify_files, CleanOptions};
use pfg_policy::CleanProfile;
use std::fs;

fn create_test_jpeg() -> Vec<u8> {
    let mut jpeg = vec![0xFF, 0xD8]; // SOI

    // APP0 (JFIF)
    let app0_payload = b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0";
    let app0_len = (app0_payload.len() + 2) as u16;
    jpeg.extend_from_slice(&[0xFF, 0xE0]);
    jpeg.extend_from_slice(&app0_len.to_be_bytes());
    jpeg.extend_from_slice(app0_payload);

    // APP1 (EXIF)
    let app1_payload = b"Exif\0\0DummyExifDataHere";
    let app1_len = (app1_payload.len() + 2) as u16;
    jpeg.extend_from_slice(&[0xFF, 0xE1]);
    jpeg.extend_from_slice(&app1_len.to_be_bytes());
    jpeg.extend_from_slice(app1_payload);

    // COM (Comment)
    let com_payload = b"Secret comment\0";
    let com_len = (com_payload.len() + 2) as u16;
    jpeg.extend_from_slice(&[0xFF, 0xFE]);
    jpeg.extend_from_slice(&com_len.to_be_bytes());
    jpeg.extend_from_slice(com_payload);

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
fn test_clean_file_atomic_and_verification() {
    let temp_dir = std::env::temp_dir().join("pfg_clean_tests_atomic");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let test_file = temp_dir.join("photo.jpg");
    fs::write(&test_file, create_test_jpeg()).unwrap();

    let options = CleanOptions {
        profile: CleanProfile::Balanced,
        output_dir: None,
        safe_name: false,
        overwrite: false,
    };

    let res = clean_file(&test_file, &options).expect("clean_file failed");
    let report = res.verification;
    assert!(report.verified);
    assert!(report.original_findings_count > 0);
    assert_eq!(report.remaining_findings_count, 0);
    assert_ne!(report.original_sha256, report.cleaned_sha256);

    let cleaned_file = temp_dir.join("photo.pfg.jpg");
    assert!(cleaned_file.exists());

    let v_report = verify_files(&test_file, &cleaned_file).expect("verify_files failed");
    assert!(v_report.verified);
    assert_eq!(
        v_report.original_findings_count,
        report.original_findings_count
    );
    assert_eq!(v_report.remaining_findings_count, 0);

    fs::remove_dir_all(&temp_dir).ok();
}

#[test]
fn test_clean_file_symlink_denied() {
    #[cfg(unix)]
    {
        use pfg_core::CoreError;
        use std::os::unix::fs::symlink;

        let temp_dir = std::env::temp_dir().join("pfg_clean_tests_symlink");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let target_file = temp_dir.join("target.jpg");
        fs::write(&target_file, b"dummy").unwrap();

        let symlink_file = temp_dir.join("symlink.jpg");
        symlink(&target_file, &symlink_file).unwrap();

        let options = CleanOptions {
            profile: CleanProfile::Balanced,
            output_dir: None,
            safe_name: false,
            overwrite: false,
        };

        let result = clean_file(&symlink_file, &options);
        assert!(matches!(result, Err(CoreError::SymlinkDenied)));

        fs::remove_dir_all(&temp_dir).ok();
    }
}

#[test]
fn test_clean_file_safe_name() {
    let temp_dir = std::env::temp_dir().join("pfg_clean_tests_safename");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let test_file = temp_dir.join("photo.jpg");
    fs::write(&test_file, create_test_jpeg()).unwrap();

    let options = CleanOptions {
        profile: CleanProfile::Balanced,
        output_dir: None,
        safe_name: true,
        overwrite: false,
    };

    let res = clean_file(&test_file, &options).unwrap();
    assert!(res.verification.verified);

    let entries: Vec<_> = fs::read_dir(&temp_dir)
        .unwrap()
        .map(|r| r.unwrap().file_name().to_string_lossy().to_string())
        .collect();

    assert_eq!(entries.len(), 2);
    assert!(entries
        .iter()
        .any(|name| name != "photo.jpg" && name.ends_with(".jpg")));
    assert!(!entries.contains(&"photo.pfg.jpg".to_string()));

    fs::remove_dir_all(&temp_dir).ok();
}

#[test]
fn test_clean_file_overwrite_false_fails_if_exists() {
    let temp_dir = std::env::temp_dir().join("pfg_clean_tests_overwrite");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let test_file = temp_dir.join("photo.jpg");
    fs::write(&test_file, create_test_jpeg()).unwrap();

    let target_file = temp_dir.join("photo.pfg.jpg");
    fs::write(&target_file, b"already exists").unwrap();

    let options = CleanOptions {
        profile: CleanProfile::Balanced,
        output_dir: None,
        safe_name: false,
        overwrite: false,
    };

    let result = clean_file(&test_file, &options);
    assert!(result.is_err());

    fs::remove_dir_all(&temp_dir).ok();
}
