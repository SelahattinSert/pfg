use pfg_core::{scan_directory, BatchScanOptions};
use std::fs;
use std::path::PathBuf;

#[test]
fn test_batch_directory_scanning() {
    let temp_dir = std::env::temp_dir().join("pfg_batch_scan_test");
    fs::create_dir_all(&temp_dir).unwrap();

    let sample_jpg =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/images/sample.jpg");
    let img1 = temp_dir.join("test1.jpg");
    fs::copy(&sample_jpg, &img1).unwrap();

    let opts = BatchScanOptions {
        recursive: true,
        jobs: Some(2),
        include_values: false,
        ignore_patterns: vec![],
    };

    let report = scan_directory(&temp_dir, &opts).unwrap();
    assert!(report.files_scanned >= 1);
    assert_eq!(report.target_path, temp_dir);

    fs::remove_dir_all(&temp_dir).ok();
}
