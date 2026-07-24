use std::fs;
use std::path::PathBuf;
use pfg_core::{clean_directory, BatchCleanOptions};
use pfg_policy::CleanProfile;

#[test]
fn test_batch_directory_cleaning() {
    let temp_dir = std::env::temp_dir().join("pfg_batch_clean_test");
    fs::create_dir_all(&temp_dir).unwrap();

    let sample_jpg = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/images/sample.jpg");
    let img1 = temp_dir.join("test1.jpg");
    fs::copy(&sample_jpg, &img1).unwrap();

    let opts = BatchCleanOptions {
        recursive: true,
        jobs: Some(2),
        profile: CleanProfile::Balanced,
        output_dir: None,
        in_place: false,
        safe_name: false,
        overwrite: true,
    };

    let report = clean_directory(&temp_dir, &opts).unwrap();
    assert!(report.cleaned_files >= 1);
    assert_eq!(report.verified_clean_count, report.cleaned_files);

    fs::remove_dir_all(&temp_dir).ok();
}
