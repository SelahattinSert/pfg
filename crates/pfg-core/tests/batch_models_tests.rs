use std::path::PathBuf;
use pfg_core::{BatchScanOptions, BatchCleanOptions};

#[test]
fn test_batch_options_instantiation() {
    let scan_opts = BatchScanOptions {
        recursive: true,
        jobs: Some(4),
        include_values: false,
        ignore_patterns: vec![".git".to_string()],
    };
    assert!(scan_opts.recursive);

    let clean_opts = BatchCleanOptions {
        recursive: true,
        jobs: Some(4),
        profile: pfg_policy::CleanProfile::Balanced,
        output_dir: Some(PathBuf::from("/tmp")),
        in_place: false,
        safe_name: false,
        overwrite: true,
    };
    assert!(clean_opts.overwrite);
}
