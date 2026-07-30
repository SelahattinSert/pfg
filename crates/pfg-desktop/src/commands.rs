#![forbid(unsafe_code)]

use pfg_core::{
    clean_directory, clean_file, scan_directory, scan_file, verify_files, BatchCleanOptions,
    BatchCleanReport, BatchScanOptions, BatchScanReport, CleanOptions, CleanProfile, ScanOptions,
    VerificationReport,
};
use pfg_model::ScanReport;
use std::path::PathBuf;

fn parse_profile(profile_str: &str) -> Result<CleanProfile, String> {
    match profile_str.to_lowercase().as_str() {
        "balanced" => Ok(CleanProfile::Balanced),
        "strict" => Ok(CleanProfile::Strict),
        other => Err(format!(
            "Invalid clean profile '{}'. Expected 'balanced' or 'strict'",
            other
        )),
    }
}

#[tauri::command]
pub fn select_file_dialog_cmd() -> Result<Option<String>, String> {
    let file = rfd::FileDialog::new()
        .add_filter(
            "Supported Privacy Files",
            &["jpg", "jpeg", "png", "webp", "pdf", "docx", "xlsx", "pptx"],
        )
        .pick_file();
    Ok(file.map(|p| p.to_string_lossy().to_string()))
}

#[tauri::command]
pub fn select_folder_dialog_cmd() -> Result<Option<String>, String> {
    let folder = rfd::FileDialog::new().pick_folder();
    Ok(folder.map(|p| p.to_string_lossy().to_string()))
}

#[tauri::command]
pub fn scan_file_cmd(path: String, include_values: bool) -> Result<ScanReport, String> {
    let path_buf = PathBuf::from(&path);
    let options = ScanOptions { include_values };
    scan_file(&path_buf, &options).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn clean_file_cmd(
    path: String,
    profile: String,
    output_dir: Option<String>,
    safe_name: bool,
) -> Result<VerificationReport, String> {
    let path_buf = PathBuf::from(&path);
    let clean_profile = parse_profile(&profile)?;
    let output_dir_buf = output_dir.map(PathBuf::from);
    let options = CleanOptions {
        profile: clean_profile,
        output_dir: output_dir_buf,
        safe_name,
        overwrite: true,
    };
    clean_file(&path_buf, &options)
        .map(|res| res.verification)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn verify_files_cmd(
    original_path: String,
    cleaned_path: String,
) -> Result<VerificationReport, String> {
    let orig_buf = PathBuf::from(&original_path);
    let cleaned_buf = PathBuf::from(&cleaned_path);
    verify_files(&orig_buf, &cleaned_buf).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn scan_directory_cmd(
    path: String,
    recursive: bool,
    jobs: Option<usize>,
    ignore_patterns: Vec<String>,
) -> Result<BatchScanReport, String> {
    let path_buf = PathBuf::from(&path);
    let options = BatchScanOptions {
        recursive,
        jobs,
        include_values: false,
        ignore_patterns,
    };
    scan_directory(&path_buf, &options).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn clean_directory_cmd(
    path: String,
    recursive: bool,
    jobs: Option<usize>,
    profile: String,
    in_place: bool,
) -> Result<BatchCleanReport, String> {
    let path_buf = PathBuf::from(&path);
    let clean_profile = parse_profile(&profile)?;
    let options = BatchCleanOptions {
        recursive,
        jobs,
        profile: clean_profile,
        output_dir: None,
        in_place,
        safe_name: false,
        overwrite: true,
    };
    clean_directory(&path_buf, &options).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn create_temp_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("{}_{}", prefix, nanos));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn create_dummy_jpeg(path: &PathBuf) {
        let jpeg_bytes: [u8; 17] = [
            0xFF, 0xD8, // SOI
            0xFF, 0xFE, 0x00, 0x0B, // COM marker + len (11 bytes)
            0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x6F, 0x6D, 0x6D, // "Test Comm"
            0xFF, 0xD9, // EOI
        ];
        let mut file = File::create(path).unwrap();
        file.write_all(&jpeg_bytes).unwrap();
    }

    #[test]
    fn test_scan_file_cmd_success() {
        let temp_dir = create_temp_dir("pfg_test_scan");
        let file_path = temp_dir.join("test.jpg");
        create_dummy_jpeg(&file_path);

        let result = scan_file_cmd(file_path.to_str().unwrap().to_string(), true);
        assert!(result.is_ok());
        let report = result.unwrap();
        assert_eq!(report.input.display_name, "test.jpg");

        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_scan_file_cmd_nonexistent() {
        let result = scan_file_cmd("/nonexistent/file/path/foo.bar".to_string(), false);
        assert!(result.is_err());
    }

    #[test]
    fn test_clean_file_cmd_invalid_profile() {
        let result = clean_file_cmd(
            "/some/path.jpg".to_string(),
            "invalid_profile".to_string(),
            None,
            false,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid clean profile"));
    }

    #[test]
    fn test_clean_file_cmd_success() {
        let temp_dir = create_temp_dir("pfg_test_clean");
        let file_path = temp_dir.join("test_clean.jpg");
        create_dummy_jpeg(&file_path);

        let result = clean_file_cmd(
            file_path.to_str().unwrap().to_string(),
            "balanced".to_string(),
            Some(temp_dir.to_str().unwrap().to_string()),
            false,
        );
        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(report.verified);

        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_verify_files_cmd_success() {
        let temp_dir = create_temp_dir("pfg_test_verify");
        let orig_path = temp_dir.join("orig.jpg");
        create_dummy_jpeg(&orig_path);

        let clean_report = clean_file_cmd(
            orig_path.to_str().unwrap().to_string(),
            "strict".to_string(),
            Some(temp_dir.to_str().unwrap().to_string()),
            false,
        )
        .unwrap();

        // Standard output name for clean_file is {stem}.pfg.{ext}
        let cleaned_path = temp_dir.join("orig.pfg.jpg");
        assert!(cleaned_path.exists());

        let verify_res = verify_files_cmd(
            orig_path.to_str().unwrap().to_string(),
            cleaned_path.to_str().unwrap().to_string(),
        );
        assert!(verify_res.is_ok());
        let v_report = verify_res.unwrap();
        assert_eq!(v_report.original_sha256, clean_report.original_sha256);
        assert_eq!(v_report.cleaned_sha256, clean_report.cleaned_sha256);

        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_scan_directory_cmd_success() {
        let temp_dir = create_temp_dir("pfg_test_scan_dir");
        let f1 = temp_dir.join("img1.jpg");
        let f2 = temp_dir.join("img2.jpg");
        create_dummy_jpeg(&f1);
        create_dummy_jpeg(&f2);

        let scan_res = scan_directory_cmd(
            temp_dir.to_str().unwrap().to_string(),
            true,
            Some(2),
            vec!["ignore_me".to_string()],
        );
        assert!(scan_res.is_ok());
        let report = scan_res.unwrap();
        assert_eq!(report.files_scanned, 2);

        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_clean_directory_cmd_success() {
        let temp_dir = create_temp_dir("pfg_test_clean_dir");
        let f1 = temp_dir.join("img1.jpg");
        create_dummy_jpeg(&f1);

        let clean_res = clean_directory_cmd(
            temp_dir.to_str().unwrap().to_string(),
            false,
            Some(1),
            "balanced".to_string(),
            true,
        );
        assert!(clean_res.is_ok());
        let report = clean_res.unwrap();
        assert_eq!(report.total_files, 1);

        let _ = fs::remove_dir_all(temp_dir);
    }
}
