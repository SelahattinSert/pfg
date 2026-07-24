#![forbid(unsafe_code)]

mod commands;

use commands::{
    clean_directory_cmd, clean_file_cmd, scan_directory_cmd, scan_file_cmd, verify_files_cmd,
};

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            scan_file_cmd,
            clean_file_cmd,
            verify_files_cmd,
            scan_directory_cmd,
            clean_directory_cmd,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
