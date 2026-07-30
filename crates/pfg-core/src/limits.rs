#[derive(Debug, Clone, Copy)]
pub struct ResourceLimits {
    pub max_file_size: u64,
    pub max_uncompressed_size: u64,
    pub max_zip_entries: usize,
    pub max_pdf_objects: usize,
    pub max_pdf_pages: usize,
    pub max_worker_threads: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_file_size: 500 * 1024 * 1024,         // 500 MB
            max_uncompressed_size: 500 * 1024 * 1024, // 500 MB
            max_zip_entries: 10_000,
            max_pdf_objects: 500_000,
            max_pdf_pages: 10_000,
            max_worker_threads: 64,
        }
    }
}
