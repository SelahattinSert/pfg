#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand, ValueEnum};
use pfg_core::{
    clean_directory, clean_file, scan_directory, scan_file, verify_files, BatchCleanOptions,
    BatchScanOptions, CleanOptions, CleanProfile, CoreError, ScanOptions,
};
use pfg_model::Severity;

#[derive(Parser)]
#[command(
    name = "pfg",
    about = "Privacy File Guard - Local metadata scanner and cleaner"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a file or directory for privacy-sensitive metadata
    Scan {
        /// Path to target file or directory
        path: PathBuf,

        /// Process directory recursively
        #[arg(short = 'r', long = "recursive")]
        recursive: bool,

        /// Number of parallel worker threads
        #[arg(short = 'j', long = "jobs")]
        jobs: Option<usize>,

        /// Ignore patterns for file/directory names
        #[arg(long = "ignore")]
        ignore: Vec<String>,

        /// Output format (text or json)
        #[arg(short = 'f', long = "format", default_value = "text")]
        format: OutputFormat,

        /// Save report to specified JSON file
        #[arg(short = 'o', long = "report")]
        report: Option<PathBuf>,

        /// Fail with exit code 1 if findings reach or exceed threshold
        #[arg(long = "fail-on")]
        fail_on: Option<SeverityArg>,

        /// Include raw unmasked values in output
        #[arg(long = "include-values")]
        include_values: bool,
    },

    /// Clean privacy-sensitive metadata from a file or directory
    Clean {
        /// Path to target file or directory
        path: PathBuf,

        /// Process directory recursively
        #[arg(short = 'r', long = "recursive")]
        recursive: bool,

        /// Number of parallel worker threads
        #[arg(short = 'j', long = "jobs")]
        jobs: Option<usize>,

        /// Clean files in-place replacing original files
        #[arg(long = "in-place")]
        in_place: bool,

        /// Sanitization profile (balanced or strict)
        #[arg(long = "profile", default_value = "balanced")]
        profile: ProfileArg,

        /// Output directory for sanitized file
        #[arg(short = 'o', long = "output-dir")]
        output_dir: Option<PathBuf>,

        /// Use SHA-256 hash based safe filename
        #[arg(long = "safe-name")]
        safe_name: bool,
    },

    /// Verify that a cleaned file contains no residual sensitive metadata
    Verify {
        /// Path to original file
        original: PathBuf,

        /// Path to cleaned file
        cleaned: PathBuf,
    },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[value(rename_all = "lowercase")]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[value(rename_all = "lowercase")]
enum ProfileArg {
    Balanced,
    Strict,
}

impl From<ProfileArg> for CleanProfile {
    fn from(arg: ProfileArg) -> Self {
        match arg {
            ProfileArg::Balanced => CleanProfile::Balanced,
            ProfileArg::Strict => CleanProfile::Strict,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[value(rename_all = "lowercase")]
enum SeverityArg {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl From<SeverityArg> for Severity {
    fn from(arg: SeverityArg) -> Self {
        match arg {
            SeverityArg::Informational => Severity::Informational,
            SeverityArg::Low => Severity::Low,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::High => Severity::High,
            SeverityArg::Critical => Severity::Critical,
        }
    }
}

fn exit_code_for_error(err: &CoreError) -> i32 {
    match err {
        CoreError::IoError(_) | CoreError::SymlinkDenied => 2,
        CoreError::UnsupportedFormat => 3,
        CoreError::ParseError(_) => 4,
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            recursive,
            jobs,
            ignore,
            format,
            report,
            fail_on,
            include_values,
        } => {
            if path.is_dir() {
                let opts = BatchScanOptions {
                    recursive,
                    jobs,
                    include_values,
                    ignore_patterns: ignore,
                };
                match scan_directory(&path, &opts) {
                    Ok(batch_report) => {
                        let json_output = match serde_json::to_string_pretty(&batch_report) {
                            Ok(json) => json,
                            Err(e) => {
                                eprintln!("Failed to serialize batch report: {}", e);
                                process::exit(4);
                            }
                        };

                        if let Some(ref report_path) = report {
                            if let Err(e) = fs::write(report_path, &json_output) {
                                eprintln!("Error writing report file: {}", e);
                                process::exit(2);
                            }
                        }

                        match format {
                            OutputFormat::Json => {
                                println!("{}", json_output);
                            }
                            OutputFormat::Text => {
                                println!("Privacy File Guard Batch Scan Report");
                                println!("====================================");
                                println!(
                                    "Target Directory: {}",
                                    batch_report.target_path.display()
                                );
                                println!("Files Scanned: {}", batch_report.files_scanned);
                                println!("Files Skipped: {}", batch_report.files_skipped);
                                println!("Total Findings: {}\n", batch_report.total_findings);
                            }
                        }
                        process::exit(0);
                    }
                    Err(e) => {
                        eprintln!("Batch scan error: {}", e);
                        process::exit(exit_code_for_error(&e));
                    }
                }
            } else {
                let options = ScanOptions { include_values };
                match scan_file(&path, &options) {
                    Ok(scan_report) => {
                        let json_output = match serde_json::to_string_pretty(&scan_report) {
                            Ok(json) => json,
                            Err(e) => {
                                eprintln!("Failed to serialize scan report: {}", e);
                                process::exit(4);
                            }
                        };

                        if let Some(ref report_path) = report {
                            if let Err(e) = fs::write(report_path, &json_output) {
                                eprintln!("Error writing report file: {}", e);
                                process::exit(2);
                            }
                        }

                        match format {
                            OutputFormat::Json => {
                                println!("{}", json_output);
                            }
                            OutputFormat::Text => {
                                println!("Privacy File Guard Scan Report");
                                println!("==============================");
                                println!("File: {}", scan_report.input.display_name);
                                println!("Format: {}", scan_report.detected_format);
                                println!("Size: {} bytes", scan_report.input.size);
                                println!("Findings: {}\n", scan_report.findings.len());

                                for finding in &scan_report.findings {
                                    println!(
                                        "[{:?}] {} (Source: {:?})",
                                        finding.severity, finding.key, finding.source
                                    );
                                    if let Some(ref val) = finding.display_value {
                                        println!("  Value: {}", val);
                                    }
                                    println!("  Risk: {}", finding.risk_explanation);
                                }
                            }
                        }

                        if let Some(threshold_arg) = fail_on {
                            let threshold_severity: Severity = threshold_arg.into();
                            let max_found = scan_report.findings.iter().map(|f| f.severity).max();

                            if let Some(max_sev) = max_found {
                                if max_sev >= threshold_severity {
                                    process::exit(1);
                                }
                            }
                        }

                        process::exit(0);
                    }
                    Err(e) => {
                        eprintln!("Scan error: {}", e);
                        process::exit(exit_code_for_error(&e));
                    }
                }
            }
        }
        Commands::Clean {
            path,
            recursive,
            jobs,
            in_place,
            profile,
            output_dir,
            safe_name,
        } => {
            if path.is_dir() {
                let opts = BatchCleanOptions {
                    recursive,
                    jobs,
                    profile: profile.into(),
                    output_dir,
                    in_place,
                    safe_name,
                    overwrite: true,
                };
                match clean_directory(&path, &opts) {
                    Ok(batch_report) => {
                        println!("Privacy File Guard Batch Clean Report");
                        println!("====================================");
                        println!("Target Directory: {}", batch_report.target_path.display());
                        println!("Total Files:   {}", batch_report.total_files);
                        println!("Cleaned Files: {}", batch_report.cleaned_files);
                        println!("Verified Clean: {}", batch_report.verified_clean_count);
                        println!("Failed Files:  {}", batch_report.failed_files);
                        process::exit(0);
                    }
                    Err(e) => {
                        eprintln!("Batch clean error: {}", e);
                        process::exit(exit_code_for_error(&e));
                    }
                }
            } else {
                let options = CleanOptions {
                    profile: profile.into(),
                    output_dir,
                    safe_name,
                    overwrite: true,
                };

                match clean_file(&path, &options) {
                    Ok(report) => {
                        if in_place && options.output_dir.is_none() {
                            let ext_str = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                            let file_stem =
                                path.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
                            let generated_name = if options.safe_name {
                                format!("{}.{}", &report.cleaned_sha256[..12], ext_str)
                            } else if ext_str.is_empty() {
                                format!("{}.pfg", file_stem)
                            } else {
                                format!("{}.pfg.{}", file_stem, ext_str)
                            };
                            let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
                            let generated_path = parent.join(generated_name);
                            if generated_path.exists() && generated_path != path {
                                if let Err(e) = fs::rename(&generated_path, &path) {
                                    eprintln!("Failed to perform in-place replacement: {}", e);
                                    process::exit(2);
                                }
                            }
                        }
                        println!("Privacy File Guard Clean Report");
                        println!("==============================");
                        println!("Original SHA256: {}", report.original_sha256);
                        println!("Cleaned SHA256:  {}", report.cleaned_sha256);
                        println!("Original Findings: {}", report.original_findings_count);
                        println!("Remaining Findings: {}", report.remaining_findings_count);
                        println!("Verified Clean: {}", report.verified);
                        println!("Assurance Level: {}", report.assurance_level);
                        process::exit(0);
                    }
                    Err(e) => {
                        eprintln!("Clean error: {}", e);
                        process::exit(exit_code_for_error(&e));
                    }
                }
            }
        }
        Commands::Verify { original, cleaned } => match verify_files(&original, &cleaned) {
            Ok(report) => {
                println!("Privacy File Guard Verification Report");
                println!("=====================================");
                println!("Original SHA256: {}", report.original_sha256);
                println!("Cleaned SHA256:  {}", report.cleaned_sha256);
                println!("Original Findings: {}", report.original_findings_count);
                println!("Remaining Findings: {}", report.remaining_findings_count);
                println!("Verified Clean: {}", report.verified);
                println!("Assurance Level: {}", report.assurance_level);

                if report.verified {
                    process::exit(0);
                } else {
                    process::exit(6);
                }
            }
            Err(e) => {
                eprintln!("Verification error: {}", e);
                process::exit(exit_code_for_error(&e));
            }
        },
    }
}
