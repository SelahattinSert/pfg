#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand, ValueEnum};
use pfg_core::{clean_file, scan_file, verify_files, CleanOptions, CleanProfile, ScanOptions};
use pfg_model::Severity;

#[derive(Parser)]
#[command(name = "pfg", about = "Privacy File Guard - Local metadata scanner and cleaner")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a file for privacy-sensitive metadata
    Scan {
        /// Path to target file
        path: PathBuf,

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

    /// Clean privacy-sensitive metadata from a file
    Clean {
        /// Path to target file
        path: PathBuf,

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

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            format,
            report,
            fail_on,
            include_values,
        } => {
            let options = ScanOptions { include_values };
            match scan_file(&path, &options) {
                Ok(scan_report) => {
                    let json_output = match serde_json::to_string_pretty(&scan_report) {
                        Ok(json) => json,
                        Err(e) => {
                            eprintln!("Failed to serialize scan report: {}", e);
                            process::exit(3);
                        }
                    };

                    if let Some(ref report_path) = report {
                        if let Err(e) = fs::write(report_path, &json_output) {
                            eprintln!("Error writing report file: {}", e);
                            process::exit(4);
                        }
                    }

                    match format {
                        OutputFormat::Json => {
                            println!("{}", json_output);
                        }
                        OutputFormat::Text => {
                            println!("Privacy File Guard Scan Report");
                            println!("==============================");
                            println!("File: {}", scan_report.input.name);
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
                        let max_found = scan_report
                            .findings
                            .iter()
                            .map(|f| f.severity)
                            .max();

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
                    process::exit(3);
                }
            }
        }
        Commands::Clean {
            path,
            profile,
            output_dir,
            safe_name,
        } => {
            let options = CleanOptions {
                profile: profile.into(),
                output_dir,
                safe_name,
                overwrite: true,
            };

            match clean_file(&path, &options) {
                Ok(report) => {
                    println!("Privacy File Guard Clean Report");
                    println!("==============================");
                    println!("Original SHA256: {}", report.original_sha256);
                    println!("Cleaned SHA256:  {}", report.cleaned_sha256);
                    println!("Original Findings: {}", report.original_findings_count);
                    println!("Cleaned Findings:  {}", report.cleaned_findings_count);
                    println!("Verified Clean: {}", report.verified_clean);
                    println!("Assurance Level: {}", report.assurance_level);
                    process::exit(0);
                }
                Err(e) => {
                    eprintln!("Clean error: {}", e);
                    process::exit(5);
                }
            }
        }
        Commands::Verify { original, cleaned } => {
            match verify_files(&original, &cleaned) {
                Ok(report) => {
                    println!("Privacy File Guard Verification Report");
                    println!("=====================================");
                    println!("Original SHA256: {}", report.original_sha256);
                    println!("Cleaned SHA256:  {}", report.cleaned_sha256);
                    println!("Original Findings: {}", report.original_findings_count);
                    println!("Cleaned Findings:  {}", report.cleaned_findings_count);
                    println!("Verified Clean: {}", report.verified_clean);
                    println!("Assurance Level: {}", report.assurance_level);

                    if report.verified_clean {
                        process::exit(0);
                    } else {
                        process::exit(6);
                    }
                }
                Err(e) => {
                    eprintln!("Verification error: {}", e);
                    process::exit(6);
                }
            }
        }
    }
}

