#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand, ValueEnum};
use pfg_core::{scan_file, ScanOptions};
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
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[value(rename_all = "lowercase")]
enum OutputFormat {
    Text,
    Json,
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
    }
}
