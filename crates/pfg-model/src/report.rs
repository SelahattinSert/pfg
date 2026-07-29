use serde::{Deserialize, Serialize};
use crate::finding::Finding;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputFileMetadata {
    pub display_name: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingSummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub informational: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanReport {
    pub schema_version: u32,
    pub tool_version: String,
    pub operation: String,
    pub input: InputFileMetadata,
    pub detected_format: String,
    pub support_level: String,
    pub findings: Vec<Finding>,
    pub summary: FindingSummary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssuranceLevel {
    MetadataRemoved,
    StructurallyVerified,
    ContainerRebuilt,
    VerificationFailed,
}

impl std::fmt::Display for AssuranceLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssuranceLevel::MetadataRemoved => write!(f, "Metadata Removed"),
            AssuranceLevel::StructurallyVerified => write!(f, "Structurally Verified"),
            AssuranceLevel::ContainerRebuilt => write!(f, "Container Rebuilt"),
            AssuranceLevel::VerificationFailed => write!(f, "Verification Failed"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationStatus {
    Passed,
    Failed,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationCheck {
    pub name: String,
    pub status: VerificationStatus,
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReport {
    pub original_sha256: String,
    pub cleaned_sha256: String,
    pub original_findings_count: usize,
    pub remaining_findings_count: usize,
    pub required_removals_remaining: usize,
    pub verified: bool,
    pub assurance_level: AssuranceLevel,
    pub checks: Vec<VerificationCheck>,
    pub warnings: Vec<String>,
}
