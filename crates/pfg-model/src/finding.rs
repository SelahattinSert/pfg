use serde::{Deserialize, Serialize};
use crate::category::FindingCategory;
use crate::severity::Severity;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSource {
    Exif,
    Xmp,
    Iptc,
    Comment,
    PdfInfo,
    PdfObject,
    FileSystem,
    OfficeXml,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingLocation {
    Header { segment: String },
    Offset { byte_offset: u64 },
    PdfObject { object_number: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub category: FindingCategory,
    pub severity: Severity,
    pub source: FindingSource,
    pub key: String,
    pub display_value: Option<String>,
    pub raw_value_available: bool,
    pub location: FindingLocation,
    pub risk_explanation: String,
    pub removable: bool,
}
