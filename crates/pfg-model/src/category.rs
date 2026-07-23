use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingCategory {
    Location,
    Identity,
    Device,
    Time,
    Software,
    DocumentHistory,
    Comments,
    EmbeddedContent,
    Thumbnail,
    UniqueIdentifier,
    Network,
    Credentials,
    Filesystem,
    Technical,
    Unknown,
}
