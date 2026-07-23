use pfg_model::{FindingCategory, Severity};

pub fn categorize_severity(category: FindingCategory, key: &str) -> Severity {
    match category {
        FindingCategory::Credentials | FindingCategory::Network => Severity::Critical,
        FindingCategory::Location
        | FindingCategory::Identity
        | FindingCategory::EmbeddedContent => Severity::High,
        FindingCategory::Device
        | FindingCategory::Time
        | FindingCategory::Comments
        | FindingCategory::DocumentHistory
        | FindingCategory::UniqueIdentifier => {
            if key.contains("Serial") || key.contains("ID") {
                Severity::High
            } else {
                Severity::Medium
            }
        }
        FindingCategory::Software
        | FindingCategory::Filesystem
        | FindingCategory::Thumbnail => Severity::Low,
        FindingCategory::Technical | FindingCategory::Unknown => Severity::Informational,
    }
}
