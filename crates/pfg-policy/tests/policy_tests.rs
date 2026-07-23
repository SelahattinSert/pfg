use pfg_model::{FindingCategory, Severity};
use pfg_policy::PolicyEngine;

#[test]
fn test_critical_severity_categories() {
    let engine = PolicyEngine::balanced();
    assert_eq!(
        engine.categorize_severity(FindingCategory::Credentials, "api_key"),
        Severity::Critical
    );
    assert_eq!(
        engine.categorize_severity(FindingCategory::Network, "ip_address"),
        Severity::Critical
    );
}

#[test]
fn test_high_severity_categories() {
    let engine = PolicyEngine::balanced();
    assert_eq!(
        engine.categorize_severity(FindingCategory::Location, "GPS Latitude"),
        Severity::High
    );
    assert_eq!(
        engine.categorize_severity(FindingCategory::Identity, "Author"),
        Severity::High
    );
    assert_eq!(
        engine.categorize_severity(FindingCategory::EmbeddedContent, "OLE Object"),
        Severity::High
    );
}

#[test]
fn test_conditional_high_or_medium_categories() {
    let engine = PolicyEngine::balanced();

    // Key contains "Serial" or "ID" -> High
    assert_eq!(
        engine.categorize_severity(FindingCategory::Device, "Device Serial Number"),
        Severity::High
    );
    assert_eq!(
        engine.categorize_severity(FindingCategory::UniqueIdentifier, "UUID"),
        Severity::High
    );
    assert_eq!(
        engine.categorize_severity(FindingCategory::Time, "Creation Date ID"),
        Severity::High
    );
    assert_eq!(
        engine.categorize_severity(FindingCategory::Comments, "Author ID Note"),
        Severity::High
    );
    assert_eq!(
        engine.categorize_severity(FindingCategory::DocumentHistory, "Revision Serial"),
        Severity::High
    );

    // Key does NOT contain "Serial" or "ID" -> Medium
    assert_eq!(
        engine.categorize_severity(FindingCategory::Device, "Camera Model"),
        Severity::Medium
    );
    assert_eq!(
        engine.categorize_severity(FindingCategory::Time, "Modify Date"),
        Severity::Medium
    );
    assert_eq!(
        engine.categorize_severity(FindingCategory::Comments, "User Comment"),
        Severity::Medium
    );
    assert_eq!(
        engine.categorize_severity(FindingCategory::DocumentHistory, "Last Saved By"),
        Severity::Medium
    );
    assert_eq!(
        engine.categorize_severity(FindingCategory::UniqueIdentifier, "Hash"),
        Severity::Medium
    );
}

#[test]
fn test_low_severity_categories() {
    let engine = PolicyEngine::balanced();
    assert_eq!(
        engine.categorize_severity(FindingCategory::Software, "Software Version"),
        Severity::Low
    );
    assert_eq!(
        engine.categorize_severity(FindingCategory::Filesystem, "File Path"),
        Severity::Low
    );
    assert_eq!(
        engine.categorize_severity(FindingCategory::Thumbnail, "Preview Thumbnail"),
        Severity::Low
    );
}

#[test]
fn test_informational_severity_categories() {
    let engine = PolicyEngine::balanced();
    assert_eq!(
        engine.categorize_severity(FindingCategory::Technical, "Compression Type"),
        Severity::Informational
    );
    assert_eq!(
        engine.categorize_severity(FindingCategory::Unknown, "Custom Attribute"),
        Severity::Informational
    );
}
