use pfg_model::*;

#[test]
fn test_finding_and_report_serialization() {
    let finding = Finding {
        id: "finding-1".to_string(),
        category: FindingCategory::Location,
        severity: Severity::High,
        source: FindingSource::Exif,
        key: "GPSLatitude".to_string(),
        display_value: Some("38.4***, 27.1***".to_string()),
        raw_value_available: true,
        location: FindingLocation::Header {
            segment: "APP1".to_string(),
        },
        risk_explanation: "GPS location reveals exact position".to_string(),
        removable: true,
    };

    let report = ScanReport {
        schema_version: 1,
        tool_version: "0.1.0".to_string(),
        operation: "scan".to_string(),
        input: InputFileMetadata {
            name: "sample.jpg".to_string(),
            size: 1024,
            sha256: "abc...".to_string(),
        },
        detected_format: "jpeg".to_string(),
        support_level: "full".to_string(),
        findings: vec![finding],
        summary: FindingSummary {
            critical: 0,
            high: 1,
            medium: 0,
            low: 0,
            informational: 0,
        },
    };

    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("\"detected_format\":\"jpeg\""));
    assert!(json.contains("\"location\""));
    assert!(json.contains("\"high\""));
}
