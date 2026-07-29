use pfg_model::{Finding, FindingCategory, FindingLocation, FindingSource};
use pfg_policy::PolicyEngine;

pub fn parse_xmp(xmp_bytes: &[u8], policy: &PolicyEngine) -> Vec<Finding> {
    if xmp_bytes.is_empty() {
        return Vec::new();
    }

    let xmp_str = String::from_utf8_lossy(xmp_bytes);
    let mut findings = Vec::new();

    // Top-level XMP Packet Finding
    let category = FindingCategory::EmbeddedContent;
    let key = "XMP Metadata".to_string();
    let severity = policy.categorize_severity(category, &key);

    findings.push(Finding {
        id: "xmp-packet".to_string(),
        category,
        severity,
        source: FindingSource::Xmp,
        key,
        display_value: Some("XMP Packet Present".to_string()),
        raw_value_available: true,
        location: FindingLocation::Header {
            segment: "APP1/XMP".to_string(),
        },
        risk_explanation: "XMP metadata packet found containing embedded XML properties."
            .to_string(),
        removable: true,
    });

    // Scan for specific XMP tag elements / attributes
    extract_xmp_properties(&xmp_str, policy, &mut findings);

    findings
}

fn extract_xmp_properties(xmp_str: &str, policy: &PolicyEngine, findings: &mut Vec<Finding>) {
    // List of common property tags to look for in XMP XML
    let property_keys = [
        "dc:creator",
        "dc:rights",
        "dc:description",
        "dc:title",
        "xmp:CreateDate",
        "xmp:ModifyDate",
        "xmp:CreatorTool",
        "photoshop:Credit",
        "exif:GPSLatitude",
        "exif:GPSLongitude",
    ];

    for &prop_key in &property_keys {
        if let Some(val) = find_element_or_attr(xmp_str, prop_key) {
            let category = categorize_xmp_prop(prop_key);
            let key = prop_key.to_string();
            let severity = policy.categorize_severity(category, &key);

            findings.push(Finding {
                id: format!("xmp-{}", prop_key.replace(':', "-")),
                category,
                severity,
                source: FindingSource::Xmp,
                key,
                display_value: Some(val),
                raw_value_available: true,
                location: FindingLocation::Header {
                    segment: "APP1/XMP".to_string(),
                },
                risk_explanation: format!(
                    "XMP property '{}' present in metadata packet.",
                    prop_key
                ),
                removable: true,
            });
        }
    }
}

fn find_element_or_attr(xml: &str, prop: &str) -> Option<String> {
    // Look for <prop>Value</prop>
    let open_tag = format!("<{}>", prop);
    let close_tag = format!("</{}>", prop);
    if let Some(start_idx) = xml.find(&open_tag) {
        let val_start = start_idx + open_tag.len();
        if let Some(end_idx) = xml[val_start..].find(&close_tag) {
            let val = &xml[val_start..val_start + end_idx];
            return Some(val.trim().to_string());
        }
    }

    // Look for prop="Value"
    let attr_pattern = format!("{}=\"", prop);
    if let Some(start_idx) = xml.find(&attr_pattern) {
        let val_start = start_idx + attr_pattern.len();
        if let Some(end_idx) = xml[val_start..].find('"') {
            let val = &xml[val_start..val_start + end_idx];
            return Some(val.trim().to_string());
        }
    }

    None
}

fn categorize_xmp_prop(prop: &str) -> FindingCategory {
    if prop.contains("GPS") || prop.contains("Latitude") || prop.contains("Longitude") {
        FindingCategory::Location
    } else if prop.contains("Date") || prop.contains("Time") {
        FindingCategory::Time
    } else if prop.contains("creator") || prop.contains("rights") || prop.contains("Credit") {
        FindingCategory::Identity
    } else if prop.contains("CreatorTool") || prop.contains("Software") {
        FindingCategory::Software
    } else if prop.contains("description") || prop.contains("title") {
        FindingCategory::Comments
    } else {
        FindingCategory::EmbeddedContent
    }
}
