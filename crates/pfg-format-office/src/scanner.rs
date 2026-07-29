use std::io::{Cursor, Read};
use thiserror::Error;
use zip::ZipArchive;

use pfg_model::{Finding, FindingCategory, FindingLocation, FindingSource};
use pfg_policy::PolicyEngine;

use crate::detector::detect_office_format;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OfficeParseError {
    #[error("Invalid Office container")]
    InvalidContainer,
    #[error("Corrupted ZIP archive: {0}")]
    CorruptedZip(String),
}

/// Scans an Office Open XML buffer (DOCX, XLSX, PPTX) for metadata, comments,
/// custom properties, macros, embeddings, and thumbnail images.
pub fn scan_office_metadata(
    buffer: &[u8],
    policy: &PolicyEngine,
) -> Result<Vec<Finding>, OfficeParseError> {
    // 1. Verify PK magic bytes
    if buffer.len() < 4 || &buffer[0..4] != b"PK\x03\x04" {
        return Err(OfficeParseError::InvalidContainer);
    }

    // 2. Validate zip archive structure
    let cursor = Cursor::new(buffer);
    let mut archive =
        ZipArchive::new(cursor).map_err(|err| OfficeParseError::CorruptedZip(err.to_string()))?;

    if archive.len() > 10_000 {
        return Err(OfficeParseError::CorruptedZip(
            "Zip bomb limit exceeded: too many entries".to_string(),
        ));
    }

    let mut total_uncompressed: u64 = 0;
    for i in 0..archive.len() {
        if let Ok(file) = archive.by_index(i) {
            total_uncompressed += file.size();
            if total_uncompressed > 500 * 1024 * 1024 {
                return Err(OfficeParseError::CorruptedZip(
                    "Zip bomb limit exceeded: total uncompressed size exceeds 500 MB".to_string(),
                ));
            }
        }
    }

    // 3. Verify it is a supported Office container
    if detect_office_format(buffer).is_none() {
        return Err(OfficeParseError::InvalidContainer);
    }

    let mut findings = Vec::new();

    // 4. Parse docProps/core.xml if present
    if let Ok(mut file) = archive.by_name("docProps/core.xml") {
        let mut xml_content = String::new();
        if file.read_to_string(&mut xml_content).is_ok() {
            let core_fields: &[(&str, &str, FindingCategory, &str)] = &[
                (
                    "creator",
                    "dc:creator",
                    FindingCategory::Identity,
                    "Author identity in core properties",
                ),
                (
                    "lastModifiedBy",
                    "cp:lastModifiedBy",
                    FindingCategory::Identity,
                    "Last modified by identity in core properties",
                ),
                (
                    "created",
                    "dcterms:created",
                    FindingCategory::Time,
                    "Creation timestamp in core properties",
                ),
                (
                    "modified",
                    "dcterms:modified",
                    FindingCategory::Time,
                    "Modification timestamp in core properties",
                ),
                (
                    "title",
                    "dc:title",
                    FindingCategory::DocumentHistory,
                    "Document title in core properties",
                ),
                (
                    "subject",
                    "dc:subject",
                    FindingCategory::DocumentHistory,
                    "Document subject in core properties",
                ),
                (
                    "keywords",
                    "cp:keywords",
                    FindingCategory::DocumentHistory,
                    "Keywords in core properties",
                ),
            ];

            for &(local_name, key, category, risk) in core_fields {
                if let Some(val) = extract_xml_element_text(&xml_content, local_name) {
                    let severity = policy.categorize_severity(category, key);
                    findings.push(Finding {
                        id: format!("office-core-{}", local_name),
                        category,
                        severity,
                        source: FindingSource::OfficeXml,
                        key: key.to_string(),
                        display_value: Some(val),
                        raw_value_available: true,
                        location: FindingLocation::Header {
                            segment: "docProps/core.xml".to_string(),
                        },
                        risk_explanation: risk.to_string(),
                        removable: true,
                    });
                }
            }
        }
    }

    // 5. Parse docProps/app.xml if present
    if let Ok(mut file) = archive.by_name("docProps/app.xml") {
        let mut xml_content = String::new();
        if file.read_to_string(&mut xml_content).is_ok() {
            let app_fields: &[(&str, &str, FindingCategory, &str)] = &[
                (
                    "Company",
                    "Company",
                    FindingCategory::Identity,
                    "Company name in app properties",
                ),
                (
                    "Manager",
                    "Manager",
                    FindingCategory::Identity,
                    "Manager name in app properties",
                ),
                (
                    "Application",
                    "Application",
                    FindingCategory::Software,
                    "Application name in app properties",
                ),
                (
                    "AppVersion",
                    "AppVersion",
                    FindingCategory::Software,
                    "Application version in app properties",
                ),
                (
                    "TotalTime",
                    "TotalTime",
                    FindingCategory::DocumentHistory,
                    "Total editing time in app properties",
                ),
            ];

            for &(local_name, key, category, risk) in app_fields {
                if let Some(val) = extract_xml_element_text(&xml_content, local_name) {
                    let severity = policy.categorize_severity(category, key);
                    findings.push(Finding {
                        id: format!("office-app-{}", local_name),
                        category,
                        severity,
                        source: FindingSource::OfficeXml,
                        key: key.to_string(),
                        display_value: Some(val),
                        raw_value_available: true,
                        location: FindingLocation::Header {
                            segment: "docProps/app.xml".to_string(),
                        },
                        risk_explanation: risk.to_string(),
                        removable: true,
                    });
                }
            }
        }
    }

    // 6. Scan zip entries for special XML parts, macros, embeddings, comments, thumbnails
    for i in 0..archive.len() {
        let entry = match archive.by_index(i) {
            Ok(file) => file,
            Err(_) => continue,
        };
        let name = entry.name().to_string();

        if name == "docProps/custom.xml" {
            let category = FindingCategory::DocumentHistory;
            let severity = policy.categorize_severity(category, &name);
            findings.push(Finding {
                id: format!("office-part-{}", sanitize_id(&name)),
                category,
                severity,
                source: FindingSource::OfficeXml,
                key: name.clone(),
                display_value: Some(name.clone()),
                raw_value_available: true,
                location: FindingLocation::Header { segment: name },
                risk_explanation: "Custom document properties part present".to_string(),
                removable: true,
            });
        } else if name.ends_with("vbaProject.bin") || name.contains("vbaProject.bin") {
            let category = FindingCategory::EmbeddedContent;
            let severity = policy.categorize_severity(category, &name);
            findings.push(Finding {
                id: format!("office-part-{}", sanitize_id(&name)),
                category,
                severity,
                source: FindingSource::OfficeXml,
                key: name.clone(),
                display_value: Some(name.clone()),
                raw_value_available: true,
                location: FindingLocation::Header { segment: name },
                risk_explanation: "VBA macro binary part present".to_string(),
                removable: true,
            });
        } else if name.contains("/embeddings/") || name.starts_with("embeddings/") {
            let category = FindingCategory::EmbeddedContent;
            let severity = policy.categorize_severity(category, &name);
            findings.push(Finding {
                id: format!("office-part-{}", sanitize_id(&name)),
                category,
                severity,
                source: FindingSource::OfficeXml,
                key: name.clone(),
                display_value: Some(name.clone()),
                raw_value_available: true,
                location: FindingLocation::Header { segment: name },
                risk_explanation: "Embedded object part present".to_string(),
                removable: true,
            });
        } else if name.starts_with("word/comments")
            || name.starts_with("xl/comments")
            || name.starts_with("ppt/comments")
            || name.ends_with("comments.xml")
        {
            let category = FindingCategory::Comments;
            let severity = policy.categorize_severity(category, &name);
            findings.push(Finding {
                id: format!("office-part-{}", sanitize_id(&name)),
                category,
                severity,
                source: FindingSource::OfficeXml,
                key: name.clone(),
                display_value: Some(name.clone()),
                raw_value_available: true,
                location: FindingLocation::Header { segment: name },
                risk_explanation: "Document comments part present".to_string(),
                removable: true,
            });
        } else if name.starts_with("docProps/thumbnail.") {
            let category = FindingCategory::Thumbnail;
            let severity = policy.categorize_severity(category, &name);
            findings.push(Finding {
                id: format!("office-part-{}", sanitize_id(&name)),
                category,
                severity,
                source: FindingSource::OfficeXml,
                key: name.clone(),
                display_value: Some(name.clone()),
                raw_value_available: true,
                location: FindingLocation::Header { segment: name },
                risk_explanation: "Document thumbnail image present".to_string(),
                removable: true,
            });
        }
    }

    Ok(findings)
}

fn sanitize_id(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect()
}

fn extract_xml_element_text(xml: &str, tag_local_name: &str) -> Option<String> {
    let mut search_idx = 0;
    while search_idx < xml.len() {
        let open_rel = xml[search_idx..].find('<')?;
        let open_start = search_idx + open_rel;
        let open_end_rel = xml[open_start..].find('>')?;
        let open_end = open_start + open_end_rel;

        let tag_header = &xml[open_start + 1..open_end];

        if tag_header.starts_with('?') || tag_header.starts_with('!') {
            search_idx = open_end + 1;
            continue;
        }

        let is_self_closing = tag_header.ends_with('/');
        let tag_name_part = if is_self_closing {
            tag_header[..tag_header.len() - 1].trim()
        } else {
            tag_header.trim()
        };

        let tag_name = tag_name_part.split_whitespace().next().unwrap_or("");
        let local_name = if let Some((_prefix, local)) = tag_name.split_once(':') {
            local
        } else {
            tag_name
        };

        if local_name == tag_local_name {
            if is_self_closing {
                search_idx = open_end + 1;
                continue;
            }

            let mut close_search = open_end + 1;
            while close_search < xml.len() {
                if let Some(c_start_rel) = xml[close_search..].find("</") {
                    let c_start_abs = close_search + c_start_rel;
                    if let Some(c_end_rel) = xml[c_start_abs..].find('>') {
                        let c_end_abs = c_start_abs + c_end_rel;
                        let close_header = xml[c_start_abs + 2..c_end_abs].trim();
                        let close_local =
                            if let Some((_prefix, local)) = close_header.split_once(':') {
                                local
                            } else {
                                close_header
                            };
                        if close_local == tag_local_name {
                            let inner_text = &xml[open_end + 1..c_start_abs];
                            let trimmed = inner_text.trim();
                            if !trimmed.is_empty() {
                                return Some(trimmed.to_string());
                            }
                            break;
                        } else {
                            close_search = c_end_abs + 1;
                            continue;
                        }
                    }
                }
                break;
            }
        }

        search_idx = open_end + 1;
    }

    None
}
