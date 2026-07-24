use pfg_model::{Finding, FindingCategory, FindingLocation, FindingSource, Severity};
use pfg_policy::PolicyEngine;

use crate::jpeg::ImageParseError;

pub fn scan_webp_metadata(
    buffer: &[u8],
    _policy: &PolicyEngine,
) -> Result<Vec<Finding>, ImageParseError> {
    if buffer.len() < 12 || &buffer[0..4] != b"RIFF" || &buffer[8..12] != b"WEBP" {
        return Err(ImageParseError::InvalidSoi);
    }

    let mut findings = Vec::new();
    let mut cursor = 12;
    let mut finding_counter = 1;

    while cursor + 8 <= buffer.len() {
        let chunk_fourcc = &buffer[cursor..cursor + 4];
        let chunk_size = u32::from_le_bytes([
            buffer[cursor + 4],
            buffer[cursor + 5],
            buffer[cursor + 6],
            buffer[cursor + 7],
        ]) as usize;

        let data_start = cursor + 8;
        let data_end = data_start + chunk_size;

        if data_end > buffer.len() {
            break;
        }

        match chunk_fourcc {
            b"EXIF" => {
                findings.push(Finding {
                    id: format!("webp-exif-{}", finding_counter),
                    category: FindingCategory::Device,
                    severity: Severity::High,
                    source: FindingSource::Exif,
                    key: "EXIF".to_string(),
                    display_value: Some("WebP EXIF metadata chunk present".to_string()),
                    raw_value_available: true,
                    location: FindingLocation::Offset {
                        byte_offset: cursor as u64,
                    },
                    risk_explanation: "WebP EXIF chunk contains camera, location, or hardware details.".to_string(),
                    removable: true,
                });
                finding_counter += 1;
            }
            b"XMP " => {
                findings.push(Finding {
                    id: format!("webp-xmp-{}", finding_counter),
                    category: FindingCategory::DocumentHistory,
                    severity: Severity::High,
                    source: FindingSource::Xmp,
                    key: "XMP".to_string(),
                    display_value: Some("WebP XMP metadata stream present".to_string()),
                    raw_value_available: true,
                    location: FindingLocation::Offset {
                        byte_offset: cursor as u64,
                    },
                    risk_explanation: "WebP XMP chunk contains XML metadata stream with author or application details.".to_string(),
                    removable: true,
                });
                finding_counter += 1;
            }
            b"ICCP" => {
                findings.push(Finding {
                    id: format!("webp-iccp-{}", finding_counter),
                    category: FindingCategory::Device,
                    severity: Severity::Informational,
                    source: FindingSource::Comment,
                    key: "ICCP".to_string(),
                    display_value: Some("WebP ICC color profile chunk present".to_string()),
                    raw_value_available: true,
                    location: FindingLocation::Offset {
                        byte_offset: cursor as u64,
                    },
                    risk_explanation: "WebP ICCP chunk contains embedded color profile.".to_string(),
                    removable: true,
                });
                finding_counter += 1;
            }
            _ => {}
        }

        let padded_size = if chunk_size % 2 == 1 { chunk_size + 1 } else { chunk_size };
        cursor = data_start + padded_size;
    }

    Ok(findings)
}
