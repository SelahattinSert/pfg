use pfg_model::{Finding, FindingCategory, FindingLocation, FindingSource, Severity};
use pfg_policy::PolicyEngine;

use crate::jpeg::ImageParseError;

pub fn scan_png_metadata(
    buffer: &[u8],
    _policy: &PolicyEngine,
) -> Result<Vec<Finding>, ImageParseError> {
    if buffer.len() < 8 || &buffer[0..8] != b"\x89PNG\r\n\x1a\n" {
        return Err(ImageParseError::InvalidSoi);
    }

    let mut findings = Vec::new();
    let mut cursor = 8;
    let mut finding_counter = 1;

    while cursor + 12 <= buffer.len() {
        let length = u32::from_be_bytes([
            buffer[cursor],
            buffer[cursor + 1],
            buffer[cursor + 2],
            buffer[cursor + 3],
        ]) as usize;

        let chunk_type = &buffer[cursor + 4..cursor + 8];
        let chunk_end = cursor + 12 + length;

        if chunk_end > buffer.len() {
            return Err(ImageParseError::UnexpectedEof);
        }

        match chunk_type {
            b"eXIf" => {
                findings.push(Finding {
                    id: format!("png-exif-{}", finding_counter),
                    category: FindingCategory::Device,
                    severity: Severity::High,
                    source: FindingSource::Exif,
                    key: "eXIf".to_string(),
                    display_value: Some("PNG EXIF metadata chunk present".to_string()),
                    raw_value_available: true,
                    location: FindingLocation::Offset {
                        byte_offset: cursor as u64,
                    },
                    risk_explanation:
                        "PNG eXIf chunk contains camera, location, or capture hardware details."
                            .to_string(),
                    removable: true,
                });
                finding_counter += 1;
            }
            b"tEXt" | b"zTXt" | b"iTXt" => {
                let chunk_name = std::str::from_utf8(chunk_type)
                    .unwrap_or("text")
                    .to_string();
                let data_slice = &buffer[cursor + 8..cursor + 8 + length];
                let key_str = data_slice
                    .split(|&b| b == 0)
                    .next()
                    .and_then(|s| std::str::from_utf8(s).ok())
                    .unwrap_or("TextChunk")
                    .to_string();

                findings.push(Finding {
                    id: format!("png-text-{}", finding_counter),
                    category: FindingCategory::Software,
                    severity: Severity::Medium,
                    source: FindingSource::Comment,
                    key: format!("{}: {}", chunk_name, key_str),
                    display_value: Some(format!("PNG {} keyword: {}", chunk_name, key_str)),
                    raw_value_available: true,
                    location: FindingLocation::Offset {
                        byte_offset: cursor as u64,
                    },
                    risk_explanation: format!(
                        "PNG {} chunk contains textual metadata ({})",
                        chunk_name, key_str
                    ),
                    removable: true,
                });
                finding_counter += 1;
            }
            b"tIME" => {
                findings.push(Finding {
                    id: format!("png-time-{}", finding_counter),
                    category: FindingCategory::Time,
                    severity: Severity::Medium,
                    source: FindingSource::Comment,
                    key: "tIME".to_string(),
                    display_value: Some("PNG modification timestamp chunk present".to_string()),
                    raw_value_available: true,
                    location: FindingLocation::Offset {
                        byte_offset: cursor as u64,
                    },
                    risk_explanation:
                        "PNG tIME chunk exposes precise file modification date and time."
                            .to_string(),
                    removable: true,
                });
                finding_counter += 1;
            }
            b"iCCP" => {
                findings.push(Finding {
                    id: format!("png-iccp-{}", finding_counter),
                    category: FindingCategory::Device,
                    severity: Severity::Informational,
                    source: FindingSource::Comment,
                    key: "iCCP".to_string(),
                    display_value: Some("PNG ICC color profile chunk present".to_string()),
                    raw_value_available: true,
                    location: FindingLocation::Offset {
                        byte_offset: cursor as u64,
                    },
                    risk_explanation: "PNG iCCP chunk contains embedded color profile metadata."
                        .to_string(),
                    removable: true,
                });
                finding_counter += 1;
            }
            _ => {}
        }

        cursor = chunk_end;
    }

    Ok(findings)
}
