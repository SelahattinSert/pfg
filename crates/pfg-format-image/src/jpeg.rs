use pfg_model::{Finding, FindingCategory, FindingLocation, FindingSource};
use pfg_policy::PolicyEngine;
use thiserror::Error;

use crate::{exif, xmp};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ImageParseError {
    #[error("Invalid SOI marker")]
    InvalidSoi,
    #[error("Unexpected end of buffer")]
    UnexpectedEof,
    #[error("Invalid JPEG marker length")]
    InvalidMarkerLength,
    #[error("Invalid marker structure")]
    InvalidMarkerStructure,
}

pub fn extract_jpeg_orientation(buffer: &[u8]) -> Option<u16> {
    if buffer.len() < 2 || buffer[0] != 0xFF || buffer[1] != 0xD8 {
        return None;
    }
    let mut cursor = 2;
    while cursor < buffer.len() {
        if buffer[cursor] != 0xFF {
            break;
        }
        while cursor < buffer.len() && buffer[cursor] == 0xFF {
            cursor += 1;
        }
        if cursor >= buffer.len() {
            break;
        }
        let marker = buffer[cursor];
        cursor += 1;
        if marker == 0xD9 || marker == 0xDA {
            break;
        }
        if cursor + 2 > buffer.len() {
            break;
        }
        let length = u16::from_be_bytes([buffer[cursor], buffer[cursor + 1]]) as usize;
        if length < 2 || cursor + length > buffer.len() {
            break;
        }
        let payload = &buffer[cursor + 2..cursor + length];
        if marker == 0xE1 && payload.starts_with(b"Exif\0\0") && payload.len() >= 6 {
            return exif::extract_orientation(&payload[6..]);
        }
        cursor += length;
    }
    None
}

pub fn scan_jpeg_metadata(
    buffer: &[u8],
    policy: &PolicyEngine,
) -> Result<Vec<Finding>, ImageParseError> {
    if buffer.len() < 2 || buffer[0] != 0xFF || buffer[1] != 0xD8 {
        return Err(ImageParseError::InvalidSoi);
    }

    let mut findings = Vec::new();
    let mut pos = 2;

    while pos < buffer.len() {
        if buffer[pos] != 0xFF {
            return Err(ImageParseError::InvalidMarkerStructure);
        }

        // Skip extra 0xFF padding bytes
        while pos < buffer.len() && buffer[pos] == 0xFF {
            pos += 1;
        }

        if pos >= buffer.len() {
            break;
        }

        let marker = buffer[pos];
        pos += 1;

        // Standalone markers with no length payload
        match marker {
            0xD8 => continue,        // SOI
            0xD9 => break,           // EOI - End of image
            0x00 => continue,        // Escaped byte
            0xD0..=0xD7 => continue, // RST0..RST7
            _ => {}
        }

        // Markers with 2-byte Big-Endian length parameter
        if pos + 2 > buffer.len() {
            return Err(ImageParseError::UnexpectedEof);
        }

        let len = u16::from_be_bytes([buffer[pos], buffer[pos + 1]]) as usize;
        pos += 2;

        if len < 2 {
            return Err(ImageParseError::InvalidMarkerLength);
        }

        let payload_len = len - 2;
        if pos + payload_len > buffer.len() {
            return Err(ImageParseError::UnexpectedEof);
        }

        let payload = &buffer[pos..pos + payload_len];
        pos += payload_len;

        if marker == 0xDA {
            // SOS (Start of Scan) header parsed, image entropy data follows
            break;
        }

        if marker == 0xE1 {
            // APP1 marker
            if payload.starts_with(b"Exif\0\0") && payload.len() >= 6 {
                let exif_findings = exif::parse_exif(&payload[6..], policy);
                findings.extend(exif_findings);
            } else if payload.starts_with(b"http://ns.adobe.com/xap/1.0/\0") && payload.len() >= 29
            {
                let xmp_findings = xmp::parse_xmp(&payload[29..], policy);
                findings.extend(xmp_findings);
            }
        } else if marker == 0xFE {
            // COM marker (Comment)
            let comment_str = String::from_utf8_lossy(payload)
                .trim_matches('\0')
                .trim()
                .to_string();

            let category = FindingCategory::Comments;
            let key = "Comment".to_string();
            let severity = policy.categorize_severity(category, &key);

            findings.push(Finding {
                id: format!("com-comment-{}", findings.len()),
                category,
                severity,
                source: FindingSource::Comment,
                key,
                display_value: Some(comment_str),
                raw_value_available: !payload.is_empty(),
                location: FindingLocation::Header {
                    segment: "COM".to_string(),
                },
                risk_explanation: "JPEG COM segment contains text comments.".to_string(),
                removable: true,
            });
        }
    }

    Ok(findings)
}
