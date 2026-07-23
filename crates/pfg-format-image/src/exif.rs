use std::collections::HashSet;

use pfg_model::{Finding, FindingCategory, FindingLocation, FindingSource};
use pfg_policy::PolicyEngine;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

impl Endian {
    pub fn read_u16(&self, buf: &[u8]) -> Option<u16> {
        if buf.len() < 2 {
            return None;
        }
        Some(match self {
            Endian::Little => u16::from_le_bytes([buf[0], buf[1]]),
            Endian::Big => u16::from_be_bytes([buf[0], buf[1]]),
        })
    }

    pub fn read_u32(&self, buf: &[u8]) -> Option<u32> {
        if buf.len() < 4 {
            return None;
        }
        Some(match self {
            Endian::Little => u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            Endian::Big => u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
        })
    }
}

pub fn parse_exif(exif_bytes: &[u8], policy: &PolicyEngine) -> Vec<Finding> {
    if exif_bytes.len() < 8 {
        return Vec::new();
    }

    let endian = match &exif_bytes[0..2] {
        b"II" => Endian::Little,
        b"MM" => Endian::Big,
        _ => return Vec::new(),
    };

    let magic = endian.read_u16(&exif_bytes[2..4]);
    if magic != Some(42) {
        return Vec::new();
    }

    let ifd0_offset = match endian.read_u32(&exif_bytes[4..8]) {
        Some(offset) => offset as usize,
        None => return Vec::new(),
    };

    let mut findings = Vec::new();
    let mut visited = HashSet::new();

    parse_ifd(
        exif_bytes,
        ifd0_offset,
        endian,
        false,
        policy,
        &mut findings,
        &mut visited,
    );

    findings
}

fn parse_ifd(
    exif_bytes: &[u8],
    ifd_offset: usize,
    endian: Endian,
    is_gps_ifd: bool,
    policy: &PolicyEngine,
    findings: &mut Vec<Finding>,
    visited: &mut HashSet<usize>,
) {
    if visited.contains(&ifd_offset) || ifd_offset + 2 > exif_bytes.len() {
        return;
    }
    visited.insert(ifd_offset);

    let num_entries = match endian.read_u16(&exif_bytes[ifd_offset..ifd_offset + 2]) {
        Some(n) => n as usize,
        None => return,
    };

    let entries_start = ifd_offset + 2;
    if entries_start + num_entries * 12 > exif_bytes.len() {
        return;
    }

    let mut sub_ifd_pointers = Vec::new();

    for i in 0..num_entries {
        let entry_offset = entries_start + i * 12;
        let tag = match endian.read_u16(&exif_bytes[entry_offset..entry_offset + 2]) {
            Some(t) => t,
            None => continue,
        };
        let format = match endian.read_u16(&exif_bytes[entry_offset + 2..entry_offset + 4]) {
            Some(f) => f,
            None => continue,
        };
        let count = match endian.read_u32(&exif_bytes[entry_offset + 4..entry_offset + 8]) {
            Some(c) => c,
            None => continue,
        };

        let val_bytes = &exif_bytes[entry_offset + 8..entry_offset + 12];

        // Handle sub-IFD pointers
        if tag == 0x8769 || tag == 0x8825 || tag == 0xA005 {
            if let Some(ptr_offset) = endian.read_u32(val_bytes) {
                let is_gps = tag == 0x8825;
                sub_ifd_pointers.push((ptr_offset as usize, is_gps));
            }
            continue;
        }

        let fmt_size = format_unit_size(format);
        let total_size = count as usize * fmt_size;

        let val_slice = if total_size <= 4 {
            if total_size <= val_bytes.len() {
                &val_bytes[..total_size]
            } else {
                val_bytes
            }
        } else if let Some(offset) = endian.read_u32(val_bytes) {
            let offset = offset as usize;
            if offset + total_size <= exif_bytes.len() {
                &exif_bytes[offset..offset + total_size]
            } else {
                &[]
            }
        } else {
            &[]
        };

        let (tag_name, category) = map_tag_info(tag, is_gps_ifd);
        let key = if tag_name == "ExifTag" {
            format!("Exif Tag 0x{:04X}", tag)
        } else {
            tag_name.to_string()
        };

        let severity = policy.categorize_severity(category, &key);
        let display_value = format_value(format, count, val_slice, endian);

        findings.push(Finding {
            id: format!("exif-{}-{}", key.to_lowercase(), findings.len()),
            category,
            severity,
            source: FindingSource::Exif,
            key,
            display_value,
            raw_value_available: !val_slice.is_empty(),
            location: FindingLocation::Header {
                segment: "APP1/EXIF".to_string(),
            },
            risk_explanation: format!("EXIF metadata entry '{}' present in JPEG header.", tag_name),
            removable: true,
        });
    }

    // Process sub-IFDs (Exif IFD, GPS IFD, Interop IFD)
    for (sub_offset, is_gps) in sub_ifd_pointers {
        parse_ifd(
            exif_bytes, sub_offset, endian, is_gps, policy, findings, visited,
        );
    }

    // Check for next IFD offset (e.g. IFD1 for Thumbnail)
    let next_ifd_ptr_offset = entries_start + num_entries * 12;
    if next_ifd_ptr_offset + 4 <= exif_bytes.len() {
        if let Some(next_offset) = endian.read_u32(&exif_bytes[next_ifd_ptr_offset..]) {
            if next_offset > 0 {
                parse_ifd(
                    exif_bytes,
                    next_offset as usize,
                    endian,
                    false,
                    policy,
                    findings,
                    visited,
                );
            }
        }
    }
}

fn format_unit_size(format: u16) -> usize {
    match format {
        1 | 2 | 7 => 1,
        3 => 2,
        4 | 9 => 4,
        5 | 10 => 8,
        _ => 1,
    }
}

fn map_tag_info(tag: u16, is_gps_ifd: bool) -> (&'static str, FindingCategory) {
    if is_gps_ifd {
        let name = match tag {
            0x0000 => "GPSVersionID",
            0x0001 => "GPSLatitudeRef",
            0x0002 => "GPSLatitude",
            0x0003 => "GPSLongitudeRef",
            0x0004 => "GPSLongitude",
            0x0005 => "GPSAltitudeRef",
            0x0006 => "GPSAltitude",
            0x0007 => "GPSTimeStamp",
            0x000B => "GPSDOP",
            0x001B => "GPSProcessingMethod",
            0x001D => "GPSDateStamp",
            _ => "GPSMetadata",
        };
        return (name, FindingCategory::Location);
    }

    match tag {
        0x010F => ("Make", FindingCategory::Device),
        0x0110 => ("Model", FindingCategory::Device),
        0x0112 => ("Orientation", FindingCategory::Technical),
        0x0131 => ("Software", FindingCategory::Software),
        0x0132 => ("DateTime", FindingCategory::Time),
        0x013B => ("Artist", FindingCategory::Identity),
        0x8298 => ("Copyright", FindingCategory::Identity),
        0x9003 => ("DateTimeOriginal", FindingCategory::Time),
        0x9004 => ("DateTimeDigitized", FindingCategory::Time),
        0x9286 => ("UserComment", FindingCategory::Comments),
        0xA002 => ("ExifImageWidth", FindingCategory::Technical),
        0xA003 => ("ExifImageHeight", FindingCategory::Technical),
        0xA420 => ("ImageUniqueID", FindingCategory::UniqueIdentifier),
        0xA430 => ("CameraOwnerName", FindingCategory::Identity),
        0xA431 => ("BodySerialNumber", FindingCategory::Device),
        0xA433 => ("LensMake", FindingCategory::Device),
        0xA434 => ("LensModel", FindingCategory::Device),
        0xA435 => ("LensSerialNumber", FindingCategory::Device),
        0x0201 => ("JPEGInterchangeFormat", FindingCategory::Thumbnail),
        0x0202 => ("JPEGInterchangeFormatLength", FindingCategory::Thumbnail),
        _ => ("ExifTag", FindingCategory::Technical),
    }
}

fn format_value(format: u16, _count: u32, val_slice: &[u8], endian: Endian) -> Option<String> {
    if val_slice.is_empty() {
        return None;
    }

    match format {
        2 => {
            // ASCII string
            let s = String::from_utf8_lossy(val_slice);
            let trimmed = s.trim_matches('\0').trim();
            Some(trimmed.to_string())
        }
        3 => endian.read_u16(val_slice).map(|v| v.to_string()),
        4 => endian.read_u32(val_slice).map(|v| v.to_string()),
        5 => {
            if val_slice.len() >= 8 {
                let num = endian.read_u32(&val_slice[0..4])?;
                let den = endian.read_u32(&val_slice[4..8])?;
                Some(format!("{}/{}", num, den))
            } else {
                None
            }
        }
        _ => {
            let s = String::from_utf8_lossy(val_slice);
            let trimmed = s.trim_matches('\0').trim();
            if !trimmed.is_empty() {
                Some(trimmed.to_string())
            } else {
                None
            }
        }
    }
}
