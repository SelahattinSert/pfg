use std::io::{Cursor, Read, Write};
use zip::write::FileOptions;
use zip::{ZipArchive, ZipWriter};

use pfg_policy::CleanProfile;

use crate::detector::detect_office_format;
use crate::scanner::OfficeParseError;

/// Sanitizes an Office Open XML document (DOCX, XLSX, PPTX) by redacting
/// metadata in `docProps/core.xml` and `docProps/app.xml`, stripping custom properties,
/// thumbnails, VBA macros, and stripping comments in `Strict` mode.
pub fn sanitize_office(
    buffer: &[u8],
    profile: CleanProfile,
) -> Result<Vec<u8>, OfficeParseError> {
    // 1. Check magic bytes
    if buffer.len() < 4 || &buffer[0..4] != b"PK\x03\x04" {
        return Err(OfficeParseError::InvalidContainer);
    }

    // 2. Validate zip archive
    let cursor = Cursor::new(buffer);
    let mut archive = ZipArchive::new(cursor)
        .map_err(|err| OfficeParseError::CorruptedZip(err.to_string()))?;

    // 3. Detect format
    if detect_office_format(buffer).is_none() {
        return Err(OfficeParseError::InvalidContainer);
    }

    let mut output_buf = Vec::new();
    {
        let output_cursor = Cursor::new(&mut output_buf);
        let mut zip_out = ZipWriter::new(output_cursor);

        for i in 0..archive.len() {
            let mut file = archive
                .by_index(i)
                .map_err(|err| OfficeParseError::CorruptedZip(err.to_string()))?;
            let name = file.name().to_string();

            // Check if entry should be stripped
            if should_strip_entry(&name, profile) {
                continue;
            }

            let mut contents = Vec::new();
            file.read_to_end(&mut contents)
                .map_err(|err| OfficeParseError::CorruptedZip(err.to_string()))?;

            let options = FileOptions::default().compression_method(file.compression());

            if name == "docProps/core.xml" {
                let redacted = redact_core_xml(&contents);
                zip_out
                    .start_file(name, options)
                    .map_err(|err| OfficeParseError::CorruptedZip(err.to_string()))?;
                zip_out
                    .write_all(&redacted)
                    .map_err(|err| OfficeParseError::CorruptedZip(err.to_string()))?;
            } else if name == "docProps/app.xml" {
                let redacted = redact_app_xml(&contents);
                zip_out
                    .start_file(name, options)
                    .map_err(|err| OfficeParseError::CorruptedZip(err.to_string()))?;
                zip_out
                    .write_all(&redacted)
                    .map_err(|err| OfficeParseError::CorruptedZip(err.to_string()))?;
            } else {
                zip_out
                    .start_file(name, options)
                    .map_err(|err| OfficeParseError::CorruptedZip(err.to_string()))?;
                zip_out
                    .write_all(&contents)
                    .map_err(|err| OfficeParseError::CorruptedZip(err.to_string()))?;
            }
        }

        zip_out
            .finish()
            .map_err(|err| OfficeParseError::CorruptedZip(err.to_string()))?;
    }

    Ok(output_buf)
}

fn should_strip_entry(name: &str, profile: CleanProfile) -> bool {
    // 1. docProps/custom.xml
    if name == "docProps/custom.xml" {
        return true;
    }

    // 2. docProps/thumbnail.*
    if name.starts_with("docProps/thumbnail.") {
        return true;
    }

    // 3. vbaProject.bin, word/vbaProject.bin, xl/vbaProject.bin, etc.
    if name == "vbaProject.bin" || name.ends_with("/vbaProject.bin") || name.contains("vbaProject.bin") {
        return true;
    }

    // 4. Strip comments files in Strict profile
    if profile == CleanProfile::Strict {
        if name.starts_with("word/comments")
            || name.starts_with("xl/comments")
            || name.starts_with("ppt/comments")
            || name.ends_with("comments.xml")
        {
            return true;
        }
    }

    false
}

fn redact_core_xml(content: &[u8]) -> Vec<u8> {
    let text = match std::str::from_utf8(content) {
        Ok(s) => s,
        Err(_) => return content.to_vec(),
    };

    let tags = &[
        "creator",
        "lastModifiedBy",
        "created",
        "modified",
        "title",
        "subject",
        "keywords",
    ];

    redact_xml_tags(text, tags).into_bytes()
}

fn redact_app_xml(content: &[u8]) -> Vec<u8> {
    let text = match std::str::from_utf8(content) {
        Ok(s) => s,
        Err(_) => return content.to_vec(),
    };

    let tags = &[
        "Company",
        "Manager",
        "Application",
        "AppVersion",
        "TotalTime",
    ];

    redact_xml_tags(text, tags).into_bytes()
}

fn redact_xml_tags(xml: &str, target_local_names: &[&str]) -> String {
    let mut result = String::with_capacity(xml.len());
    let mut search_idx = 0;

    while search_idx < xml.len() {
        let open_rel = match xml[search_idx..].find('<') {
            Some(idx) => idx,
            None => {
                result.push_str(&xml[search_idx..]);
                break;
            }
        };

        let open_start = search_idx + open_rel;
        result.push_str(&xml[search_idx..open_start]);

        let open_end_rel = match xml[open_start..].find('>') {
            Some(idx) => idx,
            None => {
                result.push_str(&xml[open_start..]);
                break;
            }
        };
        let open_end = open_start + open_end_rel;
        let tag_header = &xml[open_start + 1..open_end];

        if tag_header.starts_with('?') || tag_header.starts_with('!') || tag_header.starts_with('/') {
            result.push_str(&xml[open_start..=open_end]);
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

        if target_local_names.contains(&local_name) {
            if is_self_closing {
                result.push_str(&xml[open_start..=open_end]);
                search_idx = open_end + 1;
                continue;
            }

            // Find matching closing tag
            let mut close_search = open_end + 1;
            let mut found_close = None;

            while close_search < xml.len() {
                if let Some(c_start_rel) = xml[close_search..].find("</") {
                    let c_start_abs = close_search + c_start_rel;
                    if let Some(c_end_rel) = xml[c_start_abs..].find('>') {
                        let c_end_abs = c_start_abs + c_end_rel;
                        let close_header = xml[c_start_abs + 2..c_end_abs].trim();
                        let close_local = if let Some((_prefix, local)) = close_header.split_once(':') {
                            local
                        } else {
                            close_header
                        };
                        if close_local == local_name {
                            found_close = Some((c_start_abs, c_end_abs));
                            break;
                        } else {
                            close_search = c_end_abs + 1;
                            continue;
                        }
                    }
                }
                break;
            }

            if let Some((c_start_abs, c_end_abs)) = found_close {
                // Keep opening tag <tag_name ...> and closing tag </tag_name>, but empty inner content
                result.push_str(&xml[open_start..=open_end]);
                result.push_str(&xml[c_start_abs..=c_end_abs]);
                search_idx = c_end_abs + 1;
            } else {
                result.push_str(&xml[open_start..=open_end]);
                search_idx = open_end + 1;
            }
        } else {
            result.push_str(&xml[open_start..=open_end]);
            search_idx = open_end + 1;
        }
    }

    result
}
