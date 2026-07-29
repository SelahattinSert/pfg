use crate::detector::detect_office_format;
use crate::OfficeParseError;
use pfg_policy::CleanProfile;
use quick_xml::events::Event;
use quick_xml::{Reader, Writer};
use std::io::{Cursor, Read, Write};
use zip::write::FileOptions;
use zip::{ZipArchive, ZipWriter};

pub fn sanitize_office(buffer: &[u8], profile: CleanProfile) -> Result<Vec<u8>, OfficeParseError> {
    // 1. Check magic bytes
    if buffer.len() < 4 || &buffer[0..4] != b"PK\x03\x04" {
        return Err(OfficeParseError::InvalidContainer);
    }

    // 2. Validate zip archive
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

    // 3. Detect format
    if detect_office_format(buffer).is_none() {
        return Err(OfficeParseError::InvalidContainer);
    }

    // Pass 1: Identify all stripped entry names
    let mut stripped_parts = Vec::new();
    for i in 0..archive.len() {
        if let Ok(file) = archive.by_index(i) {
            let name = file.name().to_string();
            if is_stripped_part(&name, profile) {
                stripped_parts.push(name);
            }
        }
    }

    // Pass 2: Build new ZIP container
    let output_cursor = Cursor::new(Vec::new());
    let mut zip_writer = ZipWriter::new(output_cursor);

    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|err| OfficeParseError::CorruptedZip(err.to_string()))?;
        let name = file.name().to_string();

        if is_stripped_part(&name, profile) {
            continue;
        }

        let mut content = Vec::new();
        file.read_to_end(&mut content)
            .map_err(|err| OfficeParseError::CorruptedZip(err.to_string()))?;

        // Sanitize specific XML streams
        let final_content = if name == "docProps/core.xml" {
            redact_core_xml(&content)
        } else if name == "docProps/app.xml" {
            redact_app_xml(&content)
        } else if name == "[Content_Types].xml" {
            clean_content_types_xml(&content, &stripped_parts)
        } else if name.ends_with(".rels") {
            clean_rels_xml(&content, &stripped_parts)
        } else {
            content
        };

        let options = FileOptions::default()
            .compression_method(file.compression())
            .unix_permissions(file.unix_mode().unwrap_or(0o644));

        zip_writer
            .start_file(name, options)
            .map_err(|err| OfficeParseError::CorruptedZip(err.to_string()))?;
        zip_writer
            .write_all(&final_content)
            .map_err(|err| OfficeParseError::CorruptedZip(err.to_string()))?;
    }

    let output_cursor = zip_writer
        .finish()
        .map_err(|err| OfficeParseError::CorruptedZip(err.to_string()))?;

    Ok(output_cursor.into_inner())
}

fn is_stripped_part(name: &str, profile: CleanProfile) -> bool {
    // 1. Always strip custom properties XML
    if name == "docProps/custom.xml" {
        return true;
    }

    // 2. Always strip thumbnails
    if name.starts_with("docProps/thumbnail.") || name.starts_with("docProps/thumbnail") {
        return true;
    }

    // 3. Always strip VBA macro binaries
    if name.ends_with("vbaProject.bin") || name.contains("vbaData.xml") {
        return true;
    }

    // 4. Strip comments files in Strict profile
    if profile == CleanProfile::Strict
        && (name.starts_with("word/comments")
            || name.starts_with("xl/comments")
            || name.starts_with("ppt/comments")
            || name.ends_with("comments.xml"))
    {
        return true;
    }

    false
}

fn clean_content_types_xml(content: &[u8], stripped_parts: &[String]) -> Vec<u8> {
    let mut reader = Reader::from_reader(content);
    reader.trim_text(false);
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let _ = writer.write_event(Event::Start(e));
            }
            Ok(Event::Empty(e)) => {
                let name = e.name();
                if name.as_ref() == b"Override" {
                    let mut should_skip = false;
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"PartName" {
                            let val = String::from_utf8_lossy(&attr.value);
                            let normalized_val = val.trim_start_matches('/');
                            if stripped_parts
                                .iter()
                                .any(|p| p == normalized_val || p.ends_with(normalized_val))
                            {
                                should_skip = true;
                                break;
                            }
                        }
                    }
                    if should_skip {
                        buf.clear();
                        continue;
                    }
                }
                let _ = writer.write_event(Event::Empty(e));
            }
            Ok(Event::Eof) => break,
            Ok(event) => {
                let _ = writer.write_event(event);
            }
            Err(_) => return content.to_vec(),
        }
        buf.clear();
    }

    writer.into_inner().into_inner()
}

fn clean_rels_xml(content: &[u8], stripped_parts: &[String]) -> Vec<u8> {
    let mut reader = Reader::from_reader(content);
    reader.trim_text(false);
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let _ = writer.write_event(Event::Start(e));
            }
            Ok(Event::Empty(e)) => {
                let name = e.name();
                if name.as_ref() == b"Relationship" {
                    let mut should_skip = false;
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"Target" {
                            let val = String::from_utf8_lossy(&attr.value);
                            let target_normalized = val.trim_start_matches('/');
                            if stripped_parts.iter().any(|p| {
                                p.ends_with(target_normalized) || target_normalized.ends_with(p)
                            }) {
                                should_skip = true;
                                break;
                            }
                        }
                    }
                    if should_skip {
                        buf.clear();
                        continue;
                    }
                }
                let _ = writer.write_event(Event::Empty(e));
            }
            Ok(Event::Eof) => break,
            Ok(event) => {
                let _ = writer.write_event(event);
            }
            Err(_) => return content.to_vec(),
        }
        buf.clear();
    }

    writer.into_inner().into_inner()
}

fn redact_xml_element_content(content: &[u8], target_local_names: &[&[u8]]) -> Vec<u8> {
    let mut reader = Reader::from_reader(content);
    reader.trim_text(false);
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    let mut buf = Vec::new();
    let mut current_redact_depth: usize = 0;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let local_name = e.name().into_inner();
                let local = if let Some(idx) = local_name.iter().position(|&b| b == b':') {
                    &local_name[idx + 1..]
                } else {
                    local_name
                };

                let is_target = target_local_names.contains(&local);
                let _ = writer.write_event(Event::Start(e));

                if is_target {
                    current_redact_depth += 1;
                }
            }
            Ok(Event::End(e)) => {
                let local_name = e.name().into_inner();
                let local = if let Some(idx) = local_name.iter().position(|&b| b == b':') {
                    &local_name[idx + 1..]
                } else {
                    local_name
                };

                let is_target = target_local_names.contains(&local);
                let _ = writer.write_event(Event::End(e));

                if is_target && current_redact_depth > 0 {
                    current_redact_depth -= 1;
                }
            }
            Ok(Event::Text(e)) => {
                if current_redact_depth > 0 {
                    buf.clear();
                    continue;
                } else {
                    let _ = writer.write_event(Event::Text(e));
                }
            }
            Ok(Event::Eof) => break,
            Ok(event) => {
                let _ = writer.write_event(event);
            }
            Err(_) => return content.to_vec(),
        }
        buf.clear();
    }

    writer.into_inner().into_inner()
}

fn redact_core_xml(content: &[u8]) -> Vec<u8> {
    let tags: &[&[u8]] = &[
        b"creator",
        b"lastModifiedBy",
        b"created",
        b"modified",
        b"title",
        b"subject",
        b"keywords",
        b"description",
    ];
    redact_xml_element_content(content, tags)
}

fn redact_app_xml(content: &[u8]) -> Vec<u8> {
    let tags: &[&[u8]] = &[
        b"Company",
        b"Manager",
        b"Application",
        b"AppVersion",
        b"TotalTime",
    ];
    redact_xml_element_content(content, tags)
}
