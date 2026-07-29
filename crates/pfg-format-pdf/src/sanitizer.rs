use lopdf::{Document, Object};
use pfg_policy::CleanProfile;
use std::collections::HashSet;

use crate::detector::detect_pdf_format;
use crate::scanner::PdfParseError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdfStructureReport {
    pub valid_header: bool,
    pub catalog_exists: bool,
    pub page_tree_exists: bool,
    pub page_count: usize,
    pub dangling_references_count: usize,
}

pub fn sanitize_pdf(buffer: &[u8], profile: CleanProfile) -> Result<Vec<u8>, PdfParseError> {
    if !detect_pdf_format(buffer) {
        return Err(PdfParseError::InvalidHeader);
    }

    let mut doc = Document::load_mem(buffer).map_err(|err| match err {
        lopdf::Error::Header => PdfParseError::InvalidHeader,
        _ => {
            let msg = err.to_string();
            if msg.to_lowercase().contains("encrypted") {
                PdfParseError::EncryptedPdf
            } else if msg.to_lowercase().contains("header") {
                PdfParseError::InvalidHeader
            } else {
                PdfParseError::CorruptedPdf(msg)
            }
        }
    })?;

    if doc.objects.len() > 500_000 {
        return Err(PdfParseError::CorruptedPdf(
            "PDF object count exceeds resource limit (max 500,000)".to_string(),
        ));
    }

    let initial_page_count = doc.get_pages().len();

    // 1. Identify objects to remove (specifically streams/dicts of metadata, JavaScript, embedded files, or annots in strict mode)
    let mut objects_to_remove = HashSet::new();

    if let Ok(Object::Reference(id)) = doc.trailer.get(b"Info") {
        objects_to_remove.insert(*id);
    }

    // Remove /Info entry from trailer dictionary
    doc.trailer.remove(b"Info");

    for (&obj_id, object) in &doc.objects {
        match object {
            Object::Stream(stream) => {
                let dict = &stream.dict;
                if is_metadata_dict(dict) {
                    objects_to_remove.insert(obj_id);
                }
            }
            Object::Dictionary(dict) => {
                // NEVER mark Catalog (/Type /Catalog), Pages (/Type /Pages), or Page (/Type /Page) objects for deletion!
                if is_essential_structure_dict(dict) {
                    continue;
                }

                if is_metadata_dict(dict)
                    || is_javascript_dict(dict)
                    || is_embedded_file_dict(dict)
                    || (profile == CleanProfile::Strict && is_annotation_dict(dict))
                {
                    objects_to_remove.insert(obj_id);
                }
            }
            _ => {}
        }
    }

    // 2. Clean up keys across all remaining object dictionaries
    for (&_obj_id, object) in doc.objects.iter_mut() {
        match object {
            Object::Stream(stream) => {
                clean_dictionary(&mut stream.dict, profile, &objects_to_remove);
            }
            Object::Dictionary(dict) => {
                clean_dictionary(dict, profile, &objects_to_remove);
            }
            _ => {}
        }
    }

    // Also clean trailer dictionary
    clean_dictionary(&mut doc.trailer, profile, &objects_to_remove);

    // Delete marked objects
    for obj_id in objects_to_remove {
        doc.objects.remove(&obj_id);
    }

    // 3. Re-serialize document structure to byte vector
    let mut bytes = Vec::new();
    doc.save_to(&mut bytes)
        .map_err(|err| PdfParseError::CorruptedPdf(err.to_string()))?;

    // 4. Perform post-sanitization structural validation
    let validation = validate_pdf_structure(&bytes)?;
    let has_root = doc.trailer.has(b"Root");
    if has_root && (!validation.catalog_exists || !validation.page_tree_exists) {
        return Err(PdfParseError::CorruptedPdf(
            "PDF structural validation failed after sanitization".to_string(),
        ));
    }
    if validation.dangling_references_count > 0 {
        return Err(PdfParseError::CorruptedPdf(
            "PDF structural validation failed: dangling references remain".to_string(),
        ));
    }
    if initial_page_count > 0 && validation.page_count != initial_page_count {
        return Err(PdfParseError::CorruptedPdf(format!(
            "Page count changed after sanitization: before={}, after={}",
            initial_page_count, validation.page_count
        )));
    }

    Ok(bytes)
}

pub fn validate_pdf_structure(buffer: &[u8]) -> Result<PdfStructureReport, PdfParseError> {
    if !detect_pdf_format(buffer) {
        return Err(PdfParseError::InvalidHeader);
    }

    let doc = Document::load_mem(buffer).map_err(|err| match err {
        lopdf::Error::Header => PdfParseError::InvalidHeader,
        _ => PdfParseError::CorruptedPdf(err.to_string()),
    })?;

    let root_ref = doc.trailer.get(b"Root").ok();
    let catalog_exists = match root_ref {
        Some(Object::Reference(id)) => doc.objects.contains_key(id),
        Some(Object::Dictionary(_)) => true,
        _ => doc.catalog().is_ok(),
    };

    let page_count = doc.get_pages().len();
    let page_tree_exists = page_count > 0 || catalog_exists;

    // Check for dangling references in remaining dictionaries
    let mut dangling_count = 0;
    for object in doc.objects.values() {
        match object {
            Object::Dictionary(dict) => {
                dangling_count += count_dangling_in_dict(dict, &doc);
            }
            Object::Stream(stream) => {
                dangling_count += count_dangling_in_dict(&stream.dict, &doc);
            }
            _ => {}
        }
    }

    Ok(PdfStructureReport {
        valid_header: true,
        catalog_exists,
        page_tree_exists,
        page_count,
        dangling_references_count: dangling_count,
    })
}

fn count_dangling_in_dict(dict: &lopdf::Dictionary, doc: &Document) -> usize {
    let mut count = 0;
    for (_key, value) in dict.iter() {
        match value {
            Object::Reference(id) => {
                if !doc.objects.contains_key(id) {
                    count += 1;
                }
            }
            Object::Array(arr) => {
                for item in arr {
                    if let Object::Reference(id) = item {
                        if !doc.objects.contains_key(id) {
                            count += 1;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    count
}

fn is_essential_structure_dict(dict: &lopdf::Dictionary) -> bool {
    let type_name = dict.get(b"Type").ok().and_then(|v| v.as_name_str().ok());
    type_name == Some("Catalog") || type_name == Some("Pages") || type_name == Some("Page")
}

fn is_metadata_dict(dict: &lopdf::Dictionary) -> bool {
    dict.get(b"Type").ok().and_then(|v| v.as_name_str().ok()) == Some("Metadata")
        || dict.get(b"Subtype").ok().and_then(|v| v.as_name_str().ok()) == Some("XML")
}

fn is_javascript_dict(dict: &lopdf::Dictionary) -> bool {
    dict.get(b"S")
        .ok()
        .and_then(|v| v.as_name_str().ok())
        .map(|name| name == "JavaScript" || name == "JS")
        .unwrap_or(false)
}

fn is_embedded_file_dict(dict: &lopdf::Dictionary) -> bool {
    let type_name = dict.get(b"Type").ok().and_then(|v| v.as_name_str().ok());
    let subtype_name = dict.get(b"Subtype").ok().and_then(|v| v.as_name_str().ok());
    type_name == Some("Filespec")
        || type_name == Some("EmbeddedFile")
        || subtype_name == Some("EmbeddedFile")
}

fn is_annotation_dict(dict: &lopdf::Dictionary) -> bool {
    dict.get(b"Type").ok().and_then(|v| v.as_name_str().ok()) == Some("Annot")
}

fn clean_dictionary(
    dict: &mut lopdf::Dictionary,
    profile: CleanProfile,
    objects_to_remove: &HashSet<(u32, u16)>,
) {
    dict.remove(b"Info");
    dict.remove(b"Metadata");
    dict.remove(b"JS");
    dict.remove(b"JavaScript");
    dict.remove(b"EmbeddedFiles");
    dict.remove(b"EF");

    if profile == CleanProfile::Strict {
        dict.remove(b"Annots");
    }

    if let Ok(action_obj) = dict.get(b"OpenAction") {
        let should_remove = match action_obj {
            Object::Reference(id) => objects_to_remove.contains(id),
            Object::Dictionary(action_dict) => is_javascript_dict(action_dict),
            _ => false,
        };
        if should_remove {
            dict.remove(b"OpenAction");
        }
    }

    if let Ok(aa_obj) = dict.get(b"AA") {
        let should_remove = match aa_obj {
            Object::Reference(id) => objects_to_remove.contains(id),
            Object::Dictionary(aa_dict) => is_javascript_dict(aa_dict),
            _ => false,
        };
        if should_remove {
            dict.remove(b"AA");
        }
    }
}
