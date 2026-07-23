use std::collections::HashSet;
use lopdf::{Document, Object};
use pfg_policy::CleanProfile;

use crate::detector::detect_pdf_format;
use crate::scanner::PdfParseError;

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

    // 1. Remove /Info entry from trailer dictionary
    doc.trailer.remove(b"Info");

    // 2. Identify objects to remove
    let mut objects_to_remove = HashSet::new();

    for (&obj_id, object) in &doc.objects {
        match object {
            Object::Stream(stream) => {
                let dict = &stream.dict;
                if is_metadata_dict(dict) {
                    objects_to_remove.insert(obj_id);
                }
            }
            Object::Dictionary(dict) => {
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

    // 3. Clean up keys across all remaining object dictionaries
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

    // 4. Re-serialize document structure to byte vector
    let mut bytes = Vec::new();
    doc.save_to(&mut bytes)
        .map_err(|err| PdfParseError::CorruptedPdf(err.to_string()))?;

    Ok(bytes)
}

fn is_metadata_dict(dict: &lopdf::Dictionary) -> bool {
    dict.get(b"Type")
        .map(|v| v.as_name_str().ok() == Some("Metadata"))
        .unwrap_or(false)
        || dict
            .get(b"Subtype")
            .map(|v| v.as_name_str().ok() == Some("XML"))
            .unwrap_or(false)
        || dict.get(b"Metadata").is_ok()
}

fn is_javascript_dict(dict: &lopdf::Dictionary) -> bool {
    dict.get(b"JS").is_ok()
        || dict.get(b"JavaScript").is_ok()
        || dict
            .get(b"S")
            .map(|v| {
                if let Ok(name) = v.as_name_str() {
                    name == "JavaScript" || name == "JS"
                } else {
                    false
                }
            })
            .unwrap_or(false)
}

fn is_embedded_file_dict(dict: &lopdf::Dictionary) -> bool {
    let is_filespec = dict
        .get(b"Type")
        .map(|v| v.as_name_str().ok() == Some("Filespec") || v.as_name_str().ok() == Some("EmbeddedFile"))
        .unwrap_or(false);
    let has_ef = dict.get(b"EF").is_ok() || dict.get(b"EmbeddedFiles").is_ok();
    let is_subtype_ef = dict
        .get(b"Subtype")
        .map(|v| v.as_name_str().ok() == Some("EmbeddedFile"))
        .unwrap_or(false);

    is_filespec || has_ef || is_subtype_ef
}

fn is_annotation_dict(dict: &lopdf::Dictionary) -> bool {
    dict.get(b"Type")
        .map(|v| v.as_name_str().ok() == Some("Annot"))
        .unwrap_or(false)
        || dict.get(b"Annots").is_ok()
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
