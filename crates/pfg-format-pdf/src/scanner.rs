use lopdf::{Document, Object};
use pfg_model::{Finding, FindingCategory, FindingLocation, FindingSource};
use pfg_policy::PolicyEngine;
use thiserror::Error;

use crate::detector::detect_pdf_format;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PdfParseError {
    #[error("Invalid PDF header")]
    InvalidHeader,
    #[error("Corrupted PDF structure: {0}")]
    CorruptedPdf(String),
    #[error("Encrypted PDF document")]
    EncryptedPdf,
}

pub fn scan_pdf_metadata(
    buffer: &[u8],
    policy: &PolicyEngine,
) -> Result<Vec<Finding>, PdfParseError> {
    if !detect_pdf_format(buffer) {
        return Err(PdfParseError::InvalidHeader);
    }

    let doc = Document::load_mem(buffer).map_err(|err| match err {
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

    let mut findings = Vec::new();

    // 1. Trailer checks
    // Trailer /Info dictionary
    if let Ok(info_obj) = doc.trailer.get(b"Info") {
        let (info_dict, info_obj_num) = match info_obj {
            Object::Reference(id) => {
                if let Ok(dict) = doc.get_dictionary(*id) {
                    (Some(dict), id.0)
                } else {
                    (None, id.0)
                }
            }
            Object::Dictionary(dict) => (Some(dict), 0),
            _ => (None, 0),
        };

        if let Some(dict) = info_dict {
            for (k_bytes, v_obj) in dict {
                let key_str = String::from_utf8_lossy(k_bytes).to_string();
                let category = categorize_info_key(&key_str);
                let severity = policy.categorize_severity(category, &key_str);
                let display_val = object_to_string(v_obj);

                findings.push(Finding {
                    id: format!("pdf-info-{}-{}", info_obj_num, key_str),
                    category,
                    severity,
                    source: FindingSource::PdfInfo,
                    key: key_str,
                    display_value: Some(display_val),
                    raw_value_available: true,
                    location: FindingLocation::PdfObject {
                        object_number: info_obj_num,
                    },
                    risk_explanation: "PDF /Info trailer dictionary contains document metadata."
                        .to_string(),
                    removable: true,
                });
            }
        }
    }

    // Trailer /Encrypt check
    if doc.trailer.get(b"Encrypt").is_ok() {
        let category = FindingCategory::Technical;
        let key = "Encrypt".to_string();
        let severity = policy.categorize_severity(category, &key);

        findings.push(Finding {
            id: "pdf-trailer-encrypt".to_string(),
            category,
            severity,
            source: FindingSource::PdfObject,
            key,
            display_value: Some("PDF Encryption dictionary present".to_string()),
            raw_value_available: true,
            location: FindingLocation::PdfObject { object_number: 0 },
            risk_explanation: "PDF trailer contains encryption dictionary.".to_string(),
            removable: true,
        });
    }

    // Trailer /Sig check
    if doc.trailer.get(b"Sig").is_ok() {
        let category = FindingCategory::Identity;
        let key = "Digital Signature".to_string();
        let severity = policy.categorize_severity(category, &key);

        findings.push(Finding {
            id: "pdf-trailer-sig".to_string(),
            category,
            severity,
            source: FindingSource::PdfObject,
            key,
            display_value: Some("Digital signature present in trailer".to_string()),
            raw_value_available: true,
            location: FindingLocation::PdfObject { object_number: 0 },
            risk_explanation: "PDF trailer references digital signature.".to_string(),
            removable: true,
        });
    }

    // 2. Iterate through all PDF objects
    for (&(obj_num, _gen), object) in &doc.objects {
        match object {
            Object::Stream(stream) => {
                inspect_dictionary(&stream.dict, obj_num, policy, &mut findings);

                let is_metadata = stream
                    .dict
                    .get(b"Type")
                    .map(|v| v.as_name_str().ok() == Some("Metadata"))
                    .unwrap_or(false)
                    || stream
                        .dict
                        .get(b"Subtype")
                        .map(|v| v.as_name_str().ok() == Some("XML"))
                        .unwrap_or(false);

                if is_metadata {
                    let content_bytes = stream
                        .decompressed_content()
                        .unwrap_or_else(|_| stream.content.clone());

                    let xmp_findings = extract_xmp_findings(&content_bytes, obj_num, policy);
                    findings.extend(xmp_findings);
                }
            }
            Object::Dictionary(dict) => {
                inspect_dictionary(dict, obj_num, policy, &mut findings);
            }
            _ => {}
        }
    }

    Ok(findings)
}

fn inspect_dictionary(
    dict: &lopdf::Dictionary,
    obj_num: u32,
    policy: &PolicyEngine,
    findings: &mut Vec<Finding>,
) {
    // Check for Executable JavaScript Actions (/JS or /JavaScript or /S /JavaScript)
    let has_js_key = dict.get(b"JS").is_ok() || dict.get(b"JavaScript").is_ok();
    let has_js_type = dict
        .get(b"S")
        .map(|v| {
            if let Ok(name) = v.as_name_str() {
                name == "JavaScript" || name == "JS"
            } else {
                false
            }
        })
        .unwrap_or(false);

    if has_js_key || has_js_type {
        let js_code = dict
            .get(b"JS")
            .ok()
            .or_else(|| dict.get(b"JavaScript").ok())
            .map(object_to_string)
            .unwrap_or_else(|| "JavaScript Action Present".to_string());

        let category = FindingCategory::Technical;
        let key = "JavaScript Action".to_string();
        let severity = policy.categorize_severity(category, &key);

        findings.push(Finding {
            id: format!("pdf-js-{}", obj_num),
            category,
            severity,
            source: FindingSource::PdfObject,
            key,
            display_value: Some(js_code),
            raw_value_available: true,
            location: FindingLocation::PdfObject {
                object_number: obj_num,
            },
            risk_explanation:
                "PDF object contains executable JavaScript code posing security risks.".to_string(),
            removable: true,
        });
    }

    // Check for Embedded Files (/Type /Filespec or /EF or /EmbeddedFiles)
    let is_filespec = dict
        .get(b"Type")
        .map(|v| {
            v.as_name_str().ok() == Some("Filespec") || v.as_name_str().ok() == Some("EmbeddedFile")
        })
        .unwrap_or(false);
    let has_ef = dict.get(b"EF").is_ok() || dict.get(b"EmbeddedFiles").is_ok();

    if is_filespec || has_ef {
        let filename = dict
            .get(b"F")
            .ok()
            .or_else(|| dict.get(b"UF").ok())
            .map(object_to_string)
            .unwrap_or_else(|| "Embedded file attachment".to_string());

        let category = FindingCategory::EmbeddedContent;
        let key = if has_ef {
            "EmbeddedFiles".to_string()
        } else {
            "EmbeddedFile".to_string()
        };
        let severity = policy.categorize_severity(category, &key);

        findings.push(Finding {
            id: format!("pdf-ef-{}", obj_num),
            category,
            severity,
            source: FindingSource::PdfObject,
            key,
            display_value: Some(filename),
            raw_value_available: true,
            location: FindingLocation::PdfObject {
                object_number: obj_num,
            },
            risk_explanation: "PDF object contains embedded file attachments.".to_string(),
            removable: true,
        });
    }

    // Check for Annotations (/Type /Annot or /Annots)
    let is_annot = dict
        .get(b"Type")
        .map(|v| v.as_name_str().ok() == Some("Annot"))
        .unwrap_or(false);
    let has_annots = dict.get(b"Annots").is_ok();

    if is_annot || has_annots {
        let content = dict
            .get(b"Contents")
            .ok()
            .map(object_to_string)
            .or_else(|| {
                dict.get(b"Subtype")
                    .ok()
                    .map(|s| format!("Annot Subtype: {}", object_to_string(s)))
            })
            .unwrap_or_else(|| "PDF Annotation present".to_string());

        let category = FindingCategory::Comments;
        let key = if has_annots {
            "Annots".to_string()
        } else {
            "Annotation".to_string()
        };
        let severity = policy.categorize_severity(category, &key);

        findings.push(Finding {
            id: format!("pdf-annot-{}", obj_num),
            category,
            severity,
            source: FindingSource::PdfObject,
            key,
            display_value: Some(content),
            raw_value_available: true,
            location: FindingLocation::PdfObject {
                object_number: obj_num,
            },
            risk_explanation: "PDF object contains annotations or comments.".to_string(),
            removable: true,
        });
    }

    // Check for Digital Signatures (/Type /Sig or /SubFilter)
    let is_sig = dict
        .get(b"Type")
        .map(|v| v.as_name_str().ok() == Some("Sig"))
        .unwrap_or(false);
    let has_sig_filter = dict
        .get(b"SubFilter")
        .map(|v| {
            if let Ok(name) = v.as_name_str() {
                name.contains("pkcs7") || name.contains("signature")
            } else {
                false
            }
        })
        .unwrap_or(false);

    if is_sig || has_sig_filter {
        let signer = dict
            .get(b"Name")
            .ok()
            .map(object_to_string)
            .unwrap_or_else(|| "Digital Signature".to_string());

        let category = FindingCategory::Identity;
        let key = "Digital Signature".to_string();
        let severity = policy.categorize_severity(category, &key);

        findings.push(Finding {
            id: format!("pdf-sig-{}", obj_num),
            category,
            severity,
            source: FindingSource::PdfObject,
            key,
            display_value: Some(signer),
            raw_value_available: true,
            location: FindingLocation::PdfObject {
                object_number: obj_num,
            },
            risk_explanation: "PDF contains digital signature object.".to_string(),
            removable: true,
        });
    }

    // Check for Encryption Object (/Filter /Standard or /Type /Encrypt)
    let is_encrypt = dict
        .get(b"Type")
        .map(|v| v.as_name_str().ok() == Some("Encrypt"))
        .unwrap_or(false);

    if is_encrypt {
        let category = FindingCategory::Technical;
        let key = "Encrypt".to_string();
        let severity = policy.categorize_severity(category, &key);

        findings.push(Finding {
            id: format!("pdf-encrypt-{}", obj_num),
            category,
            severity,
            source: FindingSource::PdfObject,
            key,
            display_value: Some("PDF Encryption dictionary present".to_string()),
            raw_value_available: true,
            location: FindingLocation::PdfObject {
                object_number: obj_num,
            },
            risk_explanation: "PDF contains encryption dictionary.".to_string(),
            removable: true,
        });
    }
}

fn categorize_info_key(key: &str) -> FindingCategory {
    match key {
        "Author" => FindingCategory::Identity,
        "Creator" | "Producer" => FindingCategory::Software,
        "Title" | "Subject" | "Keywords" => FindingCategory::Comments,
        "CreationDate" | "ModDate" => FindingCategory::Time,
        _ => FindingCategory::DocumentHistory,
    }
}

fn object_to_string(obj: &Object) -> String {
    match obj {
        Object::String(bytes, _) => String::from_utf8_lossy(bytes).to_string(),
        Object::Name(bytes) => String::from_utf8_lossy(bytes).to_string(),
        Object::Integer(i) => i.to_string(),
        Object::Real(f) => f.to_string(),
        Object::Boolean(b) => b.to_string(),
        Object::Reference(id) => format!("{} {} R", id.0, id.1),
        _ => format!("{:?}", obj),
    }
}

fn extract_xmp_findings(xmp_bytes: &[u8], obj_num: u32, policy: &PolicyEngine) -> Vec<Finding> {
    if xmp_bytes.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let xmp_str = String::from_utf8_lossy(xmp_bytes);

    let category = FindingCategory::EmbeddedContent;
    let key = "XMP Metadata".to_string();
    let severity = policy.categorize_severity(category, &key);

    findings.push(Finding {
        id: format!("pdf-xmp-packet-{}", obj_num),
        category,
        severity,
        source: FindingSource::Xmp,
        key,
        display_value: Some("XMP Stream Present".to_string()),
        raw_value_available: true,
        location: FindingLocation::PdfObject {
            object_number: obj_num,
        },
        risk_explanation: "PDF contains embedded XMP metadata stream.".to_string(),
        removable: true,
    });

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
        if let Some(val) = find_element_or_attr(&xmp_str, prop_key) {
            let cat = categorize_xmp_prop(prop_key);
            let k = prop_key.to_string();
            let sev = policy.categorize_severity(cat, &k);

            findings.push(Finding {
                id: format!("pdf-xmp-{}-{}", obj_num, prop_key.replace(':', "-")),
                category: cat,
                severity: sev,
                source: FindingSource::Xmp,
                key: k,
                display_value: Some(val),
                raw_value_available: true,
                location: FindingLocation::PdfObject {
                    object_number: obj_num,
                },
                risk_explanation: format!(
                    "XMP property '{}' present in PDF metadata stream.",
                    prop_key
                ),
                removable: true,
            });
        }
    }

    findings
}

fn find_element_or_attr(xml: &str, prop: &str) -> Option<String> {
    let open_tag = format!("<{}>", prop);
    let close_tag = format!("</{}>", prop);
    if let Some(start_idx) = xml.find(&open_tag) {
        let val_start = start_idx + open_tag.len();
        if let Some(end_idx) = xml[val_start..].find(&close_tag) {
            let val = &xml[val_start..val_start + end_idx];
            return Some(val.trim().to_string());
        }
    }

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
