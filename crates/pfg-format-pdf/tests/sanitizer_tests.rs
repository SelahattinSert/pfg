use lopdf::{dictionary, Document, Object, StringFormat};
use pfg_format_pdf::{sanitize_pdf, scan_pdf_metadata, PdfParseError};
use pfg_policy::{CleanProfile, PolicyEngine};

fn create_base_pdf() -> Document {
    Document::with_version("1.5")
}

#[test]
fn test_sanitize_pdf_invalid_header() {
    let result = sanitize_pdf(b"NOT_A_PDF_HEADER", CleanProfile::Balanced);
    assert_eq!(result, Err(PdfParseError::InvalidHeader));
}

#[test]
fn test_sanitize_pdf_info_dictionary() {
    let policy = PolicyEngine::balanced();
    let mut doc = create_base_pdf();

    let info_id = doc.add_object(dictionary! {
        "Title" => Object::String(b"Secret Document".to_vec(), StringFormat::Literal),
        "Author" => Object::String(b"John Doe".to_vec(), StringFormat::Literal),
        "CreationDate" => Object::String(b"D:20260724120000Z".to_vec(), StringFormat::Literal),
    });

    doc.trailer.set("Info", info_id);

    let mut input_bytes = Vec::new();
    doc.save_to(&mut input_bytes).unwrap();

    // Verify initial scan has findings
    let initial_findings = scan_pdf_metadata(&input_bytes, &policy).unwrap();
    assert!(initial_findings.iter().any(|f| f.key == "Title"));

    // Sanitize
    let sanitized_bytes = sanitize_pdf(&input_bytes, CleanProfile::Balanced).unwrap();

    // Verify sanitized scan has no /Info findings
    let sanitized_findings = scan_pdf_metadata(&sanitized_bytes, &policy).unwrap();
    assert!(!sanitized_findings
        .iter()
        .any(|f| f.key == "Title" || f.key == "Author"));
}

#[test]
fn test_sanitize_pdf_xmp_metadata() {
    let policy = PolicyEngine::balanced();
    let mut doc = create_base_pdf();

    let xmp_content = br#"<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/">
   <dc:creator>Jane Doe</dc:creator>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"#;

    let xmp_stream = lopdf::Stream::new(
        dictionary! {
            "Type" => Object::Name(b"Metadata".to_vec()),
            "Subtype" => Object::Name(b"XML".to_vec()),
        },
        xmp_content.to_vec(),
    );

    let stream_id = doc.add_object(xmp_stream);
    doc.trailer.set(
        "Root",
        dictionary! {
            "Metadata" => stream_id,
        },
    );

    let mut input_bytes = Vec::new();
    doc.save_to(&mut input_bytes).unwrap();

    let initial_findings = scan_pdf_metadata(&input_bytes, &policy).unwrap();
    assert!(initial_findings
        .iter()
        .any(|f| f.key == "XMP Metadata" || f.key == "dc:creator"));

    let sanitized_bytes = sanitize_pdf(&input_bytes, CleanProfile::Balanced).unwrap();

    let sanitized_findings = scan_pdf_metadata(&sanitized_bytes, &policy).unwrap();
    assert!(!sanitized_findings
        .iter()
        .any(|f| f.key == "XMP Metadata" || f.key == "dc:creator"));
}

#[test]
fn test_sanitize_pdf_javascript_actions() {
    let policy = PolicyEngine::balanced();
    let mut doc = create_base_pdf();

    let js_obj = doc.add_object(dictionary! {
        "S" => Object::Name(b"JavaScript".to_vec()),
        "JS" => Object::String(b"app.alert('Malicious');".to_vec(), StringFormat::Literal),
    });

    doc.trailer.set("OpenAction", js_obj);

    let mut input_bytes = Vec::new();
    doc.save_to(&mut input_bytes).unwrap();

    let initial_findings = scan_pdf_metadata(&input_bytes, &policy).unwrap();
    assert!(initial_findings
        .iter()
        .any(|f| f.key.contains("JavaScript") || f.key.contains("JS")));

    let sanitized_bytes = sanitize_pdf(&input_bytes, CleanProfile::Balanced).unwrap();

    let sanitized_findings = scan_pdf_metadata(&sanitized_bytes, &policy).unwrap();
    assert!(!sanitized_findings
        .iter()
        .any(|f| f.key.contains("JavaScript") || f.key.contains("JS")));
}

#[test]
fn test_sanitize_pdf_embedded_files() {
    let policy = PolicyEngine::balanced();
    let mut doc = create_base_pdf();

    let ef_obj = doc.add_object(dictionary! {
        "Type" => Object::Name(b"Filespec".to_vec()),
        "F" => Object::String(b"attachment.txt".to_vec(), StringFormat::Literal),
        "EF" => dictionary! {
            "F" => Object::Reference((99, 0)),
        },
    });

    doc.trailer.set(
        "Root",
        dictionary! {
            "Names" => dictionary! {
                "EmbeddedFiles" => ef_obj,
            },
        },
    );

    let mut input_bytes = Vec::new();
    doc.save_to(&mut input_bytes).unwrap();

    let initial_findings = scan_pdf_metadata(&input_bytes, &policy).unwrap();
    assert!(initial_findings
        .iter()
        .any(|f| f.key == "EmbeddedFile" || f.key == "EmbeddedFiles"));

    let sanitized_bytes = sanitize_pdf(&input_bytes, CleanProfile::Balanced).unwrap();

    let sanitized_findings = scan_pdf_metadata(&sanitized_bytes, &policy).unwrap();
    assert!(!sanitized_findings
        .iter()
        .any(|f| f.key == "EmbeddedFile" || f.key == "EmbeddedFiles"));
}

#[test]
fn test_sanitize_pdf_annots_balanced_vs_strict() {
    let policy = PolicyEngine::balanced();
    let mut doc = create_base_pdf();

    let annot_obj = doc.add_object(dictionary! {
        "Type" => Object::Name(b"Annot".to_vec()),
        "Subtype" => Object::Name(b"Text".to_vec()),
        "Contents" => Object::String(b"Review note".to_vec(), StringFormat::Literal),
    });

    doc.trailer.set(
        "Root",
        dictionary! {
            "Annots" => Object::Array(vec![Object::Reference(annot_obj)]),
        },
    );

    let mut input_bytes = Vec::new();
    doc.save_to(&mut input_bytes).unwrap();

    let initial_findings = scan_pdf_metadata(&input_bytes, &policy).unwrap();
    assert!(initial_findings
        .iter()
        .any(|f| f.key == "Annotation" || f.key == "Annots"));

    // Balanced mode retains annotations
    let balanced_bytes = sanitize_pdf(&input_bytes, CleanProfile::Balanced).unwrap();
    let balanced_findings = scan_pdf_metadata(&balanced_bytes, &policy).unwrap();
    assert!(balanced_findings
        .iter()
        .any(|f| f.key == "Annotation" || f.key == "Annots"));

    // Strict mode removes annotations
    let strict_bytes = sanitize_pdf(&input_bytes, CleanProfile::Strict).unwrap();
    let strict_findings = scan_pdf_metadata(&strict_bytes, &policy).unwrap();
    assert!(!strict_findings
        .iter()
        .any(|f| f.key == "Annotation" || f.key == "Annots"));
}

#[test]
fn test_sanitize_pdf_removes_referenced_info_object() {
    let mut doc = create_base_pdf();

    let info_id = doc.add_object(dictionary! {
        "Title" => Object::String(b"Secret Document".to_vec(), StringFormat::Literal),
        "Author" => Object::String(b"John Doe".to_vec(), StringFormat::Literal),
        "Creator" => Object::String(b"PDF Generator".to_vec(), StringFormat::Literal),
        "Producer" => Object::String(b"PDF Producer".to_vec(), StringFormat::Literal),
    });

    doc.trailer.set("Info", info_id);

    let mut input_bytes = Vec::new();
    doc.save_to(&mut input_bytes).unwrap();

    let sanitized_bytes = sanitize_pdf(&input_bytes, CleanProfile::Balanced).unwrap();
    let cleaned_doc = Document::load_mem(&sanitized_bytes).unwrap();

    assert!(!cleaned_doc.objects.contains_key(&info_id));

    let info_keys: &[&[u8]] = &[
        b"Author",
        b"Creator",
        b"Title",
        b"Producer",
        b"Subject",
        b"Keywords",
    ];
    for object in cleaned_doc.objects.values() {
        if let Ok(dict) = object.as_dict() {
            for key in info_keys {
                assert!(!dict.has(key), "Found info key {:?} in object", key);
            }
        }
    }
}
