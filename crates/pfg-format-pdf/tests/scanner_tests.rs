use lopdf::{dictionary, Document, Object, StringFormat};
use pfg_format_pdf::{scan_pdf_metadata, PdfParseError};
use pfg_model::{FindingCategory, FindingSource};
use pfg_policy::PolicyEngine;

fn create_base_pdf() -> Document {
    Document::with_version("1.5")
}

#[test]
fn test_scan_pdf_invalid_header() {
    let policy = PolicyEngine::balanced();
    let result = scan_pdf_metadata(b"NOT_A_PDF_HEADER", &policy);
    assert_eq!(result, Err(PdfParseError::InvalidHeader));
}

#[test]
fn test_scan_pdf_corrupted() {
    let policy = PolicyEngine::balanced();
    let result = scan_pdf_metadata(b"%PDF-1.4\ncorrupted content without trailer", &policy);
    assert!(matches!(result, Err(PdfParseError::CorruptedPdf(_))));
}

#[test]
fn test_scan_pdf_info_dictionary() {
    let policy = PolicyEngine::balanced();
    let mut doc = create_base_pdf();

    let info_id = doc.add_object(dictionary! {
        "Title" => Object::String(b"Confidential Report".to_vec(), StringFormat::Literal),
        "Author" => Object::String(b"Alice Smith".to_vec(), StringFormat::Literal),
        "Creator" => Object::String(b"SuperPdf 2.0".to_vec(), StringFormat::Literal),
        "CreationDate" => Object::String(b"D:20260724120000Z".to_vec(), StringFormat::Literal),
    });

    doc.trailer.set("Info", info_id);

    let mut pdf_bytes = Vec::new();
    doc.save_to(&mut pdf_bytes).unwrap();

    let findings = scan_pdf_metadata(&pdf_bytes, &policy).unwrap();

    assert!(findings.iter().any(|f| f.source == FindingSource::PdfInfo && f.key == "Title" && f.display_value.as_deref() == Some("Confidential Report")));
    assert!(findings.iter().any(|f| f.source == FindingSource::PdfInfo && f.key == "Author" && f.category == FindingCategory::Identity));
    assert!(findings.iter().any(|f| f.source == FindingSource::PdfInfo && f.key == "Creator" && f.category == FindingCategory::Software));
    assert!(findings.iter().any(|f| f.source == FindingSource::PdfInfo && f.key == "CreationDate" && f.category == FindingCategory::Time));
}

#[test]
fn test_scan_pdf_xmp_metadata_stream() {
    let policy = PolicyEngine::balanced();
    let mut doc = create_base_pdf();

    let xmp_content = br#"<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/">
   <dc:creator>John Doe</dc:creator>
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
    doc.trailer.set("Root", dictionary! {
        "Metadata" => stream_id,
    });

    let mut pdf_bytes = Vec::new();
    doc.save_to(&mut pdf_bytes).unwrap();

    let findings = scan_pdf_metadata(&pdf_bytes, &policy).unwrap();

    assert!(findings.iter().any(|f| f.key == "XMP Metadata"));
    assert!(findings.iter().any(|f| f.key == "dc:creator" && f.display_value.as_deref() == Some("John Doe")));
}

#[test]
fn test_scan_pdf_javascript_actions() {
    let policy = PolicyEngine::balanced();
    let mut doc = create_base_pdf();

    let js_obj = doc.add_object(dictionary! {
        "S" => Object::Name(b"JavaScript".to_vec()),
        "JS" => Object::String(b"app.alert('Hello');".to_vec(), StringFormat::Literal),
    });

    doc.trailer.set("OpenAction", js_obj);

    let mut pdf_bytes = Vec::new();
    doc.save_to(&mut pdf_bytes).unwrap();

    let findings = scan_pdf_metadata(&pdf_bytes, &policy).unwrap();

    assert!(findings.iter().any(|f| f.key.contains("JavaScript") || f.key.contains("JS")));
}

#[test]
fn test_scan_pdf_embedded_files_and_annots() {
    let policy = PolicyEngine::balanced();
    let mut doc = create_base_pdf();

    let annot_obj = doc.add_object(dictionary! {
        "Type" => Object::Name(b"Annot".to_vec()),
        "Subtype" => Object::Name(b"Text".to_vec()),
        "Contents" => Object::String(b"Secret Note".to_vec(), StringFormat::Literal),
    });

    let ef_obj = doc.add_object(dictionary! {
        "Type" => Object::Name(b"Filespec".to_vec()),
        "F" => Object::String(b"data.csv".to_vec(), StringFormat::Literal),
        "EF" => dictionary! {
            "F" => Object::Reference((99, 0)),
        },
    });

    doc.trailer.set("Root", dictionary! {
        "Annots" => Object::Array(vec![Object::Reference(annot_obj)]),
        "Names" => dictionary! {
            "EmbeddedFiles" => ef_obj,
        },
    });

    let mut pdf_bytes = Vec::new();
    doc.save_to(&mut pdf_bytes).unwrap();

    let findings = scan_pdf_metadata(&pdf_bytes, &policy).unwrap();

    assert!(findings.iter().any(|f| f.key == "Annotation" || f.key == "Annots"));
    assert!(findings.iter().any(|f| f.key == "EmbeddedFile" || f.key == "EmbeddedFiles"));
}

#[test]
fn test_scan_pdf_encrypt_and_sig() {
    let policy = PolicyEngine::balanced();
    let mut doc = create_base_pdf();

    let sig_obj = doc.add_object(dictionary! {
        "Type" => Object::Name(b"Sig".to_vec()),
        "Filter" => Object::Name(b"Adobe.PPKLite".to_vec()),
        "SubFilter" => Object::Name(b"adbe.pkcs7.detached".to_vec()),
        "Name" => Object::String(b"Signer Name".to_vec(), StringFormat::Literal),
    });

    let encrypt_obj = doc.add_object(dictionary! {
        "Filter" => Object::Name(b"Standard".to_vec()),
        "V" => 2,
    });

    doc.trailer.set("Encrypt", encrypt_obj);
    doc.trailer.set("Sig", sig_obj);

    let mut pdf_bytes = Vec::new();
    doc.save_to(&mut pdf_bytes).unwrap();

    let findings = scan_pdf_metadata(&pdf_bytes, &policy).unwrap();

    assert!(findings.iter().any(|f| f.key == "Encrypt"));
    assert!(findings.iter().any(|f| f.key == "Digital Signature" || f.key == "Sig"));
}
