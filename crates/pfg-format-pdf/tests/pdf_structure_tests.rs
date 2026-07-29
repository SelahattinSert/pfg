use lopdf::{dictionary, Document, Object};
use pfg_format_pdf::{sanitize_pdf, validate_pdf_structure};
use pfg_policy::CleanProfile;

fn create_full_pdf_structure() -> Vec<u8> {
    let mut doc = Document::with_version("1.5");

    let page_id = doc.add_object(dictionary! {
        "Type" => Object::Name(b"Page".to_vec()),
        "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
    });

    let pages_id = doc.add_object(dictionary! {
        "Type" => Object::Name(b"Pages".to_vec()),
        "Count" => 1,
        "Kids" => vec![Object::Reference(page_id)],
    });

    let metadata_stream_id = doc.add_object(lopdf::Stream::new(
        dictionary! {
            "Type" => Object::Name(b"Metadata".to_vec()),
            "Subtype" => Object::Name(b"XML".to_vec()),
        },
        b"<xmp>Sensitive metadata</xmp>".to_vec(),
    ));

    let catalog_id = doc.add_object(dictionary! {
        "Type" => Object::Name(b"Catalog".to_vec()),
        "Pages" => Object::Reference(pages_id),
        "Metadata" => Object::Reference(metadata_stream_id),
    });

    doc.trailer.set("Root", catalog_id);

    let mut bytes = Vec::new();
    doc.save_to(&mut bytes).unwrap();
    bytes
}

#[test]
fn test_pdf_catalog_and_page_tree_preserved() {
    let pdf_bytes = create_full_pdf_structure();
    let sanitized_bytes =
        sanitize_pdf(&pdf_bytes, CleanProfile::Strict).expect("PDF sanitization must succeed");

    let validation =
        validate_pdf_structure(&sanitized_bytes).expect("Structure validation must pass");
    assert!(validation.catalog_exists, "Catalog must exist");
    assert!(validation.page_tree_exists, "Page tree must exist");
    assert_eq!(validation.page_count, 1, "Page count must remain 1");
    assert_eq!(
        validation.dangling_references_count, 0,
        "No dangling references must remain"
    );
}
