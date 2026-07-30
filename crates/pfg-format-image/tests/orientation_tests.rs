use image::{GenericImageView, ImageBuffer, Rgb};
use pfg_format_image::{extract_jpeg_orientation, sanitize_jpeg, CleanProfile};

fn create_test_jpeg_with_orientation(width: u32, height: u32, orientation: u16) -> Vec<u8> {
    // 1. Create an asymmetric image (e.g., 20x10)
    let mut img = ImageBuffer::<Rgb<u8>, Vec<u8>>::new(width, height);
    for y in 0..height {
        for x in 0..width {
            let r = if x < width / 2 { 255 } else { 0 };
            let g = if y < height / 2 { 255 } else { 0 };
            let b = 128;
            img.put_pixel(x, y, Rgb([r, g, b]));
        }
    }

    // Encode to JPEG memory buffer
    let mut raw_jpeg = Vec::new();
    let mut encoder = image::codecs::jpeg::JpegEncoder::new(&mut raw_jpeg);
    encoder.encode_image(&img).unwrap();

    if orientation == 1 {
        return raw_jpeg;
    }

    // Build minimal EXIF payload with Orientation tag (0x0112)
    let mut exif_payload = Vec::new();
    exif_payload.extend_from_slice(b"Exif\0\0II\x2a\0\x08\0\0\0");
    exif_payload.extend_from_slice(&[1, 0]);
    let orient_bytes = orientation.to_le_bytes();
    exif_payload.extend_from_slice(&[0x12, 0x01, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, orient_bytes[0], orient_bytes[1], 0x00, 0x00]);
    exif_payload.extend_from_slice(&[0, 0, 0, 0]);

    let app1_len = (exif_payload.len() + 2) as u16;
    let mut final_jpeg = vec![0xFF, 0xD8, 0xFF, 0xE1];
    final_jpeg.extend_from_slice(&app1_len.to_be_bytes());
    final_jpeg.extend_from_slice(&exif_payload);
    final_jpeg.extend_from_slice(&raw_jpeg[2..]);

    final_jpeg
}

#[test]
fn test_all_eight_exif_orientations() {
    let orig_width = 20u32;
    let orig_height = 10u32;

    for orient in 1..=8 {
        let jpeg_bytes = create_test_jpeg_with_orientation(orig_width, orig_height, orient);

        if orient > 1 {
            let extracted = extract_jpeg_orientation(&jpeg_bytes);
            assert_eq!(extracted, Some(orient), "Failed to extract orientation {}", orient);
        }

        let cleaned_bytes = sanitize_jpeg(&jpeg_bytes, CleanProfile::Balanced)
            .unwrap_or_else(|_| panic!("Failed to sanitize JPEG with orientation {}", orient));

        let cleaned_img = image::load_from_memory_with_format(&cleaned_bytes, image::ImageFormat::Jpeg)
            .unwrap_or_else(|_| panic!("Cleaned image for orientation {} failed to decode", orient));

        let (c_width, c_height) = cleaned_img.dimensions();

        if (5..=8).contains(&orient) {
            assert_eq!(c_width, orig_height, "Orientation {} width failed", orient);
            assert_eq!(c_height, orig_width, "Orientation {} height failed", orient);
        } else {
            assert_eq!(c_width, orig_width, "Orientation {} width failed", orient);
            assert_eq!(c_height, orig_height, "Orientation {} height failed", orient);
        }

        let cleaned_extracted = extract_jpeg_orientation(&cleaned_bytes);
        assert_eq!(cleaned_extracted, None, "Cleaned image must have no EXIF orientation tag");
    }
}
