use pfg_format_image::{
    detect_format, sanitize_image, sanitize_png, sanitize_webp, ImageFormat, ImageParseError,
};
use pfg_policy::CleanProfile;

fn build_png_chunk(chunk_type: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut chunk = Vec::new();
    let len = data.len() as u32;
    chunk.extend_from_slice(&len.to_be_bytes());
    chunk.extend_from_slice(chunk_type);
    chunk.extend_from_slice(data);
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(chunk_type);
    hasher.update(data);
    let crc = hasher.finalize();
    chunk.extend_from_slice(&crc.to_be_bytes());
    chunk
}

#[test]
fn test_sanitize_png_removes_metadata_chunks_and_recalculates_crc() {
    let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]; // PNG signature
    png.extend_from_slice(&build_png_chunk(b"IHDR", &[0; 13]));
    png.extend_from_slice(&build_png_chunk(b"tEXt", b"Comment\0Secret Metadata"));
    png.extend_from_slice(&build_png_chunk(b"eXIf", b"EXIF payload data"));
    png.extend_from_slice(&build_png_chunk(b"IDAT", b"Compressed image data"));
    png.extend_from_slice(&build_png_chunk(b"IEND", b""));

    let cleaned = sanitize_png(&png, CleanProfile::Balanced).unwrap();

    assert_eq!(detect_format(&cleaned), Some(ImageFormat::Png));
    assert!(!cleaned.windows(4).any(|w| w == b"tEXt"));
    assert!(!cleaned.windows(4).any(|w| w == b"eXIf"));
    assert!(cleaned.windows(4).any(|w| w == b"IHDR"));
    assert!(cleaned.windows(4).any(|w| w == b"IDAT"));
    assert!(cleaned.windows(4).any(|w| w == b"IEND"));

    // Verify CRC calculation for output chunks
    let mut cursor = 8;
    while cursor + 12 <= cleaned.len() {
        let len = u32::from_be_bytes([
            cleaned[cursor],
            cleaned[cursor + 1],
            cleaned[cursor + 2],
            cleaned[cursor + 3],
        ]) as usize;
        let chunk_type = &cleaned[cursor + 4..cursor + 8];
        let chunk_data = &cleaned[cursor + 8..cursor + 8 + len];
        let crc_in_file = u32::from_be_bytes([
            cleaned[cursor + 8 + len],
            cleaned[cursor + 8 + len + 1],
            cleaned[cursor + 8 + len + 2],
            cleaned[cursor + 8 + len + 3],
        ]);

        let mut hasher = crc32fast::Hasher::new();
        hasher.update(chunk_type);
        hasher.update(chunk_data);
        assert_eq!(hasher.finalize(), crc_in_file);

        cursor += 12 + len;
    }
}

#[test]
fn test_sanitize_png_invalid_header() {
    let invalid_buffer = b"NOT_A_PNG_HEADER";
    let res = sanitize_png(invalid_buffer, CleanProfile::Balanced);
    assert_eq!(res.err(), Some(ImageParseError::InvalidSoi));
}

#[test]
fn test_sanitize_webp_removes_exif_xmp_and_updates_header() {
    let mut webp = Vec::new();
    webp.extend_from_slice(b"RIFF");
    webp.extend_from_slice(&[0, 0, 0, 0]); // RIFF size placeholder
    webp.extend_from_slice(b"WEBP");

    // VP8X chunk with EXIF (0x08) and XMP (0x04) flags set
    let vp8x_payload = vec![0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    webp.extend_from_slice(b"VP8X");
    webp.extend_from_slice(&(vp8x_payload.len() as u32).to_le_bytes());
    webp.extend_from_slice(&vp8x_payload);

    // EXIF chunk
    let exif_data = b"EXIF raw data";
    webp.extend_from_slice(b"EXIF");
    webp.extend_from_slice(&(exif_data.len() as u32).to_le_bytes());
    webp.extend_from_slice(exif_data);
    if exif_data.len() % 2 == 1 {
        webp.push(0); // padding
    }

    // XMP chunk
    let xmp_data = b"<xmp>meta</xmp>";
    webp.extend_from_slice(b"XMP ");
    webp.extend_from_slice(&(xmp_data.len() as u32).to_le_bytes());
    webp.extend_from_slice(xmp_data);
    if xmp_data.len() % 2 == 1 {
        webp.push(0); // padding
    }

    // VP8 chunk
    let vp8_data = b"VP8 frame data payload";
    webp.extend_from_slice(b"VP8 ");
    webp.extend_from_slice(&(vp8_data.len() as u32).to_le_bytes());
    webp.extend_from_slice(vp8_data);

    // Set correct RIFF size
    let riff_size = (webp.len() - 8) as u32;
    webp[4..8].copy_from_slice(&riff_size.to_le_bytes());

    let cleaned = sanitize_webp(&webp, CleanProfile::Balanced).unwrap();

    assert_eq!(detect_format(&cleaned), Some(ImageFormat::WebP));
    assert!(!cleaned.windows(4).any(|w| w == b"EXIF"));
    assert!(!cleaned.windows(4).any(|w| w == b"XMP "));
    assert!(cleaned.windows(4).any(|w| w == b"VP8 "));

    // Verify RIFF size updated
    let new_riff_size = u32::from_le_bytes([cleaned[4], cleaned[5], cleaned[6], cleaned[7]]);
    assert_eq!(new_riff_size as usize, cleaned.len() - 8);

    // Verify VP8X flags updated (0x0C & !(0x08 | 0x04) == 0x00)
    let vp8x_pos = cleaned.windows(4).position(|w| w == b"VP8X").unwrap();
    let flags_byte = cleaned[vp8x_pos + 8];
    assert_eq!(flags_byte & 0x08, 0, "EXIF bit should be cleared");
    assert_eq!(flags_byte & 0x04, 0, "XMP bit should be cleared");
}

#[test]
fn test_sanitize_image_unified() {
    let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    png.extend_from_slice(&build_png_chunk(b"IHDR", &[0; 13]));
    png.extend_from_slice(&build_png_chunk(b"tEXt", b"Metadata"));
    png.extend_from_slice(&build_png_chunk(b"IEND", b""));

    let cleaned = sanitize_image(&png, ImageFormat::Png, CleanProfile::Balanced).unwrap();
    assert!(!cleaned.windows(4).any(|w| w == b"tEXt"));
}
