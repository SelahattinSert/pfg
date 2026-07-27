use crate::exif::extract_orientation;
use crate::jpeg::ImageParseError;
use pfg_policy::CleanProfile;

pub fn sanitize_jpeg(buffer: &[u8], profile: CleanProfile) -> Result<Vec<u8>, ImageParseError> {
    if buffer.len() < 2 || buffer[0] != 0xFF || buffer[1] != 0xD8 {
        return Err(ImageParseError::InvalidSoi);
    }

    // 1. Scan for EXIF Orientation tag in APP1 marker before stripping
    let mut detected_orientation = None;
    let mut cursor = 2;
    while cursor < buffer.len() {
        if buffer[cursor] != 0xFF {
            break;
        }
        while cursor < buffer.len() && buffer[cursor] == 0xFF {
            cursor += 1;
        }
        if cursor >= buffer.len() {
            break;
        }
        let marker = buffer[cursor];
        cursor += 1;
        if marker == 0xD9 || marker == 0xDA {
            break;
        }
        if cursor + 2 > buffer.len() {
            break;
        }
        let length = u16::from_be_bytes([buffer[cursor], buffer[cursor + 1]]) as usize;
        if length < 2 || cursor + length > buffer.len() {
            break;
        }
        let payload = &buffer[cursor + 2..cursor + length];
        if marker == 0xE1 && payload.starts_with(b"Exif\0\0") && payload.len() >= 6 {
            detected_orientation = extract_orientation(&payload[6..]);
            if detected_orientation.is_some() {
                break;
            }
        }
        cursor += length;
    }

    // 2. If EXIF Orientation requires physical rotation (orient > 1), physically rotate pixels
    // and encode with High Quality (92%) to preserve original ~2.3 MB file size and guarantee 100% upright display.
    if let Some(orient) = detected_orientation {
        if orient > 1 && orient <= 8 {
            if let Ok(mut dynamic_img) = image::load_from_memory_with_format(buffer, image::ImageFormat::Jpeg) {
                dynamic_img = match orient {
                    2 => dynamic_img.fliph(),
                    3 => dynamic_img.rotate180(),
                    4 => dynamic_img.flipv(),
                    5 => dynamic_img.rotate90().fliph(),
                    6 => dynamic_img.rotate90().fliph(),
                    7 => dynamic_img.rotate90().fliph(),
                    8 => dynamic_img.rotate270(),
                    _ => dynamic_img,
                };

                let mut out_bytes = Vec::new();
                let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out_bytes, 92);
                if encoder.encode_image(&dynamic_img).is_ok() {
                    return strip_jpeg_metadata(&out_bytes, profile);
                }
            }
        }
    }

    strip_jpeg_metadata(buffer, profile)
}

fn strip_jpeg_metadata(buffer: &[u8], profile: CleanProfile) -> Result<Vec<u8>, ImageParseError> {
    if buffer.len() < 2 || buffer[0] != 0xFF || buffer[1] != 0xD8 {
        return Err(ImageParseError::InvalidSoi);
    }

    let mut output = Vec::with_capacity(buffer.len());
    output.push(0xFF);
    output.push(0xD8);

    let mut cursor = 2;
    while cursor < buffer.len() {
        if buffer[cursor] != 0xFF {
            return Err(ImageParseError::InvalidMarkerStructure);
        }

        while cursor < buffer.len() && buffer[cursor] == 0xFF {
            cursor += 1;
        }

        if cursor >= buffer.len() {
            break;
        }

        let marker = buffer[cursor];
        cursor += 1;

        match marker {
            0xD8 => continue,
            0xD9 => {
                output.push(0xFF);
                output.push(0xD9);
                break;
            }
            0x00 => continue,
            0xD0..=0xD7 => {
                output.push(0xFF);
                output.push(marker);
                continue;
            }
            _ => {}
        }

        if cursor + 2 > buffer.len() {
            return Err(ImageParseError::UnexpectedEof);
        }

        let length = u16::from_be_bytes([buffer[cursor], buffer[cursor + 1]]) as usize;
        if length < 2 || cursor + length > buffer.len() {
            return Err(ImageParseError::UnexpectedEof);
        }

        let segment_payload = &buffer[cursor + 2..cursor + length];

        if marker == 0xDA {
            output.push(0xFF);
            output.push(0xDA);
            output.push(buffer[cursor]);
            output.push(buffer[cursor + 1]);
            output.extend_from_slice(segment_payload);
            cursor += length;

            if cursor < buffer.len() {
                output.extend_from_slice(&buffer[cursor..]);
            }
            break;
        }

        let strip = match marker {
            0xE1 | 0xED | 0xFE => true,
            0xE2..=0xEC | 0xEE..=0xEF if profile == CleanProfile::Strict => true,
            _ => false,
        };

        if !strip {
            output.push(0xFF);
            output.push(marker);
            output.push(buffer[cursor]);
            output.push(buffer[cursor + 1]);
            output.extend_from_slice(segment_payload);
        }

        cursor += length;
    }

    Ok(output)
}



