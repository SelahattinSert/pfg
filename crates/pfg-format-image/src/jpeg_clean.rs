use crate::jpeg::ImageParseError;
use pfg_policy::CleanProfile;

pub fn sanitize_jpeg(buffer: &[u8], profile: CleanProfile) -> Result<Vec<u8>, ImageParseError> {
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

        // Skip extra 0xFF padding bytes
        while cursor < buffer.len() && buffer[cursor] == 0xFF {
            cursor += 1;
        }

        if cursor >= buffer.len() {
            break;
        }

        let marker = buffer[cursor];
        cursor += 1;

        // Standalone markers with no length payload
        match marker {
            0xD8 => continue, // SOI
            0xD9 => {
                // EOI - End of image
                output.push(0xFF);
                output.push(0xD9);
                break;
            }
            0x00 => continue, // Escaped byte
            0xD0..=0xD7 => {
                output.push(0xFF);
                output.push(marker);
                continue;
            }
            _ => {}
        }

        // Markers with 2-byte Big-Endian length parameter
        if cursor + 2 > buffer.len() {
            return Err(ImageParseError::UnexpectedEof);
        }

        let length = u16::from_be_bytes([buffer[cursor], buffer[cursor + 1]]) as usize;
        if length < 2 {
            return Err(ImageParseError::InvalidMarkerLength);
        }

        if cursor + length > buffer.len() {
            return Err(ImageParseError::UnexpectedEof);
        }

        let segment_payload = &buffer[cursor + 2..cursor + length];

        if marker == 0xDA {
            // SOS (Start of Scan) header parsed, image entropy data follows
            output.push(0xFF);
            output.push(0xDA);
            output.push(buffer[cursor]);
            output.push(buffer[cursor + 1]);
            output.extend_from_slice(segment_payload);
            cursor += length;

            // Append all remaining entropy payload (up to and including EOI)
            if cursor < buffer.len() {
                output.extend_from_slice(&buffer[cursor..]);
            }
            break;
        }

        let strip = match marker {
            0xE1 | 0xED | 0xFE => true, // APP1 (EXIF/XMP), APP13 (IPTC/Photoshop), COM (Comment)
            0xE2..=0xEC | 0xEE..=0xEF if profile == CleanProfile::Strict => true, // Other APP markers in Strict mode
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
