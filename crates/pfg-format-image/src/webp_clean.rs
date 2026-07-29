use pfg_policy::CleanProfile;
use crate::jpeg::ImageParseError;

pub fn sanitize_webp(buffer: &[u8], profile: CleanProfile) -> Result<Vec<u8>, ImageParseError> {
    if buffer.len() < 12 || &buffer[0..4] != b"RIFF" || &buffer[8..12] != b"WEBP" {
        return Err(ImageParseError::InvalidSoi);
    }

    let mut output = Vec::with_capacity(buffer.len());
    output.extend_from_slice(&buffer[0..12]);

    let mut cursor = 12;
    while cursor < buffer.len() {
        if cursor + 8 > buffer.len() {
            return Err(ImageParseError::UnexpectedEof);
        }

        let chunk_type = &buffer[cursor..cursor + 4];
        let length = u32::from_le_bytes([
            buffer[cursor + 4],
            buffer[cursor + 5],
            buffer[cursor + 6],
            buffer[cursor + 7],
        ]) as usize;

        let padded_len = if length % 2 != 0 { length + 1 } else { length };
        let chunk_end = cursor + 8 + padded_len;

        if chunk_end > buffer.len() {
            return Err(ImageParseError::UnexpectedEof);
        }

        let is_removable = match profile {
            CleanProfile::Balanced => chunk_type == b"EXIF" || chunk_type == b"XMP ",
            CleanProfile::Strict => chunk_type == b"EXIF" || chunk_type == b"XMP " || chunk_type == b"ICCP",
        };

        if !is_removable {
            if chunk_type == b"VP8X" && length >= 1 {
                // Copy 8-byte chunk header
                output.extend_from_slice(&buffer[cursor..cursor + 8]);
                let payload_start = output.len();
                // Copy payload
                output.extend_from_slice(&buffer[cursor + 8..cursor + 8 + length]);
                // Clear EXIF (bit 3 - 0x08) and XMP (bit 2 - 0x04) flags in VP8X
                let mut clear_mask = 0x08 | 0x04;
                if profile == CleanProfile::Strict {
                    clear_mask |= 0x20; // Clear ICCP bit in VP8X in strict mode
                }
                output[payload_start] &= !clear_mask;

                if length % 2 != 0 {
                    output.push(0);
                }
            } else {
                output.extend_from_slice(&buffer[cursor..cursor + 8 + length]);
                if length % 2 != 0 {
                    output.push(0);
                }
            }
        }

        cursor = chunk_end;
    }

    // Update RIFF payload size (file_size - 8)
    let riff_size = (output.len() - 8) as u32;
    output[4..8].copy_from_slice(&riff_size.to_le_bytes());

    Ok(output)
}
