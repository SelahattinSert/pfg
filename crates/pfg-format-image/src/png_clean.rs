use crc32fast::Hasher;
use crate::jpeg::ImageParseError;

pub fn sanitize_png(buffer: &[u8]) -> Result<Vec<u8>, ImageParseError> {
    if buffer.len() < 8 || &buffer[0..8] != b"\x89PNG\r\n\x1a\n" {
        return Err(ImageParseError::InvalidSoi);
    }

    let mut output = Vec::with_capacity(buffer.len());
    output.extend_from_slice(&buffer[0..8]);

    let mut cursor = 8;
    while cursor + 12 <= buffer.len() {
        let length = u32::from_be_bytes([
            buffer[cursor],
            buffer[cursor + 1],
            buffer[cursor + 2],
            buffer[cursor + 3],
        ]) as usize;

        let chunk_type = &buffer[cursor + 4..cursor + 8];
        let chunk_end = cursor + 12 + length;

        if chunk_end > buffer.len() {
            return Err(ImageParseError::UnexpectedEof);
        }

        let is_removable = matches!(
            chunk_type,
            b"eXIf" | b"tEXt" | b"zTXt" | b"iTXt" | b"tIME" | b"iCCP" | b"pHYs" | b"sPLT"
        );

        if !is_removable {
            // Copy 4-byte length
            output.extend_from_slice(&buffer[cursor..cursor + 4]);
            // Copy 4-byte type + length bytes data
            let type_and_data = &buffer[cursor + 4..cursor + 8 + length];
            output.extend_from_slice(type_and_data);

            // Compute and append CRC32
            let mut hasher = Hasher::new();
            hasher.update(type_and_data);
            let crc = hasher.finalize();
            output.extend_from_slice(&crc.to_be_bytes());
        }

        cursor = chunk_end;
    }

    if cursor != buffer.len() {
        return Err(ImageParseError::UnexpectedEof);
    }

    Ok(output)
}
