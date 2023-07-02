mod cache;
pub mod decode;
mod insts;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum VCDiffDecoderError {
    #[error("attempted to read `{0}` byte(s) out of bounds (index: `{1}, length: `{2}`)")]
    IndexOutOfBounds(usize, usize, usize),
    #[error("invalid patch header")]
    InvalidHeader,
    #[error("patch uses an unsupported feature: {0}")]
    UnsupportedFeature(String),
    #[error("checksum does not match data (expected: `{0}`, got: `{1}`)")]
    InvalidChecksum(u32, u32),
    #[error("unexpected window size (expected: `{0}`, got: `{1}`)")]
    UnexpectedWindowSize(usize, usize),
}

fn read_byte(array: &[u8], index: &mut usize) -> Result<u8, VCDiffDecoderError> {
    *index += 1;
    array
        .get(*index - 1)
        .ok_or(VCDiffDecoderError::IndexOutOfBounds(
            1,
            *index - 1,
            array.len(),
        ))
        .copied()
}

fn read_bytes<'a>(
    num: usize,
    array: &'a [u8],
    index: &mut usize,
) -> Result<&'a [u8], VCDiffDecoderError> {
    *index += num;
    array
        .get(*index - num..*index)
        .ok_or(VCDiffDecoderError::IndexOutOfBounds(
            num,
            *index - num,
            array.len(),
        ))
}

fn read_int(array: &[u8], index: &mut usize) -> Result<u32, VCDiffDecoderError> {
    let mut result = 0;

    loop {
        let byte = read_byte(array, index)?;
        let digit = byte & 0x7f;
        result = (result << 7) | digit as u32;

        if byte & 0x80 == 0 {
            break;
        }
    }

    Ok(result)
}
