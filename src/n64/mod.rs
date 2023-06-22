mod cache;
pub mod decode;
mod insts;

fn read_byte(array: &[u8], index: &mut usize) -> u8 {
    *index += 1;
    array[*index - 1]
}

fn read_bytes<'a>(num: usize, array: &'a [u8], index: &mut usize) -> &'a [u8] {
    *index += num;
    &array[*index - num..*index]
}

fn read_int(array: &[u8], index: &mut usize) -> u32 {
    let mut result = 0;

    loop {
        let byte = read_byte(array, index);
        let digit = byte & 0x7f;
        result = (result << 7) | digit as u32;

        if byte & 0x80 == 0 {
            break;
        }
    }

    result
}
