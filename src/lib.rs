use wasm_bindgen::prelude::*;

pub mod n64;
pub mod wii;

#[wasm_bindgen]
pub fn n64_decode(rom: Vec<u8>, patch: Vec<u8>) -> Result<Vec<u8>, String> {
    let mut x = n64::decode::VCDiffDecoder::new(patch, rom);
    Ok(x.decode().map(|v| v.to_vec())?)
}

#[wasm_bindgen]
pub fn wii_decode(rom: Vec<u8>) {
    let mut x = wii::decode::Parser::new(rom);
    x.decode()
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_n64_decode() {
        let rom = std::fs::read("tests/rom.z64").unwrap();
        let patch = std::fs::read("tests/patch.xdelta").unwrap();
        let out = std::fs::read("tests/out.z64").unwrap();

        assert_eq!(n64_decode(rom, patch).unwrap(), out);
    }

    #[test]
    fn test_u8() {
        let content5 = std::fs::read("tests/content5.app").unwrap();
        let mut p = wii::u8::U8Unpacker::new(content5.clone());
        let out = p.unpack();
        let mut p = wii::u8::U8Packer::new();
        //std::fs::write("out.bin", p.pack(out)).unwrap()
        assert_eq!(content5, p.pack(out));
    }
}
