use wasm_bindgen::prelude::*;

pub mod n64;

#[wasm_bindgen]
pub fn n64_decode(rom: Vec<u8>, patch: Vec<u8>) -> Result<Vec<u8>, String> {
    let mut x = n64::decode::VCDiffDecoder::new(patch, rom);
    Ok(x.decode().map(|v| v.to_vec())?)
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
}
