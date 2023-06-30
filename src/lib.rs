use wasm_bindgen::prelude::*;
use wii::{wad::{Parser, Encoder}, romc::Romc, u8::{U8Packer, U8Unpacker}};

pub mod n64;
pub mod wii;

#[wasm_bindgen]
pub fn n64_decode(rom: Vec<u8>, patch: Vec<u8>) -> Result<Vec<u8>, String> {
    let mut x = n64::decode::VCDiffDecoder::new(&patch, &rom);
    Ok(x.decode().map(|v| v.to_vec())?)
}

#[wasm_bindgen]
pub struct WiiInjectConfig {
    wad: Vec<u8>,
    xdelta_patch: Vec<u8>,
    gzi_patches: Vec<Vec<u8>>
}

#[wasm_bindgen]
pub fn wii_inject(x: WiiInjectConfig) -> Result<Vec<u8>, String> {
    let mut wad_parser = Parser::new(x.wad);
    let mut wad = wad_parser.decode();
    let mut u8_unpack = U8Unpacker::new(&wad.contents[5]);
    let mut content5 = u8_unpack.unpack();
    let rom = content5.find_entry("./romc").ok_or("Rom Unpacking error")?;
    let mut romc_decode = Romc::new();
    let decoded_rom = romc_decode.decode(rom.get_file_contents()?);
    let patched_rom = n64_decode(decoded_rom, x.xdelta_patch)?;
    let mut romc_encode = Romc::new();
    let encoded_rom = romc_encode.encode(&patched_rom);
    rom.set_file_contents(encoded_rom)?;
    let mut u8_pack = U8Packer::new();
    let content5 = u8_pack.pack(content5);
    wad.contents[5] = content5;
    for patch in x.gzi_patches {
        wad.parse_gzi_patch(patch);
    }

    let mut wad_encoder = Encoder::new(wad);
    Ok(wad_encoder.encode())
}

#[cfg(test)]
mod tests {
    use crate::wii::{
        romc,
        u8::{Entry, File, Folder},
    };

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
    fn test_wii_decode() {
        let wad = std::fs::read("pm.wad").unwrap();
        let gzi = std::fs::read("patch.gzi").unwrap();
        let xdelta = std::fs::read("fp-us.xdelta").unwrap();
        let x = WiiInjectConfig {
            wad,
            xdelta_patch: xdelta,
            gzi_patches: vec![gzi],
        };
        let wad = wii_inject(x);
        std::fs::write("OUT.wad", wad.unwrap()).unwrap();
    }

    /*
    #[test]
    fn test_u8() {
        let content5 = std::fs::read("tests/content5.app").unwrap();
        let mut p = wii::u8::U8Unpacker::new(content5);
        let mut out = p.unpack();
        let x = out.find_entry("./romc").unwrap();
        *x = Entry::File(File {
            name: "womc".to_string(),
            contents: vec![0xde, 0xad, 0xbe, 0xef],
        });
        let mut p = wii::u8::U8Packer::new();
        std::fs::write("out.bin", p.pack(out)).unwrap();
        //assert_eq!(content5, p.pack(out));
    }

    #[test]
    fn test_romc() {
        let f = std::fs::read("tests/rom.z64").unwrap();
        let mut r = wii::romc::Romc::new();
        let comp = r.encode(&f);
        let mut r = wii::romc::Romc::new();
        let decomp = r.decode(&comp);
        assert_eq!(f, decomp);
    }
    */
}
