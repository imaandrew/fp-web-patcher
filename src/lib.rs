use wasm_bindgen::prelude::*;
use wii::wad::Wad;

pub mod n64;
pub mod wii;

#[wasm_bindgen]
pub fn n64_decode(rom: Vec<u8>, patch: Vec<u8>) -> Result<Vec<u8>, String> {
    let mut x = n64::decode::VCDiffDecoder::new(patch, rom);
    Ok(x.decode().map(|v| v.to_vec())?)
}

pub fn wii_decode(rom: Vec<u8>) -> Wad {
    let mut x = wii::wad::Parser::new(rom);
    x.decode()
}

pub fn wii_encode(wad: Wad) -> Vec<u8> {
    let mut x = wii::wad::Encoder::new(wad);
    x.encode()
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
        let mut w = wii_decode(wad.clone());
        let rom = std::fs::read("fp-us.z64").unwrap();
        let mut u8p = wii::u8::U8Unpacker::new(w.contents[5].clone());
        let mut out = u8p.unpack();
        let c = match &mut out {
            Entry::Folder(f) => &mut f.contents,
            _ => panic!(),
        };
        for i in 0..c.len() {
            let a = match &c[i] {
                Entry::File(f) => f,
                _ => continue,
            };

            if a.name == "romc" {
                let mut r = romc::Romc::new();
                c[i] = Entry::File(File {
                    name: "romc".to_string(),
                    contents: r.encode(&rom),
                })
            }
        }
        let mut u8p = wii::u8::U8Packer::new();
        let new_content5 = u8p.pack(out);
        w.contents[5] = new_content5;
        let gzi = std::fs::read("patch.gzi").unwrap();
        w.parse_gzi_patch(gzi);
        w.footer = Vec::with_capacity(0x40);
        let mut x = wii::wad::Encoder::new(w);
        let v = x.encode();
        std::fs::write("OUT.wad", &v).unwrap();

        //assert_eq!(v, wad);
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

    #[test]
    fn test_romc() {
        let f = std::fs::read("tests/rom.z64").unwrap();
        let mut r = wii::romc::Romc::new();
        let comp = r.encode(&f);
        let mut r = wii::romc::Romc::new();
        let decomp = r.decode(&comp);
        assert_eq!(f, decomp);
    }
}
