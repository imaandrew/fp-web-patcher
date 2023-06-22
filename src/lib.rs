use wasm_bindgen::prelude::*;

pub mod n64;

#[wasm_bindgen]
pub fn n64_decode(rom: Vec<u8>, patch: Vec<u8>) -> Vec<u8> {
    let mut x = n64::decode::VCDiffDecoder::new(rom, patch);
    x.decode().to_vec()
}
