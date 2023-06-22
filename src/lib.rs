use wasm_bindgen::prelude::*;

pub mod n64;

#[wasm_bindgen]
pub fn decode(input: Vec<u8>, source: Vec<u8>) -> Vec<u8> {
    let mut x = n64::decode::VCDiffDecoder::new(input, source);
    x.decode().to_vec()
}
