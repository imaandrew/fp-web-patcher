use serde::{Deserialize, Serialize};
use std::panic;
use wasm_bindgen::prelude::*;
use wii::{
    romc::Romc,
    u8::{U8Error, U8Packer, U8Unpacker},
    wad::{Encoder, Parser, WadError},
};
extern crate console_error_panic_hook;

impl From<U8Error> for String {
    fn from(value: U8Error) -> Self {
        format!("u8 error: {}", value)
    }
}

impl From<WadError> for String {
    fn from(value: WadError) -> Self {
        format!("wad packer/unpacker error: {}", value)
    }
}

pub mod n64;
pub mod wii;
pub mod wiiu;

#[wasm_bindgen]
pub fn n64_decode(rom: &[u8], patch: &[u8]) -> Result<Vec<u8>, String> {
    let mut x = n64::decode::VCDiffDecoder::new(patch, rom);
    x.decode().map_err(|e| format!("n64 error: {}", e))
}

#[derive(Serialize, Deserialize)]
pub struct WiiInjectSettings {
    pub wad: Vec<u8>,
    pub xdelta_patch: Vec<u8>,
    pub gzi_patch: Vec<u8>,
    pub channel_id: String,
    pub title: String,
}

#[wasm_bindgen]
pub fn wii_inject(s: JsValue) -> Result<Vec<u8>, String> {
    panic::set_hook(Box::new(console_error_panic_hook::hook));
    let s: WiiInjectSettings = serde_wasm_bindgen::from_value(s).map_err(|_| "Invalid settings")?;
    let mut wad_parser = Parser::new(&s.wad);
    let mut wad = wad_parser.decode()?;
    let mut u8_unpack = U8Unpacker::new(&wad.contents[5]);
    let mut content5 = u8_unpack.unpack()?;
    let rom = content5.find_entry("./romc")?;
    let mut romc_decode = Romc::new();
    let decoded_rom = romc_decode.decode(rom.get_file_contents()?);
    let patched_rom = n64_decode(&decoded_rom, &s.xdelta_patch)?;
    let mut romc_encode = Romc::new();
    let encoded_rom = romc_encode.encode(&patched_rom);
    rom.set_file_contents(encoded_rom)?;
    let mut u8_pack = U8Packer::new();
    let content5 = u8_pack.pack(content5);
    wad.contents[5] = content5;

    wad.set_channel_id(&s.channel_id);
    wad.set_channel_title(&s.title);
    wad.set_region(3);

    wad.parse_gzi_patch(&s.gzi_patch)?;

    let mut wad_encoder = Encoder::new(&mut wad);
    Ok(wad_encoder.encode()?)
}

#[derive(Serialize, Deserialize)]
pub struct WiiUInjectSettings {
    input_archive: Vec<u8>,
    xdelta_patch: Vec<u8>,
    enable_dark_filter: bool,
    enable_widescreen: bool,
    config: Vec<u8>,
    return_zip: bool,
    frame_layout: Vec<u8>,
}

#[wasm_bindgen]
pub fn wiiu_inject(s: JsValue) -> Vec<u8> {
    panic::set_hook(Box::new(console_error_panic_hook::hook));
    let mut s: WiiUInjectSettings = serde_wasm_bindgen::from_value(s).unwrap();
    wiiu::patch(&mut s)
}
