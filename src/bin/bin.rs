use fp_web_patcher::n64_decode;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let rom = std::fs::read(args.get(1).unwrap()).unwrap();
    let patch = std::fs::read(args.get(2).unwrap()).unwrap();
    std::fs::write(args.get(3).unwrap(), n64_decode(rom, patch)).unwrap();
}
