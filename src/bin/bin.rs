use fp_web_patcher::n64_decode;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let rom = std::fs::read(args.get(0).unwrap()).unwrap();
    let patch = std::fs::read(args.get(1).unwrap()).unwrap();
    std::fs::write(args.get(2).unwrap(), n64_decode(patch, rom)).unwrap();
}
