use super::{
    cache::AddrCache,
    insts::{CodeTable, Instruction, Type},
    read_byte, read_bytes, read_int,
};

pub struct VCDiffDecoder {
    input: Vec<u8>,
    source: Vec<u8>,
    output: Vec<u8>,
    index: usize,
    window_header: WindowHeader,
    window: Window,
    code_table: CodeTable,
    addr_cache: AddrCache,
}

#[derive(Debug)]
struct WindowHeader {
    window_indicator: u8,
    source: Option<(u32, u32)>,
    delta_encoding_len: u32,
    target_window_len: usize,
    delta_indicator: u8,
    data_len: usize,
    inst_len: usize,
    addr_len: usize,
    hash: Option<u32>,
    len: usize,
}

struct Window {
    data_index: usize,
    inst_index: usize,
    addr_index: usize,
}

const VCD_DECOMPRESS: u8 = 1;
const VCD_CODETABLE: u8 = 2;
const VCD_APPHEADER: u8 = 4;

const VCD_SOURCE: u8 = 1;
const VCD_TARGET: u8 = 2;
const VCD_CHECKSUM: u8 = 4;

const VCD_DATACOMP: u8 = 1;
const VCD_INSTCOMP: u8 = 2;
const VCD_ADDRCOMP: u8 = 4;

impl VCDiffDecoder {
    pub fn new(input: Vec<u8>, source: Vec<u8>) -> Self {
        VCDiffDecoder {
            input,
            source,
            output: vec![],
            index: 0,
            window_header: WindowHeader {
                window_indicator: 0,
                source: None,
                delta_encoding_len: 0,
                target_window_len: 0,
                delta_indicator: 0,
                data_len: 0,
                inst_len: 0,
                addr_len: 0,
                hash: None,
                len: 0,
            },
            window: Window {
                data_index: 0,
                inst_index: 0,
                addr_index: 0,
            },
            code_table: CodeTable::default(),
            addr_cache: AddrCache::default(),
        }
    }

    pub fn decode(&mut self) -> &[u8] {
        let header = read_bytes(3, &self.input, &mut self.index);
        assert_eq!(*header, [0xd6, 0xc3, 0xc4]);
        self.seek(1);

        let header_indicator = read_byte(&self.input, &mut self.index);

        if header_indicator & VCD_DECOMPRESS != 0 && read_byte(&self.input, &mut self.index) != 0 {
            panic!("Decompression not implemented");
        }

        if header_indicator & VCD_CODETABLE != 0 && read_int(&self.input, &mut self.index) != 0 {
            panic!("custom code table not implemented");
        }

        if header_indicator & VCD_APPHEADER != 0 {
            let len = read_int(&self.input, &mut self.index);
            self.seek(len as usize);
        }

        while !self.at_end() {
            self.decode_window_header();
            self.decode_window();
            self.addr_cache = AddrCache::default();
        }

        &self.output
    }

    fn decode_window_header(&mut self) {
        let window_indicator = read_byte(&self.input, &mut self.index);
        let source = if window_indicator & (VCD_SOURCE | VCD_TARGET) != 0 {
            Some((
                read_int(&self.input, &mut self.index),
                read_int(&self.input, &mut self.index),
            ))
        } else {
            None
        };

        let delta_encoding_len = read_int(&self.input, &mut self.index);
        let start_index = self.index;
        let target_window_len = read_int(&self.input, &mut self.index) as usize;
        let delta_indicator = read_byte(&self.input, &mut self.index);

        if delta_indicator & (VCD_DATACOMP | VCD_INSTCOMP | VCD_ADDRCOMP) != 0 {
            panic!("Decompression not implemented");
        }

        let data_len = read_int(&self.input, &mut self.index) as usize;
        let inst_len = read_int(&self.input, &mut self.index) as usize;
        let addr_len = read_int(&self.input, &mut self.index) as usize;

        let hash = if window_indicator & VCD_CHECKSUM != 0 {
            Some(u32::from_be_bytes(
                read_bytes(4, &self.input, &mut self.index)
                    .try_into()
                    .unwrap(),
            ))
        } else {
            None
        };

        self.window_header = WindowHeader {
            window_indicator,
            source,
            delta_encoding_len,
            target_window_len,
            delta_indicator,
            data_len,
            inst_len,
            addr_len,
            hash,
            len: self.index - start_index,
        };
    }

    fn decode_window(&mut self) {
        let data_index = self.index;
        let inst_index = self.window_header.data_len + data_index;
        let addr_index = self.window_header.inst_len + inst_index;

        self.window = Window {
            data_index,
            inst_index,
            addr_index,
        };

        assert_eq!(
            self.window_header.delta_encoding_len as usize,
            addr_index + self.window_header.addr_len + self.window_header.len - self.index
        );

        let mut out = Vec::with_capacity(self.window_header.target_window_len);

        self.index = addr_index + self.window_header.addr_len;

        while self.window.inst_index < addr_index {
            let (inst1, inst2) = self.code_table.table[self.input[self.window.inst_index] as usize];
            self.window.inst_index += 1;
            self.decode_instruction(inst1, &mut out);

            if let Some(inst2) = inst2 {
                self.decode_instruction(inst2, &mut out);
            };
        }

        let a = adler32::RollingAdler32::from_buffer(&out);
        if let Some(hash) = self.window_header.hash {
            assert_eq!(a.hash(), hash);
        }
        self.output.append(&mut out);
    }

    fn decode_instruction(&mut self, inst: Instruction, out: &mut Vec<u8>) {
        let size = if inst.size == 0 {
            read_int(&self.input, &mut self.window.inst_index)
        } else {
            inst.size
        } as usize;

        match inst.ty {
            Type::Run => {
                let b = self.input[self.window.data_index];
                self.window.data_index += 1;
                for _ in 0..size {
                    out.push(b);
                }
            }
            Type::Add => {
                self.window.data_index += size;
                self.input
                    .get(self.window.data_index - size..self.window.data_index)
                    .unwrap()
                    .iter()
                    .for_each(|x| out.push(*x));
            }
            Type::Copy => {
                let src_sgmt_len = self.window_header.source.map_or(0, |x| x.0);
                let addr = self.addr_cache.addr_decode(
                    src_sgmt_len + out.len() as u32,
                    inst.mode,
                    &mut self.window.addr_index,
                    &self.input,
                );
                if addr < src_sgmt_len {
                    let src_sgmt_pos = (self.window_header.source.unwrap().1 + addr) as usize;
                    for b in &mut self.source[src_sgmt_pos..src_sgmt_pos + size] {
                        out.push(*b);
                    }
                } else {
                    let addr = addr - src_sgmt_len;
                    for i in addr..(addr + size as u32) {
                        let b = out[i as usize];
                        out.push(b);
                    }
                }
            }
        }
    }

    fn seek(&mut self, num: usize) {
        self.index += num;
    }

    fn at_end(&self) -> bool {
        self.index == self.input.len()
    }
}
