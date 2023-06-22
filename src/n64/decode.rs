use super::{
    cache::AddrCache,
    insts::{CodeTable, Type},
    read_byte, read_bytes, read_int,
};

pub struct VCDiffDecoder {
    input: Vec<u8>,
    source: Vec<u8>,
    output: Vec<u8>,
    index: usize,
    window_header: WindowHeader,
    code_table: CodeTable,
    addr_cache: AddrCache,
}

#[derive(Debug)]
struct WindowHeader {
    window_indicator: u8,
    source: Option<(u32, u32)>,
    delta_encoding_len: u32,
    target_window_len: u32,
    delta_indicator: u8,
    data_len: u32,
    inst_len: u32,
    addr_len: u32,
    hash: Option<u32>,
}

const VCD_DECOMPRESS: u8 = 1;
const VCD_CODETABLE: u8 = 2;
const VCD_APPHEADER: u8 = 4;

const VCD_SOURCE: u8 = 1;
const VCD_TARGET: u8 = 2;
const VCD_ALDER32: u8 = 4;

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
            },
            code_table: CodeTable::default(),
            addr_cache: AddrCache::default(),
        }
    }

    pub fn decode(&mut self) -> &[u8] {
        let header = read_bytes(3, &self.input, &mut self.index);
        assert!(header == [0xd6, 0xc3, 0xc4]);
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
        let target_window_len = read_int(&self.input, &mut self.index);
        let delta_indicator = read_byte(&self.input, &mut self.index);

        if delta_indicator & (VCD_DATACOMP | VCD_INSTCOMP | VCD_ADDRCOMP) != 0 {
            panic!("Decompression not implemented");
        }

        let data_len = read_int(&self.input, &mut self.index);
        let inst_len = read_int(&self.input, &mut self.index);
        let addr_len = read_int(&self.input, &mut self.index);

        let hash = if window_indicator & VCD_ALDER32 != 0 {
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
        };
    }

    fn decode_window(&mut self) {
        let mut data_index = self.index;
        let mut inst_index = self.window_header.data_len as usize + data_index;
        let mut addr_index = self.window_header.inst_len as usize + inst_index;
        let a = addr_index;
        let mut out = Vec::with_capacity(self.window_header.target_window_len as usize);
        self.index = addr_index + self.window_header.addr_len as usize;
        while inst_index < a {
            let ii = self.input[inst_index];
            let (inst1, inst2) = self.code_table.table[ii as usize];
            inst_index += 1;
            let size1 = if inst1.size == 0 {
                read_int(&self.input, &mut inst_index)
            } else {
                inst1.size
            };

            match inst1.ty {
                Type::Run => {
                    let b = self.input[data_index];
                    data_index += 1;
                    for _ in 0..size1 {
                        out.push(b);
                    }
                }
                Type::Add => {
                    data_index += size1 as usize;
                    self.input
                        .get(data_index - size1 as usize..data_index)
                        .unwrap()
                        .iter()
                        .for_each(|x| out.push(*x));
                }
                Type::Copy => {
                    let addr = self.addr_cache.addr_decode(
                        self.window_header.source.map_or(0, |x| x.0) + out.len() as u32,
                        inst1.mode,
                        &mut addr_index,
                        &self.input,
                    );
                    if addr < self.window_header.source.unwrap().0 {
                        let s = self.window_header.source.unwrap().1;
                        for b in &mut self.source[(s + addr) as usize..(s + addr + size1) as usize]
                        {
                            out.push(*b);
                        }
                    } else {
                        let addr = addr - self.window_header.source.map_or(0, |x| x.0);
                        for i in addr..(addr + size1) {
                            let b = out[i as usize];
                            out.push(b);
                        }
                    }
                }
            }

            if let Some(inst2) = inst2 {
                let size2 = if inst2.size == 0 {
                    read_int(&self.input, &mut inst_index)
                } else {
                    inst2.size
                };

                match inst2.ty {
                    Type::Run => {
                        let b = self.input[data_index];
                        data_index += 1;
                        for _ in 0..size2 {
                            out.push(b);
                        }
                    }
                    Type::Add => {
                        data_index += size2 as usize;
                        self.input
                            .get(data_index - size2 as usize..data_index)
                            .unwrap()
                            .iter()
                            .for_each(|x| out.push(*x));
                    }
                    Type::Copy => {
                        let addr = self.addr_cache.addr_decode(
                            self.window_header.source.map_or(0, |x| x.0) + out.len() as u32,
                            inst2.mode,
                            &mut addr_index,
                            &self.input,
                        );
                        if addr < self.window_header.source.unwrap().0 {
                            let s = self.window_header.source.unwrap().1;
                            for b in
                                &mut self.source[(s + addr) as usize..(s + addr + size2) as usize]
                            {
                                out.push(*b);
                            }
                        } else {
                            let addr = addr - self.window_header.source.map_or(0, |x| x.0);
                            for i in addr..(addr + size2) {
                                let b = out[i as usize];
                                out.push(b);
                            }
                        }
                    }
                }
            };
        }

        let a = adler32::RollingAdler32::from_buffer(&out);
        if let Some(hash) = self.window_header.hash {
            assert_eq!(a.hash(), hash);
        }

        self.output.append(&mut out);
    }

    fn seek(&mut self, num: usize) {
        self.index += num;
    }

    fn at_end(&self) -> bool {
        self.index == self.input.len()
    }
}
