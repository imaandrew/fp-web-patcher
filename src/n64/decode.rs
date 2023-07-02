use super::{
    cache::AddrCache,
    insts::{CodeTable, Instruction, Type},
    read_byte, read_bytes, read_int, VCDiffDecoderError,
};

pub struct VCDiffDecoder<'a> {
    input: &'a [u8],
    source: &'a [u8],
    index: usize,
    window_header: WindowHeader,
    window: Window,
    code_table: CodeTable,
    addr_cache: AddrCache,
}

#[derive(Debug)]
struct WindowHeader {
    source: (u32, u32),
    delta_encoding_len: u32,
    target_window_len: usize,
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

impl<'a> VCDiffDecoder<'a> {
    pub fn new(input: &'a [u8], source: &'a [u8]) -> Self {
        VCDiffDecoder {
            input,
            source,
            index: 0,
            window_header: WindowHeader {
                source: (0, 0),
                delta_encoding_len: 0,
                target_window_len: 0,
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

    pub fn decode(&mut self) -> Result<Vec<u8>, VCDiffDecoderError> {
        let header = read_bytes(3, self.input, &mut self.index)?;
        if *header != [0xd6, 0xc3, 0xc4] {
            return Err(VCDiffDecoderError::InvalidHeader);
        }
        self.seek(1);

        let header_indicator = read_byte(self.input, &mut self.index)?;

        if header_indicator & VCD_DECOMPRESS != 0 && read_byte(self.input, &mut self.index)? != 0 {
            return Err(VCDiffDecoderError::UnsupportedFeature(
                "external compression".to_string(),
            ));
        }

        if header_indicator & VCD_CODETABLE != 0 && read_int(self.input, &mut self.index)? != 0 {
            return Err(VCDiffDecoderError::UnsupportedFeature(
                "custom code tables".to_string(),
            ));
        }

        if header_indicator & VCD_APPHEADER != 0 {
            let len = read_int(self.input, &mut self.index)?;
            self.seek(len as usize);
        }

        let mut out = vec![];

        while !self.at_end() {
            self.window_header = self.decode_window_header()?;
            out.append(&mut self.decode_window()?);
            self.addr_cache = AddrCache::default();
        }

        Ok(out)
    }

    fn decode_window_header(&mut self) -> Result<WindowHeader, VCDiffDecoderError> {
        let window_indicator = read_byte(self.input, &mut self.index)?;
        let source = if window_indicator & (VCD_SOURCE | VCD_TARGET) != 0 {
            (
                read_int(self.input, &mut self.index)?,
                read_int(self.input, &mut self.index)?,
            )
        } else {
            (0, 0)
        };

        let delta_encoding_len = read_int(self.input, &mut self.index)?;
        let start_index = self.index;
        let target_window_len = read_int(self.input, &mut self.index)? as usize;
        let delta_indicator = read_byte(self.input, &mut self.index)?;

        if delta_indicator & (VCD_DATACOMP | VCD_INSTCOMP | VCD_ADDRCOMP) != 0 {
            return Err(VCDiffDecoderError::UnsupportedFeature(
                "secondary compression".to_string(),
            ));
        }

        let data_len = read_int(self.input, &mut self.index)? as usize;
        let inst_len = read_int(self.input, &mut self.index)? as usize;
        let addr_len = read_int(self.input, &mut self.index)? as usize;

        let hash = if window_indicator & VCD_CHECKSUM != 0 {
            Some(u32::from_be_bytes(
                read_bytes(4, self.input, &mut self.index)?
                    .try_into()
                    .unwrap(),
            ))
        } else {
            None
        };

        Ok(WindowHeader {
            source,
            delta_encoding_len,
            target_window_len,
            data_len,
            inst_len,
            addr_len,
            hash,
            len: self.index - start_index,
        })
    }

    fn decode_window(&mut self) -> Result<Vec<u8>, VCDiffDecoderError> {
        let data_index = self.index;
        let inst_index = self.window_header.data_len + data_index;
        let addr_index = self.window_header.inst_len + inst_index;

        self.window = Window {
            data_index,
            inst_index,
            addr_index,
        };

        if self.window_header.delta_encoding_len as usize
            != addr_index + self.window_header.addr_len + self.window_header.len - self.index
        {
            return Err(VCDiffDecoderError::UnexpectedWindowSize(
                self.window_header.delta_encoding_len as usize,
                addr_index + self.window_header.addr_len + self.window_header.len - self.index,
            ));
        }

        let mut out = Vec::with_capacity(self.window_header.target_window_len);

        self.index = addr_index + self.window_header.addr_len;

        while self.window.inst_index < addr_index {
            let (inst1, inst2) = *self
                .code_table
                .table
                .get(*self.input.get(self.window.inst_index).ok_or(
                    VCDiffDecoderError::IndexOutOfBounds(
                        1,
                        self.window.inst_index,
                        self.input.len(),
                    ),
                )? as usize)
                .ok_or(VCDiffDecoderError::IndexOutOfBounds(
                    1,
                    self.input[self.window.inst_index] as usize,
                    self.code_table.table.len(),
                ))?;
            self.window.inst_index += 1;
            self.decode_instruction(inst1, &mut out)?;

            if let Some(inst2) = inst2 {
                self.decode_instruction(inst2, &mut out)?;
            };
        }

        let a = adler32::RollingAdler32::from_buffer(&out);
        if let Some(hash) = self.window_header.hash {
            let exp = a.hash();
            if exp != hash {
                return Err(VCDiffDecoderError::InvalidChecksum(exp, hash));
            }
        }

        Ok(out)
    }

    fn decode_instruction(
        &mut self,
        inst: Instruction,
        out: &mut Vec<u8>,
    ) -> Result<(), VCDiffDecoderError> {
        let size = if inst.size == 0 {
            read_int(self.input, &mut self.window.inst_index)?
        } else {
            inst.size
        } as usize;

        match inst.ty {
            Type::Run => {
                let b = self.input.get(self.window.data_index).ok_or(
                    VCDiffDecoderError::IndexOutOfBounds(
                        1,
                        self.window.data_index,
                        self.input.len(),
                    ),
                )?;
                self.window.data_index += 1;
                for _ in 0..size {
                    out.push(*b);
                }
            }
            Type::Add => {
                self.window.data_index += size;
                self.input
                    .get(self.window.data_index - size..self.window.data_index)
                    .ok_or(VCDiffDecoderError::IndexOutOfBounds(
                        size,
                        self.window.data_index - size,
                        self.input.len(),
                    ))?
                    .iter()
                    .for_each(|x| out.push(*x));
            }
            Type::Copy => {
                let src_sgmt_len = self.window_header.source.0;
                let addr = self.addr_cache.addr_decode(
                    src_sgmt_len + out.len() as u32,
                    inst.mode,
                    &mut self.window.addr_index,
                    self.input,
                )?;
                if addr < src_sgmt_len {
                    let src_sgmt_pos = (self.window_header.source.1 + addr) as usize;
                    for b in self.source.get(src_sgmt_pos..src_sgmt_pos + size).ok_or(
                        VCDiffDecoderError::IndexOutOfBounds(size, src_sgmt_pos, self.source.len()),
                    )? {
                        out.push(*b);
                    }
                } else {
                    let addr = addr - src_sgmt_len;
                    for i in addr..(addr + size as u32) {
                        let b = out
                            .get(i as usize)
                            .ok_or(VCDiffDecoderError::IndexOutOfBounds(
                                1,
                                i as usize,
                                out.len(),
                            ))?;
                        out.push(*b);
                    }
                }
            }
        }

        Ok(())
    }

    fn seek(&mut self, num: usize) {
        self.index += num;
    }

    fn at_end(&self) -> bool {
        self.index == self.input.len()
    }
}
