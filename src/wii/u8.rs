#[derive(Debug)]
pub enum Entry {
    File(File),
    Folder(Folder),
    None,
}

impl Entry {
    pub fn find_entry(&mut self, path: &str) -> Option<&mut Entry> {
        if let Some((name, remaining)) = path.split_once('/') {
            match self {
                Entry::File(_) => None,
                Entry::Folder(Folder {
                    name: folder_name,
                    contents,
                }) if *folder_name == name => {
                    for entry in contents {
                        if let Some(x) = entry.find_entry(remaining) {
                            return Some(x);
                        }
                    }
                    None
                }
                _ => None,
            }
        } else {
            match self {
                Entry::File(f) if f.name == path => Some(self),
                _ => None,
            }
        }
    }

    pub fn get_file_contents(&mut self) -> Result<&mut Vec<u8>, String> {
        match self {
            Entry::File(File { name: _, contents }) => Ok(contents),
            _ => Err("File not found".to_string())
        }
    }

    pub fn set_file_contents(&mut self, c: Vec<u8>) -> Result <(), String> {
        match self {
            Entry::File(File { name: _, contents }) => *contents = c,
            _ => return Err("File not found".to_string())
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct File {
    pub name: String,
    pub contents: Vec<u8>,
}

#[derive(Debug)]
pub struct Folder {
    pub name: String,
    pub contents: Vec<Entry>,
}

#[derive(Debug)]
pub struct U8Unpacker<'a> {
    data: &'a Vec<u8>,
    index: usize,
    pub node_count: usize,
    pub str_table_index: usize,
    pub data_index: usize,
    num: usize,
}

impl<'a> U8Unpacker<'a> {
    pub fn new(data: &'a Vec<u8>) -> Self {
        Self {
            data,
            index: 0,
            node_count: 0,
            str_table_index: 0,
            data_index: 0,
            num: 1,
        }
    }

    pub fn unpack(&mut self) -> Entry {
        assert_eq!(self.get_u32(), 0x55aa382d);
        assert_eq!(self.get_u32(), 0x20);
        self.seek(4);
        self.data_index = self.get_u32() as usize;
        self.seek(16 + 8);
        self.node_count = self.get_u32() as usize - 1;
        self.str_table_index = self.index + self.node_count * 0xc;

        self.parse_entries()
    }

    fn parse_entries(&mut self) -> Entry {
        let ty = self.get_u16();
        let name_offset = self.get_u16() as usize;
        let data_offset = self.get_u32();
        let size = self.get_u32();
        self.num += 1;

        if ty == 0 {
            Entry::File(File {
                name: self.get_string(name_offset),
                contents: self.data[data_offset as usize..(data_offset + size) as usize].to_vec(),
            })
        } else if ty == 0x0100 {
            let mut contents = vec![];
            while self.num <= size as usize && self.num <= self.node_count {
                contents.push(self.parse_entries());
            }
            Entry::Folder(Folder {
                name: self.get_string(name_offset),
                contents,
            })
        } else {
            Entry::None
        }
    }

    fn get_bytes(&mut self, count: usize) -> &[u8] {
        self.index += count;
        &self.data[self.index - count..self.index]
    }

    fn get_u16(&mut self) -> u16 {
        u16::from_be_bytes(self.get_bytes(2).try_into().unwrap())
    }

    fn get_u32(&mut self) -> u32 {
        u32::from_be_bytes(self.get_bytes(4).try_into().unwrap())
    }

    fn get_string(&mut self, start: usize) -> String {
        let mut i = self.str_table_index + start;
        while self.data[i] != b'\0' {
            i += 1;
        }
        i += 1;

        String::from_utf8(self.data[self.str_table_index + start..i - 1].to_vec())
            .unwrap_or("idk man".to_owned())
    }

    fn seek(&mut self, count: usize) {
        self.index += count;
    }
}

pub struct U8Packer {
    strings: Vec<u8>,
    data: Vec<u8>,
    out: Vec<u8>,
    num_nodes: u32,
    strings_size: u32,
    node_idx: u32,
}

impl Default for U8Packer {
    fn default() -> Self {
        Self::new()
    }
}

impl U8Packer {
    pub fn new() -> Self {
        Self {
            strings: vec![0],
            data: vec![],
            out: vec![],
            num_nodes: 0,
            strings_size: 1,
            node_idx: 1,
        }
    }

    pub fn pack(&mut self, input: Entry) -> Vec<u8> {
        self.out.push(1);
        self.out.resize(8, 0);
        self.calc_sizes(&input);
        self.out
            .append(&mut u32::to_be_bytes(self.num_nodes + 1).to_vec());
        let mut e = self.encode_entry(input);
        let mut head = vec![0x55, 0xaa, 0x38, 0x2d, 0x00, 0x00, 0x00, 0x20];
        head.append(
            &mut u32::to_be_bytes((self.out.len() + self.strings.len() + e.len()) as u32).to_vec(),
        );
        let data_offset =
            align((self.out.len() + self.strings.len() + e.len()) as u32, 0x40) + 0x20;
        head.append(&mut u32::to_be_bytes(data_offset as u32).to_vec());
        head.resize(head.len() + 16, 0);
        self.out.append(&mut e);
        head.append(&mut self.out);
        head.append(&mut self.strings);
        head.resize(align(head.len() as u32, 0x20), 0);
        head.append(&mut self.data);
        head
    }

    fn calc_sizes(&mut self, entry: &Entry) {
        match entry {
            Entry::File(file) => {
                self.num_nodes += 1;
                self.strings_size += file.name.len() as u32 + 1;
            }
            Entry::Folder(folder) => {
                self.num_nodes += 1;
                self.strings_size += folder.name.len() as u32 + 1;
                for e in &folder.contents {
                    self.calc_sizes(e);
                }
            }
            Entry::None => (),
        }
    }

    fn encode_entry(&mut self, entry: Entry) -> Vec<u8> {
        let mut out = vec![];
        match entry {
            Entry::File(mut file) => {
                self.node_idx += 1;
                out.push(0);
                out.push(0);
                out.append(&mut u16::to_be_bytes(self.strings.len() as u16).to_vec());
                self.strings.append(&mut file.name.as_bytes().to_vec());
                self.strings.push(0);
                out.append(
                    &mut u32::to_be_bytes(
                        align(0x2c + self.strings_size + (self.num_nodes) * 0xc, 0x20) as u32
                            + self.data.len() as u32,
                    )
                    .to_vec(),
                );
                out.append(&mut u32::to_be_bytes(file.contents.len() as u32).to_vec());
                self.data.append(&mut file.contents);
                self.data.resize(align(self.data.len() as u32, 0x20), 0);
            }
            Entry::Folder(folder) => {
                self.node_idx += 1;
                out.push(1);
                out.push(0);
                out.append(&mut u16::to_be_bytes(self.strings.len() as u16).to_vec());
                self.strings.append(&mut folder.name.as_bytes().to_vec());
                self.strings.push(0);
                out.resize(out.len() + 4, 0);

                let mut sub = vec![];
                for e in folder.contents {
                    sub.append(&mut self.encode_entry(e));
                }

                out.append(&mut u32::to_be_bytes(self.node_idx).to_vec());
                out.append(&mut sub);
            }
            Entry::None => (),
        }

        out
    }
}

fn align(num: u32, amt: usize) -> usize {
    if num as usize % amt != 0 {
        amt * ((num as usize / amt) + 1)
    } else {
        num as usize
    }
}
