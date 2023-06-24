use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use sha1::{Digest, Sha1};

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

const COMMON_KEY: [u8; 16] = [
    0xeb, 0xe4, 0x2a, 0x22, 0x5e, 0x85, 0x93, 0xe4, 0x48, 0xd9, 0xc5, 0x45, 0x73, 0x81, 0xaa, 0xf7,
];

#[derive(Debug)]
struct Wad {
    header: WadHeader,
    ticket: Ticket,
    tmd: Title,
    dec_title_key: [u8; 16],
    contents: Vec<Vec<u8>>,
    footer: Vec<u8>,
}

impl Wad {
    fn new() -> Self {
        Wad {
            header: WadHeader::new(),
            ticket: Ticket::new(),
            tmd: Title::new(),
            dec_title_key: [0; 16],
            contents: vec![],
            footer: vec![],
        }
    }
}

#[derive(Debug)]
struct WadHeader {
    certificate_chain_size: u32,
    ticket_size: u32,
    tmd_size: u32,
    encrypted_data_size: u32,
    footer_size: u32,
}

impl WadHeader {
    fn new() -> Self {
        Self {
            certificate_chain_size: 0,
            ticket_size: 0,
            tmd_size: 0,
            encrypted_data_size: 0,
            footer_size: 0,
        }
    }
}

#[derive(Debug)]
struct Ticket {
    sig_issuer: [u8; 0x40],
    ecdh_data: [u8; 0x3c],
    ticket_format_ver: u8,
    title_key: [u8; 0x10],
    ticket_id: [u8; 0x08],
    console_id: u32,
    title_id: [u8; 0x08],
    ticket_title_ver: u16,
    permitted_titles_mask: u32,
    permit_mask: u32,
    title_export_allowed: u8,
    common_key_index: u8,
    content_access_perms: [u8; 0x40],
    limits: Vec<CcLimit>,
}

impl Ticket {
    fn new() -> Self {
        Self {
            sig_issuer: [0; 0x40],
            ecdh_data: [0; 0x3c],
            ticket_format_ver: 0,
            title_key: [0; 0x10],
            ticket_id: [0; 0x08],
            console_id: 0,
            title_id: [0; 0x08],
            ticket_title_ver: 0,
            permitted_titles_mask: 0,
            permit_mask: 0,
            title_export_allowed: 0,
            common_key_index: 0,
            content_access_perms: [0; 0x40],
            limits: vec![],
        }
    }
}

#[derive(Debug)]
struct CcLimit {
    limit_type: u32,
    max_usage: u32,
}

impl CcLimit {
    fn new() -> Self {
        Self {
            limit_type: 0,
            max_usage: 0,
        }
    }
}

#[derive(Debug)]
struct Title {
    header: TitleHeader,
    contents: Vec<ContentRecord>,
}

impl Title {
    fn new() -> Self {
        Self {
            header: TitleHeader::new(),
            contents: vec![],
        }
    }
}

#[derive(Debug)]
struct TitleHeader {
    cert_issuer: [u8; 0x40],
    version: u8,
    ca_crl_ver: u8,
    signer_crl_ver: u8,
    is_vwii: u8,
    sys_version: u64,
    title_id: [u8; 8],
    title_type: u32,
    group_id: u16,
    region: u16,
    ratings: [u8; 0x10],
    ipc_mask: [u8; 0x0c],
    access_rights: u32,
    title_version: u16,
    num_contents: u16,
    boot_index: u16,
    minor_ver: u16,
}

impl TitleHeader {
    fn new() -> Self {
        Self {
            cert_issuer: [0; 0x40],
            version: 0,
            ca_crl_ver: 0,
            signer_crl_ver: 0,
            is_vwii: 0,
            sys_version: 0,
            title_id: [0; 8],
            title_type: 0,
            group_id: 0,
            region: 0,
            ratings: [0; 0x10],
            ipc_mask: [0; 0x0c],
            access_rights: 0,
            title_version: 0,
            num_contents: 0,
            boot_index: 0,
            minor_ver: 0,
        }
    }
}

#[derive(Debug)]
struct ContentRecord {
    content_id: u32,
    index: [u8; 2],
    ty: u16,
    size: u64,
    hash: [u8; 20],
}

struct Certificate {
    sig_type: u32,
    sig: [u8; 256],
    issuer: [u8; 0x40],
    pub_key_type: u32,
    name: [u8; 0x40],
    date: u32,
    key: Vec<u8>,
}

pub struct Parser {
    data: Vec<u8>,
    index: usize,
    wad: Wad,
}

impl Parser {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            index: 0,
            wad: Wad::new(),
        }
    }

    pub fn decode(&mut self) {
        self.wad.header = self.parse_wad_header();
        self.align(0x40);
        self.seek(self.wad.header.certificate_chain_size as usize);
        self.align(0x40);
        let x = self.index;
        self.seek(0x140);
        self.wad.ticket = self.parse_ticket();
        assert_eq!(self.index - x, self.wad.header.ticket_size as usize);
        self.align(0x40);
        self.decrypt_title_key();
        let x = self.index;
        self.seek(0x140);
        self.wad.tmd = self.parse_title();
        assert_eq!(self.index - x, self.wad.header.tmd_size as usize);
        self.align(0x40);

        for i in 0..self.wad.tmd.contents.len() {
            let size = self.wad.tmd.contents[i].size;

            let mut iv = [0; 16];
            iv[..2].copy_from_slice(&self.wad.tmd.contents[i].index);
            let title_key = self.wad.dec_title_key;
            let contents = self.get_bytes_aligned(size as usize, 0x10);
            let mut out = Aes128CbcDec::new(&title_key.into(), &iv.into())
                .decrypt_padded_vec_mut::<NoPadding>(contents)
                .unwrap();
            out.truncate(size as usize);
            let mut hasher = Sha1::new();
            hasher.update(&out);
            let result = hasher.finalize();
            assert_eq!(result, self.wad.tmd.contents[i].hash.into());
            self.wad.contents.push(out);
            self.align(0x40);
        }

        self.wad.footer = self.get_bytes(self.wad.header.footer_size as usize).into();
    }

    fn decrypt_title_key(&mut self) {
        let mut iv = [0; 16];
        iv[..8].copy_from_slice(&self.wad.ticket.title_id[..]);

        let mut buf = [0u8; 16];
        self.wad.dec_title_key = Aes128CbcDec::new(&COMMON_KEY.into(), &iv.into())
            .decrypt_padded_b2b_mut::<NoPadding>(&self.wad.ticket.title_key, &mut buf)
            .unwrap()
            .try_into()
            .unwrap();
    }

    fn parse_wad_header(&mut self) -> WadHeader {
        assert_eq!(
            self.get_bytes(8),
            &[0x00, 0x00, 0x00, 0x20, 0x49, 0x73, 0x00, 0x00]
        );
        let certificate_chain_size = self.get_u32();
        self.seek(0x04);
        let ticket_size = self.get_u32();
        let tmd_size = self.get_u32();
        let encrypted_data_size = self.get_u32();
        let footer_size = self.get_u32();

        WadHeader {
            certificate_chain_size,
            ticket_size,
            tmd_size,
            encrypted_data_size,
            footer_size,
        }
    }

    fn parse_ticket(&mut self) -> Ticket {
        let sig_issuer = self.get_bytes(0x40).try_into().unwrap();
        let ecdh_data = self.get_bytes(0x3c).try_into().unwrap();
        let ticket_format_ver = self.get_byte();
        self.seek(0x02);
        let title_key = self.get_bytes(0x10).try_into().unwrap();
        self.seek(0x01);
        let ticket_id = self.get_bytes(8).try_into().unwrap();
        let console_id = self.get_u32();
        let title_id = self.get_bytes(8).try_into().unwrap();
        self.seek(0x02);
        let ticket_title_ver = self.get_u16();
        let permitted_titles_mask = self.get_u32();
        let permit_mask = self.get_u32();
        let title_export_allowed = self.get_byte();
        let common_key_index = self.get_byte();
        self.seek(0x30);
        let content_access_perms = self.get_bytes(0x40).try_into().unwrap();
        self.seek(0x02);

        let mut limits = Vec::with_capacity(8);

        for _ in 0..8 {
            limits.push(CcLimit {
                limit_type: self.get_u32(),
                max_usage: self.get_u32(),
            });
        }

        Ticket {
            sig_issuer,
            ecdh_data,
            ticket_format_ver,
            title_key,
            ticket_id,
            console_id,
            title_id,
            ticket_title_ver,
            permitted_titles_mask,
            permit_mask,
            title_export_allowed,
            common_key_index,
            content_access_perms,
            limits,
        }
    }

    fn parse_title_header(&mut self) -> TitleHeader {
        let cert_issuer = self.get_bytes(0x40).try_into().unwrap();
        let version = self.get_byte();
        let ca_crl_ver = self.get_byte();
        let signer_crl_ver = self.get_byte();
        let is_vwii = self.get_byte();
        let sys_version = self.get_u64();
        let title_id = self.get_bytes(8).try_into().unwrap();
        let title_type = self.get_u32();
        let group_id = self.get_u16();
        self.seek(2);
        let region = self.get_u16();
        let ratings = self.get_bytes(0x10).try_into().unwrap();
        self.seek(0x0c);
        let ipc_mask = self.get_bytes(0x0c).try_into().unwrap();
        self.seek(0x12);
        let access_rights = self.get_u32();
        let title_version = self.get_u16();
        let num_contents = self.get_u16();
        let boot_index = self.get_u16();
        let minor_ver = self.get_u16();

        TitleHeader {
            cert_issuer,
            version,
            ca_crl_ver,
            signer_crl_ver,
            is_vwii,
            sys_version,
            title_id,
            title_type,
            group_id,
            region,
            ratings,
            ipc_mask,
            access_rights,
            title_version,
            num_contents,
            boot_index,
            minor_ver,
        }
    }

    fn parse_title(&mut self) -> Title {
        let header = self.parse_title_header();
        let mut contents = vec![];

        for _ in 0..header.num_contents {
            contents.push(self.parse_contents());
        }

        Title { header, contents }
    }

    fn parse_contents(&mut self) -> ContentRecord {
        let content_id = self.get_u32();
        let index = self.get_bytes(2).try_into().unwrap();
        let ty = self.get_u16();
        let size = self.get_u64();
        let hash = self.get_bytes(20).try_into().unwrap();

        ContentRecord {
            content_id,
            index,
            ty,
            size,
            hash,
        }
    }

    fn get_byte(&mut self) -> u8 {
        self.index += 1;
        self.data[self.index - 1]
    }

    fn get_bytes(&mut self, count: usize) -> &[u8] {
        self.index += count;
        &self.data[self.index - count..self.index]
    }

    fn get_bytes_aligned(&mut self, count: usize, align: usize) -> &[u8] {
        let i = self.index;
        self.index += count;
        self.align(align);
        &self.data[i..self.index]
    }

    fn get_u16(&mut self) -> u16 {
        u16::from_be_bytes(self.get_bytes(2).try_into().unwrap())
    }

    fn get_u32(&mut self) -> u32 {
        u32::from_be_bytes(self.get_bytes(4).try_into().unwrap())
    }

    fn get_u64(&mut self) -> u64 {
        u64::from_be_bytes(self.get_bytes(8).try_into().unwrap())
    }

    fn seek(&mut self, count: usize) {
        self.index += count;
    }

    fn align(&mut self, amt: usize) {
        if self.index % amt != 0 {
            self.index = amt * ((self.index / amt) + 1);
        }
    }
}
