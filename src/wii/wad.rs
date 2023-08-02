use aes::cipher::{
    block_padding::{NoPadding, ZeroPadding},
    BlockDecryptMut, BlockEncryptMut, KeyIvInit,
};
use sha1::{Digest, Sha1};
use thiserror::Error;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

const COMMON_KEY: [u8; 16] = [
    0xeb, 0xe4, 0x2a, 0x22, 0x5e, 0x85, 0x93, 0xe4, 0x48, 0xd9, 0xc5, 0x45, 0x73, 0x81, 0xaa, 0xf7,
];

#[derive(Error, Debug)]
pub enum WadError {
    #[error("attempted to read `{0}` byte(s) out of bounds (index: `{1}, length: `{2}`)")]
    IndexOutOfBounds(usize, usize, usize),
    #[error("invalid patch file")]
    InvalidPatchFile,
    #[error("lz77 compression/decompression not supported")]
    UnsupportedLz77,
    #[error("unexpected {0} size (expected: `{1}`, got: `{2}`)")]
    UnexpectedSectionSize(String, u32, usize),
    #[error("unexpected content {0} hash (expected: `{1}, got `{2}`)")]
    UnexpectedContentHash(usize, String, String),
    #[error("could not decrypt data")]
    CouldNotDecrypt,
    #[error("unexpected wad header (expected: `{0}`, got: `{1}`)")]
    UnexpectedWadHeader(String, String),
}

#[derive(Clone, Debug)]
pub struct Wad {
    pub header: WadHeader,
    pub cert_chain: Vec<Certificate>,
    pub ticket: Ticket,
    pub tmd: Title,
    dec_title_key: [u8; 16],
    pub contents: Vec<Vec<u8>>,
    pub footer: Vec<u8>,
}

impl Wad {
    fn new() -> Self {
        Wad {
            header: WadHeader::new(),
            cert_chain: vec![],
            ticket: Ticket::new(),
            tmd: Title::new(),
            dec_title_key: [0; 16],
            contents: vec![],
            footer: vec![],
        }
    }

    fn recalc_hashes(&mut self) -> Result<(), WadError> {
        let mut hasher = Sha1::new();
        for i in 0..self.contents.len() {
            align(&mut self.contents[i], 0x10);
            let len = self.tmd.contents.len();
            self.tmd
                .contents
                .get_mut(i)
                .ok_or(WadError::IndexOutOfBounds(1, i, len))?
                .size = self.contents[i].capacity() as u64;
            hasher.update(&self.contents[i]);
            self.tmd.contents[i].hash = hasher.finalize_reset().into();
        }

        Ok(())
    }

    pub fn parse_gzi_patch(&mut self, patch: &[u8]) -> Result<(), WadError> {
        let lines = patch.split(|&b| b == b'\n');
        let mut file: Option<u32> = None;

        for line in lines {
            if line.starts_with(&[b'#']) || line.is_empty() {
                continue;
            }

            let parts: Vec<&[u8]> = line.split(|&byte| byte == b' ').collect();
            let cmd = u16::from_str_radix(
                std::str::from_utf8(parts.get(0).ok_or(WadError::InvalidPatchFile)?)
                    .map_err(|_| WadError::InvalidPatchFile)?,
                16,
            )
            .map_err(|_| WadError::InvalidPatchFile)?;
            let size = (cmd & 0xff) as usize;
            let cmd = cmd >> 8;
            let offset = u32::from_str_radix(
                std::str::from_utf8(parts.get(1).ok_or(WadError::InvalidPatchFile)?)
                    .map_err(|_| WadError::InvalidPatchFile)?,
                16,
            )
            .map_err(|_| WadError::InvalidPatchFile)? as usize;
            let data = u32::from_str_radix(
                std::str::from_utf8(parts.get(2).ok_or(WadError::InvalidPatchFile)?)
                    .map_err(|_| WadError::InvalidPatchFile)?,
                16,
            )
            .map_err(|_| WadError::InvalidPatchFile)?;

            match cmd {
                0 => file = Some(data),
                1 | 2 => return Err(WadError::UnsupportedLz77),
                3 => {
                    let data = match size {
                        1 => data & 0xff,
                        2 => data & 0xffff,
                        4 => data,
                        _ => return Err(WadError::InvalidPatchFile),
                    };

                    let len = self.contents.len();
                    self.contents
                        .get_mut(file.ok_or(WadError::InvalidPatchFile)? as usize)
                        .ok_or(WadError::IndexOutOfBounds(1, file.unwrap() as usize, len))?
                        .splice(
                            offset..offset + size,
                            data.to_be_bytes()[4 - size..].to_vec(),
                        );
                }
                _ => return Err(WadError::InvalidPatchFile),
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct Certificate {
    sig_type: u32,
    sig_data: Vec<u8>,
    issuer: [u8; 64],
    key_type: u32,
    child_cert_identity: [u8; 64],
    pub_key: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct WadHeader {
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

#[derive(Clone, Debug)]
pub struct Ticket {
    signed_blob_hdr: [u8; 0x140],
    sig_issuer: [u8; 0x40],
    ecdh_data: [u8; 0x3c],
    ticket_format_ver: u8,
    unk_0x1bd: [u8; 0x02],
    title_key: [u8; 0x10],
    unk_0x1cf: u8,
    ticket_id: [u8; 0x08],
    console_id: u32,
    pub title_id: [u8; 0x08],
    unk_0x1e4: [u8; 0x02],
    ticket_title_ver: u16,
    permitted_titles_mask: u32,
    permit_mask: u32,
    title_export_allowed: u8,
    common_key_index: u8,
    unk_0x1f2: [u8; 0x30],
    content_access_perms: [u8; 0x40],
    limits: Vec<CcLimit>,
}

impl Ticket {
    fn new() -> Self {
        Self {
            signed_blob_hdr: [0; 0x140],
            sig_issuer: [0; 0x40],
            ecdh_data: [0; 0x3c],
            ticket_format_ver: 0,
            unk_0x1bd: [0; 0x02],
            title_key: [0; 0x10],
            unk_0x1cf: 0,
            ticket_id: [0; 0x08],
            console_id: 0,
            title_id: [0; 0x08],
            unk_0x1e4: [0; 0x02],
            ticket_title_ver: 0,
            permitted_titles_mask: 0,
            permit_mask: 0,
            title_export_allowed: 0,
            common_key_index: 0,
            unk_0x1f2: [0; 0x30],
            content_access_perms: [0; 0x40],
            limits: vec![],
        }
    }
}

#[derive(Clone, Debug)]
struct CcLimit {
    limit_type: u32,
    max_usage: u32,
}

#[derive(Clone, Debug)]
pub struct Title {
    pub header: TitleHeader,
    pub contents: Vec<ContentRecord>,
}

impl Title {
    fn new() -> Self {
        Self {
            header: TitleHeader::new(),
            contents: vec![],
        }
    }
}

#[derive(Clone, Debug)]
pub struct TitleHeader {
    signed_blob_hdr: [u8; 0x140],
    cert_issuer: [u8; 0x40],
    version: u8,
    ca_crl_ver: u8,
    signer_crl_ver: u8,
    is_vwii: u8,
    sys_version: u64,
    pub title_id: [u8; 8],
    title_type: u32,
    group_id: u16,
    pub region: u16,
    ratings: [u8; 0x10],
    unk_0x1ae: [u8; 12],
    ipc_mask: [u8; 0x0c],
    unk_0x1c6: [u8; 0x12],
    access_rights: u32,
    title_version: u16,
    num_contents: u16,
    boot_index: u16,
    minor_ver: u16,
}

impl TitleHeader {
    fn new() -> Self {
        Self {
            signed_blob_hdr: [0; 0x140],
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
            unk_0x1ae: [0; 0xc],
            ipc_mask: [0; 0x0c],
            unk_0x1c6: [0; 0x12],
            access_rights: 0,
            title_version: 0,
            num_contents: 0,
            boot_index: 0,
            minor_ver: 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ContentRecord {
    content_id: u32,
    index: [u8; 2],
    ty: u16,
    size: u64,
    hash: [u8; 20],
}

pub struct Parser<'a> {
    data: &'a [u8],
    index: usize,
}

impl<'a> Parser<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, index: 0 }
    }

    pub fn decode(&mut self) -> Result<Wad, WadError> {
        let mut wad = Wad::new();
        wad.header = self.parse_wad_header()?;
        self.align(0x40);
        let x = self.index;
        while self.index - x < wad.header.certificate_chain_size as usize {
            let c = self.parse_cert_chain()?;
            wad.cert_chain.push(c);
        }
        if self.index - x != wad.header.certificate_chain_size as usize {
            return Err(WadError::UnexpectedSectionSize(
                "certificate chain".to_string(),
                wad.header.certificate_chain_size,
                self.index - x,
            ));
        }
        self.align(0x40);
        let x = self.index;
        wad.ticket = self.parse_ticket()?;
        if self.index - x != wad.header.ticket_size as usize {
            return Err(WadError::UnexpectedSectionSize(
                "ticket".to_string(),
                wad.header.ticket_size,
                self.index - x,
            ));
        }
        self.align(0x40);
        self.decrypt_title_key(&mut wad)?;
        let x = self.index;
        wad.tmd = self.parse_title()?;
        if self.index - x != wad.header.tmd_size as usize {
            return Err(WadError::UnexpectedSectionSize(
                "tmd".to_string(),
                wad.header.tmd_size,
                self.index - x,
            ));
        }
        self.align(0x40);

        let x = self.index;
        for i in 0..wad.tmd.contents.len() {
            let size = wad.tmd.contents[i].size;

            let mut iv = [0; 16];
            iv[..2].copy_from_slice(&wad.tmd.contents[i].index);
            let title_key = wad.dec_title_key;
            let contents = self.get_bytes_aligned(size as usize, 0x10)?;
            let out = Aes128CbcDec::new(&title_key.into(), &iv.into())
                .decrypt_padded_vec_mut::<NoPadding>(contents)
                .map_err(|_| WadError::CouldNotDecrypt)?;
            let mut hasher = Sha1::new();
            hasher.update(out.get(..size as usize).ok_or(WadError::IndexOutOfBounds(
                size as usize,
                0,
                out.len(),
            ))?);
            let result = hasher.finalize();
            if result != wad.tmd.contents[i].hash.into() {
                return Err(WadError::UnexpectedContentHash(
                    i,
                    hex::encode(wad.tmd.contents[i].hash),
                    hex::encode(result),
                ));
            }
            wad.contents.push(out);
            self.align(0x40);
        }
        if self.index - x != wad.header.encrypted_data_size as usize {
            return Err(WadError::UnexpectedSectionSize(
                "encrypted contents".to_string(),
                wad.header.encrypted_data_size,
                self.index - x,
            ));
        }

        wad.footer = self.get_bytes(wad.header.footer_size as usize)?.into();

        Ok(wad)
    }

    fn parse_cert_chain(&mut self) -> Result<Certificate, WadError> {
        let sig_type = self.get_u32()?;
        let sig_len = match sig_type {
            0x10000 => 0x200,
            0x10001 => 0x100,
            0x10002 => 0x3c,
            _ => panic!("Invalid signature type"),
        };
        let sig_data = self.get_bytes(sig_len)?.into();
        self.align(0x40);
        let issuer = self.get_bytes(64)?.try_into().unwrap();
        let key_type = self.get_u32()?;
        let child_cert_identity = self.get_bytes(64)?.try_into().unwrap();
        let pub_key_len = match key_type {
            0 => 0x23c,
            1 => 0x13c,
            2 => 0x78,
            _ => panic!("Invalid key type"),
        };
        let pub_key = self.get_bytes(pub_key_len)?.into();
        self.align(0x40);

        Ok(Certificate {
            sig_type,
            sig_data,
            issuer,
            key_type,
            child_cert_identity,
            pub_key,
        })
    }

    fn decrypt_title_key(&mut self, wad: &mut Wad) -> Result<(), WadError> {
        let mut iv = [0; 16];
        iv[..8].copy_from_slice(&wad.ticket.title_id[..]);

        let mut buf = [0u8; 16];
        wad.dec_title_key = Aes128CbcDec::new(&COMMON_KEY.into(), &iv.into())
            .decrypt_padded_b2b_mut::<NoPadding>(&wad.ticket.title_key, &mut buf)
            .map_err(|_| WadError::CouldNotDecrypt)?
            .try_into()
            .map_err(|_| WadError::CouldNotDecrypt)?;

        Ok(())
    }

    fn parse_wad_header(&mut self) -> Result<WadHeader, WadError> {
        let hdr = self.get_bytes(8)?;
        let expected_hdr = &[0x00, 0x00, 0x00, 0x20, 0x49, 0x73, 0x00, 0x00];
        if hdr != expected_hdr {
            return Err(WadError::UnexpectedWadHeader(
                hex::encode(hdr),
                hex::encode(expected_hdr),
            ));
        }
        let certificate_chain_size = self.get_u32()?;
        self.seek(0x04);
        let ticket_size = self.get_u32()?;
        let tmd_size = self.get_u32()?;
        let encrypted_data_size = self.get_u32()?;
        let footer_size = self.get_u32()?;

        Ok(WadHeader {
            certificate_chain_size,
            ticket_size,
            tmd_size,
            encrypted_data_size,
            footer_size,
        })
    }

    fn parse_ticket(&mut self) -> Result<Ticket, WadError> {
        let signed_blob_hdr = self.get_bytes(0x140)?.try_into().unwrap();
        let sig_issuer = self.get_bytes(0x40)?.try_into().unwrap();
        let ecdh_data = self.get_bytes(0x3c)?.try_into().unwrap();
        let ticket_format_ver = self.get_byte()?;
        let unk_0x1bd = self.get_bytes(0x02)?.try_into().unwrap();
        let title_key = self.get_bytes(0x10)?.try_into().unwrap();
        let unk_0x1cf = self.get_byte()?;
        let ticket_id = self.get_bytes(8)?.try_into().unwrap();
        let console_id = self.get_u32()?;
        let title_id = self.get_bytes(8)?.try_into().unwrap();
        let unk_0x1e4 = self.get_bytes(2)?.try_into().unwrap();
        let ticket_title_ver = self.get_u16()?;
        let permitted_titles_mask = self.get_u32()?;
        let permit_mask = self.get_u32()?;
        let title_export_allowed = self.get_byte()?;
        let common_key_index = self.get_byte()?;
        let unk_0x1f2 = self.get_bytes(0x30)?.try_into().unwrap();
        let content_access_perms = self.get_bytes(0x40)?.try_into().unwrap();
        self.seek(0x02);

        let mut limits = Vec::with_capacity(8);

        for _ in 0..8 {
            limits.push(CcLimit {
                limit_type: self.get_u32()?,
                max_usage: self.get_u32()?,
            });
        }

        Ok(Ticket {
            signed_blob_hdr,
            sig_issuer,
            ecdh_data,
            ticket_format_ver,
            unk_0x1bd,
            title_key,
            unk_0x1cf,
            ticket_id,
            console_id,
            title_id,
            unk_0x1e4,
            ticket_title_ver,
            permitted_titles_mask,
            permit_mask,
            title_export_allowed,
            common_key_index,
            unk_0x1f2,
            content_access_perms,
            limits,
        })
    }

    fn parse_title_header(&mut self) -> Result<TitleHeader, WadError> {
        let signed_blob_hdr = self.get_bytes(0x140)?.try_into().unwrap();
        let cert_issuer = self.get_bytes(0x40)?.try_into().unwrap();
        let version = self.get_byte()?;
        let ca_crl_ver = self.get_byte()?;
        let signer_crl_ver = self.get_byte()?;
        let is_vwii = self.get_byte()?;
        let sys_version = self.get_u64()?;
        let title_id = self.get_bytes(8)?.try_into().unwrap();
        let title_type = self.get_u32()?;
        let group_id = self.get_u16()?;
        self.seek(2);
        let region = self.get_u16()?;
        let ratings = self.get_bytes(0x10)?.try_into().unwrap();
        let unk_0x1ae = self.get_bytes(0x0c)?.try_into().unwrap();
        let ipc_mask = self.get_bytes(0x0c)?.try_into().unwrap();
        let unk_0x1c6 = self.get_bytes(0x12)?.try_into().unwrap();
        let access_rights = self.get_u32()?;
        let title_version = self.get_u16()?;
        let num_contents = self.get_u16()?;
        let boot_index = self.get_u16()?;
        let minor_ver = self.get_u16()?;

        Ok(TitleHeader {
            signed_blob_hdr,
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
            unk_0x1ae,
            ipc_mask,
            unk_0x1c6,
            access_rights,
            title_version,
            num_contents,
            boot_index,
            minor_ver,
        })
    }

    fn parse_title(&mut self) -> Result<Title, WadError> {
        let header = self.parse_title_header()?;
        let mut contents = vec![];

        for _ in 0..header.num_contents {
            contents.push(self.parse_contents()?);
        }

        Ok(Title { header, contents })
    }

    fn parse_contents(&mut self) -> Result<ContentRecord, WadError> {
        let content_id = self.get_u32()?;
        let index = self.get_bytes(2)?.try_into().unwrap();
        let ty = self.get_u16()?;
        let size = self.get_u64()?;
        let hash = self.get_bytes(20)?.try_into().unwrap();

        Ok(ContentRecord {
            content_id,
            index,
            ty,
            size,
            hash,
        })
    }

    fn get_byte(&mut self) -> Result<u8, WadError> {
        self.index += 1;
        self.data
            .get(self.index - 1)
            .ok_or(WadError::IndexOutOfBounds(
                1,
                self.index - 1,
                self.data.len(),
            ))
            .copied()
    }

    fn get_bytes(&mut self, count: usize) -> Result<&[u8], WadError> {
        self.index += count;
        self.data
            .get(self.index - count..self.index)
            .ok_or(WadError::IndexOutOfBounds(
                count,
                self.index - count,
                self.data.len(),
            ))
    }

    fn get_bytes_aligned(&mut self, count: usize, align: usize) -> Result<&[u8], WadError> {
        let i = self.index;
        self.index += count;
        self.align(align);
        self.data
            .get(i..self.index)
            .ok_or(WadError::IndexOutOfBounds(count, i, self.data.len()))
    }

    fn get_u16(&mut self) -> Result<u16, WadError> {
        Ok(u16::from_be_bytes(self.get_bytes(2)?.try_into().unwrap()))
    }

    fn get_u32(&mut self) -> Result<u32, WadError> {
        Ok(u32::from_be_bytes(self.get_bytes(4)?.try_into().unwrap()))
    }

    fn get_u64(&mut self) -> Result<u64, WadError> {
        Ok(u64::from_be_bytes(self.get_bytes(8)?.try_into().unwrap()))
    }

    fn seek(&mut self, count: usize) {
        self.index += count;
    }

    fn align(&mut self, amt: usize) {
        self.index = align_num(self.index, amt);
    }
}

pub struct Encoder<'a> {
    wad: &'a mut Wad,
}

impl<'a> Encoder<'a> {
    pub fn new(wad: &'a mut Wad) -> Self {
        Self { wad }
    }

    pub fn encode(&mut self) -> Result<Vec<u8>, WadError> {
        self.wad.recalc_hashes()?;
        self.encrypt_title_key()?;
        let mut cert_chain = self.encode_cert_chain();
        let mut ticket = self.encode_ticket();
        let mut tmd = self.encode_tmd()?;
        let (contents, contents_len) = self.encode_contents()?;

        trucha_sign(&mut ticket, 0);
        trucha_sign(&mut tmd, 1);
        let mut out = vec![];
        encode_u32(&mut out, 0x20);
        encode_u16(&mut out, 0x4973);
        encode_u16(&mut out, 0);
        encode_u32(&mut out, cert_chain.len() as u32);
        encode_u32(&mut out, 0);
        encode_u32(&mut out, ticket.len() as u32);
        encode_u32(&mut out, tmd.len() as u32);
        encode_u32(&mut out, contents_len as u32);
        encode_u32(&mut out, self.wad.footer.len() as u32);
        align(&mut out, 0x40);
        out.append(&mut cert_chain);
        align(&mut out, 0x40);
        out.append(&mut ticket);
        align(&mut out, 0x40);
        out.append(&mut tmd);
        align(&mut out, 0x40);

        for mut c in contents {
            out.append(&mut c);
            align(&mut out, 0x40);
        }

        out.append(&mut self.wad.footer);
        align(&mut out, 0x40);

        Ok(out)
    }

    fn encode_cert_chain(&mut self) -> Vec<u8> {
        let mut cert_chain = vec![];

        for c in &mut self.wad.cert_chain {
            encode_u32(&mut cert_chain, c.sig_type);
            cert_chain.append(&mut c.sig_data);
            align(&mut cert_chain, 0x40);
            cert_chain.append(&mut c.issuer.into());
            encode_u32(&mut cert_chain, c.key_type);
            cert_chain.append(&mut c.child_cert_identity.into());
            cert_chain.append(&mut c.pub_key);
            align(&mut cert_chain, 0x40);
        }
        cert_chain
    }

    fn encode_ticket(&mut self) -> Vec<u8> {
        let mut tik = vec![];
        let t = &self.wad.ticket;
        tik.append(&mut t.signed_blob_hdr.into());
        tik.append(&mut t.sig_issuer.into());
        tik.append(&mut t.ecdh_data.into());
        tik.push(t.ticket_format_ver);
        tik.append(&mut t.unk_0x1bd.into());
        tik.append(&mut t.title_key.into());
        tik.push(t.unk_0x1cf);
        tik.append(&mut t.ticket_id.into());
        encode_u32(&mut tik, t.console_id);
        tik.append(&mut t.title_id.into());
        tik.append(&mut t.unk_0x1e4.into());
        encode_u16(&mut tik, t.ticket_title_ver);
        encode_u32(&mut tik, t.permitted_titles_mask);
        encode_u32(&mut tik, t.permit_mask);
        tik.push(t.title_export_allowed);
        tik.push(t.common_key_index);
        tik.append(&mut t.unk_0x1f2.into());
        tik.append(&mut t.content_access_perms.into());
        encode_u16(&mut tik, 0);
        for l in &t.limits {
            encode_u32(&mut tik, l.limit_type);
            encode_u32(&mut tik, l.max_usage);
        }

        tik
    }

    fn encode_tmd(&mut self) -> Result<Vec<u8>, WadError> {
        let mut tmd = vec![];
        let t = &self.wad.tmd.header;
        tmd.append(&mut t.signed_blob_hdr.into());
        tmd.append(&mut t.cert_issuer.into());
        tmd.push(t.version);
        tmd.push(t.ca_crl_ver);
        tmd.push(t.signer_crl_ver);
        tmd.push(t.is_vwii);
        encode_u64(&mut tmd, t.sys_version);
        tmd.append(&mut t.title_id.into());
        encode_u32(&mut tmd, t.title_type);
        encode_u16(&mut tmd, t.group_id);
        encode_u16(&mut tmd, 0);
        encode_u16(&mut tmd, t.region);
        tmd.append(&mut t.ratings.into());
        tmd.append(&mut t.unk_0x1ae.into());
        tmd.append(&mut t.ipc_mask.into());
        tmd.append(&mut t.unk_0x1c6.into());
        encode_u32(&mut tmd, t.access_rights);
        encode_u16(&mut tmd, t.title_version);
        encode_u16(&mut tmd, t.num_contents);
        encode_u16(&mut tmd, t.boot_index);
        encode_u16(&mut tmd, t.minor_ver);

        for i in 0..t.num_contents as usize {
            let c = &self
                .wad
                .tmd
                .contents
                .get(i)
                .ok_or(WadError::IndexOutOfBounds(
                    1,
                    i,
                    self.wad.tmd.contents.len(),
                ))?;
            encode_u32(&mut tmd, c.content_id);
            tmd.append(&mut c.index.into());
            encode_u16(&mut tmd, c.ty);
            encode_u64(&mut tmd, c.size);
            tmd.append(&mut c.hash.into());
        }

        Ok(tmd)
    }

    fn encode_contents(&mut self) -> Result<(Vec<Vec<u8>>, usize), WadError> {
        let mut c = vec![];
        let mut len = 0;

        for i in 0..self.wad.tmd.contents.len() {
            let mut iv = [0; 16];
            iv[..2].copy_from_slice(&self.wad.tmd.contents[i].index);
            let title_key = self.wad.dec_title_key;
            let contents = &self.wad.contents.get(i).ok_or(WadError::IndexOutOfBounds(
                1,
                i,
                self.wad.contents.len(),
            ))?;
            let content = Aes128CbcEnc::new(&title_key.into(), &iv.into())
                .encrypt_padded_vec_mut::<ZeroPadding>(contents);
            len += align_num(content.len(), 0x40);
            c.push(content);
        }

        Ok((c, len))
    }

    fn encrypt_title_key(&mut self) -> Result<(), WadError> {
        let mut iv = [0; 16];
        self.wad.ticket.title_key = [
            0x47, 0x5a, 0x49, 0x73, 0x4c, 0x69, 0x66, 0x65, 0x41, 0x6e, 0x64, 0x42, 0x65, 0x65,
            0x72, 0x21,
        ];
        iv[..8].copy_from_slice(&self.wad.ticket.title_id[..]);

        let mut buf = [0u8; 16];
        self.wad.dec_title_key = Aes128CbcDec::new(&COMMON_KEY.into(), &iv.into())
            .decrypt_padded_b2b_mut::<NoPadding>(&self.wad.ticket.title_key, &mut buf)
            .map_err(|_| WadError::CouldNotDecrypt)?
            .try_into()
            .map_err(|_| WadError::CouldNotDecrypt)?;

        Ok(())
    }
}

fn trucha_sign(data: &mut [u8], ty: u8) {
    let pos = if ty == 1 { 0x1d4 } else { 0x1f2 };

    let mut hasher = Sha1::new();
    hasher.update(&data[0x140..data.len() - 0x140]);

    if hasher.finalize_reset()[0] != 0 {
        for i in &mut data[4..260] {
            *i = 0
        }

        for i in 0..0xFFFF {
            data[pos..pos + 2].copy_from_slice(&(i as u16).to_be_bytes());
            hasher.update(&data[0x140..data.len()]);
            if hasher.finalize_reset()[0] == 0 {
                break;
            }
        }
    }
}

fn encode_u16(vec: &mut Vec<u8>, val: u16) {
    vec.append(&mut val.to_be_bytes().into());
}

fn encode_u32(vec: &mut Vec<u8>, val: u32) {
    vec.append(&mut val.to_be_bytes().into());
}

fn encode_u64(vec: &mut Vec<u8>, val: u64) {
    vec.append(&mut val.to_be_bytes().into());
}

fn align(vec: &mut Vec<u8>, amt: usize) {
    if vec.len() % amt != 0 {
        vec.resize(amt * ((vec.len() / amt) + 1), 0);
    }
}

fn align_num(num: usize, amt: usize) -> usize {
    if num % amt != 0 {
        amt * ((num / amt) + 1)
    } else {
        num
    }
}
