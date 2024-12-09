use crate::n64_decode;
use crate::WiiUInjectSettings;
use crc::{Crc, CRC_16_ARC};
use ouroboros::self_referencing;
use std::io::{Cursor, Read, Seek, Write};
use std::str;
use tar::{Archive, Builder, Entries, EntryType, Header};
use thiserror::Error;
use zip::{
    result::ZipError,
    write::{FileOptions, ZipWriter},
    CompressionMethod, ZipArchive,
};

enum Ver {
    Us,
    Jp,
}

#[derive(Error, Debug)]
pub enum WiiUError {
    #[error(transparent)]
    Zip(#[from] ZipError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("could not locate game files")]
    EndOfArchive,
    #[error("{0}")]
    PatchError(String),
    #[error("invalid archive, missing game files")]
    MissingFiles,
    #[error(transparent)]
    InvalidStr(#[from] std::str::Utf8Error),
}

pub fn patch(s: &mut WiiUInjectSettings) -> Result<Vec<u8>, WiiUError> {
    let c = Cursor::new(&s.input_archive);
    let mut file_reader = get_iter(c, s.return_zip)?;

    let mut cur_file;
    let start_idx = loop {
        cur_file = file_reader.next();
        if cur_file.is_none() {
            return Err(WiiUError::EndOfArchive);
        }

        match cur_file.as_ref().unwrap() {
            Ok((path, _)) => {
                if let Some(idx) = path
                    .find("code/")
                    .or(path.find("content/").or(path.find("meta/")))
                {
                    break idx;
                } else {
                    continue;
                }
            }
            Err(_) => return Err(cur_file.unwrap().unwrap_err()),
        }
    };

    let mut file_writer = FileWriter::new(Cursor::new(vec![]), s.return_zip);

    let mut ver = None;
    let mut app_cfg = None;
    let mut meta_cfg = None;
    let crc = Crc::<u16>::new(&CRC_16_ARC);
    let mut rom_digest = crc.digest();
    let mut cfg_digest = crc.digest();
    while let Some(file) = cur_file {
        let (ref path, ref data) = file?;
        if (path.ends_with(".ini") && !path.ends_with("config.ini")) || path.ends_with(".t64") {
            cur_file = file_reader.next();
            continue;
        }

        match &path[start_idx..] {
            "content/rom/UNMQE0.785" => {
                ver = Some(Ver::Us);
                let rom = patch_rom(data, &s.xdelta_patch)?;
                file_writer.write_file("content/rom/UNMQE0.z64", &rom)?;
                rom_digest.update(&rom);
                file_writer.write_file("content/config/UNMQE0.z64.ini", &s.config)?;
                cfg_digest.update(&s.config);
            }
            "content/rom/Unmqj0.716" => {
                ver = Some(Ver::Jp);
                let rom = patch_rom(data, &s.xdelta_patch)?;
                file_writer.write_file("content/rom/UNMQJ0.z64", &rom)?;
                rom_digest.update(&rom);
                file_writer.write_file("content/config/UNMQJ0.z64.ini", &s.config)?;
                cfg_digest.update(&s.config);
            }
            "code/app.xml" => app_cfg = Some(str::from_utf8(data)?.to_string()),
            "meta/meta.xml" => meta_cfg = Some(str::from_utf8(data)?.to_string()),
            "content/FrameLayout.arc" => {
                file_writer.write_file("content/FrameLayout.arc", &s.frame_layout)?;
            }
            name => {
                file_writer.write_file(name, data)?;
            }
        }
        cur_file = file_reader.next();
    }

    let title_id = format!(
        "0005000264{:04X}{:02X}",
        ((rom_digest.finalize() as u32 + cfg_digest.finalize() as u32) >> 1) as u16,
        if s.enable_dark_filter { 0x80 } else { 0 }
            | if s.enable_widescreen { 0x40 } else { 0 }
            | 4
    );

    let group_id = format!("0000{}{}", &title_id[10..12], &title_id[12..14]);

    let mut app_str = app_cfg.ok_or(WiiUError::MissingFiles)?;
    let mut meta_str = meta_cfg.ok_or(WiiUError::MissingFiles)?;
    match ver.ok_or(WiiUError::MissingFiles)? {
        Ver::Us => {
            meta_str = meta_str
                .replace("NACE", "NMQE")
                .replace("Paper Mario", "fp-US")
                .replace("00001997", &group_id)
                .replace("0005000010199700", &title_id);
            app_str = app_str
                .replace("00001997", &group_id)
                .replace("0005000010199700", &title_id);
        }
        Ver::Jp => {
            meta_str = meta_str
                .replace("NACJ", "NMQJ")
                .replace("マリオストーリー", "fp-JP")
                .replace("00001996", &group_id)
                .replace("0005000010199600", &title_id);
            app_str = app_str
                .replace("00001996", &group_id)
                .replace("0005000010199600", &title_id);
        }
    }

    file_writer.write_file("code/app.xml", app_str.as_bytes())?;
    file_writer.write_file("meta/meta.xml", meta_str.as_bytes())?;

    match file_writer {
        FileWriter::Zip(mut z) => Ok(z.finish()?.into_inner()),
        FileWriter::Tar(mut t) => {
            t.finish()?;
            Ok(t.into_inner()?.into_inner())
        }
    }
}

fn patch_rom(file: &[u8], patch: &[u8]) -> Result<Vec<u8>, WiiUError> {
    n64_decode(file, patch).map_err(WiiUError::PatchError)
}

struct ZipReader<'a> {
    zip: ZipArchive<Cursor<&'a Vec<u8>>>,
    idx: usize,
}

impl<'a> ZipReader<'a> {
    fn build(input: Cursor<&'a Vec<u8>>) -> Result<Self, WiiUError> {
        Ok(Self {
            zip: ZipArchive::new(input)?,
            idx: 0,
        })
    }
}

impl Iterator for ZipReader<'_> {
    type Item = Result<(String, Vec<u8>), WiiUError>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut file = loop {
            if self.idx >= self.zip.len() {
                return None;
            }

            match self.zip.by_index(self.idx) {
                Ok(f) => {
                    self.idx += 1;
                    if !f.is_dir() {
                        break f;
                    }
                }
                Err(e) => return Some(Err(e.into())),
            }
        };

        let mut contents = vec![];
        if let Err(e) = file.read_to_end(&mut contents) {
            return Some(Err(e.into()));
        }
        Some(Ok((file.name().to_string(), contents)))
    }
}

#[self_referencing]
struct TarReader<'a> {
    tar: Archive<Cursor<&'a Vec<u8>>>,
    #[borrows(mut tar)]
    #[not_covariant]
    entries: Entries<'this, Cursor<&'a Vec<u8>>>,
}

impl<'a> TarReader<'a> {
    fn build(input: Cursor<&'a Vec<u8>>) -> Self {
        TarReaderBuilder {
            tar: Archive::new(input),
            entries_builder: |archive| archive.entries().unwrap(),
        }
        .build()
    }
}

impl Iterator for TarReader<'_> {
    type Item = Result<(String, Vec<u8>), WiiUError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.with_mut(|x| loop {
            match x.entries.next() {
                Some(Ok(mut file)) => {
                    if file.header().entry_type() == EntryType::Regular {
                        let mut contents = vec![];
                        if let Err(e) = file.read_to_end(&mut contents) {
                            return Some(Err(e.into()));
                        }
                        match file.path() {
                            Ok(p) => return Some(Ok((p.to_str().unwrap().to_string(), contents))),
                            Err(e) => return Some(Err(e.into())),
                        }
                    }
                }
                Some(Err(e)) => {
                    return Some(Err(e.into()));
                }
                None => return None,
            }
        })
    }
}

type ArchiveIter<'a> = Box<dyn Iterator<Item = Result<(String, Vec<u8>), WiiUError>> + 'a>;
fn get_iter(input: Cursor<&Vec<u8>>, is_zip: bool) -> Result<ArchiveIter, WiiUError> {
    if is_zip {
        Ok(Box::new(ZipReader::build(input)?))
    } else {
        Ok(Box::new(TarReader::build(input)))
    }
}

enum FileWriter<W: Write + Seek> {
    Zip(ZipWriter<W>),
    Tar(Builder<W>),
}

impl<W: Write + Seek> FileWriter<W> {
    fn new(out: W, zip: bool) -> Self {
        if zip {
            FileWriter::Zip(ZipWriter::new(out))
        } else {
            FileWriter::Tar(Builder::new(out))
        }
    }

    fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), WiiUError> {
        match self {
            FileWriter::Zip(z) => {
                let options = FileOptions::default().compression_method(CompressionMethod::Stored);
                z.start_file(path, options)?;
                z.write_all(data)?;
            }
            FileWriter::Tar(t) => {
                let mut header = Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_cksum();
                t.append_data(&mut header, path, data)?;
            }
        }

        Ok(())
    }
}
