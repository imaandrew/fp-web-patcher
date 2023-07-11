use crate::n64_decode;
use crate::WiiUInjectSettings;
use crc::{Crc, CRC_16_ARC};
use std::io::{Cursor, Read, Seek, Write};
use std::str;
use tar::{Archive, Builder, Entries, EntryType, Header};
use zip::{
    write::{FileOptions, ZipWriter},
    CompressionMethod, ZipArchive,
};

enum Ver {
    Us,
    Jp,
}

pub fn patch(s: &mut WiiUInjectSettings) -> Vec<u8> {
    let mut a = Archive::new(Cursor::new(&s.input_archive));
    let entries = a.entries().unwrap();

    let mut file_reader = if s.return_zip {
        FileReader::new((Some(Cursor::new(&s.input_archive)), None), s.return_zip)
    } else {
        FileReader::new((None, Some(entries)), s.return_zip)
    };

    let mut cur_file = file_reader.next_file();
    let path = &cur_file.as_ref().unwrap().0;
    let start_idx = if let Some(x) = path.match_indices("code/").next() {
        x.0
    } else if let Some(x) = path.match_indices("content/").next() {
        x.0
    } else if let Some(x) = path.match_indices("meta/").next() {
        x.0
    } else {
        panic!();
    };

    let mut file_writer = FileWriter::new(Cursor::new(vec![]), s.return_zip);

    let mut ver = None;
    let mut app_cfg = None;
    let mut meta_cfg = None;
    let crc = Crc::<u16>::new(&CRC_16_ARC);
    let mut digest = crc.digest();
    while let Some((ref path, ref data)) = cur_file {
        match &path[start_idx..] {
            "content/rom/UNMQE0.785" => {
                ver = Some(Ver::Us);
                let rom = patch_rom(data, &s.xdelta_patch);
                file_writer.write_file("content/rom/UNMQE0.z64", &rom);
                digest.update(&rom);
            }
            "content/rom/Unmqj0.716" => {
                ver = Some(Ver::Jp);
                let rom = patch_rom(data, &s.xdelta_patch);
                file_writer.write_file("content/rom/UNMQJ0.z64", &rom);
                digest.update(&rom);
            }
            "code/app.xml" => app_cfg = Some(str::from_utf8(data).unwrap().to_string()),
            "meta/meta.xml" => meta_cfg = Some(str::from_utf8(data).unwrap().to_string()),
            "content/FrameLayout.arc" => {
                file_writer.write_file("content/FrameLayout.arc", &s.frame_layout)
            }
            name => {
                file_writer.write_file(name, data);
            }
        }
        cur_file = file_reader.next_file();
    }

    let title_id = format!(
        "0005000264{:x}{:x}",
        digest.finalize(),
        if s.enable_dark_filter { 0x80 } else { 0 }
            | if s.enable_widescreen { 0x40 } else { 0 }
            | 4
    );

    let group_id = format!("0000{}{}", &title_id[10..12], &title_id[12..14]);

    let mut app_str = app_cfg.unwrap();
    let mut meta_str = meta_cfg.unwrap();
    match ver.unwrap() {
        Ver::Us => {
            meta_str = meta_str.replace("NACE", "NMQE");
            meta_str = meta_str.replace("Paper Mario", "fp-US");
            meta_str = meta_str.replace("00001997", &group_id);
            app_str = app_str.replace("00001997", &group_id);
        }
        Ver::Jp => {
            meta_str = meta_str.replace("NACJ", "NMQJ");
            meta_str = meta_str.replace("マリオストーリー", "fp-JP");
            meta_str = meta_str.replace("00001996", &group_id);
            app_str = app_str.replace("00001996", &group_id);
        }
    }

    meta_str = meta_str.replace("0005000010199700", &title_id);
    app_str = app_str.replace("0005000010199700", &title_id);
    file_writer.write_file("code/app.xml", app_str.as_bytes());
    file_writer.write_file("meta/meta.xml", meta_str.as_bytes());

    match file_writer {
        FileWriter::Zip(mut z) => z.finish().unwrap().into_inner(),
        FileWriter::Tar(mut t) => {
            t.finish().unwrap();
            t.into_inner().unwrap().into_inner()
        }
    }
}

fn patch_rom(file: &[u8], patch: &[u8]) -> Vec<u8> {
    n64_decode(file, patch).unwrap()
}

enum FileReader<'a, R: Read + Seek> {
    Zip(ZipArchive<R>, usize),
    Tar(Entries<'a, R>),
}

impl<'a, R: Read + Seek> FileReader<'a, R> {
    fn new(input: (Option<R>, Option<Entries<'a, R>>), zip: bool) -> Self {
        if zip {
            FileReader::Zip(ZipArchive::new(input.0.unwrap()).unwrap(), 0)
        } else {
            FileReader::Tar(input.1.unwrap())
        }
    }

    fn next_file(&mut self) -> Option<(String, Vec<u8>)> {
        let mut read_another_file = false;

        let x = match self {
            FileReader::Zip(z, i) => {
                if *i >= z.len() {
                    return None;
                }
                let mut file = z.by_index(*i).unwrap();
                *i += 1;
                if file.is_dir() {
                    read_another_file = true;
                    None
                } else {
                    let mut contents = vec![];
                    file.read_to_end(&mut contents).unwrap();
                    Some((file.name().to_string(), contents))
                }
            }
            FileReader::Tar(t) => {
                let mut file = if let Some(f) = t.next() {
                    f.unwrap()
                } else {
                    return None;
                };
                if file.header().entry_type() == EntryType::Directory {
                    read_another_file = true;
                    None
                } else {
                    let mut contents = vec![];
                    file.read_to_end(&mut contents).unwrap();
                    Some((file.path().unwrap().to_str().unwrap().to_string(), contents))
                }
            }
        };

        if read_another_file {
            self.next_file()
        } else {
            x
        }
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

    fn write_file(&mut self, path: &str, data: &[u8]) {
        match self {
            FileWriter::Zip(z) => {
                let options = FileOptions::default().compression_method(CompressionMethod::Stored);
                z.start_file(path, options).unwrap();
                z.write_all(data).unwrap();
            }
            FileWriter::Tar(t) => {
                let mut header = Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_cksum();
                t.append_data(&mut header, path, data).unwrap();
            }
        }
    }
}
