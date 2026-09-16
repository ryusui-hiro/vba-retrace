use std::fs;
use std::process::Command;
use vba_insight::export::{Disclosure, inspect_to_json, inspect_to_markdown, stomping_to_sarif};
use vba_insight::extract::extract_macro_container;
use vba_insight::host::HostProfile;
use vba_insight::stomping::{StompingFindingKind, StompingSeverity};
use vba_insight::{AnalysisOptions, Limits, inspect_macro_file};

/// CRC32 helper following IEEE 802.3 polynomial.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Helper to compress data according to MS-OVBA Section 2.4.1.
fn comp_ovba(data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    for chunk in data.chunks(8) {
        body.push(0); // raw uncompressed flags byte
        body.extend_from_slice(chunk);
    }
    let total = body.len() + 2;
    let h = 0xb000u16 | ((total - 3) as u16);
    let mut out = vec![1]; // signature byte
    out.extend_from_slice(&h.to_le_bytes());
    out.extend_from_slice(&body);
    out
}

fn put16(b: &mut [u8], i: usize, v: u16) {
    b[i..i + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(b: &mut [u8], i: usize, v: u32) {
    b[i..i + 4].copy_from_slice(&v.to_le_bytes());
}

#[allow(clippy::too_many_arguments)]
fn put_cfb_entry(
    buf: &mut [u8],
    id: usize,
    name: &str,
    kind: u8,
    left: u32,
    right: u32,
    child: u32,
    start: u32,
    size: u64,
) {
    let off = id * 128;
    for (i, u) in name.encode_utf16().chain(std::iter::once(0)).enumerate() {
        buf[off + i * 2..off + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
    }
    put16(
        buf,
        off + 64,
        ((name.encode_utf16().count() + 1) * 2) as u16,
    );
    buf[off + 66] = kind;
    put32(buf, off + 68, left);
    put32(buf, off + 72, right);
    put32(buf, off + 76, child);
    put32(buf, off + 116, start);
    buf[off + 120..off + 128].copy_from_slice(&size.to_le_bytes());
}

fn record_dir(id: u16, payload: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
}

/// Allocate a mini-stream into the mini buffer and wire up its MiniFAT chain.
fn allocate_mini_stream(data: &[u8], mini: &mut Vec<u8>, minifat: &mut [u32]) -> (u32, u64) {
    if data.is_empty() {
        return (0xffff_fffe, 0);
    }
    let start_sector = (mini.len() / 64) as u32;
    let num_sectors = data.len().div_ceil(64);
    for i in 0..num_sectors {
        let sec = start_sector + i as u32;
        if i + 1 < num_sectors {
            minifat[sec as usize] = sec + 1;
        } else {
            minifat[sec as usize] = 0xffff_fffe; // ENDOFCHAIN
        }
    }
    mini.extend_from_slice(data);
    let rem = mini.len() % 64;
    if rem != 0 {
        mini.resize(mini.len() + (64 - rem), 0);
    }
    (start_sector, data.len() as u64)
}

/// Synthesize a realistic CFB (OLE Compound File) containing one or more modules in a VBA Project.
fn synthesize_cfb_project(
    proj_name: &str,
    modules: &[(&str, &str, &[u8])],
    identifiers: &[&str],
) -> Vec<u8> {
    assert!(
        modules.len() <= 3,
        "test synthesizer supports up to 3 modules in 2 directory sectors"
    );

    let mut dir_raw = Vec::new();
    record_dir(0x0001, &1u32.to_le_bytes(), &mut dir_raw); // SYSKIND = Win32
    record_dir(0x0002, &0x0409u32.to_le_bytes(), &mut dir_raw); // LCID
    record_dir(0x0014, &0x0409u32.to_le_bytes(), &mut dir_raw);
    record_dir(0x0003, &1252u16.to_le_bytes(), &mut dir_raw); // CodePage CP1252
    record_dir(0x0004, proj_name.as_bytes(), &mut dir_raw); // ProjectName
    dir_raw.extend_from_slice(&0x0005u16.to_le_bytes());
    dir_raw.extend_from_slice(&0u32.to_le_bytes());
    dir_raw.extend_from_slice(&0x0040u16.to_le_bytes());
    dir_raw.extend_from_slice(&0u32.to_le_bytes());
    dir_raw.extend_from_slice(&0x0006u16.to_le_bytes());
    dir_raw.extend_from_slice(&0u32.to_le_bytes());
    dir_raw.extend_from_slice(&0x003du16.to_le_bytes());
    dir_raw.extend_from_slice(&0u32.to_le_bytes());
    record_dir(0x0007, &0u32.to_le_bytes(), &mut dir_raw);
    record_dir(0x0008, &0u32.to_le_bytes(), &mut dir_raw);
    dir_raw.extend_from_slice(&0x0009u16.to_le_bytes());
    dir_raw.extend_from_slice(&4u32.to_le_bytes());
    dir_raw.extend_from_slice(&0x0097u32.to_le_bytes());
    dir_raw.extend_from_slice(&1u16.to_le_bytes());

    // PROJECTMODULES header
    dir_raw.extend_from_slice(&0x000fu16.to_le_bytes());
    dir_raw.extend_from_slice(&2u32.to_le_bytes());
    dir_raw.extend_from_slice(&(modules.len() as u16).to_le_bytes());
    dir_raw.extend_from_slice(&0x0013u16.to_le_bytes());
    dir_raw.extend_from_slice(&2u32.to_le_bytes());
    dir_raw.extend_from_slice(&0xffffu16.to_le_bytes()); // cookie

    for &(mod_name, _, pcode) in modules {
        record_dir(0x0019, mod_name.as_bytes(), &mut dir_raw);
        let name16 = mod_name
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        record_dir(0x0047, &name16, &mut dir_raw);
        record_dir(0x001a, mod_name.as_bytes(), &mut dir_raw);
        dir_raw.extend_from_slice(&0x0032u16.to_le_bytes());
        dir_raw.extend_from_slice(&(name16.len() as u32).to_le_bytes());
        dir_raw.extend_from_slice(&name16);
        record_dir(0x001c, b"", &mut dir_raw);
        dir_raw.extend_from_slice(&0x0048u16.to_le_bytes());
        dir_raw.extend_from_slice(&0u32.to_le_bytes());

        // Text offset record (0x0031)
        let text_offset = pcode.len() as u32;
        record_dir(0x0031, &text_offset.to_le_bytes(), &mut dir_raw);
        record_dir(0x001e, &0u32.to_le_bytes(), &mut dir_raw);
        record_dir(0x002c, &0xffffu16.to_le_bytes(), &mut dir_raw);
        record_dir(0x0021, &0u32.to_le_bytes(), &mut dir_raw);
        dir_raw.extend_from_slice(&0x002bu16.to_le_bytes());
        dir_raw.extend_from_slice(&0u32.to_le_bytes());
    }

    let dir_comp = comp_ovba(&dir_raw);
    let mut project_str = format!("Name={proj_name}\r\n");
    for &(mod_name, _, _) in modules {
        project_str.push_str(&format!("Module={mod_name}\r\n"));
    }
    let project_stream = project_str.into_bytes();

    // Build _VBA_PROJECT stream with magic 0x61CC
    let mut vba_project_stream = Vec::new();
    vba_project_stream.extend_from_slice(&0x61CCu16.to_le_bytes());
    vba_project_stream.extend_from_slice(&0x0097u16.to_le_bytes()); // VBA7
    vba_project_stream.extend_from_slice(&0x0000u16.to_le_bytes());
    vba_project_stream.resize(0x1E, 0);
    vba_project_stream.extend_from_slice(&0u16.to_le_bytes()); // numRefs
    vba_project_stream.extend_from_slice(&0u16.to_le_bytes());
    vba_project_stream.extend_from_slice(&0u16.to_le_bytes()); // class table
    vba_project_stream.extend_from_slice(&0u16.to_le_bytes()); // compile pairs
    vba_project_stream.extend_from_slice(&0u16.to_le_bytes());
    vba_project_stream.extend_from_slice(&0u16.to_le_bytes()); // typeinfo
    vba_project_stream.extend_from_slice(&0u16.to_le_bytes()); // desc
    vba_project_stream.extend_from_slice(&0u16.to_le_bytes()); // help
    vba_project_stream.resize(vba_project_stream.len() + 0x64, 0);
    vba_project_stream.extend_from_slice(&0u16.to_le_bytes()); // numProjects = 0
    vba_project_stream.extend_from_slice(&[0; 6]);
    vba_project_stream.extend_from_slice(&0u32.to_le_bytes()); // table before IDs
    vba_project_stream.extend_from_slice(&[0; 6]);

    let num_ids = identifiers.len() as u16;
    vba_project_stream.extend_from_slice(&num_ids.to_le_bytes()); // w0
    vba_project_stream.extend_from_slice(&num_ids.to_le_bytes()); // num_total_ids
    vba_project_stream.extend_from_slice(&0u16.to_le_bytes()); // w1
    vba_project_stream.extend_from_slice(&[0; 4]);

    for id in identifiers {
        vba_project_stream.push(0);
        vba_project_stream.push(id.len() as u8);
        vba_project_stream.extend_from_slice(id.as_bytes());
        vba_project_stream.extend_from_slice(&[0; 4]);
    }

    // Build mini-stream and MiniFAT dynamically
    let mut mini = Vec::new();
    let mut minifat = vec![0xffff_ffffu32; 256];

    let (dir_start, dir_size) = allocate_mini_stream(&dir_comp, &mut mini, &mut minifat);
    let (proj_start, proj_size) = allocate_mini_stream(&project_stream, &mut mini, &mut minifat);
    let (vba_start, vba_size) = allocate_mini_stream(&vba_project_stream, &mut mini, &mut minifat);

    let mut mod_allocs = Vec::new();
    for &(_, src, pcode) in modules {
        let mut mod_bytes = pcode.to_vec();
        mod_bytes.extend_from_slice(&comp_ovba(src.as_bytes()));
        let (start, sz) = allocate_mini_stream(&mod_bytes, &mut mini, &mut minifat);
        mod_allocs.push((start, sz));
    }

    let mini_sectors_512 = mini.len().div_ceil(512);
    mini.resize(mini_sectors_512 * 512, 0);

    let mut dir_entries = vec![0u8; 1024];
    put_cfb_entry(
        &mut dir_entries,
        0,
        "Root Entry",
        5,
        0xffff_ffff,
        0xffff_ffff,
        1,
        4,
        mini.len() as u64,
    );
    put_cfb_entry(
        &mut dir_entries,
        1,
        "PROJECT",
        2,
        0xffff_ffff,
        2,
        0xffff_ffff,
        proj_start,
        proj_size,
    );
    put_cfb_entry(
        &mut dir_entries,
        2,
        "VBA",
        1,
        0xffff_ffff,
        0xffff_ffff,
        3,
        0xffff_ffff,
        0,
    );
    put_cfb_entry(
        &mut dir_entries,
        3,
        "dir",
        2,
        0xffff_ffff,
        4,
        0xffff_ffff,
        dir_start,
        dir_size,
    );
    put_cfb_entry(
        &mut dir_entries,
        4,
        "_VBA_PROJECT",
        2,
        0xffff_ffff,
        5,
        0xffff_ffff,
        vba_start,
        vba_size,
    );

    for (i, (&(mod_name, _, _), &(m_start, m_sz))) in modules.iter().zip(&mod_allocs).enumerate() {
        let entry_id = 5 + i;
        let right = if i + 1 < modules.len() {
            (5 + i + 1) as u32
        } else {
            0xffff_ffff
        };
        put_cfb_entry(
            &mut dir_entries,
            entry_id,
            mod_name,
            2,
            0xffff_ffff,
            right,
            0xffff_ffff,
            m_start,
            m_sz,
        );
    }

    let total_file_sectors = 4 + mini_sectors_512;
    let mut file = vec![0u8; 512 + total_file_sectors * 512];
    file[..8].copy_from_slice(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
    put16(&mut file, 24, 0x003e);
    put16(&mut file, 26, 3);
    put16(&mut file, 28, 0xfffe);
    put16(&mut file, 30, 9); // sector size 512 (2^9)
    put16(&mut file, 32, 6); // mini sector size 64 (2^6)
    put32(&mut file, 44, 1); // num FAT sectors
    put32(&mut file, 48, 1); // first dir sector = 1
    put32(&mut file, 56, 4096); // mini stream cutoff = 4096
    put32(&mut file, 60, 3); // first MiniFAT sector = 3
    put32(&mut file, 64, 1); // num MiniFAT sectors = 1
    put32(&mut file, 68, 0xffff_fffe); // first DIFAT
    put32(&mut file, 72, 0);
    put32(&mut file, 76, 0); // FAT sector 0 is at offset 512
    for i in 1..109 {
        put32(&mut file, 76 + i * 4, 0xffff_ffff);
    }

    // FAT sector (offset 512)
    let fat_offset = 512;
    put32(&mut file, fat_offset, 0xffff_fffd); // Sector 0 is FAT
    put32(&mut file, fat_offset + 4, 2); // Sector 1 -> 2 (Dir entries)
    put32(&mut file, fat_offset + 8, 0xffff_fffe); // Sector 2 = END (Dir entries)
    put32(&mut file, fat_offset + 12, 0xffff_fffe); // Sector 3 = END (MiniFAT)

    // Wire up mini stream sectors in FAT (sectors 4..)
    for i in 0..mini_sectors_512 {
        let sec = 4 + i;
        if i + 1 < mini_sectors_512 {
            put32(&mut file, fat_offset + sec * 4, (sec + 1) as u32);
        } else {
            put32(&mut file, fat_offset + sec * 4, 0xffff_fffe);
        }
    }
    for i in (4 + mini_sectors_512)..128 {
        put32(&mut file, fat_offset + i * 4, 0xffff_ffff);
    }

    // Directory sectors (sectors 1 & 2: offset 1024..2048)
    file[1024..1536].copy_from_slice(&dir_entries[..512]);
    file[1536..2048].copy_from_slice(&dir_entries[512..]);

    // MiniFAT sector (sector 3: offset 2048..2560)
    for (i, val) in minifat.iter().enumerate() {
        put32(&mut file, 2048 + i * 4, *val);
    }

    // Mini stream content (sectors 4..: offset 2560..)
    file[2560..2560 + mini.len()].copy_from_slice(&mini);

    file
}

/// Backward-compatible single module CFB synthesizer.
fn synthesize_cfb(
    proj_name: &str,
    module_name: &str,
    source_code: &str,
    pcode_bytes: &[u8],
) -> Vec<u8> {
    synthesize_cfb_project(
        proj_name,
        &[(module_name, source_code, pcode_bytes)],
        &["CalculateTotal", "TaxRate"],
    )
}

/// Synthesize a valid CAFE P-code line map buffer from line instruction slices.
fn synthesize_pcode_line_map(lines: &[&[u8]]) -> Vec<u8> {
    let mut pcode = Vec::new();
    pcode.extend_from_slice(&0xCAFEu16.to_le_bytes()); // 0xCAFE
    pcode.extend_from_slice(&[0x00, 0x00]); // profile header
    pcode.extend_from_slice(&(lines.len() as u16).to_le_bytes()); // line count

    let mut rel_offset = 0u32;
    for line in lines {
        pcode.extend_from_slice(&[0u8; 4]); // prefix
        pcode.extend_from_slice(&(line.len() as u16).to_le_bytes()); // length
        pcode.extend_from_slice(&[0u8; 2]); // middle
        pcode.extend_from_slice(&rel_offset.to_le_bytes()); // relative offset
        rel_offset += line.len() as u32;
    }

    pcode.extend_from_slice(&[0u8; 10]); // padding before code table

    for line in lines {
        pcode.extend_from_slice(line);
    }

    pcode
}

/// Build a FuncDefn instruction targeting an identifier index.
fn build_func_defn(ident_idx: u16) -> Vec<u8> {
    let mut inst = Vec::new();
    inst.extend_from_slice(&150u16.to_le_bytes()); // FuncDefn
    let id_code = ((0x100 + 4 + ident_idx) << 1) as u32;
    inst.extend_from_slice(&id_code.to_le_bytes());
    inst
}

/// Build a LitStr instruction containing a string literal with proper padding.
fn build_lit_str(s: &str) -> Vec<u8> {
    let mut inst = Vec::new();
    inst.extend_from_slice(&182u16.to_le_bytes()); // 32-bit LitStr (translates to 185)
    inst.extend_from_slice(&(s.len() as u16).to_le_bytes());
    inst.extend_from_slice(s.as_bytes());
    if s.len() & 1 != 0 {
        inst.push(0); // 1 byte padding for odd lengths
    }
    inst
}

/// Build an ArgsCall instruction calling a procedure by identifier index.
fn build_args_call(ident_idx: u16, arg_count: u16) -> Vec<u8> {
    let mut inst = Vec::new();
    inst.extend_from_slice(&65u16.to_le_bytes()); // ArgsCall
    let id_code = (0x100 + 4 + ident_idx) << 1;
    inst.extend_from_slice(&id_code.to_le_bytes());
    inst.extend_from_slice(&arg_count.to_le_bytes());
    inst
}

/// Package entries into a valid standard ZIP archive.
fn synthesize_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut z = Vec::new();
    let mut records = Vec::new();
    for &(name, payload) in entries {
        let name_b = name.as_bytes();
        let crc = crc32(payload);
        let local_offset = z.len() as u32;
        z.extend_from_slice(&0x04034b50u32.to_le_bytes());
        z.extend_from_slice(&20u16.to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes());
        z.extend_from_slice(&[0; 4]);
        z.extend_from_slice(&crc.to_le_bytes());
        z.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        z.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        z.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes());
        z.extend_from_slice(name_b);
        z.extend_from_slice(payload);
        records.push((name_b, crc, payload.len() as u32, local_offset));
    }
    let cd = z.len();
    for (name_b, crc, size, local_offset) in &records {
        z.extend_from_slice(&0x02014b50u32.to_le_bytes());
        z.extend_from_slice(&[20, 0, 20, 0, 0, 0]);
        z.extend_from_slice(&0u16.to_le_bytes());
        z.extend_from_slice(&[0; 4]);
        z.extend_from_slice(&crc.to_le_bytes());
        z.extend_from_slice(&size.to_le_bytes());
        z.extend_from_slice(&size.to_le_bytes());
        z.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
        z.extend_from_slice(&[0; 6]);
        z.extend_from_slice(&[0; 6]);
        z.extend_from_slice(&local_offset.to_le_bytes());
        z.extend_from_slice(name_b);
    }
    let cdsize = z.len() - cd;
    z.extend_from_slice(&0x06054b50u32.to_le_bytes());
    z.extend_from_slice(&[0; 4]);
    z.extend_from_slice(&(records.len() as u16).to_le_bytes());
    z.extend_from_slice(&(records.len() as u16).to_le_bytes());
    z.extend_from_slice(&(cdsize as u32).to_le_bytes());
    z.extend_from_slice(&(cd as u32).to_le_bytes());
    z.extend_from_slice(&0u16.to_le_bytes());
    z
}

/// Package CFB bytes into an OpenXML (.xlsm) ZIP container.
fn synthesize_xlsm(cfb_data: &[u8]) -> Vec<u8> {
    let content_types = "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.ms-excel.sheet.macroEnabled.main+xml\"/><Override PartName=\"/xl/vbaProject.bin\" ContentType=\"application/vnd.ms-office.vbaProject\"/></Types>";
    let pkg_rels = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/></Relationships>";
    let wb = "<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><workbookPr codeName=\"ThisWorkbook\"/><sheets><sheet name=\"Orders\" sheetId=\"1\" r:id=\"rId1\"/></sheets></workbook>";
    let wb_rels = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.microsoft.com/office/2006/relationships/vbaProject\" Target=\"vbaProject.bin\"/></Relationships>";

    synthesize_zip(&[
        ("[Content_Types].xml", content_types.as_bytes()),
        ("_rels/.rels", pkg_rels.as_bytes()),
        ("xl/workbook.xml", wb.as_bytes()),
        ("xl/_rels/workbook.xml.rels", wb_rels.as_bytes()),
        ("xl/vbaProject.bin", cfb_data),
    ])
}

/// Package CFB bytes into a Word (.docm) macro container.
fn synthesize_docm(cfb_data: &[u8]) -> Vec<u8> {
    let content_types = "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.ms-word.document.macroEnabled.main+xml\"/><Override PartName=\"/word/vbaProject.bin\" ContentType=\"application/vnd.ms-office.vbaProject\"/></Types>";
    let pkg_rels = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/></Relationships>";
    let doc = "<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body/></w:document>";
    let doc_rels = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.microsoft.com/office/2006/relationships/vbaProject\" Target=\"vbaProject.bin\"/></Relationships>";

    synthesize_zip(&[
        ("[Content_Types].xml", content_types.as_bytes()),
        ("_rels/.rels", pkg_rels.as_bytes()),
        ("word/document.xml", doc.as_bytes()),
        ("word/_rels/document.xml.rels", doc_rels.as_bytes()),
        ("word/vbaProject.bin", cfb_data),
    ])
}

/// Package CFB bytes into a PowerPoint (.pptm) macro container.
fn synthesize_pptm(cfb_data: &[u8]) -> Vec<u8> {
    let content_types = "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/ppt/presentation.xml\" ContentType=\"application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml\"/><Override PartName=\"/ppt/vbaProject.bin\" ContentType=\"application/vnd.ms-office.vbaProject\"/></Types>";
    let pkg_rels = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"ppt/presentation.xml\"/></Relationships>";
    let pres =
        "<p:presentation xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\"/>";
    let pres_rels = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.microsoft.com/office/2006/relationships/vbaProject\" Target=\"vbaProject.bin\"/></Relationships>";

    synthesize_zip(&[
        ("[Content_Types].xml", content_types.as_bytes()),
        ("_rels/.rels", pkg_rels.as_bytes()),
        ("ppt/presentation.xml", pres.as_bytes()),
        ("ppt/_rels/presentation.xml.rels", pres_rels.as_bytes()),
        ("ppt/vbaProject.bin", cfb_data),
    ])
}

/// Package CFB bytes into an Excel Binary (.xlsb) macro container.
fn synthesize_xlsb(cfb_data: &[u8]) -> Vec<u8> {
    let content_types = "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"bin\" ContentType=\"application/vnd.ms-excel.sheet.binary.macroEnabled.main\"/><Override PartName=\"/xl/vbaProject.bin\" ContentType=\"application/vnd.ms-office.vbaProject\"/></Types>";
    let pkg_rels = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.bin\"/></Relationships>";
    let dummy_bin = b"\xD0\xCF\x11\xE0";
    let wb_rels = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.microsoft.com/office/2006/relationships/vbaProject\" Target=\"vbaProject.bin\"/></Relationships>";

    synthesize_zip(&[
        ("[Content_Types].xml", content_types.as_bytes()),
        ("_rels/.rels", pkg_rels.as_bytes()),
        ("xl/workbook.bin", dummy_bin),
        ("xl/_rels/workbook.bin.rels", wb_rels.as_bytes()),
        ("xl/vbaProject.bin", cfb_data),
    ])
}

/// Package CFB bytes into a stripped ZIP container without OPC XML metadata.
fn synthesize_stripped_zip(cfb_data: &[u8], entry_name: &str) -> Vec<u8> {
    synthesize_zip(&[(entry_name, cfb_data)])
}

#[test]
fn e2e_clean_production_xlsm_inspection() {
    let src = "Attribute VB_Name = \"OrdersModule\"\nSub CalculateTotal()\n    Dim total As Double\n    total = 100 * 1.1\nEnd Sub\n";
    let line0 = build_func_defn(0);
    let pcode = synthesize_pcode_line_map(&[&line0]);

    let cfb = synthesize_cfb_project(
        "ProductionProject",
        &[("OrdersModule", src, &pcode)],
        &["CalculateTotal"],
    );
    let xlsm = synthesize_xlsm(&cfb);

    let options = AnalysisOptions {
        limits: Limits::default(),
        host_profile: HostProfile::Excel,
        ..Default::default()
    };

    let inspection = inspect_macro_file(&xlsm, &options).expect("inspection should succeed");

    assert_eq!(
        inspection.extracted.name.as_deref(),
        Some("ProductionProject")
    );
    assert_eq!(inspection.extracted.modules.len(), 1);
    assert_eq!(
        inspection.stomping_report.overall_severity,
        StompingSeverity::Clean
    );
    assert!(!inspection.stomping_report.has_stomping);

    // Verify JSON export
    let json_out = inspect_to_json(&inspection, Disclosure::IncludeSource);
    assert!(json_out.contains("ProductionProject"));
    assert!(json_out.contains("OrdersModule"));
    assert!(json_out.contains("\"overall_severity\":\"clean\""));

    // Verify Markdown export
    let md_out = inspect_to_markdown(&inspection);
    assert!(md_out.contains("Comprehensive Macro Container Inspection"));
    assert!(md_out.contains("OrdersModule"));
    assert!(md_out.contains("CLEAN"));
}

#[test]
fn e2e_weaponized_stomping_detection_and_sarif_export() {
    // 1. Deceptive source code in the VBA text stream
    let deceptive_src = "Attribute VB_Name = \"MalModule\"\nSub InnocentDocSummary()\n    Dim msg As String\n    msg = \"Harmless Invoice Report\"\nEnd Sub\n";

    // 2. Weaponized P-code line map:
    // Line 0: FuncDefn for "EvilPayload" (divergent procedure name)
    // Line 1: LitStr with suspicious powershell payload
    // Line 2: LitStr with suspicious url
    // Line 3: ArgsCall for "URLDownloadToFileA"
    let line0 = build_func_defn(0); // ident 0: EvilPayload
    let line1 = build_lit_str("powershell -ExecutionPolicy Bypass -enc SQBFAFgA");
    let line2 = build_lit_str("https://c2.evil-attacker.com/payload.exe");
    let line3 = build_args_call(1, 1); // ident 1: URLDownloadToFileA
    let pcode = synthesize_pcode_line_map(&[&line0, &line1, &line2, &line3]);

    let identifiers = &["EvilPayload", "URLDownloadToFileA"];
    let cfb = synthesize_cfb_project(
        "AttackProject",
        &[("MalModule", deceptive_src, &pcode)],
        identifiers,
    );
    let xlsm = synthesize_xlsm(&cfb);

    let options = AnalysisOptions::default();
    let inspection = inspect_macro_file(&xlsm, &options).expect("inspection should succeed");

    let report = inspection.stomping_report;
    assert!(report.has_stomping);
    assert_eq!(report.overall_severity, StompingSeverity::Critical);

    let mal_mod = &report.modules[0];
    assert!(mal_mod.is_stomped);
    assert_eq!(mal_mod.severity, StompingSeverity::Critical);
    assert_eq!(mal_mod.confidence_score, 100);

    // Verify individual finding types
    let has_hidden_proc = mal_mod.findings.iter().any(|f| {
        matches!(
            &f.kind,
            StompingFindingKind::ProcedureHiddenInPCode(name) if name == "EvilPayload"
        )
    });
    let has_missing_proc = mal_mod.findings.iter().any(|f| {
        matches!(
            &f.kind,
            StompingFindingKind::ProcedureMissingInPCode(name) if name == "InnocentDocSummary"
        )
    });
    let has_suspicious_ps = mal_mod.findings.iter().any(|f| {
        matches!(
            &f.kind,
            StompingFindingKind::SuspiciousLiteralInPCode(lit) if lit.contains("powershell")
        )
    });
    let has_suspicious_url = mal_mod.findings.iter().any(|f| {
        matches!(
            &f.kind,
            StompingFindingKind::SuspiciousLiteralInPCode(lit) if lit.contains("https://")
        )
    });
    let has_sensitive_call = mal_mod.findings.iter().any(|f| {
        matches!(
            &f.kind,
            StompingFindingKind::SensitiveCallInPCode(name) if name == "URLDownloadToFileA"
        )
    });

    assert!(has_hidden_proc, "should detect hidden procedure in P-code");
    assert!(
        has_missing_proc,
        "should detect missing procedure from source in P-code"
    );
    assert!(
        has_suspicious_ps,
        "should detect suspicious powershell command"
    );
    assert!(has_suspicious_url, "should detect suspicious URL");
    assert!(
        has_sensitive_call,
        "should detect sensitive URLDownloadToFileA API call"
    );

    // SARIF export validation
    let sarif_out = stomping_to_sarif(&report, "infected_invoice.xlsm");
    assert!(sarif_out.contains("sarif-schema-2.1.0.json"));
    assert!(sarif_out.contains("infected_invoice.xlsm"));
    assert!(sarif_out.contains("VBA-STOMP-002"));
    assert!(sarif_out.contains("VBA-STOMP-004"));
    assert!(sarif_out.contains("VBA-STOMP-005"));
    assert!(sarif_out.contains("vba-insight"));
}

#[test]
fn e2e_docm_container_extraction_and_inspection() {
    let src = "Attribute VB_Name = \"DocModule\"\nSub WordOpenHandler()\n    MsgBox \"Doc opened\"\nEnd Sub\n";
    let line0 = build_func_defn(0);
    let pcode = synthesize_pcode_line_map(&[&line0]);

    let cfb = synthesize_cfb_project(
        "WordDocumentProject",
        &[("DocModule", src, &pcode)],
        &["WordOpenHandler"],
    );
    let docm = synthesize_docm(&cfb);

    let extracted = extract_macro_container(&docm, &Limits::default())
        .expect("extract_macro_container for .docm should succeed");
    assert_eq!(extracted.name.as_deref(), Some("WordDocumentProject"));
    assert_eq!(extracted.modules.len(), 1);
    assert_eq!(extracted.modules[0].name, "DocModule");

    let inspection = inspect_macro_file(
        &docm,
        &AnalysisOptions {
            host_profile: HostProfile::Word,
            ..Default::default()
        },
    )
    .expect("inspect_macro_file for .docm should succeed");

    assert_eq!(
        inspection.stomping_report.overall_severity,
        StompingSeverity::Clean
    );
    assert!(!inspection.stomping_report.has_stomping);
}

#[test]
fn e2e_pptm_container_extraction_and_inspection() {
    let src = "Attribute VB_Name = \"SlideModule\"\nSub OnSlideShowPageChange()\n    ' Slide change handler\nEnd Sub\n";
    let line0 = build_func_defn(0);
    let pcode = synthesize_pcode_line_map(&[&line0]);

    let cfb = synthesize_cfb_project(
        "PowerPointProject",
        &[("SlideModule", src, &pcode)],
        &["OnSlideShowPageChange"],
    );
    let pptm = synthesize_pptm(&cfb);

    let extracted = extract_macro_container(&pptm, &Limits::default())
        .expect("extract_macro_container for .pptm should succeed");
    assert_eq!(extracted.name.as_deref(), Some("PowerPointProject"));
    assert_eq!(extracted.modules.len(), 1);
    assert_eq!(extracted.modules[0].name, "SlideModule");

    let inspection = inspect_macro_file(
        &pptm,
        &AnalysisOptions {
            host_profile: HostProfile::PowerPoint,
            ..Default::default()
        },
    )
    .expect("inspect_macro_file for .pptm should succeed");

    assert_eq!(
        inspection.stomping_report.overall_severity,
        StompingSeverity::Clean
    );
    assert!(!inspection.stomping_report.has_stomping);
}

#[test]
fn e2e_xlsb_container_extraction_and_inspection() {
    let src = "Attribute VB_Name = \"BinarySheetModule\"\nSub BinaryCalc()\n    Dim total As Long\n    total = 500\nEnd Sub\n";
    let line0 = build_func_defn(0);
    let pcode = synthesize_pcode_line_map(&[&line0]);

    let cfb = synthesize_cfb_project(
        "XlsbProject",
        &[("BinarySheetModule", src, &pcode)],
        &["BinaryCalc"],
    );
    let xlsb = synthesize_xlsb(&cfb);

    let extracted = extract_macro_container(&xlsb, &Limits::default())
        .expect("extract_macro_container for .xlsb should succeed");
    assert_eq!(extracted.name.as_deref(), Some("XlsbProject"));
    assert_eq!(extracted.modules.len(), 1);
    assert_eq!(extracted.modules[0].name, "BinarySheetModule");

    let inspection = inspect_macro_file(&xlsb, &AnalysisOptions::default())
        .expect("inspect_macro_file for .xlsb should succeed");

    assert_eq!(
        inspection.stomping_report.overall_severity,
        StompingSeverity::Clean
    );
}

#[test]
fn e2e_stripped_zip_fallback_extraction() {
    let src = "Attribute VB_Name = \"FallbackModule\"\nSub FallbackMain()\nEnd Sub\n";
    let line0 = build_func_defn(0);
    let pcode = synthesize_pcode_line_map(&[&line0]);

    let cfb = synthesize_cfb_project(
        "FallbackProject",
        &[("FallbackModule", src, &pcode)],
        &["FallbackMain"],
    );

    // Scenario 1: Stripped ZIP with xl/vbaProject.bin
    let stripped_zip_xl = synthesize_stripped_zip(&cfb, "xl/vbaProject.bin");
    let extracted_xl = extract_macro_container(&stripped_zip_xl, &Limits::default())
        .expect("fallback extraction should succeed for xl/vbaProject.bin");
    assert_eq!(extracted_xl.name.as_deref(), Some("FallbackProject"));
    assert_eq!(extracted_xl.modules.len(), 1);
    assert!(
        extracted_xl
            .diagnostics
            .iter()
            .any(|d| d.contains("extracted directly from entry 'xl/vbaProject.bin'"))
    );

    // Scenario 2: Stripped ZIP with root vbaProject.bin
    let stripped_zip_root = synthesize_stripped_zip(&cfb, "vbaProject.bin");
    let extracted_root = extract_macro_container(&stripped_zip_root, &Limits::default())
        .expect("fallback extraction should succeed for root vbaProject.bin");
    assert_eq!(extracted_root.name.as_deref(), Some("FallbackProject"));
    assert!(
        extracted_root
            .diagnostics
            .iter()
            .any(|d| d.contains("extracted directly from entry 'vbaProject.bin'"))
    );
}

#[test]
fn e2e_multi_module_container_inspection() {
    let src1 = "Attribute VB_Name = \"OrderModule\"\nSub CalcOrderTotal()\n    Dim total As Double\n    total = 250.0\nEnd Sub\n";
    let src2 = "Attribute VB_Name = \"AuditClass\"\nSub LogAuditEntry()\n    ' Audit entry logger\nEnd Sub\n";

    let line_mod1 = build_func_defn(0);
    let pcode1 = synthesize_pcode_line_map(&[&line_mod1]);

    let line_mod2 = build_func_defn(1);
    let pcode2 = synthesize_pcode_line_map(&[&line_mod2]);

    let cfb = synthesize_cfb_project(
        "MultiModuleCorp",
        &[
            ("OrderModule", src1, &pcode1),
            ("AuditClass", src2, &pcode2),
        ],
        &["CalcOrderTotal", "LogAuditEntry"],
    );
    let xlsm = synthesize_xlsm(&cfb);

    let inspection = inspect_macro_file(&xlsm, &AnalysisOptions::default())
        .expect("multi-module inspection should succeed");

    assert_eq!(
        inspection.extracted.name.as_deref(),
        Some("MultiModuleCorp")
    );
    assert_eq!(inspection.extracted.modules.len(), 2);
    assert_eq!(inspection.stomping_report.modules.len(), 2);
    assert_eq!(
        inspection.stomping_report.overall_severity,
        StompingSeverity::Clean
    );

    let json_out = inspect_to_json(&inspection, Disclosure::IncludeSource);
    assert!(json_out.contains("OrderModule"));
    assert!(json_out.contains("AuditClass"));
}

#[test]
fn e2e_legacy_cfb_direct_container_extraction() {
    let src = "Sub LegacyTask()\nEnd Sub\n";
    let mut pcode = vec![0u8; 32];
    pcode[0..2].copy_from_slice(&0xCAFEu16.to_le_bytes());

    let cfb_raw = synthesize_cfb("LegacyProject", "OldModule", src, &pcode);

    let extracted = extract_macro_container(&cfb_raw, &Limits::default())
        .expect("direct CFB extraction should succeed");

    assert_eq!(extracted.name.as_deref(), Some("LegacyProject"));
    assert_eq!(extracted.modules.len(), 1);
    assert_eq!(extracted.modules[0].name, "OldModule");
}

#[test]
fn e2e_cli_binary_execution_workflow() {
    let src = "Attribute VB_Name = \"TestModule\"\nSub Main()\nEnd Sub\n";
    let mut pcode = vec![0u8; 32];
    pcode[0..2].copy_from_slice(&0xCAFEu16.to_le_bytes());

    let cfb = synthesize_cfb("CliProject", "TestModule", src, &pcode);
    let xlsm = synthesize_xlsm(&cfb);

    let temp_dir = std::env::temp_dir();
    let file_path = temp_dir.join("vba_insight_cli_test.xlsm");
    fs::write(&file_path, &xlsm).expect("should write test file");

    let bin_path = env!("CARGO_BIN_EXE_vba-insight");

    // 1. Test 'inspect --format json'
    let output = Command::new(bin_path)
        .arg("inspect")
        .arg(&file_path)
        .arg("--format")
        .arg("json")
        .output()
        .expect("CLI execution failed");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"schema_version\":\"0.1\""));
    assert!(stdout.contains("CliProject"));

    // 2. Test 'stomping --format sarif'
    let output_sarif = Command::new(bin_path)
        .arg("stomping")
        .arg(&file_path)
        .arg("--format")
        .arg("sarif")
        .output()
        .expect("CLI execution failed");

    assert!(output_sarif.status.success());
    let stdout_sarif = String::from_utf8_lossy(&output_sarif.stdout);
    assert!(stdout_sarif.contains("sarif-schema-2.1.0.json"));

    // 3. Test 'disasm --format markdown'
    let output_disasm = Command::new(bin_path)
        .arg("disasm")
        .arg(&file_path)
        .arg("--format")
        .arg("markdown")
        .output()
        .expect("CLI execution failed");

    assert!(output_disasm.status.success());
    let stdout_disasm = String::from_utf8_lossy(&output_disasm.stdout);
    assert!(stdout_disasm.contains("VBA P-Code Disassembly Report"));

    // Cleanup
    let _ = fs::remove_file(&file_path);
}
