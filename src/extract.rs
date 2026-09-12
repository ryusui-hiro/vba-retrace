//! Direct read-only extraction of VBA sources and cache metadata from `.xlsm` files.

use crate::cfb::CompoundFile;
use crate::compiled::PCodeLineMap;
use crate::model::Limits;
use crate::ovba::{OvbaProject, parse_project};
use crate::source::decode_text;
use crate::zip::ZipArchive;

#[derive(Clone, Debug, Default)]
pub struct CacheRecord {
    pub module: String,
    pub byte_length: usize,
    pub fingerprint: u64,
    pub interpretation: String,
}
#[derive(Clone, Debug, Default)]
pub struct ExtractedModule {
    pub name: String,
    pub stream_name: String,
    pub source_text: Option<String>,
    pub source_bytes: Vec<u8>,
    pub performance_cache: Vec<u8>,
    pub cache: CacheRecord,
    pub pcode_layout: Option<PCodeLineMap>,
    pub pcode_layout_status: String,
    pub module_type: Option<String>,
    pub text_offset: u32,
    pub diagnostic: Option<String>,
}
#[derive(Clone, Debug, Default)]
pub struct ExtractedProject {
    pub name: Option<String>,
    pub code_page: Option<u16>,
    pub system_kind: Option<u32>,
    pub modules: Vec<ExtractedModule>,
    pub references: Vec<String>,
    pub conditional_constants: std::collections::BTreeMap<String, String>,
    pub project_cache: CacheRecord,
    pub metadata: Vec<(String, String)>,
    pub diagnostics: Vec<String>,
    pub compiled_representation_status: String,
}

pub fn extract_xlsm(data: &[u8], limits: &Limits) -> Result<ExtractedProject, String> {
    let zip = ZipArchive::open(data, limits)?;
    let entry = zip
        .find("xl/vbaProject.bin")
        .ok_or_else(|| "OOXML package has no xl/vbaProject.bin part".to_string())?;
    let bin = zip.read(entry)?;
    extract_vba_project(&bin, limits)
}

pub fn extract_vba_project(data: &[u8], limits: &Limits) -> Result<ExtractedProject, String> {
    let cfb = CompoundFile::open(data, limits)?;
    let dir = cfb
        .stream_by_path("VBA/dir")?
        .ok_or_else(|| "VBA storage has no dir stream".to_string())?;
    let project = cfb.stream_by_path("PROJECT")?;
    let cache = cfb.stream_by_path("VBA/_VBA_PROJECT")?;
    let mut streams = Vec::new();
    let mut total = 0usize;
    for e in &cfb.entries {
        if e.kind != 2
            || !e.path.to_ascii_lowercase().starts_with("vba/")
            || e.path.eq_ignore_ascii_case("VBA/dir")
            || e.path.eq_ignore_ascii_case("VBA/_VBA_PROJECT")
        {
            continue;
        }
        let bytes = cfb.stream(e)?;
        total = total
            .checked_add(bytes.len())
            .ok_or("VBA streams size overflow")?;
        if total > limits.max_decompressed_bytes {
            return Err("total VBA streams exceed configured limit".into());
        }
        let name = e.path.rsplit('/').next().unwrap_or(&e.name).to_string();
        streams.push((name, bytes));
    }
    let ovba = parse_project(
        &dir,
        project.as_deref(),
        cache.as_deref(),
        &streams,
        limits.max_decompressed_bytes,
        limits.max_modules,
    )?;
    Ok(convert(ovba))
}

fn convert(p: OvbaProject) -> ExtractedProject {
    let mut result = ExtractedProject {
        name: p.name,
        code_page: p.code_page,
        system_kind: p.system_kind,
        references: p.references,
        conditional_constants: p.compile_constants,
        ..ExtractedProject::default()
    };
    result.compiled_representation_status =
        "opaque_version_dependent_performance_cache; not disassembled or verified".into();
    result.project_cache=CacheRecord{module:"<project>".into(),byte_length:p.project_performance_cache_len,fingerprint:p.project_performance_cache_fingerprint,interpretation:"MS-OVBA performance cache is implementation/version dependent and MUST be ignored on read".into()};
    result.metadata.push((
        "VBA project version field".into(),
        p.project_version
            .map(|v| format!("0x{v:04X}"))
            .unwrap_or_else(|| "unavailable".into()),
    ));
    for m in p.modules {
        let diagnostic = m.source_error.clone();
        if let Some(e) = &diagnostic {
            result.diagnostics.push(format!("{}: {e}", m.name));
        }
        result.modules.push(ExtractedModule {
            name: m.name.clone(),
            stream_name: m.stream_name,
            source_text: m.source_text,
            source_bytes: m.source_bytes,
            performance_cache: m.performance_cache,
            cache: CacheRecord {
                module: m.name,
                byte_length: m.performance_cache_len,
                fingerprint: m.performance_cache_fingerprint,
                interpretation:
                    "opaque module performance cache; ignored for interoperable source analysis"
                        .into(),
            },
            pcode_layout: None,
            pcode_layout_status: "not_requested".into(),
            module_type: m.module_type,
            text_offset: m.text_offset,
            diagnostic,
        });
    }
    result
}

pub fn sources_from_extracted(project: &ExtractedProject) -> Vec<crate::model::SourceUnit> {
    project
        .modules
        .iter()
        .filter_map(|m| {
            m.source_text.as_ref().map(|text| crate::model::SourceUnit {
                name: m.name.clone(),
                text: text.clone(),
            })
        })
        .collect()
}

pub fn decode_extracted_bytes(
    module: &ExtractedModule,
    code_page: Option<u16>,
) -> Result<String, String> {
    decode_text(&module.source_bytes, code_page).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zip::crc32;
    #[test]
    fn rejects_plain_text() {
        assert!(
            extract_xlsm(b"not a workbook", &Limits::default())
                .unwrap_err()
                .contains("ZIP")
        );
    }
    #[test]
    fn extracts_module_from_synthetic_xlsm_package() {
        let bin = fixture_cfb();
        let x = extract_xlsm(&fixture_zip(&bin), &Limits::default()).unwrap();
        assert_eq!(x.name.as_deref(), Some("TestProject"));
        assert_eq!(x.code_page, Some(1252));
        assert_eq!(x.system_kind, Some(1));
        assert_eq!(
            x.conditional_constants.get("Win64").map(String::as_str),
            Some("1")
        );
        assert_eq!(x.modules.len(), 1);
        assert_eq!(x.modules[0].name, "Mod1");
        assert_eq!(
            x.modules[0].source_text.as_deref(),
            Some("Public Sub Hello()\r\nEnd Sub\r\n")
        );
        assert_eq!(x.modules[0].cache.byte_length, 2);
        assert!(x.compiled_representation_status.contains("opaque"));
        assert_eq!(x.references[0], "stdole");
    }
    fn record(id: u16, payload: &[u8], out: &mut Vec<u8>) {
        out.extend_from_slice(&id.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
    }
    fn comp(data: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        for chunk in data.chunks(8) {
            body.push(0);
            body.extend_from_slice(chunk);
        }
        let total = body.len() + 2;
        let h = 0xb000u16 | ((total - 3) as u16);
        let mut out = vec![1];
        out.extend_from_slice(&h.to_le_bytes());
        out.extend_from_slice(&body);
        out
    }
    fn fixture_cfb() -> Vec<u8> {
        let mut dir = Vec::new();
        record(0x0001, &1u32.to_le_bytes(), &mut dir);
        record(0x0002, &0x0409u32.to_le_bytes(), &mut dir);
        record(0x0014, &0x0409u32.to_le_bytes(), &mut dir);
        record(0x0003, &1252u16.to_le_bytes(), &mut dir);
        record(0x0004, b"TestProject", &mut dir);
        dir.extend_from_slice(&0x0005u16.to_le_bytes());
        dir.extend_from_slice(&0u32.to_le_bytes());
        dir.extend_from_slice(&0x0040u16.to_le_bytes());
        dir.extend_from_slice(&0u32.to_le_bytes());
        dir.extend_from_slice(&0x0006u16.to_le_bytes());
        dir.extend_from_slice(&0u32.to_le_bytes());
        dir.extend_from_slice(&0x003du16.to_le_bytes());
        dir.extend_from_slice(&0u32.to_le_bytes());
        record(0x0007, &0u32.to_le_bytes(), &mut dir);
        record(0x0008, &0u32.to_le_bytes(), &mut dir);
        dir.extend_from_slice(&0x0009u16.to_le_bytes());
        dir.extend_from_slice(&4u32.to_le_bytes());
        dir.extend_from_slice(&1u32.to_le_bytes());
        dir.extend_from_slice(&1u16.to_le_bytes());
        let constants = b"Win64 = 1";
        dir.extend_from_slice(&0x000cu16.to_le_bytes());
        dir.extend_from_slice(&(constants.len() as u32).to_le_bytes());
        dir.extend_from_slice(constants);
        dir.extend_from_slice(&0x003cu16.to_le_bytes());
        let constants_u = "Win64 = 1"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        dir.extend_from_slice(&(constants_u.len() as u32).to_le_bytes());
        dir.extend_from_slice(&constants_u);
        // One optional REFERENCENAME followed by a registered-library reference.
        dir.extend_from_slice(&0x0016u16.to_le_bytes());
        dir.extend_from_slice(&6u32.to_le_bytes());
        dir.extend_from_slice(b"stdole");
        dir.extend_from_slice(&0x003eu16.to_le_bytes());
        let ref_name_u = "stdole"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        dir.extend_from_slice(&(ref_name_u.len() as u32).to_le_bytes());
        dir.extend_from_slice(&ref_name_u);
        let libid = b"stdole";
        dir.extend_from_slice(&0x000du16.to_le_bytes());
        dir.extend_from_slice(&((4 + libid.len() + 4 + 2) as u32).to_le_bytes());
        dir.extend_from_slice(&(libid.len() as u32).to_le_bytes());
        dir.extend_from_slice(libid);
        dir.extend_from_slice(&0u32.to_le_bytes());
        dir.extend_from_slice(&0u16.to_le_bytes());
        dir.extend_from_slice(&0x000fu16.to_le_bytes());
        dir.extend_from_slice(&2u32.to_le_bytes());
        dir.extend_from_slice(&1u16.to_le_bytes());
        dir.extend_from_slice(&0x0013u16.to_le_bytes());
        dir.extend_from_slice(&2u32.to_le_bytes());
        dir.extend_from_slice(&0xffffu16.to_le_bytes());
        record(0x0019, b"Mod1", &mut dir);
        let name16 = "Mod1"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        record(0x0047, &name16, &mut dir);
        record(0x001a, b"Mod1", &mut dir);
        dir.extend_from_slice(&0x0032u16.to_le_bytes());
        dir.extend_from_slice(&(name16.len() as u32).to_le_bytes());
        dir.extend_from_slice(&name16);
        record(0x001c, b"", &mut dir);
        dir.extend_from_slice(&0x0048u16.to_le_bytes());
        dir.extend_from_slice(&0u32.to_le_bytes());
        record(0x0031, &2u32.to_le_bytes(), &mut dir); // replace payload size below with a 4-byte offset value
        let off_record = dir.len() - 10;
        dir[off_record + 2..off_record + 6].copy_from_slice(&4u32.to_le_bytes());
        dir[off_record + 6..off_record + 10].copy_from_slice(&2u32.to_le_bytes());
        record(0x001e, &0u32.to_le_bytes(), &mut dir);
        record(0x002c, &0xffffu16.to_le_bytes(), &mut dir);
        record(0x0021, &0u32.to_le_bytes(), &mut dir);
        dir.extend_from_slice(&0x002bu16.to_le_bytes());
        dir.extend_from_slice(&0u32.to_le_bytes());
        let dir = comp(&dir);
        let project = b"Name=TestProject\r\nReference=stdole\r\n".to_vec();
        let vcache = vec![0xcc, 0x61, 0xff, 0xff, 0, 0, 0];
        let source = comp(b"Public Sub Hello()\r\nEnd Sub\r\n");
        let mut module = vec![0xde, 0xad];
        module.extend_from_slice(&source);
        let mut mini = vec![0u8; 576];
        let mut at = 0;
        mini[at..at + dir.len()].copy_from_slice(&dir);
        at = 384;
        mini[at..at + project.len()].copy_from_slice(&project);
        at = 448;
        mini[at..at + vcache.len()].copy_from_slice(&vcache);
        at = 512;
        mini[at..at + module.len()].copy_from_slice(&module);
        // The directory occupies mini-sectors 0..5; the other streams occupy 6, 7, and 8.
        let mut dir_entries = vec![0u8; 1024];
        entry(
            &mut dir_entries,
            0,
            "Root Entry",
            5,
            0xffff_ffff,
            0xffff_ffff,
            1,
            4,
            576,
        );
        entry(
            &mut dir_entries,
            1,
            "VBA",
            1,
            0xffff_ffff,
            5,
            2,
            0xffff_ffff,
            0,
        );
        entry(
            &mut dir_entries,
            2,
            "dir",
            2,
            0xffff_ffff,
            3,
            0xffff_ffff,
            0,
            dir.len() as u64,
        );
        entry(
            &mut dir_entries,
            3,
            "Mod1",
            2,
            0xffff_ffff,
            4,
            0xffff_ffff,
            8,
            module.len() as u64,
        );
        entry(
            &mut dir_entries,
            4,
            "_VBA_PROJECT",
            2,
            0xffff_ffff,
            0xffff_ffff,
            0xffff_ffff,
            4,
            7,
        );
        entry(
            &mut dir_entries,
            5,
            "PROJECT",
            2,
            0xffff_ffff,
            0xffff_ffff,
            0xffff_ffff,
            6,
            project.len() as u64,
        );
        let mut file = vec![0u8; 512 + 6 * 512];
        file[..8].copy_from_slice(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
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
        let fat = 512;
        put32(&mut file, fat, 0xffff_fffd);
        put32(&mut file, fat + 4, 2);
        put32(&mut file, fat + 8, 0xffff_fffe);
        put32(&mut file, fat + 12, 0xffff_fffe);
        put32(&mut file, fat + 16, 5);
        put32(&mut file, fat + 20, 0xffff_fffe);
        put32(&mut file, fat + 24, 0xffff_ffff);
        file[1024..1536].copy_from_slice(&dir_entries[..512]);
        file[1536..2048].copy_from_slice(&dir_entries[512..]);
        put32(&mut file, 2048, 1);
        put32(&mut file, 2052, 2);
        put32(&mut file, 2056, 3);
        put32(&mut file, 2060, 4);
        put32(&mut file, 2064, 5);
        put32(&mut file, 2068, 0xffff_fffe);
        for i in 5..9 {
            put32(&mut file, 2048 + i * 4, 0xffff_fffe);
        }
        for i in 8..128 {
            put32(&mut file, 2048 + i * 4, 0xffff_ffff);
        }
        file[2560..3136].copy_from_slice(&mini);
        file
    }
    #[allow(clippy::too_many_arguments)]
    fn entry(
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
    fn put16(b: &mut [u8], i: usize, v: u16) {
        b[i..i + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn put32(b: &mut [u8], i: usize, v: u32) {
        b[i..i + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn fixture_zip(payload: &[u8]) -> Vec<u8> {
        let name = b"xl/vbaProject.bin";
        let crc = crc32(payload);
        let mut z = Vec::new();
        z.extend_from_slice(&0x04034b50u32.to_le_bytes());
        z.extend_from_slice(&20u16.to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes());
        z.extend_from_slice(&[0; 4]);
        z.extend_from_slice(&crc.to_le_bytes());
        z.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        z.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        z.extend_from_slice(&(name.len() as u16).to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes());
        z.extend_from_slice(name);
        z.extend_from_slice(payload);
        let cd = z.len();
        z.extend_from_slice(&0x02014b50u32.to_le_bytes());
        z.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        z.extend_from_slice(&crc.to_le_bytes());
        z.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        z.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        z.extend_from_slice(&(name.len() as u16).to_le_bytes());
        z.extend_from_slice(&[0; 6]);
        z.extend_from_slice(&[0; 6]);
        z.extend_from_slice(&0u32.to_le_bytes());
        z.extend_from_slice(name);
        let cdsize = z.len() - cd;
        z.extend_from_slice(&0x06054b50u32.to_le_bytes());
        z.extend_from_slice(&[0; 4]);
        z.extend_from_slice(&1u16.to_le_bytes());
        z.extend_from_slice(&1u16.to_le_bytes());
        z.extend_from_slice(&(cdsize as u32).to_le_bytes());
        z.extend_from_slice(&(cd as u32).to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes());
        z
    }
}
