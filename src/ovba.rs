//! Microsoft Office VBA project records and compressed source containers.

use crate::compiled::{inspect_module_stream, inspect_project_stream};
use crate::source::decode_text;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default)]
pub struct OvbaModule {
    pub name: String,
    pub stream_name: String,
    pub text_offset: u32,
    pub module_type: Option<String>,
    pub source_bytes: Vec<u8>,
    pub performance_cache: Vec<u8>,
    pub source_text: Option<String>,
    pub source_error: Option<String>,
    pub performance_cache_len: usize,
    pub performance_cache_fingerprint: u64,
}
#[derive(Clone, Debug, Default)]
pub struct OvbaProject {
    pub code_page: Option<u16>,
    pub name: Option<String>,
    pub system_kind: Option<u32>,
    pub references: Vec<String>,
    pub compile_constants: BTreeMap<String, String>,
    pub modules: Vec<OvbaModule>,
    pub project_version: Option<u16>,
    pub project_performance_cache_len: usize,
    pub project_performance_cache_fingerprint: u64,
}

pub fn decompress_container(data: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    if data.first() != Some(&1) {
        return Err("OVBA compressed-container signature must be 0x01".into());
    }
    let (mut pos, mut out) = (1usize, Vec::new());
    while pos < data.len() {
        if data.len() - pos < 2 {
            return Err("truncated OVBA compressed chunk header".into());
        }
        let h = u16::from_le_bytes([data[pos], data[pos + 1]]);
        if (h >> 12) & 7 != 3 {
            return Err("invalid OVBA compressed chunk signature".into());
        }
        let total = (h as usize & 0x0fff) + 3;
        if !(3..=4098).contains(&total) {
            return Err("invalid OVBA compressed chunk length".into());
        }
        let end = pos.checked_add(total).ok_or("OVBA chunk length overflow")?;
        if end > data.len() {
            return Err("OVBA chunk extends beyond compressed container".into());
        }
        let compressed = h & 0x8000 != 0;
        let body = &data[pos + 2..end];
        let chunk_start = out.len();
        if !compressed {
            if h & 0x0fff != 0x0fff || body.len() != 4096 {
                return Err("raw OVBA chunk must contain exactly 4096 bytes".into());
            }
            if out.len() + body.len() > limit {
                return Err("OVBA decompressed-size limit exceeded".into());
            }
            out.extend_from_slice(body);
        } else {
            let mut p = 0usize;
            while p < body.len() {
                let flags = body[p];
                p += 1;
                for bit in 0..8 {
                    if p >= body.len() {
                        break;
                    }
                    if flags & (1 << bit) == 0 {
                        if out.len() - chunk_start >= 4096 {
                            return Err("compressed OVBA chunk exceeds 4096 output bytes".into());
                        }
                        if out.len() >= limit {
                            return Err("OVBA decompressed-size limit exceeded".into());
                        }
                        out.push(body[p]);
                        p += 1;
                    } else {
                        if p + 2 > body.len() {
                            return Err("truncated OVBA copy token".into());
                        }
                        let token = u16::from_le_bytes([body[p], body[p + 1]]);
                        p += 2;
                        let diff = out.len() - chunk_start;
                        if diff == 0 {
                            return Err("OVBA copy token cannot refer before chunk start".into());
                        }
                        let bit_count = (usize::BITS - (diff - 1).leading_zeros()).max(4) as u16;
                        let length_mask = 0xffffu16 >> bit_count;
                        let offset_mask = !length_mask;
                        let length = (token & length_mask) as usize + 3;
                        let offset = ((token & offset_mask) >> (16 - bit_count)) as usize + 1;
                        if offset > diff {
                            return Err("OVBA copy token points before the current chunk".into());
                        }
                        if diff + length > 4096 {
                            return Err("OVBA copy sequence crosses its 4096-byte chunk".into());
                        }
                        if out.len().checked_add(length).is_none_or(|x| x > limit) {
                            return Err("OVBA decompressed-size limit exceeded".into());
                        }
                        for _ in 0..length {
                            let v = out[out.len() - offset];
                            out.push(v);
                        }
                    }
                }
            }
        }
        if out.len() == chunk_start {
            return Err("empty OVBA compressed chunk".into());
        }
        pos = end;
    }
    Ok(out)
}

#[derive(Clone, Debug, Default)]
struct ModRec {
    name: Option<Vec<u8>>,
    name_u: Option<String>,
    stream: Option<Vec<u8>>,
    stream_u: Option<String>,
    offset: Option<u32>,
    typ: Option<String>,
}

#[derive(Default)]
struct DirDirectory {
    code_page: u16,
    system_kind: u32,
    project_name: Option<String>,
    references: Vec<String>,
    compile_constants: BTreeMap<String, String>,
    module_count: usize,
    module_records_offset: usize,
}

struct DirReader<'a> {
    data: &'a [u8],
    pos: usize,
}
impl<'a> DirReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    fn u16(&mut self) -> Result<u16, String> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, String> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes(b.try_into().unwrap()))
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or("OVBA dir-stream offset overflow")?;
        let bytes = self
            .data
            .get(self.pos..end)
            .ok_or("truncated OVBA dir stream")?;
        self.pos = end;
        Ok(bytes)
    }
    fn peek_id(&self) -> Option<u16> {
        u16at(self.data, self.pos)
    }
    fn fixed(&mut self, id: u16, size: u32) -> Result<&'a [u8], String> {
        let got = self.u16()?;
        let n = self.u32()?;
        if got != id || n != size {
            return Err(format!(
                "invalid OVBA dir record 0x{got:04x} (expected 0x{id:04x}, size {size})"
            ));
        }
        self.take(size as usize)
    }
    fn variable(&mut self, id: u16, max: usize) -> Result<&'a [u8], String> {
        let got = self.u16()?;
        let n = self.u32()? as usize;
        if got != id || n > max {
            return Err(format!("invalid OVBA variable record 0x{got:04x}"));
        }
        self.take(n)
    }
}

fn parse_dir_directory(data: &[u8], max_modules: usize) -> Result<DirDirectory, String> {
    let mut r = DirReader::new(data);
    let system_kind = u32::from_le_bytes(r.fixed(0x0001, 4)?.try_into().unwrap());
    let mut out = DirDirectory {
        system_kind,
        ..DirDirectory::default()
    };
    if r.peek_id() == Some(0x004a) {
        let _ = r.fixed(0x004a, 4)?;
    }
    let _lcid = r.fixed(0x0002, 4)?;
    let _lcid_invoke = r.fixed(0x0014, 4)?;
    out.code_page = u16::from_le_bytes(r.fixed(0x0003, 2)?.try_into().unwrap());
    let name = r.variable(0x0004, 128)?;
    out.project_name = decode_text(name, Some(out.code_page)).ok();
    let _doc = r.variable(0x0005, 2000)?;
    if r.u16()? != 0x0040 {
        return Err("invalid PROJECTDOCSTRING reserved id".into());
    }
    let doc_unicode = r.u32()? as usize;
    if doc_unicode & 1 != 0 {
        return Err("odd-sized PROJECTDOCSTRING Unicode field".into());
    }
    let _ = r.take(doc_unicode)?;
    let _help1 = r.variable(0x0006, 260)?;
    if r.u16()? != 0x003d {
        return Err("invalid PROJECTHELPFILEPATH reserved id".into());
    }
    let help2 = r.u32()? as usize;
    let _ = r.take(help2)?;
    let _help_context = r.fixed(0x0007, 4)?;
    let _lib_flags = r.fixed(0x0008, 4)?;
    if r.u16()? != 0x0009 {
        return Err("PROJECTVERSION record is missing".into());
    }
    let _version_reserved = r.u32()?;
    let _version_major = r.u32()?;
    let _version_minor = r.u16()?;
    if r.peek_id() == Some(0x000c) {
        let constants = r.variable(0x000c, 1015)?;
        if r.u16()? != 0x003c {
            return Err("invalid PROJECTCONSTANTS reserved id".into());
        }
        let unicode_len = r.u32()? as usize;
        if unicode_len & 1 != 0 {
            return Err("odd-sized PROJECTCONSTANTS Unicode field".into());
        }
        let _ = r.take(unicode_len)?;
        if let Ok(text) = decode_text(constants, Some(out.code_page)) {
            for item in text.split(" : ") {
                if let Some((name, value)) = item.split_once(" = ") {
                    out.compile_constants
                        .insert(name.trim().into(), value.trim().into());
                }
            }
        }
    }
    loop {
        let Some(id) = r.peek_id() else {
            return Err("OVBA dir stream ended before PROJECTMODULES".into());
        };
        if id == 0x000f {
            break;
        }
        let name = if id == 0x0016 {
            Some(parse_reference_name(&mut r, out.code_page)?)
        } else {
            None
        };
        let kind = r.peek_id().ok_or("truncated PROJECTREFERENCES record")?;
        let fallback = match kind {
            0x000d => {
                let _id = r.u16()?;
                let _size = r.u32()?;
                let lib_len = r.u32()? as usize;
                let lib = r.take(lib_len)?;
                let _reserved1 = r.u32()?;
                let _reserved2 = r.u16()?;
                decode_text(lib, Some(out.code_page)).ok()
            }
            0x000e => {
                let _id = r.u16()?;
                let _size = r.u32()?;
                let abs_len = r.u32()? as usize;
                let abs = r.take(abs_len)?;
                let rel_len = r.u32()? as usize;
                let _rel = r.take(rel_len)?;
                let _major = r.u32()?;
                let _minor = r.u16()?;
                decode_text(abs, Some(out.code_page)).ok()
            }
            0x0033 => {
                let _id = r.u16()?;
                let original_len = r.u32()? as usize;
                let original = r.take(original_len)?;
                let original = decode_text(original, Some(out.code_page)).ok();
                parse_reference_control(&mut r, out.code_page)?.or(original)
            }
            0x002f => parse_reference_control(&mut r, out.code_page)?,
            _ => return Err(format!("unsupported OVBA reference record 0x{kind:04x}")),
        };
        if let Some(reference) = name.or(fallback) {
            out.references.push(reference);
        }
    }
    let _modules_header = r.pos;
    if r.u16()? != 0x000f || r.u32()? != 2 {
        return Err("invalid PROJECTMODULES record".into());
    }
    out.module_count = r.u16()? as usize;
    if out.module_count > max_modules {
        return Err("OVBA module count exceeds configured limit".into());
    }
    if r.u16()? != 0x0013 || r.u32()? != 2 {
        return Err("invalid PROJECTCOOKIE record".into());
    }
    let _project_cookie = r.u16()?;
    out.module_records_offset = r.pos;
    Ok(out)
}

fn parse_reference_name(r: &mut DirReader<'_>, code_page: u16) -> Result<String, String> {
    if r.u16()? != 0x0016 {
        return Err("invalid REFERENCENAME record".into());
    }
    let len = r.u32()? as usize;
    let ansi = r.take(len)?;
    if r.u16()? != 0x003e {
        return Err("invalid REFERENCENAME reserved id".into());
    }
    let unicode_len = r.u32()? as usize;
    if unicode_len & 1 != 0 {
        return Err("odd-sized REFERENCENAME Unicode value".into());
    }
    let unicode = r.take(unicode_len)?;
    utf16_bytes_to_string(unicode)
        .or_else(|_| decode_text(ansi, Some(code_page)).map_err(|e| e.to_string()))
}

fn parse_reference_control(
    r: &mut DirReader<'_>,
    code_page: u16,
) -> Result<Option<String>, String> {
    if r.u16()? != 0x002f {
        return Err("REFERENCECONTROL record is missing".into());
    }
    let size_twiddled = r.u32()? as usize;
    let before = r.pos;
    let lib_len = r.u32()? as usize;
    let lib = r.take(lib_len)?;
    let _reserved1 = r.u32()?;
    let _reserved2 = r.u16()?;
    if r.pos - before != size_twiddled {
        return Err("REFERENCECONTROL twiddled size mismatch".into());
    }
    let mut name = None;
    if r.peek_id() == Some(0x0016) {
        name = Some(parse_reference_name(r, code_page)?);
    }
    if r.u16()? != 0x0030 {
        return Err("invalid REFERENCECONTROL reserved id".into());
    }
    let size_extended = r.u32()? as usize;
    let extended_start = r.pos;
    let extended_len = r.u32()? as usize;
    let extended = r.take(extended_len)?;
    let _reserved4 = r.u32()?;
    let _reserved5 = r.u16()?;
    let _guid = r.take(16)?;
    let _cookie = r.u32()?;
    if r.pos - extended_start != size_extended {
        return Err("REFERENCECONTROL extended size mismatch".into());
    }
    Ok(name
        .or_else(|| decode_text(extended, Some(code_page)).ok())
        .or_else(|| decode_text(lib, Some(code_page)).ok()))
}

pub fn parse_project(
    dir_compressed: &[u8],
    project_stream: Option<&[u8]>,
    project_cache: Option<&[u8]>,
    module_streams: &[(String, Vec<u8>)],
    limit: usize,
    max_modules: usize,
) -> Result<OvbaProject, String> {
    let dir = decompress_container(dir_compressed, limit)?;
    let directory = parse_dir_directory(&dir, max_modules)?;
    let code_page = Some(directory.code_page);
    let recs = parse_module_records(
        &dir,
        directory.module_records_offset,
        directory.module_count,
        max_modules,
    )?;
    let mut p = OvbaProject {
        code_page,
        name: directory.project_name,
        system_kind: Some(directory.system_kind),
        references: directory.references,
        compile_constants: directory.compile_constants,
        ..OvbaProject::default()
    };
    let has_dir_references = !p.references.is_empty();
    if let Some(project) = project_stream
        && let Ok(t) = decode_text(project, code_page)
    {
        for l in t.lines() {
            if let Some(x) = l.strip_prefix("Name=") {
                p.name
                    .get_or_insert_with(|| x.trim().trim_matches('"').to_owned());
            }
            if !has_dir_references && let Some(x) = l.strip_prefix("Reference=") {
                p.references.push(x.trim().to_owned());
            }
        }
    }
    if let Some(v) = project_cache {
        let report = inspect_project_stream(v)?;
        p.project_version = Some(report.version);
        p.project_performance_cache_len = report.cache_length;
        p.project_performance_cache_fingerprint = report.fingerprint_fnv1a64;
    }
    for r in recs {
        let name = r
            .name_u
            .or_else(|| decode_field(r.name.as_deref(), code_page))
            .unwrap_or_else(|| "<undecodable module name>".into());
        let stream = r
            .stream_u
            .or_else(|| decode_field(r.stream.as_deref(), code_page))
            .unwrap_or_else(|| name.clone());
        let raw = module_streams
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(&stream))
            .map(|(_, b)| b.as_slice())
            .ok_or_else(|| format!("module stream missing for {name} ({stream})"))?;
        let declared_offset = r
            .offset
            .ok_or_else(|| format!("module offset missing for {name}"))?;
        let offset = declared_offset as usize;
        if offset >= raw.len() {
            return Err(format!(
                "module text offset {offset} is outside stream for {name}"
            ));
        }
        let cache = inspect_module_stream(raw, declared_offset)?;
        let source_bytes = decompress_container(&raw[offset..], limit)?;
        let source_text = decode_text(&source_bytes, code_page).ok();
        let source_error = decode_text(&source_bytes, code_page)
            .err()
            .map(|e| e.to_string());
        p.modules.push(OvbaModule {
            name,
            stream_name: stream,
            text_offset: offset as u32,
            module_type: r.typ,
            source_bytes,
            performance_cache: raw[..offset].to_vec(),
            source_text,
            source_error,
            performance_cache_len: cache.cache_length,
            performance_cache_fingerprint: cache.fingerprint_fnv1a64,
        });
    }
    Ok(p)
}

fn parse_module_records(
    d: &[u8],
    mut pos: usize,
    count: usize,
    max: usize,
) -> Result<Vec<ModRec>, String> {
    if count > max {
        return Err("OVBA module count exceeds configured limit".into());
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let mut r = ModRec::default();
        let mut steps = 0;
        loop {
            steps += 1;
            if steps > 32 {
                return Err("too many records in OVBA MODULE record".into());
            }
            let id = u16at(d, pos).ok_or("truncated OVBA MODULE record")?;
            match id {
                0x0019 | 0x0047 => {
                    let n = u32at(d, pos + 2).ok_or("truncated module name record")? as usize;
                    let b = d
                        .get(pos + 6..pos + 6 + n)
                        .ok_or("truncated module name")?
                        .to_vec();
                    if id == 0x0019 {
                        r.name = Some(b)
                    } else {
                        r.name_u = Some(utf16_bytes_to_string(&b)?);
                    }
                    pos += 6 + n;
                }
                0x001a => {
                    let n = u32at(d, pos + 2).ok_or("truncated stream name record")? as usize;
                    let b = d
                        .get(pos + 6..pos + 6 + n)
                        .ok_or("truncated stream name")?
                        .to_vec();
                    r.stream = Some(b);
                    pos += 6 + n;
                    if u16at(d, pos) != Some(0x0032) {
                        return Err("missing OVBA MODULESTREAMNAME Unicode record".into());
                    }
                    let ulen = u32at(d, pos + 2).ok_or("truncated Unicode stream name")? as usize;
                    if ulen & 1 != 0 {
                        return Err("odd-sized OVBA Unicode stream name".into());
                    }
                    let ub = d
                        .get(pos + 6..pos + 6 + ulen)
                        .ok_or("truncated Unicode stream name bytes")?;
                    r.stream_u = Some(utf16_bytes_to_string(ub)?);
                    pos += 6 + ulen;
                }
                0x001c => {
                    let n = u32at(d, pos + 2).ok_or("truncated module docstring")? as usize;
                    pos += 6 + n;
                    if u16at(d, pos) != Some(0x0048) {
                        return Err("missing OVBA MODULEDOCSTRING Unicode record".into());
                    }
                    let u = u32at(d, pos + 2).ok_or("truncated module docstring")? as usize;
                    pos += 6 + u;
                }
                0x0031 => {
                    if u32at(d, pos + 2) != Some(4) {
                        return Err("invalid MODULEOFFSET record size".into());
                    }
                    r.offset = u32at(d, pos + 6);
                    pos += 10;
                }
                0x001e | 0x002c | 0x0021 | 0x0022 | 0x0025 | 0x0028 => {
                    let sz = u32at(d, pos + 2).ok_or("truncated fixed module record")? as usize;
                    if pos + 6 + sz > d.len() {
                        return Err("truncated fixed module record".into());
                    }
                    if id == 0x0021 {
                        r.typ = Some("procedural".into());
                    }
                    if id == 0x0022 {
                        r.typ = Some("document_or_class".into());
                    }
                    pos += 6 + sz;
                }
                0x002b => {
                    pos += 2;
                    if u32at(d, pos) != Some(0) {
                        return Err("invalid MODULE terminator reserved field".into());
                    }
                    pos += 4;
                    break;
                }
                _ => {
                    return Err(format!(
                        "unexpected OVBA MODULE record 0x{id:04x} at offset {pos}"
                    ));
                }
            }
        }
        if r.name.is_none() && r.name_u.is_none() {
            return Err("OVBA module has no name".into());
        }
        if r.stream.is_none() && r.stream_u.is_none() {
            return Err("OVBA module has no stream name".into());
        }
        out.push(r);
    }
    Ok(out)
}
fn decode_field(v: Option<&[u8]>, cp: Option<u16>) -> Option<String> {
    let b = v?;
    decode_text(b, cp).ok()
}
fn utf16_bytes_to_string(b: &[u8]) -> Result<String, String> {
    if b.len() & 1 != 0 {
        return Err("odd-length UTF-16 field in OVBA dir stream".into());
    }
    let units = b
        .chunks_exact(2)
        .map(|x| u16::from_le_bytes([x[0], x[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&units).map_err(|_| "invalid UTF-16 field in OVBA dir stream".into())
}
fn u16at(d: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(i..i + 2)?.try_into().ok()?))
}
fn u32at(d: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(i..i + 4)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sized(id: u16, payload: &[u8], out: &mut Vec<u8>) {
        out.extend_from_slice(&id.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
    }
    fn directory_prefix() -> Vec<u8> {
        let mut d = Vec::new();
        sized(1, &1u32.to_le_bytes(), &mut d);
        sized(2, &0x409u32.to_le_bytes(), &mut d);
        sized(0x14, &0x409u32.to_le_bytes(), &mut d);
        sized(3, &1252u16.to_le_bytes(), &mut d);
        sized(4, b"Proj", &mut d);
        d.extend_from_slice(&5u16.to_le_bytes());
        d.extend_from_slice(&0u32.to_le_bytes());
        d.extend_from_slice(&0x40u16.to_le_bytes());
        d.extend_from_slice(&0u32.to_le_bytes());
        d.extend_from_slice(&6u16.to_le_bytes());
        d.extend_from_slice(&0u32.to_le_bytes());
        d.extend_from_slice(&0x3du16.to_le_bytes());
        d.extend_from_slice(&0u32.to_le_bytes());
        sized(7, &0u32.to_le_bytes(), &mut d);
        sized(8, &0u32.to_le_bytes(), &mut d);
        d.extend_from_slice(&9u16.to_le_bytes());
        d.extend_from_slice(&4u32.to_le_bytes());
        d.extend_from_slice(&1u32.to_le_bytes());
        d.extend_from_slice(&1u16.to_le_bytes());
        d
    }
    fn ref_name(name: &str, out: &mut Vec<u8>) {
        let ansi = name.as_bytes();
        let unicode = name
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        out.extend_from_slice(&0x16u16.to_le_bytes());
        out.extend_from_slice(&(ansi.len() as u32).to_le_bytes());
        out.extend_from_slice(ansi);
        out.extend_from_slice(&0x3eu16.to_le_bytes());
        out.extend_from_slice(&(unicode.len() as u32).to_le_bytes());
        out.extend_from_slice(&unicode);
    }
    fn modules_zero(out: &mut Vec<u8>) {
        out.extend_from_slice(&0x0fu16.to_le_bytes());
        out.extend_from_slice(&2u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0x13u16.to_le_bytes());
        out.extend_from_slice(&2u32.to_le_bytes());
        out.extend_from_slice(&0xffffu16.to_le_bytes());
    }
    #[test]
    fn decompresses_literal_chunk() {
        assert_eq!(
            decompress_container(&[1, 3, 0xb0, 0, b'a', b'b', b'c'], 100).unwrap(),
            b"abc"
        );
    }
    #[test]
    fn decompresses_uncompressed_chunk() {
        let mut b = vec![1, 0xff, 0x3f];
        b.extend(std::iter::repeat_n(b'x', 4096));
        assert_eq!(decompress_container(&b, 4096).unwrap(), vec![b'x'; 4096]);
    }
    #[test]
    fn rejects_bad_signature_and_forward_reference() {
        assert!(decompress_container(&[2], 100).is_err());
        let b = [1, 4, 0xb0, 1, 0, 0];
        assert!(decompress_container(&b, 100).is_err());
    }
    #[test]
    fn walks_project_information_and_registered_reference_records_in_order() {
        let mut d = directory_prefix();
        ref_name("stdole", &mut d);
        let lib = b"*\\G{00000000-0000-0000-0000-000000000000}#2.0#0#stdole.tlb#OLE";
        d.extend_from_slice(&0x0du16.to_le_bytes());
        d.extend_from_slice(&((4 + lib.len() + 4 + 2) as u32).to_le_bytes());
        d.extend_from_slice(&(lib.len() as u32).to_le_bytes());
        d.extend_from_slice(lib);
        d.extend_from_slice(&0u32.to_le_bytes());
        d.extend_from_slice(&0u16.to_le_bytes());
        modules_zero(&mut d);
        let info = parse_dir_directory(&d, 32).unwrap();
        assert_eq!(info.code_page, 1252);
        assert_eq!(info.project_name.as_deref(), Some("Proj"));
        assert_eq!(info.references, vec!["stdole"]);
        assert_eq!(info.module_count, 0);
    }
    #[test]
    fn walks_referenceproject_and_referencecontrol_records() {
        let mut d = directory_prefix();
        ref_name("BookRef", &mut d);
        let abs = b"*\\CBookRef.xls";
        let rel = b"*\\CBookRef.xls";
        d.extend_from_slice(&0x0eu16.to_le_bytes());
        d.extend_from_slice(&((4 + abs.len() + 4 + rel.len() + 4 + 2) as u32).to_le_bytes());
        d.extend_from_slice(&(abs.len() as u32).to_le_bytes());
        d.extend_from_slice(abs);
        d.extend_from_slice(&(rel.len() as u32).to_le_bytes());
        d.extend_from_slice(rel);
        d.extend_from_slice(&1u32.to_le_bytes());
        d.extend_from_slice(&1u16.to_le_bytes());
        ref_name("MSForms", &mut d);
        let lib = b"twiddled";
        let ext = b"extended";
        d.extend_from_slice(&0x2fu16.to_le_bytes());
        d.extend_from_slice(&((4 + lib.len() + 4 + 2) as u32).to_le_bytes());
        d.extend_from_slice(&(lib.len() as u32).to_le_bytes());
        d.extend_from_slice(lib);
        d.extend_from_slice(&0u32.to_le_bytes());
        d.extend_from_slice(&0u16.to_le_bytes());
        d.extend_from_slice(&0x30u16.to_le_bytes());
        d.extend_from_slice(&((4 + ext.len() + 4 + 2 + 16 + 4) as u32).to_le_bytes());
        d.extend_from_slice(&(ext.len() as u32).to_le_bytes());
        d.extend_from_slice(ext);
        d.extend_from_slice(&0u32.to_le_bytes());
        d.extend_from_slice(&0u16.to_le_bytes());
        d.extend_from_slice(&[0; 16]);
        d.extend_from_slice(&1u32.to_le_bytes());
        modules_zero(&mut d);
        let info = parse_dir_directory(&d, 32).unwrap();
        assert_eq!(info.references, vec!["BookRef", "MSForms"]);
    }
}
