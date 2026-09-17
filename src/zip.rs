//! Read-only bounded ZIP package reader for OOXML containers.

use crate::deflate::inflate_raw;
use crate::model::Limits;

const EOCD: u32 = 0x06054b50;
const CENTRAL: u32 = 0x02014b50;
const LOCAL: u32 = 0x04034b50;
#[derive(Clone, Debug)]
pub struct ZipEntry {
    pub name: String,
    pub method: u16,
    pub flags: u16,
    pub crc32: u32,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub local_offset: u64,
}
#[derive(Clone, Debug)]
pub struct ZipArchive<'a> {
    data: &'a [u8],
    pub entries: Vec<ZipEntry>,
    limits: Limits,
}

impl<'a> ZipArchive<'a> {
    pub fn open(data: &'a [u8], limits: &Limits) -> Result<Self, String> {
        if data.len() > limits.max_input_bytes {
            return Err("ZIP input exceeds configured limit".into());
        }
        let start = data.len().saturating_sub(65_557);
        let mut eocd = None;
        if data.len() < 22 {
            return Err("truncated ZIP file".into());
        }
        for i in (start..=data.len() - 22).rev() {
            if u32le(data, i) == Some(EOCD) {
                let comment = u16le(data, i + 20).unwrap_or(0) as usize;
                if i + 22 + comment <= data.len() {
                    eocd = Some(i);
                    break;
                }
            }
        }
        let e = eocd.ok_or_else(|| "ZIP end-of-central-directory record not found".to_string())?;
        let disk = u16le(data, e + 4).ok_or("truncated ZIP EOCD")?;
        let cddisk = u16le(data, e + 6).ok_or("truncated ZIP EOCD")?;
        let disk_count = u16le(data, e + 8).ok_or("truncated ZIP EOCD")?;
        let count = u16le(data, e + 10).ok_or("truncated ZIP EOCD")?;
        let cd_size = u32le(data, e + 12).ok_or("truncated ZIP EOCD")? as usize;
        let cd_off = u32le(data, e + 16).ok_or("truncated ZIP EOCD")? as usize;
        if disk != 0 || cddisk != 0 || disk_count != count {
            return Err("multi-disk ZIP archives are not supported".into());
        }
        if count == u16::MAX || cd_size == u32::MAX as usize || cd_off == u32::MAX as usize {
            return Err("ZIP64 archives are not supported".into());
        }
        if count as usize > limits.max_zip_entries {
            return Err("ZIP entry count exceeds configured limit".into());
        }
        if cd_off.checked_add(cd_size).is_none_or(|x| x > data.len()) {
            return Err("central directory is outside the file".into());
        }
        let (mut at, mut entries) = (cd_off, Vec::with_capacity(count as usize));
        for _ in 0..count {
            if u32le(data, at) != Some(CENTRAL) {
                return Err(format!("invalid central directory record at {at}"));
            }
            let flags = u16le(data, at + 8).ok_or("truncated central entry")?;
            let method = u16le(data, at + 10).ok_or("truncated central entry")?;
            let crc32 = u32le(data, at + 16).ok_or("truncated central entry")?;
            let csize = u32le(data, at + 20).ok_or("truncated central entry")?;
            let usize_ = u32le(data, at + 24).ok_or("truncated central entry")?;
            let nlen = u16le(data, at + 28).ok_or("truncated central entry")? as usize;
            let xlen = u16le(data, at + 30).ok_or("truncated central entry")? as usize;
            let clen = u16le(data, at + 32).ok_or("truncated central entry")? as usize;
            let offset = u32le(data, at + 42).ok_or("truncated central entry")?;
            let end = at
                .checked_add(46 + nlen + xlen + clen)
                .ok_or("central directory overflow")?;
            if end > cd_off + cd_size {
                return Err("central entry exceeds central directory".into());
            }
            let name = decode_name(&data[at + 46..at + 46 + nlen], flags & 0x0800 != 0);
            entries.push(ZipEntry {
                name,
                method,
                flags,
                crc32,
                compressed_size: csize as u64,
                uncompressed_size: usize_ as u64,
                local_offset: offset as u64,
            });
            at = end;
        }
        Ok(Self {
            data,
            entries,
            limits: limits.clone(),
        })
    }
    pub fn find(&self, path: &str) -> Option<&ZipEntry> {
        self.entries
            .iter()
            .find(|e| normalize(&e.name).eq_ignore_ascii_case(&normalize(path)))
    }
    pub fn read(&self, e: &ZipEntry) -> Result<Vec<u8>, String> {
        if e.flags & 1 != 0 {
            return Err(format!("encrypted ZIP entry is unsupported: {}", e.name));
        }
        if e.uncompressed_size > self.limits.max_decompressed_bytes as u64 {
            return Err(format!("ZIP entry exceeds decompression limit: {}", e.name));
        }
        if e.compressed_size > usize::MAX as u64 || e.uncompressed_size > usize::MAX as u64 {
            return Err("ZIP entry size is not representable".into());
        }
        let off =
            usize::try_from(e.local_offset).map_err(|_| "ZIP local-header offset overflow")?;
        if u32le(self.data, off) != Some(LOCAL) {
            return Err(format!("invalid local header for {}", e.name));
        }
        let flags = u16le(self.data, off + 6).ok_or("truncated local header")?;
        let method = u16le(self.data, off + 8).ok_or("truncated local header")?;
        if flags != e.flags || flags & 1 != 0 || method != e.method {
            return Err(format!("local and central headers disagree for {}", e.name));
        }
        if flags & 0x0008 == 0 {
            let crc = u32le(self.data, off + 14).ok_or("truncated local header")?;
            let compressed = u32le(self.data, off + 18).ok_or("truncated local header")?;
            let uncompressed = u32le(self.data, off + 22).ok_or("truncated local header")?;
            if crc != e.crc32
                || compressed as u64 != e.compressed_size
                || uncompressed as u64 != e.uncompressed_size
            {
                return Err(format!(
                    "local and central sizes or CRC disagree for {}",
                    e.name
                ));
            }
        }
        let nlen = u16le(self.data, off + 26).ok_or("truncated local header")? as usize;
        let xlen = u16le(self.data, off + 28).ok_or("truncated local header")? as usize;
        if off
            .checked_add(30 + nlen)
            .is_none_or(|x| x > self.data.len())
            || decode_name(&self.data[off + 30..off + 30 + nlen], flags & 0x0800 != 0) != e.name
        {
            return Err(format!(
                "local and central filenames disagree for {}",
                e.name
            ));
        }
        let start = off
            .checked_add(30 + nlen + xlen)
            .ok_or("ZIP local header overflow")?;
        let end = start
            .checked_add(e.compressed_size as usize)
            .ok_or("ZIP data overflow")?;
        if end > self.data.len() {
            return Err(format!("truncated compressed ZIP data for {}", e.name));
        }
        let packed = &self.data[start..end];
        let out = match e.method {
            0 => packed.to_vec(),
            8 => inflate_raw(packed, self.limits.max_decompressed_bytes)
                .map_err(|x| format!("{}: {x}", e.name))?,
            _ => {
                return Err(format!(
                    "unsupported ZIP compression method {} for {}",
                    e.method, e.name
                ));
            }
        };
        if out.len() as u64 != e.uncompressed_size {
            return Err(format!("uncompressed size mismatch for {}", e.name));
        }
        if crc32(&out) != e.crc32 {
            return Err(format!("CRC-32 mismatch for {}", e.name));
        }
        Ok(out)
    }
}

fn normalize(s: &str) -> String {
    s.replace('\\', "/").trim_start_matches('/').to_owned()
}
fn decode_name(s: &[u8], utf8: bool) -> String {
    if utf8 {
        String::from_utf8_lossy(s).into_owned()
    } else {
        s.iter().map(|&b| char::from(b)).collect()
    }
}
fn u16le(d: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(i..i + 2)?.try_into().ok()?))
}
fn u32le(d: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(i..i + 4)?.try_into().ok()?))
}
pub fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = (c >> 1) ^ ((0u32.wrapping_sub(c & 1)) & 0xedb88320);
        }
    }
    !c
}

#[cfg(test)]
mod tests {
    use super::*;
    fn zip_one(name: &[u8], payload: &[u8]) -> Vec<u8> {
        zip_with_method(name, payload, payload, 0)
    }
    fn zip_with_method(name: &[u8], packed: &[u8], plain: &[u8], method: u16) -> Vec<u8> {
        let mut z = Vec::new();
        let crc = crc32(plain);
        z.extend_from_slice(&LOCAL.to_le_bytes());
        z.extend_from_slice(&20u16.to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes());
        z.extend_from_slice(&method.to_le_bytes());
        z.extend_from_slice(&[0; 4]);
        z.extend_from_slice(&crc.to_le_bytes());
        z.extend_from_slice(&(packed.len() as u32).to_le_bytes());
        z.extend_from_slice(&(plain.len() as u32).to_le_bytes());
        z.extend_from_slice(&(name.len() as u16).to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes());
        z.extend_from_slice(name);
        z.extend_from_slice(packed);
        let cd = z.len();
        z.extend_from_slice(&CENTRAL.to_le_bytes());
        z.extend_from_slice(&[20, 0, 20, 0, 0, 0]);
        z.extend_from_slice(&method.to_le_bytes());
        z.extend_from_slice(&[0; 4]);
        z.extend_from_slice(&crc.to_le_bytes());
        z.extend_from_slice(&(packed.len() as u32).to_le_bytes());
        z.extend_from_slice(&(plain.len() as u32).to_le_bytes());
        z.extend_from_slice(&(name.len() as u16).to_le_bytes());
        z.extend_from_slice(&[0; 6]);
        z.extend_from_slice(&[0; 6]);
        z.extend_from_slice(&0u32.to_le_bytes());
        z.extend_from_slice(name);
        let cds = z.len() - cd;
        z.extend_from_slice(&EOCD.to_le_bytes());
        z.extend_from_slice(&[0; 4]);
        z.extend_from_slice(&1u16.to_le_bytes());
        z.extend_from_slice(&1u16.to_le_bytes());
        z.extend_from_slice(&(cds as u32).to_le_bytes());
        z.extend_from_slice(&(cd as u32).to_le_bytes());
        z.extend_from_slice(&[0; 2]);
        z
    }
    #[test]
    fn reads_stored_ooxml_entry() {
        let z = zip_one(b"xl/vbaProject.bin", b"abc");
        let a = ZipArchive::open(&z, &Limits::default()).unwrap();
        let e = a.find("xl/vbaProject.bin").unwrap();
        assert_eq!(a.read(e).unwrap(), b"abc");
    }
    #[test]
    fn reads_deflated_ooxml_entry() {
        let z = zip_with_method(
            b"xl/vbaProject.bin",
            &[0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00],
            b"hello",
            8,
        );
        let a = ZipArchive::open(&z, &Limits::default()).unwrap();
        assert_eq!(
            a.read(a.find("xl/vbaProject.bin").unwrap()).unwrap(),
            b"hello"
        );
    }
    #[test]
    fn rejects_local_header_crc_or_size_disagreement() {
        let mut z = zip_one(b"xl/vbaProject.bin", b"abc");
        z[14] ^= 1;
        let archive = ZipArchive::open(&z, &Limits::default()).unwrap();
        let entry = archive.find("xl/vbaProject.bin").unwrap();
        assert!(archive.read(entry).unwrap_err().contains("CRC"));
    }
}
