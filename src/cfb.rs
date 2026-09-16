//! Bounded read-only Compound File Binary (CFB/OLE) reader.

use crate::model::Limits;
use std::collections::HashSet;

const FREE: u32 = 0xFFFFFFFF;
const END: u32 = 0xFFFFFFFE;
const SIG: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
#[derive(Clone, Debug)]
pub struct DirectoryEntry {
    pub id: usize,
    pub name: String,
    pub kind: u8,
    pub path: String,
    pub start_sector: u32,
    pub size: u64,
    pub left: u32,
    pub right: u32,
    pub child: u32,
}
#[derive(Clone, Debug)]
pub struct CompoundFile<'a> {
    data: &'a [u8],
    sector_size: usize,
    mini_sector_size: usize,
    cutoff: usize,
    fat: Vec<u32>,
    mini_fat: Vec<u32>,
    root_mini_stream: Vec<u8>,
    pub entries: Vec<DirectoryEntry>,
    max_sectors: usize,
    max_bytes: usize,
}

impl<'a> CompoundFile<'a> {
    pub fn open(data: &'a [u8], limits: &Limits) -> Result<Self, String> {
        if data.len() > limits.max_input_bytes {
            return Err("CFB input exceeds configured limit".into());
        }
        if data.len() < 512 || data[..8] != SIG {
            return Err("not a Compound File Binary file".into());
        }
        let major = u16le(data, 26)?;
        let shift = u16le(data, 30)? as u32;
        let mini_shift = u16le(data, 32)? as u32;
        if !matches!(major, 3 | 4) || shift != if major == 3 { 9 } else { 12 } || mini_shift != 6 {
            return Err("unsupported or inconsistent CFB sector geometry".into());
        }
        let sector_size = 1usize << shift;
        let mini_sector_size = 1usize << mini_shift;
        if data.len() < sector_size {
            return Err("truncated CFB header sector".into());
        }
        let num_fat = u32le(data, 44)? as usize;
        let first_dir = u32le(data, 48)?;
        let cutoff = u32le(data, 56)? as usize;
        let first_mini = u32le(data, 60)?;
        let num_mini = u32le(data, 64)? as usize;
        let first_difat = u32le(data, 68)?;
        let num_difat = u32le(data, 72)? as usize;
        if cutoff != 4096 {
            return Err("invalid CFB mini-stream cutoff".into());
        }
        let available = data.len().saturating_sub(sector_size) / sector_size;
        if available > limits.max_cfb_sectors {
            return Err("CFB sector count exceeds configured limit".into());
        }
        let mut difat = Vec::new();
        for i in 0..109 {
            let v = u32le(data, 76 + i * 4)?;
            if v != FREE {
                difat.push(v);
            }
        }
        let mut sid = first_difat;
        let mut seen = HashSet::new();
        let per = sector_size / 4 - 1;
        if num_difat > limits.max_cfb_sectors {
            return Err("CFB DIFAT sector count exceeds configured limit".into());
        }
        for _ in 0..num_difat {
            if sid == END || sid == FREE || !seen.insert(sid) {
                return Err("invalid or cyclic CFB DIFAT chain".into());
            }
            let sec = sector(data, sector_size, sid)?;
            for i in 0..per {
                let v = u32le(sec, i * 4)?;
                if v != FREE {
                    difat.push(v);
                }
            }
            sid = u32le(sec, per * 4)?;
        }
        if difat.len() < num_fat {
            return Err("CFB DIFAT contains fewer FAT sectors than declared".into());
        }
        difat.truncate(num_fat);
        let mut fat = Vec::new();
        for fsid in difat {
            let sec = sector(data, sector_size, fsid)?;
            for c in sec.chunks_exact(4) {
                fat.push(u32::from_le_bytes(c.try_into().unwrap()));
            }
        }
        let dir_bytes = read_regular(
            data,
            sector_size,
            &fat,
            first_dir,
            None,
            limits.max_decompressed_bytes,
            limits.max_cfb_sectors,
        )?;
        if dir_bytes.len() % 128 != 0 {
            return Err("CFB directory stream has a partial entry".into());
        }
        let mut entries = Vec::new();
        for (id, r) in dir_bytes.chunks_exact(128).enumerate() {
            let nlen = u16le(r, 64)? as usize;
            if !(2..=64).contains(&nlen) || nlen & 1 != 0 {
                if r[66] == 0 {
                    continue;
                }
                return Err(format!("invalid CFB directory name length in entry {id}"));
            }
            let units = r[..nlen - 2]
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect::<Vec<_>>();
            let raw_name = String::from_utf16(&units)
                .map_err(|_| format!("invalid UTF-16 CFB directory name in entry {id}"))?;
            let name = raw_name.trim_matches('\0').to_string();
            let kind = r[66];
            let start_sector = u32le(r, 116)?;
            let size = u64le(r, 120)?;
            let (left, right, child) = (u32le(r, 68)?, u32le(r, 72)?, u32le(r, 76)?);
            entries.push(DirectoryEntry {
                id,
                name,
                kind,
                path: String::new(),
                start_sector,
                size,
                left,
                right,
                child,
            });
        }
        if entries.is_empty() || entries[0].kind != 5 {
            return Err("CFB root directory entry is missing".into());
        }
        let mut visited_storages = HashSet::new();
        assign_paths(&mut entries, 0, "", 0, &mut visited_storages)?;
        for entry in &mut entries {
            if entry.id != 0 && entry.path.is_empty() && matches!(entry.kind, 1 | 2) {
                entry.path = format!("[unlinked]/{}", entry.name);
            }
        }
        let mini_stream = read_regular(
            data,
            sector_size,
            &fat,
            entries[0].start_sector,
            Some(entries[0].size),
            limits.max_decompressed_bytes,
            limits.max_cfb_sectors,
        )?;
        let mini_fat_bytes = if num_mini == 0 {
            Vec::new()
        } else {
            read_regular(
                data,
                sector_size,
                &fat,
                first_mini,
                Some((num_mini * sector_size) as u64),
                limits.max_decompressed_bytes,
                limits.max_cfb_sectors,
            )?
        };
        let mini_fat = mini_fat_bytes
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect();
        Ok(Self {
            data,
            sector_size,
            mini_sector_size,
            cutoff,
            fat,
            mini_fat,
            root_mini_stream: mini_stream,
            entries,
            max_sectors: limits.max_cfb_sectors,
            max_bytes: limits.max_decompressed_bytes,
        })
    }
    pub fn find(&self, path: &str) -> Option<&DirectoryEntry> {
        let p = path.replace('\\', "/");
        self.entries
            .iter()
            .find(|e| e.kind == 2 && e.path.eq_ignore_ascii_case(&p))
    }
    pub fn stream(&self, e: &DirectoryEntry) -> Result<Vec<u8>, String> {
        if e.kind != 2 {
            return Err(format!("CFB entry is not a stream: {}", e.path));
        }
        if e.size > self.max_bytes as u64 {
            return Err(format!("CFB stream exceeds limit: {}", e.path));
        }
        if e.size == 0 {
            return Ok(Vec::new());
        }
        if e.size < self.cutoff as u64 {
            read_mini(
                &self.root_mini_stream,
                self.mini_sector_size,
                &self.mini_fat,
                e.start_sector,
                e.size,
                self.max_bytes,
                self.max_sectors,
            )
        } else {
            read_regular(
                self.data,
                self.sector_size,
                &self.fat,
                e.start_sector,
                Some(e.size),
                self.max_bytes,
                self.max_sectors,
            )
        }
    }
    pub fn stream_by_path(&self, path: &str) -> Result<Option<Vec<u8>>, String> {
        match self.find(path) {
            Some(e) => self.stream(e).map(Some),
            None => Ok(None),
        }
    }
    fn _phantom(&self) -> usize {
        self.mini_sector_size
    }
}

fn assign_paths(
    entries: &mut [DirectoryEntry],
    storage: usize,
    prefix: &str,
    depth: usize,
    visited_storages: &mut HashSet<usize>,
) -> Result<(), String> {
    if depth > 128 {
        return Err("CFB directory nesting limit exceeded".into());
    }
    if !visited_storages.insert(storage) {
        return Err("CFB directory storage contains a cycle".into());
    }
    let child = entries.get(storage).map(|e| e.child).unwrap_or(FREE);
    let mut seen = HashSet::new();
    walk_siblings(entries, child, prefix, depth, &mut seen, visited_storages)
}
fn walk_siblings(
    entries: &mut [DirectoryEntry],
    id: u32,
    parent: &str,
    depth: usize,
    seen: &mut HashSet<u32>,
    visited_storages: &mut HashSet<usize>,
) -> Result<(), String> {
    if id == FREE || id == END {
        return Ok(());
    }
    if depth > 128 {
        return Err("CFB directory tree depth exceeded".into());
    }
    let idx = id as usize;
    if idx >= entries.len() {
        return Err("CFB directory tree contains an invalid entry id".into());
    }
    if !seen.insert(id) {
        return Err("CFB directory tree contains a cycle".into());
    }
    let left = entries[idx].left;
    let right = entries[idx].right;
    let name = entries[idx].name.clone();
    let path = if parent.is_empty() {
        name.clone()
    } else {
        format!("{parent}/{name}")
    };
    let kind = entries[idx].kind;
    entries[idx].path = path.clone();
    walk_siblings(entries, left, parent, depth + 1, seen, visited_storages)?;
    if kind == 1 {
        assign_paths(entries, idx, &path, depth + 1, visited_storages)?;
    }
    walk_siblings(entries, right, parent, depth + 1, seen, visited_storages)
}
fn sector(data: &[u8], size: usize, sid: u32) -> Result<&[u8], String> {
    let off = (sid as usize)
        .checked_add(1)
        .and_then(|x| x.checked_mul(size))
        .ok_or("CFB sector offset overflow")?;
    data.get(off..off + size)
        .ok_or_else(|| format!("CFB sector {sid} lies outside the file"))
}
fn read_regular(
    data: &[u8],
    ss: usize,
    fat: &[u32],
    start: u32,
    size: Option<u64>,
    limit: usize,
    max_sectors: usize,
) -> Result<Vec<u8>, String> {
    if start == END || start == FREE {
        return if size.unwrap_or(0) == 0 {
            Ok(Vec::new())
        } else {
            Err("CFB stream starts at an end marker".into())
        };
    }
    let mut out = Vec::new();
    let mut sid = start;
    let mut visited = HashSet::new();
    while sid != END && sid != FREE {
        if visited.len() >= max_sectors {
            return Err("CFB sector chain exceeds traversal limit".into());
        }
        if !visited.insert(sid) {
            return Err("cyclic CFB sector chain".into());
        }
        let idx = sid as usize;
        let next = *fat
            .get(idx)
            .ok_or_else(|| format!("CFB sector {sid} has no FAT entry"))?;
        let sec = sector(data, ss, sid)?;
        if out.len() + sec.len() > limit.saturating_add(ss) {
            return Err("CFB stream exceeds size limit".into());
        }
        out.extend_from_slice(sec);
        sid = next;
    }
    if let Some(n) = size {
        if n > out.len() as u64 {
            return Err("CFB chain shorter than declared stream size".into());
        }
        out.truncate(n as usize);
    }
    Ok(out)
}
fn read_mini(
    root: &[u8],
    ms: usize,
    fat: &[u32],
    start: u32,
    size: u64,
    limit: usize,
    max: usize,
) -> Result<Vec<u8>, String> {
    if start == END || start == FREE {
        return Err("mini stream starts at an end marker".into());
    }
    if size > limit as u64 {
        return Err("CFB mini stream exceeds limit".into());
    }
    let mut out = Vec::new();
    let mut sid = start;
    let mut seen = HashSet::new();
    while sid != END && sid != FREE {
        if seen.len() >= max {
            return Err("CFB mini-sector chain exceeds traversal limit".into());
        }
        if !seen.insert(sid) {
            return Err("cyclic CFB mini-sector chain".into());
        }
        let off = (sid as usize)
            .checked_mul(ms)
            .ok_or("mini-sector offset overflow")?;
        let chunk = root
            .get(off..off + ms)
            .ok_or("mini-sector outside root mini stream")?;
        out.extend_from_slice(chunk);
        sid = *fat
            .get(sid as usize)
            .ok_or("mini-sector has no MiniFAT entry")?;
    }
    if size > out.len() as u64 {
        return Err("mini-sector chain shorter than declared stream size".into());
    }
    out.truncate(size as usize);
    Ok(out)
}
fn u16le(d: &[u8], i: usize) -> Result<u16, String> {
    Ok(u16::from_le_bytes(
        d.get(i..i + 2)
            .ok_or("truncated CFB structure")?
            .try_into()
            .unwrap(),
    ))
}
fn u32le(d: &[u8], i: usize) -> Result<u32, String> {
    Ok(u32::from_le_bytes(
        d.get(i..i + 4)
            .ok_or("truncated CFB structure")?
            .try_into()
            .unwrap(),
    ))
}
fn u64le(d: &[u8], i: usize) -> Result<u64, String> {
    Ok(u64::from_le_bytes(
        d.get(i..i + 8)
            .ok_or("truncated CFB structure")?
            .try_into()
            .unwrap(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_non_cfb_and_bad_signature() {
        assert!(
            CompoundFile::open(b"nope", &Limits::default())
                .unwrap_err()
                .contains("Compound File")
        );
    }
    #[test]
    fn opens_a_minimal_v4_compound_file() {
        let sector_size = 4096usize;
        let mut bytes = vec![0u8; sector_size * 4];
        bytes[..8].copy_from_slice(&SIG);
        bytes[26..28].copy_from_slice(&4u16.to_le_bytes());
        bytes[30..32].copy_from_slice(&12u16.to_le_bytes());
        bytes[32..34].copy_from_slice(&6u16.to_le_bytes());
        bytes[44..48].copy_from_slice(&1u32.to_le_bytes());
        bytes[48..52].copy_from_slice(&1u32.to_le_bytes());
        bytes[56..60].copy_from_slice(&4096u32.to_le_bytes());
        bytes[60..64].copy_from_slice(&END.to_le_bytes());
        bytes[64..68].copy_from_slice(&0u32.to_le_bytes());
        bytes[68..72].copy_from_slice(&END.to_le_bytes());
        bytes[72..76].copy_from_slice(&0u32.to_le_bytes());
        bytes[76..80].copy_from_slice(&0u32.to_le_bytes());
        for entry in 1..109 {
            bytes[76 + entry * 4..80 + entry * 4].copy_from_slice(&FREE.to_le_bytes());
        }
        bytes[sector_size..sector_size + 4].copy_from_slice(&0xfffffffdu32.to_le_bytes());
        bytes[sector_size + 4..sector_size + 8].copy_from_slice(&END.to_le_bytes());
        let directory = sector_size * 2;
        let name = "Root Entry".encode_utf16().collect::<Vec<_>>();
        for (index, unit) in name.iter().enumerate() {
            bytes[directory + index * 2..directory + index * 2 + 2]
                .copy_from_slice(&unit.to_le_bytes());
        }
        bytes[directory + 64..directory + 66]
            .copy_from_slice(&((name.len() as u16 + 1) * 2).to_le_bytes());
        bytes[directory + 66] = 5;
        for offset in [68usize, 72, 76] {
            bytes[directory + offset..directory + offset + 4].copy_from_slice(&FREE.to_le_bytes());
        }
        bytes[directory + 116..directory + 120].copy_from_slice(&END.to_le_bytes());
        bytes[directory + 120..directory + 128].copy_from_slice(&0u64.to_le_bytes());
        let cfb = CompoundFile::open(&bytes, &Limits::default()).unwrap();
        assert_eq!(cfb.entries.len(), 1);
        assert_eq!(cfb.entries[0].name, "Root Entry");
        assert_eq!(cfb.entries[0].kind, 5);
        let mut cyclic = bytes;
        cyclic[sector_size + 4..sector_size + 8].copy_from_slice(&1u32.to_le_bytes());
        assert!(
            CompoundFile::open(&cyclic, &Limits::default())
                .unwrap_err()
                .contains("cyclic")
        );
    }
}
