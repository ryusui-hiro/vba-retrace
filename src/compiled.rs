//! Structural inspection of VBA compiled-cache regions.
//!
//! MS-OVBA defines module/project performance caches as implementation and
//! version dependent. This module validates their boundaries and fingerprints
//! the bytes without interpreting them as portable p-code.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectCacheInspection {
    pub reserved1: u16,
    pub version: u16,
    pub reserved2: u8,
    pub reserved3: u16,
    pub cache_length: usize,
    pub fingerprint_fnv1a64: u64,
    pub header_well_formed: bool,
    pub pcode_disassembled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleCacheInspection {
    pub declared_text_offset: u32,
    pub cache_length: usize,
    pub fingerprint_fnv1a64: u64,
    pub source_container_signature_valid: bool,
    pub pcode_disassembled: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PCodeLayoutProfile {
    /// Observed line-map layout used by modern VBA7 module caches.
    /// This profile identifies framing only; it does not identify a specific Office build.
    Vba7Observed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PCodeLineSegment {
    pub source_line: usize,
    pub line_length: u16,
    pub cache_offset: Option<usize>,
    pub raw_bytes: Vec<u8>,
    pub raw_word_count: usize,
    pub has_partial_word: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PCodeLineMap {
    pub profile: PCodeLayoutProfile,
    pub cafe_offset: usize,
    pub line_count: usize,
    pub directory_offset: usize,
    pub code_table_offset: usize,
    pub code_bytes_total: usize,
    pub lines: Vec<PCodeLineSegment>,
    pub mnemonics_decoded: bool,
}

/// Extract validated source-line slices from the VBA7-observed p-code layout.
/// The caller must select the profile; the generic MS-OVBA cache is opaque.
pub fn inspect_vba7_line_map(
    cache: &[u8],
    profile: PCodeLayoutProfile,
    max_lines: usize,
) -> Result<Option<PCodeLineMap>, String> {
    let mut search = 0usize;
    while search + 1 < cache.len() {
        let Some(relative) = cache[search..].windows(2).position(|w| w == [0xFE, 0xCA]) else {
            return Ok(None);
        };
        let cafe = search + relative;
        search = cafe + 2;
        if let Some(map) = try_line_map(cache, cafe, profile, max_lines)? {
            return Ok(Some(map));
        }
    }
    Ok(None)
}

fn try_line_map(
    cache: &[u8],
    cafe: usize,
    profile: PCodeLayoutProfile,
    max_lines: usize,
) -> Result<Option<PCodeLineMap>, String> {
    // Two profile-specific bytes follow CAFE before the u16 source-line count.
    let Some(count_offset) = cafe.checked_add(4) else {
        return Ok(None);
    };
    let Some(count_bytes) = cache.get(count_offset..count_offset + 2) else {
        return Ok(None);
    };
    let line_count = u16::from_le_bytes([count_bytes[0], count_bytes[1]]) as usize;
    if line_count == 0 || line_count > max_lines {
        return Ok(None);
    }
    let directory_offset = count_offset + 2;
    let Some(directory_bytes) = line_count.checked_mul(12) else {
        return Ok(None);
    };
    let Some(directory_end) = directory_offset.checked_add(directory_bytes) else {
        return Ok(None);
    };
    let Some(code_table_offset) = directory_end.checked_add(10) else {
        return Ok(None);
    };
    if code_table_offset > cache.len() {
        return Ok(None);
    }

    let mut lines = Vec::with_capacity(line_count);
    let mut total = 0usize;
    let mut previous_line_end = 0usize;
    for source_line in 0..line_count {
        let record = directory_offset + source_line * 12;
        let line_length = u16::from_le_bytes([cache[record + 4], cache[record + 5]]);
        let relative_offset =
            u32::from_le_bytes(cache[record + 8..record + 12].try_into().unwrap());
        if relative_offset == u32::MAX || line_length == 0 {
            lines.push(PCodeLineSegment {
                source_line,
                line_length,
                cache_offset: None,
                raw_bytes: Vec::new(),
                raw_word_count: 0,
                has_partial_word: false,
            });
            continue;
        }
        let Some(start) = code_table_offset.checked_add(relative_offset as usize) else {
            return Ok(None);
        };
        let Some(end) = start.checked_add(line_length as usize) else {
            return Ok(None);
        };
        let Some(bytes) = cache.get(start..end) else {
            return Ok(None);
        };
        let relative_end = (relative_offset as usize)
            .checked_add(line_length as usize)
            .ok_or("p-code line offset overflow")?;
        if (relative_offset as usize) < previous_line_end {
            return Ok(None);
        }
        previous_line_end = relative_end;
        total = total
            .checked_add(bytes.len())
            .ok_or("p-code byte count overflow")?;
        lines.push(PCodeLineSegment {
            source_line,
            line_length,
            cache_offset: Some(start),
            raw_bytes: bytes.to_vec(),
            raw_word_count: bytes.len() / 2,
            has_partial_word: bytes.len() & 1 != 0,
        });
    }
    Ok(Some(PCodeLineMap {
        profile,
        cafe_offset: cafe,
        line_count,
        directory_offset,
        code_table_offset,
        code_bytes_total: total,
        lines,
        mnemonics_decoded: false,
    }))
}

pub fn inspect_project_stream(stream: &[u8]) -> Result<ProjectCacheInspection, String> {
    if stream.len() < 7 {
        return Err("_VBA_PROJECT stream is shorter than its 7-byte header".into());
    }
    let reserved1 = u16::from_le_bytes([stream[0], stream[1]]);
    let version = u16::from_le_bytes([stream[2], stream[3]]);
    let reserved2 = stream[4];
    let reserved3 = u16::from_le_bytes([stream[5], stream[6]]);
    let cache = &stream[7..];
    Ok(ProjectCacheInspection {
        reserved1,
        version,
        reserved2,
        reserved3,
        cache_length: cache.len(),
        fingerprint_fnv1a64: fingerprint_fnv1a64(cache),
        header_well_formed: reserved1 == 0x61CC && reserved2 == 0,
        pcode_disassembled: false,
    })
}

pub fn inspect_module_stream(
    stream: &[u8],
    text_offset: u32,
) -> Result<ModuleCacheInspection, String> {
    let offset = text_offset as usize;
    if offset > stream.len() {
        return Err("MODULEOFFSET lies outside the module stream".into());
    }
    Ok(ModuleCacheInspection {
        declared_text_offset: text_offset,
        cache_length: offset,
        fingerprint_fnv1a64: fingerprint_fnv1a64(&stream[..offset]),
        source_container_signature_valid: stream.get(offset) == Some(&0x01),
        pcode_disassembled: false,
    })
}

pub fn fingerprint_fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for &byte in bytes {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_project_header_but_never_claims_to_decode_pcode() {
        let stream = [0xcc, 0x61, 0xff, 0xff, 0, 1, 0, 0xaa, 0xbb];
        let report = inspect_project_stream(&stream).unwrap();
        assert_eq!(report.version, 0xffff);
        assert_eq!(report.cache_length, 2);
        assert!(report.header_well_formed);
        assert!(!report.pcode_disassembled);
    }

    #[test]
    fn checks_module_cache_boundary_and_source_signature() {
        let report = inspect_module_stream(&[0xaa, 0xbb, 1, 0, 0], 2).unwrap();
        assert_eq!(report.cache_length, 2);
        assert!(report.source_container_signature_valid);
        assert!(!report.pcode_disassembled);
        assert!(inspect_module_stream(&[0], 2).is_err());
    }

    #[test]
    fn validates_line_map_and_preserves_raw_pcode_without_decoding_it() {
        let mut cache = vec![0u8; 2 + 2 + 2 + 12 * 2 + 10 + 6];
        cache[0..2].copy_from_slice(&[0xfe, 0xca]);
        cache[4..6].copy_from_slice(&2u16.to_le_bytes());
        cache[6 + 4..6 + 6].copy_from_slice(&4u16.to_le_bytes());
        cache[6 + 8..6 + 12].copy_from_slice(&0u32.to_le_bytes());
        cache[18 + 4..18 + 6].copy_from_slice(&2u16.to_le_bytes());
        cache[18 + 8..18 + 12].copy_from_slice(&4u32.to_le_bytes());
        let code = 40;
        cache[code..code + 6].copy_from_slice(&[0x05, 0x00, 0xAA, 0xBB, 0x09, 0x04]);
        let map = inspect_vba7_line_map(&cache, PCodeLayoutProfile::Vba7Observed, 100)
            .unwrap()
            .unwrap();
        assert_eq!(map.line_count, 2);
        assert_eq!(map.lines[0].raw_word_count, 2);
        assert_eq!(map.lines[1].raw_bytes, [0x09, 0x04]);
        assert!(!map.mnemonics_decoded);
    }

    #[test]
    fn accepts_independently_published_line_record_shapes() {
        // The 12-byte records are the published examples in the provenance document.
        let mut cache = vec![0u8; 40 + 0x10 + 6];
        cache[..2].copy_from_slice(&[0xfe, 0xca]);
        cache[4..6].copy_from_slice(&2u16.to_le_bytes());
        cache[6..18].copy_from_slice(&[
            0x00, 0x80, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        ]);
        cache[18..30].copy_from_slice(&[
            0x42, 0xa1, 0x08, 0x00, 0x06, 0x00, 0x0c, 0x00, 0x10, 0x00, 0x00, 0x00,
        ]);
        let map = inspect_vba7_line_map(&cache, PCodeLayoutProfile::Vba7Observed, 10)
            .unwrap()
            .unwrap();
        assert_eq!(map.lines[0].cache_offset, None);
        assert_eq!(map.lines[1].line_length, 6);
        assert_eq!(map.lines[1].cache_offset, Some(40 + 0x10));
    }
}
