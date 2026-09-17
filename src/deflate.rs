//! Small bounded RFC 1951 inflater used by the ZIP reader. No encoder is provided.

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct InflateError(pub String);
impl std::fmt::Display for InflateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for InflateError {}

struct Bits<'a> {
    data: &'a [u8],
    bit: usize,
}
impl<'a> Bits<'a> {
    fn read(&mut self, n: usize) -> Result<u32, InflateError> {
        if n > 24 || self.bit + n > self.data.len() * 8 {
            return Err(InflateError("truncated deflate bitstream".into()));
        }
        let mut v = 0;
        for j in 0..n {
            v |= (((self.data[(self.bit + j) / 8] >> ((self.bit + j) % 8)) & 1) as u32) << j;
        }
        self.bit += n;
        Ok(v)
    }
    fn align(&mut self) {
        self.bit = (self.bit + 7) & !7;
    }
}

#[derive(Clone)]
struct Huffman {
    entries: Vec<(u32, u8, u16)>,
    max: u8,
}
impl Huffman {
    fn new(lengths: &[u8]) -> Result<Self, InflateError> {
        let max = *lengths.iter().max().unwrap_or(&0);
        if max == 0 || max > 15 {
            return Err(InflateError("invalid Huffman code lengths".into()));
        }
        let mut counts = [0u32; 16];
        for &l in lengths {
            if l > 0 {
                counts[l as usize] += 1;
            }
        }
        let mut left = 1i32;
        for &count in counts.iter().skip(1) {
            left = (left << 1) - count as i32;
            if left < 0 {
                return Err(InflateError("oversubscribed Huffman tree".into()));
            }
        }
        let mut next = [0u32; 16];
        let mut code = 0u32;
        for bits in 1..=15 {
            code = (code + counts[bits - 1]) << 1;
            next[bits] = code;
        }
        let mut entries = Vec::new();
        for (symbol, &len) in lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let c = next[len as usize];
            next[len as usize] += 1;
            entries.push((c, len, symbol as u16));
        }
        Ok(Self { entries, max })
    }
    fn decode(&self, b: &mut Bits) -> Result<u16, InflateError> {
        let mut c = 0u32;
        for n in 1..=self.max {
            c = (c << 1) | b.read(1)?;
            if let Some((_, _, sym)) = self
                .entries
                .iter()
                .find(|(code, len, _)| *len == n && *code == c)
            {
                return Ok(*sym);
            }
        }
        Err(InflateError("invalid Huffman code".into()))
    }
}
pub fn inflate_raw(input: &[u8], max_output: usize) -> Result<Vec<u8>, InflateError> {
    let mut bits = Bits {
        data: input,
        bit: 0,
    };
    let mut out = Vec::new();
    let mut final_block = false;
    while !final_block {
        final_block = bits.read(1)? != 0;
        let kind = bits.read(2)?;
        match kind {
            0 => {
                bits.align();
                let len = bits.read(16)? as usize;
                let nlen = bits.read(16)? as u16;
                if (len as u16) != !nlen {
                    return Err(InflateError("invalid stored-block length check".into()));
                }
                for _ in 0..len {
                    if out.len() >= max_output {
                        return Err(InflateError("decompressed size limit exceeded".into()));
                    }
                    out.push(bits.read(8)? as u8);
                }
            }
            1 => {
                let (lit, dist) = fixed_trees()?;
                inflate_codes(&mut bits, &mut out, &lit, &dist, max_output)?;
            }
            2 => {
                let (lit, dist) = dynamic_trees(&mut bits)?;
                inflate_codes(&mut bits, &mut out, &lit, &dist, max_output)?;
            }
            _ => return Err(InflateError("reserved deflate block type".into())),
        }
    }
    Ok(out)
}

fn fixed_trees() -> Result<(Huffman, Huffman), InflateError> {
    let mut l = vec![0; 288];
    for x in &mut l[0..=143] {
        *x = 8;
    }
    for x in &mut l[144..=255] {
        *x = 9;
    }
    for x in &mut l[256..=279] {
        *x = 7;
    }
    for x in &mut l[280..=287] {
        *x = 8;
    }
    Ok((Huffman::new(&l)?, Huffman::new(&[5; 32])?))
}

fn dynamic_trees(b: &mut Bits) -> Result<(Huffman, Huffman), InflateError> {
    let hlit = b.read(5)? as usize + 257;
    let hdist = b.read(5)? as usize + 1;
    let hclen = b.read(4)? as usize + 4;
    let order = [
        16usize, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];
    let mut clen = vec![0u8; 19];
    for i in 0..hclen {
        clen[order[i]] = b.read(3)? as u8;
    }
    let tree = Huffman::new(&clen)?;
    let mut lens = Vec::with_capacity(hlit + hdist);
    while lens.len() < hlit + hdist {
        match tree.decode(b)? {
            s @ 0..=15 => lens.push(s as u8),
            16 => {
                let prev = *lens
                    .last()
                    .ok_or_else(|| InflateError("repeat code without prior length".into()))?;
                let n = b.read(2)? as usize + 3;
                for _ in 0..n {
                    lens.push(prev);
                }
            }
            17 => {
                let n = b.read(3)? as usize + 3;
                lens.extend(std::iter::repeat_n(0, n));
            }
            18 => {
                let n = b.read(7)? as usize + 11;
                lens.extend(std::iter::repeat_n(0, n));
            }
            _ => unreachable!(),
        }
        if lens.len() > hlit + hdist {
            return Err(InflateError("code-length repeat exceeds table".into()));
        }
    }
    let dist_start = hlit;
    let ll = lens[..hlit].to_vec();
    if ll.len() <= 256 || ll[256] == 0 {
        return Err(InflateError(
            "literal/length tree has no end-of-block code".into(),
        ));
    }
    let dd = lens[dist_start..].to_vec();
    if dd.iter().all(|&x| x == 0) {
        return Err(InflateError("empty distance tree".into()));
    }
    Ok((Huffman::new(&ll)?, Huffman::new(&dd)?))
}

fn inflate_codes(
    b: &mut Bits,
    out: &mut Vec<u8>,
    lit: &Huffman,
    dist: &Huffman,
    limit: usize,
) -> Result<(), InflateError> {
    const LB: [usize; 29] = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115,
        131, 163, 195, 227, 258,
    ];
    const LE: [usize; 29] = [
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
    ];
    const DB: [usize; 30] = [
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
        2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
    ];
    const DE: [usize; 30] = [
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12,
        13, 13,
    ];
    loop {
        let sym = lit.decode(b)? as usize;
        match sym {
            0..=255 => {
                if out.len() >= limit {
                    return Err(InflateError("decompressed size limit exceeded".into()));
                }
                out.push(sym as u8);
            }
            256 => return Ok(()),
            257..=285 => {
                let ix = sym - 257;
                let len = LB[ix] + b.read(LE[ix])? as usize;
                let ds = dist.decode(b)? as usize;
                if ds >= 30 {
                    return Err(InflateError("reserved distance symbol".into()));
                }
                let distance = DB[ds] + b.read(DE[ds])? as usize;
                if distance == 0 || distance > out.len() {
                    return Err(InflateError(
                        "invalid deflate back-reference distance".into(),
                    ));
                }
                if out.len().saturating_add(len) > limit {
                    return Err(InflateError("decompressed size limit exceeded".into()));
                }
                for _ in 0..len {
                    let v = out[out.len() - distance];
                    out.push(v);
                }
            }
            _ => return Err(InflateError("reserved literal/length symbol".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inflates_fixed_and_stored_blocks() {
        assert_eq!(
            inflate_raw(&[0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00], 100).unwrap(),
            b"hello"
        );
        assert_eq!(
            inflate_raw(&[1, 3, 0, 0xfc, 0xff, b'a', b'b', b'c'], 10).unwrap(),
            b"abc"
        );
    }
    #[test]
    fn inflates_dynamic_huffman_block() {
        let encoded = [
            0xed, 0xcc, 0x41, 0x0a, 0xc2, 0x30, 0x14, 0x84, 0xe1, 0x7d, 0x20, 0x77, 0x78, 0xe7,
            0x10, 0x2a, 0x58, 0xe8, 0xc2, 0x55, 0x41, 0x25, 0xfb, 0xd0, 0x3c, 0x31, 0x92, 0x44,
            0x88, 0xd1, 0xf3, 0x37, 0x68, 0x4f, 0x51, 0xfe, 0x59, 0xce, 0x0c, 0x9f, 0x1b, 0x4f,
            0x07, 0x39, 0xdf, 0xc5, 0xe7, 0xd7, 0xa7, 0x34, 0x39, 0x0e, 0x92, 0x62, 0x8e, 0x4d,
            0x6e, 0x0f, 0x2d, 0xd6, 0x48, 0xcf, 0xd5, 0x7f, 0x75, 0xae, 0x41, 0xeb, 0xf6, 0xb1,
            0x66, 0x4a, 0x6f, 0xfd, 0x6f, 0x17, 0x7d, 0xea, 0xd2, 0x7e, 0x6b, 0xaf, 0x4b, 0xe8,
            0x92, 0x35, 0x0e, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
            0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
            0x12, 0x12, 0x12, 0x12, 0x12, 0x72, 0xbf, 0xe4, 0x0a,
        ];
        let expected = b"VBA: If amount >= limit Then\r\n    SaveOrder amount\r\nElse\r\n    RejectOrder\r\nEnd If\r\n".repeat(100);
        assert_eq!(inflate_raw(&encoded, 9_000).unwrap(), expected);
    }
}
