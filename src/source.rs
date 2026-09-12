use std::fmt;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DecodeError {
    UnsupportedEncoding(String),
    InvalidEncoding(String),
}
impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedEncoding(s) => write!(f, "unsupported source encoding: {s}"),
            Self::InvalidEncoding(s) => write!(f, "invalid source encoding: {s}"),
        }
    }
}
impl std::error::Error for DecodeError {}

pub fn decode_text(bytes: &[u8], code_page: Option<u16>) -> Result<String, DecodeError> {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8(bytes[3..].to_vec())
            .map_err(|_| DecodeError::InvalidEncoding("UTF-8 BOM".into()));
    }
    if bytes.starts_with(&[0xFF, 0xFE]) {
        if (bytes.len() - 2) & 1 != 0 {
            return Err(DecodeError::InvalidEncoding(
                "UTF-16LE odd byte count".into(),
            ));
        }
        let units = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect::<Vec<_>>();
        return String::from_utf16(&units)
            .map_err(|_| DecodeError::InvalidEncoding("UTF-16LE surrogate sequence".into()));
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        if (bytes.len() - 2) & 1 != 0 {
            return Err(DecodeError::InvalidEncoding(
                "UTF-16BE odd byte count".into(),
            ));
        }
        let units = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect::<Vec<_>>();
        return String::from_utf16(&units)
            .map_err(|_| DecodeError::InvalidEncoding("UTF-16BE surrogate sequence".into()));
    }
    if let Some(cp) = code_page {
        if cp == 65001 {
            return String::from_utf8(bytes.to_vec())
                .map_err(|_| DecodeError::InvalidEncoding("UTF-8".into()));
        }
        if cp == 1252 {
            return Ok(bytes.iter().map(|&b| cp1252(b)).collect());
        }
        if bytes.is_ascii() {
            return Ok(bytes.iter().map(|&b| b as char).collect());
        }
        return decode_legacy(bytes, cp);
    }
    String::from_utf8(bytes.to_vec()).map_err(|_| {
        DecodeError::InvalidEncoding("UTF-8 (try an explicit encoding conversion)".into())
    })
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn decode_legacy(bytes: &[u8], cp: u16) -> Result<String, DecodeError> {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_void};
    #[cfg(target_os = "macos")]
    #[link(name = "iconv")]
    unsafe extern "C" {
        fn iconv_open(tocode: *const c_char, fromcode: *const c_char) -> *mut c_void;
        fn iconv(
            cd: *mut c_void,
            inbuf: *mut *mut c_char,
            inbytesleft: *mut usize,
            outbuf: *mut *mut c_char,
            outbytesleft: *mut usize,
        ) -> usize;
        fn iconv_close(cd: *mut c_void) -> i32;
    }
    #[cfg(not(target_os = "macos"))]
    unsafe extern "C" {
        fn iconv_open(tocode: *const c_char, fromcode: *const c_char) -> *mut c_void;
        fn iconv(
            cd: *mut c_void,
            inbuf: *mut *mut c_char,
            inbytesleft: *mut usize,
            outbuf: *mut *mut c_char,
            outbytesleft: *mut usize,
        ) -> usize;
        fn iconv_close(cd: *mut c_void) -> i32;
    }
    let target = CString::new("UTF-8").unwrap();
    let encoding = CString::new(format!("CP{cp}")).unwrap();
    // iconv is only used to decode the workbook's declared legacy code page; no input is executed.
    unsafe {
        let cd = iconv_open(target.as_ptr(), encoding.as_ptr());
        if cd as isize == -1 {
            return Err(DecodeError::UnsupportedEncoding(format!(
                "Windows code page {cp}"
            )));
        }
        let mut out = vec![0u8; bytes.len().saturating_mul(4).saturating_add(16)];
        let mut in_ptr = bytes.as_ptr() as *mut c_char;
        let mut in_left = bytes.len();
        let mut out_ptr = out.as_mut_ptr() as *mut c_char;
        let mut out_left = out.len();
        let rc = iconv(cd, &mut in_ptr, &mut in_left, &mut out_ptr, &mut out_left);
        let flush = if rc == usize::MAX {
            usize::MAX
        } else {
            iconv(
                cd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut out_ptr,
                &mut out_left,
            )
        };
        iconv_close(cd);
        if rc == usize::MAX || flush == usize::MAX || in_left != 0 {
            return Err(DecodeError::InvalidEncoding(format!(
                "Windows code page {cp}"
            )));
        }
        let len = out.len() - out_left;
        out.truncate(len);
        String::from_utf8(out)
            .map_err(|_| DecodeError::InvalidEncoding(format!("Windows code page {cp}")))
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn decode_legacy(_bytes: &[u8], cp: u16) -> Result<String, DecodeError> {
    Err(DecodeError::UnsupportedEncoding(format!(
        "Windows code page {cp} on this platform"
    )))
}

fn cp1252(b: u8) -> char {
    const HIGH: [char; 32] = [
        '€', '\u{81}', '‚', 'ƒ', '„', '…', '†', '‡', 'ˆ', '‰', 'Š', '‹', 'Œ', '\u{8D}', 'Ž',
        '\u{8F}', '\u{90}', '‘', '’', '“', '”', '•', '–', '—', '˜', '™', 'š', '›', 'œ', '\u{9D}',
        'ž', 'Ÿ',
    ];
    if (0x80..=0x9F).contains(&b) {
        HIGH[(b - 0x80) as usize]
    } else {
        char::from(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decodes_boms_and_cp1252() {
        assert_eq!(
            decode_text(&[0xEF, 0xBB, 0xBF, b'h', b'i'], None).unwrap(),
            "hi"
        );
        assert_eq!(decode_text(&[0xFF, 0xFE, 0x41, 0], None).unwrap(), "A");
        assert_eq!(decode_text(&[0x80], Some(1252)).unwrap(), "€");
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn decodes_vba_cp932_using_platform_iconv() {
        assert_eq!(
            decode_text(&[0x93, 0xfa, 0x96, 0x7b, 0x8c, 0xea], Some(932)).unwrap(),
            "日本語"
        );
    }
}
