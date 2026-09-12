use crate::model::Span;

#[derive(Clone, Debug, PartialEq)]
pub enum TokenKind {
    Identifier,
    Number,
    String,
    Date,
    Symbol,
    Newline,
    Eof,
}

#[derive(Clone, Debug)]
pub struct Token {
    pub kind: TokenKind,
    pub text: String,
    pub span: Span,
}

pub fn lex(source: &str, max_tokens: usize) -> (Vec<Token>, Vec<(Span, String)>) {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut errors = Vec::new();
    let (mut i, mut line, mut col) = (0usize, 1u32, 1u32);
    let mut statement_start = true;
    let mk = |kind, text: String, start, end, ln, cl| Token {
        kind,
        text,
        span: Span {
            start,
            end,
            line: ln,
            column: cl,
        },
    };
    while i < bytes.len() {
        let b = bytes[i];
        if b == b' ' || b == b'\t' || b == b'\r' {
            i += 1;
            col += 1;
            continue;
        }
        if b == b'\n' {
            tokens.push(mk(TokenKind::Newline, "\n".into(), i, i + 1, line, col));
            i += 1;
            line += 1;
            col = 1;
            statement_start = true;
            continue;
        }
        if b == b'_' {
            let mut j = i + 1;
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t' || bytes[j] == b'\r') {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'\n' {
                i = j + 1;
                line += 1;
                col = 1;
                continue;
            }
        }
        if b == b'\''
            || (statement_start
                && source[i..]
                    .get(..3)
                    .is_some_and(|s| s.eq_ignore_ascii_case("rem"))
                && source
                    .as_bytes()
                    .get(i + 3)
                    .is_none_or(|c| c.is_ascii_whitespace() || *c == b'\n' || *c == b':'))
        {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
                col += 1;
            }
            continue;
        }
        let start = i;
        let ln = line;
        let cl = col;
        if b == b'"' {
            i += 1;
            col += 1;
            let mut value = String::new();
            let mut closed = false;
            while i < bytes.len() {
                if bytes[i] == b'"' {
                    if bytes.get(i + 1) == Some(&b'"') {
                        value.push('"');
                        i += 2;
                        col += 2;
                    } else {
                        i += 1;
                        col += 1;
                        closed = true;
                        break;
                    }
                } else if bytes[i] == b'\n' {
                    break;
                } else {
                    let c = source[i..].chars().next().unwrap();
                    value.push(c);
                    i += c.len_utf8();
                    col += 1;
                }
            }
            if !closed {
                errors.push((
                    Span {
                        start,
                        end: i,
                        line: ln,
                        column: cl,
                    },
                    "unterminated string literal".into(),
                ));
            }
            tokens.push(mk(TokenKind::String, value, start, i, ln, cl));
            statement_start = false;
        } else if b == b'#' {
            i += 1;
            col += 1;
            while i < bytes.len() && bytes[i] != b'#' && bytes[i] != b'\n' {
                i += 1;
                col += 1;
            }
            if i < bytes.len() && bytes[i] == b'#' {
                i += 1;
                col += 1;
            }
            tokens.push(mk(
                TokenKind::Date,
                source[start..i].to_owned(),
                start,
                i,
                ln,
                cl,
            ));
            statement_start = false;
        } else if is_ident_start(source[i..].chars().next().unwrap()) || b == b'[' {
            if b == b'[' {
                i += 1;
                col += 1;
                while i < bytes.len() && bytes[i] != b']' && bytes[i] != b'\n' {
                    i += 1;
                    col += 1;
                }
                let content_start = start + 1;
                let end_content = if i < bytes.len() && bytes[i] == b']' {
                    let e = i;
                    i += 1;
                    col += 1;
                    e
                } else {
                    i
                };
                tokens.push(mk(
                    TokenKind::Identifier,
                    source[content_start..end_content].to_owned(),
                    start,
                    i,
                    ln,
                    cl,
                ));
            } else {
                i += source[i..].chars().next().unwrap().len_utf8();
                col += 1;
                while i < bytes.len() {
                    let c = source[i..].chars().next().unwrap();
                    if is_ident_continue(c) {
                        i += c.len_utf8();
                        col += 1;
                    } else {
                        break;
                    }
                }
                if i < bytes.len() && matches!(bytes[i], b'%' | b'&' | b'@' | b'!' | b'#' | b'$') {
                    i += 1;
                    col += 1;
                }
                tokens.push(mk(
                    TokenKind::Identifier,
                    source[start..i].to_owned(),
                    start,
                    i,
                    ln,
                    cl,
                ));
            }
            statement_start = false;
        } else if b == b'&'
            && bytes
                .get(i + 1)
                .is_some_and(|x| matches!(x.to_ascii_lowercase(), b'h' | b'o'))
        {
            if let Some(end) = scan_radix_number(bytes, i) {
                i = end;
                col += (end - start) as u32;
                tokens.push(mk(
                    TokenKind::Number,
                    source[start..i].to_owned(),
                    start,
                    i,
                    ln,
                    cl,
                ));
                statement_start = false;
            } else {
                tokens.push(mk(TokenKind::Symbol, "&".into(), i, i + 1, ln, cl));
                i += 1;
                col += 1;
                statement_start = false;
            }
        } else if b.is_ascii_digit()
            || (b == b'.' && bytes.get(i + 1).is_some_and(u8::is_ascii_digit))
        {
            i = scan_decimal_number(bytes, i);
            col += (i - start) as u32;
            tokens.push(mk(
                TokenKind::Number,
                source[start..i].to_owned(),
                start,
                i,
                ln,
                cl,
            ));
            statement_start = false;
        } else {
            let two = bytes.get(i..i + 2).unwrap_or_default();
            let n = if matches!(two, b"<=" | b">=" | b"<>" | b":=" | b"=>") {
                2
            } else {
                1
            };
            let text = source[i..i + n].to_owned();
            i += n;
            col += n as u32;
            statement_start = text == ":";
            tokens.push(mk(TokenKind::Symbol, text, start, i, ln, cl));
        }
        if tokens.len() >= max_tokens {
            errors.push((
                Span {
                    start: i,
                    end: i,
                    line,
                    column: col,
                },
                "token limit exceeded".into(),
            ));
            break;
        }
    }
    tokens.push(mk(
        TokenKind::Eof,
        String::new(),
        bytes.len(),
        bytes.len(),
        line,
        col,
    ));
    (tokens, errors)
}

fn is_ident_start(c: char) -> bool {
    c == '_' || c.is_alphabetic() || c as u32 >= 0x80
}
fn is_ident_continue(c: char) -> bool {
    is_ident_start(c) || c.is_ascii_digit()
}
fn scan_radix_number(bytes: &[u8], start: usize) -> Option<usize> {
    let radix = match bytes.get(start + 1)?.to_ascii_lowercase() {
        b'h' => 16,
        b'o' => 8,
        _ => return None,
    };
    let mut i = start + 2;
    let digits = i;
    while i < bytes.len()
        && match radix {
            16 => bytes[i].is_ascii_hexdigit(),
            8 => (b'0'..=b'7').contains(&bytes[i]),
            _ => false,
        }
    {
        i += 1;
    }
    if i == digits {
        return None;
    }
    if i < bytes.len() && matches!(bytes[i], b'%' | b'&' | b'@' | b'!' | b'#') {
        i += 1;
    }
    Some(i)
}
fn scan_decimal_number(bytes: &[u8], start: usize) -> usize {
    let mut i = start;
    if bytes.get(i) == Some(&b'.') {
        i += 1;
    }
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if bytes.get(i) == Some(&b'.') {
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
    }
    if i < bytes.len() && matches!(bytes[i], b'e' | b'E' | b'd' | b'D') {
        let exponent = i;
        let mut j = i + 1;
        if matches!(bytes.get(j), Some(b'+' | b'-')) {
            j += 1;
        }
        let digits = j;
        while j < bytes.len() && bytes[j].is_ascii_digit() {
            j += 1;
        }
        if j > digits {
            i = j;
        } else {
            i = exponent;
        }
    }
    if i < bytes.len() && matches!(bytes[i], b'%' | b'&' | b'@' | b'!' | b'#') {
        i += 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn handles_escaped_strings_comments_and_continuation() {
        let (t, e) = lex("x = \"a\"\"b\" ' c\ny = 1 _\n + 2\n", 100);
        assert!(e.is_empty());
        assert_eq!(
            t.iter().find(|x| x.kind == TokenKind::String).unwrap().text,
            "a\"b"
        );
        assert_eq!(t.iter().filter(|x| x.text == "+").count(), 1);
    }
    #[test]
    fn separates_numeric_type_suffixes_radix_literals_and_concat_operators() {
        let (t, e) = lex("a = 1 & 2\nb = &HFF&\nc = 1.5E-3\n", 100);
        assert!(e.is_empty());
        assert_eq!(
            t.iter()
                .filter(|x| x.kind == TokenKind::Number)
                .map(|x| x.text.as_str())
                .collect::<Vec<_>>(),
            vec!["1", "2", "&HFF&", "1.5E-3"]
        );
        assert_eq!(t.iter().filter(|x| x.text == "&").count(), 1);
    }
}
