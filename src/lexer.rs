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
    pub bracket_delimited: bool,
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
        bracket_delimited: false,
        span: Span {
            start,
            end,
            line: ln,
            column: cl,
        },
    };
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\n' {
            tokens.push(mk(TokenKind::Newline, "\n".into(), i, i + 1, line, col));
            i += 1;
            line += 1;
            col = 1;
            statement_start = true;
            continue;
        }
        if b == b'\r' {
            if bytes.get(i + 1) == Some(&b'\n') {
                i += 1;
                col += 1;
                continue;
            }
            tokens.push(mk(TokenKind::Newline, "\n".into(), i, i + 1, line, col));
            i += 1;
            line += 1;
            col = 1;
            statement_start = true;
            continue;
        }
        let character = source[i..].chars().next().unwrap();
        if is_vba_whitespace(character) {
            i += character.len_utf8();
            col += 1;
            continue;
        }
        if b == b'_'
            && i > 0
            && source[..i]
                .chars()
                .next_back()
                .is_some_and(is_vba_whitespace)
        {
            let mut j = i + 1;
            if j < bytes.len() && bytes[j] == b'\r' {
                if bytes.get(j + 1) == Some(&b'\n') {
                    j += 1;
                }
                i = j + 1;
                line += 1;
                col = 1;
                continue;
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
                && source.as_bytes().get(i + 3).is_none_or(|byte| {
                    *byte == b'\n'
                        || *byte == b':'
                        || source[i + 3..]
                            .chars()
                            .next()
                            .is_some_and(is_vba_whitespace)
                }))
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
            let closing = bytes[i + 1..]
                .iter()
                .position(|&byte| matches!(byte, b'#' | b'\n'));
            if let Some(offset) = closing
                && bytes[i + 1 + offset] == b'#'
            {
                i += offset + 2;
                col += (offset + 2) as u32;
                tokens.push(mk(
                    TokenKind::Date,
                    source[start..i].to_owned(),
                    start,
                    i,
                    ln,
                    cl,
                ));
            } else {
                i += 1;
                col += 1;
                tokens.push(mk(TokenKind::Symbol, "#".into(), start, i, ln, cl));
            }
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
                let mut token = mk(
                    TokenKind::Identifier,
                    source[content_start..end_content].to_owned(),
                    start,
                    i,
                    ln,
                    cl,
                );
                token.bracket_delimited = true;
                tokens.push(token);
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
                let bang_member_access = bytes.get(i) == Some(&b'!')
                    && source
                        .get(i + 1..)
                        .and_then(|tail| tail.chars().next())
                        .is_some_and(|next| is_ident_start(next) || next == '[');
                if i < bytes.len()
                    && !bang_member_access
                    && (matches!(bytes[i], b'%' | b'&' | b'@' | b'!' | b'#' | b'$')
                        || bytes[i] == b'^'
                            && is_caret_type_suffix(bytes, i, is_declaration_line(bytes, start)))
                {
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
    !is_vba_whitespace(c) && (c == '_' || c.is_alphabetic() || c as u32 >= 0x80)
}
fn is_ident_continue(c: char) -> bool {
    is_ident_start(c) || c.is_ascii_digit()
}
// MS-VBAL WSC includes ASCII separators, EOM, DBCS whitespace and Unicode Zs.
// Retain CR here as the second half of a CRLF line terminator.
pub(crate) fn is_vba_whitespace(character: char) -> bool {
    matches!(
        character,
        '\t' | '\r'
            | '\u{0019}'
            | ' '
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{202F}'
            | '\u{205F}'
            | '\u{3000}'
    ) || ('\u{2000}'..='\u{200A}').contains(&character)
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
    if i < bytes.len()
        && (matches!(bytes[i], b'%' | b'&' | b'@' | b'!' | b'#')
            || bytes[i] == b'^' && is_caret_type_suffix(bytes, i, false))
    {
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
    let integer_literal = !bytes[start..i]
        .iter()
        .any(|byte| matches!(byte, b'.' | b'e' | b'E' | b'd' | b'D'));
    if i < bytes.len()
        && (matches!(bytes[i], b'%' | b'&' | b'@' | b'!' | b'#')
            || integer_literal && bytes[i] == b'^' && is_caret_type_suffix(bytes, i, false))
    {
        i += 1;
    }
    i
}

// A caret can be either the LongLong type character or the exponentiation
// operator. Treat it as a suffix only when its following text looks like a
// declaration boundary or expression delimiter; a following operand keeps it
// as an operator (so `2^3` remains exponentiation). Declarations also allow
// `^(` for typed array names and procedure names.
pub(crate) fn is_caret_type_suffix(bytes: &[u8], caret: usize, declaration: bool) -> bool {
    let mut next = caret + 1;
    if next == bytes.len() {
        return true;
    }
    if bytes[next] == b'(' {
        return declaration || bytes.get(next + 1) == Some(&b')');
    }
    if bytes[next] == b'\n' {
        return true;
    }
    if std::str::from_utf8(&bytes[next..])
        .ok()
        .and_then(|text| text.chars().next())
        .is_some_and(is_vba_whitespace)
    {
        while next < bytes.len() {
            let Some(character) = std::str::from_utf8(&bytes[next..])
                .ok()
                .and_then(|text| text.chars().next())
            else {
                break;
            };
            if !is_vba_whitespace(character) {
                break;
            }
            next += character.len_utf8();
        }
        if next == bytes.len() || bytes[next] == b'\n' {
            return true;
        }
        if declaration
            && bytes[next..]
                .get(..2)
                .is_some_and(|word| word.eq_ignore_ascii_case(b"as"))
            && std::str::from_utf8(&bytes[next + 2..])
                .ok()
                .and_then(|text| text.chars().next())
                .is_none_or(is_vba_whitespace)
        {
            return true;
        }
    }
    matches!(
        bytes.get(next),
        Some(
            b',' | b')'
                | b']'
                | b':'
                | b'='
                | b'+'
                | b'-'
                | b'*'
                | b'/'
                | b'\\'
                | b'&'
                | b'<'
                | b'>'
                | b'.'
                | b'!'
        )
    ) || bytes.get(next) == Some(&b'\'')
}

fn is_declaration_line(bytes: &[u8], position: usize) -> bool {
    let line_start = bytes[..position]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |newline| newline + 1);
    let line = String::from_utf8_lossy(&bytes[line_start..position]);
    let line = line
        .trim_start_matches(is_vba_whitespace)
        .to_ascii_lowercase();
    [
        "dim",
        "redim",
        "public",
        "private",
        "friend",
        "global",
        "static",
        "const",
        "type",
        "function",
        "sub",
        "property",
        "declare",
        "byval",
        "byref",
        "optional",
        "paramarray",
    ]
    .iter()
    .any(|keyword| {
        line.strip_prefix(keyword)
            .is_some_and(|tail| tail.chars().next().is_some_and(is_vba_whitespace))
    })
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
    fn underscore_needs_preceding_whitespace_to_continue_a_line() {
        let (tokens, errors) = lex("x +_\n2\nx + _ \n3\ny = 1 _\r\n + 2\n", 100);
        assert!(errors.is_empty());
        assert_eq!(
            tokens
                .iter()
                .filter(|token| token.kind == TokenKind::Identifier && token.text == "_")
                .count(),
            2
        );
        assert_eq!(tokens.iter().filter(|token| token.text == "\n").count(), 5);
    }

    #[test]
    fn recognizes_unicode_vba_whitespace_without_absorbing_it_into_names() {
        let source = "\u{3000}Dim\u{3000}amount^\u{00A0}As LongLong\n";
        let (tokens, errors) = lex(source, 100);
        assert!(errors.is_empty());
        let identifiers = tokens
            .iter()
            .filter(|token| token.kind == TokenKind::Identifier)
            .map(|token| token.text.as_str())
            .collect::<Vec<_>>();
        assert_eq!(identifiers, ["Dim", "amount^", "As", "LongLong"]);
        let amount = tokens.iter().find(|token| token.text == "amount^").unwrap();
        assert_eq!(amount.span.start, 9);
        assert_eq!(amount.span.column, 6);
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

    #[test]
    fn recognizes_longlong_suffix_without_eating_exponentiation() {
        let (tokens, errors) = lex(
            "Dim amount^ As LongLong\nvalue = amount^ + 1^\npower = 2^3 + amount ^ 2\nDim values^(5) As LongLong\n",
            100,
        );
        assert!(errors.is_empty());
        assert!(
            tokens
                .iter()
                .any(|token| token.kind == TokenKind::Identifier && token.text == "amount^")
        );
        assert!(
            tokens
                .iter()
                .any(|token| token.kind == TokenKind::Number && token.text == "1^")
        );
        assert!(
            tokens
                .iter()
                .any(|token| token.kind == TokenKind::Identifier && token.text == "values^")
        );
        assert_eq!(tokens.iter().filter(|token| token.text == "^").count(), 2);
        assert!(
            tokens
                .iter()
                .any(|token| token.kind == TokenKind::Number && token.text == "2")
        );
        assert!(
            tokens
                .iter()
                .any(|token| token.kind == TokenKind::Number && token.text == "3")
        );
        let (decimal_tokens, decimal_errors) = lex("decimal = 1.0^\n", 32);
        assert!(decimal_errors.is_empty());
        assert!(
            decimal_tokens
                .iter()
                .any(|token| token.kind == TokenKind::Number && token.text == "1.0")
        );
        assert!(
            decimal_tokens
                .iter()
                .any(|token| token.kind == TokenKind::Symbol && token.text == "^")
        );
    }

    #[test]
    fn distinguishes_bang_dictionary_access_from_single_type_suffix() {
        let (tokens, errors) = lex(
            "value = records!Customer\nbracketed = records![Order Form]\nsingleValue = amount!\nspaced = records ! Customer\n",
            100,
        );
        assert!(errors.is_empty());
        assert!(tokens.iter().any(|token| {
            token.kind == TokenKind::Identifier && token.text.eq_ignore_ascii_case("amount!")
        }));
        assert_eq!(tokens.iter().filter(|token| token.text == "!").count(), 3);
        assert!(tokens.iter().any(|token| {
            token.kind == TokenKind::Identifier && token.text.eq_ignore_ascii_case("Customer")
        }));
        assert!(tokens.iter().any(|token| {
            token.kind == TokenKind::Identifier
                && token.text == "Order Form"
                && token.bracket_delimited
        }));
    }

    #[test]
    fn distinguishes_date_literals_from_file_number_markers() {
        let (tokens, errors) = lex(
            "dateValue = #1/2/2024#\nGet #1, , record\nOpen path For Input As #fileNo\n",
            100,
        );
        assert!(errors.is_empty());
        assert_eq!(
            tokens
                .iter()
                .filter(|token| token.kind == TokenKind::Date)
                .map(|token| token.text.as_str())
                .collect::<Vec<_>>(),
            vec!["#1/2/2024#"]
        );
        assert_eq!(tokens.iter().filter(|token| token.text == "#").count(), 2);
        assert!(tokens.iter().any(|token| token.text == "record"));
        assert!(tokens.iter().any(|token| token.text == "fileNo"));
    }

    #[test]
    fn handles_lone_cr_line_endings_and_line_continuation() {
        let (tokens, errors) = lex("Sub Foo()\r    x = 1 _\r    + 2\rEnd Sub\r", 100);
        assert!(errors.is_empty());
        let newlines = tokens
            .iter()
            .filter(|t| t.kind == TokenKind::Newline)
            .count();
        assert_eq!(newlines, 3);
    }
}
