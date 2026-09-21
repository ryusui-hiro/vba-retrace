//! Conservative evaluator for VBA conditional-compilation directives.

use crate::lexer::is_vba_whitespace;
use crate::model::{Diagnostic, Severity, Span};
use std::collections::{BTreeMap, HashSet};

#[derive(Clone, Debug, Default)]
pub struct PreprocessOptions {
    /// Compile-time constants supplied by the caller. Keys are case-insensitive.
    pub constants: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default)]
pub struct PreprocessResult {
    pub text: String,
    pub diagnostics: Vec<Diagnostic>,
    pub had_unknown_condition: bool,
    pub conditional_constants: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StringCompareMode {
    Binary,
    LocaleDependent,
}

#[derive(Clone, Debug)]
struct Frame {
    parent_active: bool,
    branch_taken: bool,
    active: bool,
    unknown: bool,
    seen_else: bool,
}

pub fn preprocess(
    source_name: &str,
    source: &str,
    options: &PreprocessOptions,
) -> PreprocessResult {
    let string_compare_mode = module_string_compare_mode(source);
    let mut constants = options
        .constants
        .iter()
        .map(|(k, v)| {
            (
                parse_cc_const_name(k).unwrap_or_else(|| canon(k)),
                parse_value(v),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let duplicate_const_names = duplicate_cc_constant_names(source);
    for name in &duplicate_const_names {
        constants.insert(name.clone(), None);
    }
    let mut seen_const_names = HashSet::new();
    let mut frames: Vec<Frame> = Vec::new();
    let mut out = String::with_capacity(source.len());
    let mut diagnostics = Vec::new();
    let mut had_unknown = !duplicate_const_names.is_empty();
    let mut offset = 0usize;
    let mut line_no = 1u32;
    while offset < source.len() {
        let start = offset;
        let start_line = line_no;
        let (end, next_line_no) = logical_line_end(source, start, line_no);
        let source_lines = &source[start..end];
        let first_line = first_physical_line(source, start, end);
        let first_trimmed = first_line.trim_start_matches(is_vba_whitespace);
        let directive_text = first_trimmed
            .starts_with('#')
            .then(|| logical_line_text(source, start, end));
        let directive = directive_text
            .as_deref()
            .map(|text| strip_cc_comment(text.trim()).trim());
        if let Some(directive) = directive {
            let if_expression = directive_keyword_rest(directive, "#If");
            let elseif_expression = directive_keyword_rest(directive, "#ElseIf");
            let const_body = directive_keyword_rest(directive, "#Const");
            let is_else = directive.eq_ignore_ascii_case("#Else");
            let is_end_if = directive_keyword_rest(directive, "#End")
                .is_some_and(|kind| kind.eq_ignore_ascii_case("If"));
            let span = Span {
                start,
                end,
                line: start_line,
                column: (first_line.len() - first_trimmed.len()) as u32 + 1,
            };
            if let Some(expression) = if_expression {
                let parent_active = frames.last().map(|f| f.active).unwrap_or(true);
                let expr = condition_expression(expression);
                let value = if parent_active {
                    eval(expr, &constants, string_compare_mode)
                } else {
                    Some(false)
                };
                let unknown = parent_active && value.is_none();
                if unknown {
                    had_unknown = true;
                    diagnostics.push(diag(
                        source_name,
                        span,
                        "VBA3001",
                        "conditional expression is unknown; all alternatives are retained",
                    ));
                }
                let active = parent_active && value.unwrap_or(true);
                frames.push(Frame {
                    parent_active,
                    branch_taken: value == Some(true),
                    active,
                    unknown,
                    seen_else: false,
                });
            } else if let Some(expression) = elseif_expression {
                if let Some(frame) = frames.last_mut() {
                    if frame.seen_else {
                        diagnostics.push(diag(
                            source_name,
                            span,
                            "VBA3002",
                            "#ElseIf appears after #Else",
                        ));
                        frame.active = false;
                    } else if !frame.parent_active {
                        frame.active = false;
                    } else if frame.unknown {
                        frame.active = true;
                    } else if frame.branch_taken {
                        frame.active = false;
                    } else {
                        let expr = condition_expression(expression);
                        match eval(expr, &constants, string_compare_mode) {
                            Some(v) => {
                                frame.active = v;
                                frame.branch_taken = v;
                            }
                            None => {
                                frame.active = true;
                                frame.unknown = true;
                                had_unknown = true;
                                diagnostics.push(diag(source_name,span,"VBA3001","conditional expression is unknown; all alternatives are retained"));
                            }
                        }
                    }
                } else {
                    diagnostics.push(diag(
                        source_name,
                        span,
                        "VBA3003",
                        "#ElseIf has no matching #If",
                    ));
                }
            } else if is_else {
                if let Some(frame) = frames.last_mut() {
                    if frame.seen_else {
                        diagnostics.push(diag(source_name, span, "VBA3004", "duplicate #Else"));
                        frame.active = false;
                    } else {
                        frame.seen_else = true;
                        frame.active =
                            frame.parent_active && (frame.unknown || !frame.branch_taken);
                        frame.branch_taken = true;
                    }
                } else {
                    diagnostics.push(diag(
                        source_name,
                        span,
                        "VBA3005",
                        "#Else has no matching #If",
                    ));
                }
            } else if is_end_if {
                if frames.pop().is_none() {
                    diagnostics.push(diag(
                        source_name,
                        span,
                        "VBA3006",
                        "#End If has no matching #If",
                    ));
                }
            } else if let Some(body) = const_body {
                if let Some(eq) = body.find('=') {
                    if let Some(name) = parse_cc_const_name(body[..eq].trim()) {
                        if !seen_const_names.insert(name.clone()) {
                            constants.insert(name.clone(), None);
                            had_unknown = true;
                            diagnostics.push(Diagnostic {
                                code: "VBA3011",
                                severity: Severity::Error,
                                message: format!(
                                    "conditional compilation constant '{}' is defined more than once",
                                    name
                                ),
                                source: source_name.into(),
                                span,
                            });
                        } else if duplicate_const_names.contains(&name) {
                            constants.insert(name, None);
                        } else if let Some(value) =
                            eval_value(body[eq + 1..].trim(), &constants, string_compare_mode)
                        {
                            constants.insert(name, Some(value));
                        } else {
                            constants.insert(name, None);
                            had_unknown = true;
                            diagnostics.push(diag(
                                source_name,
                                span,
                                "VBA3007",
                                "#Const expression is not a supported constant expression",
                            ));
                        }
                    } else {
                        diagnostics.push(diag(
                            source_name,
                            span,
                            "VBA3008",
                            "malformed #Const directive name",
                        ));
                    }
                } else {
                    diagnostics.push(diag(
                        source_name,
                        span,
                        "VBA3008",
                        "malformed #Const directive",
                    ));
                }
            } else {
                diagnostics.push(diag(
                    source_name,
                    span,
                    "VBA3009",
                    "unrecognized conditional-compilation directive",
                ));
            }
            out.push_str(&mask_line(source_lines));
        } else {
            let active = frames.last().map(|f| f.active).unwrap_or(true);
            if active {
                out.push_str(source_lines);
            } else {
                out.push_str(&mask_line(source_lines));
            }
        }
        offset = end;
        line_no = next_line_no;
    }
    if !frames.is_empty() {
        had_unknown = true;
        diagnostics.push(Diagnostic {
            code: "VBA3010",
            severity: Severity::Warning,
            message: "conditional-compilation block is not terminated".into(),
            source: source_name.into(),
            span: Span {
                start: source.len(),
                end: source.len(),
                line: count_lines(source),
                column: 1,
            },
        });
    }
    PreprocessResult {
        text: out,
        diagnostics,
        had_unknown_condition: had_unknown,
        conditional_constants: constants
            .into_iter()
            .filter_map(|(name, value)| value.map(|value| (name, display_value(&value))))
            .collect(),
    }
}

fn find_next_line_break(source: &str, start: usize) -> Option<(usize, usize)> {
    let bytes = source.get(start..)?.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'\n' {
            let content_end = if i > 0 && bytes[i - 1] == b'\r' {
                start + i - 1
            } else {
                start + i
            };
            return Some((content_end, start + i + 1));
        } else if b == b'\r' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                return Some((start + i, start + i + 2));
            } else {
                return Some((start + i, start + i + 1));
            }
        }
    }
    None
}

fn count_lines(source: &str) -> u32 {
    if source.is_empty() {
        return 0;
    }
    let mut count = 0;
    let mut cursor = 0;
    while cursor < source.len() {
        count += 1;
        if let Some((_, next_cursor)) = find_next_line_break(source, cursor) {
            cursor = next_cursor;
        } else {
            break;
        }
    }
    count
}

fn logical_line_end(source: &str, start: usize, line_number: u32) -> (usize, u32) {
    let mut cursor = start;
    let mut next_line_number = line_number;
    loop {
        let Some((content_end, next_cursor)) = find_next_line_break(source, cursor) else {
            return (source.len(), next_line_number);
        };
        let physical_line = &source[cursor..content_end];
        next_line_number += 1;
        if line_continuation_marker(physical_line).is_some() {
            cursor = next_cursor;
        } else {
            return (next_cursor, next_line_number);
        }
    }
}

fn first_physical_line(source: &str, start: usize, end: usize) -> &str {
    let slice = &source[..end];
    if let Some((content_end, _)) = find_next_line_break(slice, start) {
        &source[start..content_end]
    } else {
        &source[start..end]
    }
}

fn logical_line_text(source: &str, start: usize, end: usize) -> String {
    let mut text = String::new();
    let mut cursor = start;
    while cursor < end {
        let slice = &source[..end];
        if let Some((content_end, next_cursor)) = find_next_line_break(slice, cursor) {
            let physical_line = &source[cursor..content_end];
            if let Some(marker) = line_continuation_marker(physical_line) {
                text.push_str(&physical_line[..marker]);
            } else {
                text.push_str(physical_line);
            }
            cursor = next_cursor;
        } else {
            text.push_str(&source[cursor..end]);
            cursor = end;
        }
    }
    text
}

fn line_continuation_marker(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut index = 0usize;
    let mut in_string = false;
    let mut statement_start = true;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                if in_string && bytes.get(index + 1) == Some(&b'"') {
                    index += 2;
                    continue;
                }
                in_string = !in_string;
                statement_start = false;
                index += 1;
            }
            b'\'' if !in_string => return None,
            b':' if !in_string => {
                statement_start = true;
                index += 1;
            }
            _ => {
                let character = line[index..].chars().next()?;
                if is_vba_whitespace(character) {
                    index += character.len_utf8();
                    continue;
                }
                if !in_string && statement_start && is_rem_comment_start(line, index) {
                    return None;
                }
                statement_start = false;
                index += character.len_utf8();
            }
        }
    }
    if in_string {
        return None;
    }
    if bytes.last() != Some(&b'_') {
        return None;
    }
    let marker = bytes.len() - 1;
    line[..marker]
        .chars()
        .next_back()
        .is_some_and(is_vba_whitespace)
        .then_some(marker)
}

fn is_rem_comment_start(line: &str, index: usize) -> bool {
    line.get(index..index + 3)
        .is_some_and(|word| word.eq_ignore_ascii_case("rem"))
        && line
            .get(index + 3..)
            .and_then(|rest| rest.chars().next())
            .is_none_or(|next| is_vba_whitespace(next) || next == ':')
}

fn display_value(value: &Value) -> String {
    match value {
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(number) if number.fract() == 0.0 => format!("{number:.0}"),
        Value::Number(number) => number.to_string(),
        Value::ConvertedNumber(number) if number.fract() == 0.0 => format!("{number:.0}"),
        Value::ConvertedNumber(number) => number.to_string(),
        Value::Text(text) => text.clone(),
        Value::Empty => "Empty".into(),
        Value::Null => "Null".into(),
        Value::Nothing => "Nothing".into(),
        Value::Date { canonical, .. } => canonical.clone(),
    }
}

fn diag(source: &str, span: Span, code: &'static str, message: &str) -> Diagnostic {
    Diagnostic {
        code,
        severity: Severity::Warning,
        message: message.into(),
        source: source.into(),
        span,
    }
}
fn canon(s: &str) -> String {
    s.to_lowercase()
}

fn strip_cc_comment(text: &str) -> &str {
    let bytes = text.as_bytes();
    let mut in_string = false;
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'"' if in_string && bytes.get(index + 1) == Some(&b'"') => index += 2,
            b'"' => {
                in_string = !in_string;
                index += 1;
            }
            b'\'' if !in_string => return text[..index].trim_end(),
            _ => index += 1,
        }
    }
    text.trim_end()
}

fn module_string_compare_mode(source: &str) -> StringCompareMode {
    let mut mode = None;
    let mut offset = 0usize;
    while offset < source.len() {
        let (end, _) = logical_line_end(source, offset, 1);
        let first_line = first_physical_line(source, offset, end);
        let trimmed = first_line.trim_start_matches(is_vba_whitespace);
        if trimmed.starts_with('#') {
            offset = end;
            continue;
        }
        let statement_text = if trimmed.to_ascii_lowercase().starts_with("option") {
            logical_line_text(source, offset, end)
        } else {
            trimmed.to_owned()
        };
        let statement = strip_cc_comment(&statement_text).trim();
        let words = statement.split_whitespace().map(canon).collect::<Vec<_>>();
        if words.first().is_some_and(|word| word == "option")
            && words.get(1).is_some_and(|word| word == "compare")
        {
            if mode.is_some() {
                return StringCompareMode::LocaleDependent;
            }
            mode = Some(match words.as_slice() {
                [_, _, value] if value == "binary" => StringCompareMode::Binary,
                [_, _, value] if value == "text" || value == "database" => {
                    StringCompareMode::LocaleDependent
                }
                _ => StringCompareMode::LocaleDependent,
            });
        }
        offset = end;
    }
    mode.unwrap_or(StringCompareMode::Binary)
}

fn parse_cc_const_name(lhs: &str) -> Option<String> {
    let lhs = lhs.trim();
    let candidate = if lhs
        .chars()
        .next_back()
        .is_some_and(|suffix| matches!(suffix, '%' | '&' | '@' | '!' | '#' | '$' | '^'))
    {
        &lhs[..lhs.len() - 1]
    } else {
        lhs
    };
    if candidate
        .chars()
        .next_back()
        .is_some_and(|suffix| matches!(suffix, '%' | '&' | '@' | '!' | '#' | '$' | '^'))
    {
        return None;
    }
    let (tokens, errors) = crate::lexer::lex(candidate, 4);
    if !errors.is_empty() {
        return None;
    }
    let mut identifiers = tokens.iter().filter(|token| {
        !matches!(
            token.kind,
            crate::lexer::TokenKind::Newline | crate::lexer::TokenKind::Eof
        )
    });
    let token = identifiers.next()?;
    (token.kind == crate::lexer::TokenKind::Identifier && identifiers.next().is_none())
        .then(|| canon(&token.text))
}

fn duplicate_cc_constant_names(source: &str) -> HashSet<String> {
    let mut counts = BTreeMap::<String, usize>::new();
    let mut offset = 0usize;
    while offset < source.len() {
        let (end, _) = logical_line_end(source, offset, 1);
        let first_line = first_physical_line(source, offset, end);
        let trimmed = first_line.trim_start_matches(is_vba_whitespace);
        if !trimmed.starts_with('#') {
            offset = end;
            continue;
        }
        let logical_text = logical_line_text(source, offset, end);
        let directive = strip_cc_comment(logical_text.trim()).trim();
        let Some(body) = directive_keyword_rest(directive, "#Const") else {
            offset = end;
            continue;
        };
        let Some(equal) = body.find('=') else {
            offset = end;
            continue;
        };
        let Some(name) = parse_cc_const_name(body[..equal].trim()) else {
            offset = end;
            continue;
        };
        *counts.entry(name).or_default() += 1;
        offset = end;
    }
    counts
        .into_iter()
        .filter_map(|(name, count)| (count > 1).then_some(name))
        .collect()
}

fn directive_keyword_rest<'a>(directive: &'a str, keyword: &str) -> Option<&'a str> {
    let prefix = directive.get(..keyword.len())?;
    if !prefix.eq_ignore_ascii_case(keyword) {
        return None;
    }
    let rest = directive.get(keyword.len()..)?;
    if rest
        .chars()
        .next()
        .is_some_and(|character| !is_vba_whitespace(character))
    {
        return None;
    }
    Some(rest.trim_start_matches(is_vba_whitespace))
}

fn condition_expression(expression: &str) -> &str {
    let end = expression.trim_end_matches(is_vba_whitespace).len();
    if end >= 4 && expression[end - 4..end].eq_ignore_ascii_case("then") {
        let prefix = &expression[..end - 4];
        if prefix.chars().next_back().is_some_and(is_vba_whitespace) {
            return prefix.trim_end_matches(is_vba_whitespace);
        }
    }
    expression.trim()
}
fn mask_line(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    for c in line.chars() {
        if c == '\n' || c == '\r' {
            out.push(c)
        } else {
            out.extend(std::iter::repeat_n(' ', c.len_utf8()));
        }
    }
    out
}

#[derive(Clone, Debug, PartialEq)]
enum Value {
    Bool(bool),
    Number(f64),
    ConvertedNumber(f64),
    Text(String),
    Empty,
    Null,
    Nothing,
    Date { serial: f64, canonical: String },
}
#[derive(Clone, Debug, PartialEq)]
enum Token {
    Value(Value),
    Name(String),
    Op(String),
    Left,
    Right,
}
fn parse_value(text: &str) -> Option<Value> {
    parse_value_depth(text.trim(), 0)
}

fn parse_value_depth(s: &str, depth: usize) -> Option<Value> {
    if depth >= 8 {
        return None;
    }
    if s.to_ascii_lowercase().starts_with("cdate(") && s.ends_with(')') {
        let argument = parse_value_depth(&s[6..s.len() - 1], depth + 1)?;
        return coerce_to_date(argument);
    }
    if s.eq_ignore_ascii_case("true") {
        Some(Value::Bool(true))
    } else if s.eq_ignore_ascii_case("false") {
        Some(Value::Bool(false))
    } else if s.eq_ignore_ascii_case("empty") {
        Some(Value::Empty)
    } else if s.eq_ignore_ascii_case("null") {
        Some(Value::Null)
    } else if s.eq_ignore_ascii_case("nothing") {
        Some(Value::Nothing)
    } else if s.starts_with('#') && s.ends_with('#') && s.len() >= 2 {
        parse_date_literal(&s[1..s.len() - 1])
    } else if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        Some(Value::Text(s[1..s.len() - 1].replace("\"\"", "\"")))
    } else {
        let number = s.parse::<f64>().ok()?;
        (number.is_finite() && number.abs() <= (1u64 << 53) as f64).then_some(Value::Number(number))
    }
}

fn parse_date_literal(text: &str) -> Option<Value> {
    let literal = text.trim();
    if literal.is_empty() {
        return None;
    }
    let (date_text, time_text) = split_date_and_time(literal)?;
    let (year, month, day) = if date_text.trim().is_empty() {
        (1899, 12, 30)
    } else {
        parse_explicit_date(date_text)?
    };
    let (hour, minute, second) = if let Some(time) = time_text {
        parse_time_value(time)?
    } else {
        (0, 0, 0)
    };
    let days = days_from_civil(year, month, day) - days_from_civil(1899, 12, 30);
    let seconds = hour * 3600 + minute * 60 + second;
    let serial = days as f64 + seconds as f64 / 86_400.0;
    let month_name = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ][month as usize - 1];
    let canonical = format!("#{month_name} {day}, {year:04} {hour:02}:{minute:02}:{second:02}#");
    Some(Value::Date { serial, canonical })
}

fn date_serial_bounds() -> (f64, f64) {
    let epoch = days_from_civil(1899, 12, 30);
    (
        (days_from_civil(100, 1, 1) - epoch) as f64,
        (days_from_civil(10_000, 1, 1) - epoch) as f64,
    )
}

fn serial_is_date(serial: f64) -> bool {
    let (minimum, maximum_exclusive) = date_serial_bounds();
    serial.is_finite() && serial >= minimum && serial < maximum_exclusive
}

fn date_from_serial(serial: f64) -> Option<Value> {
    serial_is_date(serial).then(|| Value::Date {
        serial,
        canonical: format!("CDate({serial})"),
    })
}

/// Return the VBA date serial for an already parsed date literal/text. This
/// deliberately reuses the conservative English/explicit-date parser used by
/// conditional compilation; locale-dependent strings remain unresolved.
pub(crate) fn date_text_serial(text: &str) -> Option<f64> {
    let text = text.trim();
    let text = text
        .strip_prefix('#')
        .and_then(|value| value.strip_suffix('#'))
        .unwrap_or(text);
    match parse_date_literal(text)? {
        Value::Date { serial, .. } => Some(serial),
        _ => None,
    }
}

/// Return a bounded VBA date serial for DateSerial-like Gregorian components.
/// Month overflow is normalized as VBA does, while two-digit/ambiguous years
/// are left unresolved by the caller.
pub(crate) fn date_serial_from_components(year: i32, month: i32, day: i32) -> Option<f64> {
    if !(100..=9999).contains(&year) || !(1..=31).contains(&day) {
        return None;
    }
    let month_offset = month.checked_sub(1)?;
    let normalized_year = year.checked_add(month_offset.div_euclid(12))?;
    let normalized_month = month_offset.rem_euclid(12) + 1;
    if !(100..=9999).contains(&normalized_year) {
        return None;
    }
    let epoch = days_from_civil(1899, 12, 30);
    let days = days_from_civil(normalized_year, normalized_month, 1)
        .checked_sub(epoch)?
        .checked_add(i64::from(day - 1))?;
    let serial = days as f64;
    serial_is_date(serial).then_some(serial)
}

/// Add calendar months to a VBA serial while retaining the time fraction.
/// Month-end days are clamped (for example, January 31 plus one month becomes
/// the last day of February), matching the documented DateAdd behavior for
/// the bounded Gregorian subset.
pub(crate) fn date_serial_add_months(serial: f64, months: i64) -> Option<f64> {
    if !serial_is_date(serial) {
        return None;
    }
    let whole_days = serial.floor() as i64;
    let fraction = serial - whole_days as f64;
    let epoch = days_from_civil(1899, 12, 30);
    let (year, month, day) = civil_from_days(epoch.checked_add(whole_days)?)?;
    let month_index = i64::from(year)
        .checked_mul(12)?
        .checked_add(i64::from(month - 1))?
        .checked_add(months)?;
    let normalized_year = month_index.div_euclid(12);
    let normalized_month = month_index.rem_euclid(12) + 1;
    if !(100..=9999).contains(&normalized_year) {
        return None;
    }
    let month_days = days_in_month(normalized_year as i32, normalized_month as i32);
    let normalized_day = i64::from(day).min(i64::from(month_days));
    let normalized_days = days_from_civil(
        normalized_year as i32,
        normalized_month as i32,
        normalized_day as i32,
    )
    .checked_sub(epoch)?;
    let result = normalized_days as f64 + fraction;
    serial_is_date(result).then_some(result)
}

/// Break a bounded VBA serial into Gregorian date/time components for
/// DateDiff/DatePart-style static evaluation.
pub(crate) fn date_components_from_serial(serial: f64) -> Option<(i32, i32, i32, i32, i32, i32)> {
    if !serial_is_date(serial) {
        return None;
    }
    let whole_days = serial.floor() as i64;
    let fraction = serial - whole_days as f64;
    let epoch = days_from_civil(1899, 12, 30);
    let (year, month, day) = civil_from_days(epoch.checked_add(whole_days)?)?;
    let mut seconds = (fraction * 86_400.0).round() as i64;
    if seconds >= 86_400 {
        seconds = 86_399;
    }
    Some((
        year,
        month,
        day,
        i32::try_from(seconds / 3_600).ok()?,
        i32::try_from((seconds % 3_600) / 60).ok()?,
        i32::try_from(seconds % 60).ok()?,
    ))
}

pub(crate) fn days_in_month(year: i32, month: i32) -> i32 {
    match month {
        2 if is_leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn coerce_to_date(value: Value) -> Option<Value> {
    match value {
        date @ Value::Date { .. } => Some(date),
        Value::Number(serial) | Value::ConvertedNumber(serial) => date_from_serial(serial),
        _ => None,
    }
}

fn arithmetic_double(value: &Value) -> Option<f64> {
    match value {
        Value::Date { serial, .. } => Some(*serial),
        Value::Number(number) | Value::ConvertedNumber(number) => Some(*number),
        Value::Empty => Some(0.0),
        _ => None,
    }
}

fn date_serial_for_comparison(value: &Value) -> Option<f64> {
    match value {
        Value::Date { serial, .. } if serial_is_date(*serial) => Some(*serial),
        Value::Number(serial) | Value::ConvertedNumber(serial) if serial_is_date(*serial) => {
            Some(*serial)
        }
        _ => None,
    }
}

fn split_date_and_time(literal: &str) -> Option<(&str, Option<&str>)> {
    if let Some(separator) = literal.find([':', '.']) {
        let hour_start = trailing_decimal_component_start(&literal[..separator])?;
        return Some((
            literal[..hour_start].trim_end(),
            Some(literal[hour_start..].trim()),
        ));
    }
    if let Some(hour_start) = ampm_hour_start(literal) {
        return Some((
            literal[..hour_start].trim_end(),
            Some(literal[hour_start..].trim()),
        ));
    }
    Some((literal, None))
}

fn trailing_decimal_component_start(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let end = text.trim_end().len();
    let mut start = end;
    let mut saw_digit = false;
    while start > 0 {
        let byte = bytes[start - 1];
        if byte.is_ascii_digit() {
            saw_digit = true;
            start -= 1;
        } else if byte == b'.' {
            start -= 1;
        } else {
            break;
        }
    }
    if saw_digit { Some(start) } else { None }
}

fn ampm_hour_start(text: &str) -> Option<usize> {
    let trimmed = text.trim_end();
    let lower = trimmed.to_ascii_lowercase();
    for suffix in ["am", "pm", "a", "p"] {
        let marker_start = lower.len().checked_sub(suffix.len())?;
        if !lower[marker_start..].eq_ignore_ascii_case(suffix) {
            continue;
        }
        let before_marker = &trimmed[..marker_start];
        if before_marker.chars().next_back().is_none_or(|character| {
            !(character.is_ascii_digit()
                || character.is_whitespace()
                || character == ':'
                || character == '.')
        }) {
            continue;
        }
        if let Some(start) = trailing_decimal_component_start(before_marker) {
            return Some(start);
        }
    }
    None
}

fn parse_explicit_date(text: &str) -> Option<(i32, i32, i32)> {
    let components = date_components(text)?;
    if !(2..=3).contains(&components.len()) {
        return None;
    }
    let mut month = None;
    let mut numbers = Vec::new();
    for component in components {
        if let Some(value) = month_number(component) {
            if month.replace(value).is_some() {
                return None;
            }
        } else if component.bytes().all(|byte| byte.is_ascii_digit()) {
            numbers.push(component);
        } else {
            return None;
        }
    }
    let month = month?;
    let (year, day) = match numbers.as_slice() {
        [number] => (explicit_year(number)?, 1),
        [first, second] => {
            let first_year = explicit_year(first);
            let second_year = explicit_year(second);
            match (first_year, second_year) {
                (Some(year), None) => (year, parse_day(second)?),
                (None, Some(year)) => (year, parse_day(first)?),
                _ => return None,
            }
        }
        _ => return None,
    };
    let days_in_month = match month {
        2 if is_leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    (day <= days_in_month).then_some((year, month, day))
}

fn date_components(text: &str) -> Option<Vec<&str>> {
    let bytes = text.as_bytes();
    let mut index = 0usize;
    let mut components = Vec::new();
    while index < bytes.len() {
        while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
            index += 1;
        }
        if index == bytes.len() {
            break;
        }
        let start = index;
        while bytes
            .get(index)
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        {
            index += 1;
        }
        if start == index {
            return None;
        }
        components.push(&text[start..index]);

        let before_space = index;
        while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
            index += 1;
        }
        if index == bytes.len() {
            break;
        }
        if matches!(bytes[index], b'/' | b'-' | b',') {
            index += 1;
            while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
                index += 1;
            }
            if index == bytes.len() {
                return None;
            }
        } else if index == before_space {
            return None;
        }
    }
    Some(components)
}

fn month_number(text: &str) -> Option<i32> {
    [
        ("january", 1),
        ("jan", 1),
        ("february", 2),
        ("feb", 2),
        ("march", 3),
        ("mar", 3),
        ("april", 4),
        ("apr", 4),
        ("may", 5),
        ("june", 6),
        ("jun", 6),
        ("july", 7),
        ("jul", 7),
        ("august", 8),
        ("aug", 8),
        ("september", 9),
        ("sep", 9),
        ("october", 10),
        ("oct", 10),
        ("november", 11),
        ("nov", 11),
        ("december", 12),
        ("dec", 12),
    ]
    .iter()
    .find_map(|(name, month)| text.eq_ignore_ascii_case(name).then_some(*month))
}

fn explicit_year(text: &str) -> Option<i32> {
    if text.len() < 4 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let year = text.parse::<i32>().ok()?;
    (100..=9999).contains(&year).then_some(year)
}

fn parse_day(text: &str) -> Option<i32> {
    let day = text.parse::<i32>().ok()?;
    (1..=31).contains(&day).then_some(day)
}

fn is_leap_year(year: i32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_from_civil(year: i32, month: i32, day: i32) -> i64 {
    let adjusted_year = year - i32::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    (era * 146_097 + day_of_era - 719_468) as i64
}

fn civil_from_days(days: i64) -> Option<(i32, i32, i32)> {
    let shifted = days.checked_add(719_468)?;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524
        - day_of_era / 146_096)
        .div_euclid(365);
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month = (5 * day_of_year + 2).div_euclid(153);
    let day = day_of_year - (153 * month + 2).div_euclid(5) + 1;
    let year = year + i64::from(month >= 10);
    let month = month + if month < 10 { 3 } else { -9 };
    Some((
        i32::try_from(year).ok()?,
        i32::try_from(month).ok()?,
        i32::try_from(day).ok()?,
    ))
}

fn parse_time_value(text: &str) -> Option<(i32, i32, i32)> {
    let trimmed = text.trim();
    let lower = trimmed.to_ascii_lowercase();
    let (time, marker) = [
        ("am", Some(false)),
        ("pm", Some(true)),
        ("a", Some(false)),
        ("p", Some(true)),
    ]
    .into_iter()
    .find_map(|(suffix, marker)| {
        let start = lower.len().checked_sub(suffix.len())?;
        if !lower[start..].eq_ignore_ascii_case(suffix) {
            return None;
        }
        let before = &trimmed[..start];
        before
            .chars()
            .next_back()
            .is_some_and(|character| {
                character.is_ascii_digit()
                    || character.is_whitespace()
                    || character == ':'
                    || character == '.'
            })
            .then_some((before.trim_end(), marker))
    })
    .unwrap_or((trimmed, None));
    let fields = time.split([':', '.']).collect::<Vec<_>>();
    if fields.is_empty() || fields.len() > 3 || (fields.len() == 1 && marker.is_none()) {
        return None;
    }
    let parse_field = |field: &str| {
        let field = field.trim();
        (!field.is_empty() && field.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| field.parse::<i32>().ok())
            .flatten()
    };
    let hour = parse_field(fields[0])?;
    let minute = if let Some(field) = fields.get(1) {
        parse_field(field)?
    } else {
        0
    };
    let second = if let Some(field) = fields.get(2) {
        parse_field(field)?
    } else {
        0
    };
    if !(0..=23).contains(&hour) || !(0..=59).contains(&minute) || !(0..=59).contains(&second) {
        return None;
    }
    let hour = match marker {
        Some(true) if hour <= 11 => hour + 12,
        Some(false) if hour == 12 => 0,
        _ => hour,
    };
    Some((hour, minute, second))
}

fn eval(
    text: &str,
    constants: &BTreeMap<String, Option<Value>>,
    string_compare_mode: StringCompareMode,
) -> Option<bool> {
    truth(&eval_value(text, constants, string_compare_mode)?)
}
fn eval_value(
    text: &str,
    constants: &BTreeMap<String, Option<Value>>,
    string_compare_mode: StringCompareMode,
) -> Option<Value> {
    let mut p = ExprParser {
        tokens: scan(text, constants)?,
        at: 0,
        constants,
        string_compare_mode,
    };
    let value = p.expr(0)?;
    if p.at != p.tokens.len() {
        return None;
    }
    Some(value)
}
fn scan(s: &str, constants: &BTreeMap<String, Option<Value>>) -> Option<Vec<Token>> {
    let mut chars = s.char_indices().peekable();
    let mut out = Vec::new();
    while let Some((i, c)) = chars.next() {
        if is_vba_whitespace(c) {
            continue;
        }
        if c == '"' {
            let mut value = String::new();
            let mut closed = false;
            while let Some((_, x)) = chars.next() {
                if x == '"' {
                    if chars.peek().is_some_and(|(_, n)| *n == '"') {
                        chars.next();
                        value.push('"');
                    } else {
                        closed = true;
                        break;
                    }
                } else {
                    value.push(x);
                }
            }
            if !closed {
                return None;
            }
            out.push(Token::Value(Value::Text(value)));
            continue;
        }
        if c == '#' {
            let mut literal = String::new();
            let mut closed = false;
            for (_, value) in chars.by_ref() {
                if value == '#' {
                    closed = true;
                    break;
                }
                literal.push(value);
            }
            if !closed {
                return None;
            }
            out.push(Token::Value(parse_date_literal(&literal)?));
            continue;
        }
        if c == '&'
            && chars
                .peek()
                .is_some_and(|(_, prefix)| matches!(prefix.to_ascii_lowercase(), 'h' | 'o'))
        {
            let (_, prefix) = chars.next()?;
            let radix = if prefix.eq_ignore_ascii_case(&'h') {
                16
            } else {
                8
            };
            let digit_start = chars.peek()?.0;
            let mut end = digit_start;
            while let Some((at, digit)) = chars.peek() {
                let valid = match radix {
                    16 => digit.is_ascii_hexdigit(),
                    _ => matches!(digit, '0'..='7'),
                };
                if !valid {
                    break;
                }
                end = *at + digit.len_utf8();
                chars.next();
            }
            if end == digit_start {
                return None;
            }
            let value = u64::from_str_radix(&s[digit_start..end], radix).ok()?;
            let suffix = if chars.peek().is_some_and(|(at, _)| *at == end) {
                if let Some(suffix) = numeric_type_suffix(s.as_bytes(), end, true) {
                    chars.next();
                    Some(suffix)
                } else {
                    None
                }
            } else {
                None
            };
            out.push(Token::Value(radix_literal_value(value, suffix, constants)?));
            continue;
        }
        if c.is_ascii_digit() || c == '.' && chars.peek().is_some_and(|(_, x)| x.is_ascii_digit()) {
            let mut end = i + c.len_utf8();
            let mut saw_dot = c == '.';
            while let Some((at, digit)) = chars.peek() {
                if digit.is_ascii_digit() {
                    end = *at + digit.len_utf8();
                    chars.next();
                } else if *digit == '.' && !saw_dot {
                    saw_dot = true;
                    end = *at + 1;
                    chars.next();
                } else {
                    break;
                }
            }
            if chars
                .peek()
                .is_some_and(|(_, exponent)| matches!(exponent, 'e' | 'E' | 'd' | 'D'))
            {
                let (exponent_at, _) = chars.next()?;
                end = exponent_at + 1;
                if chars
                    .peek()
                    .is_some_and(|(_, sign)| matches!(sign, '+' | '-'))
                {
                    end = chars.next()?.0 + 1;
                }
                let digit_start = end;
                while let Some((at, digit)) = chars.peek() {
                    if digit.is_ascii_digit() {
                        end = *at + digit.len_utf8();
                        chars.next();
                    } else {
                        break;
                    }
                }
                if end == digit_start {
                    return None;
                }
            }
            while chars.peek().is_some_and(|(at, _)| *at < end) {
                chars.next();
            }
            let number_text = &s[i..end];
            let normalized_number = number_text.replace(['d', 'D'], "E");
            let number = normalized_number.parse::<f64>().ok()?;
            if !number.is_finite() || number.abs() > (1u64 << 53) as f64 {
                return None;
            }
            let integer_literal = !number_text
                .chars()
                .any(|character| matches!(character, '.' | 'e' | 'E' | 'd' | 'D'));
            let suffix = if chars.peek().is_some_and(|(at, _)| *at == end) {
                if let Some(suffix) = numeric_type_suffix(s.as_bytes(), end, integer_literal) {
                    chars.next();
                    Some(suffix)
                } else {
                    None
                }
            } else {
                None
            };
            out.push(Token::Value(decimal_literal_value(
                number,
                integer_literal,
                suffix,
                constants,
            )?));
            continue;
        }
        if c.is_alphabetic() || c == '_' || c as u32 >= 0x80 {
            let mut name = String::from(c);
            while chars
                .peek()
                .is_some_and(|(_, x)| x.is_alphanumeric() || *x == '_' || *x as u32 >= 0x80)
            {
                name.push(chars.next()?.1);
            }
            if let Some((at, suffix)) = chars.peek().copied()
                && at == i + name.len()
                && (matches!(suffix, '%' | '&' | '!' | '#' | '@' | '$')
                    || suffix == '^' && crate::lexer::is_caret_type_suffix(s.as_bytes(), at, false))
            {
                chars.next();
            }
            let low = canon(&name);
            if matches!(
                low.as_str(),
                "and" | "or" | "xor" | "eqv" | "imp" | "not" | "mod" | "like" | "is"
            ) {
                out.push(Token::Op(low));
            } else if low == "true" {
                out.push(Token::Value(Value::Bool(true)));
            } else if low == "false" {
                out.push(Token::Value(Value::Bool(false)));
            } else if low == "empty" {
                out.push(Token::Value(Value::Empty));
            } else if low == "null" {
                out.push(Token::Value(Value::Null));
            } else if low == "nothing" {
                out.push(Token::Value(Value::Nothing));
            } else {
                out.push(Token::Name(low));
            }
            continue;
        }
        match c {
            '(' => out.push(Token::Left),
            ')' => out.push(Token::Right),
            '=' | '+' | '-' | '*' | '/' | '^' | '\\' | '&' => out.push(Token::Op(c.to_string())),
            '<' | '>' => {
                let op = if chars
                    .peek()
                    .is_some_and(|(_, x)| *x == '=' || c == '<' && *x == '>')
                {
                    let second = chars.next()?.1;
                    format!("{c}{second}")
                } else {
                    c.to_string()
                };
                out.push(Token::Op(op));
            }
            _ => return None,
        }
    }
    Some(out)
}

fn numeric_type_suffix(bytes: &[u8], position: usize, integer_literal: bool) -> Option<char> {
    let suffix = *bytes.get(position)? as char;
    match suffix {
        '%' | '&' if integer_literal => Some(suffix),
        '^' if integer_literal && crate::lexer::is_caret_type_suffix(bytes, position, false) => {
            Some(suffix)
        }
        '!' | '#' | '@' => Some(suffix),
        _ => None,
    }
}

fn decimal_literal_value(
    number: f64,
    integer_literal: bool,
    suffix: Option<char>,
    constants: &BTreeMap<String, Option<Value>>,
) -> Option<Value> {
    match suffix {
        None | Some('#') => Some(Value::Number(number)),
        Some('%') if integer_literal => typed_integer_literal(number, i16::MAX as i64),
        Some('&') if integer_literal => typed_integer_literal(number, i32::MAX as i64),
        Some('^') if integer_literal => {
            if constants
                .get("win64")
                .and_then(Option::as_ref)
                .and_then(truth)
                != Some(true)
            {
                return None;
            }
            typed_integer_literal(number, i64::MAX)
        }
        Some('!') => {
            let value = number as f32;
            value
                .is_finite()
                .then_some(Value::ConvertedNumber(f64::from(value)))
        }
        Some('@') => convert_currency(number),
        _ => None,
    }
}

fn typed_integer_literal(number: f64, maximum: i64) -> Option<Value> {
    let value = integer(number)?;
    (0..=maximum)
        .contains(&value)
        .then_some(Value::ConvertedNumber(value as f64))
}

fn radix_literal_value(
    value: u64,
    suffix: Option<char>,
    constants: &BTreeMap<String, Option<Value>>,
) -> Option<Value> {
    let (signed, typed) = match suffix {
        None => {
            if value <= u16::MAX as u64 {
                (sign_extend_radix(value, 16), false)
            } else if value <= u32::MAX as u64 {
                (sign_extend_radix(value, 32), false)
            } else {
                return None;
            }
        }
        Some('%') if value <= u16::MAX as u64 => (sign_extend_radix(value, 16), true),
        Some('&') if value <= u32::MAX as u64 => (sign_extend_radix(value, 32), true),
        Some('^') => {
            if constants
                .get("win64")
                .and_then(Option::as_ref)
                .and_then(truth)
                != Some(true)
            {
                return None;
            }
            (value as i64, true)
        }
        _ => return None,
    };
    let number = signed as f64;
    if number.abs() > (1u64 << 53) as f64 {
        return None;
    }
    if typed {
        Some(Value::ConvertedNumber(number))
    } else {
        Some(Value::Number(number))
    }
}

fn sign_extend_radix(value: u64, bits: u32) -> i64 {
    let sign_bit = 1u64 << (bits - 1);
    if bits == 64 || value & sign_bit == 0 {
        value as i64
    } else {
        (value as i64) - (1i64 << bits)
    }
}

struct ExprParser<'a> {
    tokens: Vec<Token>,
    at: usize,
    constants: &'a BTreeMap<String, Option<Value>>,
    string_compare_mode: StringCompareMode,
}
impl ExprParser<'_> {
    fn expr(&mut self, min: u8) -> Option<Value> {
        let tok = self.tokens.get(self.at)?.clone();
        self.at += 1;
        let mut left = match tok {
            Token::Value(v) => v,
            Token::Name(n)
                if self.tokens.get(self.at) == Some(&Token::Left) && is_cc_intrinsic(&n) =>
            {
                self.at += 1;
                let argument = self.expr(0)?;
                if self.tokens.get(self.at) != Some(&Token::Right) {
                    return None;
                }
                self.at += 1;
                eval_cc_intrinsic(&n, argument, self.constants)?
            }
            Token::Name(n) => self.constants.get(&n)?.clone()?,
            Token::Left => {
                let v = self.expr(0)?;
                if self.tokens.get(self.at) != Some(&Token::Right) {
                    return None;
                }
                self.at += 1;
                v
            }
            Token::Op(op) if op == "not" => {
                let value = self.expr(6)?;
                apply_unary_not(value)?
            }
            Token::Op(op) if op == "-" => match self.expr(13)? {
                Value::Date { serial, .. } => date_from_serial(-serial)?,
                value => Value::Number(-number(value)?),
            },
            _ => return None,
        };
        loop {
            let Some(Token::Op(op)) = self.tokens.get(self.at) else {
                break;
            };
            let Some(prec) = prec(op) else { break };
            if prec < min {
                break;
            }
            let op = op.clone();
            self.at += 1;
            let right = self.expr(prec + 1)?;
            left = apply(&op, left, right, self.string_compare_mode)?;
        }
        Some(left)
    }
}
fn prec(op: &str) -> Option<u8> {
    Some(match op {
        "imp" => 1,
        "eqv" => 2,
        "xor" => 3,
        "or" => 4,
        "and" => 5,
        "=" | "<>" | "<" | ">" | "<=" | ">=" | "like" | "is" => 7,
        "&" => 8,
        "+" | "-" => 9,
        "\\" => 10,
        "mod" => 11,
        "*" | "/" => 12,
        "^" => 14,
        _ => return None,
    })
}
fn apply(op: &str, a: Value, b: Value, string_compare_mode: StringCompareMode) -> Option<Value> {
    match op {
        "and" | "or" | "xor" | "eqv" | "imp" => {
            if !matches!((&a, &b), (Value::Bool(_), Value::Bool(_))) {
                if matches!(&a, Value::ConvertedNumber(_))
                    || matches!(&b, Value::ConvertedNumber(_))
                {
                    return None;
                }
                let (x, y) = (number(a)?, number(b)?);
                let (x, y) = (integer(x)?, integer(y)?);
                let value = match op {
                    "and" => x & y,
                    "or" => x | y,
                    "xor" => x ^ y,
                    "eqv" => !(x ^ y),
                    _ => !x | y,
                };
                return Some(Value::Number(value as f64));
            }
            let (x, y) = (truth(&a)?, truth(&b)?);
            Some(Value::Bool(match op {
                "and" => x && y,
                "or" => x || y,
                "xor" => x ^ y,
                "eqv" => x == y,
                _ => !x || y,
            }))
        }
        "is" => match (&a, &b) {
            (Value::Nothing, Value::Nothing) => Some(Value::Bool(true)),
            _ => None,
        },
        "like" => match (&a, &b) {
            (Value::Null, _) | (_, Value::Null) => Some(Value::Null),
            (Value::Text(value), Value::Text(pattern)) => {
                if value == pattern && !pattern.chars().any(is_like_pattern_character) {
                    Some(Value::Bool(true))
                } else if string_compare_mode == StringCompareMode::Binary {
                    like_match_ascii(value, pattern).map(Value::Bool)
                } else {
                    None
                }
            }
            _ => None,
        },
        "&" => concatenate(a, b),
        "=" | "<>" | "<" | ">" | "<=" | ">=" => {
            if matches!(&a, Value::Null) || matches!(&b, Value::Null) {
                return Some(Value::Null);
            }
            if matches!(&a, Value::Date { .. }) || matches!(&b, Value::Date { .. }) {
                let left = date_serial_for_comparison(&a)?;
                let right = date_serial_for_comparison(&b)?;
                return Some(Value::Bool(match op {
                    "=" => left == right,
                    "<>" => left != right,
                    "<" => left < right,
                    ">" => left > right,
                    "<=" => left <= right,
                    _ => left >= right,
                }));
            }
            if let (Value::Text(left), Value::Text(right)) = (&a, &b) {
                return compare_strings(op, left, right, string_compare_mode).map(Value::Bool);
            }
            if matches!(&a, Value::ConvertedNumber(_)) || matches!(&b, Value::ConvertedNumber(_)) {
                let (x, y) = (number(a)?, number(b)?);
                if x != y {
                    return None;
                }
                return Some(Value::Bool(matches!(op, "=" | "<=" | ">=")));
            }
            let (x, y) = (number(a)?, number(b)?);
            Some(Value::Bool(match op {
                "=" => x == y,
                "<>" => x != y,
                "<" => x < y,
                ">" => x > y,
                "<=" => x <= y,
                _ => x >= y,
            }))
        }
        "+" | "-" | "*" | "/" | "^" => {
            if let (Value::Text(left), Value::Text(right)) = (&a, &b)
                && op == "+"
            {
                return Some(Value::Text(format!("{left}{right}")));
            }
            if matches!(&a, Value::Date { .. }) || matches!(&b, Value::Date { .. }) {
                if matches!(&a, Value::Null) || matches!(&b, Value::Null) {
                    return Some(Value::Null);
                }
                let left_is_date = matches!(&a, Value::Date { .. });
                let right_is_date = matches!(&b, Value::Date { .. });
                let (left, right) = (arithmetic_double(&a)?, arithmetic_double(&b)?);
                let result = match op {
                    "+" => left + right,
                    "-" => left - right,
                    "*" => left * right,
                    "/" => left / right,
                    _ => left.powf(right),
                };
                if !result.is_finite() {
                    return None;
                }
                if op == "+" || op == "-" && !(left_is_date && right_is_date) {
                    return date_from_serial(result);
                }
                return Some(Value::Number(result));
            }
            if matches!(&a, Value::ConvertedNumber(_)) || matches!(&b, Value::ConvertedNumber(_)) {
                return None;
            }
            if matches!(&a, Value::Null) || matches!(&b, Value::Null) {
                return Some(Value::Null);
            }
            let (x, y) = (number(a)?, number(b)?);
            let v = match op {
                "+" => x + y,
                "-" => x - y,
                "*" => x * y,
                "/" => x / y,
                _ => x.powf(y),
            };
            v.is_finite().then_some(Value::Number(v))
        }
        "\\" | "mod" => {
            if matches!(&a, Value::ConvertedNumber(_)) || matches!(&b, Value::ConvertedNumber(_)) {
                return None;
            }
            if matches!(a, Value::Null) || matches!(b, Value::Null) {
                return Some(Value::Null);
            }
            let (x, y) = (
                coerce_numeric_to_long(number(a)?)?,
                coerce_numeric_to_long(number(b)?)?,
            );
            let value = if op == "\\" {
                x.checked_div(y)?
            } else {
                x.checked_rem(y)?.checked_abs()?
            };
            Some(Value::Number(value as f64))
        }
        _ => None,
    }
}
fn concatenate(left: Value, right: Value) -> Option<Value> {
    match (left, right) {
        (Value::Null, Value::Null) => Some(Value::Null),
        (Value::Text(left), Value::Text(right)) => Some(Value::Text(left + &right)),
        (Value::Text(value), Value::Empty | Value::Null)
        | (Value::Empty | Value::Null, Value::Text(value)) => Some(Value::Text(value)),
        (Value::Empty | Value::Null, Value::Empty | Value::Null) => {
            Some(Value::Text(String::new()))
        }
        _ => None,
    }
}

fn compare_strings(op: &str, left: &str, right: &str, mode: StringCompareMode) -> Option<bool> {
    let ordering = if left == right {
        std::cmp::Ordering::Equal
    } else if mode == StringCompareMode::Binary && left.is_ascii() && right.is_ascii() {
        left.as_bytes().cmp(right.as_bytes())
    } else {
        return None;
    };
    Some(match op {
        "=" => ordering.is_eq(),
        "<>" => !ordering.is_eq(),
        "<" => ordering.is_lt(),
        ">" => ordering.is_gt(),
        "<=" => !ordering.is_gt(),
        ">=" => !ordering.is_lt(),
        _ => return None,
    })
}

fn is_like_pattern_character(value: char) -> bool {
    matches!(value, '?' | '#' | '*' | '[')
}

#[derive(Clone, Debug)]
enum LikePatternElement {
    Literal(u8),
    AnyOne,
    Digit,
    AnySequence,
    CharacterList {
        negated: bool,
        ranges: Vec<(u8, u8)>,
    },
}

pub(crate) fn like_match_ascii(value: &str, pattern: &str) -> Option<bool> {
    const MAX_PATTERN_MATCH_CELLS: usize = 250_000;
    if !value.is_ascii() || !pattern.is_ascii() {
        return None;
    }
    let maximum_cells = pattern
        .len()
        .checked_add(1)?
        .checked_mul(value.len().checked_add(1)?)?;
    if maximum_cells > MAX_PATTERN_MATCH_CELLS {
        return None;
    }
    let elements = parse_like_pattern(pattern.as_bytes())?;
    let cells = elements
        .len()
        .checked_add(1)?
        .checked_mul(value.len().checked_add(1)?)?;
    if cells > MAX_PATTERN_MATCH_CELLS {
        return None;
    }

    let bytes = value.as_bytes();
    let mut matched = vec![false; bytes.len() + 1];
    matched[0] = true;
    for element in elements {
        let mut next = vec![false; bytes.len() + 1];
        if matches!(element, LikePatternElement::AnySequence) {
            next[0] = matched[0];
            for index in 1..=bytes.len() {
                next[index] = matched[index] || next[index - 1];
            }
        } else {
            for (index, byte) in bytes.iter().enumerate() {
                if matched[index] && element.matches(*byte) {
                    next[index + 1] = true;
                }
            }
        }
        matched = next;
    }
    Some(matched[bytes.len()])
}

impl LikePatternElement {
    fn matches(&self, value: u8) -> bool {
        match self {
            Self::Literal(expected) => value == *expected,
            Self::AnyOne => true,
            Self::Digit => value.is_ascii_digit(),
            Self::AnySequence => true,
            Self::CharacterList { negated, ranges } => {
                let contained = ranges
                    .iter()
                    .any(|(start, end)| (*start..=*end).contains(&value));
                contained != *negated
            }
        }
    }
}

fn parse_like_pattern(pattern: &[u8]) -> Option<Vec<LikePatternElement>> {
    let mut elements = Vec::new();
    let mut index = 0usize;
    while index < pattern.len() {
        match pattern[index] {
            b'?' => {
                elements.push(LikePatternElement::AnyOne);
                index += 1;
            }
            b'#' => {
                elements.push(LikePatternElement::Digit);
                index += 1;
            }
            b'*' => {
                elements.push(LikePatternElement::AnySequence);
                index += 1;
            }
            b'[' => {
                let close = pattern[index + 1..].iter().position(|byte| *byte == b']')? + index + 1;
                let body = &pattern[index + 1..close];
                if !body.is_empty() {
                    elements.push(parse_like_character_list(body)?);
                }
                index = close + 1;
            }
            byte => {
                elements.push(LikePatternElement::Literal(byte));
                index += 1;
            }
        }
    }
    Some(elements)
}

fn parse_like_character_list(body: &[u8]) -> Option<LikePatternElement> {
    let mut index = 0usize;
    let negated = body.first() == Some(&b'!');
    if negated {
        index += 1;
    }
    let mut ranges = Vec::new();
    if body.get(index) == Some(&b'-') {
        ranges.push((b'-', b'-'));
        index += 1;
    }
    while index < body.len() {
        if body[index] == b'-' {
            if index + 1 != body.len() {
                return None;
            }
            ranges.push((b'-', b'-'));
            index += 1;
            continue;
        }
        let start = body[index];
        if index + 2 < body.len() && body[index + 1] == b'-' {
            let end = body[index + 2];
            if start > end || end == b'-' {
                return None;
            }
            ranges.push((start, end));
            index += 3;
        } else {
            ranges.push((start, start));
            index += 1;
        }
    }
    (!ranges.is_empty() || negated).then_some(LikePatternElement::CharacterList { negated, ranges })
}

fn apply_unary_not(value: Value) -> Option<Value> {
    match value {
        Value::Bool(value) => Some(Value::Bool(!value)),
        Value::Null => Some(Value::Null),
        Value::Empty => Some(Value::Number(-1.0)),
        Value::ConvertedNumber(_) => None,
        other => {
            let integral = integer(number(other)?)?;
            Some(Value::Number((!integral) as f64))
        }
    }
}

fn is_cc_intrinsic(name: &str) -> bool {
    matches!(
        name,
        "abs"
            | "cbool"
            | "cbyte"
            | "ccur"
            | "cdate"
            | "cdbl"
            | "cint"
            | "clng"
            | "clnglng"
            | "clngptr"
            | "csng"
            | "cstr"
            | "cvar"
            | "fix"
            | "int"
            | "len"
            | "lenb"
            | "sgn"
    )
}

fn eval_cc_intrinsic(
    name: &str,
    value: Value,
    constants: &BTreeMap<String, Option<Value>>,
) -> Option<Value> {
    if name == "cvar" {
        return Some(value);
    }
    if name == "cdate" {
        return coerce_to_date(value);
    }
    if name == "lenb" {
        return match value {
            Value::Text(text) => {
                let bytes = text.encode_utf16().count().checked_mul(2)?;
                (bytes <= i32::MAX as usize).then_some(Value::ConvertedNumber(bytes as f64))
            }
            Value::Null => Some(Value::Null),
            _ => None,
        };
    }
    if name == "cstr" {
        return match value {
            Value::Text(text) => Some(Value::Text(text)),
            Value::Empty => Some(Value::Text(String::new())),
            Value::Bool(true) => Some(Value::Text("True".into())),
            Value::Bool(false) => Some(Value::Text("False".into())),
            Value::Number(number) if number.fract() == 0.0 && number >= 0.0 => {
                Some(Value::Text(format!("{number:.0}")))
            }
            Value::ConvertedNumber(number) if number.fract() == 0.0 && number >= 0.0 => {
                Some(Value::Text(format!("{number:.0}")))
            }
            Value::Null
            | Value::Nothing
            | Value::Date { .. }
            | Value::Number(_)
            | Value::ConvertedNumber(_) => None,
        };
    }
    if name == "len" {
        return match value {
            Value::Text(text) => Some(Value::ConvertedNumber(text.encode_utf16().count() as f64)),
            Value::Null => Some(Value::Null),
            _ => None,
        };
    }
    if name == "cbool" {
        return match value {
            Value::Bool(value) => Some(Value::Bool(value)),
            Value::Empty => Some(Value::Bool(false)),
            Value::Number(value) | Value::ConvertedNumber(value) => Some(Value::Bool(value != 0.0)),
            Value::Text(value) if value.eq_ignore_ascii_case("true") => Some(Value::Bool(true)),
            Value::Text(value) if value.eq_ignore_ascii_case("false") => Some(Value::Bool(false)),
            Value::Text(value) if value == "#TRUE#" => Some(Value::Bool(true)),
            Value::Text(value) if value == "#FALSE#" => Some(Value::Bool(false)),
            Value::Text(_) | Value::Null | Value::Nothing | Value::Date { .. } => None,
        };
    }

    let number = number(value)?;
    match name {
        "int" => Some(Value::ConvertedNumber(number.floor())),
        "fix" => Some(Value::ConvertedNumber(number.trunc())),
        "abs" => Some(Value::ConvertedNumber(number.abs())),
        "sgn" => Some(Value::ConvertedNumber(if number < 0.0 {
            -1.0
        } else if number > 0.0 {
            1.0
        } else {
            0.0
        })),
        "cdbl" => Some(Value::ConvertedNumber(number)),
        "csng" => {
            let converted = number as f32;
            (converted.is_finite() && converted as f64 == number)
                .then_some(Value::ConvertedNumber(converted as f64))
        }
        "cbyte" => convert_integral(number, 0, 255),
        "cint" => convert_integral(number, i16::MIN as i64, i16::MAX as i64),
        "clng" => convert_integral(number, i32::MIN as i64, i32::MAX as i64),
        "clnglng" => convert_integral(number, i64::MIN, i64::MAX),
        "clngptr" => {
            let rounded = number.round_ties_even();
            if rounded >= i32::MIN as f64 && rounded <= i32::MAX as f64 {
                convert_integral(number, i32::MIN as i64, i32::MAX as i64)
            } else if constants
                .get("win64")
                .and_then(|value| value.as_ref())
                .and_then(truth)
                == Some(true)
            {
                convert_integral(number, i64::MIN, i64::MAX)
            } else {
                None
            }
        }
        "ccur" => convert_currency(number),
        _ => None,
    }
}

fn convert_integral(number: f64, minimum: i64, maximum: i64) -> Option<Value> {
    let rounded = number.round_ties_even();
    if !rounded.is_finite()
        || rounded < minimum as f64
        || rounded > maximum as f64
        || rounded.abs() > (1u64 << 53) as f64
    {
        return None;
    }
    Some(Value::ConvertedNumber(rounded))
}

fn convert_currency(number: f64) -> Option<Value> {
    let scaled = number * 10_000.0;
    if !scaled.is_finite() || scaled.abs() > (1u64 << 53) as f64 {
        return None;
    }
    // A source value near a half-unit tie may already have lost decimal
    // precision in its f64 representation, so keep that case unresolved.
    let fractional = scaled.fract().abs();
    if (fractional - 0.5).abs() < 1e-9 {
        return None;
    }
    let rounded = scaled.round_ties_even();
    Some(Value::ConvertedNumber(rounded / 10_000.0))
}

pub(crate) fn coerce_numeric_value_to_currency(number: f64) -> Option<f64> {
    match convert_currency(number)? {
        Value::ConvertedNumber(value) => Some(value),
        _ => None,
    }
}

fn number(v: Value) -> Option<f64> {
    match v {
        Value::Number(n) | Value::ConvertedNumber(n) => Some(n),
        Value::Bool(b) => Some(if b { -1.0 } else { 0.0 }),
        Value::Empty => Some(0.0),
        Value::Text(_) | Value::Null | Value::Nothing | Value::Date { .. } => None,
    }
}
fn integer(n: f64) -> Option<i64> {
    let exact_limit = (1u64 << 53) as f64;
    (n.is_finite() && n.fract() == 0.0 && n >= -exact_limit && n <= exact_limit).then_some(n as i64)
}

fn coerce_numeric_to_long(number: f64) -> Option<i64> {
    if !number.is_finite() || number < i32::MIN as f64 || number > i32::MAX as f64 {
        return None;
    }
    let rounded = number.round_ties_even();
    (rounded >= i32::MIN as f64 && rounded <= i32::MAX as f64).then_some(rounded as i64)
}
fn truth(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        Value::Number(n) | Value::ConvertedNumber(n) => Some(*n != 0.0),
        Value::Empty => Some(false),
        Value::Text(_) | Value::Null | Value::Nothing | Value::Date { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selects_known_preprocessor_branch_without_shifting_spans() {
        let source = "#Const UseNew = True\n#If UseNew Then\nPublic Sub NewPath()\nEnd Sub\n#Else\nPublic Sub OldPath()\nEnd Sub\n#End If\n";
        let result = preprocess("M.bas", source, &PreprocessOptions::default());
        assert!(result.diagnostics.is_empty());
        assert!(result.text.contains("Public Sub NewPath"));
        assert!(!result.text.contains("Public Sub OldPath"));
        assert_eq!(result.text.len(), source.len());
    }

    #[test]
    fn evaluates_condition_and_const_directives_across_continuation_lines() {
        let source = "#Const Feature = 1 _\r\n    + 1\r\n#If Feature = 2 _\r\n    And True Then ' continue the directive\r\nSelected = True\r\n#Else\r\nSelected = False\r\n#End If\r\n";
        let result = preprocess("M.bas", source, &PreprocessOptions::default());
        assert!(result.diagnostics.is_empty(), "{:?}", result.diagnostics);
        assert!(!result.had_unknown_condition);
        assert!(result.text.contains("Selected = True"));
        assert!(!result.text.contains("Selected = False"));
        assert_eq!(
            result
                .conditional_constants
                .get("feature")
                .map(String::as_str),
            Some("2")
        );
        assert_eq!(result.text.len(), source.len());
    }

    #[test]
    fn recognizes_fullwidth_whitespace_around_conditional_directive_keywords() {
        let source = "\u{3000}#Const\u{3000}Feature = 1 _\n\u{3000}+ 1\n\u{3000}#If\u{3000}Feature = 2 Then\nSelected = True\n\u{3000}#Else\nSelected = False\n\u{3000}#End\u{3000}If\n";
        let result = preprocess("M.bas", source, &PreprocessOptions::default());
        assert!(result.diagnostics.is_empty(), "{:?}", result.diagnostics);
        assert!(!result.had_unknown_condition);
        assert!(result.text.contains("Selected = True"));
        assert!(!result.text.contains("Selected = False"));
        assert_eq!(result.text.len(), source.len());
    }

    #[test]
    fn duplicate_const_detection_uses_logical_lines_and_rem_comments_do_not_continue() {
        let duplicate_source = "#If False Then\n#Const Feature = 1 _\n + 1\n#Else\n#Const feature = 2\n#End If\n#If Feature = 1 Then\nA = 1\n#Else\nA = 2\n#End If\n";
        let duplicate = preprocess("M.bas", duplicate_source, &PreprocessOptions::default());
        assert!(duplicate.had_unknown_condition);
        assert!(duplicate.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "VBA3011" && diagnostic.severity == Severity::Error
        }));
        assert!(duplicate.text.contains("A = 1"));
        assert!(duplicate.text.contains("A = 2"));

        let rem_comment = "Rem trailing underscore is comment text _\n#If True Then\nA = 1\n#Else\nA = 2\n#End If\n";
        let result = preprocess("M.bas", rem_comment, &PreprocessOptions::default());
        assert!(result.diagnostics.is_empty(), "{:?}", result.diagnostics);
        assert!(!result.text.contains("A = 2"));
        assert_eq!(result.text.len(), rem_comment.len());
    }

    #[test]
    fn line_continuation_requires_whitespace_before_final_underscore() {
        assert_eq!(line_continuation_marker("x = 1 _"), Some(6));
        assert!(line_continuation_marker("x = 1_").is_none());
        assert!(line_continuation_marker("x = 1 _ ").is_none());
        assert!(line_continuation_marker("Rem comment _").is_none());
        assert!(line_continuation_marker("x = \"text _\"").is_none());
    }
    #[test]
    fn retains_all_branches_when_the_environment_is_unknown() {
        let source = "#If Win64 Then\nA = 1\n#Else\nA = 2\n#End If\n";
        let result = preprocess("M.bas", source, &PreprocessOptions::default());
        assert!(result.had_unknown_condition);
        assert!(result.text.contains("A = 1"));
        assert!(result.text.contains("A = 2"));
        assert_eq!(result.diagnostics.len(), 1);
    }
    #[test]
    fn records_effective_source_level_constants() {
        let mut options = PreprocessOptions::default();
        options.constants.insert("Feature".into(), "False".into());
        let result = preprocess("x.bas", "#Const Feature = 1\n", &options);
        assert_eq!(
            result
                .conditional_constants
                .get("feature")
                .map(String::as_str),
            Some("1")
        );
    }

    #[test]
    fn processes_source_constants_even_inside_excluded_blocks_and_ignores_comments() {
        let source = "#If False Then ' disabled\n#Const Hidden& = 7 ' still defines a module constant\n#End If ' close block\n#If Hidden = 7 Then ' use hidden-block constant\nA = 1\n#Else ' unused\nA = 2\n#End If ' close condition\n";
        let result = preprocess("M.bas", source, &PreprocessOptions::default());
        assert!(!result.had_unknown_condition, "{:?}", result.diagnostics);
        assert!(result.diagnostics.is_empty(), "{:?}", result.diagnostics);
        assert!(result.text.contains("A = 1"));
        assert!(!result.text.contains("A = 2"));
        assert_eq!(
            result
                .conditional_constants
                .get("hidden")
                .map(String::as_str),
            Some("7")
        );
    }

    #[test]
    fn duplicate_module_conditional_constants_are_errors_and_keep_alternatives_unknown() {
        let source = "#If False Then\n#Const Feature = 1\n#Else\n#Const feature& = 0\n#End If\n#If Feature Then\nA = 1\n#Else\nA = 2\n#End If\n";
        let result = preprocess("M.bas", source, &PreprocessOptions::default());
        assert!(result.had_unknown_condition);
        assert!(result.text.contains("A = 1"));
        assert!(result.text.contains("A = 2"));
        assert!(result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "VBA3011" && diagnostic.severity == Severity::Error
        }));
    }

    #[test]
    fn strips_apostrophe_comments_without_truncating_quoted_text() {
        assert_eq!(
            strip_cc_comment("#Const Text = \"A'B\" ' comment"),
            "#Const Text = \"A'B\""
        );
        let source = "#Const Enabled = 1 ' comment\n#If Enabled = 1 Then ' comment\nA = 1\n#Else ' comment\nA = 2\n#End If ' comment\n";
        let result = preprocess("M.bas", source, &PreprocessOptions::default());
        assert!(result.text.contains("A = 1"));
        assert!(!result.text.contains("A = 2"));
        assert!(result.diagnostics.is_empty(), "{:?}", result.diagnostics);
    }

    #[test]
    fn evaluates_supported_operators_with_vba_precedence_and_left_associativity() {
        let source = "#If -2 ^ 2 = -4 And 2 ^ 3 ^ 2 = 64 And 5 \\ 2 = 2 And 5 Mod 2 = 1 And &H10 = 16 And 1E3 = 1000 And \"A\" & \"B\" = \"AB\" And \"A\" + \"B\" = \"AB\" And Not 0 And (Not 1) = -2 And Not False And CInt(2.5) = 2 And CInt(3.5) = 4 Then\nSelected = True\n#Else\nSelected = False\n#End If\n";
        let result = preprocess("M.bas", source, &PreprocessOptions::default());
        assert!(!result.had_unknown_condition, "{:?}", result.diagnostics);
        assert!(result.text.contains("Selected = True"));
        assert!(!result.text.contains("Selected = False"));
    }

    #[test]
    fn coerces_mod_and_integer_division_operands_to_long_and_uses_vba_remainder_sign() {
        let source = "#If -8 Mod 3 = 2 And 8 Mod -3 = 2 And -8 Mod -3 = 2 And 5.5 \\ 2 = 3 And -5.5 \\ 2 = -3 And 1.5 Mod 1 = 0 And 2.5 Mod 2 = 0 Then\nSelected = True\n#Else\nSelected = False\n#End If\n";
        let result = preprocess("M.bas", source, &PreprocessOptions::default());
        assert!(!result.had_unknown_condition, "{:?}", result.diagnostics);
        assert!(result.text.contains("Selected = True"));
        assert!(!result.text.contains("Selected = False"));
    }

    #[test]
    fn evaluates_numeric_type_suffixes_and_radix_literal_signs() {
        let source = "#If 1% = 1 And 32767% = 32767 And 1& = 1 And 32768& = 32768 And 1! = 1 And 1# = 1 And 1@ = 1 And 1D3 = 1000 And &H10 = 16 And &H8000 = -32768 And &HFFFF% = -1 And &HFFFF& = 65535 And &HFFFFFFFF = -1 And &HFFFFFFFF& = -1 And &O177777 = -1 And &O37777777777& = -1 Then\nSelected = True\n#Else\nSelected = False\n#End If\n";
        let result = preprocess("M.bas", source, &PreprocessOptions::default());
        assert!(!result.had_unknown_condition, "{:?}", result.diagnostics);
        assert!(result.text.contains("Selected = True"));
        assert!(!result.text.contains("Selected = False"));

        let longlong_source = "#If 1^ = 1 And &HFFFFFFFFFFFFFFFF^ = -1 Then\nSelected = True\n#Else\nSelected = False\n#End If\n";
        let unknown_target = preprocess("M.bas", longlong_source, &PreprocessOptions::default());
        assert!(unknown_target.had_unknown_condition);
        assert!(unknown_target.text.contains("Selected = True"));
        assert!(unknown_target.text.contains("Selected = False"));
        let mut win64 = PreprocessOptions::default();
        win64.constants.insert("Win64".into(), "True".into());
        let known_target = preprocess("M.bas", longlong_source, &win64);
        assert!(
            !known_target.had_unknown_condition,
            "{:?}",
            known_target.diagnostics
        );
        assert!(known_target.text.contains("Selected = True"));
        assert!(!known_target.text.contains("Selected = False"));
    }

    #[test]
    fn retains_branches_for_invalid_or_overflowing_numeric_suffixes() {
        for expression in ["32768% = 32768", "2147483648& = 0", "1.5% = 2"] {
            let source = format!("#If {expression} Then\nA = 1\n#Else\nA = 2\n#End If\n");
            let result = preprocess("M.bas", &source, &PreprocessOptions::default());
            assert!(result.had_unknown_condition, "{expression}");
            assert!(result.text.contains("A = 1"), "{expression}");
            assert!(result.text.contains("A = 2"), "{expression}");
        }
    }

    #[test]
    fn handles_empty_and_nothing_but_retains_null_and_unsupported_patterns_as_unknown() {
        let empty = preprocess(
            "M.bas",
            "#If Empty Then\nA = 1\n#Else\nA = 2\n#End If\n",
            &PreprocessOptions::default(),
        );
        assert!(!empty.text.contains("A = 1"));
        assert!(empty.text.contains("A = 2"));

        let nothing = preprocess(
            "M.bas",
            "#If Nothing Is Nothing Then\nA = 1\n#Else\nA = 2\n#End If\n",
            &PreprocessOptions::default(),
        );
        assert!(nothing.text.contains("A = 1"));
        assert!(!nothing.text.contains("A = 2"));

        for expression in ["Null = Null", "\"abc\" Like \"a[\"", "1 Is 1", "+1"] {
            let source = format!("#If {expression} Then\nA = 1\n#Else\nA = 2\n#End If\n");
            let unknown = preprocess("M.bas", &source, &PreprocessOptions::default());
            assert!(unknown.had_unknown_condition, "{expression}");
            assert!(unknown.text.contains("A = 1"), "{expression}");
            assert!(unknown.text.contains("A = 2"), "{expression}");
        }
    }

    #[test]
    fn evaluates_locale_independent_conditional_intrinsics_on_known_values() {
        let source = "#If Int(-1.2) = -2 And Fix(-1.2) = -1 And Abs(-3) = 3 And Sgn(-3) = -1 And Len(\"A😀\") = 3 And LenB(\"abc\") = 6 And LenB(\"A😀\") = 6 And LenB(\"あ\") = 2 And LenB(\"A\" & \"😀\") = 6 And CByte(2.5) = 2 And CInt(3.5) = 4 And CBool(0) = False And CCur(1.23456) = 1.2346 And CDbl(3) = 3 And CSng(2) = 2 And CStr(\"ok\") = \"ok\" And CVar(9) = 9 Then\nSelected = True\n#Else\nSelected = False\n#End If\n";
        let result = preprocess("M.bas", source, &PreprocessOptions::default());
        assert!(!result.had_unknown_condition, "{:?}", result.diagnostics);
        assert!(result.text.contains("Selected = True"));
        assert!(!result.text.contains("Selected = False"));
    }

    #[test]
    fn evaluates_plus_as_concatenation_for_two_known_string_values_only() {
        let source = "#Const Greeting = \"VBA\" + \" Insight\"\n#If Greeting = \"VBA Insight\" And \"\" + \"x\" = \"x\" Then\nSelected = True\n#Else\nSelected = False\n#End If\n";
        let result = preprocess("M.bas", source, &PreprocessOptions::default());
        assert!(!result.had_unknown_condition, "{:?}", result.diagnostics);
        assert!(result.text.contains("Selected = True"));
        assert!(!result.text.contains("Selected = False"));

        for expression in ["\"A\" + Empty = \"A\"", "\"1\" + 2 = 3"] {
            let source = format!("#If {expression} Then\nA = 1\n#Else\nA = 2\n#End If\n");
            let result = preprocess("M.bas", &source, &PreprocessOptions::default());
            assert!(result.had_unknown_condition, "{expression}");
            assert!(result.text.contains("A = 1"), "{expression}");
            assert!(result.text.contains("A = 2"), "{expression}");
        }
    }

    #[test]
    fn ignores_type_suffixes_on_conditional_constant_references() {
        let source = "#Const ProjectFlag& = 1\n#If ProjectFlag& = 1 And CallerText$ = \"ready\" Then\nSelected = True\n#Else\nSelected = False\n#End If\n";
        let mut options = PreprocessOptions::default();
        options
            .constants
            .insert("CallerText$".into(), "\"ready\"".into());
        let result = preprocess("M.bas", source, &options);
        assert!(!result.had_unknown_condition, "{:?}", result.diagnostics);
        assert!(result.text.contains("Selected = True"));
        assert!(!result.text.contains("Selected = False"));
        assert_eq!(
            result
                .conditional_constants
                .get("projectflag")
                .map(String::as_str),
            Some("1")
        );
    }

    #[test]
    fn string_relations_use_binary_order_only_when_module_collation_is_known() {
        for source in [
            "#If \"A\" < \"a\" Then\nA = 1\n#Else\nA = 2\n#End If\n",
            "Option Compare Binary\n#If \"A\" < \"a\" Then\nA = 1\n#Else\nA = 2\n#End If\n",
        ] {
            let result = preprocess("M.bas", source, &PreprocessOptions::default());
            assert!(!result.had_unknown_condition, "{:?}", result.diagnostics);
            assert!(result.text.contains("A = 1"));
            assert!(!result.text.contains("A = 2"));
        }

        for option in ["Option Compare Text", "Option Compare Database"] {
            let source =
                format!("{option}\n#If \"A\" = \"a\" Then\nA = 1\n#Else\nA = 2\n#End If\n");
            let result = preprocess("M.bas", &source, &PreprocessOptions::default());
            assert!(result.had_unknown_condition, "{option}");
            assert!(result.text.contains("A = 1"), "{option}");
            assert!(result.text.contains("A = 2"), "{option}");
        }

        let same_text = preprocess(
            "M.bas",
            "Option Compare Text\n#If \"same\" = \"same\" Then\nA = 1\n#Else\nA = 2\n#End If\n",
            &PreprocessOptions::default(),
        );
        assert!(!same_text.had_unknown_condition);
        assert!(same_text.text.contains("A = 1"));
        assert!(!same_text.text.contains("A = 2"));
    }

    #[test]
    fn evaluates_ascii_like_wildcards_and_character_lists_in_binary_mode() {
        let source = "Option Compare Binary\n#If \"aBBBa\" Like \"a*a\" And \"a2a\" Like \"a#a\" And \"BAT123khg\" Like \"B?T*\" And \"F\" Like \"[A-Z]\" And \"G\" Like \"[!A-F]\" And \"-\" Like \"[-]\" And \"-\" Like \"[a-]\" And \"[\" Like \"[[]\" And \"]\" Like \"]\" And \"\" Like \"*\" And \"\" Like \"[]\" And \"A\" Like \"A[]\" And \"X\" Like \"[!]\" And Not (\"CAT123khg\" Like \"B?T*\") Then\nSelected = True\n#Else\nSelected = False\n#End If\n";
        let result = preprocess("M.bas", source, &PreprocessOptions::default());
        assert!(!result.had_unknown_condition, "{:?}", result.diagnostics);
        assert!(result.text.contains("Selected = True"));
        assert!(!result.text.contains("Selected = False"));
    }

    #[test]
    fn leaves_locale_dependent_non_ascii_and_invalid_like_patterns_unknown() {
        for source in [
            "Option Compare Text\n#If \"abc\" Like \"A*\" Then\nA = 1\n#Else\nA = 2\n#End If\n",
            "Option Compare Database\n#If \"abc\" Like \"a*\" Then\nA = 1\n#Else\nA = 2\n#End If\n",
            "Option Compare Binary\n#If \"é\" Like \"*\" Then\nA = 1\n#Else\nA = 2\n#End If\n",
            "Option Compare Binary\n#If \"abc\" Like \"a[\" Then\nA = 1\n#Else\nA = 2\n#End If\n",
        ] {
            let result = preprocess("M.bas", source, &PreprocessOptions::default());
            assert!(result.had_unknown_condition, "{source}");
            assert!(result.text.contains("A = 1"), "{source}");
            assert!(result.text.contains("A = 2"), "{source}");
        }
    }

    #[test]
    fn like_matching_is_capped_before_pattern_token_allocation() {
        let pattern = "a".repeat(250_000);
        assert!(like_match_ascii("", &pattern).is_none());
    }

    #[test]
    fn evaluates_only_explicit_english_month_date_tokens() {
        let source = "#Const ReleaseDate = #Jan 2 2000#\n#If ReleaseDate = #January 2, 2000# And #2000 February 29# > #Feb 28, 2000# And #1 Mar 2000# = #March 1, 2000# And CallerDate = #Mar 1, 2000# And CallerSerial = #Jan 2, 2000# Then\nSelected = True\n#Else\nSelected = False\n#End If\n";
        let mut options = PreprocessOptions::default();
        options
            .constants
            .insert("CallerDate".into(), "#March 1, 2000#".into());
        options
            .constants
            .insert("CallerSerial".into(), "CDate(36527)".into());
        let result = preprocess("M.bas", source, &options);
        assert!(!result.had_unknown_condition, "{:?}", result.diagnostics);
        assert!(result.text.contains("Selected = True"));
        assert!(!result.text.contains("Selected = False"));
        assert_eq!(
            result
                .conditional_constants
                .get("releasedate")
                .map(String::as_str),
            Some("#January 2, 2000 00:00:00#")
        );
        assert_eq!(
            result
                .conditional_constants
                .get("callerserial")
                .map(String::as_str),
            Some("CDate(36527)")
        );
    }

    #[test]
    fn evaluates_explicit_date_token_times_and_time_only_epoch() {
        let source = "#If #January 2, 2000 12:30 PM# = #2 Jan 2000 12.30.00 p# And #Jan 2 2000 12 AM# < #Jan 2 2000 1:00 AM# And #5 PM# = #17:00# And #5 PM# = #December 30, 1899 17:00# And #Jan 2 2000 13 PM# = #Jan 2 2000 13:00# And CDate(#January 2, 2000#) = #Jan 2 2000# Then\nSelected = True\n#Else\nSelected = False\n#End If\n";
        let result = preprocess("M.bas", source, &PreprocessOptions::default());
        assert!(!result.had_unknown_condition, "{:?}", result.diagnostics);
        assert!(result.text.contains("Selected = True"));
        assert!(!result.text.contains("Selected = False"));
    }

    #[test]
    fn coerces_numeric_serials_to_dates_within_the_vba_date_domain() {
        let source = "#Const SerialDate = CDate(36527)\n#If CDate(0) = #December 30, 1899# And CDate(1) = #December 31, 1899# And CDate(0.5) = #December 30, 1899 12:00# And CDate(-0.5) = #December 29, 1899 12:00# And SerialDate = #January 2, 2000# And #January 2, 2000# = 36527 And CDate(-657434) = #January 1, 0100# And CDate(2958465) = #December 31, 9999# And CDate(CInt(1.5)) = #January 1, 1900# Then\nSelected = True\n#Else\nSelected = False\n#End If\n";
        let result = preprocess("M.bas", source, &PreprocessOptions::default());
        assert!(!result.had_unknown_condition, "{:?}", result.diagnostics);
        assert!(result.text.contains("Selected = True"));
        assert!(!result.text.contains("Selected = False"));
        assert_eq!(
            result
                .conditional_constants
                .get("serialdate")
                .map(String::as_str),
            Some("CDate(36527)")
        );
    }

    #[test]
    fn evaluates_supported_date_arithmetic_and_keeps_overflow_unknown() {
        let source = "#If #January 2, 2000# + 1 = #January 3, 2000# And 1 + #January 2, 2000# = #January 3, 2000# And #January 3, 2000# - #January 2, 2000# = 1 And #January 3, 2000# - 1 = #January 2, 2000# And 36528 - #January 2, 2000# = #December 31, 1899# And #December 31, 1899# - #December 30, 1899# = 1 And #December 31, 1899# * 2 = 2 And #December 31, 1899# / 2 = 0.5 And #December 31, 1899# ^ 2 = 1 And -#December 31, 1899# = #December 29, 1899# And #January 2, 2000# + #December 31, 1899# = #January 3, 2000# And #January 2, 2000# + CInt(1) = #January 3, 2000# And CDate(1.5) - CDate(1) = 0.5 Then\nSelected = True\n#Else\nSelected = False\n#End If\n";
        let result = preprocess("M.bas", source, &PreprocessOptions::default());
        assert!(!result.had_unknown_condition, "{:?}", result.diagnostics);
        assert!(result.text.contains("Selected = True"));
        assert!(!result.text.contains("Selected = False"));

        let source =
            "#If CDate(2958465) + 1 = #December 31, 9999# Then\nA = 1\n#Else\nA = 2\n#End If\n";
        let overflow = preprocess("M.bas", source, &PreprocessOptions::default());
        assert!(overflow.had_unknown_condition);
        assert!(overflow.text.contains("A = 1"));
        assert!(overflow.text.contains("A = 2"));
    }

    #[test]
    fn leaves_ambiguous_or_invalid_date_tokens_unknown() {
        for expression in [
            "#1/2/2000# = #January 2, 2000#",
            "#January 2# = #January 2, 2000#",
            "#January 2, 99# = #January 2, 1999#",
            "#February 29, 1900# = #February 28, 1900#",
            "#January 1, 2000 24:00# = #January 1, 2000#",
            "#January 1, 2000 5# = #January 1, 2000#",
            "CDate(2958466) = #January 1, 10000#",
            "CDate(Null) = CDate(0)",
            "CDate(\"1\") = CDate(1)",
            "CDate(True) = CDate(-1)",
            "#January 1, 2000#",
        ] {
            let source = format!("#If {expression} Then\nA = 1\n#Else\nA = 2\n#End If\n");
            let result = preprocess("M.bas", &source, &PreprocessOptions::default());
            assert!(
                result.had_unknown_condition,
                "{expression}: {:?}",
                result.diagnostics
            );
            assert!(result.text.contains("A = 1"), "{expression}");
            assert!(result.text.contains("A = 2"), "{expression}");
        }
    }

    #[test]
    fn leaves_locale_or_representation_dependent_intrinsics_unknown() {
        for expression in [
            "LenB(1) = 2",
            "LenB(Null) = 0",
            "CDate(\"1\") = CDate(1)",
            "CStr(1.5) = \"1.5\"",
            "CInt(2) + 1 = 3",
        ] {
            let source = format!("#If {expression} Then\nA = 1\n#Else\nA = 2\n#End If\n");
            let result = preprocess("M.bas", &source, &PreprocessOptions::default());
            assert!(result.had_unknown_condition, "{expression}");
            assert!(result.text.contains("A = 1"), "{expression}");
            assert!(result.text.contains("A = 2"), "{expression}");
        }

        let source = "#If CLngPtr(3000000000) = 3000000000 Then\nA = 1\n#Else\nA = 2\n#End If\n";
        let unknown_target = preprocess("M.bas", source, &PreprocessOptions::default());
        assert!(unknown_target.had_unknown_condition);
        let mut win64 = PreprocessOptions::default();
        win64.constants.insert("Win64".into(), "True".into());
        let known_target = preprocess("M.bas", source, &win64);
        assert!(!known_target.had_unknown_condition);
        assert!(known_target.text.contains("A = 1"));
        assert!(!known_target.text.contains("A = 2"));
    }

    #[test]
    fn handles_lone_cr_in_preprocessor_directives() {
        let source = "#Const FOO = 1\r#If FOO = 1\rActive = 1\r#Else\rActive = 2\r#End If\r";
        let result = preprocess("M.bas", source, &PreprocessOptions::default());
        assert!(!result.had_unknown_condition);
        assert!(result.text.contains("Active = 1"));
        assert!(!result.text.contains("Active = 2"));
    }
}
