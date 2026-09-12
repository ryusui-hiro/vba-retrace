//! Conservative evaluator for VBA conditional-compilation directives.

use crate::model::{Diagnostic, Severity, Span};
use std::collections::BTreeMap;

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
    let mut constants = options
        .constants
        .iter()
        .map(|(k, v)| (canon(k), parse_value(v)))
        .collect::<BTreeMap<_, _>>();
    let mut frames: Vec<Frame> = Vec::new();
    let mut out = String::with_capacity(source.len());
    let mut diagnostics = Vec::new();
    let mut had_unknown = false;
    let mut offset = 0usize;
    for (line_no, line) in source.split_inclusive('\n').enumerate() {
        let trimmed = line.trim_start_matches([' ', '\t']);
        let directive = if trimmed.starts_with('#') {
            Some(trimmed.trim_end_matches(['\r', '\n']).trim())
        } else {
            None
        };
        if let Some(directive) = directive {
            let lower = directive.to_ascii_lowercase();
            let span = Span {
                start: offset,
                end: offset + line.len(),
                line: line_no as u32 + 1,
                column: (line.len() - trimmed.len()) as u32 + 1,
            };
            if lower.starts_with("#if ") {
                let parent_active = frames.last().map(|f| f.active).unwrap_or(true);
                let expr = condition_expression(directive, 3);
                let value = if parent_active {
                    eval(expr, &constants)
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
            } else if lower.starts_with("#elseif ") {
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
                        let expr = condition_expression(directive, 7);
                        match eval(expr, &constants) {
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
            } else if lower == "#else" {
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
            } else if lower == "#end if" {
                if frames.pop().is_none() {
                    diagnostics.push(diag(
                        source_name,
                        span,
                        "VBA3006",
                        "#End If has no matching #If",
                    ));
                }
            } else if lower.starts_with("#const ") {
                let body = directive[6..].trim();
                if let Some(eq) = body.find('=') {
                    let name = canon(body[..eq].trim());
                    let value = body[eq + 1..].trim();
                    let active = frames.last().map(|f| f.active).unwrap_or(true);
                    let uncertain = frames.iter().any(|f| f.unknown);
                    if active && !uncertain {
                        if let Some(v) = eval_value(value, &constants) {
                            constants.insert(name, Some(v));
                        } else {
                            constants.remove(&name);
                            had_unknown = true;
                            diagnostics.push(diag(
                                source_name,
                                span,
                                "VBA3007",
                                "#Const expression is not a supported constant expression",
                            ));
                        }
                    } else if active {
                        constants.remove(&name);
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
            out.push_str(&mask_line(line));
        } else {
            let active = frames.last().map(|f| f.active).unwrap_or(true);
            if active {
                out.push_str(line);
            } else {
                out.push_str(&mask_line(line));
            }
        }
        offset += line.len();
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
                line: source.lines().count() as u32,
                column: 1,
            },
        });
    }
    PreprocessResult {
        text: out,
        diagnostics,
        had_unknown_condition: had_unknown,
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
fn condition_expression(directive: &str, prefix: usize) -> &str {
    let expression = directive.get(prefix..).unwrap_or("").trim();
    if expression.to_ascii_lowercase().ends_with(" then") {
        expression[..expression.len() - 5].trim()
    } else {
        expression
    }
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
    Text(String),
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
    let s = text.trim();
    if s.eq_ignore_ascii_case("true") {
        Some(Value::Bool(true))
    } else if s.eq_ignore_ascii_case("false") {
        Some(Value::Bool(false))
    } else if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        Some(Value::Text(s[1..s.len() - 1].replace("\"\"", "\"")))
    } else {
        s.parse::<f64>().ok().map(Value::Number)
    }
}

fn eval(text: &str, constants: &BTreeMap<String, Option<Value>>) -> Option<bool> {
    truth(&eval_value(text, constants)?)
}
fn eval_value(text: &str, constants: &BTreeMap<String, Option<Value>>) -> Option<Value> {
    let mut p = ExprParser {
        tokens: scan(text)?,
        at: 0,
        constants,
    };
    let value = p.expr(0)?;
    if p.at != p.tokens.len() {
        return None;
    }
    Some(value)
}
fn scan(s: &str) -> Option<Vec<Token>> {
    let mut chars = s.char_indices().peekable();
    let mut out = Vec::new();
    while let Some((i, c)) = chars.next() {
        if c.is_whitespace() {
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
        if c.is_ascii_digit() || c == '.' && chars.peek().is_some_and(|(_, x)| x.is_ascii_digit()) {
            let mut end = i + c.len_utf8();
            while let Some((at, x)) = chars.peek() {
                if x.is_ascii_digit() || *x == '.' {
                    end = *at + x.len_utf8();
                    chars.next();
                } else {
                    break;
                }
            }
            out.push(Token::Value(Value::Number(s[i..end].parse().ok()?)));
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
            let low = canon(&name);
            if matches!(
                low.as_str(),
                "and" | "or" | "xor" | "eqv" | "imp" | "not" | "mod"
            ) {
                out.push(Token::Op(low));
            } else if low == "true" {
                out.push(Token::Value(Value::Bool(true)));
            } else if low == "false" {
                out.push(Token::Value(Value::Bool(false)));
            } else {
                out.push(Token::Name(low));
            }
            continue;
        }
        match c {
            '(' => out.push(Token::Left),
            ')' => out.push(Token::Right),
            '=' | '+' | '-' | '*' | '/' => out.push(Token::Op(c.to_string())),
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

struct ExprParser<'a> {
    tokens: Vec<Token>,
    at: usize,
    constants: &'a BTreeMap<String, Option<Value>>,
}
impl ExprParser<'_> {
    fn expr(&mut self, min: u8) -> Option<Value> {
        let tok = self.tokens.get(self.at)?.clone();
        self.at += 1;
        let mut left = match tok {
            Token::Value(v) => v,
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
                let v = self.expr(6)?;
                Value::Bool(!truth(&v)?)
            }
            Token::Op(op) if op == "+" || op == "-" => {
                let v = number(self.expr(7)?)?;
                Value::Number(if op == "-" { -v } else { v })
            }
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
            left = apply(&op, left, right)?;
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
        "=" | "<>" | "<" | ">" | "<=" | ">=" => 6,
        "+" | "-" => 7,
        "*" | "/" | "mod" => 8,
        _ => return None,
    })
}
fn apply(op: &str, a: Value, b: Value) -> Option<Value> {
    match op {
        "and" | "or" | "xor" | "eqv" | "imp" => {
            if !matches!((&a, &b), (Value::Bool(_), Value::Bool(_))) {
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
        "=" | "<>" | "<" | ">" | "<=" | ">=" => {
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
        "+" | "-" | "*" | "/" | "mod" => {
            let (x, y) = (number(a)?, number(b)?);
            let v = match op {
                "+" => x + y,
                "-" => x - y,
                "*" => x * y,
                "/" => x / y,
                _ => x % y,
            };
            v.is_finite().then_some(Value::Number(v))
        }
        _ => None,
    }
}
fn number(v: Value) -> Option<f64> {
    match v {
        Value::Number(n) => Some(n),
        Value::Bool(b) => Some(if b { -1.0 } else { 0.0 }),
        Value::Text(_) => None,
    }
}
fn integer(n: f64) -> Option<i64> {
    (n.is_finite() && n.fract() == 0.0 && n >= i64::MIN as f64 && n < -(i64::MIN as f64))
        .then_some(n as i64)
}
fn truth(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        Value::Number(n) => Some(*n != 0.0),
        Value::Text(_) => None,
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
    fn retains_all_branches_when_the_environment_is_unknown() {
        let source = "#If Win64 Then\nA = 1\n#Else\nA = 2\n#End If\n";
        let result = preprocess("M.bas", source, &PreprocessOptions::default());
        assert!(result.had_unknown_condition);
        assert!(result.text.contains("A = 1"));
        assert!(result.text.contains("A = 2"));
        assert_eq!(result.diagnostics.len(), 1);
    }
}
