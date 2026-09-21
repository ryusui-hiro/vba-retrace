//! Bounded, side-effect-free evaluator for a small Excel formula subset.
//!
//! This module is intentionally separate from the workbook extractor.  It
//! never writes cached values back to a workbook and never recursively
//! recalculates a referenced formula cell.  A caller must opt into evaluation
//! and receives an explicit status when a reference, function, locale rule,
//! or resource bound is outside this subset.

use crate::model::WorkbookCellInfo;

#[derive(Clone, Debug, PartialEq)]
pub enum FormulaValue {
    Number(f64),
    String(String),
    Boolean(bool),
    Blank,
    Error(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FormulaEvaluationLimits {
    pub max_tokens: usize,
    pub max_depth: usize,
    pub max_steps: usize,
    pub max_string_bytes: usize,
    pub max_range_cells: usize,
}

impl Default for FormulaEvaluationLimits {
    fn default() -> Self {
        Self {
            max_tokens: 4096,
            max_depth: 64,
            max_steps: 50_000,
            max_string_bytes: 16 * 1024,
            max_range_cells: 100_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct FormulaEvaluation {
    /// `resolved`, `invalid_formula`, `unsupported`, `unresolved_reference`,
    /// or `resource_limit`.
    pub status: String,
    pub value: Option<FormulaValue>,
    /// References visited by the evaluator, retained as evidence even when
    /// the final value is unresolved.
    pub references: Vec<String>,
    pub references_truncated: bool,
    pub steps: usize,
}

/// Evaluate a formula against non-formula worksheet values supplied by the
/// extractor.  `formula` may start with `=`. `current_sheet` is used for
/// unqualified A1 references. Formula cells are deliberately not recalculated:
/// a reference to one produces `unresolved_reference`.
pub fn evaluate_formula(
    formula: &str,
    current_sheet: Option<&str>,
    cells: &[WorkbookCellInfo],
    limits: FormulaEvaluationLimits,
) -> FormulaEvaluation {
    let mut output = FormulaEvaluation {
        status: "invalid_formula".into(),
        value: None,
        references: Vec::new(),
        references_truncated: false,
        steps: 0,
    };
    let text = formula.trim().strip_prefix('=').unwrap_or(formula.trim());
    if text.is_empty() {
        return output;
    }
    let tokens = match tokenize(text, limits.max_tokens) {
        Ok(tokens) => tokens,
        Err(status) => {
            output.status = status.into();
            return output;
        }
    };
    let mut parser = Parser {
        tokens: &tokens,
        position: 0,
        limits,
    };
    let expression = match parser.parse_expression(0, 0) {
        Ok(expression) if parser.at_end() => expression,
        Ok(_) => return output,
        Err(status) => {
            output.status = status.into();
            return output;
        }
    };
    let mut evaluator = Evaluator {
        cells,
        current_sheet,
        limits,
        references: Vec::new(),
        references_truncated: false,
        steps: 0,
    };
    match evaluator.evaluate(&expression, 0) {
        Ok(EvalValue::Scalar(value)) => {
            output.status = "resolved".into();
            output.value = Some(value);
        }
        Ok(EvalValue::Range {
            mut values,
            rows,
            cols,
        }) if rows == 1 && cols == 1 && !values.is_empty() => {
            output.status = "resolved".into();
            output.value = Some(values.swap_remove(0));
        }
        Ok(EvalValue::Range { .. }) => output.status = "unsupported".into(),
        Err(status) => output.status = status.into(),
    }
    output.references = evaluator.references;
    output.references_truncated = evaluator.references_truncated;
    output.steps = evaluator.steps;
    output
}

#[derive(Clone, Debug, PartialEq)]
enum Token {
    Number(f64),
    String(String),
    Ident(String),
    Sheet(String),
    Operator(String),
    LParen,
    RParen,
    Comma,
    Colon,
}

fn tokenize(input: &str, max_tokens: usize) -> Result<Vec<Token>, &'static str> {
    let bytes = input.as_bytes();
    let mut index = 0usize;
    let mut tokens = Vec::new();
    while index < bytes.len() {
        let character = bytes[index] as char;
        if character.is_ascii_whitespace() {
            index += 1;
            continue;
        }
        let token = match character {
            '(' => {
                index += 1;
                Token::LParen
            }
            ')' => {
                index += 1;
                Token::RParen
            }
            ',' | ';' => {
                index += 1;
                Token::Comma
            }
            ':' => {
                index += 1;
                Token::Colon
            }
            '"' => {
                index += 1;
                let mut value = String::new();
                let mut closed = false;
                while index < bytes.len() {
                    if bytes[index] as char == '"' {
                        if bytes.get(index + 1).copied() == Some(b'"') {
                            value.push('"');
                            index += 2;
                        } else {
                            index += 1;
                            closed = true;
                            break;
                        }
                    } else {
                        let Some(next) = input[index..].chars().next() else {
                            break;
                        };
                        value.push(next);
                        index += next.len_utf8();
                    }
                }
                if !closed {
                    return Err("invalid_formula");
                }
                Token::String(value)
            }
            '\'' => {
                index += 1;
                let start = index;
                let mut value = String::new();
                let mut closed = false;
                while index < bytes.len() {
                    if bytes[index] as char == '\'' {
                        if bytes.get(index + 1).copied() == Some(b'\'') {
                            value.push_str(&input[start..index]);
                            value.push('\'');
                            index += 2;
                        } else {
                            value.push_str(&input[start..index]);
                            index += 1;
                            closed = true;
                            break;
                        }
                    } else {
                        index += 1;
                    }
                }
                if !closed {
                    return Err("invalid_formula");
                }
                Token::Sheet(value)
            }
            '+' | '-' | '*' | '/' | '^' | '&' => {
                index += 1;
                Token::Operator(character.to_string())
            }
            '!' => {
                index += 1;
                Token::Operator("!".into())
            }
            '=' | '<' | '>' => {
                let start = index;
                index += 1;
                if index < bytes.len()
                    && (bytes[index] as char == '='
                        || (character == '<' && bytes[index] as char == '>'))
                {
                    index += 1;
                }
                Token::Operator(input[start..index].to_owned())
            }
            _ if character.is_ascii_digit() || character == '.' => {
                let start = index;
                index += 1;
                while index < bytes.len()
                    && ((bytes[index] as char).is_ascii_digit()
                        || matches!(bytes[index] as char, '.' | 'e' | 'E' | '+' | '-'))
                {
                    let candidate = &input[start..=index];
                    if candidate.ends_with('+') || candidate.ends_with('-') {
                        let previous = candidate.as_bytes().get(candidate.len().saturating_sub(2));
                        if !matches!(previous.map(|value| *value as char), Some('e' | 'E')) {
                            break;
                        }
                    }
                    index += 1;
                }
                let value = input[start..index]
                    .parse::<f64>()
                    .map_err(|_| "invalid_formula")?;
                Token::Number(value)
            }
            _ if character.is_ascii_alphanumeric()
                || matches!(character, '_' | '$' | '.' | '[' | ']') =>
            {
                let start = index;
                index += 1;
                while index < bytes.len()
                    && ((bytes[index] as char).is_ascii_alphanumeric()
                        || matches!(bytes[index] as char, '_' | '$' | '.' | '[' | ']'))
                {
                    index += 1;
                }
                Token::Ident(input[start..index].to_owned())
            }
            '#' => {
                let start = index;
                index += 1;
                while index < bytes.len()
                    && !matches!(
                        bytes[index] as char,
                        '(' | ')' | ',' | ';' | ':' | '+' | '-' | '*' | '^' | '&' | '=' | '<' | '>'
                    )
                    && !(bytes[index] as char).is_ascii_whitespace()
                {
                    index += 1;
                }
                Token::Ident(input[start..index].to_owned())
            }
            _ => return Err("unsupported"),
        };
        tokens.push(token);
        if tokens.len() > max_tokens {
            return Err("resource_limit");
        }
    }
    Ok(tokens)
}

#[derive(Clone, Debug, PartialEq)]
enum Expr {
    Value(FormulaValue),
    Reference {
        sheet: Option<String>,
        cell: CellAddress,
        source: String,
    },
    Range {
        sheet: Option<String>,
        first: CellAddress,
        last: CellAddress,
        source: String,
    },
    Unary {
        operator: String,
        value: Box<Expr>,
    },
    Binary {
        left: Box<Expr>,
        operator: String,
        right: Box<Expr>,
    },
    Call {
        name: String,
        arguments: Vec<Expr>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CellAddress {
    row: u32,
    column: u32,
}

struct Parser<'a> {
    tokens: &'a [Token],
    position: usize,
    limits: FormulaEvaluationLimits,
}

impl Parser<'_> {
    fn at_end(&self) -> bool {
        self.position == self.tokens.len()
    }

    fn parse_expression(
        &mut self,
        minimum_precedence: u8,
        depth: usize,
    ) -> Result<Expr, &'static str> {
        if depth >= self.limits.max_depth {
            return Err("resource_limit");
        }
        let mut left = self.parse_unary(depth + 1)?;
        loop {
            let Some(Token::Operator(operator)) = self.tokens.get(self.position) else {
                break;
            };
            let Some(precedence) = operator_precedence(operator) else {
                break;
            };
            if precedence < minimum_precedence {
                break;
            }
            let operator = operator.clone();
            self.position += 1;
            let next_minimum = if operator == "^" {
                precedence
            } else {
                precedence + 1
            };
            let right = self.parse_expression(next_minimum, depth + 1)?;
            left = Expr::Binary {
                left: Box::new(left),
                operator,
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_unary(&mut self, depth: usize) -> Result<Expr, &'static str> {
        if let Some(Token::Operator(operator)) = self.tokens.get(self.position)
            && matches!(operator.as_str(), "+" | "-")
        {
            let operator = operator.clone();
            self.position += 1;
            return Ok(Expr::Unary {
                operator,
                value: Box::new(self.parse_unary(depth + 1)?),
            });
        }
        self.parse_primary(depth + 1)
    }

    fn parse_primary(&mut self, depth: usize) -> Result<Expr, &'static str> {
        if depth >= self.limits.max_depth {
            return Err("resource_limit");
        }
        if matches!(self.tokens.get(self.position), Some(Token::LParen)) {
            self.position += 1;
            let value = self.parse_expression(0, depth + 1)?;
            if !matches!(self.tokens.get(self.position), Some(Token::RParen)) {
                return Err("invalid_formula");
            }
            self.position += 1;
            return Ok(value);
        }
        let token = self
            .tokens
            .get(self.position)
            .cloned()
            .ok_or("invalid_formula")?;
        self.position += 1;
        match token {
            Token::Number(value) => Ok(Expr::Value(FormulaValue::Number(value))),
            Token::String(value) => Ok(Expr::Value(FormulaValue::String(value))),
            Token::Ident(name) | Token::Sheet(name) => {
                if matches!(self.tokens.get(self.position), Some(Token::LParen)) {
                    self.position += 1;
                    let mut arguments = Vec::new();
                    if !matches!(self.tokens.get(self.position), Some(Token::RParen)) {
                        loop {
                            arguments.push(self.parse_expression(0, depth + 1)?);
                            if !matches!(self.tokens.get(self.position), Some(Token::Comma)) {
                                break;
                            }
                            self.position += 1;
                        }
                    }
                    if !matches!(self.tokens.get(self.position), Some(Token::RParen)) {
                        return Err("invalid_formula");
                    }
                    self.position += 1;
                    return Ok(Expr::Call {
                        name: name.to_ascii_lowercase(),
                        arguments,
                    });
                }
                if name.eq_ignore_ascii_case("true") {
                    return Ok(Expr::Value(FormulaValue::Boolean(true)));
                }
                if name.eq_ignore_ascii_case("false") {
                    return Ok(Expr::Value(FormulaValue::Boolean(false)));
                }
                if name.starts_with('#') {
                    return Ok(Expr::Value(FormulaValue::Error(name)));
                }
                let (sheet, cell_name) = if matches!(self.tokens.get(self.position), Some(Token::Operator(operator)) if operator == "!")
                {
                    self.position += 1;
                    (Some(name.clone()), self.next_identifier()?)
                } else {
                    (None, name.clone())
                };
                let first = parse_cell_address(&cell_name).ok_or("unsupported")?;
                if matches!(self.tokens.get(self.position), Some(Token::Colon)) {
                    self.position += 1;
                    let last_name = self.next_identifier()?;
                    let last = parse_cell_address(&last_name).ok_or("unsupported")?;
                    Ok(Expr::Range {
                        sheet: sheet.clone(),
                        first,
                        last,
                        source: if let Some(sheet) = &sheet {
                            format!("{sheet}!{cell_name}:{last_name}")
                        } else {
                            format!("{cell_name}:{last_name}")
                        },
                    })
                } else {
                    Ok(Expr::Reference {
                        sheet,
                        cell: first,
                        source: cell_name,
                    })
                }
            }
            _ => Err("invalid_formula"),
        }
    }

    fn next_identifier(&mut self) -> Result<String, &'static str> {
        match self.tokens.get(self.position).cloned() {
            Some(Token::Ident(value) | Token::Sheet(value)) => {
                self.position += 1;
                Ok(value)
            }
            _ => Err("invalid_formula"),
        }
    }
}

fn operator_precedence(operator: &str) -> Option<u8> {
    Some(match operator {
        "=" | "<>" | "<" | ">" | "<=" | ">=" => 1,
        "&" => 2,
        "+" | "-" => 3,
        "*" | "/" => 4,
        "^" => 5,
        _ => return None,
    })
}

fn parse_cell_address(input: &str) -> Option<CellAddress> {
    let input = input.replace('$', "");
    let input = input.as_str();
    let split = input.find(|character: char| character.is_ascii_digit())?;
    let (letters, digits) = input.split_at(split);
    if letters.is_empty() || digits.is_empty() || !letters.chars().all(|c| c.is_ascii_alphabetic())
    {
        return None;
    }
    let row = digits.parse::<u32>().ok()?;
    if row == 0 {
        return None;
    }
    let mut column = 0u32;
    for character in letters.chars() {
        column = column
            .checked_mul(26)?
            .checked_add((character.to_ascii_uppercase() as u32) - ('A' as u32) + 1)?;
    }
    (row <= 1_048_576 && column > 0 && column <= 16_384).then_some(CellAddress { row, column })
}

fn parse_sheet_and_cell_str(input: &str) -> (Option<String>, String) {
    let trimmed = input.trim();
    if let Some(pos) = trimmed.rfind('!') {
        let sheet_part = &trimmed[..pos];
        let cell_part = &trimmed[pos + 1..];
        let sheet = if sheet_part.starts_with('\'')
            && sheet_part.ends_with('\'')
            && sheet_part.len() >= 2
        {
            sheet_part[1..sheet_part.len() - 1].replace("''", "'")
        } else {
            sheet_part.to_string()
        };
        (Some(sheet), cell_part.to_string())
    } else {
        (None, trimmed.to_string())
    }
}

fn column_to_letters(mut col: u32) -> String {
    let mut s = String::new();
    while col > 0 {
        col -= 1;
        let rem = (col % 26) as u8;
        s.push((b'A' + rem) as char);
        col /= 26;
    }
    s.chars().rev().collect()
}

fn gcd_pair(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

#[derive(Clone, Debug, PartialEq)]
enum EvalValue {
    Scalar(FormulaValue),
    Range {
        values: Vec<FormulaValue>,
        rows: usize,
        cols: usize,
    },
}

impl EvalValue {
    fn into_scalar(self) -> Option<FormulaValue> {
        match self {
            Self::Scalar(value) => Some(value),
            Self::Range { .. } => None,
        }
    }
}

struct Evaluator<'a> {
    cells: &'a [WorkbookCellInfo],
    current_sheet: Option<&'a str>,
    limits: FormulaEvaluationLimits,
    references: Vec<String>,
    references_truncated: bool,
    steps: usize,
}

impl Evaluator<'_> {
    fn evaluate(&mut self, expression: &Expr, depth: usize) -> Result<EvalValue, &'static str> {
        self.steps = self.steps.saturating_add(1);
        if self.steps > self.limits.max_steps || depth >= self.limits.max_depth {
            return Err("resource_limit");
        }
        match expression {
            Expr::Value(value) => Ok(EvalValue::Scalar(value.clone())),
            Expr::Reference {
                sheet,
                cell,
                source,
            } => {
                self.record_reference(source);
                Ok(EvalValue::Scalar(self.lookup(sheet.as_deref(), *cell)?))
            }
            Expr::Range {
                sheet,
                first,
                last,
                source,
            } => {
                self.record_reference(source);
                let row_range = first.row.min(last.row)..=first.row.max(last.row);
                let col_range = first.column.min(last.column)..=first.column.max(last.column);
                let rows = row_range.clone().count();
                let cols = col_range.clone().count();
                let count = rows.saturating_mul(cols);
                if count > self.limits.max_range_cells {
                    return Err("resource_limit");
                }
                let mut values = Vec::with_capacity(count);
                for row in row_range {
                    for column in col_range.clone() {
                        values.push(self.lookup(sheet.as_deref(), CellAddress { row, column })?);
                    }
                }
                Ok(EvalValue::Range { values, rows, cols })
            }
            Expr::Unary { operator, value } => {
                let value = self.eval_scalar(value, depth + 1)?;
                let number = to_number(&value)?;
                Ok(EvalValue::Scalar(FormulaValue::Number(
                    if operator == "-" { -number } else { number },
                )))
            }
            Expr::Binary {
                left,
                operator,
                right,
            } => {
                let left = self.eval_scalar(left, depth + 1)?;
                let right = self.eval_scalar(right, depth + 1)?;
                Ok(EvalValue::Scalar(evaluate_binary(
                    &left,
                    operator,
                    &right,
                    self.limits.max_string_bytes,
                )?))
            }
            Expr::Call { name, arguments } => self.evaluate_call(name, arguments, depth + 1),
        }
    }

    fn scalar(&self, value: EvalValue) -> Result<FormulaValue, &'static str> {
        value.into_scalar().ok_or("unsupported")
    }

    fn eval_scalar(
        &mut self,
        expression: &Expr,
        depth: usize,
    ) -> Result<FormulaValue, &'static str> {
        let value = self.evaluate(expression, depth)?;
        self.scalar(value)
    }

    fn eval_cell_origin(
        &mut self,
        expr: &Expr,
        depth: usize,
    ) -> Result<(Option<String>, CellAddress), &'static str> {
        match expr {
            Expr::Reference { sheet, cell, .. } => Ok((sheet.clone(), *cell)),
            Expr::Range { sheet, first, .. } => Ok((sheet.clone(), *first)),
            Expr::Call { name, arguments } if name == "offset" => {
                if !(3..=5).contains(&arguments.len()) {
                    return Err("unsupported");
                }
                let (sheet, origin) = self.eval_cell_origin(&arguments[0], depth + 1)?;
                let row_offset =
                    to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.trunc() as i64;
                let col_offset =
                    to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?.trunc() as i64;
                let target_row = origin.row as i64 + row_offset;
                let target_col = origin.column as i64 + col_offset;
                if !(1..=1_048_576).contains(&target_row) || !(1..=16_384).contains(&target_col) {
                    return Err("unsupported");
                }
                Ok((
                    sheet,
                    CellAddress {
                        row: target_row as u32,
                        column: target_col as u32,
                    },
                ))
            }
            Expr::Call { name, arguments } if name == "indirect" => {
                if !(1..=2).contains(&arguments.len()) {
                    return Err("unsupported");
                }
                let ref_text = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let (sheet, cell_str) = parse_sheet_and_cell_str(&ref_text);
                let address = parse_cell_address(&cell_str).ok_or("unsupported")?;
                Ok((sheet, address))
            }
            _ => Err("unsupported"),
        }
    }

    fn evaluate_call(
        &mut self,
        name: &str,
        arguments: &[Expr],
        depth: usize,
    ) -> Result<EvalValue, &'static str> {
        match name {
            "if" => {
                if !(2..=3).contains(&arguments.len()) {
                    return Err("unsupported");
                }
                let condition = to_bool(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let branch = if condition {
                    &arguments[1]
                } else {
                    arguments
                        .get(2)
                        .unwrap_or(&Expr::Value(FormulaValue::Blank))
                };
                self.evaluate(branch, depth + 1)
            }
            "and" | "or" => {
                if arguments.is_empty() {
                    return Err("unsupported");
                }
                let mut result = name == "and";
                for argument in arguments {
                    let value = self.evaluate(argument, depth + 1)?;
                    let values = match value {
                        EvalValue::Scalar(value) => vec![value],
                        EvalValue::Range { values, .. } => values,
                    };
                    for value in values {
                        let boolean = to_bool(&value)?;
                        if name == "and" {
                            result &= boolean;
                        } else {
                            result |= boolean;
                        }
                    }
                }
                Ok(EvalValue::Scalar(FormulaValue::Boolean(result)))
            }
            "not" => {
                if arguments.len() != 1 {
                    return Err("unsupported");
                }
                Ok(EvalValue::Scalar(FormulaValue::Boolean(!to_bool(
                    &self.eval_scalar(&arguments[0], depth + 1)?,
                )?)))
            }
            "sum" | "average" | "min" | "max" | "count" | "counta" | "product" => {
                self.evaluate_aggregate(name, arguments, depth + 1)
            }
            "abs" => {
                if arguments.len() != 1 {
                    return Err("unsupported");
                }
                Ok(EvalValue::Scalar(FormulaValue::Number(
                    to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?.abs(),
                )))
            }
            "round" => {
                if !(1..=2).contains(&arguments.len()) {
                    return Err("unsupported");
                }
                let number = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let digits = if arguments.len() == 2 {
                    to_number(&self.eval_scalar(&arguments[1], depth + 1)?)? as i32
                } else {
                    0
                };
                if !(-15..=15).contains(&digits) {
                    return Err("unsupported");
                }
                let factor = 10f64.powi(digits);
                Ok(EvalValue::Scalar(FormulaValue::Number(
                    (number * factor).round() / factor,
                )))
            }
            "roundup" | "rounddown" | "trunc" => {
                if !(1..=2).contains(&arguments.len()) {
                    return Err("unsupported");
                }
                let number = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let digits = if arguments.len() == 2 {
                    to_number(&self.eval_scalar(&arguments[1], depth + 1)?)? as i32
                } else {
                    0
                };
                if !(-15..=15).contains(&digits) {
                    return Err("unsupported");
                }
                let factor = 10f64.powi(digits);
                let rounded = match name {
                    "roundup" => {
                        if number >= 0.0 {
                            (number * factor).ceil() / factor
                        } else {
                            (number * factor).floor() / factor
                        }
                    }
                    "rounddown" | "trunc" => {
                        if number >= 0.0 {
                            (number * factor).floor() / factor
                        } else {
                            (number * factor).ceil() / factor
                        }
                    }
                    _ => unreachable!(),
                };
                Ok(EvalValue::Scalar(FormulaValue::Number(rounded)))
            }
            "true" if arguments.is_empty() => Ok(EvalValue::Scalar(FormulaValue::Boolean(true))),
            "false" if arguments.is_empty() => Ok(EvalValue::Scalar(FormulaValue::Boolean(false))),
            "iferror" if arguments.len() == 2 => match self.eval_scalar(&arguments[0], depth + 1) {
                Ok(FormulaValue::Error(_)) => self.evaluate(&arguments[1], depth + 1),
                Ok(scalar) => Ok(EvalValue::Scalar(scalar)),
                Err(_) => self.evaluate(&arguments[1], depth + 1),
            },
            "isnumber" if arguments.len() == 1 => {
                let val = self.eval_scalar(&arguments[0], depth + 1)?;
                Ok(EvalValue::Scalar(FormulaValue::Boolean(matches!(
                    val,
                    FormulaValue::Number(_)
                ))))
            }
            "isblank" if arguments.len() == 1 => {
                let val = self.eval_scalar(&arguments[0], depth + 1)?;
                Ok(EvalValue::Scalar(FormulaValue::Boolean(matches!(
                    val,
                    FormulaValue::Blank
                ))))
            }
            "iserror" if arguments.len() == 1 => {
                let val = self.eval_scalar(&arguments[0], depth + 1)?;
                Ok(EvalValue::Scalar(FormulaValue::Boolean(matches!(
                    val,
                    FormulaValue::Error(_)
                ))))
            }
            "iserr" if arguments.len() == 1 => {
                let val = self.eval_scalar(&arguments[0], depth + 1)?;
                let is_err = match &val {
                    FormulaValue::Error(s) => !s.eq_ignore_ascii_case("#N/A"),
                    _ => false,
                };
                Ok(EvalValue::Scalar(FormulaValue::Boolean(is_err)))
            }
            "isref" if arguments.len() == 1 => {
                let is_reference =
                    matches!(&arguments[0], Expr::Reference { .. } | Expr::Range { .. })
                        || match &arguments[0] {
                            Expr::Call { name, .. } => {
                                matches!(name.as_str(), "indirect" | "offset" | "index")
                            }
                            _ => false,
                        };
                Ok(EvalValue::Scalar(FormulaValue::Boolean(is_reference)))
            }
            "isna" if arguments.len() == 1 => {
                let val = self.eval_scalar(&arguments[0], depth + 1)?;
                let is_na =
                    matches!(&val, FormulaValue::Error(s) if s.eq_ignore_ascii_case("#N/A"));
                Ok(EvalValue::Scalar(FormulaValue::Boolean(is_na)))
            }
            "na" if arguments.is_empty() => {
                Ok(EvalValue::Scalar(FormulaValue::Error("#N/A".into())))
            }
            "istext" if arguments.len() == 1 => {
                let val = self.eval_scalar(&arguments[0], depth + 1)?;
                Ok(EvalValue::Scalar(FormulaValue::Boolean(matches!(
                    val,
                    FormulaValue::String(_)
                ))))
            }
            "islogical" if arguments.len() == 1 => {
                let val = self.eval_scalar(&arguments[0], depth + 1)?;
                Ok(EvalValue::Scalar(FormulaValue::Boolean(matches!(
                    val,
                    FormulaValue::Boolean(_)
                ))))
            }
            "isnontext" if arguments.len() == 1 => {
                let val = self.eval_scalar(&arguments[0], depth + 1)?;
                Ok(EvalValue::Scalar(FormulaValue::Boolean(!matches!(
                    val,
                    FormulaValue::String(_)
                ))))
            }
            "type" if arguments.len() == 1 => {
                let eval_res = self.evaluate(&arguments[0], depth + 1)?;
                let type_code = match eval_res {
                    EvalValue::Range { .. } => 64.0,
                    EvalValue::Scalar(s) => match s {
                        FormulaValue::Number(_) | FormulaValue::Blank => 1.0,
                        FormulaValue::String(_) => 2.0,
                        FormulaValue::Boolean(_) => 4.0,
                        FormulaValue::Error(_) => 16.0,
                    },
                };
                Ok(EvalValue::Scalar(FormulaValue::Number(type_code)))
            }
            "formulatext" if arguments.len() == 1 => {
                let (sheet, addr) = match self.eval_cell_origin(&arguments[0], depth + 1) {
                    Ok(res) => res,
                    Err(_) => return Ok(EvalValue::Scalar(FormulaValue::Error("#N/A".into()))),
                };
                let effective_sheet = sheet.as_deref().or(self.current_sheet);
                let mut found_formula = None;
                for c in self.cells {
                    let sheet_matches = match (effective_sheet, &c.sheet_name) {
                        (Some(s), target) => s.eq_ignore_ascii_case(target),
                        (None, _) => true,
                    };
                    if sheet_matches && c.row == Some(addr.row) && c.column == Some(addr.column) {
                        if let Some(f) = c.formula.as_deref().filter(|f| !f.trim().is_empty()) {
                            let formatted = if f.starts_with('=') {
                                f.to_string()
                            } else {
                                format!("={f}")
                            };
                            found_formula = Some(formatted);
                        }
                        break;
                    }
                }
                if let Some(f) = found_formula {
                    self.record_reference(&format!(
                        "{}{}",
                        sheet
                            .as_deref()
                            .map(|s| format!("{s}!"))
                            .unwrap_or_default(),
                        column_to_letters(addr.column) + &addr.row.to_string()
                    ));
                    Ok(EvalValue::Scalar(FormulaValue::String(f)))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#N/A".into())))
                }
            }
            "roman" => {
                if !(1..=2).contains(&arguments.len()) {
                    return Err("unsupported");
                }
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?.trunc() as i64;
                Ok(EvalValue::Scalar(to_roman(n)))
            }
            "arabic" if arguments.len() == 1 => {
                let text = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                Ok(EvalValue::Scalar(from_roman(&text)))
            }
            "int" if arguments.len() == 1 => {
                let number = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                Ok(EvalValue::Scalar(FormulaValue::Number(number.floor())))
            }
            "mod" if arguments.len() == 2 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let d = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                if d == 0.0 {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#DIV/0!".into())))
                } else {
                    let r = n - d * (n / d).floor();
                    Ok(EvalValue::Scalar(FormulaValue::Number(r)))
                }
            }
            "sign" if arguments.len() == 1 => {
                let number = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let s = if number > 0.0 {
                    1.0
                } else if number < 0.0 {
                    -1.0
                } else {
                    0.0
                };
                Ok(EvalValue::Scalar(FormulaValue::Number(s)))
            }
            "sqrt" if arguments.len() == 1 => {
                let number = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                if number < 0.0 {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Number(number.sqrt())))
                }
            }
            "power" if arguments.len() == 2 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let p = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                Ok(EvalValue::Scalar(FormulaValue::Number(n.powf(p))))
            }
            "delta" if arguments.len() == 1 || arguments.len() == 2 => {
                let n1 = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let n2 = if arguments.len() == 2 {
                    to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?
                } else {
                    0.0
                };
                let res = if (n1 - n2).abs() < 1e-12 { 1.0 } else { 0.0 };
                Ok(EvalValue::Scalar(FormulaValue::Number(res)))
            }
            "gestep" if arguments.len() == 1 || arguments.len() == 2 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let step = if arguments.len() == 2 {
                    to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?
                } else {
                    0.0
                };
                let res = if n >= step { 1.0 } else { 0.0 };
                Ok(EvalValue::Scalar(FormulaValue::Number(res)))
            }
            "pi" if arguments.is_empty() => Ok(EvalValue::Scalar(FormulaValue::Number(
                std::f64::consts::PI,
            ))),
            "exp" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let res = n.exp();
                if res.is_finite() {
                    Ok(EvalValue::Scalar(FormulaValue::Number(res)))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                }
            }
            "ln" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                if n <= 0.0 {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Number(n.ln())))
                }
            }
            "log10" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                if n <= 0.0 {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Number(n.log10())))
                }
            }
            "isnontext" if arguments.len() == 1 => {
                let val = self.eval_scalar(&arguments[0], depth + 1)?;
                Ok(EvalValue::Scalar(FormulaValue::Boolean(!matches!(
                    val,
                    FormulaValue::String(_)
                ))))
            }
            "type" if arguments.len() == 1 => {
                let val = self.eval_scalar(&arguments[0], depth + 1)?;
                let code = match val {
                    FormulaValue::Number(_) | FormulaValue::Blank => 1.0,
                    FormulaValue::String(_) => 2.0,
                    FormulaValue::Boolean(_) => 4.0,
                    FormulaValue::Error(_) => 16.0,
                };
                Ok(EvalValue::Scalar(FormulaValue::Number(code)))
            }
            "choose" => {
                if arguments.is_empty() {
                    return Err("unsupported");
                }
                let index_val = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let index = index_val.floor() as i64;
                if index < 1 || (index as usize) >= arguments.len() {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())))
                } else {
                    self.evaluate(&arguments[index as usize], depth + 1)
                }
            }
            "ifna" if arguments.len() == 2 => match self.eval_scalar(&arguments[0], depth + 1) {
                Ok(FormulaValue::Error(ref s)) if s.eq_ignore_ascii_case("#N/A") => {
                    self.evaluate(&arguments[1], depth + 1)
                }
                Ok(scalar) => Ok(EvalValue::Scalar(scalar)),
                Err(_) => self.evaluate(&arguments[1], depth + 1),
            },
            "ifs" => {
                if arguments.len() < 2 || !arguments.len().is_multiple_of(2) {
                    return Err("unsupported");
                }
                for chunk in arguments.chunks_exact(2) {
                    let cond = to_bool(&self.eval_scalar(&chunk[0], depth + 1)?)?;
                    if cond {
                        return self.evaluate(&chunk[1], depth + 1);
                    }
                }
                Ok(EvalValue::Scalar(FormulaValue::Error("#N/A".into())))
            }
            "switch" => {
                if arguments.len() < 3 {
                    return Err("unsupported");
                }
                let target = self.eval_scalar(&arguments[0], depth + 1)?;
                let remaining = &arguments[1..];
                let has_default = !remaining.len().is_multiple_of(2);
                let pairs_len = if has_default {
                    remaining.len() - 1
                } else {
                    remaining.len()
                };
                for i in (0..pairs_len).step_by(2) {
                    let val = self.eval_scalar(&remaining[i], depth + 1)?;
                    if values_equal(&target, &val) {
                        return self.evaluate(&remaining[i + 1], depth + 1);
                    }
                }
                if has_default {
                    self.evaluate(&remaining[remaining.len() - 1], depth + 1)
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#N/A".into())))
                }
            }
            "xor" => {
                if arguments.is_empty() {
                    return Err("unsupported");
                }
                let mut true_count = 0usize;
                let mut total_count = 0usize;
                for arg in arguments {
                    let val = self.evaluate(arg, depth + 1)?;
                    let values = match val {
                        EvalValue::Scalar(s) => vec![s],
                        EvalValue::Range { values, .. } => values,
                    };
                    for v in values {
                        if let FormulaValue::Error(err) = v {
                            return Ok(EvalValue::Scalar(FormulaValue::Error(err)));
                        }
                        if matches!(v, FormulaValue::Blank) {
                            continue;
                        }
                        if let Ok(b) = to_bool(&v) {
                            total_count += 1;
                            if b {
                                true_count += 1;
                            }
                        }
                    }
                }
                if total_count == 0 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                }
                Ok(EvalValue::Scalar(FormulaValue::Boolean(
                    !true_count.is_multiple_of(2),
                )))
            }
            "quotient" if arguments.len() == 2 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let d = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                if d == 0.0 {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#DIV/0!".into())))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Number((n / d).trunc())))
                }
            }
            "log" if (1..=2).contains(&arguments.len()) => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                if n <= 0.0 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                let base = if arguments.len() == 2 {
                    to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?
                } else {
                    10.0
                };
                if base <= 0.0 || (base - 1.0).abs() < f64::EPSILON {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                let res = n.ln() / base.ln();
                if res.is_finite() {
                    Ok(EvalValue::Scalar(FormulaValue::Number(res)))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                }
            }
            "index" => {
                if !(2..=3).contains(&arguments.len()) {
                    return Err("unsupported");
                }
                let target = self.evaluate(&arguments[0], depth + 1)?;
                match target {
                    EvalValue::Scalar(scalar) => {
                        let row_num =
                            to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.trunc() as i64;
                        let col_num = if arguments.len() == 3 {
                            to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?.trunc() as i64
                        } else {
                            1
                        };
                        if row_num == 1 && col_num == 1 {
                            Ok(EvalValue::Scalar(scalar))
                        } else {
                            Ok(EvalValue::Scalar(FormulaValue::Error("#REF!".into())))
                        }
                    }
                    EvalValue::Range { values, rows, cols } => {
                        let row_num =
                            to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.trunc() as i64;
                        if arguments.len() == 2 {
                            if rows == 1 {
                                if (1..=cols as i64).contains(&row_num) {
                                    Ok(EvalValue::Scalar(values[(row_num - 1) as usize].clone()))
                                } else {
                                    Ok(EvalValue::Scalar(FormulaValue::Error("#REF!".into())))
                                }
                            } else if cols == 1 {
                                if (1..=rows as i64).contains(&row_num) {
                                    Ok(EvalValue::Scalar(values[(row_num - 1) as usize].clone()))
                                } else {
                                    Ok(EvalValue::Scalar(FormulaValue::Error("#REF!".into())))
                                }
                            } else {
                                Ok(EvalValue::Scalar(FormulaValue::Error("#REF!".into())))
                            }
                        } else {
                            let col_num = to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?
                                .trunc() as i64;
                            if (1..=rows as i64).contains(&row_num)
                                && (1..=cols as i64).contains(&col_num)
                            {
                                let idx = (row_num - 1) as usize * cols + (col_num - 1) as usize;
                                Ok(EvalValue::Scalar(values[idx].clone()))
                            } else {
                                Ok(EvalValue::Scalar(FormulaValue::Error("#REF!".into())))
                            }
                        }
                    }
                }
            }
            "match" => {
                if !(2..=3).contains(&arguments.len()) {
                    return Err("unsupported");
                }
                let lookup_val = self.eval_scalar(&arguments[0], depth + 1)?;
                let target = self.evaluate(&arguments[1], depth + 1)?;
                let values = match target {
                    EvalValue::Scalar(s) => vec![s],
                    EvalValue::Range { values, .. } => values,
                };
                let match_type = if arguments.len() == 3 {
                    to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?.trunc() as i32
                } else {
                    1
                };
                if match_type == 0 {
                    for (idx, val) in values.iter().enumerate() {
                        if values_equal(&lookup_val, val) {
                            return Ok(EvalValue::Scalar(FormulaValue::Number((idx + 1) as f64)));
                        }
                    }
                    Ok(EvalValue::Scalar(FormulaValue::Error("#N/A".into())))
                } else if match_type == 1 {
                    let mut best: Option<usize> = None;
                    for (idx, val) in values.iter().enumerate() {
                        if values_less_than_or_equal(val, &lookup_val) {
                            best = Some(idx);
                        } else {
                            break;
                        }
                    }
                    if let Some(idx) = best {
                        Ok(EvalValue::Scalar(FormulaValue::Number((idx + 1) as f64)))
                    } else {
                        Ok(EvalValue::Scalar(FormulaValue::Error("#N/A".into())))
                    }
                } else if match_type == -1 {
                    let mut best: Option<usize> = None;
                    for (idx, val) in values.iter().enumerate() {
                        if values_greater_than_or_equal(val, &lookup_val) {
                            best = Some(idx);
                        } else {
                            break;
                        }
                    }
                    if let Some(idx) = best {
                        Ok(EvalValue::Scalar(FormulaValue::Number((idx + 1) as f64)))
                    } else {
                        Ok(EvalValue::Scalar(FormulaValue::Error("#N/A".into())))
                    }
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())))
                }
            }
            "vlookup" => {
                if !(3..=4).contains(&arguments.len()) {
                    return Err("unsupported");
                }
                let lookup_val = self.eval_scalar(&arguments[0], depth + 1)?;
                let target = self.evaluate(&arguments[1], depth + 1)?;
                let (values, rows, cols) = match target {
                    EvalValue::Range { values, rows, cols } => (values, rows, cols),
                    _ => return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into()))),
                };
                let col_index =
                    to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?.trunc() as i64;
                let range_lookup = if arguments.len() == 4 {
                    to_bool(&self.eval_scalar(&arguments[3], depth + 1)?)?
                } else {
                    true
                };
                if col_index < 1 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                }
                if col_index > cols as i64 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#REF!".into())));
                }
                let target_col = (col_index - 1) as usize;
                if !range_lookup {
                    for r in 0..rows {
                        let first_val = &values[r * cols];
                        if values_equal(&lookup_val, first_val) {
                            return Ok(EvalValue::Scalar(values[r * cols + target_col].clone()));
                        }
                    }
                    Ok(EvalValue::Scalar(FormulaValue::Error("#N/A".into())))
                } else {
                    let mut best_row: Option<usize> = None;
                    for r in 0..rows {
                        let first_val = &values[r * cols];
                        if values_less_than_or_equal(first_val, &lookup_val) {
                            best_row = Some(r);
                        } else {
                            break;
                        }
                    }
                    if let Some(r) = best_row {
                        Ok(EvalValue::Scalar(values[r * cols + target_col].clone()))
                    } else {
                        Ok(EvalValue::Scalar(FormulaValue::Error("#N/A".into())))
                    }
                }
            }
            "hlookup" => {
                if !(3..=4).contains(&arguments.len()) {
                    return Err("unsupported");
                }
                let lookup_val = self.eval_scalar(&arguments[0], depth + 1)?;
                let target = self.evaluate(&arguments[1], depth + 1)?;
                let (values, rows, cols) = match target {
                    EvalValue::Range { values, rows, cols } => (values, rows, cols),
                    _ => return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into()))),
                };
                let row_index =
                    to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?.trunc() as i64;
                let range_lookup = if arguments.len() == 4 {
                    to_bool(&self.eval_scalar(&arguments[3], depth + 1)?)?
                } else {
                    true
                };
                if row_index < 1 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                }
                if row_index > rows as i64 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#REF!".into())));
                }
                let target_row = (row_index - 1) as usize;
                if !range_lookup {
                    for (c, first_val) in values.iter().take(cols).enumerate() {
                        if values_equal(&lookup_val, first_val) {
                            return Ok(EvalValue::Scalar(values[target_row * cols + c].clone()));
                        }
                    }
                    Ok(EvalValue::Scalar(FormulaValue::Error("#N/A".into())))
                } else {
                    let mut best_col: Option<usize> = None;
                    for (c, first_val) in values.iter().take(cols).enumerate() {
                        if values_less_than_or_equal(first_val, &lookup_val) {
                            best_col = Some(c);
                        } else {
                            break;
                        }
                    }
                    if let Some(c) = best_col {
                        Ok(EvalValue::Scalar(values[target_row * cols + c].clone()))
                    } else {
                        Ok(EvalValue::Scalar(FormulaValue::Error("#N/A".into())))
                    }
                }
            }
            "indirect" => {
                if !(1..=2).contains(&arguments.len()) {
                    return Err("unsupported");
                }
                let ref_text = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let (sheet, cell_str) = parse_sheet_and_cell_str(&ref_text);
                if cell_str.contains(':') {
                    if let Some((first_s, last_s)) = cell_str.split_once(':')
                        && let (Some(first), Some(last)) =
                            (parse_cell_address(first_s), parse_cell_address(last_s))
                    {
                        self.record_reference(&ref_text);
                        let row_range = first.row.min(last.row)..=first.row.max(last.row);
                        let col_range =
                            first.column.min(last.column)..=first.column.max(last.column);
                        let rows = row_range.clone().count();
                        let cols = col_range.clone().count();
                        let count = rows.saturating_mul(cols);
                        if count > self.limits.max_range_cells {
                            return Err("resource_limit");
                        }
                        let mut values = Vec::with_capacity(count);
                        for row in row_range {
                            for column in col_range.clone() {
                                values.push(
                                    self.lookup(sheet.as_deref(), CellAddress { row, column })?,
                                );
                            }
                        }
                        return Ok(EvalValue::Range { values, rows, cols });
                    }
                    Ok(EvalValue::Scalar(FormulaValue::Error("#REF!".into())))
                } else if let Some(cell) = parse_cell_address(&cell_str) {
                    self.record_reference(&ref_text);
                    Ok(EvalValue::Scalar(self.lookup(sheet.as_deref(), cell)?))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#REF!".into())))
                }
            }
            "offset" => {
                if !(3..=5).contains(&arguments.len()) {
                    return Err("unsupported");
                }
                let (sheet, origin) = match self.eval_cell_origin(&arguments[0], depth + 1) {
                    Ok(res) => res,
                    Err(_) => {
                        return Ok(EvalValue::Scalar(FormulaValue::Error("#REF!".into())));
                    }
                };
                let row_offset =
                    to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.trunc() as i64;
                let col_offset =
                    to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?.trunc() as i64;
                let target_row = origin.row as i64 + row_offset;
                let target_col = origin.column as i64 + col_offset;
                if !(1..=1_048_576).contains(&target_row) || !(1..=16_384).contains(&target_col) {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#REF!".into())));
                }
                let height = if arguments.len() >= 4 {
                    to_number(&self.eval_scalar(&arguments[3], depth + 1)?)?.trunc() as i64
                } else {
                    1
                };
                let width = if arguments.len() == 5 {
                    to_number(&self.eval_scalar(&arguments[4], depth + 1)?)?.trunc() as i64
                } else {
                    1
                };
                if height <= 0 || width <= 0 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#REF!".into())));
                }
                let end_row = target_row + height - 1;
                let end_col = target_col + width - 1;
                if end_row > 1_048_576 || end_col > 16_384 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#REF!".into())));
                }
                if height == 1 && width == 1 {
                    let addr = CellAddress {
                        row: target_row as u32,
                        column: target_col as u32,
                    };
                    self.record_reference(&format!(
                        "{}{}",
                        sheet
                            .as_deref()
                            .map(|s| format!("{s}!"))
                            .unwrap_or_default(),
                        column_to_letters(addr.column) + &addr.row.to_string()
                    ));
                    Ok(EvalValue::Scalar(self.lookup(sheet.as_deref(), addr)?))
                } else {
                    let rows = height as usize;
                    let cols = width as usize;
                    let count = rows.saturating_mul(cols);
                    if count > self.limits.max_range_cells {
                        return Err("resource_limit");
                    }
                    let mut values = Vec::with_capacity(count);
                    for r in target_row..=end_row {
                        for c in target_col..=end_col {
                            values.push(self.lookup(
                                sheet.as_deref(),
                                CellAddress {
                                    row: r as u32,
                                    column: c as u32,
                                },
                            )?);
                        }
                    }
                    Ok(EvalValue::Range { values, rows, cols })
                }
            }
            "address" => {
                if !(2..=5).contains(&arguments.len()) {
                    return Err("unsupported");
                }
                let row_num =
                    to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?.trunc() as i64;
                let col_num =
                    to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.trunc() as i64;
                if !(1..=1_048_576).contains(&row_num) || !(1..=16_384).contains(&col_num) {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                }
                let abs_num = if arguments.len() >= 3 {
                    to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?.trunc() as i32
                } else {
                    1
                };
                if !(1..=4).contains(&abs_num) {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                }
                let a1 = if arguments.len() >= 4 {
                    to_bool(&self.eval_scalar(&arguments[3], depth + 1)?)?
                } else {
                    true
                };
                if !a1 {
                    return Err("unsupported");
                }
                let sheet_text = if arguments.len() == 5 {
                    let s = to_string(&self.eval_scalar(&arguments[4], depth + 1)?)?;
                    if s.is_empty() { None } else { Some(s) }
                } else {
                    None
                };
                let col_letters = column_to_letters(col_num as u32);
                let cell_coord = match abs_num {
                    1 => format!("${col_letters}${row_num}"),
                    2 => format!("{col_letters}${row_num}"),
                    3 => format!("${col_letters}{row_num}"),
                    4 => format!("{col_letters}{row_num}"),
                    _ => unreachable!(),
                };
                let full_addr = if let Some(sheet) = sheet_text {
                    if sheet.contains(' ') || sheet.contains('\'') {
                        let escaped = sheet.replace('\'', "''");
                        format!("'{escaped}'!{cell_coord}")
                    } else {
                        format!("{sheet}!{cell_coord}")
                    }
                } else {
                    cell_coord
                };
                self.check_string_size(&full_addr)?;
                Ok(EvalValue::Scalar(FormulaValue::String(full_addr)))
            }
            "ceiling" | "ceiling.math" => {
                if !(1..=2).contains(&arguments.len()) {
                    return Err("unsupported");
                }
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let sig = if arguments.len() == 2 {
                    to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?
                } else if n >= 0.0 {
                    1.0
                } else {
                    -1.0
                };
                if sig == 0.0 {
                    Ok(EvalValue::Scalar(FormulaValue::Number(0.0)))
                } else {
                    let ratio = n / sig;
                    Ok(EvalValue::Scalar(FormulaValue::Number(ratio.ceil() * sig)))
                }
            }
            "floor" | "floor.math" => {
                if !(1..=2).contains(&arguments.len()) {
                    return Err("unsupported");
                }
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let sig = if arguments.len() == 2 {
                    to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?
                } else if n >= 0.0 {
                    1.0
                } else {
                    -1.0
                };
                if sig == 0.0 {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#DIV/0!".into())))
                } else {
                    let ratio = n / sig;
                    Ok(EvalValue::Scalar(FormulaValue::Number(ratio.floor() * sig)))
                }
            }
            "even" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let abs_ceil = n.abs().ceil() as i64;
                let even = if abs_ceil % 2 == 0 {
                    abs_ceil
                } else {
                    abs_ceil + 1
                };
                let res = if n < 0.0 { -even } else { even };
                Ok(EvalValue::Scalar(FormulaValue::Number(res as f64)))
            }
            "odd" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let abs_ceil = n.abs().ceil() as i64;
                let odd = if abs_ceil % 2 != 0 {
                    abs_ceil
                } else {
                    abs_ceil + 1
                };
                let res = if n < 0.0 { -odd } else { odd };
                Ok(EvalValue::Scalar(FormulaValue::Number(res as f64)))
            }
            "fact" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                if !(0.0..=170.0).contains(&n) {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                } else {
                    let count = n.floor() as u64;
                    let mut res = 1.0f64;
                    for i in 2..=count {
                        res *= i as f64;
                    }
                    Ok(EvalValue::Scalar(FormulaValue::Number(res)))
                }
            }
            "gcd" if !arguments.is_empty() => {
                let mut current = 0u64;
                for arg in arguments {
                    let n = to_number(&self.eval_scalar(arg, depth + 1)?)?;
                    if n < 0.0 {
                        return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                    }
                    let val = n.floor() as u64;
                    current = if current == 0 {
                        val
                    } else {
                        gcd_pair(current, val)
                    };
                }
                Ok(EvalValue::Scalar(FormulaValue::Number(current as f64)))
            }
            "lcm" if !arguments.is_empty() => {
                let mut current = 1u64;
                for arg in arguments {
                    let n = to_number(&self.eval_scalar(arg, depth + 1)?)?;
                    if n < 0.0 {
                        return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                    }
                    let val = n.floor() as u64;
                    if val == 0 {
                        return Ok(EvalValue::Scalar(FormulaValue::Number(0.0)));
                    }
                    let g = gcd_pair(current, val);
                    if let Some(next) = (current / g).checked_mul(val) {
                        current = next;
                    } else {
                        return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                    }
                }
                Ok(EvalValue::Scalar(FormulaValue::Number(current as f64)))
            }
            "degrees" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                Ok(EvalValue::Scalar(FormulaValue::Number(
                    n * 180.0 / std::f64::consts::PI,
                )))
            }
            "radians" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                Ok(EvalValue::Scalar(FormulaValue::Number(
                    n * std::f64::consts::PI / 180.0,
                )))
            }
            "sin" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                Ok(EvalValue::Scalar(FormulaValue::Number(n.sin())))
            }
            "cos" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                Ok(EvalValue::Scalar(FormulaValue::Number(n.cos())))
            }
            "tan" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                Ok(EvalValue::Scalar(FormulaValue::Number(n.tan())))
            }
            "asin" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                if !(-1.0..=1.0).contains(&n) {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Number(n.asin())))
                }
            }
            "acos" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                if !(-1.0..=1.0).contains(&n) {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Number(n.acos())))
                }
            }
            "atan" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                Ok(EvalValue::Scalar(FormulaValue::Number(n.atan())))
            }
            "atan2" if arguments.len() == 2 => {
                let x = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let y = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                if x == 0.0 && y == 0.0 {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#DIV/0!".into())))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Number(y.atan2(x))))
                }
            }
            "bitand" if arguments.len() == 2 => {
                let a = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?.trunc() as i64;
                let b = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.trunc() as i64;
                const MAX_BIT_VAL: i64 = (1i64 << 48) - 1;
                if !(0..=MAX_BIT_VAL).contains(&a) || !(0..=MAX_BIT_VAL).contains(&b) {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Number((a & b) as f64)))
                }
            }
            "bitor" if arguments.len() == 2 => {
                let a = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?.trunc() as i64;
                let b = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.trunc() as i64;
                const MAX_BIT_VAL: i64 = (1i64 << 48) - 1;
                if !(0..=MAX_BIT_VAL).contains(&a) || !(0..=MAX_BIT_VAL).contains(&b) {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Number((a | b) as f64)))
                }
            }
            "bitxor" if arguments.len() == 2 => {
                let a = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?.trunc() as i64;
                let b = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.trunc() as i64;
                const MAX_BIT_VAL: i64 = (1i64 << 48) - 1;
                if !(0..=MAX_BIT_VAL).contains(&a) || !(0..=MAX_BIT_VAL).contains(&b) {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Number((a ^ b) as f64)))
                }
            }
            "bitlshift" if arguments.len() == 2 => {
                let a = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?.trunc() as i64;
                let shift = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.trunc() as i64;
                const MAX_BIT_VAL: i64 = (1i64 << 48) - 1;
                if !(0..=MAX_BIT_VAL).contains(&a) || !(-53..=53).contains(&shift) {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                } else if shift >= 0 {
                    if shift >= 48 || (a << shift) > MAX_BIT_VAL {
                        Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                    } else {
                        Ok(EvalValue::Scalar(FormulaValue::Number((a << shift) as f64)))
                    }
                } else {
                    let rshift = -shift;
                    if rshift >= 48 {
                        Ok(EvalValue::Scalar(FormulaValue::Number(0.0)))
                    } else {
                        Ok(EvalValue::Scalar(FormulaValue::Number(
                            (a >> rshift) as f64,
                        )))
                    }
                }
            }
            "bitrshift" if arguments.len() == 2 => {
                let a = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?.trunc() as i64;
                let shift = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.trunc() as i64;
                const MAX_BIT_VAL: i64 = (1i64 << 48) - 1;
                if !(0..=MAX_BIT_VAL).contains(&a) || !(-53..=53).contains(&shift) {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                } else if shift >= 0 {
                    if shift >= 48 {
                        Ok(EvalValue::Scalar(FormulaValue::Number(0.0)))
                    } else {
                        Ok(EvalValue::Scalar(FormulaValue::Number((a >> shift) as f64)))
                    }
                } else {
                    let lshift = -shift;
                    if lshift >= 48 || (a << lshift) > MAX_BIT_VAL {
                        Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                    } else {
                        Ok(EvalValue::Scalar(FormulaValue::Number(
                            (a << lshift) as f64,
                        )))
                    }
                }
            }
            "date" if arguments.len() == 3 => {
                let mut y = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?.trunc() as i32;
                let m = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.trunc() as i32;
                let d = to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?.trunc() as i32;
                if (0..=1899).contains(&y) {
                    y += 1900;
                }
                if let Some(serial) = crate::preprocessor::date_serial_from_components(y, m, d) {
                    Ok(EvalValue::Scalar(FormulaValue::Number(serial)))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                }
            }
            "year" if arguments.len() == 1 => {
                let serial = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                if let Some((y, _, _, _, _, _)) =
                    crate::preprocessor::date_components_from_serial(serial)
                {
                    Ok(EvalValue::Scalar(FormulaValue::Number(y as f64)))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())))
                }
            }
            "month" if arguments.len() == 1 => {
                let serial = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                if let Some((_, m, _, _, _, _)) =
                    crate::preprocessor::date_components_from_serial(serial)
                {
                    Ok(EvalValue::Scalar(FormulaValue::Number(m as f64)))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())))
                }
            }
            "day" if arguments.len() == 1 => {
                let serial = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                if let Some((_, _, d, _, _, _)) =
                    crate::preprocessor::date_components_from_serial(serial)
                {
                    Ok(EvalValue::Scalar(FormulaValue::Number(d as f64)))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())))
                }
            }
            "time" if arguments.len() == 3 => {
                let h = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?.trunc() as i64;
                let m = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.trunc() as i64;
                let s = to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?.trunc() as i64;
                let total_secs = h * 3600 + m * 60 + s;
                let mut day_frac = (total_secs % 86400) as f64 / 86400.0;
                if day_frac < 0.0 {
                    day_frac += 1.0;
                }
                Ok(EvalValue::Scalar(FormulaValue::Number(day_frac)))
            }
            "hour" if arguments.len() == 1 => {
                let serial = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let frac = serial - serial.floor();
                let secs = (frac * 86400.0).round() as i64;
                let h = (secs / 3600) % 24;
                Ok(EvalValue::Scalar(FormulaValue::Number(h as f64)))
            }
            "minute" if arguments.len() == 1 => {
                let serial = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let frac = serial - serial.floor();
                let secs = (frac * 86400.0).round() as i64;
                let m = (secs % 3600) / 60;
                Ok(EvalValue::Scalar(FormulaValue::Number(m as f64)))
            }
            "second" if arguments.len() == 1 => {
                let serial = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let frac = serial - serial.floor();
                let secs = (frac * 86400.0).round() as i64;
                let s = secs % 60;
                Ok(EvalValue::Scalar(FormulaValue::Number(s as f64)))
            }
            "edate" if arguments.len() == 2 => {
                let serial = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let months =
                    to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.trunc() as i64;
                if let Some(res) = crate::preprocessor::date_serial_add_months(serial, months) {
                    Ok(EvalValue::Scalar(FormulaValue::Number(res)))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                }
            }
            "eomonth" if arguments.len() == 2 => {
                let serial = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let months =
                    to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.trunc() as i64;
                if let Some(res) = crate::preprocessor::date_serial_add_months(serial, months)
                    && let Some((y, m, _, _, _, _)) =
                        crate::preprocessor::date_components_from_serial(res)
                {
                    let last_day = crate::preprocessor::days_in_month(y, m);
                    if let Some(eom) =
                        crate::preprocessor::date_serial_from_components(y, m, last_day)
                    {
                        return Ok(EvalValue::Scalar(FormulaValue::Number(eom)));
                    }
                }
                Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
            }
            "xlookup" => {
                if !(3..=6).contains(&arguments.len()) {
                    return Err("unsupported");
                }
                let lookup_val = self.eval_scalar(&arguments[0], depth + 1)?;
                let lookup_target = self.evaluate(&arguments[1], depth + 1)?;
                let (lookup_vals, l_rows, l_cols) = match lookup_target {
                    EvalValue::Range { values, rows, cols } => (values, rows, cols),
                    EvalValue::Scalar(s) => (vec![s], 1, 1),
                };
                let return_target = self.evaluate(&arguments[2], depth + 1)?;
                let (ret_vals, r_rows, r_cols) = match return_target {
                    EvalValue::Range { values, rows, cols } => (values, rows, cols),
                    EvalValue::Scalar(s) => (vec![s], 1, 1),
                };
                let if_not_found = if arguments.len() >= 4 {
                    Some(self.eval_scalar(&arguments[3], depth + 1)?)
                } else {
                    None
                };
                let match_mode = if arguments.len() >= 5 {
                    to_number(&self.eval_scalar(&arguments[4], depth + 1)?)?.trunc() as i32
                } else {
                    0
                };
                let search_mode = if arguments.len() >= 6 {
                    to_number(&self.eval_scalar(&arguments[5], depth + 1)?)?.trunc() as i32
                } else {
                    1
                };

                let mut matched_index: Option<usize> = None;

                if search_mode == -1 {
                    for (i, val) in lookup_vals.iter().enumerate().rev() {
                        if matches_lookup(&lookup_val, val, match_mode) {
                            matched_index = Some(i);
                            break;
                        }
                    }
                } else {
                    for (i, val) in lookup_vals.iter().enumerate() {
                        if matches_lookup(&lookup_val, val, match_mode) {
                            matched_index = Some(i);
                            break;
                        }
                    }
                }

                if let Some(idx) = matched_index {
                    if l_cols == 1 && r_rows == l_rows {
                        if r_cols == 1 {
                            Ok(EvalValue::Scalar(ret_vals[idx].clone()))
                        } else {
                            let start = idx * r_cols;
                            let end = start + r_cols;
                            if end <= ret_vals.len() {
                                Ok(EvalValue::Range {
                                    values: ret_vals[start..end].to_vec(),
                                    rows: 1,
                                    cols: r_cols,
                                })
                            } else {
                                Ok(EvalValue::Scalar(FormulaValue::Error("#REF!".into())))
                            }
                        }
                    } else if l_rows == 1 && r_cols == l_cols {
                        if r_rows == 1 {
                            Ok(EvalValue::Scalar(ret_vals[idx].clone()))
                        } else {
                            let mut col_values = Vec::with_capacity(r_rows);
                            for r in 0..r_rows {
                                col_values.push(ret_vals[r * r_cols + idx].clone());
                            }
                            Ok(EvalValue::Range {
                                values: col_values,
                                rows: r_rows,
                                cols: 1,
                            })
                        }
                    } else if idx < ret_vals.len() {
                        Ok(EvalValue::Scalar(ret_vals[idx].clone()))
                    } else {
                        Ok(EvalValue::Scalar(FormulaValue::Error("#REF!".into())))
                    }
                } else if let Some(nf) = if_not_found {
                    Ok(EvalValue::Scalar(nf))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#N/A".into())))
                }
            }
            "xmatch" => {
                if !(2..=4).contains(&arguments.len()) {
                    return Err("unsupported");
                }
                let lookup_val = self.eval_scalar(&arguments[0], depth + 1)?;
                let lookup_target = self.evaluate(&arguments[1], depth + 1)?;
                let lookup_vals = match lookup_target {
                    EvalValue::Range { values, .. } => values,
                    EvalValue::Scalar(s) => vec![s],
                };
                let match_mode = if arguments.len() >= 3 {
                    to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?.trunc() as i32
                } else {
                    0
                };
                let search_mode = if arguments.len() >= 4 {
                    to_number(&self.eval_scalar(&arguments[3], depth + 1)?)?.trunc() as i32
                } else {
                    1
                };

                let mut matched_index: Option<usize> = None;

                if search_mode == -1 {
                    for (i, val) in lookup_vals.iter().enumerate().rev() {
                        if matches_lookup(&lookup_val, val, match_mode) {
                            matched_index = Some(i);
                            break;
                        }
                    }
                } else {
                    for (i, val) in lookup_vals.iter().enumerate() {
                        if matches_lookup(&lookup_val, val, match_mode) {
                            matched_index = Some(i);
                            break;
                        }
                    }
                }

                if let Some(idx) = matched_index {
                    Ok(EvalValue::Scalar(FormulaValue::Number((idx + 1) as f64)))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#N/A".into())))
                }
            }
            "rows" if arguments.len() == 1 => {
                let res = match self.evaluate(&arguments[0], depth + 1)? {
                    EvalValue::Scalar(_) => 1.0,
                    EvalValue::Range { rows, .. } => rows as f64,
                };
                Ok(EvalValue::Scalar(FormulaValue::Number(res)))
            }
            "columns" if arguments.len() == 1 => {
                let res = match self.evaluate(&arguments[0], depth + 1)? {
                    EvalValue::Scalar(_) => 1.0,
                    EvalValue::Range { cols, .. } => cols as f64,
                };
                Ok(EvalValue::Scalar(FormulaValue::Number(res)))
            }
            "mround" if arguments.len() == 2 => {
                let num = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let multiple = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                if multiple == 0.0 {
                    return Ok(EvalValue::Scalar(FormulaValue::Number(0.0)));
                }
                if (num > 0.0 && multiple < 0.0) || (num < 0.0 && multiple > 0.0) {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                let res = (num / multiple).round() * multiple;
                Ok(EvalValue::Scalar(FormulaValue::Number(res)))
            }
            "take" | "drop" | "chooserows" | "choosecols" | "torow" | "tocol" | "expand"
            | "wraprows" | "wrapcols" | "filter" | "sort" | "sortby" | "unique" | "arraytotext"
            | "valuetotext" => self.evaluate_array_manipulation(name, arguments, depth + 1),
            "len" | "left" | "right" | "mid" | "concatenate" | "concat" | "value" | "trim"
            | "upper" | "lower" | "exact" | "rept" | "substitute" | "replace" | "char" | "code"
            | "clean" | "t" | "n" | "find" | "search" | "hyperlink" | "proper" | "unichar"
            | "unicode" | "hex2dec" | "dec2hex" | "bin2dec" | "dec2bin" | "oct2dec" | "dec2oct"
            | "textjoin" | "textbefore" | "textafter" | "textsplit" | "base" | "decimal" => {
                self.evaluate_string_function(name, arguments, depth + 1)
            }
            _ => Err("unsupported"),
        }
    }

    fn evaluate_aggregate(
        &mut self,
        name: &str,
        arguments: &[Expr],
        depth: usize,
    ) -> Result<EvalValue, &'static str> {
        let mut values = Vec::new();
        for argument in arguments {
            match self.evaluate(argument, depth + 1)? {
                EvalValue::Scalar(value) => values.push(value),
                EvalValue::Range {
                    values: range_vals, ..
                } => values.extend(range_vals),
            }
        }
        if name == "counta" {
            return Ok(EvalValue::Scalar(FormulaValue::Number(
                values
                    .iter()
                    .filter(|value| !matches!(value, FormulaValue::Blank))
                    .count() as f64,
            )));
        }
        let mut numbers = Vec::new();
        for value in values {
            if let FormulaValue::Error(error) = value {
                return Ok(EvalValue::Scalar(FormulaValue::Error(error)));
            }
            if let Ok(number) = to_number(&value) {
                numbers.push(number);
            }
        }
        if name == "count" {
            return Ok(EvalValue::Scalar(
                FormulaValue::Number(numbers.len() as f64),
            ));
        }
        if numbers.is_empty() {
            return if name == "average" {
                Ok(EvalValue::Scalar(FormulaValue::Error("#DIV/0!".into())))
            } else {
                Ok(EvalValue::Scalar(FormulaValue::Number(0.0)))
            };
        }
        let result = match name {
            "sum" => numbers.iter().sum(),
            "average" => numbers.iter().sum::<f64>() / numbers.len() as f64,
            "min" => numbers.iter().copied().fold(f64::INFINITY, f64::min),
            "max" => numbers.iter().copied().fold(f64::NEG_INFINITY, f64::max),
            "product" => numbers.iter().product(),
            _ => return Err("unsupported"),
        };
        Ok(EvalValue::Scalar(FormulaValue::Number(result)))
    }

    fn evaluate_string_function(
        &mut self,
        name: &str,
        arguments: &[Expr],
        depth: usize,
    ) -> Result<EvalValue, &'static str> {
        match name {
            "len" | "value" if arguments.len() == 1 => {
                let value = self.eval_scalar(&arguments[0], depth + 1)?;
                if name == "len" {
                    return Ok(EvalValue::Scalar(FormulaValue::Number(
                        to_string(&value)?.chars().count() as f64,
                    )));
                }
                let text = to_string(&value)?;
                let number = text.trim().parse::<f64>().map_err(|_| "unsupported")?;
                Ok(EvalValue::Scalar(FormulaValue::Number(number)))
            }
            "left" | "right" if arguments.len() == 1 || arguments.len() == 2 => {
                let text = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let count = if arguments.len() == 2 {
                    nonnegative_count(&self.eval_scalar(&arguments[1], depth + 1)?)?
                } else {
                    1
                };
                let value = if name == "left" {
                    text.chars().take(count).collect::<String>()
                } else {
                    text.chars()
                        .rev()
                        .take(count)
                        .collect::<String>()
                        .chars()
                        .rev()
                        .collect()
                };
                self.check_string_size(&value)?;
                Ok(EvalValue::Scalar(FormulaValue::String(value)))
            }
            "mid" if arguments.len() == 3 => {
                let text = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let start = nonnegative_count(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let count = nonnegative_count(&self.eval_scalar(&arguments[2], depth + 1)?)?;
                let value = text
                    .chars()
                    .skip(start.saturating_sub(1))
                    .take(count)
                    .collect::<String>();
                self.check_string_size(&value)?;
                Ok(EvalValue::Scalar(FormulaValue::String(value)))
            }
            "concatenate" | "concat" if !arguments.is_empty() => {
                let mut value = String::new();
                for argument in arguments {
                    match self.evaluate(argument, depth + 1)? {
                        EvalValue::Scalar(val) => {
                            value.push_str(&to_string(&val)?);
                            self.check_string_size(&value)?;
                        }
                        EvalValue::Range { values, .. } => {
                            for val in values {
                                value.push_str(&to_string(&val)?);
                                self.check_string_size(&value)?;
                            }
                        }
                    }
                }
                Ok(EvalValue::Scalar(FormulaValue::String(value)))
            }
            "upper" | "lower" if arguments.len() == 1 => {
                let text = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let value = if name == "upper" {
                    text.to_ascii_uppercase()
                } else {
                    text.to_ascii_lowercase()
                };
                self.check_string_size(&value)?;
                Ok(EvalValue::Scalar(FormulaValue::String(value)))
            }
            "trim" if arguments.len() == 1 => {
                let text = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let mut words = text.split_whitespace();
                let mut value = String::new();
                if let Some(first) = words.next() {
                    value.push_str(first);
                    for w in words {
                        value.push(' ');
                        value.push_str(w);
                    }
                }
                self.check_string_size(&value)?;
                Ok(EvalValue::Scalar(FormulaValue::String(value)))
            }
            "exact" if arguments.len() == 2 => {
                let s1 = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let s2 = to_string(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                Ok(EvalValue::Scalar(FormulaValue::Boolean(s1 == s2)))
            }
            "rept" if arguments.len() == 2 => {
                let s = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let times = nonnegative_count(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                if times > 32767 {
                    return Err("resource_limit");
                }
                let total_bytes = s.len().saturating_mul(times);
                if total_bytes > self.limits.max_string_bytes {
                    return Err("resource_limit");
                }
                let value = s.repeat(times);
                self.check_string_size(&value)?;
                Ok(EvalValue::Scalar(FormulaValue::String(value)))
            }
            "substitute" if arguments.len() == 3 || arguments.len() == 4 => {
                let text = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let old_text = to_string(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let new_text = to_string(&self.eval_scalar(&arguments[2], depth + 1)?)?;
                let instance = if arguments.len() == 4 {
                    Some(nonnegative_count(
                        &self.eval_scalar(&arguments[3], depth + 1)?,
                    )?)
                } else {
                    None
                };
                let value = if old_text.is_empty() {
                    text
                } else if let Some(target_inst) = instance {
                    if target_inst == 0 {
                        text
                    } else {
                        let mut count = 0;
                        let mut result = String::new();
                        let mut last_end = 0;
                        for (idx, m) in text.match_indices(&old_text) {
                            count += 1;
                            if count == target_inst {
                                result.push_str(&text[last_end..idx]);
                                result.push_str(&new_text);
                                last_end = idx + m.len();
                                break;
                            }
                        }
                        result.push_str(&text[last_end..]);
                        result
                    }
                } else {
                    text.replace(&old_text, &new_text)
                };
                self.check_string_size(&value)?;
                Ok(EvalValue::Scalar(FormulaValue::String(value)))
            }
            "replace" if arguments.len() == 4 => {
                let old_text = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let start_num = nonnegative_count(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let num_chars = nonnegative_count(&self.eval_scalar(&arguments[2], depth + 1)?)?;
                let new_text = to_string(&self.eval_scalar(&arguments[3], depth + 1)?)?;
                if start_num == 0 {
                    return Err("unsupported");
                }
                let prefix: String = old_text.chars().take(start_num - 1).collect();
                let suffix: String = old_text.chars().skip(start_num - 1 + num_chars).collect();
                let value = format!("{prefix}{new_text}{suffix}");
                self.check_string_size(&value)?;
                Ok(EvalValue::Scalar(FormulaValue::String(value)))
            }
            "char" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let code = n.floor() as i64;
                if !(1..=255).contains(&code) {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())))
                } else {
                    let ch = (code as u8) as char;
                    let mut s = String::with_capacity(1);
                    s.push(ch);
                    Ok(EvalValue::Scalar(FormulaValue::String(s)))
                }
            }
            "code" if arguments.len() == 1 => {
                let s = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                if let Some(ch) = s.chars().next() {
                    let code = (ch as u32) as f64;
                    Ok(EvalValue::Scalar(FormulaValue::Number(code)))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())))
                }
            }
            "clean" if arguments.len() == 1 => {
                let s = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let cleaned: String = s
                    .chars()
                    .filter(|&c| (c as u32) >= 32 && (c as u32) != 127)
                    .collect();
                self.check_string_size(&cleaned)?;
                Ok(EvalValue::Scalar(FormulaValue::String(cleaned)))
            }
            "t" if arguments.len() == 1 => {
                let val = self.eval_scalar(&arguments[0], depth + 1)?;
                match val {
                    FormulaValue::String(s) => Ok(EvalValue::Scalar(FormulaValue::String(s))),
                    FormulaValue::Error(err) => Ok(EvalValue::Scalar(FormulaValue::Error(err))),
                    _ => Ok(EvalValue::Scalar(FormulaValue::String(String::new()))),
                }
            }
            "n" if arguments.len() == 1 => {
                let val = self.eval_scalar(&arguments[0], depth + 1)?;
                match val {
                    FormulaValue::Number(n) => Ok(EvalValue::Scalar(FormulaValue::Number(n))),
                    FormulaValue::Boolean(b) => Ok(EvalValue::Scalar(FormulaValue::Number(if b {
                        1.0
                    } else {
                        0.0
                    }))),
                    FormulaValue::Error(err) => Ok(EvalValue::Scalar(FormulaValue::Error(err))),
                    _ => Ok(EvalValue::Scalar(FormulaValue::Number(0.0))),
                }
            }
            "find" if arguments.len() == 2 || arguments.len() == 3 => {
                let find_text = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let within_text = to_string(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let start_num = if arguments.len() == 3 {
                    let num = to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?;
                    let count = num.floor() as i64;
                    if count <= 0 {
                        return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                    }
                    count as usize
                } else {
                    1
                };
                let within_chars: Vec<char> = within_text.chars().collect();
                let find_chars: Vec<char> = find_text.chars().collect();
                if start_num > within_chars.len() + 1 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                }
                if find_chars.is_empty() {
                    return Ok(EvalValue::Scalar(FormulaValue::Number(start_num as f64)));
                }
                let start_idx = start_num - 1;
                let mut found = None;
                if start_idx + find_chars.len() <= within_chars.len() {
                    for i in start_idx..=(within_chars.len() - find_chars.len()) {
                        if within_chars[i..i + find_chars.len()] == find_chars[..] {
                            found = Some(i + 1);
                            break;
                        }
                    }
                }
                match found {
                    Some(pos) => Ok(EvalValue::Scalar(FormulaValue::Number(pos as f64))),
                    None => Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into()))),
                }
            }
            "search" if arguments.len() == 2 || arguments.len() == 3 => {
                let find_text = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let within_text = to_string(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let start_num = if arguments.len() == 3 {
                    let num = to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?;
                    let count = num.floor() as i64;
                    if count <= 0 {
                        return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                    }
                    count as usize
                } else {
                    1
                };
                let within_chars: Vec<char> = within_text.chars().collect();
                let find_chars: Vec<char> = find_text.chars().collect();
                if start_num > within_chars.len() + 1 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                }
                if find_chars.is_empty() {
                    return Ok(EvalValue::Scalar(FormulaValue::Number(start_num as f64)));
                }
                let start_idx = start_num - 1;
                let mut found = None;
                if start_idx + find_chars.len() <= within_chars.len() {
                    for i in start_idx..=(within_chars.len() - find_chars.len()) {
                        let slice = &within_chars[i..i + find_chars.len()];
                        let matches = slice.iter().zip(find_chars.iter()).all(|(a, b)| {
                            a.to_lowercase().collect::<Vec<_>>()
                                == b.to_lowercase().collect::<Vec<_>>()
                        });
                        if matches {
                            found = Some(i + 1);
                            break;
                        }
                    }
                }
                match found {
                    Some(pos) => Ok(EvalValue::Scalar(FormulaValue::Number(pos as f64))),
                    None => Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into()))),
                }
            }
            "hyperlink" if arguments.len() == 1 || arguments.len() == 2 => {
                let target = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                if arguments.len() == 2 {
                    let _ = self.eval_scalar(&arguments[1], depth + 1)?;
                }
                self.check_string_size(&target)?;
                Ok(EvalValue::Scalar(FormulaValue::String(target)))
            }
            "proper" if arguments.len() == 1 => {
                let s = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let val = proper(&s);
                self.check_string_size(&val)?;
                Ok(EvalValue::Scalar(FormulaValue::String(val)))
            }
            "unichar" if arguments.len() == 1 => {
                let code = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                Ok(EvalValue::Scalar(unichar(code)))
            }
            "unicode" if arguments.len() == 1 => {
                let s = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                Ok(EvalValue::Scalar(unicode(&s)))
            }
            "hex2dec" if arguments.len() == 1 => {
                let s = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                Ok(EvalValue::Scalar(hex_to_dec(&s)))
            }
            "dec2hex" if arguments.len() == 1 || arguments.len() == 2 => {
                let num = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let places = if arguments.len() == 2 {
                    Some(to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?)
                } else {
                    None
                };
                let val = dec_to_hex(num, places);
                if let FormulaValue::String(ref s) = val {
                    self.check_string_size(s)?;
                }
                Ok(EvalValue::Scalar(val))
            }
            "bin2dec" if arguments.len() == 1 => {
                let s = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                Ok(EvalValue::Scalar(bin_to_dec(&s)))
            }
            "dec2bin" if arguments.len() == 1 || arguments.len() == 2 => {
                let num = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let places = if arguments.len() == 2 {
                    Some(to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?)
                } else {
                    None
                };
                let val = dec_to_bin(num, places);
                if let FormulaValue::String(ref s) = val {
                    self.check_string_size(s)?;
                }
                Ok(EvalValue::Scalar(val))
            }
            "oct2dec" if arguments.len() == 1 => {
                let s = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                Ok(EvalValue::Scalar(oct_to_dec(&s)))
            }
            "dec2oct" if arguments.len() == 1 || arguments.len() == 2 => {
                let num = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let places = if arguments.len() == 2 {
                    Some(to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?)
                } else {
                    None
                };
                let val = dec_to_oct(num, places);
                if let FormulaValue::String(ref s) = val {
                    self.check_string_size(s)?;
                }
                Ok(EvalValue::Scalar(val))
            }
            "base" if arguments.len() == 2 || arguments.len() == 3 => {
                let num = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let radix = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let min_len = if arguments.len() == 3 {
                    Some(to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?)
                } else {
                    None
                };
                let val = base_to_str(num, radix, min_len);
                if let FormulaValue::String(ref s) = val {
                    self.check_string_size(s)?;
                }
                Ok(EvalValue::Scalar(val))
            }
            "decimal" if arguments.len() == 2 => {
                let s = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let radix = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                Ok(EvalValue::Scalar(decimal_from_base(&s, radix)))
            }
            "textjoin" if arguments.len() >= 3 => {
                let delim = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let ignore_empty = to_bool(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let mut parts: Vec<String> = Vec::new();
                for arg in &arguments[2..] {
                    match self.evaluate(arg, depth + 1)? {
                        EvalValue::Scalar(val) => {
                            if let FormulaValue::Error(err) = val {
                                return Ok(EvalValue::Scalar(FormulaValue::Error(err)));
                            }
                            if matches!(val, FormulaValue::Blank) {
                                if !ignore_empty {
                                    parts.push(String::new());
                                }
                            } else {
                                let s = to_string(&val)?;
                                if !(ignore_empty && s.is_empty()) {
                                    parts.push(s);
                                }
                            }
                        }
                        EvalValue::Range { values, .. } => {
                            for val in values {
                                if let FormulaValue::Error(err) = val {
                                    return Ok(EvalValue::Scalar(FormulaValue::Error(err)));
                                }
                                if matches!(val, FormulaValue::Blank) {
                                    if !ignore_empty {
                                        parts.push(String::new());
                                    }
                                } else {
                                    let s = to_string(&val)?;
                                    if !(ignore_empty && s.is_empty()) {
                                        parts.push(s);
                                    }
                                }
                            }
                        }
                    }
                }
                let result = parts.join(&delim);
                self.check_string_size(&result)?;
                Ok(EvalValue::Scalar(FormulaValue::String(result)))
            }
            "textbefore" | "textafter" => {
                if !(2..=6).contains(&arguments.len()) {
                    return Err("unsupported");
                }
                let text = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let delim = to_string(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let instance_num = if arguments.len() >= 3 {
                    to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?.trunc() as i64
                } else {
                    1
                };
                if instance_num == 0 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                }
                let match_mode = if arguments.len() >= 4 {
                    to_number(&self.eval_scalar(&arguments[3], depth + 1)?)?.trunc() as i32
                } else {
                    0
                };
                let match_end = if arguments.len() >= 5 {
                    to_number(&self.eval_scalar(&arguments[4], depth + 1)?)?.trunc() as i32
                } else {
                    0
                };
                let if_not_found = if arguments.len() >= 6 {
                    Some(self.eval_scalar(&arguments[5], depth + 1)?)
                } else {
                    None
                };

                let mut match_indices = Vec::new();
                if delim.is_empty() {
                    match_indices.push(0);
                } else if match_mode == 1 {
                    let text_lower = text.to_ascii_lowercase();
                    let delim_lower = delim.to_ascii_lowercase();
                    let mut start = 0;
                    while let Some(idx) = text_lower[start..].find(&delim_lower) {
                        let abs_idx = start + idx;
                        match_indices.push(abs_idx);
                        start = abs_idx + delim.len();
                    }
                } else {
                    let mut start = 0;
                    while let Some(idx) = text[start..].find(&delim) {
                        let abs_idx = start + idx;
                        match_indices.push(abs_idx);
                        start = abs_idx + delim.len();
                    }
                }

                if match_end == 1 && !match_indices.contains(&text.len()) {
                    match_indices.push(text.len());
                }

                let target_match: Option<usize> = if instance_num > 0 {
                    let idx = (instance_num - 1) as usize;
                    match_indices.get(idx).copied()
                } else {
                    let rev_idx = (-instance_num) as usize;
                    if rev_idx <= match_indices.len() {
                        Some(match_indices[match_indices.len() - rev_idx])
                    } else {
                        None
                    }
                };

                if let Some(pos) = target_match {
                    let result_str = if name == "textbefore" {
                        text[..pos].to_string()
                    } else {
                        let after_pos = (pos + delim.len()).min(text.len());
                        text[after_pos..].to_string()
                    };
                    self.check_string_size(&result_str)?;
                    Ok(EvalValue::Scalar(FormulaValue::String(result_str)))
                } else if let Some(nf) = if_not_found {
                    Ok(EvalValue::Scalar(nf))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#N/A".into())))
                }
            }
            "textsplit" => {
                if !(2..=4).contains(&arguments.len()) {
                    return Err("unsupported");
                }
                let text = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let col_delim = to_string(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let row_delim = if arguments.len() >= 3 {
                    let s = to_string(&self.eval_scalar(&arguments[2], depth + 1)?)?;
                    if s.is_empty() { None } else { Some(s) }
                } else {
                    None
                };
                let ignore_empty = if arguments.len() >= 4 {
                    to_bool(&self.eval_scalar(&arguments[3], depth + 1)?)?
                } else {
                    false
                };

                let mut rows_list: Vec<Vec<FormulaValue>> = Vec::new();
                let row_splits: Vec<&str> = if let Some(ref rd) = row_delim {
                    text.split(rd).collect()
                } else {
                    vec![&text]
                };

                let mut max_cols = 0;
                for r_text in row_splits {
                    if ignore_empty && r_text.is_empty() {
                        continue;
                    }
                    let col_splits: Vec<FormulaValue> = if col_delim.is_empty() {
                        vec![FormulaValue::String(r_text.to_string())]
                    } else {
                        r_text
                            .split(&col_delim)
                            .filter(|s| !ignore_empty || !s.is_empty())
                            .map(|s| FormulaValue::String(s.to_string()))
                            .collect()
                    };
                    max_cols = max_cols.max(col_splits.len());
                    rows_list.push(col_splits);
                }

                let num_rows = rows_list.len();
                let num_cols = max_cols;
                let count = num_rows.saturating_mul(num_cols);
                if count > self.limits.max_range_cells {
                    return Err("resource_limit");
                }
                let mut flat_values = Vec::with_capacity(count);
                for mut row in rows_list {
                    while row.len() < num_cols {
                        row.push(FormulaValue::Error("#N/A".into()));
                    }
                    flat_values.extend(row);
                }
                if num_rows == 1 && num_cols == 1 && !flat_values.is_empty() {
                    Ok(EvalValue::Scalar(flat_values.remove(0)))
                } else {
                    Ok(EvalValue::Range {
                        values: flat_values,
                        rows: num_rows,
                        cols: num_cols,
                    })
                }
            }
            _ => Err("unsupported"),
        }
    }

    fn evaluate_array_manipulation(
        &mut self,
        name: &str,
        arguments: &[Expr],
        depth: usize,
    ) -> Result<EvalValue, &'static str> {
        if arguments.is_empty() {
            return Err("unsupported");
        }
        let (values, orig_rows, orig_cols) = match self.evaluate(&arguments[0], depth + 1)? {
            EvalValue::Scalar(s) => (vec![s], 1, 1),
            EvalValue::Range { values, rows, cols } => (values, rows, cols),
        };

        match name {
            "take" if (2..=3).contains(&arguments.len()) => {
                let num_rows =
                    to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.trunc() as i64;
                if num_rows == 0 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                }
                let num_cols = if arguments.len() == 3 {
                    let c = to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?.trunc() as i64;
                    if c == 0 {
                        return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                    }
                    Some(c)
                } else {
                    None
                };

                let (start_r, end_r) = if num_rows > 0 {
                    (0, (num_rows as usize).min(orig_rows))
                } else {
                    let take_r = ((-num_rows) as usize).min(orig_rows);
                    (orig_rows - take_r, orig_rows)
                };

                let (start_c, end_c) = if let Some(c) = num_cols {
                    if c > 0 {
                        (0, (c as usize).min(orig_cols))
                    } else {
                        let take_c = ((-c) as usize).min(orig_cols);
                        (orig_cols - take_c, orig_cols)
                    }
                } else {
                    (0, orig_cols)
                };

                let new_rows = end_r.saturating_sub(start_r);
                let new_cols = end_c.saturating_sub(start_c);
                if new_rows == 0 || new_cols == 0 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#CALC!".into())));
                }

                let mut new_values = Vec::with_capacity(new_rows * new_cols);
                for r in start_r..end_r {
                    for c in start_c..end_c {
                        new_values.push(values[r * orig_cols + c].clone());
                    }
                }
                Ok(EvalValue::Range {
                    values: new_values,
                    rows: new_rows,
                    cols: new_cols,
                })
            }
            "drop" if (2..=3).contains(&arguments.len()) => {
                let drop_rows =
                    to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.trunc() as i64;
                let drop_cols = if arguments.len() == 3 {
                    to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?.trunc() as i64
                } else {
                    0
                };

                let (start_r, end_r) = if drop_rows >= 0 {
                    let dr = (drop_rows as usize).min(orig_rows);
                    (dr, orig_rows)
                } else {
                    let dr = ((-drop_rows) as usize).min(orig_rows);
                    (0, orig_rows.saturating_sub(dr))
                };

                let (start_c, end_c) = if drop_cols >= 0 {
                    let dc = (drop_cols as usize).min(orig_cols);
                    (dc, orig_cols)
                } else {
                    let dc = ((-drop_cols) as usize).min(orig_cols);
                    (0, orig_cols.saturating_sub(dc))
                };

                if start_r >= end_r || start_c >= end_c {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#CALC!".into())));
                }

                let new_rows = end_r - start_r;
                let new_cols = end_c - start_c;
                let mut new_values = Vec::with_capacity(new_rows * new_cols);
                for r in start_r..end_r {
                    for c in start_c..end_c {
                        new_values.push(values[r * orig_cols + c].clone());
                    }
                }
                Ok(EvalValue::Range {
                    values: new_values,
                    rows: new_rows,
                    cols: new_cols,
                })
            }
            "chooserows" if arguments.len() >= 2 => {
                let mut selected_rows = Vec::with_capacity(arguments.len() - 1);
                for arg in &arguments[1..] {
                    let r_idx = to_number(&self.eval_scalar(arg, depth + 1)?)?.trunc() as i64;
                    if r_idx == 0 {
                        return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                    }
                    let row = if r_idx > 0 {
                        (r_idx - 1) as usize
                    } else {
                        let offset = (-r_idx) as usize;
                        if offset > orig_rows {
                            return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                        }
                        orig_rows - offset
                    };
                    if row >= orig_rows {
                        return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                    }
                    selected_rows.push(row);
                }

                let new_rows = selected_rows.len();
                let mut new_values = Vec::with_capacity(new_rows * orig_cols);
                for row in selected_rows {
                    for c in 0..orig_cols {
                        new_values.push(values[row * orig_cols + c].clone());
                    }
                }
                Ok(EvalValue::Range {
                    values: new_values,
                    rows: new_rows,
                    cols: orig_cols,
                })
            }
            "choosecols" if arguments.len() >= 2 => {
                let mut selected_cols = Vec::with_capacity(arguments.len() - 1);
                for arg in &arguments[1..] {
                    let c_idx = to_number(&self.eval_scalar(arg, depth + 1)?)?.trunc() as i64;
                    if c_idx == 0 {
                        return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                    }
                    let col = if c_idx > 0 {
                        (c_idx - 1) as usize
                    } else {
                        let offset = (-c_idx) as usize;
                        if offset > orig_cols {
                            return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                        }
                        orig_cols - offset
                    };
                    if col >= orig_cols {
                        return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                    }
                    selected_cols.push(col);
                }

                let new_cols = selected_cols.len();
                let mut new_values = Vec::with_capacity(orig_rows * new_cols);
                for r in 0..orig_rows {
                    for &col in &selected_cols {
                        new_values.push(values[r * orig_cols + col].clone());
                    }
                }
                Ok(EvalValue::Range {
                    values: new_values,
                    rows: orig_rows,
                    cols: new_cols,
                })
            }
            "torow" | "tocol" if (1..=3).contains(&arguments.len()) => {
                let ignore = if arguments.len() >= 2 {
                    to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.trunc() as i64
                } else {
                    0
                };
                let scan_by_column = if arguments.len() == 3 {
                    to_bool(&self.eval_scalar(&arguments[2], depth + 1)?)?
                } else {
                    false
                };

                let mut ordered_values = Vec::with_capacity(values.len());
                if scan_by_column {
                    for c in 0..orig_cols {
                        for r in 0..orig_rows {
                            ordered_values.push(values[r * orig_cols + c].clone());
                        }
                    }
                } else {
                    ordered_values = values;
                }

                let filtered: Vec<FormulaValue> = ordered_values
                    .into_iter()
                    .filter(|val| match ignore {
                        1 => !matches!(val, FormulaValue::Blank),
                        2 => !matches!(val, FormulaValue::Error(_)),
                        3 => !matches!(val, FormulaValue::Blank | FormulaValue::Error(_)),
                        _ => true,
                    })
                    .collect();

                let res_values = if filtered.is_empty() {
                    vec![FormulaValue::Error("#CALC!".into())]
                } else {
                    filtered
                };

                let (rows, cols) = if name == "torow" {
                    (1, res_values.len())
                } else {
                    (res_values.len(), 1)
                };

                Ok(EvalValue::Range {
                    values: res_values,
                    rows,
                    cols,
                })
            }
            "expand" if (2..=4).contains(&arguments.len()) => {
                let target_rows =
                    to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.trunc() as usize;
                let target_cols = if arguments.len() >= 3 {
                    to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?.trunc() as usize
                } else {
                    orig_cols
                };
                let pad_with = if arguments.len() == 4 {
                    self.eval_scalar(&arguments[3], depth + 1)?
                } else {
                    FormulaValue::Error("#N/A".into())
                };

                if target_rows < orig_rows
                    || target_cols < orig_cols
                    || target_rows == 0
                    || target_cols == 0
                {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                }

                if target_rows.saturating_mul(target_cols) > self.limits.max_range_cells {
                    return Err("resource_limit");
                }

                let mut new_values = Vec::with_capacity(target_rows * target_cols);
                for r in 0..target_rows {
                    for c in 0..target_cols {
                        if r < orig_rows && c < orig_cols {
                            new_values.push(values[r * orig_cols + c].clone());
                        } else {
                            new_values.push(pad_with.clone());
                        }
                    }
                }
                Ok(EvalValue::Range {
                    values: new_values,
                    rows: target_rows,
                    cols: target_cols,
                })
            }
            "arraytotext" if (1..=2).contains(&arguments.len()) => {
                let format_mode = if arguments.len() == 2 {
                    to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.trunc() as i64
                } else {
                    0
                };
                let mut row_strings = Vec::with_capacity(orig_rows);
                for r in 0..orig_rows {
                    let mut col_strings = Vec::with_capacity(orig_cols);
                    for c in 0..orig_cols {
                        let item = &values[r * orig_cols + c];
                        let item_str = format_formula_value_text(item, format_mode == 1);
                        col_strings.push(item_str);
                    }
                    row_strings.push(col_strings.join(", "));
                }

                let result = if format_mode == 1 {
                    format!("{{{}}}", row_strings.join("; "))
                } else {
                    row_strings.join("; ")
                };
                self.check_string_size(&result)?;
                Ok(EvalValue::Scalar(FormulaValue::String(result)))
            }
            "valuetotext" if (1..=2).contains(&arguments.len()) => {
                let format_mode = if arguments.len() == 2 {
                    to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.trunc() as i64
                } else {
                    0
                };
                let item = values.into_iter().next().unwrap_or(FormulaValue::Blank);
                let result = format_formula_value_text(&item, format_mode == 1);
                self.check_string_size(&result)?;
                Ok(EvalValue::Scalar(FormulaValue::String(result)))
            }
            "wraprows" if (2..=3).contains(&arguments.len()) => {
                let wrap_count =
                    to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.trunc() as i64;
                if wrap_count <= 0 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                }
                let wrap_cols = wrap_count as usize;
                let pad_with = if arguments.len() == 3 {
                    self.eval_scalar(&arguments[2], depth + 1)?
                } else {
                    FormulaValue::Error("#N/A".into())
                };
                if values.is_empty() {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#CALC!".into())));
                }
                let num_rows = values.len().div_ceil(wrap_cols);
                let total_cells = num_rows.saturating_mul(wrap_cols);
                if total_cells > self.limits.max_range_cells {
                    return Err("resource_limit");
                }
                let mut new_values = Vec::with_capacity(total_cells);
                for i in 0..total_cells {
                    if i < values.len() {
                        new_values.push(values[i].clone());
                    } else {
                        new_values.push(pad_with.clone());
                    }
                }
                if num_rows == 1 && wrap_cols == 1 {
                    Ok(EvalValue::Scalar(new_values.swap_remove(0)))
                } else {
                    Ok(EvalValue::Range {
                        values: new_values,
                        rows: num_rows,
                        cols: wrap_cols,
                    })
                }
            }
            "wrapcols" if (2..=3).contains(&arguments.len()) => {
                let wrap_count =
                    to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.trunc() as i64;
                if wrap_count <= 0 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                }
                let wrap_rows = wrap_count as usize;
                let pad_with = if arguments.len() == 3 {
                    self.eval_scalar(&arguments[2], depth + 1)?
                } else {
                    FormulaValue::Error("#N/A".into())
                };
                if values.is_empty() {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#CALC!".into())));
                }
                let num_cols = values.len().div_ceil(wrap_rows);
                let total_cells = wrap_rows.saturating_mul(num_cols);
                if total_cells > self.limits.max_range_cells {
                    return Err("resource_limit");
                }
                let mut new_values = vec![pad_with; total_cells];
                for (i, val) in values.into_iter().enumerate() {
                    let col = i / wrap_rows;
                    let row = i % wrap_rows;
                    new_values[row * num_cols + col] = val;
                }
                if wrap_rows == 1 && num_cols == 1 {
                    Ok(EvalValue::Scalar(new_values.swap_remove(0)))
                } else {
                    Ok(EvalValue::Range {
                        values: new_values,
                        rows: wrap_rows,
                        cols: num_cols,
                    })
                }
            }
            "filter" if (2..=3).contains(&arguments.len()) => {
                let include_eval = self.evaluate(&arguments[1], depth + 1)?;
                let (inc_vals, _, _) = match include_eval {
                    EvalValue::Scalar(s) => (vec![s], 1, 1),
                    EvalValue::Range { values, rows, cols } => (values, rows, cols),
                };
                let filter_by_cols = orig_rows == 1 && orig_cols > 1 && inc_vals.len() == orig_cols;
                if !filter_by_cols && inc_vals.len() != orig_rows {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                }

                let mut kept_indices = Vec::new();
                for (idx, v) in inc_vals.iter().enumerate() {
                    match v {
                        FormulaValue::Boolean(b) => {
                            if *b {
                                kept_indices.push(idx);
                            }
                        }
                        FormulaValue::Number(n) => {
                            if *n != 0.0 {
                                kept_indices.push(idx);
                            }
                        }
                        FormulaValue::Error(err) => {
                            return Ok(EvalValue::Scalar(FormulaValue::Error(err.clone())));
                        }
                        _ => return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into()))),
                    }
                }

                if kept_indices.is_empty() {
                    if arguments.len() == 3 {
                        let if_empty = self.eval_scalar(&arguments[2], depth + 1)?;
                        return Ok(EvalValue::Scalar(if_empty));
                    } else {
                        return Ok(EvalValue::Scalar(FormulaValue::Error("#CALC!".into())));
                    }
                }

                if filter_by_cols {
                    let new_cols = kept_indices.len();
                    let mut new_values = Vec::with_capacity(new_cols);
                    for c in kept_indices {
                        new_values.push(values[c].clone());
                    }
                    if new_cols == 1 {
                        Ok(EvalValue::Scalar(new_values.swap_remove(0)))
                    } else {
                        Ok(EvalValue::Range {
                            values: new_values,
                            rows: 1,
                            cols: new_cols,
                        })
                    }
                } else {
                    let new_rows = kept_indices.len();
                    let total_cells = new_rows.saturating_mul(orig_cols);
                    if total_cells > self.limits.max_range_cells {
                        return Err("resource_limit");
                    }
                    let mut new_values = Vec::with_capacity(total_cells);
                    for r in kept_indices {
                        let start = r * orig_cols;
                        let end = start + orig_cols;
                        new_values.extend_from_slice(&values[start..end]);
                    }
                    if new_rows == 1 && orig_cols == 1 {
                        Ok(EvalValue::Scalar(new_values.swap_remove(0)))
                    } else {
                        Ok(EvalValue::Range {
                            values: new_values,
                            rows: new_rows,
                            cols: orig_cols,
                        })
                    }
                }
            }
            "sort" if (1..=4).contains(&arguments.len()) => {
                if orig_rows <= 1 && orig_cols <= 1 {
                    return Ok(EvalValue::Scalar(
                        values.into_iter().next().unwrap_or(FormulaValue::Blank),
                    ));
                }
                let by_col = if arguments.len() >= 4 {
                    to_bool(&self.eval_scalar(&arguments[3], depth + 1)?)?
                } else {
                    false
                };
                let sort_index = if arguments.len() >= 2 {
                    to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.trunc() as i64
                } else {
                    1
                };
                let sort_order = if arguments.len() >= 3 {
                    to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?.trunc() as i64
                } else {
                    1
                };
                if sort_order != 1 && sort_order != -1 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                }
                let ascending = sort_order == 1;

                if by_col {
                    if sort_index < 1 || sort_index as usize > orig_rows {
                        return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                    }
                    let sort_row = (sort_index - 1) as usize;
                    let mut col_indices: Vec<usize> = (0..orig_cols).collect();
                    col_indices.sort_by(|&c1, &c2| {
                        let v1 = &values[sort_row * orig_cols + c1];
                        let v2 = &values[sort_row * orig_cols + c2];
                        let ord = compare_formula_values(v1, v2);
                        if ascending { ord } else { ord.reverse() }
                    });
                    let mut new_values = Vec::with_capacity(values.len());
                    for r in 0..orig_rows {
                        for &c in &col_indices {
                            new_values.push(values[r * orig_cols + c].clone());
                        }
                    }
                    if orig_rows == 1 && orig_cols == 1 {
                        Ok(EvalValue::Scalar(new_values.swap_remove(0)))
                    } else {
                        Ok(EvalValue::Range {
                            values: new_values,
                            rows: orig_rows,
                            cols: orig_cols,
                        })
                    }
                } else {
                    if sort_index < 1 || sort_index as usize > orig_cols {
                        return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                    }
                    let sort_col = (sort_index - 1) as usize;
                    let mut row_indices: Vec<usize> = (0..orig_rows).collect();
                    row_indices.sort_by(|&r1, &r2| {
                        let v1 = &values[r1 * orig_cols + sort_col];
                        let v2 = &values[r2 * orig_cols + sort_col];
                        let ord = compare_formula_values(v1, v2);
                        if ascending { ord } else { ord.reverse() }
                    });
                    let mut new_values = Vec::with_capacity(values.len());
                    for &r in &row_indices {
                        let start = r * orig_cols;
                        new_values.extend_from_slice(&values[start..start + orig_cols]);
                    }
                    if orig_rows == 1 && orig_cols == 1 {
                        Ok(EvalValue::Scalar(new_values.swap_remove(0)))
                    } else {
                        Ok(EvalValue::Range {
                            values: new_values,
                            rows: orig_rows,
                            cols: orig_cols,
                        })
                    }
                }
            }
            "sortby" if (2..=3).contains(&arguments.len()) => {
                let by_eval = self.evaluate(&arguments[1], depth + 1)?;
                let (by_vals, _, _) = match by_eval {
                    EvalValue::Scalar(s) => (vec![s], 1, 1),
                    EvalValue::Range { values, rows, cols } => (values, rows, cols),
                };
                let sort_order = if arguments.len() == 3 {
                    to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?.trunc() as i64
                } else {
                    1
                };
                if sort_order != 1 && sort_order != -1 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                }
                let ascending = sort_order == 1;

                let by_cols_mode = orig_rows == 1 && orig_cols > 1 && by_vals.len() == orig_cols;
                if !by_cols_mode && by_vals.len() != orig_rows {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                }

                if by_cols_mode {
                    let mut col_indices: Vec<usize> = (0..orig_cols).collect();
                    col_indices.sort_by(|&c1, &c2| {
                        let ord = compare_formula_values(&by_vals[c1], &by_vals[c2]);
                        if ascending { ord } else { ord.reverse() }
                    });
                    let mut new_values = Vec::with_capacity(values.len());
                    for &c in &col_indices {
                        new_values.push(values[c].clone());
                    }
                    if orig_cols == 1 {
                        Ok(EvalValue::Scalar(new_values.swap_remove(0)))
                    } else {
                        Ok(EvalValue::Range {
                            values: new_values,
                            rows: 1,
                            cols: orig_cols,
                        })
                    }
                } else {
                    let mut row_indices: Vec<usize> = (0..orig_rows).collect();
                    row_indices.sort_by(|&r1, &r2| {
                        let ord = compare_formula_values(&by_vals[r1], &by_vals[r2]);
                        if ascending { ord } else { ord.reverse() }
                    });
                    let mut new_values = Vec::with_capacity(values.len());
                    for &r in &row_indices {
                        let start = r * orig_cols;
                        new_values.extend_from_slice(&values[start..start + orig_cols]);
                    }
                    if orig_rows == 1 && orig_cols == 1 {
                        Ok(EvalValue::Scalar(new_values.swap_remove(0)))
                    } else {
                        Ok(EvalValue::Range {
                            values: new_values,
                            rows: orig_rows,
                            cols: orig_cols,
                        })
                    }
                }
            }
            "unique" if (1..=3).contains(&arguments.len()) => {
                let by_col = if arguments.len() >= 2 {
                    to_bool(&self.eval_scalar(&arguments[1], depth + 1)?)?
                } else {
                    false
                };
                let exactly_once = if arguments.len() == 3 {
                    to_bool(&self.eval_scalar(&arguments[2], depth + 1)?)?
                } else {
                    false
                };

                if by_col {
                    let mut seen_cols: Vec<usize> = Vec::new();
                    for c1 in 0..orig_cols {
                        let total_count = (0..orig_cols)
                            .filter(|&c2| {
                                (0..orig_rows).all(|r| {
                                    values[r * orig_cols + c1] == values[r * orig_cols + c2]
                                })
                            })
                            .count();
                        let already_seen = seen_cols.iter().any(|&c_prev| {
                            (0..orig_rows).all(|r| {
                                values[r * orig_cols + c1] == values[r * orig_cols + c_prev]
                            })
                        });
                        if (!already_seen && !exactly_once) || (exactly_once && total_count == 1) {
                            seen_cols.push(c1);
                        }
                    }
                    if seen_cols.is_empty() {
                        return Ok(EvalValue::Scalar(FormulaValue::Error("#CALC!".into())));
                    }
                    let new_cols = seen_cols.len();
                    let mut new_values = Vec::with_capacity(orig_rows * new_cols);
                    for r in 0..orig_rows {
                        for &c in &seen_cols {
                            new_values.push(values[r * orig_cols + c].clone());
                        }
                    }
                    if orig_rows == 1 && new_cols == 1 {
                        Ok(EvalValue::Scalar(new_values.swap_remove(0)))
                    } else {
                        Ok(EvalValue::Range {
                            values: new_values,
                            rows: orig_rows,
                            cols: new_cols,
                        })
                    }
                } else {
                    let mut seen_rows: Vec<usize> = Vec::new();
                    for r1 in 0..orig_rows {
                        let total_count = (0..orig_rows)
                            .filter(|&r2| {
                                let s1 = r1 * orig_cols;
                                let s2 = r2 * orig_cols;
                                values[s1..s1 + orig_cols] == values[s2..s2 + orig_cols]
                            })
                            .count();
                        let already_seen = seen_rows.iter().any(|&r_prev| {
                            let s1 = r1 * orig_cols;
                            let sp = r_prev * orig_cols;
                            values[s1..s1 + orig_cols] == values[sp..sp + orig_cols]
                        });
                        if (!already_seen && !exactly_once) || (exactly_once && total_count == 1) {
                            seen_rows.push(r1);
                        }
                    }
                    if seen_rows.is_empty() {
                        return Ok(EvalValue::Scalar(FormulaValue::Error("#CALC!".into())));
                    }
                    let new_rows = seen_rows.len();
                    let mut new_values = Vec::with_capacity(new_rows * orig_cols);
                    for &r in &seen_rows {
                        let s = r * orig_cols;
                        new_values.extend_from_slice(&values[s..s + orig_cols]);
                    }
                    if new_rows == 1 && orig_cols == 1 {
                        Ok(EvalValue::Scalar(new_values.swap_remove(0)))
                    } else {
                        Ok(EvalValue::Range {
                            values: new_values,
                            rows: new_rows,
                            cols: orig_cols,
                        })
                    }
                }
            }
            _ => Err("unsupported"),
        }
    }

    fn lookup(
        &self,
        sheet: Option<&str>,
        address: CellAddress,
    ) -> Result<FormulaValue, &'static str> {
        let sheet = sheet.or(self.current_sheet);
        let Some(cell) = self.cells.iter().find(|cell| {
            cell.row == Some(address.row)
                && cell.column == Some(address.column)
                && sheet.is_none_or(|name| cell.sheet_name.eq_ignore_ascii_case(name))
        }) else {
            return Ok(FormulaValue::Blank);
        };
        if cell.formula.is_some() {
            return Err("unresolved_reference");
        }
        let value = cell.value.as_deref().or(cell.stored_value.as_deref());
        let Some(value) = value else {
            return Ok(FormulaValue::Blank);
        };
        match cell.cell_type.to_ascii_lowercase().as_str() {
            "b" | "boolean" => Ok(FormulaValue::Boolean(
                value.eq_ignore_ascii_case("1") || value.eq_ignore_ascii_case("true"),
            )),
            "s" | "str" | "inlinestr" | "inline_str" | "inline_string" | "string" => {
                Ok(FormulaValue::String(value.to_owned()))
            }
            "e" | "error" => Ok(FormulaValue::Error(value.to_owned())),
            _ => value
                .parse::<f64>()
                .map(FormulaValue::Number)
                .map_err(|_| "unresolved_reference"),
        }
    }

    fn record_reference(&mut self, reference: &str) {
        if self.references.len() >= self.limits.max_range_cells.min(4096) {
            self.references_truncated = true;
        } else {
            self.references.push(reference.to_owned());
        }
    }

    fn check_string_size(&self, value: &str) -> Result<(), &'static str> {
        (value.len() <= self.limits.max_string_bytes)
            .then_some(())
            .ok_or("resource_limit")
    }
}

fn to_number(value: &FormulaValue) -> Result<f64, &'static str> {
    match value {
        FormulaValue::Number(value) if value.is_finite() => Ok(*value),
        FormulaValue::Boolean(value) => Ok(if *value { 1.0 } else { 0.0 }),
        FormulaValue::Blank => Ok(0.0),
        FormulaValue::String(value) => value.trim().parse::<f64>().map_err(|_| "unsupported"),
        FormulaValue::Error(_) => Err("unresolved_reference"),
        FormulaValue::Number(_) => Err("unsupported"),
    }
}

fn to_bool(value: &FormulaValue) -> Result<bool, &'static str> {
    match value {
        FormulaValue::Boolean(value) => Ok(*value),
        FormulaValue::Number(value) => Ok(*value != 0.0),
        FormulaValue::Blank => Ok(false),
        FormulaValue::String(value) if value.eq_ignore_ascii_case("true") => Ok(true),
        FormulaValue::String(value) if value.eq_ignore_ascii_case("false") => Ok(false),
        _ => Err("unsupported"),
    }
}

fn to_string(value: &FormulaValue) -> Result<String, &'static str> {
    Ok(match value {
        FormulaValue::Number(value) if value.is_finite() => value.to_string(),
        FormulaValue::String(value) => value.clone(),
        FormulaValue::Boolean(value) => value.to_string().to_ascii_uppercase(),
        FormulaValue::Blank => String::new(),
        FormulaValue::Error(_) => return Err("unresolved_reference"),
        FormulaValue::Number(_) => return Err("unsupported"),
    })
}

fn nonnegative_count(value: &FormulaValue) -> Result<usize, &'static str> {
    let value = to_number(value)?;
    if !value.is_finite() || value < 0.0 || value > usize::MAX as f64 || value.fract() != 0.0 {
        return Err("unsupported");
    }
    Ok(value as usize)
}

fn values_equal(left: &FormulaValue, right: &FormulaValue) -> bool {
    match (left, right) {
        (FormulaValue::Number(a), FormulaValue::Number(b)) => (a - b).abs() < f64::EPSILON,
        (FormulaValue::String(a), FormulaValue::String(b)) => a.eq_ignore_ascii_case(b),
        (FormulaValue::Boolean(a), FormulaValue::Boolean(b)) => a == b,
        (FormulaValue::Blank, FormulaValue::Blank) => true,
        (FormulaValue::Error(a), FormulaValue::Error(b)) => a.eq_ignore_ascii_case(b),
        (FormulaValue::String(s), FormulaValue::Number(n))
        | (FormulaValue::Number(n), FormulaValue::String(s)) => {
            if let Ok(parsed) = s.trim().parse::<f64>() {
                (parsed - n).abs() < f64::EPSILON
            } else {
                false
            }
        }
        _ => false,
    }
}

fn values_less_than_or_equal(left: &FormulaValue, right: &FormulaValue) -> bool {
    match (to_number(left), to_number(right)) {
        (Ok(a), Ok(b)) => a <= b,
        _ => match (to_string(left), to_string(right)) {
            (Ok(a), Ok(b)) => a.to_ascii_lowercase() <= b.to_ascii_lowercase(),
            _ => false,
        },
    }
}

fn values_greater_than_or_equal(left: &FormulaValue, right: &FormulaValue) -> bool {
    match (to_number(left), to_number(right)) {
        (Ok(a), Ok(b)) => a >= b,
        _ => match (to_string(left), to_string(right)) {
            (Ok(a), Ok(b)) => a.to_ascii_lowercase() >= b.to_ascii_lowercase(),
            _ => false,
        },
    }
}

fn matches_lookup(pattern: &FormulaValue, candidate: &FormulaValue, match_mode: i32) -> bool {
    match match_mode {
        0 => values_equal(pattern, candidate),
        -1 => values_less_than_or_equal(candidate, pattern),
        1 => values_greater_than_or_equal(candidate, pattern),
        2 => {
            if let (Ok(pat), Ok(cand)) = (to_string(pattern), to_string(candidate)) {
                wildcard_match(&pat.to_ascii_lowercase(), &cand.to_ascii_lowercase())
            } else {
                values_equal(pattern, candidate)
            }
        }
        _ => false,
    }
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p_bytes = pattern.as_bytes();
    let t_bytes = text.as_bytes();
    let mut p = 0;
    let mut t = 0;
    let mut star_idx = None;
    let mut match_idx = 0;

    while t < t_bytes.len() {
        if p < p_bytes.len() && (p_bytes[p] == b'?' || p_bytes[p] == t_bytes[t]) {
            p += 1;
            t += 1;
        } else if p < p_bytes.len() && p_bytes[p] == b'*' {
            star_idx = Some(p);
            p += 1;
            match_idx = t;
        } else if let Some(star) = star_idx {
            p = star + 1;
            match_idx += 1;
            t = match_idx;
        } else {
            return false;
        }
    }
    while p < p_bytes.len() && p_bytes[p] == b'*' {
        p += 1;
    }
    p == p_bytes.len()
}

fn proper(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut capitalize_next = true;
    for c in text.chars() {
        if c.is_alphabetic() {
            if capitalize_next {
                for upper in c.to_uppercase() {
                    result.push(upper);
                }
                capitalize_next = false;
            } else {
                for lower in c.to_lowercase() {
                    result.push(lower);
                }
            }
        } else {
            capitalize_next = true;
            result.push(c);
        }
    }
    result
}

fn unichar(code: f64) -> FormulaValue {
    if !code.is_finite() || code.fract() != 0.0 {
        return FormulaValue::Error("#VALUE!".into());
    }
    let n = code as i64;
    if !(1..=0x10FFFF).contains(&n) || (0xD800..=0xDFFF).contains(&n) {
        return FormulaValue::Error("#VALUE!".into());
    }
    match char::from_u32(n as u32) {
        Some(c) => FormulaValue::String(c.to_string()),
        None => FormulaValue::Error("#VALUE!".into()),
    }
}

fn unicode(s: &str) -> FormulaValue {
    match s.chars().next() {
        Some(c) => FormulaValue::Number((c as u32) as f64),
        None => FormulaValue::Error("#VALUE!".into()),
    }
}

fn hex_to_dec(s: &str) -> FormulaValue {
    let s = s.trim();
    if s.is_empty() || s.len() > 10 {
        return FormulaValue::Error("#NUM!".into());
    }
    if !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return FormulaValue::Error("#NUM!".into());
    }
    let val = match u64::from_str_radix(s, 16) {
        Ok(v) => v,
        Err(_) => return FormulaValue::Error("#NUM!".into()),
    };
    if s.len() == 10 && (val & (1u64 << 39)) != 0 {
        let res = (val as f64) - ((1u64 << 40) as f64);
        FormulaValue::Number(res)
    } else {
        FormulaValue::Number(val as f64)
    }
}

fn dec_to_hex(number: f64, places: Option<f64>) -> FormulaValue {
    if !number.is_finite() || number.fract() != 0.0 {
        return FormulaValue::Error("#NUM!".into());
    }
    let n = number as i64;
    if !(-549_755_813_888..=549_755_813_887).contains(&n) {
        return FormulaValue::Error("#NUM!".into());
    }
    if n < 0 {
        let val = ((1i64 << 40) + n) as u64;
        let s = format!("{:010X}", val);
        FormulaValue::String(s)
    } else {
        let s = format!("{:X}", n);
        if let Some(p) = places {
            if !p.is_finite() || p.fract() != 0.0 {
                return FormulaValue::Error("#NUM!".into());
            }
            let p = p as i64;
            if !(1..=10).contains(&p) {
                return FormulaValue::Error("#NUM!".into());
            }
            let p = p as usize;
            if s.len() > p {
                return FormulaValue::Error("#NUM!".into());
            }
            let padded = format!("{:0>width$}", s, width = p);
            FormulaValue::String(padded)
        } else {
            FormulaValue::String(s)
        }
    }
}

fn bin_to_dec(s: &str) -> FormulaValue {
    let s = s.trim();
    if s.is_empty() || s.len() > 10 {
        return FormulaValue::Error("#NUM!".into());
    }
    if !s.chars().all(|c| c == '0' || c == '1') {
        return FormulaValue::Error("#NUM!".into());
    }
    let val = match u64::from_str_radix(s, 2) {
        Ok(v) => v,
        Err(_) => return FormulaValue::Error("#NUM!".into()),
    };
    if s.len() == 10 && (val & (1u64 << 9)) != 0 {
        let res = (val as f64) - 1024.0;
        FormulaValue::Number(res)
    } else {
        FormulaValue::Number(val as f64)
    }
}

fn dec_to_bin(number: f64, places: Option<f64>) -> FormulaValue {
    if !number.is_finite() || number.fract() != 0.0 {
        return FormulaValue::Error("#NUM!".into());
    }
    let n = number as i64;
    if !(-512..=511).contains(&n) {
        return FormulaValue::Error("#NUM!".into());
    }
    if n < 0 {
        let val = ((1i64 << 10) + n) as u64;
        let s = format!("{:010b}", val);
        FormulaValue::String(s)
    } else {
        let s = format!("{:b}", n);
        if let Some(p) = places {
            if !p.is_finite() || p.fract() != 0.0 {
                return FormulaValue::Error("#NUM!".into());
            }
            let p = p as i64;
            if !(1..=10).contains(&p) {
                return FormulaValue::Error("#NUM!".into());
            }
            let p = p as usize;
            if s.len() > p {
                return FormulaValue::Error("#NUM!".into());
            }
            let padded = format!("{:0>width$}", s, width = p);
            FormulaValue::String(padded)
        } else {
            FormulaValue::String(s)
        }
    }
}

fn oct_to_dec(s: &str) -> FormulaValue {
    let s = s.trim();
    if s.is_empty() || s.len() > 10 {
        return FormulaValue::Error("#NUM!".into());
    }
    if !s.chars().all(|c| ('0'..='7').contains(&c)) {
        return FormulaValue::Error("#NUM!".into());
    }
    let val = match u64::from_str_radix(s, 8) {
        Ok(v) => v,
        Err(_) => return FormulaValue::Error("#NUM!".into()),
    };
    if s.len() == 10 && (val & (1u64 << 29)) != 0 {
        let res = (val as f64) - ((1u64 << 30) as f64);
        FormulaValue::Number(res)
    } else {
        FormulaValue::Number(val as f64)
    }
}

fn dec_to_oct(number: f64, places: Option<f64>) -> FormulaValue {
    if !number.is_finite() || number.fract() != 0.0 {
        return FormulaValue::Error("#NUM!".into());
    }
    let n = number as i64;
    if !(-536_870_912..=536_870_911).contains(&n) {
        return FormulaValue::Error("#NUM!".into());
    }
    if n < 0 {
        let val = ((1i64 << 30) + n) as u64;
        let s = format!("{:010o}", val);
        FormulaValue::String(s)
    } else {
        let s = format!("{:o}", n);
        if let Some(p) = places {
            if !p.is_finite() || p.fract() != 0.0 {
                return FormulaValue::Error("#NUM!".into());
            }
            let p = p as i64;
            if !(1..=10).contains(&p) {
                return FormulaValue::Error("#NUM!".into());
            }
            let p = p as usize;
            if s.len() > p {
                return FormulaValue::Error("#NUM!".into());
            }
            let padded = format!("{:0>width$}", s, width = p);
            FormulaValue::String(padded)
        } else {
            FormulaValue::String(s)
        }
    }
}

fn base_to_str(num: f64, radix: f64, min_length: Option<f64>) -> FormulaValue {
    if !num.is_finite() || !(0.0..=9_007_199_254_740_992.0).contains(&num) || !radix.is_finite() {
        return FormulaValue::Error("#NUM!".into());
    }
    let radix_i = radix.trunc() as i64;
    if !(2..=36).contains(&radix_i) {
        return FormulaValue::Error("#NUM!".into());
    }
    let min_len = if let Some(ml) = min_length {
        if !ml.is_finite() || !(0.0..=255.0).contains(&ml) {
            return FormulaValue::Error("#NUM!".into());
        }
        ml.trunc() as usize
    } else {
        0
    };

    let mut n = num.trunc() as u64;
    let mut chars = Vec::new();
    if n == 0 {
        chars.push('0');
    } else {
        while n > 0 {
            let rem = (n % radix_i as u64) as u8;
            let ch = if rem < 10 {
                (b'0' + rem) as char
            } else {
                (b'A' + (rem - 10)) as char
            };
            chars.push(ch);
            n /= radix_i as u64;
        }
        chars.reverse();
    }

    let mut s: String = chars.into_iter().collect();
    if s.len() < min_len {
        let pad = "0".repeat(min_len - s.len());
        s = format!("{pad}{s}");
    }
    FormulaValue::String(s)
}

fn decimal_from_base(text: &str, radix: f64) -> FormulaValue {
    if !radix.is_finite() {
        return FormulaValue::Error("#NUM!".into());
    }
    let radix_i = radix.trunc() as i64;
    if !(2..=36).contains(&radix_i) {
        return FormulaValue::Error("#NUM!".into());
    }
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return FormulaValue::Error("#NUM!".into());
    }

    let mut acc = 0.0f64;
    for ch in trimmed.chars() {
        let digit = match ch {
            '0'..='9' => (ch as u8 - b'0') as i64,
            'a'..='z' => (ch as u8 - b'a' + 10) as i64,
            'A'..='Z' => (ch as u8 - b'A' + 10) as i64,
            _ => return FormulaValue::Error("#NUM!".into()),
        };
        if digit >= radix_i {
            return FormulaValue::Error("#NUM!".into());
        }
        acc = acc * (radix_i as f64) + (digit as f64);
        if acc > 9_007_199_254_740_992.0 {
            return FormulaValue::Error("#NUM!".into());
        }
    }
    FormulaValue::Number(acc)
}

fn compare_formula_values(a: &FormulaValue, b: &FormulaValue) -> std::cmp::Ordering {
    fn type_rank(v: &FormulaValue) -> u8 {
        match v {
            FormulaValue::Number(_) => 1,
            FormulaValue::String(_) => 2,
            FormulaValue::Boolean(_) => 3,
            FormulaValue::Error(_) => 4,
            FormulaValue::Blank => 5,
        }
    }
    let ra = type_rank(a);
    let rb = type_rank(b);
    if ra != rb {
        return ra.cmp(&rb);
    }
    match (a, b) {
        (FormulaValue::Number(x), FormulaValue::Number(y)) => {
            x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal)
        }
        (FormulaValue::String(x), FormulaValue::String(y)) => {
            x.to_ascii_lowercase().cmp(&y.to_ascii_lowercase())
        }
        (FormulaValue::Boolean(x), FormulaValue::Boolean(y)) => x.cmp(y),
        (FormulaValue::Error(x), FormulaValue::Error(y)) => x.cmp(y),
        (FormulaValue::Blank, FormulaValue::Blank) => std::cmp::Ordering::Equal,
        _ => std::cmp::Ordering::Equal,
    }
}

fn format_formula_value_text(value: &FormulaValue, strict: bool) -> String {
    match value {
        FormulaValue::String(s) => {
            if strict {
                format!("\"{}\"", s.replace('"', "\"\""))
            } else {
                s.clone()
            }
        }
        FormulaValue::Number(n) => {
            if n.fract() == 0.0 && n.abs() < 1e15 {
                format!("{:.0}", n)
            } else {
                n.to_string()
            }
        }
        FormulaValue::Boolean(b) => {
            if *b {
                "TRUE".into()
            } else {
                "FALSE".into()
            }
        }
        FormulaValue::Blank => String::new(),
        FormulaValue::Error(e) => e.clone(),
    }
}

fn evaluate_binary(
    left: &FormulaValue,
    operator: &str,
    right: &FormulaValue,
    max_string_bytes: usize,
) -> Result<FormulaValue, &'static str> {
    if let (FormulaValue::Error(error), _) | (_, FormulaValue::Error(error)) = (left, right) {
        return Ok(FormulaValue::Error(error.clone()));
    }
    match operator {
        "&" => {
            let mut value = to_string(left)?;
            value.push_str(&to_string(right)?);
            if value.len() > max_string_bytes {
                return Err("resource_limit");
            }
            Ok(FormulaValue::String(value))
        }
        "=" | "<>" | "<" | ">" | "<=" | ">=" => {
            let comparison = match (to_number(left), to_number(right)) {
                (Ok(left), Ok(right)) => left.partial_cmp(&right),
                _ => {
                    let left = to_string(left)?;
                    let right = to_string(right)?;
                    left.partial_cmp(&right)
                }
            };
            let Some(comparison) = comparison else {
                return Err("unsupported");
            };
            let result = match operator {
                "=" => comparison.is_eq(),
                "<>" => comparison.is_ne(),
                "<" => comparison.is_lt(),
                ">" => comparison.is_gt(),
                "<=" => comparison.is_le(),
                ">=" => comparison.is_ge(),
                _ => unreachable!(),
            };
            Ok(FormulaValue::Boolean(result))
        }
        "+" | "-" | "*" | "/" | "^" => {
            let left = to_number(left)?;
            let right = to_number(right)?;
            let value = match operator {
                "+" => left + right,
                "-" => left - right,
                "*" => left * right,
                "/" if right != 0.0 => left / right,
                "/" => return Ok(FormulaValue::Error("#DIV/0!".into())),
                "^" => left.powf(right),
                _ => unreachable!(),
            };
            value
                .is_finite()
                .then_some(FormulaValue::Number(value))
                .ok_or("unsupported")
        }
        _ => Err("unsupported"),
    }
}

fn to_roman(mut num: i64) -> FormulaValue {
    if !(1..=3999).contains(&num) {
        return FormulaValue::Error("#VALUE!".into());
    }
    const ROMAN_SYMBOLS: &[(i64, &str)] = &[
        (1000, "M"),
        (900, "CM"),
        (500, "D"),
        (400, "CD"),
        (100, "C"),
        (90, "XC"),
        (50, "L"),
        (40, "XL"),
        (10, "X"),
        (9, "IX"),
        (5, "V"),
        (4, "IV"),
        (1, "I"),
    ];
    let mut result = String::new();
    for &(val, sym) in ROMAN_SYMBOLS {
        while num >= val {
            result.push_str(sym);
            num -= val;
        }
    }
    FormulaValue::String(result)
}

fn from_roman(raw: &str) -> FormulaValue {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return FormulaValue::Number(0.0);
    }
    let (is_negative, content) = if let Some(stripped) = trimmed.strip_prefix('-') {
        (true, stripped.trim())
    } else {
        (false, trimmed)
    };
    if content.is_empty() {
        return FormulaValue::Error("#VALUE!".into());
    }
    let mut total: i64 = 0;
    let mut prev: i64 = 0;
    for ch in content.chars().rev() {
        let val = match ch.to_ascii_uppercase() {
            'I' => 1,
            'V' => 5,
            'X' => 10,
            'L' => 50,
            'C' => 100,
            'D' => 500,
            'M' => 1000,
            _ => return FormulaValue::Error("#VALUE!".into()),
        };
        if val < prev {
            total -= val;
        } else {
            total += val;
            prev = val;
        }
    }
    let res = if is_negative { -total } else { total };
    FormulaValue::Number(res as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cell(reference: &str, value: &str, cell_type: &str) -> WorkbookCellInfo {
        let address = parse_cell_address(reference).unwrap();
        WorkbookCellInfo {
            sheet_index: 0,
            sheet_name: "Data".into(),
            cell_ref: reference.into(),
            row: Some(address.row),
            column: Some(address.column),
            cell_type: cell_type.into(),
            value: Some(value.into()),
            ..WorkbookCellInfo::default()
        }
    }

    #[test]
    fn evaluates_bounded_arithmetic_and_cell_references() {
        let cells = [cell("A1", "2", "n"), cell("B1", "3", "n")];
        let result = evaluate_formula("=A1+B1*4", Some("Data"), &cells, Default::default());
        assert_eq!(result.status, "resolved");
        assert_eq!(result.value, Some(FormulaValue::Number(14.0)));
        assert_eq!(result.references, vec!["A1", "B1"]);
    }

    #[test]
    fn evaluates_ranges_and_lazy_if() {
        let cells = [
            cell("A1", "1", "n"),
            cell("A2", "2", "n"),
            cell("A3", "3", "n"),
        ];
        let result = evaluate_formula(
            "=IF(SUM(A1:A3)=6,\"ok\",1/0)",
            Some("Data"),
            &cells,
            Default::default(),
        );
        assert_eq!(result.status, "resolved");
        assert_eq!(result.value, Some(FormulaValue::String("ok".into())));
    }

    #[test]
    fn evaluates_string_functions_and_sheet_qualified_reference() {
        let cells = [cell("A1", "hello", "str")];
        let result = evaluate_formula(
            "='Data'!A1&RIGHT(\"!\",1)",
            Some("Data"),
            &cells,
            Default::default(),
        );
        assert_eq!(result.status, "resolved");
        assert_eq!(result.value, Some(FormulaValue::String("hello!".into())));
    }

    #[test]
    fn leaves_formula_cells_and_unsupported_functions_unresolved() {
        let mut formula_cell = cell("A1", "2", "n");
        formula_cell.formula = Some("=1+1".into());
        let reference =
            evaluate_formula("=A1+1", Some("Data"), &[formula_cell], Default::default());
        assert_eq!(reference.status, "unresolved_reference");
        let unsupported =
            evaluate_formula("=FORECAST(1, 2, 3)", Some("Data"), &[], Default::default());
        assert_eq!(unsupported.status, "unsupported");
    }

    #[test]
    fn enforces_string_and_range_limits() {
        let cells = [cell("A1", "1", "n"), cell("A2", "2", "n")];
        let limits = FormulaEvaluationLimits {
            max_range_cells: 1,
            ..Default::default()
        };
        let result = evaluate_formula("=SUM(A1:A2)", Some("Data"), &cells, limits);
        assert_eq!(result.status, "resource_limit");
    }

    #[test]
    fn preserves_formula_boolean_and_error_literals() {
        let boolean = evaluate_formula("=IF(TRUE,1,1/0)", Some("Data"), &[], Default::default());
        assert_eq!(boolean.status, "resolved");
        assert_eq!(boolean.value, Some(FormulaValue::Number(1.0)));
        let error = evaluate_formula("=#N/A", Some("Data"), &[], Default::default());
        assert_eq!(error.status, "resolved");
        assert_eq!(error.value, Some(FormulaValue::Error("#N/A".into())));
    }

    #[test]
    fn rejects_top_level_ranges_and_out_of_grid_references() {
        let range = evaluate_formula("=A1:A2", Some("Data"), &[], Default::default());
        assert_eq!(range.status, "unsupported");
        let address = evaluate_formula("=XFE1", Some("Data"), &[], Default::default());
        assert_eq!(address.status, "unsupported");
    }

    #[test]
    fn evaluates_upper_lower_and_trim() {
        let cells = [cell("A1", "  Hello   World  ", "str")];
        let upper_res = evaluate_formula("=UPPER(A1)", Some("Data"), &cells, Default::default());
        assert_eq!(upper_res.status, "resolved");
        assert_eq!(
            upper_res.value,
            Some(FormulaValue::String("  HELLO   WORLD  ".into()))
        );

        let lower_res = evaluate_formula("=LOWER(A1)", Some("Data"), &cells, Default::default());
        assert_eq!(lower_res.status, "resolved");
        assert_eq!(
            lower_res.value,
            Some(FormulaValue::String("  hello   world  ".into()))
        );

        let trim_res = evaluate_formula("=TRIM(A1)", Some("Data"), &cells, Default::default());
        assert_eq!(trim_res.status, "resolved");
        assert_eq!(
            trim_res.value,
            Some(FormulaValue::String("Hello World".into()))
        );
    }

    #[test]
    fn evaluates_extended_math_logic_and_string_functions() {
        let cells = [
            cell("A1", "10", "n"),
            cell("A2", "3", "n"),
            cell("A3", "Excel", "str"),
            cell("A4", "#N/A", "e"),
        ];

        // TRUE() and FALSE()
        let t = evaluate_formula("=TRUE()", Some("Data"), &[], Default::default());
        assert_eq!(t.value, Some(FormulaValue::Boolean(true)));
        let f = evaluate_formula("=FALSE()", Some("Data"), &[], Default::default());
        assert_eq!(f.value, Some(FormulaValue::Boolean(false)));

        // IFERROR
        let iferr1 = evaluate_formula(
            "=IFERROR(1/0, \"fallback\")",
            Some("Data"),
            &[],
            Default::default(),
        );
        assert_eq!(iferr1.value, Some(FormulaValue::String("fallback".into())));
        let iferr2 = evaluate_formula(
            "=IFERROR(5*2, \"fallback\")",
            Some("Data"),
            &[],
            Default::default(),
        );
        assert_eq!(iferr2.value, Some(FormulaValue::Number(10.0)));

        // Information functions
        assert_eq!(
            evaluate_formula("=ISNUMBER(A1)", Some("Data"), &cells, Default::default()).value,
            Some(FormulaValue::Boolean(true))
        );
        assert_eq!(
            evaluate_formula("=ISBLANK(B10)", Some("Data"), &cells, Default::default()).value,
            Some(FormulaValue::Boolean(true))
        );
        assert_eq!(
            evaluate_formula("=ISERROR(1/0)", Some("Data"), &cells, Default::default()).value,
            Some(FormulaValue::Boolean(true))
        );
        assert_eq!(
            evaluate_formula("=ISNA(A4)", Some("Data"), &cells, Default::default()).value,
            Some(FormulaValue::Boolean(true))
        );
        assert_eq!(
            evaluate_formula("=ISTEXT(A3)", Some("Data"), &cells, Default::default()).value,
            Some(FormulaValue::Boolean(true))
        );
        assert_eq!(
            evaluate_formula(
                "=ISLOGICAL(TRUE())",
                Some("Data"),
                &cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Boolean(true))
        );

        // Math: INT, MOD, SIGN, SQRT, POWER
        assert_eq!(
            evaluate_formula("=INT(7.8)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Number(7.0))
        );
        assert_eq!(
            evaluate_formula("=MOD(10, 3)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Number(1.0))
        );
        assert_eq!(
            evaluate_formula("=SIGN(-42)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Number(-1.0))
        );
        assert_eq!(
            evaluate_formula("=SQRT(16)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Number(4.0))
        );
        assert_eq!(
            evaluate_formula("=POWER(2, 8)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Number(256.0))
        );

        // String: LEFT (1 & 2 args), RIGHT (1 & 2 args), CONCAT, EXACT, REPT
        assert_eq!(
            evaluate_formula("=LEFT(\"Macro\")", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::String("M".into()))
        );
        assert_eq!(
            evaluate_formula("=RIGHT(\"Macro\")", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::String("o".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=CONCAT(\"Foo\", \"Bar\", \"Baz\")",
                Some("Data"),
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::String("FooBarBaz".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=EXACT(\"test\", \"test\")",
                Some("Data"),
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::Boolean(true))
        );
        assert_eq!(
            evaluate_formula(
                "=EXACT(\"test\", \"Test\")",
                Some("Data"),
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::Boolean(false))
        );
        assert_eq!(
            evaluate_formula("=REPT(\"Abc\", 3)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::String("AbcAbcAbc".into()))
        );

        // ROUNDUP, ROUNDDOWN, TRUNC
        assert_eq!(
            evaluate_formula(
                "=ROUNDUP(12.3456, 2)",
                Some("Data"),
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(12.35))
        );
        assert_eq!(
            evaluate_formula(
                "=ROUNDDOWN(12.3456, 2)",
                Some("Data"),
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(12.34))
        );
        assert_eq!(
            evaluate_formula("=TRUNC(3.9)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Number(3.0))
        );

        // SUBSTITUTE, REPLACE
        assert_eq!(
            evaluate_formula(
                "=SUBSTITUTE(\"Sales Data\", \"Sales\", \"Cost\")",
                Some("Data"),
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::String("Cost Data".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=SUBSTITUTE(\"ababab\", \"b\", \"c\", 2)",
                Some("Data"),
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::String("abacab".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=REPLACE(\"ABCDEF\", 3, 2, \"123\")",
                Some("Data"),
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::String("AB123EF".into()))
        );
    }

    #[test]
    fn evaluates_advanced_control_string_and_information_functions() {
        let cells = [cell("A1", "65", "n"), cell("A2", "powershell", "str")];

        // Math: PI, EXP, LN, LOG10
        let pi_val = evaluate_formula("=PI()", Some("Data"), &[], Default::default()).value;
        if let Some(FormulaValue::Number(n)) = pi_val {
            assert!((n - std::f64::consts::PI).abs() < 1e-10);
        } else {
            panic!("Expected PI number, got {:?}", pi_val);
        }
        assert_eq!(
            evaluate_formula("=EXP(0)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Number(1.0))
        );
        assert_eq!(
            evaluate_formula("=LN(1)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Number(0.0))
        );
        assert_eq!(
            evaluate_formula("=LN(0)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Error("#NUM!".into()))
        );
        assert_eq!(
            evaluate_formula("=LOG10(100)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Number(2.0))
        );
        assert_eq!(
            evaluate_formula("=LOG10(-5)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Error("#NUM!".into()))
        );

        // Information: ISNONTEXT, TYPE
        assert_eq!(
            evaluate_formula("=ISNONTEXT(123)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Boolean(true))
        );
        assert_eq!(
            evaluate_formula(
                "=ISNONTEXT(\"hello\")",
                Some("Data"),
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::Boolean(false))
        );
        assert_eq!(
            evaluate_formula("=TYPE(123)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Number(1.0))
        );
        assert_eq!(
            evaluate_formula("=TYPE(\"hello\")", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Number(2.0))
        );
        assert_eq!(
            evaluate_formula("=TYPE(TRUE())", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Number(4.0))
        );
        assert_eq!(
            evaluate_formula("=TYPE(1/0)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Number(16.0))
        );

        // Control: CHOOSE, IFNA, IFS, SWITCH
        assert_eq!(
            evaluate_formula(
                "=CHOOSE(2, \"apple\", \"banana\", \"cherry\")",
                Some("Data"),
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::String("banana".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=CHOOSE(4, \"apple\", \"banana\")",
                Some("Data"),
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::Error("#VALUE!".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=IFNA(#N/A, \"alt\")",
                Some("Data"),
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::String("alt".into()))
        );
        assert_eq!(
            evaluate_formula("=IFNA(1/0, \"alt\")", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Error("#DIV/0!".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=IFS(1=2, \"first\", 2=2, \"second\", 3=3, \"third\")",
                Some("Data"),
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::String("second".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=IFS(1=2, \"first\", 2=3, \"second\")",
                Some("Data"),
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::Error("#N/A".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=SWITCH(2, 1, \"one\", 2, \"two\", \"none\")",
                Some("Data"),
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::String("two".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=SWITCH(9, 1, \"one\", 2, \"two\", \"none\")",
                Some("Data"),
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::String("none".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=SWITCH(9, 1, \"one\", 2, \"two\")",
                Some("Data"),
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::Error("#N/A".into()))
        );

        // String: CHAR, CODE, CLEAN, T, N, FIND, SEARCH
        assert_eq!(
            evaluate_formula("=CHAR(A1)", Some("Data"), &cells, Default::default()).value,
            Some(FormulaValue::String("A".into()))
        );
        assert_eq!(
            evaluate_formula("=CODE(\"Apple\")", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Number(65.0))
        );
        assert_eq!(
            evaluate_formula(
                "=CLEAN(\"A\"&CHAR(7)&\"B\")",
                Some("Data"),
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::String("AB".into()))
        );
        assert_eq!(
            evaluate_formula("=T(\"text\")", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::String("text".into()))
        );
        assert_eq!(
            evaluate_formula("=T(123)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::String("".into()))
        );
        assert_eq!(
            evaluate_formula("=N(42)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Number(42.0))
        );
        assert_eq!(
            evaluate_formula("=N(TRUE())", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Number(1.0))
        );
        assert_eq!(
            evaluate_formula("=N(\"hello\")", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Number(0.0))
        );
        assert_eq!(
            evaluate_formula(
                "=FIND(\"bar\", \"foobarbaz\")",
                Some("Data"),
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(4.0))
        );
        assert_eq!(
            evaluate_formula(
                "=FIND(\"BAR\", \"foobarbaz\")",
                Some("Data"),
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::Error("#VALUE!".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=SEARCH(\"BAR\", \"foobarbaz\")",
                Some("Data"),
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(4.0))
        );

        // De-obfuscation sample: CHAR concatenation creating "cmd.exe"
        assert_eq!(
            evaluate_formula(
                "=CHAR(99)&CHAR(109)&CHAR(100)&CHAR(46)&CHAR(101)&CHAR(120)&CHAR(101)",
                Some("Data"),
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::String("cmd.exe".into()))
        );

        // HYPERLINK function
        assert_eq!(
            evaluate_formula(
                "=HYPERLINK(\"http://example.com/test.exe\", \"Click\")",
                Some("Data"),
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::String("http://example.com/test.exe".into()))
        );
    }

    #[test]
    fn evaluates_radix_unicode_lookup_and_data_functions() {
        let cells = vec![
            cell("A1", "10", "n"),
            cell("B1", "20", "n"),
            cell("C1", "30", "n"),
            cell("A2", "40", "n"),
            cell("B2", "50", "n"),
            cell("C2", "60", "n"),
            cell("A3", "cmd", "s"),
            cell("B3", "powershell", "s"),
            cell("C3", "calc", "s"),
        ];

        // Radix conversions
        assert_eq!(
            evaluate_formula("=HEX2DEC(\"FF\")", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Number(255.0))
        );
        assert_eq!(
            evaluate_formula("=HEX2DEC(\"A\")", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Number(10.0))
        );
        assert_eq!(
            evaluate_formula(
                "=HEX2DEC(\"FFFFFFFFFF\")",
                Some("Data"),
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(-1.0))
        );
        assert_eq!(
            evaluate_formula("=DEC2HEX(255)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::String("FF".into()))
        );
        assert_eq!(
            evaluate_formula("=DEC2HEX(10, 4)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::String("000A".into()))
        );
        assert_eq!(
            evaluate_formula("=DEC2HEX(-1)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::String("FFFFFFFFFF".into()))
        );
        assert_eq!(
            evaluate_formula("=BIN2DEC(\"1101\")", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Number(13.0))
        );
        assert_eq!(
            evaluate_formula("=DEC2BIN(13)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::String("1101".into()))
        );
        assert_eq!(
            evaluate_formula("=DEC2BIN(5, 4)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::String("0101".into()))
        );
        assert_eq!(
            evaluate_formula("=OCT2DEC(\"77\")", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Number(63.0))
        );
        assert_eq!(
            evaluate_formula("=DEC2OCT(63)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::String("77".into()))
        );

        // Unicode functions
        assert_eq!(
            evaluate_formula("=UNICHAR(65)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::String("A".into()))
        );
        assert_eq!(
            evaluate_formula("=UNICHAR(12354)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::String("あ".into()))
        );
        assert_eq!(
            evaluate_formula("=UNICHAR(0)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Error("#VALUE!".into()))
        );
        assert_eq!(
            evaluate_formula("=UNICODE(\"Apple\")", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Number(65.0))
        );
        assert_eq!(
            evaluate_formula("=UNICODE(\"あ\")", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Number(12354.0))
        );

        // String: PROPER, TEXTJOIN
        assert_eq!(
            evaluate_formula(
                "=PROPER(\"hello world-wide\")",
                Some("Data"),
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::String("Hello World-Wide".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=TEXTJOIN(\";\", TRUE, \"a\", \"\", \"b\", \"c\")",
                Some("Data"),
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::String("a;b;c".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=TEXTJOIN(\"-\", FALSE, \"a\", \"\", \"b\")",
                Some("Data"),
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::String("a--b".into()))
        );

        // Logic & Math: XOR, PRODUCT, QUOTIENT, LOG
        assert_eq!(
            evaluate_formula("=XOR(TRUE, FALSE)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Boolean(true))
        );
        assert_eq!(
            evaluate_formula("=XOR(TRUE, TRUE)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Boolean(false))
        );
        assert_eq!(
            evaluate_formula(
                "=XOR(TRUE, TRUE, TRUE)",
                Some("Data"),
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::Boolean(true))
        );
        assert_eq!(
            evaluate_formula("=PRODUCT(2, 3, 4)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Number(24.0))
        );
        assert_eq!(
            evaluate_formula("=PRODUCT(A1:B1)", Some("Data"), &cells, Default::default()).value,
            Some(FormulaValue::Number(200.0))
        );
        assert_eq!(
            evaluate_formula("=QUOTIENT(10, 3)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Number(3.0))
        );
        assert_eq!(
            evaluate_formula("=QUOTIENT(10, 0)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Error("#DIV/0!".into()))
        );
        assert_eq!(
            evaluate_formula("=LOG(100)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Number(2.0))
        );
        assert_eq!(
            evaluate_formula("=LOG(8, 2)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::Number(3.0))
        );

        // Lookup: INDEX, MATCH, VLOOKUP, HLOOKUP
        assert_eq!(
            evaluate_formula("=INDEX(A1:C1, 2)", Some("Data"), &cells, Default::default()).value,
            Some(FormulaValue::Number(20.0))
        );
        assert_eq!(
            evaluate_formula("=INDEX(A1:A3, 3)", Some("Data"), &cells, Default::default()).value,
            Some(FormulaValue::String("cmd".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=INDEX(A1:C2, 2, 3)",
                Some("Data"),
                &cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(60.0))
        );
        assert_eq!(
            evaluate_formula(
                "=INDEX(A1:C2, 5, 1)",
                Some("Data"),
                &cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Error("#REF!".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=MATCH(20, A1:C1, 0)",
                Some("Data"),
                &cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(2.0))
        );
        assert_eq!(
            evaluate_formula(
                "=MATCH(\"powershell\", A3:C3, 0)",
                Some("Data"),
                &cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(2.0))
        );
        assert_eq!(
            evaluate_formula(
                "=MATCH(\"unknown\", A3:C3, 0)",
                Some("Data"),
                &cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Error("#N/A".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=VLOOKUP(40, A1:C2, 2, FALSE)",
                Some("Data"),
                &cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(50.0))
        );
        assert_eq!(
            evaluate_formula(
                "=VLOOKUP(40, A1:C2, 9, FALSE)",
                Some("Data"),
                &cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Error("#REF!".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=HLOOKUP(\"powershell\", A3:C3, 1, FALSE)",
                Some("Data"),
                &cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("powershell".into()))
        );

        // Obfuscation evasion sample: radix + unichar + lookup
        assert_eq!(
            evaluate_formula(
                "=INDEX(A3:C3, 1) & \".\" & UNICHAR(HEX2DEC(\"65\")) & UNICHAR(HEX2DEC(\"78\")) & UNICHAR(HEX2DEC(\"65\"))",
                Some("Data"),
                &cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("cmd.exe".into()))
        );
    }

    fn cell_on_sheet(
        sheet: &str,
        reference: &str,
        value: &str,
        cell_type: &str,
    ) -> WorkbookCellInfo {
        let address = parse_cell_address(reference).unwrap();
        WorkbookCellInfo {
            sheet_index: 0,
            sheet_name: sheet.into(),
            cell_ref: reference.into(),
            row: Some(address.row),
            column: Some(address.column),
            cell_type: cell_type.into(),
            value: Some(value.into()),
            ..WorkbookCellInfo::default()
        }
    }

    #[test]
    fn evaluates_dynamic_grid_resolution_and_math_functions() {
        let cells = vec![
            cell("A1", "cmd", "s"),
            cell("B1", ".", "s"),
            cell("C1", "exe", "s"),
            cell("A2", "powershell", "s"),
            cell("B2", " -c ", "s"),
            cell("C2", "calc", "s"),
            cell_on_sheet("Sheet2", "B5", "payload_url", "s"),
        ];

        // ADDRESS tests
        assert_eq!(
            evaluate_formula("=ADDRESS(1, 1)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::String("$A$1".into()))
        );
        assert_eq!(
            evaluate_formula("=ADDRESS(2, 3, 4)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::String("C2".into()))
        );
        assert_eq!(
            evaluate_formula("=ADDRESS(2, 3, 2)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::String("C$2".into()))
        );
        assert_eq!(
            evaluate_formula("=ADDRESS(2, 3, 3)", Some("Data"), &[], Default::default()).value,
            Some(FormulaValue::String("$C2".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=ADDRESS(5, 2, 1, TRUE, \"Sheet2\")",
                Some("Data"),
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::String("Sheet2!$B$5".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=ADDRESS(1, 1, 1, TRUE, \"Space Sheet\")",
                Some("Data"),
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::String("'Space Sheet'!$A$1".into()))
        );

        // INDIRECT tests
        assert_eq!(
            evaluate_formula(
                "=INDIRECT(\"A1\")",
                Some("Data"),
                &cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("cmd".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=INDIRECT(ADDRESS(1, 1))",
                Some("Data"),
                &cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("cmd".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=INDIRECT(\"Sheet2!B5\")",
                Some("Data"),
                &cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("payload_url".into()))
        );

        // Dynamic Chained Formula Deobfuscation: INDIRECT(ADDRESS(...)) + CONCAT(range)
        assert_eq!(
            evaluate_formula("=CONCAT(A1:C1)", Some("Data"), &cells, Default::default()).value,
            Some(FormulaValue::String("cmd.exe".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=INDIRECT(ADDRESS(1, 1)) & INDIRECT(ADDRESS(1, 2)) & INDIRECT(ADDRESS(1, 3))",
                Some("Data"),
                &cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("cmd.exe".into()))
        );

        // OFFSET tests
        assert_eq!(
            evaluate_formula(
                "=OFFSET(A1, 1, 0)",
                Some("Data"),
                &cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("powershell".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=OFFSET(A1, 1, 2)",
                Some("Data"),
                &cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("calc".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=TEXTJOIN(\"\", TRUE, OFFSET(A1, 1, 0, 1, 3))",
                Some("Data"),
                &cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("powershell -c calc".into()))
        );

        // Math & Trig tests
        assert_eq!(
            evaluate_formula("=CEILING(2.5, 1)", None, &[], Default::default()).value,
            Some(FormulaValue::Number(3.0))
        );
        assert_eq!(
            evaluate_formula("=FLOOR(2.5, 1)", None, &[], Default::default()).value,
            Some(FormulaValue::Number(2.0))
        );
        assert_eq!(
            evaluate_formula("=EVEN(1.5)", None, &[], Default::default()).value,
            Some(FormulaValue::Number(2.0))
        );
        assert_eq!(
            evaluate_formula("=EVEN(3)", None, &[], Default::default()).value,
            Some(FormulaValue::Number(4.0))
        );
        assert_eq!(
            evaluate_formula("=ODD(2)", None, &[], Default::default()).value,
            Some(FormulaValue::Number(3.0))
        );
        assert_eq!(
            evaluate_formula("=ODD(0)", None, &[], Default::default()).value,
            Some(FormulaValue::Number(1.0))
        );
        assert_eq!(
            evaluate_formula("=FACT(5)", None, &[], Default::default()).value,
            Some(FormulaValue::Number(120.0))
        );
        assert_eq!(
            evaluate_formula("=GCD(24, 36, 60)", None, &[], Default::default()).value,
            Some(FormulaValue::Number(12.0))
        );
        assert_eq!(
            evaluate_formula("=LCM(4, 6, 8)", None, &[], Default::default()).value,
            Some(FormulaValue::Number(24.0))
        );
        assert_eq!(
            evaluate_formula("=DEGREES(PI())", None, &[], Default::default()).value,
            Some(FormulaValue::Number(180.0))
        );
        assert_eq!(
            evaluate_formula("=RADIANS(180)", None, &[], Default::default()).value,
            Some(FormulaValue::Number(std::f64::consts::PI))
        );
        assert_eq!(
            evaluate_formula("=SIN(0)", None, &[], Default::default()).value,
            Some(FormulaValue::Number(0.0))
        );
        assert_eq!(
            evaluate_formula("=COS(0)", None, &[], Default::default()).value,
            Some(FormulaValue::Number(1.0))
        );
        assert_eq!(
            evaluate_formula("=TAN(0)", None, &[], Default::default()).value,
            Some(FormulaValue::Number(0.0))
        );
        assert_eq!(
            evaluate_formula("=ASIN(0)", None, &[], Default::default()).value,
            Some(FormulaValue::Number(0.0))
        );
        assert_eq!(
            evaluate_formula("=ACOS(1)", None, &[], Default::default()).value,
            Some(FormulaValue::Number(0.0))
        );
        assert_eq!(
            evaluate_formula("=ATAN(0)", None, &[], Default::default()).value,
            Some(FormulaValue::Number(0.0))
        );
        assert_eq!(
            evaluate_formula("=ATAN2(1, 1)", None, &[], Default::default()).value,
            Some(FormulaValue::Number(std::f64::consts::PI / 4.0))
        );
    }

    #[test]
    fn evaluates_bitwise_datetime_and_modern_lookup_functions() {
        let cells = [
            cell("A1", "101", "n"),
            cell("A2", "116", "n"),
            cell("A3", "116", "n"),
            cell("A4", "112", "n"),
            cell("B1", "cmd", "s"),
            cell("B2", "powershell", "s"),
            cell("B3", "mshta", "s"),
            cell("C1", "/c calc", "s"),
            cell("C2", "-enc evil", "s"),
            cell("C3", "http://c2/x.hta", "s"),
        ];

        // Bitwise functions: BITAND, BITOR, BITXOR, BITLSHIFT, BITRSHIFT
        assert_eq!(
            evaluate_formula("=BITAND(6, 3)", None, &[], Default::default()).value,
            Some(FormulaValue::Number(2.0))
        );
        assert_eq!(
            evaluate_formula("=BITOR(6, 3)", None, &[], Default::default()).value,
            Some(FormulaValue::Number(7.0))
        );
        assert_eq!(
            evaluate_formula("=BITXOR(6, 3)", None, &[], Default::default()).value,
            Some(FormulaValue::Number(5.0))
        );
        assert_eq!(
            evaluate_formula("=BITLSHIFT(4, 2)", None, &[], Default::default()).value,
            Some(FormulaValue::Number(16.0))
        );
        assert_eq!(
            evaluate_formula("=BITRSHIFT(16, 2)", None, &[], Default::default()).value,
            Some(FormulaValue::Number(4.0))
        );

        // Bitwise decryption de-obfuscation: CHAR(BITXOR(A1, 23))
        // 101 ^ 23 = 114 ('r')
        assert_eq!(
            evaluate_formula(
                "=CHAR(BITXOR(A1, 23))",
                Some("Data"),
                &cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("r".into()))
        );

        // Date & Time: DATE, YEAR, MONTH, DAY, TIME, HOUR, MINUTE, SECOND, EDATE, EOMONTH
        let date_eval = evaluate_formula("=DATE(2023, 10, 15)", None, &[], Default::default());
        let date_val = match date_eval.value {
            Some(FormulaValue::Number(n)) => n,
            other => panic!("expected date serial, got {other:?}"),
        };
        assert_eq!(
            evaluate_formula(&format!("=YEAR({date_val})"), None, &[], Default::default()).value,
            Some(FormulaValue::Number(2023.0))
        );
        assert_eq!(
            evaluate_formula(
                &format!("=MONTH({date_val})"),
                None,
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(10.0))
        );
        assert_eq!(
            evaluate_formula(&format!("=DAY({date_val})"), None, &[], Default::default()).value,
            Some(FormulaValue::Number(15.0))
        );
        assert_eq!(
            evaluate_formula("=HOUR(TIME(14, 30, 45))", None, &[], Default::default()).value,
            Some(FormulaValue::Number(14.0))
        );
        assert_eq!(
            evaluate_formula("=MINUTE(TIME(14, 30, 45))", None, &[], Default::default()).value,
            Some(FormulaValue::Number(30.0))
        );
        assert_eq!(
            evaluate_formula("=SECOND(TIME(14, 30, 45))", None, &[], Default::default()).value,
            Some(FormulaValue::Number(45.0))
        );
        let edate_eval = evaluate_formula(
            &format!("=EDATE({date_val}, 2)"),
            None,
            &[],
            Default::default(),
        );
        let edate_val = match edate_eval.value {
            Some(FormulaValue::Number(n)) => n,
            other => panic!("expected edate serial, got {other:?}"),
        };
        assert_eq!(
            evaluate_formula(
                &format!("=MONTH({edate_val})"),
                None,
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(12.0))
        );
        let eomonth_eval = evaluate_formula(
            &format!("=EOMONTH({date_val}, 0)"),
            None,
            &[],
            Default::default(),
        );
        let eomonth_val = match eomonth_eval.value {
            Some(FormulaValue::Number(n)) => n,
            other => panic!("expected eomonth serial, got {other:?}"),
        };
        assert_eq!(
            evaluate_formula(
                &format!("=DAY({eomonth_val})"),
                None,
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(31.0))
        );

        // Information: ISERR, ISREF
        assert_eq!(
            evaluate_formula("=ISERR(1/0)", None, &[], Default::default()).value,
            Some(FormulaValue::Boolean(true))
        );
        assert_eq!(
            evaluate_formula("=ISERR(NA())", None, &[], Default::default()).value,
            Some(FormulaValue::Boolean(false))
        );
        assert_eq!(
            evaluate_formula("=ISREF(A1)", None, &[], Default::default()).value,
            Some(FormulaValue::Boolean(true))
        );
        assert_eq!(
            evaluate_formula("=ISREF(123)", None, &[], Default::default()).value,
            Some(FormulaValue::Boolean(false))
        );

        // Modern Lookup: XLOOKUP, XMATCH
        assert_eq!(
            evaluate_formula(
                "=XLOOKUP(\"cmd\", B1:B3, C1:C3)",
                Some("Data"),
                &cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("/c calc".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=XLOOKUP(\"powershell\", B1:B3, C1:C3)",
                Some("Data"),
                &cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("-enc evil".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=XLOOKUP(\"unknown\", B1:B3, C1:C3, \"clean\")",
                Some("Data"),
                &cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("clean".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=XLOOKUP(\"power*\", B1:B3, C1:C3, \"none\", 2)",
                Some("Data"),
                &cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("-enc evil".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=XMATCH(\"powershell\", B1:B3)",
                Some("Data"),
                &cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(2.0))
        );

        // Modern Text: TEXTBEFORE, TEXTAFTER, TEXTSPLIT
        assert_eq!(
            evaluate_formula(
                "=TEXTBEFORE(\"cmd.exe /c calc\", \" \")",
                None,
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::String("cmd.exe".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=TEXTAFTER(\"cmd.exe /c calc\", \"/c \")",
                None,
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::String("calc".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=INDEX(TEXTSPLIT(\"cmd,powershell,wscript\", \",\"), 1, 2)",
                None,
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::String("powershell".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=CONCAT(TEXTSPLIT(\"a,b,c\", \",\"))",
                None,
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::String("abc".into()))
        );

        // Radix conversion: BASE & DECIMAL
        assert_eq!(
            evaluate_formula("=BASE(255, 16)", None, &[], Default::default()).value,
            Some(FormulaValue::String("FF".into()))
        );
        assert_eq!(
            evaluate_formula("=BASE(10, 2, 8)", None, &[], Default::default()).value,
            Some(FormulaValue::String("00001010".into()))
        );
        assert_eq!(
            evaluate_formula("=BASE(35, 36)", None, &[], Default::default()).value,
            Some(FormulaValue::String("Z".into()))
        );
        assert_eq!(
            evaluate_formula("=DECIMAL(\"FF\", 16)", None, &[], Default::default()).value,
            Some(FormulaValue::Number(255.0))
        );
        assert_eq!(
            evaluate_formula("=DECIMAL(\"00001010\", 2)", None, &[], Default::default()).value,
            Some(FormulaValue::Number(10.0))
        );
        assert_eq!(
            evaluate_formula("=DECIMAL(\"Z\", 36)", None, &[], Default::default()).value,
            Some(FormulaValue::Number(35.0))
        );
        // Radix-based malware string deobfuscation
        assert_eq!(
            evaluate_formula(
                "=CONCAT(CHAR(DECIMAL(\"63\", 16)), CHAR(DECIMAL(\"6D\", 16)), CHAR(DECIMAL(\"64\", 16)))",
                None,
                &[],
                Default::default()
            )
            .value,
            Some(FormulaValue::String("cmd".into()))
        );

        // Math: DELTA & GESTEP
        assert_eq!(
            evaluate_formula("=DELTA(5, 5)", None, &[], Default::default()).value,
            Some(FormulaValue::Number(1.0))
        );
        assert_eq!(
            evaluate_formula("=DELTA(5, 4)", None, &[], Default::default()).value,
            Some(FormulaValue::Number(0.0))
        );
        assert_eq!(
            evaluate_formula("=GESTEP(5, 3)", None, &[], Default::default()).value,
            Some(FormulaValue::Number(1.0))
        );
        assert_eq!(
            evaluate_formula("=GESTEP(2, 3)", None, &[], Default::default()).value,
            Some(FormulaValue::Number(0.0))
        );

        // Array manipulation: TAKE, DROP, CHOOSEROWS, CHOOSECOLS, TOROW, TOCOL, EXPAND
        let grid_cells = vec![
            cell_on_sheet("G", "A1", "10", "n"),
            cell_on_sheet("G", "B1", "20", "n"),
            cell_on_sheet("G", "A2", "30", "n"),
            cell_on_sheet("G", "B2", "40", "n"),
            cell_on_sheet("G", "A3", "50", "n"),
            cell_on_sheet("G", "B3", "60", "n"),
        ];
        // TAKE top-level 1x1 unwrap
        assert_eq!(
            evaluate_formula(
                "=TAKE(A1:B3, 1, 1)",
                Some("G"),
                &grid_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(10.0))
        );
        // TAKE with INDEX
        assert_eq!(
            evaluate_formula(
                "=INDEX(TAKE(A1:B3, -1, -1), 1, 1)",
                Some("G"),
                &grid_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(60.0))
        );
        // DROP with INDEX
        assert_eq!(
            evaluate_formula(
                "=INDEX(DROP(A1:B3, 2, 1), 1, 1)",
                Some("G"),
                &grid_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(60.0))
        );
        // CHOOSEROWS & CHOOSECOLS
        assert_eq!(
            evaluate_formula(
                "=INDEX(CHOOSEROWS(A1:B3, 3), 1, 1)",
                Some("G"),
                &grid_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(50.0))
        );
        assert_eq!(
            evaluate_formula(
                "=INDEX(CHOOSECOLS(A1:B3, 2), 1, 1)",
                Some("G"),
                &grid_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(20.0))
        );
        // TOROW & TOCOL
        assert_eq!(
            evaluate_formula(
                "=INDEX(TOROW(A1:B3), 1, 3)",
                Some("G"),
                &grid_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(30.0))
        );
        assert_eq!(
            evaluate_formula(
                "=INDEX(TOCOL(A1:B3), 4, 1)",
                Some("G"),
                &grid_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(40.0))
        );
        // EXPAND with pad_with
        assert_eq!(
            evaluate_formula(
                "=INDEX(EXPAND(A1:B1, 2, 3, 999), 2, 3)",
                Some("G"),
                &grid_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(999.0))
        );

        // Formatting: ARRAYTOTEXT & VALUETOTEXT
        assert_eq!(
            evaluate_formula(
                "=ARRAYTOTEXT(A1:B2, 0)",
                Some("G"),
                &grid_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("10, 20; 30, 40".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=ARRAYTOTEXT(A1:B2, 1)",
                Some("G"),
                &grid_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("{10, 20; 30, 40}".into()))
        );
        assert_eq!(
            evaluate_formula("=VALUETOTEXT(\"hello\", 1)", None, &[], Default::default()).value,
            Some(FormulaValue::String("\"hello\"".into()))
        );

        // ROWS, COLUMNS, MROUND
        assert_eq!(
            evaluate_formula("=ROWS(A1:B3)", Some("G"), &grid_cells, Default::default()).value,
            Some(FormulaValue::Number(3.0))
        );
        assert_eq!(
            evaluate_formula(
                "=COLUMNS(A1:B3)",
                Some("G"),
                &grid_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(2.0))
        );
        assert_eq!(
            evaluate_formula("=MROUND(10, 3)", None, &[], Default::default()).value,
            Some(FormulaValue::Number(9.0))
        );
        assert_eq!(
            evaluate_formula("=MROUND(11, 3)", None, &[], Default::default()).value,
            Some(FormulaValue::Number(12.0))
        );

        // WRAPROWS & WRAPCOLS
        assert_eq!(
            evaluate_formula(
                "=INDEX(WRAPROWS(A1:B3, 3), 1, 3)",
                Some("G"),
                &grid_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(30.0))
        );
        assert_eq!(
            evaluate_formula(
                "=INDEX(WRAPROWS(A1:B3, 4, 0), 2, 4)",
                Some("G"),
                &grid_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(0.0))
        );
        assert_eq!(
            evaluate_formula(
                "=INDEX(WRAPCOLS(A1:B3, 3), 1, 2)",
                Some("G"),
                &grid_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(40.0))
        );

        // FILTER
        let filter_cells = vec![
            cell_on_sheet("F", "A1", "cmd.exe", "s"),
            cell_on_sheet("F", "B1", "1", "n"),
            cell_on_sheet("F", "A2", "notepad.exe", "s"),
            cell_on_sheet("F", "B2", "0", "n"),
            cell_on_sheet("F", "A3", "powershell.exe", "s"),
            cell_on_sheet("F", "B3", "1", "n"),
        ];
        assert_eq!(
            evaluate_formula(
                "=INDEX(FILTER(A1:A3, B1:B3), 1, 1)",
                Some("F"),
                &filter_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("cmd.exe".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=INDEX(FILTER(A1:A3, B1:B3), 2, 1)",
                Some("F"),
                &filter_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("powershell.exe".into()))
        );

        // SORT
        let sort_cells = vec![
            cell_on_sheet("S", "A1", "banana", "s"),
            cell_on_sheet("S", "A2", "apple", "s"),
            cell_on_sheet("S", "A3", "cherry", "s"),
        ];
        assert_eq!(
            evaluate_formula(
                "=INDEX(SORT(A1:A3), 1, 1)",
                Some("S"),
                &sort_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("apple".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=INDEX(SORT(A1:A3, 1, -1), 1, 1)",
                Some("S"),
                &sort_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("cherry".into()))
        );

        // UNIQUE
        let dup_cells = vec![
            cell_on_sheet("U", "A1", "X", "s"),
            cell_on_sheet("U", "A2", "Y", "s"),
            cell_on_sheet("U", "A3", "X", "s"),
        ];
        assert_eq!(
            evaluate_formula(
                "=ROWS(UNIQUE(A1:A3))",
                Some("U"),
                &dup_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(2.0))
        );
        assert_eq!(
            evaluate_formula(
                "=INDEX(UNIQUE(A1:A3, FALSE, TRUE), 1, 1)",
                Some("U"),
                &dup_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("Y".into()))
        );
    }

    #[test]
    fn evaluates_formulatext_type_isnontext_roman_arabic() {
        let mut test_cells = vec![
            cell_on_sheet("Data", "A1", "123", "n"),
            cell_on_sheet("Data", "A2", "hello", "s"),
        ];
        test_cells.push(WorkbookCellInfo {
            sheet_index: 0,
            sheet_name: "Data".into(),
            cell_ref: "B1".into(),
            row: Some(1),
            column: Some(2),
            cell_type: "s".into(),
            formula: Some("CHAR(65)&CHAR(66)".into()),
            stored_value: Some("AB".into()),
            ..Default::default()
        });

        // FORMULATEXT
        assert_eq!(
            evaluate_formula(
                "=FORMULATEXT(B1)",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("=CHAR(65)&CHAR(66)".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=FORMULATEXT(A1)",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Error("#N/A".into()))
        );

        // TYPE
        assert_eq!(
            evaluate_formula("=TYPE(A1)", Some("Data"), &test_cells, Default::default()).value,
            Some(FormulaValue::Number(1.0))
        );
        assert_eq!(
            evaluate_formula("=TYPE(A2)", Some("Data"), &test_cells, Default::default()).value,
            Some(FormulaValue::Number(2.0))
        );
        assert_eq!(
            evaluate_formula("=TYPE(TRUE)", Some("Data"), &test_cells, Default::default()).value,
            Some(FormulaValue::Number(4.0))
        );
        assert_eq!(
            evaluate_formula("=TYPE(1/0)", Some("Data"), &test_cells, Default::default()).value,
            Some(FormulaValue::Number(16.0))
        );
        assert_eq!(
            evaluate_formula(
                "=TYPE(A1:A2)",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(64.0))
        );

        // ISNONTEXT
        assert_eq!(
            evaluate_formula(
                "=ISNONTEXT(A1)",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Boolean(true))
        );
        assert_eq!(
            evaluate_formula(
                "=ISNONTEXT(A2)",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Boolean(false))
        );

        // ROMAN & ARABIC
        assert_eq!(
            evaluate_formula("=ROMAN(10)", Some("Data"), &test_cells, Default::default()).value,
            Some(FormulaValue::String("X".into()))
        );
        assert_eq!(
            evaluate_formula("=ROMAN(42)", Some("Data"), &test_cells, Default::default()).value,
            Some(FormulaValue::String("XLII".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=ROMAN(1994)",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("MCMXCIV".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=ARABIC(\"X\")",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(10.0))
        );
        assert_eq!(
            evaluate_formula(
                "=ARABIC(\"XLII\")",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(42.0))
        );
        assert_eq!(
            evaluate_formula(
                "=ARABIC(\"MCMXCIV\")",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(1994.0))
        );
        assert_eq!(
            evaluate_formula(
                "=ARABIC(\"-IV\")",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(-4.0))
        );
        assert_eq!(
            evaluate_formula("=ROMAN(0)", Some("Data"), &test_cells, Default::default()).value,
            Some(FormulaValue::Error("#VALUE!".into()))
        );
    }
}
