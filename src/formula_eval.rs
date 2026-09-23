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
        variables: Vec::new(),
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
        Ok(EvalValue::Range { .. }) | Ok(EvalValue::Lambda { .. }) => {
            output.status = "unsupported".into()
        }
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
    LBrace,
    RBrace,
    Comma,
    Semicolon,
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
            '{' => {
                index += 1;
                Token::LBrace
            }
            '}' => {
                index += 1;
                Token::RBrace
            }
            ';' => {
                index += 1;
                Token::Semicolon
            }
            ',' => {
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
    Variable(String),
    ArrayLiteral {
        elements: Vec<Expr>,
        rows: usize,
        cols: usize,
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
            let is_lambda = matches!(&value, Expr::Call { name, .. } if name == "lambda");
            if is_lambda && matches!(self.tokens.get(self.position), Some(Token::LParen)) {
                self.position += 1;
                let mut invoke_args = Vec::new();
                if !matches!(self.tokens.get(self.position), Some(Token::RParen)) {
                    loop {
                        invoke_args.push(self.parse_expression(0, depth + 1)?);
                        if !matches!(
                            self.tokens.get(self.position),
                            Some(Token::Comma | Token::Semicolon)
                        ) {
                            break;
                        }
                        self.position += 1;
                    }
                }
                if !matches!(self.tokens.get(self.position), Some(Token::RParen)) {
                    return Err("invalid_formula");
                }
                self.position += 1;
                if let Expr::Call {
                    arguments: mut call_args,
                    ..
                } = value
                {
                    if !call_args.is_empty() && call_args.len() - 1 == invoke_args.len() {
                        let body = call_args.pop().unwrap();
                        let mut let_args = Vec::new();
                        for (param, val) in call_args.into_iter().zip(invoke_args) {
                            let_args.push(param);
                            let_args.push(val);
                        }
                        let_args.push(body);
                        return Ok(Expr::Call {
                            name: "let".into(),
                            arguments: let_args,
                        });
                    }
                    return Ok(Expr::Call {
                        name: "lambda".into(),
                        arguments: call_args,
                    });
                }
            }
            return Ok(value);
        }
        if matches!(self.tokens.get(self.position), Some(Token::LBrace)) {
            self.position += 1;
            let mut row_count = 0usize;
            let mut col_count = 0usize;
            let mut elements = Vec::new();
            if !matches!(self.tokens.get(self.position), Some(Token::RBrace)) {
                let mut current_row_len = 0usize;
                row_count = 1;
                loop {
                    elements.push(self.parse_expression(0, depth + 1)?);
                    current_row_len += 1;
                    if matches!(self.tokens.get(self.position), Some(Token::Comma)) {
                        self.position += 1;
                    } else if matches!(self.tokens.get(self.position), Some(Token::Semicolon)) {
                        self.position += 1;
                        if col_count == 0 {
                            col_count = current_row_len;
                        } else if col_count != current_row_len {
                            return Err("invalid_formula");
                        }
                        current_row_len = 0;
                        row_count += 1;
                    } else {
                        break;
                    }
                }
                if col_count == 0 {
                    col_count = current_row_len;
                } else if col_count != current_row_len {
                    return Err("invalid_formula");
                }
            }
            if !matches!(self.tokens.get(self.position), Some(Token::RBrace)) {
                return Err("invalid_formula");
            }
            self.position += 1;
            return Ok(Expr::ArrayLiteral {
                elements,
                rows: row_count,
                cols: col_count,
            });
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
                            if !matches!(
                                self.tokens.get(self.position),
                                Some(Token::Comma | Token::Semicolon)
                            ) {
                                break;
                            }
                            self.position += 1;
                        }
                    }
                    if !matches!(self.tokens.get(self.position), Some(Token::RParen)) {
                        return Err("invalid_formula");
                    }
                    self.position += 1;
                    let call_name = name.to_ascii_lowercase();
                    let mut call_args = arguments;
                    if call_name == "lambda"
                        && matches!(self.tokens.get(self.position), Some(Token::LParen))
                    {
                        self.position += 1;
                        let mut invoke_args = Vec::new();
                        if !matches!(self.tokens.get(self.position), Some(Token::RParen)) {
                            loop {
                                invoke_args.push(self.parse_expression(0, depth + 1)?);
                                if !matches!(
                                    self.tokens.get(self.position),
                                    Some(Token::Comma | Token::Semicolon)
                                ) {
                                    break;
                                }
                                self.position += 1;
                            }
                        }
                        if !matches!(self.tokens.get(self.position), Some(Token::RParen)) {
                            return Err("invalid_formula");
                        }
                        self.position += 1;
                        if !call_args.is_empty() && call_args.len() - 1 == invoke_args.len() {
                            let body = call_args.pop().unwrap();
                            let mut let_args = Vec::new();
                            for (param, val) in call_args.into_iter().zip(invoke_args) {
                                let_args.push(param);
                                let_args.push(val);
                            }
                            let_args.push(body);
                            return Ok(Expr::Call {
                                name: "let".into(),
                                arguments: let_args,
                            });
                        }
                    }
                    return Ok(Expr::Call {
                        name: call_name,
                        arguments: call_args,
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
                if sheet.is_none() {
                    if let Some(first) = parse_cell_address(&cell_name) {
                        if matches!(self.tokens.get(self.position), Some(Token::Colon)) {
                            self.position += 1;
                            let last_name = self.next_identifier()?;
                            let last = parse_cell_address(&last_name).ok_or("unsupported")?;
                            Ok(Expr::Range {
                                sheet: None,
                                first,
                                last,
                                source: format!("{cell_name}:{last_name}"),
                            })
                        } else {
                            Ok(Expr::Reference {
                                sheet: None,
                                cell: first,
                                source: cell_name,
                            })
                        }
                    } else {
                        Ok(Expr::Variable(cell_name))
                    }
                } else {
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

#[derive(Clone, Debug, PartialEq)]
enum EvalValue {
    Scalar(FormulaValue),
    Range {
        values: Vec<FormulaValue>,
        rows: usize,
        cols: usize,
    },
    Lambda {
        parameters: Vec<String>,
        body: Box<Expr>,
    },
}

impl EvalValue {
    fn into_scalar(self) -> Option<FormulaValue> {
        match self {
            Self::Scalar(value) => Some(value),
            Self::Range { .. } | Self::Lambda { .. } => None,
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
    variables: Vec<(String, EvalValue)>,
}

type EvalGrid = (Vec<FormulaValue>, usize, usize);

impl Evaluator<'_> {
    fn evaluate(&mut self, expression: &Expr, depth: usize) -> Result<EvalValue, &'static str> {
        self.steps = self.steps.saturating_add(1);
        if self.steps > self.limits.max_steps || depth >= self.limits.max_depth {
            return Err("resource_limit");
        }
        match expression {
            Expr::Value(value) => Ok(EvalValue::Scalar(value.clone())),
            Expr::Variable(name) => {
                let name_lower = name.to_ascii_lowercase();
                if let Some((_, val)) = self.variables.iter().rev().find(|(k, _)| k == &name_lower)
                {
                    Ok(val.clone())
                } else {
                    Err("unsupported")
                }
            }
            Expr::Reference {
                sheet,
                cell,
                source,
            } => {
                if sheet.is_none() {
                    let source_lower = source.to_ascii_lowercase();
                    if let Some((_, val)) = self
                        .variables
                        .iter()
                        .rev()
                        .find(|(k, _)| k == &source_lower)
                    {
                        return Ok(val.clone());
                    }
                }
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
            Expr::ArrayLiteral {
                elements,
                rows,
                cols,
            } => {
                let count = elements.len();
                if count > self.limits.max_range_cells {
                    return Err("resource_limit");
                }
                let mut values = Vec::with_capacity(count);
                for elem in elements {
                    values.push(self.eval_scalar(elem, depth + 1)?);
                }
                if *rows <= 1 && *cols <= 1 && !values.is_empty() {
                    Ok(EvalValue::Scalar(values.swap_remove(0)))
                } else {
                    Ok(EvalValue::Range {
                        values,
                        rows: *rows,
                        cols: *cols,
                    })
                }
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

    fn eval_lambda_instance(
        &mut self,
        parameters: &[String],
        body: &Expr,
        args: Vec<EvalValue>,
        depth: usize,
    ) -> Result<EvalValue, &'static str> {
        if parameters.len() != args.len() {
            return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
        }
        let prev_len = self.variables.len();
        for (param, val) in parameters.iter().cloned().zip(args) {
            self.variables.push((param, val));
        }
        let res = self.evaluate(body, depth + 1);
        self.variables.truncate(prev_len);
        res
    }

    fn eval_lambda_to_scalar(
        &mut self,
        lambda_val: &EvalValue,
        args: Vec<EvalValue>,
        depth: usize,
    ) -> Result<FormulaValue, &'static str> {
        let (parameters, body) = match lambda_val {
            EvalValue::Lambda { parameters, body } => (parameters, body),
            _ => return Ok(FormulaValue::Error("#VALUE!".into())),
        };
        let eval_res = self.eval_lambda_instance(parameters, body, args, depth)?;
        match eval_res {
            EvalValue::Scalar(s) => Ok(s),
            EvalValue::Range { mut values, .. } => {
                if values.is_empty() {
                    Ok(FormulaValue::Blank)
                } else {
                    Ok(values.swap_remove(0))
                }
            }
            EvalValue::Lambda { .. } => Ok(FormulaValue::Error("#VALUE!".into())),
        }
    }

    fn eval_to_grid(
        &mut self,
        expr: &Expr,
        depth: usize,
    ) -> Result<Option<EvalGrid>, &'static str> {
        match self.evaluate(expr, depth)? {
            EvalValue::Scalar(s) => Ok(Some((vec![s], 1, 1))),
            EvalValue::Range { values, rows, cols } => Ok(Some((values, rows, cols))),
            EvalValue::Lambda { .. } => Ok(None),
        }
    }

    fn evaluate_call(
        &mut self,
        name: &str,
        arguments: &[Expr],
        depth: usize,
    ) -> Result<EvalValue, &'static str> {
        let lambda_match = self.variables.iter().rev().find_map(|(k, v)| {
            if k == name {
                if let EvalValue::Lambda { parameters, body } = v {
                    Some((parameters.clone(), body.as_ref().clone()))
                } else {
                    None
                }
            } else {
                None
            }
        });
        if let Some((parameters, body)) = lambda_match {
            let mut evaled_args = Vec::with_capacity(arguments.len());
            for arg in arguments {
                evaled_args.push(self.evaluate(arg, depth + 1)?);
            }
            return self.eval_lambda_instance(&parameters, &body, evaled_args, depth);
        }

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
                        EvalValue::Lambda { .. } => {
                            return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                        }
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
            "let" if arguments.len() >= 3 && arguments.len() % 2 == 1 => {
                let prev_len = self.variables.len();
                let num_bindings = (arguments.len() - 1) / 2;
                for i in 0..num_bindings {
                    let name_idx = i * 2;
                    let val_idx = name_idx + 1;
                    let var_name = match &arguments[name_idx] {
                        Expr::Variable(n) => n.clone(),
                        Expr::Value(FormulaValue::String(n)) => n.clone(),
                        Expr::Reference { source, .. } => source.clone(),
                        _ => {
                            self.variables.truncate(prev_len);
                            return Err("invalid_formula");
                        }
                    };
                    let eval_res = self.evaluate(&arguments[val_idx], depth + 1);
                    let val = match eval_res {
                        Ok(v) => v,
                        Err(e) => {
                            self.variables.truncate(prev_len);
                            return Err(e);
                        }
                    };
                    self.variables.push((var_name.to_ascii_lowercase(), val));
                }
                let res = self.evaluate(&arguments[arguments.len() - 1], depth + 1);
                self.variables.truncate(prev_len);
                res
            }
            "lambda" if !arguments.is_empty() => {
                let mut parameters = Vec::new();
                for arg in &arguments[..arguments.len() - 1] {
                    let param_name = match arg {
                        Expr::Variable(n) => n.clone(),
                        Expr::Value(FormulaValue::String(n)) => n.clone(),
                        Expr::Reference {
                            source,
                            sheet: None,
                            ..
                        } => source.clone(),
                        _ => return Err("invalid_formula"),
                    };
                    parameters.push(param_name.to_ascii_lowercase());
                }
                let body = arguments.last().unwrap().clone();
                Ok(EvalValue::Lambda {
                    parameters,
                    body: Box::new(body),
                })
            }
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
            "isodd" if arguments.len() == 1 => {
                let val = self.eval_scalar(&arguments[0], depth + 1)?;
                if let FormulaValue::Error(e) = val {
                    return Ok(EvalValue::Scalar(FormulaValue::Error(e)));
                }
                match to_number(&val) {
                    Ok(n) => {
                        let int_val = n.trunc() as i64;
                        Ok(EvalValue::Scalar(FormulaValue::Boolean(int_val % 2 != 0)))
                    }
                    Err(_) => Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into()))),
                }
            }
            "iseven" if arguments.len() == 1 => {
                let val = self.eval_scalar(&arguments[0], depth + 1)?;
                if let FormulaValue::Error(e) = val {
                    return Ok(EvalValue::Scalar(FormulaValue::Error(e)));
                }
                match to_number(&val) {
                    Ok(n) => {
                        let int_val = n.trunc() as i64;
                        Ok(EvalValue::Scalar(FormulaValue::Boolean(int_val % 2 == 0)))
                    }
                    Err(_) => Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into()))),
                }
            }
            "type" if arguments.len() == 1 => {
                let eval_res = self.evaluate(&arguments[0], depth + 1)?;
                let type_code = match eval_res {
                    EvalValue::Range { .. } | EvalValue::Lambda { .. } => 64.0,
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
            "isformula" if arguments.len() == 1 => {
                let (sheet, addr) = match self.eval_cell_origin(&arguments[0], depth + 1) {
                    Ok(res) => res,
                    Err(_) => return Ok(EvalValue::Scalar(FormulaValue::Error("#N/A".into()))),
                };
                let effective_sheet = sheet.as_deref().or(self.current_sheet);
                let mut found_formula = false;
                for c in self.cells {
                    let sheet_matches = match (effective_sheet, &c.sheet_name) {
                        (Some(s), target) => s.eq_ignore_ascii_case(target),
                        (None, _) => true,
                    };
                    if sheet_matches
                        && c.row == Some(addr.row)
                        && c.column == Some(addr.column)
                        && c.formula.as_deref().is_some_and(|f| !f.trim().is_empty())
                    {
                        found_formula = true;
                        break;
                    }
                }
                Ok(EvalValue::Scalar(FormulaValue::Boolean(found_formula)))
            }
            "error.type" if arguments.len() == 1 => {
                let val = self.eval_scalar(&arguments[0], depth + 1)?;
                match val {
                    FormulaValue::Error(ref s) => {
                        let code = match s.to_ascii_uppercase().as_str() {
                            "#NULL!" => 1.0,
                            "#DIV/0!" => 2.0,
                            "#VALUE!" => 3.0,
                            "#REF!" => 4.0,
                            "#NAME?" => 5.0,
                            "#NUM!" => 6.0,
                            "#N/A" => 7.0,
                            "#GETTING_DATA" => 8.0,
                            _ => 7.0,
                        };
                        Ok(EvalValue::Scalar(FormulaValue::Number(code)))
                    }
                    _ => Ok(EvalValue::Scalar(FormulaValue::Error("#N/A".into()))),
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
            "quotient" if arguments.len() == 2 => {
                let num = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let den = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                if den == 0.0 {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#DIV/0!".into())))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Number((num / den).trunc())))
                }
            }
            "even" if arguments.len() == 1 => {
                let num = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                if num == 0.0 {
                    Ok(EvalValue::Scalar(FormulaValue::Number(0.0)))
                } else if num > 0.0 {
                    let ceil = num.ceil();
                    let res = if (ceil as i64) % 2 != 0 {
                        ceil + 1.0
                    } else {
                        ceil
                    };
                    Ok(EvalValue::Scalar(FormulaValue::Number(res)))
                } else {
                    let floor = num.floor();
                    let res = if (floor as i64).abs() % 2 != 0 {
                        floor - 1.0
                    } else {
                        floor
                    };
                    Ok(EvalValue::Scalar(FormulaValue::Number(res)))
                }
            }
            "odd" if arguments.len() == 1 => {
                let num = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                if num == 0.0 {
                    Ok(EvalValue::Scalar(FormulaValue::Number(1.0)))
                } else if num > 0.0 {
                    let ceil = num.ceil();
                    let res = if (ceil as i64) % 2 == 0 {
                        ceil + 1.0
                    } else {
                        ceil
                    };
                    Ok(EvalValue::Scalar(FormulaValue::Number(res)))
                } else {
                    let floor = num.floor();
                    let res = if (floor as i64).abs() % 2 == 0 {
                        floor - 1.0
                    } else {
                        floor
                    };
                    Ok(EvalValue::Scalar(FormulaValue::Number(res)))
                }
            }
            "fact" if arguments.len() == 1 => {
                let num = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                if !(0.0..=170.0).contains(&num) {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                } else {
                    let n = num.trunc() as u64;
                    let mut f: f64 = 1.0;
                    for i in 2..=n {
                        f *= i as f64;
                    }
                    Ok(EvalValue::Scalar(FormulaValue::Number(f)))
                }
            }
            "factdouble" if arguments.len() == 1 => {
                let num = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let n = num.trunc() as i64;
                if !(-1..=300).contains(&n) {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                } else if n == -1 || n == 0 {
                    Ok(EvalValue::Scalar(FormulaValue::Number(1.0)))
                } else {
                    let mut f: f64 = 1.0;
                    let mut curr = n;
                    while curr > 1 {
                        f *= curr as f64;
                        curr -= 2;
                    }
                    Ok(EvalValue::Scalar(FormulaValue::Number(f)))
                }
            }
            "gcd" if !arguments.is_empty() => {
                let mut nums = Vec::new();
                for arg in arguments {
                    match self.evaluate(arg, depth + 1)? {
                        EvalValue::Scalar(val) => {
                            if let FormulaValue::Error(err) = val {
                                return Ok(EvalValue::Scalar(FormulaValue::Error(err)));
                            }
                            nums.push(to_number(&val)?);
                        }
                        EvalValue::Range { values, .. } => {
                            for val in values {
                                if let FormulaValue::Error(err) = val {
                                    return Ok(EvalValue::Scalar(FormulaValue::Error(err)));
                                }
                                if let Ok(n) = to_number(&val) {
                                    nums.push(n);
                                }
                            }
                        }
                        EvalValue::Lambda { .. } => {
                            return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                        }
                    }
                }
                if nums.is_empty() {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                }
                if nums.iter().any(|&n| n < 0.0) {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                let mut g = nums[0].trunc() as u64;
                for n in &nums[1..] {
                    g = calc_gcd(g, n.trunc() as u64);
                }
                Ok(EvalValue::Scalar(FormulaValue::Number(g as f64)))
            }
            "lcm" if !arguments.is_empty() => {
                let mut nums = Vec::new();
                for arg in arguments {
                    match self.evaluate(arg, depth + 1)? {
                        EvalValue::Scalar(val) => {
                            if let FormulaValue::Error(err) = val {
                                return Ok(EvalValue::Scalar(FormulaValue::Error(err)));
                            }
                            nums.push(to_number(&val)?);
                        }
                        EvalValue::Range { values, .. } => {
                            for val in values {
                                if let FormulaValue::Error(err) = val {
                                    return Ok(EvalValue::Scalar(FormulaValue::Error(err)));
                                }
                                if let Ok(n) = to_number(&val) {
                                    nums.push(n);
                                }
                            }
                        }
                        EvalValue::Lambda { .. } => {
                            return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                        }
                    }
                }
                if nums.is_empty() {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                }
                if nums.iter().any(|&n| n < 0.0) {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                let mut l = nums[0].trunc() as u64;
                for n in &nums[1..] {
                    l = calc_lcm(l, n.trunc() as u64);
                }
                Ok(EvalValue::Scalar(FormulaValue::Number(l as f64)))
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
                        EvalValue::Lambda { .. } => {
                            return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                        }
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
                    EvalValue::Lambda { .. } => {
                        Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())))
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
                    EvalValue::Lambda { .. } => {
                        return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                    }
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
            "lookup" => {
                if !(2..=3).contains(&arguments.len()) {
                    return Err("unsupported");
                }
                let lookup_val = self.eval_scalar(&arguments[0], depth + 1)?;
                if arguments.len() == 3 {
                    // Vector form: LOOKUP(lookup_value, lookup_vector, result_vector)
                    let lookup_target = self.evaluate(&arguments[1], depth + 1)?;
                    let lookup_vals = match lookup_target {
                        EvalValue::Range { values, .. } => values,
                        EvalValue::Scalar(s) => vec![s],
                        _ => return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into()))),
                    };
                    let result_target = self.evaluate(&arguments[2], depth + 1)?;
                    let result_vals = match result_target {
                        EvalValue::Range { values, .. } => values,
                        EvalValue::Scalar(s) => vec![s],
                        _ => return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into()))),
                    };
                    let mut best_idx: Option<usize> = None;
                    for (i, v) in lookup_vals.iter().enumerate() {
                        if values_less_than_or_equal(v, &lookup_val) {
                            best_idx = Some(i);
                        } else {
                            break;
                        }
                    }
                    if let Some(idx) = best_idx {
                        if idx < result_vals.len() {
                            Ok(EvalValue::Scalar(result_vals[idx].clone()))
                        } else {
                            Ok(EvalValue::Scalar(FormulaValue::Error("#REF!".into())))
                        }
                    } else {
                        Ok(EvalValue::Scalar(FormulaValue::Error("#N/A".into())))
                    }
                } else {
                    // Array form: LOOKUP(lookup_value, array)
                    let target = self.evaluate(&arguments[1], depth + 1)?;
                    let (values, rows, cols) = match target {
                        EvalValue::Range { values, rows, cols } => (values, rows, cols),
                        EvalValue::Scalar(s) => (vec![s], 1, 1),
                        _ => return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into()))),
                    };
                    if rows == 1 && cols == 1 {
                        if values_equal(&lookup_val, &values[0])
                            || values_less_than_or_equal(&values[0], &lookup_val)
                        {
                            return Ok(EvalValue::Scalar(values[0].clone()));
                        } else {
                            return Ok(EvalValue::Scalar(FormulaValue::Error("#N/A".into())));
                        }
                    }
                    if cols > rows {
                        // Wide array: search first row, return from last row
                        let mut best_col: Option<usize> = None;
                        for (c, first_val) in values.iter().take(cols).enumerate() {
                            if values_less_than_or_equal(first_val, &lookup_val) {
                                best_col = Some(c);
                            } else {
                                break;
                            }
                        }
                        if let Some(c) = best_col {
                            Ok(EvalValue::Scalar(values[(rows - 1) * cols + c].clone()))
                        } else {
                            Ok(EvalValue::Scalar(FormulaValue::Error("#N/A".into())))
                        }
                    } else {
                        // Tall or square array: search first column, return from last column
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
                            Ok(EvalValue::Scalar(values[r * cols + (cols - 1)].clone()))
                        } else {
                            Ok(EvalValue::Scalar(FormulaValue::Error("#N/A".into())))
                        }
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
            "pi" if arguments.is_empty() => Ok(EvalValue::Scalar(FormulaValue::Number(
                std::f64::consts::PI,
            ))),
            "exp" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                Ok(EvalValue::Scalar(FormulaValue::Number(n.exp())))
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
            "log" if arguments.len() == 1 || arguments.len() == 2 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let base = if arguments.len() == 2 {
                    to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?
                } else {
                    10.0
                };
                if n <= 0.0 || base <= 0.0 || (base - 1.0).abs() < 1e-12 {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Number(n.log(base))))
                }
            }
            "combin" if arguments.len() == 2 => {
                let n_val = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let k_val = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let n = n_val.trunc() as i64;
                let k = k_val.trunc() as i64;
                if n < 0 || k < 0 || n < k {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                } else if k == 0 || k == n {
                    Ok(EvalValue::Scalar(FormulaValue::Number(1.0)))
                } else {
                    let k_eff = k.min(n - k);
                    let mut res = 1.0f64;
                    for i in 1..=k_eff {
                        res = res * ((n - k_eff + i) as f64) / (i as f64);
                    }
                    Ok(EvalValue::Scalar(FormulaValue::Number(res.round())))
                }
            }
            "permut" if arguments.len() == 2 => {
                let n_val = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let k_val = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let n = n_val.trunc() as i64;
                let k = k_val.trunc() as i64;
                if n < 0 || k < 0 || n < k {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                } else if k == 0 {
                    Ok(EvalValue::Scalar(FormulaValue::Number(1.0)))
                } else {
                    let mut res = 1.0f64;
                    for i in 0..k {
                        res *= (n - i) as f64;
                    }
                    Ok(EvalValue::Scalar(FormulaValue::Number(res.round())))
                }
            }
            "sumproduct" if !arguments.is_empty() => {
                let mut arg_matrices: Vec<(Vec<FormulaValue>, usize, usize)> = Vec::new();
                for arg in arguments {
                    match self.evaluate(arg, depth + 1)? {
                        EvalValue::Scalar(val) => {
                            if let FormulaValue::Error(err) = val {
                                return Ok(EvalValue::Scalar(FormulaValue::Error(err)));
                            }
                            arg_matrices.push((vec![val], 1, 1));
                        }
                        EvalValue::Range { values, rows, cols } => {
                            arg_matrices.push((values, rows, cols));
                        }
                        EvalValue::Lambda { .. } => {
                            return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                        }
                    }
                }
                let target_rows = arg_matrices[0].1;
                let target_cols = arg_matrices[0].2;
                for (_, r, c) in &arg_matrices {
                    if *r != target_rows || *c != target_cols {
                        return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                    }
                }
                let cell_count = target_rows * target_cols;
                let mut sum = 0.0f64;
                for i in 0..cell_count {
                    let mut cell_prod = 1.0f64;
                    for (vals, _, _) in &arg_matrices {
                        match &vals[i] {
                            FormulaValue::Number(n) => cell_prod *= n,
                            FormulaValue::Error(err) => {
                                return Ok(EvalValue::Scalar(FormulaValue::Error(err.clone())));
                            }
                            _ => {
                                cell_prod = 0.0;
                                break;
                            }
                        }
                    }
                    sum += cell_prod;
                }
                Ok(EvalValue::Scalar(FormulaValue::Number(sum)))
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
            "sinh" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let res = n.sinh();
                if res.is_finite() {
                    Ok(EvalValue::Scalar(FormulaValue::Number(res)))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                }
            }
            "cosh" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let res = n.cosh();
                if res.is_finite() {
                    Ok(EvalValue::Scalar(FormulaValue::Number(res)))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                }
            }
            "tanh" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                Ok(EvalValue::Scalar(FormulaValue::Number(n.tanh())))
            }
            "asinh" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let res = n.asinh();
                if res.is_finite() {
                    Ok(EvalValue::Scalar(FormulaValue::Number(res)))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                }
            }
            "acosh" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                if n < 1.0 {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                } else {
                    let res = n.acosh();
                    if res.is_finite() {
                        Ok(EvalValue::Scalar(FormulaValue::Number(res)))
                    } else {
                        Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                    }
                }
            }
            "atanh" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                if n <= -1.0 || n >= 1.0 {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Number(n.atanh())))
                }
            }
            "sqrtpi" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                if n < 0.0 {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Number(
                        (n * std::f64::consts::PI).sqrt(),
                    )))
                }
            }
            "sumsq" if !arguments.is_empty() => {
                let mut sum = 0.0;
                for arg in arguments {
                    match self.evaluate(arg, depth + 1)? {
                        EvalValue::Scalar(s) => {
                            let num = to_number(&s)?;
                            sum += num * num;
                        }
                        EvalValue::Range { values, .. } => {
                            for val in values {
                                if let Ok(num) = to_number(&val) {
                                    sum += num * num;
                                }
                            }
                        }
                        EvalValue::Lambda { .. } => {
                            return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                        }
                    }
                }
                Ok(EvalValue::Scalar(FormulaValue::Number(sum)))
            }
            "sec" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let c = n.cos();
                if c == 0.0 {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#DIV/0!".into())))
                } else {
                    let res = 1.0 / c;
                    if res.is_finite() {
                        Ok(EvalValue::Scalar(FormulaValue::Number(res)))
                    } else {
                        Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                    }
                }
            }
            "csc" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let s = n.sin();
                if s == 0.0 {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#DIV/0!".into())))
                } else {
                    let res = 1.0 / s;
                    if res.is_finite() {
                        Ok(EvalValue::Scalar(FormulaValue::Number(res)))
                    } else {
                        Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                    }
                }
            }
            "cot" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let t = n.tan();
                if t == 0.0 {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#DIV/0!".into())))
                } else {
                    let res = 1.0 / t;
                    if res.is_finite() {
                        Ok(EvalValue::Scalar(FormulaValue::Number(res)))
                    } else {
                        Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                    }
                }
            }
            "sech" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let c = n.cosh();
                let res = 1.0 / c;
                if res.is_finite() {
                    Ok(EvalValue::Scalar(FormulaValue::Number(res)))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                }
            }
            "csch" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                if n == 0.0 {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#DIV/0!".into())))
                } else {
                    let s = n.sinh();
                    if s == 0.0 {
                        Ok(EvalValue::Scalar(FormulaValue::Error("#DIV/0!".into())))
                    } else {
                        let res = 1.0 / s;
                        if res.is_finite() {
                            Ok(EvalValue::Scalar(FormulaValue::Number(res)))
                        } else {
                            Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                        }
                    }
                }
            }
            "coth" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                if n == 0.0 {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#DIV/0!".into())))
                } else {
                    let t = n.tanh();
                    if t == 0.0 {
                        Ok(EvalValue::Scalar(FormulaValue::Error("#DIV/0!".into())))
                    } else {
                        let res = 1.0 / t;
                        if res.is_finite() {
                            Ok(EvalValue::Scalar(FormulaValue::Number(res)))
                        } else {
                            Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                        }
                    }
                }
            }
            "acot" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let res = std::f64::consts::FRAC_PI_2 - n.atan();
                Ok(EvalValue::Scalar(FormulaValue::Number(res)))
            }
            "acoth" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                if n.abs() <= 1.0 {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                } else {
                    let res = 0.5 * ((n + 1.0) / (n - 1.0)).ln();
                    if res.is_finite() {
                        Ok(EvalValue::Scalar(FormulaValue::Number(res)))
                    } else {
                        Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                    }
                }
            }
            "int" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                Ok(EvalValue::Scalar(FormulaValue::Number(n.floor())))
            }
            "seriessum" if arguments.len() == 4 => {
                let x = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let n = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let m = to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?;
                let coeffs = match self.evaluate(&arguments[3], depth + 1)? {
                    EvalValue::Scalar(s) => vec![s],
                    EvalValue::Range { values, .. } => values,
                    EvalValue::Lambda { .. } => {
                        return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                    }
                };
                let mut sum = 0.0f64;
                for (i, val) in coeffs.iter().enumerate() {
                    if let FormulaValue::Error(e) = val {
                        return Ok(EvalValue::Scalar(FormulaValue::Error(e.clone())));
                    }
                    let a_i = match to_number(val) {
                        Ok(num) => num,
                        Err(_) => {
                            return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                        }
                    };
                    let power = n + (i as f64) * m;
                    let term = a_i * x.powf(power);
                    if !term.is_finite() {
                        return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                    }
                    sum += term;
                }
                Ok(EvalValue::Scalar(FormulaValue::Number(sum)))
            }
            "complex" if arguments.len() == 2 || arguments.len() == 3 => {
                let real = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let imag = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let suffix = if arguments.len() == 3 {
                    match self.eval_scalar(&arguments[2], depth + 1)? {
                        FormulaValue::String(t) => {
                            let t_lower = t.to_ascii_lowercase();
                            if t_lower == "i" || t_lower == "j" {
                                t_lower
                            } else if t.is_empty() {
                                "i".to_string()
                            } else {
                                return Ok(EvalValue::Scalar(FormulaValue::Error(
                                    "#VALUE!".into(),
                                )));
                            }
                        }
                        _ => return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into()))),
                    }
                } else {
                    "i".to_string()
                };
                let s = format_complex(real, imag, &suffix);
                Ok(EvalValue::Scalar(FormulaValue::String(s)))
            }
            "imreal" if arguments.len() == 1 => {
                let val = self.eval_scalar(&arguments[0], depth + 1)?;
                if let FormulaValue::Error(e) = val {
                    return Ok(EvalValue::Scalar(FormulaValue::Error(e)));
                }
                match parse_complex(&val) {
                    Ok((r, _)) => Ok(EvalValue::Scalar(FormulaValue::Number(r))),
                    Err(_) => Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into()))),
                }
            }
            "imaginary" if arguments.len() == 1 => {
                let val = self.eval_scalar(&arguments[0], depth + 1)?;
                if let FormulaValue::Error(e) = val {
                    return Ok(EvalValue::Scalar(FormulaValue::Error(e)));
                }
                match parse_complex(&val) {
                    Ok((_, im)) => Ok(EvalValue::Scalar(FormulaValue::Number(im))),
                    Err(_) => Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into()))),
                }
            }
            "imabs" if arguments.len() == 1 => {
                let val = self.eval_scalar(&arguments[0], depth + 1)?;
                if let FormulaValue::Error(e) = val {
                    return Ok(EvalValue::Scalar(FormulaValue::Error(e)));
                }
                match parse_complex(&val) {
                    Ok((r, im)) => {
                        let res = (r * r + im * im).sqrt();
                        Ok(EvalValue::Scalar(FormulaValue::Number(res)))
                    }
                    Err(_) => Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into()))),
                }
            }
            "imconjg" | "imconjugate" if arguments.len() == 1 => {
                let val = self.eval_scalar(&arguments[0], depth + 1)?;
                if let FormulaValue::Error(e) = val {
                    return Ok(EvalValue::Scalar(FormulaValue::Error(e)));
                }
                match parse_complex(&val) {
                    Ok((r, im)) => {
                        let s = format_complex(r, -im, "i");
                        Ok(EvalValue::Scalar(FormulaValue::String(s)))
                    }
                    Err(_) => Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into()))),
                }
            }
            "imsum" if !arguments.is_empty() => {
                let mut sum_r = 0.0f64;
                let mut sum_im = 0.0f64;
                let mut suffix = "i";
                for arg in arguments {
                    match self.evaluate(arg, depth + 1)? {
                        EvalValue::Scalar(s) => {
                            if let FormulaValue::Error(e) = s {
                                return Ok(EvalValue::Scalar(FormulaValue::Error(e)));
                            }
                            if let FormulaValue::String(ref str_val) = s
                                && (str_val.ends_with('j') || str_val.ends_with('J'))
                            {
                                suffix = "j";
                            }
                            match parse_complex(&s) {
                                Ok((r, im)) => {
                                    sum_r += r;
                                    sum_im += im;
                                }
                                Err(_) => {
                                    return Ok(EvalValue::Scalar(FormulaValue::Error(
                                        "#NUM!".into(),
                                    )));
                                }
                            }
                        }
                        EvalValue::Range { values, .. } => {
                            for v in values {
                                if let FormulaValue::Error(e) = v {
                                    return Ok(EvalValue::Scalar(FormulaValue::Error(e)));
                                }
                                if let FormulaValue::String(ref str_val) = v
                                    && (str_val.ends_with('j') || str_val.ends_with('J'))
                                {
                                    suffix = "j";
                                }
                                match parse_complex(&v) {
                                    Ok((r, im)) => {
                                        sum_r += r;
                                        sum_im += im;
                                    }
                                    Err(_) => {
                                        return Ok(EvalValue::Scalar(FormulaValue::Error(
                                            "#NUM!".into(),
                                        )));
                                    }
                                }
                            }
                        }
                        EvalValue::Lambda { .. } => {
                            return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                        }
                    }
                }
                let s = format_complex(sum_r, sum_im, suffix);
                Ok(EvalValue::Scalar(FormulaValue::String(s)))
            }
            "imsub" if arguments.len() == 2 => {
                let v1 = self.eval_scalar(&arguments[0], depth + 1)?;
                if let FormulaValue::Error(e) = v1 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error(e)));
                }
                let v2 = self.eval_scalar(&arguments[1], depth + 1)?;
                if let FormulaValue::Error(e) = v2 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error(e)));
                }
                let suffix = if let FormulaValue::String(ref s) = v1 {
                    if s.ends_with('j') || s.ends_with('J') {
                        "j"
                    } else {
                        "i"
                    }
                } else if let FormulaValue::String(ref s) = v2 {
                    if s.ends_with('j') || s.ends_with('J') {
                        "j"
                    } else {
                        "i"
                    }
                } else {
                    "i"
                };
                match (parse_complex(&v1), parse_complex(&v2)) {
                    (Ok((r1, im1)), Ok((r2, im2))) => {
                        let s = format_complex(r1 - r2, im1 - im2, suffix);
                        Ok(EvalValue::Scalar(FormulaValue::String(s)))
                    }
                    _ => Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into()))),
                }
            }
            "improduct" if !arguments.is_empty() => {
                let mut prod_r = 1.0f64;
                let mut prod_im = 0.0f64;
                let mut suffix = "i";
                for arg in arguments {
                    match self.evaluate(arg, depth + 1)? {
                        EvalValue::Scalar(s) => {
                            if let FormulaValue::Error(e) = s {
                                return Ok(EvalValue::Scalar(FormulaValue::Error(e)));
                            }
                            if let FormulaValue::String(ref str_val) = s
                                && (str_val.ends_with('j') || str_val.ends_with('J'))
                            {
                                suffix = "j";
                            }
                            match parse_complex(&s) {
                                Ok((r, im)) => {
                                    let new_r = prod_r * r - prod_im * im;
                                    let new_im = prod_r * im + prod_im * r;
                                    prod_r = new_r;
                                    prod_im = new_im;
                                }
                                Err(_) => {
                                    return Ok(EvalValue::Scalar(FormulaValue::Error(
                                        "#NUM!".into(),
                                    )));
                                }
                            }
                        }
                        EvalValue::Range { values, .. } => {
                            for v in values {
                                if let FormulaValue::Error(e) = v {
                                    return Ok(EvalValue::Scalar(FormulaValue::Error(e)));
                                }
                                if let FormulaValue::String(ref str_val) = v
                                    && (str_val.ends_with('j') || str_val.ends_with('J'))
                                {
                                    suffix = "j";
                                }
                                match parse_complex(&v) {
                                    Ok((r, im)) => {
                                        let new_r = prod_r * r - prod_im * im;
                                        let new_im = prod_r * im + prod_im * r;
                                        prod_r = new_r;
                                        prod_im = new_im;
                                    }
                                    Err(_) => {
                                        return Ok(EvalValue::Scalar(FormulaValue::Error(
                                            "#NUM!".into(),
                                        )));
                                    }
                                }
                            }
                        }
                        EvalValue::Lambda { .. } => {
                            return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                        }
                    }
                }
                let s = format_complex(prod_r, prod_im, suffix);
                Ok(EvalValue::Scalar(FormulaValue::String(s)))
            }
            "imdiv" if arguments.len() == 2 => {
                let v1 = self.eval_scalar(&arguments[0], depth + 1)?;
                if let FormulaValue::Error(e) = v1 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error(e)));
                }
                let v2 = self.eval_scalar(&arguments[1], depth + 1)?;
                if let FormulaValue::Error(e) = v2 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error(e)));
                }
                let suffix = if let FormulaValue::String(ref s) = v1 {
                    if s.ends_with('j') || s.ends_with('J') {
                        "j"
                    } else {
                        "i"
                    }
                } else if let FormulaValue::String(ref s) = v2 {
                    if s.ends_with('j') || s.ends_with('J') {
                        "j"
                    } else {
                        "i"
                    }
                } else {
                    "i"
                };
                match (parse_complex(&v1), parse_complex(&v2)) {
                    (Ok((r1, im1)), Ok((r2, im2))) => {
                        let den = r2 * r2 + im2 * im2;
                        if den == 0.0 {
                            Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                        } else {
                            let r = (r1 * r2 + im1 * im2) / den;
                            let im = (im1 * r2 - r1 * im2) / den;
                            let s = format_complex(r, im, suffix);
                            Ok(EvalValue::Scalar(FormulaValue::String(s)))
                        }
                    }
                    _ => Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into()))),
                }
            }
            "impower" if arguments.len() == 2 => {
                let v1 = self.eval_scalar(&arguments[0], depth + 1)?;
                if let FormulaValue::Error(e) = v1 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error(e)));
                }
                let p = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let suffix = if let FormulaValue::String(ref s) = v1 {
                    if s.ends_with('j') || s.ends_with('J') {
                        "j"
                    } else {
                        "i"
                    }
                } else {
                    "i"
                };
                match parse_complex(&v1) {
                    Ok((r, im)) => {
                        let m = (r * r + im * im).sqrt();
                        let theta = im.atan2(r);
                        let new_m = m.powf(p);
                        let new_theta = p * theta;
                        let new_r = new_m * new_theta.cos();
                        let new_im = new_m * new_theta.sin();
                        if !new_r.is_finite() || !new_im.is_finite() {
                            Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                        } else {
                            let s = format_complex(new_r, new_im, suffix);
                            Ok(EvalValue::Scalar(FormulaValue::String(s)))
                        }
                    }
                    Err(_) => Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into()))),
                }
            }
            "imexp" if arguments.len() == 1 => {
                let v = self.eval_scalar(&arguments[0], depth + 1)?;
                if let FormulaValue::Error(e) = v {
                    return Ok(EvalValue::Scalar(FormulaValue::Error(e)));
                }
                let suffix = if let FormulaValue::String(ref s) = v {
                    if s.ends_with('j') || s.ends_with('J') {
                        "j"
                    } else {
                        "i"
                    }
                } else {
                    "i"
                };
                match parse_complex(&v) {
                    Ok((x, y)) => {
                        let exp_x = x.exp();
                        if !exp_x.is_finite() {
                            Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                        } else {
                            let r = exp_x * y.cos();
                            let im = exp_x * y.sin();
                            let s = format_complex(r, im, suffix);
                            Ok(EvalValue::Scalar(FormulaValue::String(s)))
                        }
                    }
                    Err(_) => Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into()))),
                }
            }
            "imln" if arguments.len() == 1 => {
                let v = self.eval_scalar(&arguments[0], depth + 1)?;
                if let FormulaValue::Error(e) = v {
                    return Ok(EvalValue::Scalar(FormulaValue::Error(e)));
                }
                let suffix = if let FormulaValue::String(ref s) = v {
                    if s.ends_with('j') || s.ends_with('J') {
                        "j"
                    } else {
                        "i"
                    }
                } else {
                    "i"
                };
                match parse_complex(&v) {
                    Ok((x, y)) => {
                        if x == 0.0 && y == 0.0 {
                            Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                        } else {
                            let m = (x * x + y * y).sqrt();
                            let r = m.ln();
                            let im = y.atan2(x);
                            let s = format_complex(r, im, suffix);
                            Ok(EvalValue::Scalar(FormulaValue::String(s)))
                        }
                    }
                    Err(_) => Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into()))),
                }
            }
            "imsqrt" if arguments.len() == 1 => {
                let v = self.eval_scalar(&arguments[0], depth + 1)?;
                if let FormulaValue::Error(e) = v {
                    return Ok(EvalValue::Scalar(FormulaValue::Error(e)));
                }
                let suffix = if let FormulaValue::String(ref s) = v {
                    if s.ends_with('j') || s.ends_with('J') {
                        "j"
                    } else {
                        "i"
                    }
                } else {
                    "i"
                };
                match parse_complex(&v) {
                    Ok((x, y)) => {
                        let m = (x * x + y * y).sqrt();
                        let theta = y.atan2(x);
                        let sqrt_m = m.sqrt();
                        let r = sqrt_m * (theta / 2.0).cos();
                        let im = sqrt_m * (theta / 2.0).sin();
                        let s = format_complex(r, im, suffix);
                        Ok(EvalValue::Scalar(FormulaValue::String(s)))
                    }
                    Err(_) => Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into()))),
                }
            }
            "combina" if arguments.len() == 2 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?.trunc();
                let k = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.trunc();
                if n < 0.0 || k < 0.0 || (n + k - 1.0 < 0.0 && k > 0.0) {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                if k == 0.0 {
                    return Ok(EvalValue::Scalar(FormulaValue::Number(1.0)));
                }
                let big_n = (n + k - 1.0) as u64;
                let big_k = k as u64;
                if big_k > big_n {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                let k_eff = big_k.min(big_n - big_k);
                let mut res = 1.0f64;
                for j in 1..=k_eff {
                    res = res * ((big_n - k_eff + j) as f64) / (j as f64);
                }
                if !res.is_finite() {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Number(res.round())))
                }
            }
            "permutationa" if arguments.len() == 2 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?.trunc();
                let k = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.trunc();
                if n < 0.0 || k < 0.0 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                if n == 0.0 && k == 0.0 {
                    return Ok(EvalValue::Scalar(FormulaValue::Number(1.0)));
                }
                if n == 0.0 {
                    return Ok(EvalValue::Scalar(FormulaValue::Number(0.0)));
                }
                let res = n.powf(k);
                if !res.is_finite() {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Number(res.round())))
                }
            }
            "imsin" if arguments.len() == 1 => {
                let v = self.eval_scalar(&arguments[0], depth + 1)?;
                if let FormulaValue::Error(e) = v {
                    return Ok(EvalValue::Scalar(FormulaValue::Error(e)));
                }
                let suffix = if let FormulaValue::String(ref s) = v {
                    if s.ends_with('j') || s.ends_with('J') {
                        "j"
                    } else {
                        "i"
                    }
                } else {
                    "i"
                };
                match parse_complex(&v) {
                    Ok((x, y)) => {
                        let r = x.sin() * y.cosh();
                        let im = x.cos() * y.sinh();
                        if !r.is_finite() || !im.is_finite() {
                            Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                        } else {
                            let s = format_complex(r, im, suffix);
                            Ok(EvalValue::Scalar(FormulaValue::String(s)))
                        }
                    }
                    Err(_) => Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into()))),
                }
            }
            "imcos" if arguments.len() == 1 => {
                let v = self.eval_scalar(&arguments[0], depth + 1)?;
                if let FormulaValue::Error(e) = v {
                    return Ok(EvalValue::Scalar(FormulaValue::Error(e)));
                }
                let suffix = if let FormulaValue::String(ref s) = v {
                    if s.ends_with('j') || s.ends_with('J') {
                        "j"
                    } else {
                        "i"
                    }
                } else {
                    "i"
                };
                match parse_complex(&v) {
                    Ok((x, y)) => {
                        let r = x.cos() * y.cosh();
                        let im = -x.sin() * y.sinh();
                        if !r.is_finite() || !im.is_finite() {
                            Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                        } else {
                            let s = format_complex(r, im, suffix);
                            Ok(EvalValue::Scalar(FormulaValue::String(s)))
                        }
                    }
                    Err(_) => Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into()))),
                }
            }
            "imtan" if arguments.len() == 1 => {
                let v = self.eval_scalar(&arguments[0], depth + 1)?;
                if let FormulaValue::Error(e) = v {
                    return Ok(EvalValue::Scalar(FormulaValue::Error(e)));
                }
                let suffix = if let FormulaValue::String(ref s) = v {
                    if s.ends_with('j') || s.ends_with('J') {
                        "j"
                    } else {
                        "i"
                    }
                } else {
                    "i"
                };
                match parse_complex(&v) {
                    Ok((x, y)) => {
                        let denom = (2.0 * x).cos() + (2.0 * y).cosh();
                        if denom == 0.0 || !denom.is_finite() {
                            Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                        } else {
                            let r = (2.0 * x).sin() / denom;
                            let im = (2.0 * y).sinh() / denom;
                            if !r.is_finite() || !im.is_finite() {
                                Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                            } else {
                                let s = format_complex(r, im, suffix);
                                Ok(EvalValue::Scalar(FormulaValue::String(s)))
                            }
                        }
                    }
                    Err(_) => Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into()))),
                }
            }
            "imsinh" if arguments.len() == 1 => {
                let v = self.eval_scalar(&arguments[0], depth + 1)?;
                if let FormulaValue::Error(e) = v {
                    return Ok(EvalValue::Scalar(FormulaValue::Error(e)));
                }
                let suffix = if let FormulaValue::String(ref s) = v {
                    if s.ends_with('j') || s.ends_with('J') {
                        "j"
                    } else {
                        "i"
                    }
                } else {
                    "i"
                };
                match parse_complex(&v) {
                    Ok((x, y)) => {
                        let r = x.sinh() * y.cos();
                        let im = x.cosh() * y.sin();
                        if !r.is_finite() || !im.is_finite() {
                            Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                        } else {
                            let s = format_complex(r, im, suffix);
                            Ok(EvalValue::Scalar(FormulaValue::String(s)))
                        }
                    }
                    Err(_) => Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into()))),
                }
            }
            "imcosh" if arguments.len() == 1 => {
                let v = self.eval_scalar(&arguments[0], depth + 1)?;
                if let FormulaValue::Error(e) = v {
                    return Ok(EvalValue::Scalar(FormulaValue::Error(e)));
                }
                let suffix = if let FormulaValue::String(ref s) = v {
                    if s.ends_with('j') || s.ends_with('J') {
                        "j"
                    } else {
                        "i"
                    }
                } else {
                    "i"
                };
                match parse_complex(&v) {
                    Ok((x, y)) => {
                        let r = x.cosh() * y.cos();
                        let im = x.sinh() * y.sin();
                        if !r.is_finite() || !im.is_finite() {
                            Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                        } else {
                            let s = format_complex(r, im, suffix);
                            Ok(EvalValue::Scalar(FormulaValue::String(s)))
                        }
                    }
                    Err(_) => Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into()))),
                }
            }
            "imsec" if arguments.len() == 1 => {
                let v = self.eval_scalar(&arguments[0], depth + 1)?;
                if let FormulaValue::Error(e) = v {
                    return Ok(EvalValue::Scalar(FormulaValue::Error(e)));
                }
                let suffix = if let FormulaValue::String(ref s) = v {
                    if s.ends_with('j') || s.ends_with('J') {
                        "j"
                    } else {
                        "i"
                    }
                } else {
                    "i"
                };
                match parse_complex(&v) {
                    Ok((x, y)) => {
                        let u = x.cos() * y.cosh();
                        let w = -x.sin() * y.sinh();
                        let denom = u * u + w * w;
                        if denom == 0.0 || !denom.is_finite() {
                            Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                        } else {
                            let r = u / denom;
                            let im = -w / denom;
                            if !r.is_finite() || !im.is_finite() {
                                Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                            } else {
                                let s = format_complex(r, im, suffix);
                                Ok(EvalValue::Scalar(FormulaValue::String(s)))
                            }
                        }
                    }
                    Err(_) => Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into()))),
                }
            }
            "imcsc" if arguments.len() == 1 => {
                let v = self.eval_scalar(&arguments[0], depth + 1)?;
                if let FormulaValue::Error(e) = v {
                    return Ok(EvalValue::Scalar(FormulaValue::Error(e)));
                }
                let suffix = if let FormulaValue::String(ref s) = v {
                    if s.ends_with('j') || s.ends_with('J') {
                        "j"
                    } else {
                        "i"
                    }
                } else {
                    "i"
                };
                match parse_complex(&v) {
                    Ok((x, y)) => {
                        let u = x.sin() * y.cosh();
                        let w = x.cos() * y.sinh();
                        let denom = u * u + w * w;
                        if denom == 0.0 || !denom.is_finite() {
                            Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                        } else {
                            let r = u / denom;
                            let im = -w / denom;
                            if !r.is_finite() || !im.is_finite() {
                                Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                            } else {
                                let s = format_complex(r, im, suffix);
                                Ok(EvalValue::Scalar(FormulaValue::String(s)))
                            }
                        }
                    }
                    Err(_) => Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into()))),
                }
            }
            "imcot" if arguments.len() == 1 => {
                let v = self.eval_scalar(&arguments[0], depth + 1)?;
                if let FormulaValue::Error(e) = v {
                    return Ok(EvalValue::Scalar(FormulaValue::Error(e)));
                }
                let suffix = if let FormulaValue::String(ref s) = v {
                    if s.ends_with('j') || s.ends_with('J') {
                        "j"
                    } else {
                        "i"
                    }
                } else {
                    "i"
                };
                match parse_complex(&v) {
                    Ok((x, y)) => {
                        let denom = (2.0 * y).cosh() - (2.0 * x).cos();
                        if denom == 0.0 || !denom.is_finite() {
                            Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                        } else {
                            let r = (2.0 * x).sin() / denom;
                            let im = -(2.0 * y).sinh() / denom;
                            if !r.is_finite() || !im.is_finite() {
                                Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                            } else {
                                let s = format_complex(r, im, suffix);
                                Ok(EvalValue::Scalar(FormulaValue::String(s)))
                            }
                        }
                    }
                    Err(_) => Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into()))),
                }
            }
            "imlog10" if arguments.len() == 1 => {
                let v = self.eval_scalar(&arguments[0], depth + 1)?;
                if let FormulaValue::Error(e) = v {
                    return Ok(EvalValue::Scalar(FormulaValue::Error(e)));
                }
                let suffix = if let FormulaValue::String(ref s) = v {
                    if s.ends_with('j') || s.ends_with('J') {
                        "j"
                    } else {
                        "i"
                    }
                } else {
                    "i"
                };
                match parse_complex(&v) {
                    Ok((x, y)) => {
                        if x == 0.0 && y == 0.0 {
                            Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                        } else {
                            let ln10 = 10.0f64.ln();
                            let m = (x * x + y * y).sqrt();
                            let r = m.ln() / ln10;
                            let im = y.atan2(x) / ln10;
                            if !r.is_finite() || !im.is_finite() {
                                Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                            } else {
                                let s = format_complex(r, im, suffix);
                                Ok(EvalValue::Scalar(FormulaValue::String(s)))
                            }
                        }
                    }
                    Err(_) => Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into()))),
                }
            }
            "imlog2" if arguments.len() == 1 => {
                let v = self.eval_scalar(&arguments[0], depth + 1)?;
                if let FormulaValue::Error(e) = v {
                    return Ok(EvalValue::Scalar(FormulaValue::Error(e)));
                }
                let suffix = if let FormulaValue::String(ref s) = v {
                    if s.ends_with('j') || s.ends_with('J') {
                        "j"
                    } else {
                        "i"
                    }
                } else {
                    "i"
                };
                match parse_complex(&v) {
                    Ok((x, y)) => {
                        if x == 0.0 && y == 0.0 {
                            Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                        } else {
                            let ln2 = 2.0f64.ln();
                            let m = (x * x + y * y).sqrt();
                            let r = m.ln() / ln2;
                            let im = y.atan2(x) / ln2;
                            if !r.is_finite() || !im.is_finite() {
                                Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                            } else {
                                let s = format_complex(r, im, suffix);
                                Ok(EvalValue::Scalar(FormulaValue::String(s)))
                            }
                        }
                    }
                    Err(_) => Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into()))),
                }
            }
            "gammaln" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                match gammaln_f64(n) {
                    Ok(res) => Ok(EvalValue::Scalar(FormulaValue::Number(res))),
                    Err(e) => Ok(EvalValue::Scalar(FormulaValue::Error(e.into()))),
                }
            }
            "gamma" if arguments.len() == 1 => {
                let n = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                match gamma_f64(n) {
                    Ok(res) => Ok(EvalValue::Scalar(FormulaValue::Number(res))),
                    Err(e) => Ok(EvalValue::Scalar(FormulaValue::Error(e.into()))),
                }
            }
            "imargument" if arguments.len() == 1 => {
                let v = self.eval_scalar(&arguments[0], depth + 1)?;
                if let FormulaValue::Error(e) = v {
                    return Ok(EvalValue::Scalar(FormulaValue::Error(e)));
                }
                match parse_complex(&v) {
                    Ok((x, y)) => {
                        if x == 0.0 && y == 0.0 {
                            Ok(EvalValue::Scalar(FormulaValue::Error("#DIV/0!".into())))
                        } else {
                            let theta = y.atan2(x);
                            Ok(EvalValue::Scalar(FormulaValue::Number(theta)))
                        }
                    }
                    Err(_) => Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into()))),
                }
            }
            "erf" if arguments.len() == 1 || arguments.len() == 2 => {
                let lower = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                if arguments.len() == 2 {
                    let upper = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                    let res = erf_f64(upper) - erf_f64(lower);
                    Ok(EvalValue::Scalar(FormulaValue::Number(res)))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Number(erf_f64(lower))))
                }
            }
            "erf.precise" if arguments.len() == 1 => {
                let x = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                Ok(EvalValue::Scalar(FormulaValue::Number(erf_f64(x))))
            }
            "erfc" if arguments.len() == 1 => {
                let x = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                if x < 0.0 {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Number(1.0 - erf_f64(x))))
                }
            }
            "erfc.precise" if arguments.len() == 1 => {
                let x = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                Ok(EvalValue::Scalar(FormulaValue::Number(1.0 - erf_f64(x))))
            }
            "gauss" if arguments.len() == 1 => {
                let z = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let res = 0.5 * erf_f64(z / std::f64::consts::SQRT_2);
                Ok(EvalValue::Scalar(FormulaValue::Number(res)))
            }
            "phi" if arguments.len() == 1 => {
                let x = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let res = (-0.5 * x * x).exp() / (2.0 * std::f64::consts::PI).sqrt();
                Ok(EvalValue::Scalar(FormulaValue::Number(res)))
            }
            "besselj" if arguments.len() == 2 => {
                let x = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let n = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.trunc();
                if !(0.0..=100.0).contains(&n) {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                } else {
                    match besselj_f64(x, n as u32) {
                        Ok(res) => Ok(EvalValue::Scalar(FormulaValue::Number(res))),
                        Err(e) => Ok(EvalValue::Scalar(FormulaValue::Error(e.into()))),
                    }
                }
            }
            "besseli" if arguments.len() == 2 => {
                let x = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let n = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.trunc();
                if !(0.0..=100.0).contains(&n) {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                } else {
                    match besseli_f64(x, n as u32) {
                        Ok(res) => Ok(EvalValue::Scalar(FormulaValue::Number(res))),
                        Err(e) => Ok(EvalValue::Scalar(FormulaValue::Error(e.into()))),
                    }
                }
            }
            "bessely" if arguments.len() == 2 => {
                let x = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let n = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.trunc();
                if x <= 0.0 || !(0.0..=100.0).contains(&n) {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                } else {
                    match bessely_f64(x, n as u32) {
                        Ok(res) => Ok(EvalValue::Scalar(FormulaValue::Number(res))),
                        Err(e) => Ok(EvalValue::Scalar(FormulaValue::Error(e.into()))),
                    }
                }
            }
            "besselk" if arguments.len() == 2 => {
                let x = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let n = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.trunc();
                if x <= 0.0 || !(0.0..=100.0).contains(&n) {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                } else {
                    match besselk_f64(x, n as u32) {
                        Ok(res) => Ok(EvalValue::Scalar(FormulaValue::Number(res))),
                        Err(e) => Ok(EvalValue::Scalar(FormulaValue::Error(e.into()))),
                    }
                }
            }
            "standardize" if arguments.len() == 3 => {
                let x = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let mean = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let std_dev = to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?;
                if std_dev <= 0.0 {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Number(
                        (x - mean) / std_dev,
                    )))
                }
            }
            "normsdist" if arguments.len() == 1 => {
                let z = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let cdf = 0.5 * (1.0 + erf_f64(z / std::f64::consts::SQRT_2));
                Ok(EvalValue::Scalar(FormulaValue::Number(cdf)))
            }
            "norm.s.dist" if arguments.len() == 1 || arguments.len() == 2 => {
                let z = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let cumulative = if arguments.len() == 2 {
                    match self.eval_scalar(&arguments[1], depth + 1)? {
                        FormulaValue::Boolean(b) => b,
                        FormulaValue::Number(n) => n != 0.0,
                        _ => true,
                    }
                } else {
                    true
                };
                if cumulative {
                    let cdf = 0.5 * (1.0 + erf_f64(z / std::f64::consts::SQRT_2));
                    Ok(EvalValue::Scalar(FormulaValue::Number(cdf)))
                } else {
                    let pdf = (-0.5 * z * z).exp() / (2.0 * std::f64::consts::PI).sqrt();
                    Ok(EvalValue::Scalar(FormulaValue::Number(pdf)))
                }
            }
            "normdist" | "norm.dist" if arguments.len() == 4 => {
                let x = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let mean = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let std_dev = to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?;
                if std_dev <= 0.0 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                let cumulative = match self.eval_scalar(&arguments[3], depth + 1)? {
                    FormulaValue::Boolean(b) => b,
                    FormulaValue::Number(n) => n != 0.0,
                    _ => true,
                };
                let z = (x - mean) / std_dev;
                if cumulative {
                    let cdf = 0.5 * (1.0 + erf_f64(z / std::f64::consts::SQRT_2));
                    Ok(EvalValue::Scalar(FormulaValue::Number(cdf)))
                } else {
                    let pdf =
                        (-0.5 * z * z).exp() / (std_dev * (2.0 * std::f64::consts::PI).sqrt());
                    Ok(EvalValue::Scalar(FormulaValue::Number(pdf)))
                }
            }
            "expondist" | "expon.dist" if arguments.len() == 3 => {
                let x = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let lambda = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                if x < 0.0 || lambda <= 0.0 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                let cumulative = match self.eval_scalar(&arguments[2], depth + 1)? {
                    FormulaValue::Boolean(b) => b,
                    FormulaValue::Number(n) => n != 0.0,
                    _ => true,
                };
                if cumulative {
                    Ok(EvalValue::Scalar(FormulaValue::Number(
                        1.0 - (-lambda * x).exp(),
                    )))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Number(
                        lambda * (-lambda * x).exp(),
                    )))
                }
            }
            "weibull" | "weibull.dist" if arguments.len() == 4 => {
                let x = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let alpha = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let beta = to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?;
                if x < 0.0 || alpha <= 0.0 || beta <= 0.0 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                let cumulative = match self.eval_scalar(&arguments[3], depth + 1)? {
                    FormulaValue::Boolean(b) => b,
                    FormulaValue::Number(n) => n != 0.0,
                    _ => true,
                };
                let x_over_beta = x / beta;
                let pow_val = x_over_beta.powf(alpha);
                if cumulative {
                    Ok(EvalValue::Scalar(FormulaValue::Number(
                        1.0 - (-pow_val).exp(),
                    )))
                } else {
                    let pdf = (alpha / beta.powf(alpha)) * x.powf(alpha - 1.0) * (-pow_val).exp();
                    Ok(EvalValue::Scalar(FormulaValue::Number(pdf)))
                }
            }
            "convert" if arguments.len() == 3 => {
                let val = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let from = match self.eval_scalar(&arguments[1], depth + 1)? {
                    FormulaValue::String(s) => s,
                    _ => return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into()))),
                };
                let to = match self.eval_scalar(&arguments[2], depth + 1)? {
                    FormulaValue::String(s) => s,
                    _ => return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into()))),
                };
                match convert_units_f64(val, &from, &to) {
                    Ok(res) => Ok(EvalValue::Scalar(FormulaValue::Number(res))),
                    Err(e) => Ok(EvalValue::Scalar(FormulaValue::Error(e.into()))),
                }
            }
            "lognormdist" if arguments.len() == 3 => {
                let x = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let mean = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let std_dev = to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?;
                if x <= 0.0 || std_dev <= 0.0 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                let z = (x.ln() - mean) / std_dev;
                let cdf = 0.5 * (1.0 + erf_f64(z / std::f64::consts::SQRT_2));
                Ok(EvalValue::Scalar(FormulaValue::Number(cdf)))
            }
            "lognorm.dist" if arguments.len() == 4 => {
                let x = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let mean = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let std_dev = to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?;
                if x <= 0.0 || std_dev <= 0.0 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                let cumulative = match self.eval_scalar(&arguments[3], depth + 1)? {
                    FormulaValue::Boolean(b) => b,
                    FormulaValue::Number(n) => n != 0.0,
                    _ => true,
                };
                let z = (x.ln() - mean) / std_dev;
                if cumulative {
                    let cdf = 0.5 * (1.0 + erf_f64(z / std::f64::consts::SQRT_2));
                    Ok(EvalValue::Scalar(FormulaValue::Number(cdf)))
                } else {
                    let pdf =
                        (-0.5 * z * z).exp() / (x * std_dev * (2.0 * std::f64::consts::PI).sqrt());
                    Ok(EvalValue::Scalar(FormulaValue::Number(pdf)))
                }
            }
            "poisson" | "poisson.dist" if arguments.len() == 3 => {
                let x = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?.floor();
                let mean = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                if x < 0.0 || mean <= 0.0 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                let cumulative = match self.eval_scalar(&arguments[2], depth + 1)? {
                    FormulaValue::Boolean(b) => b,
                    FormulaValue::Number(n) => n != 0.0,
                    _ => true,
                };
                let k = x as u64;
                if cumulative {
                    let mut sum = 0.0;
                    let mut term = (-mean).exp();
                    sum += term;
                    for i in 1..=k {
                        term *= mean / (i as f64);
                        sum += term;
                    }
                    Ok(EvalValue::Scalar(FormulaValue::Number(sum.min(1.0))))
                } else {
                    let mut term = (-mean).exp();
                    for i in 1..=k {
                        term *= mean / (i as f64);
                    }
                    Ok(EvalValue::Scalar(FormulaValue::Number(term)))
                }
            }
            "binomdist" | "binom.dist" if arguments.len() == 4 => {
                let k_num = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?.floor();
                let n_num = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.floor();
                let p = to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?;
                if k_num < 0.0 || n_num < 0.0 || k_num > n_num || !(0.0..=1.0).contains(&p) {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                let cumulative = match self.eval_scalar(&arguments[3], depth + 1)? {
                    FormulaValue::Boolean(b) => b,
                    FormulaValue::Number(n) => n != 0.0,
                    _ => true,
                };
                let k = k_num as u64;
                let n = n_num as u64;
                let pmf = |i: u64| -> f64 {
                    if p == 0.0 {
                        if i == 0 { 1.0 } else { 0.0 }
                    } else if p == 1.0 {
                        if i == n { 1.0 } else { 0.0 }
                    } else {
                        let ln_comb = gammaln_f64((n + 1) as f64).unwrap_or(0.0)
                            - gammaln_f64((i + 1) as f64).unwrap_or(0.0)
                            - gammaln_f64((n - i + 1) as f64).unwrap_or(0.0);
                        (ln_comb + (i as f64) * p.ln() + ((n - i) as f64) * (1.0 - p).ln()).exp()
                    }
                };
                if cumulative {
                    let mut sum = 0.0;
                    for i in 0..=k {
                        sum += pmf(i);
                    }
                    Ok(EvalValue::Scalar(FormulaValue::Number(sum.min(1.0))))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Number(pmf(k))))
                }
            }
            "sln" if arguments.len() == 3 => {
                let cost = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let salvage = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let life = to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?;
                if life <= 0.0 {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Number(
                        (cost - salvage) / life,
                    )))
                }
            }
            "syd" if arguments.len() == 4 => {
                let cost = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let salvage = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let life = to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?;
                let per = to_number(&self.eval_scalar(&arguments[3], depth + 1)?)?;
                if life <= 0.0 || per < 1.0 || per > life {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())))
                } else {
                    let val = (cost - salvage) * (life - per + 1.0) * 2.0 / (life * (life + 1.0));
                    Ok(EvalValue::Scalar(FormulaValue::Number(val)))
                }
            }
            "npv" if arguments.len() >= 2 => {
                let rate = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                if rate <= -1.0 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                let mut sum = 0.0;
                let mut t = 1;
                for arg in &arguments[1..] {
                    match self.evaluate(arg, depth + 1)? {
                        EvalValue::Scalar(val) => {
                            if let Ok(n) = to_number(&val) {
                                sum += n / (1.0 + rate).powi(t);
                                t += 1;
                            }
                        }
                        EvalValue::Range { values, .. } => {
                            for c in values {
                                if let Ok(n) = to_number(&c) {
                                    sum += n / (1.0 + rate).powi(t);
                                    t += 1;
                                }
                            }
                        }
                        EvalValue::Lambda { .. } => {}
                    }
                }
                Ok(EvalValue::Scalar(FormulaValue::Number(sum)))
            }
            "pv" if (3..=5).contains(&arguments.len()) => {
                let rate = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let nper = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let pmt = to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?;
                let fv = if arguments.len() >= 4 {
                    to_number(&self.eval_scalar(&arguments[3], depth + 1)?)?
                } else {
                    0.0
                };
                let pmt_type = if arguments.len() == 5 {
                    to_number(&self.eval_scalar(&arguments[4], depth + 1)?)? != 0.0
                } else {
                    false
                };
                if rate == 0.0 {
                    Ok(EvalValue::Scalar(FormulaValue::Number(-(fv + pmt * nper))))
                } else {
                    let type_flag = if pmt_type { 1.0 } else { 0.0 };
                    let factor = (1.0 + rate).powf(nper);
                    let annuity_factor = (1.0 + rate * type_flag) * (factor - 1.0) / rate;
                    let pv = -(fv + pmt * annuity_factor) / factor;
                    Ok(EvalValue::Scalar(FormulaValue::Number(pv)))
                }
            }
            "fv" if (3..=5).contains(&arguments.len()) => {
                let rate = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let nper = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let pmt = to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?;
                let pv = if arguments.len() >= 4 {
                    to_number(&self.eval_scalar(&arguments[3], depth + 1)?)?
                } else {
                    0.0
                };
                let pmt_type = if arguments.len() == 5 {
                    to_number(&self.eval_scalar(&arguments[4], depth + 1)?)? != 0.0
                } else {
                    false
                };
                if rate == 0.0 {
                    Ok(EvalValue::Scalar(FormulaValue::Number(-(pv + pmt * nper))))
                } else {
                    let type_flag = if pmt_type { 1.0 } else { 0.0 };
                    let factor = (1.0 + rate).powf(nper);
                    let annuity_factor = (1.0 + rate * type_flag) * (factor - 1.0) / rate;
                    let fv = -pv * factor - pmt * annuity_factor;
                    Ok(EvalValue::Scalar(FormulaValue::Number(fv)))
                }
            }
            "pmt" if (3..=5).contains(&arguments.len()) => {
                let rate = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let nper = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let pv = to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?;
                if nper == 0.0 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                let fv = if arguments.len() >= 4 {
                    to_number(&self.eval_scalar(&arguments[3], depth + 1)?)?
                } else {
                    0.0
                };
                let pmt_type = if arguments.len() == 5 {
                    to_number(&self.eval_scalar(&arguments[4], depth + 1)?)? != 0.0
                } else {
                    false
                };
                if rate == 0.0 {
                    Ok(EvalValue::Scalar(FormulaValue::Number(-(pv + fv) / nper)))
                } else {
                    let type_flag = if pmt_type { 1.0 } else { 0.0 };
                    let factor = (1.0 + rate).powf(nper);
                    let annuity_factor = (1.0 + rate * type_flag) * (factor - 1.0) / rate;
                    let pmt = -(pv * factor + fv) / annuity_factor;
                    Ok(EvalValue::Scalar(FormulaValue::Number(pmt)))
                }
            }
            "irr" if arguments.len() == 1 || arguments.len() == 2 => {
                let cfs = match self.evaluate(&arguments[0], depth + 1)? {
                    EvalValue::Scalar(s) => {
                        if let Ok(n) = to_number(&s) {
                            vec![n]
                        } else {
                            vec![]
                        }
                    }
                    EvalValue::Range { values, .. } => {
                        let mut v = Vec::new();
                        for val in values {
                            if let Ok(n) = to_number(&val) {
                                v.push(n);
                            }
                        }
                        v
                    }
                    EvalValue::Lambda { .. } => {
                        return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                    }
                };
                if cfs.is_empty() {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                let guess = if arguments.len() == 2 {
                    to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?
                } else {
                    0.1
                };
                let has_pos = cfs.iter().any(|&x| x > 0.0);
                let has_neg = cfs.iter().any(|&x| x < 0.0);
                if !has_pos || !has_neg {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                let mut r = guess;
                for _ in 0..50 {
                    let mut f = 0.0;
                    let mut df = 0.0;
                    for (t, &cf) in cfs.iter().enumerate() {
                        let denom = (1.0 + r).powi(t as i32);
                        f += cf / denom;
                        if t > 0 {
                            df -= (t as f64) * cf / (denom * (1.0 + r));
                        }
                    }
                    if df.abs() < 1e-12 {
                        break;
                    }
                    let new_r = r - f / df;
                    if (new_r - r).abs() < 1e-7 {
                        return Ok(EvalValue::Scalar(FormulaValue::Number(new_r)));
                    }
                    r = new_r;
                }
                Ok(EvalValue::Scalar(FormulaValue::Number(r)))
            }
            "mirr" if arguments.len() == 3 => {
                let cfs = match self.evaluate(&arguments[0], depth + 1)? {
                    EvalValue::Scalar(s) => {
                        if let Ok(n) = to_number(&s) {
                            vec![n]
                        } else {
                            vec![]
                        }
                    }
                    EvalValue::Range { values, .. } => {
                        let mut v = Vec::new();
                        for val in values {
                            if let Ok(n) = to_number(&val) {
                                v.push(n);
                            }
                        }
                        v
                    }
                    EvalValue::Lambda { .. } => {
                        return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                    }
                };
                let finance_rate = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let reinvest_rate = to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?;
                let n = cfs.len();
                if n < 2 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#DIV/0!".into())));
                }
                let mut fv_pos = 0.0;
                let mut pv_neg = 0.0;
                for (t, &cf) in cfs.iter().enumerate() {
                    if cf > 0.0 {
                        fv_pos += cf * (1.0 + reinvest_rate).powi((n - 1 - t) as i32);
                    } else if cf < 0.0 {
                        pv_neg += cf / (1.0 + finance_rate).powi(t as i32);
                    }
                }
                if fv_pos == 0.0 || pv_neg == 0.0 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#DIV/0!".into())));
                }
                let mirr = (-fv_pos / pv_neg).powf(1.0 / ((n - 1) as f64)) - 1.0;
                Ok(EvalValue::Scalar(FormulaValue::Number(mirr)))
            }
            "disc" if (4..=5).contains(&arguments.len()) => {
                let settlement = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let maturity = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let pr = to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?;
                let redemption = to_number(&self.eval_scalar(&arguments[3], depth + 1)?)?;
                let basis = if arguments.len() == 5 {
                    to_number(&self.eval_scalar(&arguments[4], depth + 1)?)? as i32
                } else {
                    0
                };
                let days = maturity - settlement;
                if days <= 0.0 || pr <= 0.0 || redemption <= 0.0 || !(0..=4).contains(&basis) {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                let b = if basis == 1 || basis == 3 {
                    365.0
                } else {
                    360.0
                };
                let disc = ((redemption - pr) / redemption) * (b / days);
                Ok(EvalValue::Scalar(FormulaValue::Number(disc)))
            }
            "pricedisc" if (4..=5).contains(&arguments.len()) => {
                let settlement = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let maturity = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let discount = to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?;
                let redemption = to_number(&self.eval_scalar(&arguments[3], depth + 1)?)?;
                let basis = if arguments.len() == 5 {
                    to_number(&self.eval_scalar(&arguments[4], depth + 1)?)? as i32
                } else {
                    0
                };
                let days = maturity - settlement;
                if days <= 0.0 || discount <= 0.0 || redemption <= 0.0 || !(0..=4).contains(&basis)
                {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                let b = if basis == 1 || basis == 3 {
                    365.0
                } else {
                    360.0
                };
                let price = redemption - discount * redemption * (days / b);
                Ok(EvalValue::Scalar(FormulaValue::Number(price)))
            }
            "received" if (4..=5).contains(&arguments.len()) => {
                let settlement = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let maturity = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let investment = to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?;
                let discount = to_number(&self.eval_scalar(&arguments[3], depth + 1)?)?;
                let basis = if arguments.len() == 5 {
                    to_number(&self.eval_scalar(&arguments[4], depth + 1)?)? as i32
                } else {
                    0
                };
                let days = maturity - settlement;
                if days <= 0.0 || investment <= 0.0 || discount <= 0.0 || !(0..=4).contains(&basis)
                {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                let b = if basis == 1 || basis == 3 {
                    365.0
                } else {
                    360.0
                };
                let factor = 1.0 - discount * (days / b);
                if factor <= 0.0 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                let received = investment / factor;
                Ok(EvalValue::Scalar(FormulaValue::Number(received)))
            }
            "hypgeomdist" | "hypgeom.dist" if (4..=5).contains(&arguments.len()) => {
                let sample_s =
                    to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?.floor() as i64;
                let number_sample =
                    to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.floor() as i64;
                let population_s =
                    to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?.floor() as i64;
                let number_pop =
                    to_number(&self.eval_scalar(&arguments[3], depth + 1)?)?.floor() as i64;
                let cumulative = if arguments.len() == 5 {
                    to_number(&self.eval_scalar(&arguments[4], depth + 1)?)? != 0.0
                } else {
                    false
                };
                let k = sample_s;
                let n = number_sample;
                let cap_k = population_s;
                let cap_n = number_pop;
                if k < 0
                    || n <= 0
                    || cap_k <= 0
                    || cap_n <= 0
                    || k > n
                    || cap_k > cap_n
                    || n > cap_n
                    || k < 0.max(n - (cap_n - cap_k))
                {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                let ln_comb = |total: i64, choose: i64| -> f64 {
                    if choose < 0 || choose > total {
                        return f64::NEG_INFINITY;
                    }
                    gammaln_f64((total + 1) as f64).unwrap_or(0.0)
                        - gammaln_f64((choose + 1) as f64).unwrap_or(0.0)
                        - gammaln_f64((total - choose + 1) as f64).unwrap_or(0.0)
                };
                let pmf = |x: i64| -> f64 {
                    (ln_comb(cap_k, x) + ln_comb(cap_n - cap_k, n - x) - ln_comb(cap_n, n)).exp()
                };
                if cumulative {
                    let min_k = 0.max(n - (cap_n - cap_k));
                    let mut sum = 0.0;
                    for x in min_k..=k {
                        sum += pmf(x);
                    }
                    Ok(EvalValue::Scalar(FormulaValue::Number(sum.min(1.0))))
                } else {
                    Ok(EvalValue::Scalar(FormulaValue::Number(pmf(k))))
                }
            }
            "effect" if arguments.len() == 2 => {
                let nominal_rate = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let npery = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.floor() as i64;
                if nominal_rate <= 0.0 || npery < 1 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                let eff = (1.0 + nominal_rate / (npery as f64)).powi(npery as i32) - 1.0;
                Ok(EvalValue::Scalar(FormulaValue::Number(eff)))
            }
            "nominal" if arguments.len() == 2 => {
                let effect_rate = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let npery = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.floor() as i64;
                if effect_rate <= 0.0 || npery < 1 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                let nom = (npery as f64) * ((1.0 + effect_rate).powf(1.0 / (npery as f64)) - 1.0);
                Ok(EvalValue::Scalar(FormulaValue::Number(nom)))
            }
            "ipmt" if (4..=6).contains(&arguments.len()) => {
                let rate = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let per = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.floor() as i64;
                let nper = to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?.floor() as i64;
                let pv = to_number(&self.eval_scalar(&arguments[3], depth + 1)?)?;
                let fv = if arguments.len() >= 5 {
                    to_number(&self.eval_scalar(&arguments[4], depth + 1)?)?
                } else {
                    0.0
                };
                let pmt_type = if arguments.len() == 6 {
                    to_number(&self.eval_scalar(&arguments[5], depth + 1)?)? != 0.0
                } else {
                    false
                };
                if per < 1 || per > nper || nper <= 0 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                if rate == 0.0 {
                    return Ok(EvalValue::Scalar(FormulaValue::Number(0.0)));
                }
                let type_flag = if pmt_type { 1.0 } else { 0.0 };
                let factor_nper = (1.0 + rate).powf(nper as f64);
                let annuity_factor = (1.0 + rate * type_flag) * (factor_nper - 1.0) / rate;
                let pmt = -(pv * factor_nper + fv) / annuity_factor;
                if pmt_type && per == 1 {
                    return Ok(EvalValue::Scalar(FormulaValue::Number(0.0)));
                }
                let factor_prev = (1.0 + rate).powf((per - 1) as f64);
                let balance_prev =
                    pv * factor_prev + pmt * (1.0 + rate * type_flag) * (factor_prev - 1.0) / rate;
                let ipmt = -balance_prev * rate;
                Ok(EvalValue::Scalar(FormulaValue::Number(ipmt)))
            }
            "ppmt" if (4..=6).contains(&arguments.len()) => {
                let rate = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let per = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.floor() as i64;
                let nper = to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?.floor() as i64;
                let pv = to_number(&self.eval_scalar(&arguments[3], depth + 1)?)?;
                let fv = if arguments.len() >= 5 {
                    to_number(&self.eval_scalar(&arguments[4], depth + 1)?)?
                } else {
                    0.0
                };
                let pmt_type = if arguments.len() == 6 {
                    to_number(&self.eval_scalar(&arguments[5], depth + 1)?)? != 0.0
                } else {
                    false
                };
                if per < 1 || per > nper || nper <= 0 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                if rate == 0.0 {
                    let pmt = -(pv + fv) / (nper as f64);
                    return Ok(EvalValue::Scalar(FormulaValue::Number(pmt)));
                }
                let type_flag = if pmt_type { 1.0 } else { 0.0 };
                let factor_nper = (1.0 + rate).powf(nper as f64);
                let annuity_factor = (1.0 + rate * type_flag) * (factor_nper - 1.0) / rate;
                let pmt = -(pv * factor_nper + fv) / annuity_factor;
                let ipmt = if pmt_type && per == 1 {
                    0.0
                } else {
                    let factor_prev = (1.0 + rate).powf((per - 1) as f64);
                    let balance_prev = pv * factor_prev
                        + pmt * (1.0 + rate * type_flag) * (factor_prev - 1.0) / rate;
                    -balance_prev * rate
                };
                let ppmt = pmt - ipmt;
                Ok(EvalValue::Scalar(FormulaValue::Number(ppmt)))
            }
            "cumipmt" if arguments.len() == 6 => {
                let rate = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let nper = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.floor() as i64;
                let pv = to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?;
                let start_period =
                    to_number(&self.eval_scalar(&arguments[3], depth + 1)?)?.floor() as i64;
                let end_period =
                    to_number(&self.eval_scalar(&arguments[4], depth + 1)?)?.floor() as i64;
                let pmt_type = to_number(&self.eval_scalar(&arguments[5], depth + 1)?)? != 0.0;
                if rate <= 0.0
                    || nper <= 0
                    || pv <= 0.0
                    || start_period < 1
                    || end_period < start_period
                    || end_period > nper
                {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                let type_flag = if pmt_type { 1.0 } else { 0.0 };
                let factor_nper = (1.0 + rate).powf(nper as f64);
                let annuity_factor = (1.0 + rate * type_flag) * (factor_nper - 1.0) / rate;
                let pmt = -pv * factor_nper / annuity_factor;
                let mut total_interest = 0.0;
                for p in start_period..=end_period {
                    let ipmt = if pmt_type && p == 1 {
                        0.0
                    } else {
                        let factor_prev = (1.0 + rate).powf((p - 1) as f64);
                        let balance_prev = pv * factor_prev
                            + pmt * (1.0 + rate * type_flag) * (factor_prev - 1.0) / rate;
                        -balance_prev * rate
                    };
                    total_interest += ipmt;
                }
                Ok(EvalValue::Scalar(FormulaValue::Number(total_interest)))
            }
            "cumprinc" if arguments.len() == 6 => {
                let rate = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let nper = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.floor() as i64;
                let pv = to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?;
                let start_period =
                    to_number(&self.eval_scalar(&arguments[3], depth + 1)?)?.floor() as i64;
                let end_period =
                    to_number(&self.eval_scalar(&arguments[4], depth + 1)?)?.floor() as i64;
                let pmt_type = to_number(&self.eval_scalar(&arguments[5], depth + 1)?)? != 0.0;
                if rate <= 0.0
                    || nper <= 0
                    || pv <= 0.0
                    || start_period < 1
                    || end_period < start_period
                    || end_period > nper
                {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                let type_flag = if pmt_type { 1.0 } else { 0.0 };
                let factor_nper = (1.0 + rate).powf(nper as f64);
                let annuity_factor = (1.0 + rate * type_flag) * (factor_nper - 1.0) / rate;
                let pmt = -pv * factor_nper / annuity_factor;
                let mut total_principal = 0.0;
                for p in start_period..=end_period {
                    let ipmt = if pmt_type && p == 1 {
                        0.0
                    } else {
                        let factor_prev = (1.0 + rate).powf((p - 1) as f64);
                        let balance_prev = pv * factor_prev
                            + pmt * (1.0 + rate * type_flag) * (factor_prev - 1.0) / rate;
                        -balance_prev * rate
                    };
                    total_principal += pmt - ipmt;
                }
                Ok(EvalValue::Scalar(FormulaValue::Number(total_principal)))
            }
            "critbinom" | "binom.inv" if arguments.len() == 3 => {
                let trials =
                    to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?.floor() as i64;
                let prob_s = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let alpha = to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?;
                if trials < 0
                    || !(0.0..=1.0).contains(&prob_s)
                    || !(0.0..=1.0).contains(&alpha)
                    || trials > 10000
                {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                let ln_comb = |n: i64, k: i64| -> f64 {
                    if k < 0 || k > n {
                        return f64::NEG_INFINITY;
                    }
                    gammaln_f64((n + 1) as f64).unwrap_or(0.0)
                        - gammaln_f64((k + 1) as f64).unwrap_or(0.0)
                        - gammaln_f64((n - k + 1) as f64).unwrap_or(0.0)
                };
                let mut cumulative = 0.0;
                for k in 0..=trials {
                    let pmf = if prob_s == 0.0 {
                        if k == 0 { 1.0 } else { 0.0 }
                    } else if prob_s == 1.0 {
                        if k == trials { 1.0 } else { 0.0 }
                    } else {
                        (ln_comb(trials, k)
                            + (k as f64) * prob_s.ln()
                            + ((trials - k) as f64) * (1.0 - prob_s).ln())
                        .exp()
                    };
                    cumulative += pmf;
                    if cumulative >= alpha {
                        return Ok(EvalValue::Scalar(FormulaValue::Number(k as f64)));
                    }
                }
                Ok(EvalValue::Scalar(FormulaValue::Number(trials as f64)))
            }
            "duration" if (5..=6).contains(&arguments.len()) => {
                let settlement = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let maturity = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let coupon = to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?;
                let yld = to_number(&self.eval_scalar(&arguments[3], depth + 1)?)?;
                let frequency =
                    to_number(&self.eval_scalar(&arguments[4], depth + 1)?)?.floor() as i64;
                let basis = if arguments.len() == 6 {
                    to_number(&self.eval_scalar(&arguments[5], depth + 1)?)?.floor() as i32
                } else {
                    0
                };
                match duration_f64(settlement, maturity, coupon, yld, frequency, basis) {
                    Ok(d) => Ok(EvalValue::Scalar(FormulaValue::Number(d))),
                    Err(e) => Ok(EvalValue::Scalar(FormulaValue::Error(e.into()))),
                }
            }
            "mduration" if (5..=6).contains(&arguments.len()) => {
                let settlement = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let maturity = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let coupon = to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?;
                let yld = to_number(&self.eval_scalar(&arguments[3], depth + 1)?)?;
                let frequency =
                    to_number(&self.eval_scalar(&arguments[4], depth + 1)?)?.floor() as i64;
                let basis = if arguments.len() == 6 {
                    to_number(&self.eval_scalar(&arguments[5], depth + 1)?)?.floor() as i32
                } else {
                    0
                };
                match duration_f64(settlement, maturity, coupon, yld, frequency, basis) {
                    Ok(d) => {
                        let md = d / (1.0 + yld / (frequency as f64));
                        Ok(EvalValue::Scalar(FormulaValue::Number(md)))
                    }
                    Err(e) => Ok(EvalValue::Scalar(FormulaValue::Error(e.into()))),
                }
            }
            "intrate" if (4..=5).contains(&arguments.len()) => {
                let settlement = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let maturity = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let investment = to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?;
                let redemption = to_number(&self.eval_scalar(&arguments[3], depth + 1)?)?;
                let basis = if arguments.len() == 5 {
                    to_number(&self.eval_scalar(&arguments[4], depth + 1)?)?.floor() as i32
                } else {
                    0
                };
                match intrate_f64(settlement, maturity, investment, redemption, basis) {
                    Ok(r) => Ok(EvalValue::Scalar(FormulaValue::Number(r))),
                    Err(e) => Ok(EvalValue::Scalar(FormulaValue::Error(e.into()))),
                }
            }
            "chisq.dist" if arguments.len() == 3 => {
                let x = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let df = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.floor() as i64;
                let cumulative = to_number(&self.eval_scalar(&arguments[2], depth + 1)?)? != 0.0;
                if x < 0.0 || !(1..=100_000).contains(&df) {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                let k = df as f64;
                if cumulative {
                    match gammap_f64(k / 2.0, x / 2.0) {
                        Ok(p) => Ok(EvalValue::Scalar(FormulaValue::Number(p))),
                        Err(e) => Ok(EvalValue::Scalar(FormulaValue::Error(e.into()))),
                    }
                } else {
                    if x == 0.0 {
                        let val = if df == 2 {
                            0.5
                        } else if df > 2 {
                            0.0
                        } else {
                            return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                        };
                        return Ok(EvalValue::Scalar(FormulaValue::Number(val)));
                    }
                    let lna = match gammaln_f64(k / 2.0) {
                        Ok(v) => v,
                        Err(e) => return Ok(EvalValue::Scalar(FormulaValue::Error(e.into()))),
                    };
                    let ln_pdf = (k / 2.0 - 1.0) * x.ln() - x / 2.0 - (k / 2.0) * 2.0f64.ln() - lna;
                    Ok(EvalValue::Scalar(FormulaValue::Number(ln_pdf.exp())))
                }
            }
            "chidist" | "chisq.dist.rt" if arguments.len() == 2 => {
                let x = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let df = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.floor() as i64;
                if x < 0.0 || !(1..=100_000).contains(&df) {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                match gammap_f64((df as f64) / 2.0, x / 2.0) {
                    Ok(p) => Ok(EvalValue::Scalar(FormulaValue::Number(
                        (1.0 - p).clamp(0.0, 1.0),
                    ))),
                    Err(e) => Ok(EvalValue::Scalar(FormulaValue::Error(e.into()))),
                }
            }
            "chisq.inv" if arguments.len() == 2 => {
                let p = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let df = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.floor() as i64;
                if !(0.0..1.0).contains(&p) || !(1..=100_000).contains(&df) {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                match chisq_inv_f64(p, df as f64) {
                    Ok(inv) => Ok(EvalValue::Scalar(FormulaValue::Number(inv))),
                    Err(e) => Ok(EvalValue::Scalar(FormulaValue::Error(e.into()))),
                }
            }
            "chisq.inv.rt" | "chiinv" if arguments.len() == 2 => {
                let p = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let df = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.floor() as i64;
                if p <= 0.0 || p > 1.0 || !(1..=100_000).contains(&df) {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                match chisq_inv_f64(1.0 - p, df as f64) {
                    Ok(inv) => Ok(EvalValue::Scalar(FormulaValue::Number(inv))),
                    Err(e) => Ok(EvalValue::Scalar(FormulaValue::Error(e.into()))),
                }
            }
            "sumxmy2" | "sumx2my2" | "sumx2py2" if arguments.len() == 2 => {
                let (vals_x, r_x, c_x) = match self.evaluate(&arguments[0], depth + 1)? {
                    EvalValue::Scalar(s) => (vec![s], 1, 1),
                    EvalValue::Range { values, rows, cols } => (values, rows, cols),
                    EvalValue::Lambda { .. } => {
                        return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                    }
                };
                let (vals_y, r_y, c_y) = match self.evaluate(&arguments[1], depth + 1)? {
                    EvalValue::Scalar(s) => (vec![s], 1, 1),
                    EvalValue::Range { values, rows, cols } => (values, rows, cols),
                    EvalValue::Lambda { .. } => {
                        return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                    }
                };
                if r_x != r_y || c_x != c_y || vals_x.len() != vals_y.len() {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#N/A!".into())));
                }
                let mut sum = 0.0f64;
                for (vx, vy) in vals_x.iter().zip(vals_y.iter()) {
                    if let FormulaValue::Error(e) = vx {
                        return Ok(EvalValue::Scalar(FormulaValue::Error(e.clone())));
                    }
                    if let FormulaValue::Error(e) = vy {
                        return Ok(EvalValue::Scalar(FormulaValue::Error(e.clone())));
                    }
                    if let (Ok(nx), Ok(ny)) = (to_number(vx), to_number(vy)) {
                        let term = match name {
                            "sumxmy2" => (nx - ny) * (nx - ny),
                            "sumx2my2" => (nx * nx) - (ny * ny),
                            "sumx2py2" => (nx * nx) + (ny * ny),
                            _ => 0.0,
                        };
                        sum += term;
                    }
                }
                Ok(EvalValue::Scalar(FormulaValue::Number(sum)))
            }
            "multinomial" if !arguments.is_empty() => {
                let mut nums = Vec::new();
                for arg in arguments {
                    match self.evaluate(arg, depth + 1)? {
                        EvalValue::Scalar(s) => {
                            if let FormulaValue::Error(e) = s {
                                return Ok(EvalValue::Scalar(FormulaValue::Error(e)));
                            }
                            if let Ok(n) = to_number(&s) {
                                if n < 0.0 {
                                    return Ok(EvalValue::Scalar(FormulaValue::Error(
                                        "#NUM!".into(),
                                    )));
                                }
                                nums.push(n.trunc() as u64);
                            }
                        }
                        EvalValue::Range { values, .. } => {
                            for v in values {
                                if let FormulaValue::Error(e) = v {
                                    return Ok(EvalValue::Scalar(FormulaValue::Error(e)));
                                }
                                if let Ok(n) = to_number(&v) {
                                    if n < 0.0 {
                                        return Ok(EvalValue::Scalar(FormulaValue::Error(
                                            "#NUM!".into(),
                                        )));
                                    }
                                    nums.push(n.trunc() as u64);
                                }
                            }
                        }
                        EvalValue::Lambda { .. } => {
                            return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                        }
                    }
                }
                let total: u64 = nums.iter().sum();
                if total > 170 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                fn fact_f64(n: u64) -> f64 {
                    let mut res = 1.0f64;
                    for i in 2..=n {
                        res *= i as f64;
                    }
                    res
                }
                let mut denom = 1.0f64;
                for &n in &nums {
                    denom *= fact_f64(n);
                }
                let num = fact_f64(total);
                let result = (num / denom).round();
                Ok(EvalValue::Scalar(FormulaValue::Number(result)))
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
                    EvalValue::Lambda { .. } => {
                        return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                    }
                };
                let return_target = self.evaluate(&arguments[2], depth + 1)?;
                let (ret_vals, r_rows, r_cols) = match return_target {
                    EvalValue::Range { values, rows, cols } => (values, rows, cols),
                    EvalValue::Scalar(s) => (vec![s], 1, 1),
                    EvalValue::Lambda { .. } => {
                        return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                    }
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
                            let mut row_vals = Vec::with_capacity(r_cols);
                            for c in 0..r_cols {
                                row_vals.push(ret_vals[idx * r_cols + c].clone());
                            }
                            Ok(EvalValue::Range {
                                values: row_vals,
                                rows: 1,
                                cols: r_cols,
                            })
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
                    EvalValue::Lambda { .. } => {
                        return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                    }
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
                    EvalValue::Scalar(_) | EvalValue::Lambda { .. } => 1.0,
                    EvalValue::Range { rows, .. } => rows as f64,
                };
                Ok(EvalValue::Scalar(FormulaValue::Number(res)))
            }
            "columns" if arguments.len() == 1 => {
                let res = match self.evaluate(&arguments[0], depth + 1)? {
                    EvalValue::Scalar(_) | EvalValue::Lambda { .. } => 1.0,
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
            | "valuetotext" | "vstack" | "hstack" | "sequence" | "single" | "transpose"
            | "mmult" | "munit" | "mdeterm" | "minverse" => {
                self.evaluate_array_manipulation(name, arguments, depth + 1)
            }
            "len" | "left" | "right" | "mid" | "concatenate" | "concat" | "value" | "trim"
            | "upper" | "lower" | "exact" | "rept" | "substitute" | "replace" | "char" | "code"
            | "clean" | "t" | "n" | "find" | "search" | "hyperlink" | "proper" | "unichar"
            | "unicode" | "hex2dec" | "dec2hex" | "bin2dec" | "dec2bin" | "oct2dec" | "dec2oct"
            | "textjoin" | "textbefore" | "textafter" | "textsplit" | "base" | "decimal"
            | "encodeurl" | "bin2hex" | "hex2bin" | "oct2hex" | "hex2oct" | "numbervalue"
            | "lenb" | "leftb" | "rightb" | "midb" => {
                self.evaluate_string_function(name, arguments, depth + 1)
            }
            "map" | "reduce" | "scan" | "byrow" | "bycol" | "makearray" | "isomitted" => {
                self.evaluate_lambda_helper(name, arguments, depth + 1)
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
                EvalValue::Lambda { .. } => {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                }
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
                        EvalValue::Lambda { .. } => {
                            return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
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
                        EvalValue::Lambda { .. } => {
                            return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
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
            "encodeurl" if arguments.len() == 1 => {
                let scalar = self.eval_scalar(&arguments[0], depth + 1)?;
                let text = to_string(&scalar)?;
                use std::fmt::Write;
                let mut out = String::with_capacity(text.len());
                for b in text.as_bytes() {
                    if b.is_ascii_alphanumeric() || matches!(*b, b'-' | b'_' | b'.' | b'~') {
                        out.push(*b as char);
                    } else {
                        let _ = write!(out, "%{:02X}", b);
                    }
                    if out.len() > self.limits.max_string_bytes {
                        return Err("resource_limit");
                    }
                }
                Ok(EvalValue::Scalar(FormulaValue::String(out)))
            }
            "bin2hex" if arguments.len() == 1 || arguments.len() == 2 => {
                let s = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let places = if arguments.len() == 2 {
                    Some(to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?)
                } else {
                    None
                };
                let val = bin_to_hex(&s, places);
                if let FormulaValue::String(ref out_s) = val {
                    self.check_string_size(out_s)?;
                }
                Ok(EvalValue::Scalar(val))
            }
            "hex2bin" if arguments.len() == 1 || arguments.len() == 2 => {
                let s = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let places = if arguments.len() == 2 {
                    Some(to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?)
                } else {
                    None
                };
                let val = hex_to_bin(&s, places);
                if let FormulaValue::String(ref out_s) = val {
                    self.check_string_size(out_s)?;
                }
                Ok(EvalValue::Scalar(val))
            }
            "oct2hex" if arguments.len() == 1 || arguments.len() == 2 => {
                let s = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let places = if arguments.len() == 2 {
                    Some(to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?)
                } else {
                    None
                };
                let val = oct_to_hex(&s, places);
                if let FormulaValue::String(ref out_s) = val {
                    self.check_string_size(out_s)?;
                }
                Ok(EvalValue::Scalar(val))
            }
            "hex2oct" if arguments.len() == 1 || arguments.len() == 2 => {
                let s = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let places = if arguments.len() == 2 {
                    Some(to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?)
                } else {
                    None
                };
                let val = hex_to_oct(&s, places);
                if let FormulaValue::String(ref out_s) = val {
                    self.check_string_size(out_s)?;
                }
                Ok(EvalValue::Scalar(val))
            }
            "numbervalue" if (1..=3).contains(&arguments.len()) => {
                let text = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let dec_sep = if arguments.len() >= 2 {
                    Some(to_string(&self.eval_scalar(&arguments[1], depth + 1)?)?)
                } else {
                    None
                };
                let grp_sep = if arguments.len() == 3 {
                    Some(to_string(&self.eval_scalar(&arguments[2], depth + 1)?)?)
                } else {
                    None
                };
                let val = number_value(&text, dec_sep.as_deref(), grp_sep.as_deref());
                Ok(EvalValue::Scalar(val))
            }
            "lenb" if arguments.len() == 1 => {
                let text = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let count = string_dbcs_bytes(&text);
                Ok(EvalValue::Scalar(FormulaValue::Number(count as f64)))
            }
            "leftb" if arguments.len() == 1 || arguments.len() == 2 => {
                let text = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let max_bytes = if arguments.len() == 2 {
                    nonnegative_count(&self.eval_scalar(&arguments[1], depth + 1)?)?
                } else {
                    1
                };
                let mut accumulated = 0;
                let mut result = String::new();
                for c in text.chars() {
                    let w = char_dbcs_bytes(c);
                    if accumulated + w > max_bytes {
                        break;
                    }
                    accumulated += w;
                    result.push(c);
                }
                self.check_string_size(&result)?;
                Ok(EvalValue::Scalar(FormulaValue::String(result)))
            }
            "rightb" if arguments.len() == 1 || arguments.len() == 2 => {
                let text = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let max_bytes = if arguments.len() == 2 {
                    nonnegative_count(&self.eval_scalar(&arguments[1], depth + 1)?)?
                } else {
                    1
                };
                let mut accumulated = 0;
                let mut chars_rev = Vec::new();
                for c in text.chars().rev() {
                    let w = char_dbcs_bytes(c);
                    if accumulated + w > max_bytes {
                        break;
                    }
                    accumulated += w;
                    chars_rev.push(c);
                }
                chars_rev.reverse();
                let result: String = chars_rev.into_iter().collect();
                self.check_string_size(&result)?;
                Ok(EvalValue::Scalar(FormulaValue::String(result)))
            }
            "midb" if arguments.len() == 3 => {
                let text = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let start_byte = nonnegative_count(&self.eval_scalar(&arguments[1], depth + 1)?)?;
                let num_bytes = nonnegative_count(&self.eval_scalar(&arguments[2], depth + 1)?)?;
                if start_byte == 0 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                }
                let end_byte = start_byte.saturating_add(num_bytes).saturating_sub(1);
                let mut current_byte = 1;
                let mut result = String::new();
                for c in text.chars() {
                    let w = char_dbcs_bytes(c);
                    let char_start = current_byte;
                    let char_end = current_byte + w - 1;
                    current_byte += w;

                    if char_start >= start_byte && char_end <= end_byte {
                        result.push(c);
                    }
                }
                self.check_string_size(&result)?;
                Ok(EvalValue::Scalar(FormulaValue::String(result)))
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
        if name == "single" {
            if arguments.len() != 1 {
                return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
            }
            return match self.evaluate(&arguments[0], depth + 1)? {
                EvalValue::Scalar(s) => Ok(EvalValue::Scalar(s)),
                EvalValue::Range { mut values, .. } => {
                    let first = if values.is_empty() {
                        FormulaValue::Blank
                    } else {
                        values.swap_remove(0)
                    };
                    Ok(EvalValue::Scalar(first))
                }
                EvalValue::Lambda { .. } => {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())))
                }
            };
        }
        if name == "transpose" {
            if arguments.len() != 1 {
                return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
            }
            return match self.evaluate(&arguments[0], depth + 1)? {
                EvalValue::Scalar(s) => Ok(EvalValue::Scalar(s)),
                EvalValue::Range { values, rows, cols } => {
                    if rows == 1 && cols == 1 {
                        return Ok(EvalValue::Scalar(
                            values.into_iter().next().unwrap_or(FormulaValue::Blank),
                        ));
                    }
                    let new_rows = cols;
                    let new_cols = rows;
                    let mut transposed = Vec::with_capacity(values.len());
                    for r_new in 0..new_rows {
                        for c_new in 0..new_cols {
                            transposed.push(values[c_new * cols + r_new].clone());
                        }
                    }
                    Ok(EvalValue::Range {
                        values: transposed,
                        rows: new_rows,
                        cols: new_cols,
                    })
                }
                EvalValue::Lambda { .. } => {
                    Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())))
                }
            };
        }
        if name == "munit" {
            if arguments.len() != 1 {
                return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
            }
            let dim_num = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?.trunc() as i64;
            if dim_num <= 0 || dim_num > 256 {
                return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
            }
            if dim_num == 1 {
                return Ok(EvalValue::Scalar(FormulaValue::Number(1.0)));
            }
            let n = dim_num as usize;
            let mut values = Vec::with_capacity(n * n);
            for r in 0..n {
                for c in 0..n {
                    values.push(FormulaValue::Number(if r == c { 1.0 } else { 0.0 }));
                }
            }
            return Ok(EvalValue::Range {
                values,
                rows: n,
                cols: n,
            });
        }
        if name == "mmult" {
            if arguments.len() != 2 {
                return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
            }
            let (rows1, cols1, vals1) = match self.evaluate(&arguments[0], depth + 1)? {
                EvalValue::Scalar(s) => (1, 1, vec![s]),
                EvalValue::Range { values, rows, cols } => (rows, cols, values),
                EvalValue::Lambda { .. } => {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                }
            };
            let (rows2, cols2, vals2) = match self.evaluate(&arguments[1], depth + 1)? {
                EvalValue::Scalar(s) => (1, 1, vec![s]),
                EvalValue::Range { values, rows, cols } => (rows, cols, values),
                EvalValue::Lambda { .. } => {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                }
            };
            if cols1 != rows2 || rows1 * cols2 > 100_000 {
                return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
            }
            let mut nums1 = Vec::with_capacity(vals1.len());
            for v in &vals1 {
                if let FormulaValue::Error(e) = v {
                    return Ok(EvalValue::Scalar(FormulaValue::Error(e.clone())));
                }
                match to_number(v) {
                    Ok(n) => nums1.push(n),
                    Err(_) => return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into()))),
                }
            }
            let mut nums2 = Vec::with_capacity(vals2.len());
            for v in &vals2 {
                if let FormulaValue::Error(e) = v {
                    return Ok(EvalValue::Scalar(FormulaValue::Error(e.clone())));
                }
                match to_number(v) {
                    Ok(n) => nums2.push(n),
                    Err(_) => return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into()))),
                }
            }
            let mut res_values = Vec::with_capacity(rows1 * cols2);
            for r in 0..rows1 {
                for c in 0..cols2 {
                    let mut sum = 0.0;
                    for k in 0..cols1 {
                        sum += nums1[r * cols1 + k] * nums2[k * cols2 + c];
                    }
                    res_values.push(FormulaValue::Number(sum));
                }
            }
            if rows1 == 1 && cols2 == 1 {
                return Ok(EvalValue::Scalar(
                    res_values
                        .into_iter()
                        .next()
                        .unwrap_or(FormulaValue::Number(0.0)),
                ));
            }
            return Ok(EvalValue::Range {
                values: res_values,
                rows: rows1,
                cols: cols2,
            });
        }
        if name == "mdeterm" {
            if arguments.len() != 1 {
                return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
            }
            let (rows, cols, vals) = match self.evaluate(&arguments[0], depth + 1)? {
                EvalValue::Scalar(s) => (1, 1, vec![s]),
                EvalValue::Range { values, rows, cols } => (rows, cols, values),
                EvalValue::Lambda { .. } => {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                }
            };
            if rows != cols || rows == 0 || rows > 64 {
                return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
            }
            let n = rows;
            let mut matrix = Vec::with_capacity(n * n);
            for v in &vals {
                if let FormulaValue::Error(e) = v {
                    return Ok(EvalValue::Scalar(FormulaValue::Error(e.clone())));
                }
                match to_number(v) {
                    Ok(num) => matrix.push(num),
                    Err(_) => return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into()))),
                }
            }
            if n == 1 {
                return Ok(EvalValue::Scalar(FormulaValue::Number(matrix[0])));
            }
            if n == 2 {
                let det = matrix[0] * matrix[3] - matrix[1] * matrix[2];
                let rounded = if (det - det.round()).abs() < 1e-12 {
                    det.round()
                } else {
                    det
                };
                return Ok(EvalValue::Scalar(FormulaValue::Number(rounded)));
            }
            let mut det = 1.0f64;
            for i in 0..n {
                let mut pivot = i;
                let mut max_val = matrix[i * n + i].abs();
                for r in (i + 1)..n {
                    let val = matrix[r * n + i].abs();
                    if val > max_val {
                        max_val = val;
                        pivot = r;
                    }
                }
                if max_val < 1e-15 {
                    return Ok(EvalValue::Scalar(FormulaValue::Number(0.0)));
                }
                if pivot != i {
                    for c in 0..n {
                        matrix.swap(i * n + c, pivot * n + c);
                    }
                    det = -det;
                }
                let diag = matrix[i * n + i];
                det *= diag;
                for r in (i + 1)..n {
                    let factor = matrix[r * n + i] / diag;
                    for c in (i + 1)..n {
                        matrix[r * n + c] -= factor * matrix[i * n + c];
                    }
                }
            }
            let rounded = if (det - det.round()).abs() < 1e-12 {
                det.round()
            } else {
                det
            };
            return Ok(EvalValue::Scalar(FormulaValue::Number(rounded)));
        }
        if name == "minverse" {
            if arguments.len() != 1 {
                return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
            }
            let (rows, cols, vals) = match self.evaluate(&arguments[0], depth + 1)? {
                EvalValue::Scalar(s) => (1, 1, vec![s]),
                EvalValue::Range { values, rows, cols } => (rows, cols, values),
                EvalValue::Lambda { .. } => {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                }
            };
            if rows != cols || rows == 0 || rows > 64 {
                return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
            }
            let n = rows;
            let mut matrix = Vec::with_capacity(n * n);
            for v in &vals {
                if let FormulaValue::Error(e) = v {
                    return Ok(EvalValue::Scalar(FormulaValue::Error(e.clone())));
                }
                match to_number(v) {
                    Ok(num) => matrix.push(num),
                    Err(_) => return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into()))),
                }
            }
            if n == 1 {
                if matrix[0] == 0.0 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#DIV/0!".into())));
                }
                return Ok(EvalValue::Scalar(FormulaValue::Number(1.0 / matrix[0])));
            }
            let mut aug = vec![0.0f64; n * 2 * n];
            for r in 0..n {
                for c in 0..n {
                    aug[r * (2 * n) + c] = matrix[r * n + c];
                }
                aug[r * (2 * n) + n + r] = 1.0;
            }
            for i in 0..n {
                let mut pivot = i;
                let mut max_val = aug[i * (2 * n) + i].abs();
                for r in (i + 1)..n {
                    let val = aug[r * (2 * n) + i].abs();
                    if val > max_val {
                        max_val = val;
                        pivot = r;
                    }
                }
                if max_val < 1e-15 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#NUM!".into())));
                }
                if pivot != i {
                    for c in 0..(2 * n) {
                        aug.swap(i * (2 * n) + c, pivot * (2 * n) + c);
                    }
                }
                let diag = aug[i * (2 * n) + i];
                for c in 0..(2 * n) {
                    aug[i * (2 * n) + c] /= diag;
                }
                for r in 0..n {
                    if r != i {
                        let factor = aug[r * (2 * n) + i];
                        for c in 0..(2 * n) {
                            let sub = factor * aug[i * (2 * n) + c];
                            aug[r * (2 * n) + c] -= sub;
                        }
                    }
                }
            }
            let mut res_vals = Vec::with_capacity(n * n);
            for r in 0..n {
                for c in 0..n {
                    let val = aug[r * (2 * n) + n + c];
                    let rounded = if (val - val.round()).abs() < 1e-12 {
                        val.round()
                    } else {
                        val
                    };
                    res_vals.push(FormulaValue::Number(rounded));
                }
            }
            return Ok(EvalValue::Range {
                values: res_vals,
                rows: n,
                cols: n,
            });
        }
        if name == "sequence" {
            if arguments.len() > 4 {
                return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
            }
            let rows_num = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?.trunc() as i64;
            if rows_num <= 0 {
                return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
            }
            let cols_num = if arguments.len() >= 2 {
                to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.trunc() as i64
            } else {
                1
            };
            if cols_num <= 0 {
                return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
            }
            let start = if arguments.len() >= 3 {
                to_number(&self.eval_scalar(&arguments[2], depth + 1)?)?
            } else {
                1.0
            };
            let step = if arguments.len() >= 4 {
                to_number(&self.eval_scalar(&arguments[3], depth + 1)?)?
            } else {
                1.0
            };
            let r = rows_num as usize;
            let c = cols_num as usize;
            let total = r.saturating_mul(c);
            if total > 100_000 || total > self.limits.max_range_cells {
                return Err("resource_limit");
            }
            if r == 1 && c == 1 {
                return Ok(EvalValue::Scalar(FormulaValue::Number(start)));
            }
            let mut seq_values = Vec::with_capacity(total);
            for i in 0..total {
                seq_values.push(FormulaValue::Number(start + (i as f64) * step));
            }
            return Ok(EvalValue::Range {
                values: seq_values,
                rows: r,
                cols: c,
            });
        }
        if name == "vstack" || name == "hstack" {
            let mut grids: Vec<EvalGrid> = Vec::new();
            for arg in arguments {
                let grid = match self.evaluate(arg, depth + 1)? {
                    EvalValue::Scalar(s) => (vec![s], 1, 1),
                    EvalValue::Range { values, rows, cols } => (values, rows, cols),
                    EvalValue::Lambda { .. } => {
                        return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                    }
                };
                grids.push(grid);
            }
            if name == "vstack" {
                let total_rows: usize = grids.iter().map(|(_, r, _)| *r).sum();
                let max_cols: usize = grids.iter().map(|(_, _, c)| *c).max().unwrap_or(0);
                if total_rows == 0 || max_cols == 0 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#CALC!".into())));
                }
                if total_rows.saturating_mul(max_cols) > 100_000 {
                    return Err("resource_limit");
                }
                let mut out_values = Vec::with_capacity(total_rows * max_cols);
                for (vals, r, c) in grids {
                    for row_idx in 0..r {
                        for col_idx in 0..max_cols {
                            if col_idx < c {
                                out_values.push(vals[row_idx * c + col_idx].clone());
                            } else {
                                out_values.push(FormulaValue::Error("#N/A".into()));
                            }
                        }
                    }
                }
                return Ok(EvalValue::Range {
                    values: out_values,
                    rows: total_rows,
                    cols: max_cols,
                });
            } else {
                let max_rows: usize = grids.iter().map(|(_, r, _)| *r).max().unwrap_or(0);
                let total_cols: usize = grids.iter().map(|(_, _, c)| *c).sum();
                if max_rows == 0 || total_cols == 0 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#CALC!".into())));
                }
                if max_rows.saturating_mul(total_cols) > 100_000 {
                    return Err("resource_limit");
                }
                let mut out_values = Vec::with_capacity(max_rows * total_cols);
                for row_idx in 0..max_rows {
                    for (vals, r, c) in &grids {
                        for col_idx in 0..*c {
                            if row_idx < *r {
                                out_values.push(vals[row_idx * *c + col_idx].clone());
                            } else {
                                out_values.push(FormulaValue::Error("#N/A".into()));
                            }
                        }
                    }
                }
                return Ok(EvalValue::Range {
                    values: out_values,
                    rows: max_rows,
                    cols: total_cols,
                });
            }
        }
        let (values, orig_rows, orig_cols) = match self.evaluate(&arguments[0], depth + 1)? {
            EvalValue::Scalar(s) => (vec![s], 1, 1),
            EvalValue::Range { values, rows, cols } => (values, rows, cols),
            EvalValue::Lambda { .. } => {
                return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
            }
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
                    EvalValue::Lambda { .. } => {
                        return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                    }
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
                    EvalValue::Lambda { .. } => {
                        return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                    }
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

    fn evaluate_lambda_helper(
        &mut self,
        name: &str,
        arguments: &[Expr],
        depth: usize,
    ) -> Result<EvalValue, &'static str> {
        match name {
            "map" => {
                if arguments.len() < 2 {
                    return Err("unsupported");
                }
                let num_arrays = arguments.len() - 1;
                let lambda_val = self.evaluate(&arguments[num_arrays], depth + 1)?;
                let (params_len, is_lambda) = match &lambda_val {
                    EvalValue::Lambda { parameters, .. } => (parameters.len(), true),
                    _ => (0, false),
                };
                if !is_lambda || params_len != num_arrays {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                }

                let mut grids = Vec::with_capacity(num_arrays);
                for arg in &arguments[..num_arrays] {
                    match self.eval_to_grid(arg, depth + 1)? {
                        Some(grid) => grids.push(grid),
                        None => {
                            return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                        }
                    }
                }

                let (rows, cols) = (grids[0].1, grids[0].2);
                for g in &grids[1..] {
                    if g.1 != rows || g.2 != cols {
                        return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                    }
                }

                let total = rows.saturating_mul(cols);
                if total > 10_000 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#CALC!".into())));
                }

                let mut results = Vec::with_capacity(total);
                for i in 0..total {
                    let cell_args: Vec<EvalValue> = grids
                        .iter()
                        .map(|(vals, _, _)| EvalValue::Scalar(vals[i].clone()))
                        .collect();
                    let res = self.eval_lambda_to_scalar(&lambda_val, cell_args, depth + 1)?;
                    results.push(res);
                }

                if rows == 1 && cols == 1 {
                    Ok(EvalValue::Scalar(results.swap_remove(0)))
                } else {
                    Ok(EvalValue::Range {
                        values: results,
                        rows,
                        cols,
                    })
                }
            }
            "reduce" => {
                if !(2..=3).contains(&arguments.len()) {
                    return Err("unsupported");
                }
                let (init_val, array_arg, lambda_arg) = if arguments.len() == 3 {
                    (
                        self.eval_scalar(&arguments[0], depth + 1)?,
                        &arguments[1],
                        &arguments[2],
                    )
                } else {
                    (FormulaValue::Blank, &arguments[0], &arguments[1])
                };

                let lambda_val = self.evaluate(lambda_arg, depth + 1)?;
                if !matches!(&lambda_val, EvalValue::Lambda { parameters, .. } if parameters.len() == 2)
                {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                }

                let Some((values, _, _)) = self.eval_to_grid(array_arg, depth + 1)? else {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                };

                if values.len() > 10_000 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#CALC!".into())));
                }

                let mut acc = init_val;
                for val in values {
                    acc = self.eval_lambda_to_scalar(
                        &lambda_val,
                        vec![EvalValue::Scalar(acc), EvalValue::Scalar(val)],
                        depth + 1,
                    )?;
                }

                Ok(EvalValue::Scalar(acc))
            }
            "scan" => {
                if !(2..=3).contains(&arguments.len()) {
                    return Err("unsupported");
                }
                let (init_val, array_arg, lambda_arg) = if arguments.len() == 3 {
                    (
                        self.eval_scalar(&arguments[0], depth + 1)?,
                        &arguments[1],
                        &arguments[2],
                    )
                } else {
                    (FormulaValue::Blank, &arguments[0], &arguments[1])
                };

                let lambda_val = self.evaluate(lambda_arg, depth + 1)?;
                if !matches!(&lambda_val, EvalValue::Lambda { parameters, .. } if parameters.len() == 2)
                {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                }

                let Some((values, rows, cols)) = self.eval_to_grid(array_arg, depth + 1)? else {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                };

                if values.len() > 10_000 {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#CALC!".into())));
                }

                let mut acc = init_val;
                let mut results = Vec::with_capacity(values.len());
                for val in values {
                    acc = self.eval_lambda_to_scalar(
                        &lambda_val,
                        vec![EvalValue::Scalar(acc), EvalValue::Scalar(val)],
                        depth + 1,
                    )?;
                    results.push(acc.clone());
                }

                if rows == 1 && cols == 1 {
                    Ok(EvalValue::Scalar(results.swap_remove(0)))
                } else {
                    Ok(EvalValue::Range {
                        values: results,
                        rows,
                        cols,
                    })
                }
            }
            "byrow" => {
                if arguments.len() != 2 {
                    return Err("unsupported");
                }
                let lambda_val = self.evaluate(&arguments[1], depth + 1)?;
                if !matches!(&lambda_val, EvalValue::Lambda { parameters, .. } if parameters.len() == 1)
                {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                }

                let Some((values, rows, cols)) = self.eval_to_grid(&arguments[0], depth + 1)?
                else {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                };

                let mut results = Vec::with_capacity(rows);
                for r in 0..rows {
                    let row_vals = values[r * cols..(r + 1) * cols].to_vec();
                    let row_arg = EvalValue::Range {
                        values: row_vals,
                        rows: 1,
                        cols,
                    };
                    let res = self.eval_lambda_to_scalar(&lambda_val, vec![row_arg], depth + 1)?;
                    results.push(res);
                }

                if rows == 1 {
                    Ok(EvalValue::Scalar(results.swap_remove(0)))
                } else {
                    Ok(EvalValue::Range {
                        values: results,
                        rows,
                        cols: 1,
                    })
                }
            }
            "bycol" => {
                if arguments.len() != 2 {
                    return Err("unsupported");
                }
                let lambda_val = self.evaluate(&arguments[1], depth + 1)?;
                if !matches!(&lambda_val, EvalValue::Lambda { parameters, .. } if parameters.len() == 1)
                {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                }

                let Some((values, rows, cols)) = self.eval_to_grid(&arguments[0], depth + 1)?
                else {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                };

                let mut results = Vec::with_capacity(cols);
                for c in 0..cols {
                    let mut col_vals = Vec::with_capacity(rows);
                    for r in 0..rows {
                        col_vals.push(values[r * cols + c].clone());
                    }
                    let col_arg = EvalValue::Range {
                        values: col_vals,
                        rows,
                        cols: 1,
                    };
                    let res = self.eval_lambda_to_scalar(&lambda_val, vec![col_arg], depth + 1)?;
                    results.push(res);
                }

                if cols == 1 {
                    Ok(EvalValue::Scalar(results.swap_remove(0)))
                } else {
                    Ok(EvalValue::Range {
                        values: results,
                        rows: 1,
                        cols,
                    })
                }
            }
            "makearray" => {
                if arguments.len() != 3 {
                    return Err("unsupported");
                }
                let r_num = to_number(&self.eval_scalar(&arguments[0], depth + 1)?)?.trunc() as i64;
                let c_num = to_number(&self.eval_scalar(&arguments[1], depth + 1)?)?.trunc() as i64;
                if r_num <= 0
                    || c_num <= 0
                    || r_num > 1000
                    || c_num > 1000
                    || (r_num * c_num) > 10_000
                {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#CALC!".into())));
                }
                let (rows, cols) = (r_num as usize, c_num as usize);

                let lambda_val = self.evaluate(&arguments[2], depth + 1)?;
                if !matches!(&lambda_val, EvalValue::Lambda { parameters, .. } if parameters.len() == 2)
                {
                    return Ok(EvalValue::Scalar(FormulaValue::Error("#VALUE!".into())));
                }

                let mut results = Vec::with_capacity(rows * cols);
                for r in 1..=rows {
                    for c in 1..=cols {
                        let res = self.eval_lambda_to_scalar(
                            &lambda_val,
                            vec![
                                EvalValue::Scalar(FormulaValue::Number(r as f64)),
                                EvalValue::Scalar(FormulaValue::Number(c as f64)),
                            ],
                            depth + 1,
                        )?;
                        results.push(res);
                    }
                }

                if rows == 1 && cols == 1 {
                    Ok(EvalValue::Scalar(results.swap_remove(0)))
                } else {
                    Ok(EvalValue::Range {
                        values: results,
                        rows,
                        cols,
                    })
                }
            }
            "isomitted" => {
                if arguments.len() != 1 {
                    return Err("unsupported");
                }
                match self.eval_scalar(&arguments[0], depth + 1) {
                    Ok(FormulaValue::Blank) => Ok(EvalValue::Scalar(FormulaValue::Boolean(true))),
                    Ok(_) => Ok(EvalValue::Scalar(FormulaValue::Boolean(false))),
                    Err(_) => Ok(EvalValue::Scalar(FormulaValue::Boolean(true))),
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

fn gammaln_f64(x: f64) -> Result<f64, &'static str> {
    if x <= 0.0 || !x.is_finite() {
        return Err("#NUM!");
    }
    if x == 1.0 || x == 2.0 {
        return Ok(0.0);
    }
    #[allow(clippy::excessive_precision)]
    const COEFFS: [f64; 9] = [
        0.999_999_999_999_809_9,
        676.5203681218851,
        -1259.1392167224028,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507343278686905,
        -0.138571095836524,
        9.984_369_578_019_572e-6,
        1.5056327351493116e-7,
    ];
    let z = x - 1.0;
    let mut ag = COEFFS[0];
    for (i, &c) in COEFFS[1..].iter().enumerate() {
        ag += c / (z + (i as f64) + 1.0);
    }
    let f = z + 7.5;
    let half_ln_2pi = 0.5 * (2.0 * std::f64::consts::PI).ln();
    let ln_val = half_ln_2pi + (z + 0.5) * f.ln() - f + ag.ln();
    if !ln_val.is_finite() {
        Err("#NUM!")
    } else {
        Ok(ln_val)
    }
}

fn gamma_f64(x: f64) -> Result<f64, &'static str> {
    if x == 0.0 || !x.is_finite() {
        return Err("#NUM!");
    }
    if x > 0.0 {
        if x.fract() == 0.0 && x <= 20.0 {
            let mut f = 1.0f64;
            for i in 1..(x as u64) {
                f *= i as f64;
            }
            return Ok(f);
        }
        let ln_val = gammaln_f64(x)?;
        let res = ln_val.exp();
        if !res.is_finite() {
            Err("#NUM!")
        } else {
            Ok(res)
        }
    } else {
        if x.fract() == 0.0 {
            return Err("#NUM!");
        }
        let pi = std::f64::consts::PI;
        let sin_pi_x = (pi * x).sin();
        let ln_one_minus_x = gammaln_f64(1.0 - x)?;
        let denom = sin_pi_x * ln_one_minus_x.exp();
        if denom == 0.0 || !denom.is_finite() {
            return Err("#NUM!");
        }
        let res = pi / denom;
        if !res.is_finite() {
            Err("#NUM!")
        } else {
            Ok(res)
        }
    }
}

fn erf_f64(x: f64) -> f64 {
    if !x.is_finite() {
        return x;
    }
    if x == 0.0 {
        return 0.0;
    }
    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    let ax = x.abs();
    if ax >= 6.0 {
        return sign;
    }
    let x2 = ax * ax;
    let two_x2 = 2.0 * x2;
    let mut sum = 1.0f64;
    let mut term = 1.0f64;
    for m in 1..=100 {
        term *= two_x2 / ((2 * m + 1) as f64);
        sum += term;
        if term < sum * 1e-16 {
            break;
        }
    }
    let factor = 2.0 / std::f64::consts::PI.sqrt() * (-x2).exp() * ax;
    let res = (factor * sum).min(1.0);
    sign * res
}

fn gammap_f64(a: f64, x: f64) -> Result<f64, &'static str> {
    if a <= 0.0 || x < 0.0 || !a.is_finite() || !x.is_finite() {
        return Err("#NUM!");
    }
    if x == 0.0 {
        return Ok(0.0);
    }
    if x < a + 1.0 {
        let mut term = 1.0 / a;
        let mut sum = term;
        for n in 1..=200 {
            term *= x / (a + (n as f64));
            sum += term;
            if term.abs() < sum.abs() * 1e-15 {
                break;
            }
        }
        let lna = gammaln_f64(a)?;
        let factor = (a * x.ln() - x - lna).exp();
        let res = (factor * sum).clamp(0.0, 1.0);
        Ok(res)
    } else {
        let mut b = x + 1.0 - a;
        let mut c = 1.0 / 1e-30;
        let mut d = 1.0 / b;
        let mut h = d;
        for i in 1..=200 {
            let an = -(i as f64) * ((i as f64) - a);
            b += 2.0;
            d = an * d + b;
            if d.abs() < 1e-30 {
                d = 1e-30;
            }
            c = b + an / c;
            if c.abs() < 1e-30 {
                c = 1e-30;
            }
            d = 1.0 / d;
            let del = d * c;
            h *= del;
            if (del - 1.0).abs() < 1e-15 {
                break;
            }
        }
        let lna = gammaln_f64(a)?;
        let factor = (a * x.ln() - x - lna).exp();
        let q = factor * h;
        let p = (1.0 - q).clamp(0.0, 1.0);
        Ok(p)
    }
}

fn chisq_inv_f64(p: f64, df: f64) -> Result<f64, &'static str> {
    if !(0.0..1.0).contains(&p) || df <= 0.0 || !p.is_finite() || !df.is_finite() {
        return Err("#NUM!");
    }
    if p == 0.0 {
        return Ok(0.0);
    }
    let a = df / 2.0;
    let mut low = 0.0f64;
    let mut high = df.max(1.0) * 10.0;
    while gammap_f64(a, high / 2.0)? < p && high < 1e7 {
        high *= 2.0;
    }
    for _ in 0..80 {
        let mid = 0.5 * (low + high);
        let cdf = gammap_f64(a, mid / 2.0)?;
        if cdf < p {
            low = mid;
        } else {
            high = mid;
        }
    }
    Ok(0.5 * (low + high))
}

fn duration_f64(
    settlement: f64,
    maturity: f64,
    coupon: f64,
    yld: f64,
    frequency: i64,
    basis: i32,
) -> Result<f64, &'static str> {
    let days = maturity - settlement;
    if days <= 0.0
        || coupon < 0.0
        || yld < 0.0
        || !(0..=4).contains(&basis)
        || (frequency != 1 && frequency != 2 && frequency != 4)
    {
        return Err("#NUM!");
    }
    let b = if basis == 1 || basis == 3 {
        365.0
    } else {
        360.0
    };
    let freq = frequency as f64;
    let n = ((days / b) * freq).ceil() as i64;
    let n = n.max(1);
    let c = coupon * 100.0 / freq;
    let y = yld / freq;
    let mut total_pv = 0.0f64;
    let mut weighted_pv = 0.0f64;
    for t in 1..=n {
        let cf = if t == n { c + 100.0 } else { c };
        let df = (1.0 + y).powi(t as i32);
        let pv = cf / df;
        total_pv += pv;
        weighted_pv += (t as f64 / freq) * pv;
    }
    if total_pv <= 0.0 {
        return Err("#NUM!");
    }
    Ok(weighted_pv / total_pv)
}

fn intrate_f64(
    settlement: f64,
    maturity: f64,
    investment: f64,
    redemption: f64,
    basis: i32,
) -> Result<f64, &'static str> {
    let days = maturity - settlement;
    if days <= 0.0 || investment <= 0.0 || redemption <= 0.0 || !(0..=4).contains(&basis) {
        return Err("#NUM!");
    }
    let b = if basis == 1 || basis == 3 {
        365.0
    } else {
        360.0
    };
    Ok(((redemption - investment) / investment) * (b / days))
}

fn besselj_f64(x: f64, n: u32) -> Result<f64, &'static str> {
    if !x.is_finite() {
        return Err("#NUM!");
    }
    let sign = if x < 0.0 && n % 2 == 1 { -1.0 } else { 1.0 };
    let ax = x.abs();
    let z = ax / 2.0;
    let mut term = 1.0f64;
    for i in 1..=n {
        term *= z / (i as f64);
    }
    let mut sum = term;
    let z2 = z * z;
    for m in 1..=120 {
        term = -term * z2 / ((m as f64) * ((m + n) as f64));
        sum += term;
        if term.abs() < sum.abs() * 1e-16 && m > 5 {
            break;
        }
    }
    if !sum.is_finite() {
        Err("#NUM!")
    } else {
        Ok(sign * sum)
    }
}

fn besseli_f64(x: f64, n: u32) -> Result<f64, &'static str> {
    if !x.is_finite() {
        return Err("#NUM!");
    }
    let sign = if x < 0.0 && n % 2 == 1 { -1.0 } else { 1.0 };
    let ax = x.abs();
    let z = ax / 2.0;
    let mut term = 1.0f64;
    for i in 1..=n {
        term *= z / (i as f64);
    }
    let mut sum = term;
    let z2 = z * z;
    for m in 1..=120 {
        term = term * z2 / ((m as f64) * ((m + n) as f64));
        sum += term;
        if term.abs() < sum.abs() * 1e-16 && m > 5 {
            break;
        }
    }
    if !sum.is_finite() {
        Err("#NUM!")
    } else {
        Ok(sign * sum)
    }
}

fn bessely_f64(x: f64, n: u32) -> Result<f64, &'static str> {
    if x <= 0.0 || !x.is_finite() {
        return Err("#NUM!");
    }
    let z = x / 2.0;
    let z2 = z * z;
    const EULER_GAMMA: f64 = 0.577_215_664_901_532_9;
    let j0 = besselj_f64(x, 0)?;
    let j1 = besselj_f64(x, 1)?;

    let mut sum0 = 0.0f64;
    let mut term0 = 1.0f64;
    let mut hm0 = 0.0f64;
    for m in 1..=120 {
        term0 = -term0 * z2 / ((m as f64) * (m as f64));
        hm0 += 1.0 / (m as f64);
        let cur = term0 * hm0;
        sum0 += cur;
        if cur.abs() < sum0.abs() * 1e-16 && m > 5 {
            break;
        }
    }
    let y0 = (2.0 / std::f64::consts::PI) * ((z.ln() + EULER_GAMMA) * j0 - sum0);
    if n == 0 {
        return Ok(y0);
    }

    let mut sum1 = 0.0f64;
    let mut fact_m = 1.0f64;
    let mut fact_m1 = 1.0f64;
    let mut hm = 0.0f64;
    let mut hm1 = 1.0f64;
    let mut z_pow = z;
    for m in 0..=120 {
        if m > 0 {
            fact_m *= m as f64;
            fact_m1 *= (m + 1) as f64;
            hm += 1.0 / (m as f64);
            hm1 += 1.0 / ((m + 1) as f64);
            z_pow *= z2;
        }
        let sign_m = if m % 2 == 1 { -1.0 } else { 1.0 };
        let cur = sign_m * (hm + hm1) / (fact_m * fact_m1) * z_pow;
        sum1 += cur;
        if cur.abs() < sum1.abs() * 1e-16 && m > 5 {
            break;
        }
    }
    let y1 = (2.0 / std::f64::consts::PI) * ((z.ln() + EULER_GAMMA) * j1 - 1.0 / x - 0.5 * sum1);
    if n == 1 {
        return Ok(y1);
    }

    let mut prev = y0;
    let mut curr = y1;
    for k in 1..n {
        let next = (2.0 * (k as f64) / x) * curr - prev;
        if !next.is_finite() {
            return Err("#NUM!");
        }
        prev = curr;
        curr = next;
    }
    Ok(curr)
}

fn besselk_f64(x: f64, n: u32) -> Result<f64, &'static str> {
    if x <= 0.0 || !x.is_finite() {
        return Err("#NUM!");
    }
    let z = x / 2.0;
    let z2 = z * z;
    const EULER_GAMMA: f64 = 0.577_215_664_901_532_9;
    let i0 = besseli_f64(x, 0)?;
    let i1 = besseli_f64(x, 1)?;

    let mut sum0 = 0.0f64;
    let mut term0 = 1.0f64;
    let mut hm0 = 0.0f64;
    for m in 1..=120 {
        term0 = term0 * z2 / ((m as f64) * (m as f64));
        hm0 += 1.0 / (m as f64);
        let cur = term0 * hm0;
        sum0 += cur;
        if cur.abs() < sum0.abs() * 1e-16 && m > 5 {
            break;
        }
    }
    let k0 = -(z.ln() + EULER_GAMMA) * i0 + sum0;
    if n == 0 {
        return Ok(k0);
    }

    let mut sum1 = 0.0f64;
    let mut fact_m = 1.0f64;
    let mut fact_m1 = 1.0f64;
    let mut hm = 0.0f64;
    let mut hm1 = 1.0f64;
    let mut z_pow = z;
    for m in 0..=120 {
        if m > 0 {
            fact_m *= m as f64;
            fact_m1 *= (m + 1) as f64;
            hm += 1.0 / (m as f64);
            hm1 += 1.0 / ((m + 1) as f64);
            z_pow *= z2;
        }
        let cur = (hm + hm1) / (fact_m * fact_m1) * z_pow;
        sum1 += cur;
        if cur.abs() < sum1.abs() * 1e-16 && m > 5 {
            break;
        }
    }
    let k1 = 1.0 / x + (z.ln() + EULER_GAMMA) * i1 - 0.5 * sum1;
    if n == 1 {
        return Ok(k1);
    }

    let mut prev = k0;
    let mut curr = k1;
    for k in 1..n {
        let next = (2.0 * (k as f64) / x) * curr + prev;
        if !next.is_finite() {
            return Err("#NUM!");
        }
        prev = curr;
        curr = next;
    }
    Ok(curr)
}

fn convert_units_f64(val: f64, from: &str, to: &str) -> Result<f64, &'static str> {
    if !val.is_finite() {
        return Err("#NUM!");
    }
    let f = from.trim().to_ascii_lowercase();
    let t = to.trim().to_ascii_lowercase();
    if f == t {
        return Ok(val);
    }
    let is_temp = |s: &str| matches!(s, "c" | "cel" | "f" | "fah" | "k" | "kel" | "rank");
    if is_temp(&f) || is_temp(&t) {
        if !is_temp(&f) || !is_temp(&t) {
            return Err("#N/A");
        }
        let k = match f.as_str() {
            "c" | "cel" => val + 273.15,
            "f" | "fah" => (val - 32.0) * 5.0 / 9.0 + 273.15,
            "k" | "kel" => val,
            "rank" => val * 5.0 / 9.0,
            _ => return Err("#N/A"),
        };
        let res = match t.as_str() {
            "c" | "cel" => k - 273.15,
            "f" | "fah" => (k - 273.15) * 9.0 / 5.0 + 32.0,
            "k" | "kel" => k,
            "rank" => k * 9.0 / 5.0,
            _ => return Err("#N/A"),
        };
        return Ok(res);
    }

    const UNITS: &[(&str, u8, f64)] = &[
        ("m", 1, 1.0),
        ("km", 1, 1000.0),
        ("cm", 1, 0.01),
        ("mm", 1, 0.001),
        ("um", 1, 1e-6),
        ("nm", 1, 1e-9),
        ("in", 1, 0.0254),
        ("ft", 1, 0.3048),
        ("yd", 1, 0.9144),
        ("mi", 1, 1609.344),
        ("nmi", 1, 1852.0),
        ("ang", 1, 1e-10),
        ("pica", 1, 0.004233333333333333),
        ("g", 2, 1.0),
        ("kg", 2, 1000.0),
        ("mg", 2, 0.001),
        ("ug", 2, 1e-6),
        ("lbm", 2, 453.59237),
        ("ozm", 2, 28.349523125),
        ("grain", 2, 0.06479891),
        ("ton", 2, 907184.74),
        ("sg", 2, 14593.9029),
        ("cwt", 2, 45359.237),
        ("sec", 3, 1.0),
        ("s", 3, 1.0),
        ("min", 3, 60.0),
        ("hr", 3, 3600.0),
        ("h", 3, 3600.0),
        ("day", 3, 86400.0),
        ("d", 3, 86400.0),
        ("yr", 3, 31536000.0),
        ("ms", 3, 0.001),
        ("us", 3, 1e-6),
        ("pa", 4, 1.0),
        ("kpa", 4, 1000.0),
        ("atm", 4, 101325.0),
        ("mmhg", 4, 133.322387415),
        ("psi", 4, 6894.757293168),
        ("bar", 4, 100000.0),
        ("torr", 4, 133.322368421),
        ("n", 5, 1.0),
        ("dyn", 5, 1e-5),
        ("lbf", 5, 4.4482216152605),
        ("j", 6, 1.0),
        ("kj", 6, 1000.0),
        ("e", 6, 1e-7),
        ("c", 6, 4.184),
        ("cal", 6, 4.184),
        ("kcal", 6, 4184.0),
        ("ev", 6, 1.602176634e-19),
        ("wh", 6, 3600.0),
        ("kwh", 6, 3600000.0),
        ("btu", 6, 1055.05585262),
        ("w", 7, 1.0),
        ("kw", 7, 1000.0),
        ("hp", 7, 745.69987158227),
        ("l", 8, 1.0),
        ("lt", 8, 1.0),
        ("ml", 8, 0.001),
        ("gal", 8, 3.785411784),
        ("qt", 8, 0.946352946),
        ("pt", 8, 0.473176473),
        ("cup", 8, 0.2365882365),
        ("oz", 8, 0.0295735295625),
        ("m3", 8, 1000.0),
        ("m2", 9, 1.0),
        ("km2", 9, 1000000.0),
        ("cm2", 9, 0.0001),
        ("mm2", 9, 1e-6),
        ("ft2", 9, 0.09290304),
        ("in2", 9, 0.00064516),
        ("yd2", 9, 0.83612736),
        ("ha", 9, 10000.0),
        ("acre", 9, 4046.8564224),
        ("bit", 10, 1.0),
        ("byte", 10, 8.0),
        ("kbyte", 10, 8192.0),
        ("kb", 10, 8192.0),
        ("mbyte", 10, 8388608.0),
        ("mb", 10, 8388608.0),
        ("gbyte", 10, 8589934592.0),
        ("gb", 10, 8589934592.0),
    ];

    let from_info = UNITS.iter().find(|(u, _, _)| *u == f.as_str());
    let to_info = UNITS.iter().find(|(u, _, _)| *u == t.as_str());

    match (from_info, to_info) {
        (Some((_, cat1, scale1)), Some((_, cat2, scale2))) if cat1 == cat2 => {
            let base_val = val * scale1;
            let result = base_val / scale2;
            if result.is_finite() {
                Ok(result)
            } else {
                Err("#NUM!")
            }
        }
        _ => Err("#N/A"),
    }
}

fn format_complex(mut real: f64, mut imag: f64, suffix: &str) -> String {
    if real.abs() < 1e-13 {
        real = 0.0;
    } else if (real - real.round()).abs() < 1e-12 {
        real = real.round();
    }
    if imag.abs() < 1e-13 {
        imag = 0.0;
    } else if (imag - imag.round()).abs() < 1e-12 {
        imag = imag.round();
    }

    fn fmt_num(n: f64) -> String {
        if n.fract() == 0.0 && n.abs() < 1e15 {
            format!("{}", n as i64)
        } else {
            format!("{n}")
        }
    }

    if real == 0.0 && imag == 0.0 {
        "0".to_string()
    } else if imag == 0.0 {
        fmt_num(real)
    } else if real == 0.0 {
        if imag == 1.0 {
            suffix.to_string()
        } else if imag == -1.0 {
            format!("-{suffix}")
        } else {
            format!("{}{suffix}", fmt_num(imag))
        }
    } else {
        let r_str = fmt_num(real);
        if imag == 1.0 {
            format!("{r_str}+{suffix}")
        } else if imag == -1.0 {
            format!("{r_str}-{suffix}")
        } else if imag > 0.0 {
            format!("{r_str}+{}{suffix}", fmt_num(imag))
        } else {
            format!("{r_str}{}{suffix}", fmt_num(imag))
        }
    }
}

fn parse_complex(val: &FormulaValue) -> Result<(f64, f64), ()> {
    match val {
        FormulaValue::Number(n) if n.is_finite() => Ok((*n, 0.0)),
        FormulaValue::Boolean(b) => Ok((if *b { 1.0 } else { 0.0 }, 0.0)),
        FormulaValue::String(raw) => {
            let s = raw.trim();
            if s.is_empty() {
                return Err(());
            }
            let s_lower = s.to_ascii_lowercase();
            if !s_lower.ends_with('i') && !s_lower.ends_with('j') {
                return s.parse::<f64>().map(|r| (r, 0.0)).map_err(|_| ());
            }
            let without_suffix = &s_lower[..s_lower.len() - 1];
            if without_suffix.is_empty() || without_suffix == "+" {
                return Ok((0.0, 1.0));
            }
            if without_suffix == "-" {
                return Ok((0.0, -1.0));
            }
            let bytes = without_suffix.as_bytes();
            let mut split_pos = None;
            for i in (1..bytes.len()).rev() {
                if (bytes[i] == b'+' || bytes[i] == b'-')
                    && bytes[i - 1] != b'e'
                    && bytes[i - 1] != b'E'
                {
                    split_pos = Some(i);
                    break;
                }
            }
            if let Some(pos) = split_pos {
                let real_part = without_suffix[..pos].parse::<f64>().map_err(|_| ())?;
                let imag_str = &without_suffix[pos..];
                let imag_part = if imag_str == "+" {
                    1.0
                } else if imag_str == "-" {
                    -1.0
                } else {
                    imag_str.parse::<f64>().map_err(|_| ())?
                };
                Ok((real_part, imag_part))
            } else {
                let imag_part = without_suffix.parse::<f64>().map_err(|_| ())?;
                Ok((0.0, imag_part))
            }
        }
        _ => Err(()),
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

fn bin_to_hex(s: &str, places: Option<f64>) -> FormulaValue {
    let dec_val = bin_to_dec(s);
    match dec_val {
        FormulaValue::Number(n) => dec_to_hex(n, places),
        err => err,
    }
}

fn hex_to_bin(s: &str, places: Option<f64>) -> FormulaValue {
    let dec_val = hex_to_dec(s);
    match dec_val {
        FormulaValue::Number(n) => dec_to_bin(n, places),
        err => err,
    }
}

fn oct_to_hex(s: &str, places: Option<f64>) -> FormulaValue {
    let dec_val = oct_to_dec(s);
    match dec_val {
        FormulaValue::Number(n) => dec_to_hex(n, places),
        err => err,
    }
}

fn hex_to_oct(s: &str, places: Option<f64>) -> FormulaValue {
    let dec_val = hex_to_dec(s);
    match dec_val {
        FormulaValue::Number(n) => dec_to_oct(n, places),
        err => err,
    }
}

fn number_value(text: &str, decimal_sep: Option<&str>, group_sep: Option<&str>) -> FormulaValue {
    let mut trimmed = text.trim();
    if trimmed.is_empty() {
        return FormulaValue::Number(0.0);
    }
    let mut is_percent = false;
    if let Some(s) = trimmed.strip_suffix('%') {
        trimmed = s.trim();
        is_percent = true;
    }
    let dec = decimal_sep.unwrap_or(".");
    let grp = group_sep.unwrap_or(if dec == "," { "." } else { "," });
    if dec == grp || dec.is_empty() {
        return FormulaValue::Error("#VALUE!".into());
    }
    let without_grp = trimmed.replace(grp, "");
    let normalized = if dec != "." {
        without_grp.replace(dec, ".")
    } else {
        without_grp
    };
    match normalized.trim().parse::<f64>() {
        Ok(val) if val.is_finite() => {
            let res = if is_percent { val / 100.0 } else { val };
            FormulaValue::Number(res)
        }
        _ => FormulaValue::Error("#VALUE!".into()),
    }
}

fn char_dbcs_bytes(c: char) -> usize {
    match c as u32 {
        0x0000..=0x007F => 1,
        0xFF61..=0xFF9F => 1,
        _ => 2,
    }
}

fn string_dbcs_bytes(s: &str) -> usize {
    s.chars().map(char_dbcs_bytes).sum()
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

fn calc_gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

fn calc_lcm(a: u64, b: u64) -> u64 {
    if a == 0 || b == 0 {
        0
    } else {
        (a / calc_gcd(a, b)).saturating_mul(b)
    }
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

        // LET scoped variable evaluation
        assert_eq!(
            evaluate_formula(
                "=LET(x, 5, x + 1)",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(6.0))
        );
        assert_eq!(
            evaluate_formula(
                "=LET(a, \"powersh\", b, \"ell\", CONCAT(a, b))",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("powershell".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=LET(x, 10, y, x * 2, z, y + 5, z)",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(25.0))
        );
        // Nested LET with variable shadowing
        assert_eq!(
            evaluate_formula(
                "=LET(x, 2, y, LET(x, 10, x * 3), x + y)",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(32.0))
        );

        // ENCODEURL percent encoding
        assert_eq!(
            evaluate_formula(
                "=ENCODEURL(\"Hello World!\")",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("Hello%20World%21".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=ENCODEURL(\"cmd.exe /c whoami\")",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("cmd.exe%20%2Fc%20whoami".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=ENCODEURL(\"https://example.com/api?q=test&id=1\")",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String(
                "https%3A%2F%2Fexample.com%2Fapi%3Fq%3Dtest%26id%3D1".into()
            ))
        );

        // LAMBDA in LET and immediate invocation
        assert_eq!(
            evaluate_formula(
                "=LET(joiner, LAMBDA(a, b, a & b), joiner(\"cmd\", \".exe\"))",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("cmd.exe".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=LAMBDA(x, y, x + y)(15, 27)",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(42.0))
        );
        assert_eq!(
            evaluate_formula(
                "=(LAMBDA(x, x * 3))(7)",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(21.0))
        );
        assert_eq!(
            evaluate_formula(
                "=LET(dec, LAMBDA(c, k, CHAR(BITXOR(c, k))), dec(97, 2) & dec(111, 2) & dec(102, 2))",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("cmd".into()))
        );

        // Radix conversion functions: BIN2HEX, HEX2BIN, OCT2HEX, HEX2OCT
        assert_eq!(
            evaluate_formula(
                "=BIN2HEX(\"11111111\", 4)",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("00FF".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=HEX2BIN(\"FF\", 10)",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("0011111111".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=OCT2HEX(\"77\", 4)",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("003F".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=HEX2OCT(\"3F\", 4)",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("0077".into()))
        );

        // NUMBERVALUE locale-independent parsing
        assert_eq!(
            evaluate_formula(
                "=NUMBERVALUE(\"1,234.56\")",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(1234.56))
        );
        assert_eq!(
            evaluate_formula(
                "=NUMBERVALUE(\"1.234,56\", \",\", \".\")",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(1234.56))
        );
        assert_eq!(
            evaluate_formula(
                "=NUMBERVALUE(\"25%\")",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(0.25))
        );
    }

    #[test]
    fn evaluates_lambda_helpers_map_reduce_scan_byrow_bycol_makearray() {
        let test_cells = vec![
            cell_on_sheet("Data", "A1", "10", "n"),
            cell_on_sheet("Data", "A2", "20", "n"),
            cell_on_sheet("Data", "A3", "30", "n"),
        ];

        // MAP with single array and inline LAMBDA
        assert_eq!(
            evaluate_formula(
                "=INDEX(MAP({1, 2, 3}, LAMBDA(x, x * 10)), 1, 2)",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(20.0))
        );

        // MAP with multiple arrays
        assert_eq!(
            evaluate_formula(
                "=INDEX(MAP({1, 2}, {10, 20}, LAMBDA(a, b, a + b)), 1, 2)",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(22.0))
        );

        // MAP on scalar
        assert_eq!(
            evaluate_formula(
                "=MAP(7, LAMBDA(x, x * 3))",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(21.0))
        );

        // REDUCE with string concatenation (malware de-obfuscation pattern)
        assert_eq!(
            evaluate_formula(
                "=REDUCE(\"\", {\"c\", \"m\", \"d\"}, LAMBDA(a, b, a & b))",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("cmd".into()))
        );

        // REDUCE with accumulator
        assert_eq!(
            evaluate_formula(
                "=REDUCE(100, {1, 2, 3}, LAMBDA(acc, val, acc + val))",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(106.0))
        );

        // REDUCE with default accumulator
        assert_eq!(
            evaluate_formula(
                "=REDUCE({1, 2, 3}, LAMBDA(acc, val, acc + val))",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(6.0))
        );

        // SCAN running accumulation
        assert_eq!(
            evaluate_formula(
                "=INDEX(SCAN(0, {1, 2, 3}, LAMBDA(acc, val, acc + val)), 1, 3)",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(6.0))
        );
        assert_eq!(
            evaluate_formula(
                "=ARRAYTOTEXT(SCAN(0, {1, 2, 3}, LAMBDA(acc, val, acc + val)))",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("1, 3, 6".into()))
        );

        // BYROW row-level aggregation
        assert_eq!(
            evaluate_formula(
                "=INDEX(BYROW({1, 2; 3, 4}, LAMBDA(r, SUM(r))), 1, 1)",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(3.0))
        );
        assert_eq!(
            evaluate_formula(
                "=INDEX(BYROW({1, 2; 3, 4}, LAMBDA(r, SUM(r))), 2, 1)",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(7.0))
        );

        // BYCOL column-level aggregation
        assert_eq!(
            evaluate_formula(
                "=INDEX(BYCOL({1, 2; 3, 4}, LAMBDA(c, SUM(c))), 1, 1)",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(4.0))
        );
        assert_eq!(
            evaluate_formula(
                "=INDEX(BYCOL({1, 2; 3, 4}, LAMBDA(c, SUM(c))), 1, 2)",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(6.0))
        );

        // MAKEARRAY grid generation
        assert_eq!(
            evaluate_formula(
                "=INDEX(MAKEARRAY(2, 3, LAMBDA(r, c, r * 10 + c)), 2, 3)",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(23.0))
        );
        assert_eq!(
            evaluate_formula(
                "=ROWS(MAKEARRAY(4, 5, LAMBDA(r, c, 1)))",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(4.0))
        );
        assert_eq!(
            evaluate_formula(
                "=COLUMNS(MAKEARRAY(4, 5, LAMBDA(r, c, 1)))",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(5.0))
        );

        // LET with named LAMBDA passed to MAP
        assert_eq!(
            evaluate_formula(
                "=INDEX(LET(doubler, LAMBDA(x, x * 2), MAP({3, 5, 7}, doubler)), 1, 2)",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(10.0))
        );

        // ISOMITTED
        assert_eq!(
            evaluate_formula(
                "=ISOMITTED(\"test\")",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Boolean(false))
        );
        assert_eq!(
            evaluate_formula(
                "=ISOMITTED(Data!Z99)",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Boolean(true))
        );

        // Error cases: parameter count mismatch in MAP
        assert_eq!(
            evaluate_formula(
                "=MAP({1, 2}, LAMBDA(x, y, x + y))",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Error("#VALUE!".into()))
        );

        // Error cases: out-of-bounds MAKEARRAY
        assert_eq!(
            evaluate_formula(
                "=MAKEARRAY(2000, 2000, LAMBDA(r, c, 1))",
                Some("Data"),
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Error("#CALC!".into()))
        );
    }

    #[test]
    fn evaluates_vstack_hstack_ifs_switch_and_xor() {
        let test_cells = vec![];

        // VSTACK
        assert_eq!(
            evaluate_formula(
                "=INDEX(VSTACK({1, 2}, {3, 4}), 2, 1)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(3.0))
        );
        // VSTACK with uneven columns pads with #N/A
        assert_eq!(
            evaluate_formula(
                "=INDEX(VSTACK({1, 2}, {3, 4, 5}), 1, 3)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Error("#N/A".into()))
        );

        // HSTACK
        assert_eq!(
            evaluate_formula(
                "=CONCAT(HSTACK({\"powershell\", \" -enc \"}, {\"JAB4...\"}))",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("powershell -enc JAB4...".into()))
        );
        // HSTACK with uneven rows pads with #N/A
        assert_eq!(
            evaluate_formula(
                "=INDEX(HSTACK({1; 2}, {3; 4; 5}), 3, 1)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Error("#N/A".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=INDEX(HSTACK({1; 2}, {3; 4; 5}), 3, 2)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(5.0))
        );

        // Combined with LET
        assert_eq!(
            evaluate_formula(
                "=LET(parts, VSTACK(\"calc\", \".exe\"), CONCAT(parts))",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("calc.exe".into()))
        );

        // IFS
        assert_eq!(
            evaluate_formula(
                "=IFS(1 = 2, \"no\", 2 = 3, \"nope\", 4 = 4, \"hit\", 1 = 1, \"unreached\")",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("hit".into()))
        );
        assert_eq!(
            evaluate_formula("=IFS(1 = 2, \"no\")", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Error("#N/A".into()))
        );

        // SWITCH
        assert_eq!(
            evaluate_formula(
                "=SWITCH(2, 1, \"one\", 2, \"two\", 3, \"three\", \"default\")",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("two".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=SWITCH(\"ps\", \"cmd\", \"command\", \"ps\", \"powershell\", \"other\")",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("powershell".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=SWITCH(99, 1, \"one\", 2, \"two\", \"fallback\")",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("fallback".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=SWITCH(99, 1, \"one\", 2, \"two\")",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Error("#N/A".into()))
        );

        // XOR
        assert_eq!(
            evaluate_formula("=XOR(TRUE, FALSE)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Boolean(true))
        );
        assert_eq!(
            evaluate_formula("=XOR(TRUE, TRUE)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Boolean(false))
        );
        assert_eq!(
            evaluate_formula(
                "=XOR(TRUE, TRUE, TRUE)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Boolean(true))
        );
        assert_eq!(
            evaluate_formula("=XOR(FALSE, FALSE)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Boolean(false))
        );
    }

    #[test]
    fn evaluates_sequence_and_single() {
        let test_cells = vec![];

        // SEQUENCE 1D (rows only)
        assert_eq!(
            evaluate_formula(
                "=INDEX(SEQUENCE(4), 3, 1)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(3.0))
        );

        // SEQUENCE 2D with custom start and step
        assert_eq!(
            evaluate_formula(
                "=INDEX(SEQUENCE(2, 3, 10, 5), 2, 2)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(30.0))
        );

        // SEQUENCE combined with MAP and LAMBDA for de-obfuscating string characters
        assert_eq!(
            evaluate_formula(
                "=CONCAT(MAP(SEQUENCE(3), LAMBDA(i, MID(\"cmd\", i, 1))))",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("cmd".into()))
        );

        // SEQUENCE invalid bounds returns #VALUE!
        assert_eq!(
            evaluate_formula("=SEQUENCE(0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Error("#VALUE!".into()))
        );
        assert_eq!(
            evaluate_formula("=SEQUENCE(2, -1)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Error("#VALUE!".into()))
        );

        // SINGLE
        assert_eq!(
            evaluate_formula(
                "=SINGLE({10, 20; 30, 40})",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(10.0))
        );
        assert_eq!(
            evaluate_formula(
                "=SINGLE(\"payload\")",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("payload".into()))
        );
    }

    #[test]
    fn evaluates_transpose_and_lookup() {
        let test_cells = vec![];

        // 1. TRANSPOSE matrix 2x2
        assert_eq!(
            evaluate_formula(
                "=INDEX(TRANSPOSE({10, 20; 30, 40}), 1, 2)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(30.0))
        );
        assert_eq!(
            evaluate_formula(
                "=INDEX(TRANSPOSE({10, 20; 30, 40}), 2, 1)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(20.0))
        );

        // TRANSPOSE scalar
        assert_eq!(
            evaluate_formula(
                "=TRANSPOSE(\"scalar\")",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("scalar".into()))
        );

        // 2. LOOKUP vector form (3 arguments)
        assert_eq!(
            evaluate_formula(
                "=LOOKUP(2, {1, 2, 3}, {\"c\", \"m\", \"d\"})",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("m".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=LOOKUP(2.5, {1, 2, 3}, {\"c\", \"m\", \"d\"})",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("m".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=LOOKUP(0.5, {1, 2, 3}, {\"c\", \"m\", \"d\"})",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Error("#N/A".into()))
        );

        // 3. LOOKUP array form (2 arguments)
        // Wide array (cols > rows): searches row 1, returns last row
        assert_eq!(
            evaluate_formula(
                "=LOOKUP(3, {1, 2, 3; \"c\", \"m\", \"d\"})",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("d".into()))
        );

        // Tall array (rows >= cols): searches col 1, returns last col
        assert_eq!(
            evaluate_formula(
                "=LOOKUP(2, {1, \"c\"; 2, \"m\"; 3, \"d\"})",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("m".into()))
        );

        // De-obfuscation pipeline with CONCAT, TRANSPOSE, and LOOKUP
        assert_eq!(
            evaluate_formula(
                "=CONCAT(LOOKUP(1, {1, \"c\"; 2, \"m\"; 3, \"d\"}), LOOKUP(2, {1, \"c\"; 2, \"m\"; 3, \"d\"}), LOOKUP(3, {1, \"c\"; 2, \"m\"; 3, \"d\"}))",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("cmd".into()))
        );
    }

    #[test]
    fn evaluates_math_branchless_and_dbcs_string_functions() {
        let test_cells = vec![];

        // 1. DELTA (Kronecker delta)
        assert_eq!(
            evaluate_formula("=DELTA(5, 5)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(1.0))
        );
        assert_eq!(
            evaluate_formula("=DELTA(5, 4)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(0.0))
        );
        assert_eq!(
            evaluate_formula("=DELTA(0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(1.0))
        );

        // 2. GESTEP (Step function)
        assert_eq!(
            evaluate_formula("=GESTEP(5, 4)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(1.0))
        );
        assert_eq!(
            evaluate_formula("=GESTEP(5, 5)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(1.0))
        );
        assert_eq!(
            evaluate_formula("=GESTEP(3, 5)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(0.0))
        );
        assert_eq!(
            evaluate_formula("=GESTEP(1)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(1.0))
        );

        // 3. SIGN
        assert_eq!(
            evaluate_formula("=SIGN(42)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(1.0))
        );
        assert_eq!(
            evaluate_formula("=SIGN(-15)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(-1.0))
        );
        assert_eq!(
            evaluate_formula("=SIGN(0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(0.0))
        );

        // 4. TRUNC
        assert_eq!(
            evaluate_formula("=TRUNC(8.9)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(8.0))
        );
        assert_eq!(
            evaluate_formula("=TRUNC(-8.9)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(-8.0))
        );
        assert_eq!(
            evaluate_formula("=TRUNC(8.912, 2)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(8.91))
        );
        assert_eq!(
            evaluate_formula("=TRUNC(128.456, -1)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(120.0))
        );

        // 5. DBCS string functions: LENB, LEFTB, RIGHTB, MIDB
        // "abc" -> ASCII (3 bytes)
        // "日本語" -> 3 full-width Kanji (6 bytes)
        assert_eq!(
            evaluate_formula("=LENB(\"abc\")", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(3.0))
        );
        assert_eq!(
            evaluate_formula("=LENB(\"日本語\")", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(6.0))
        );
        assert_eq!(
            evaluate_formula("=LENB(\"cmd 日本\")", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(8.0)) // 3 + 1 (space) + 4 = 8
        );

        // LEFTB
        assert_eq!(
            evaluate_formula(
                "=LEFTB(\"日本語\", 2)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("日".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=LEFTB(\"日本語\", 3)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("日".into())) // 3 bytes cannot fit "本" (needs 4), so stops at "日"
        );
        assert_eq!(
            evaluate_formula(
                "=LEFTB(\"日本語\", 4)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("日本".into()))
        );

        // RIGHTB
        assert_eq!(
            evaluate_formula(
                "=RIGHTB(\"日本語\", 2)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("語".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=RIGHTB(\"日本語\", 3)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("語".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=RIGHTB(\"日本語\", 4)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("本語".into()))
        );

        // MIDB
        assert_eq!(
            evaluate_formula(
                "=MIDB(\"日本語\", 3, 2)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("本".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=MIDB(\"日本語\", 2, 2)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("".into())) // Byte 2 is mid-character, skipped, next character starts at 3 so doesn't fit
        );

        // De-obfuscation pipeline using DELTA + GESTEP + MIDB + CONCAT
        assert_eq!(
            evaluate_formula(
                "=CONCAT(IF(DELTA(1, 1), \"p\", \"\"), IF(GESTEP(10, 5), \"owershell\", \"\"))",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("powershell".into()))
        );
    }

    #[test]
    fn evaluates_quotient_even_odd_fact_gcd_lcm_functions() {
        let test_cells = vec![];

        // QUOTIENT
        assert_eq!(
            evaluate_formula("=QUOTIENT(10, 3)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(3.0))
        );
        assert_eq!(
            evaluate_formula("=QUOTIENT(-10, 3)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(-3.0))
        );
        assert_eq!(
            evaluate_formula("=QUOTIENT(5, 0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Error("#DIV/0!".into()))
        );

        // EVEN
        assert_eq!(
            evaluate_formula("=EVEN(1.5)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(2.0))
        );
        assert_eq!(
            evaluate_formula("=EVEN(3)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(4.0))
        );
        assert_eq!(
            evaluate_formula("=EVEN(-1)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(-2.0))
        );
        assert_eq!(
            evaluate_formula("=EVEN(0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(0.0))
        );

        // ODD
        assert_eq!(
            evaluate_formula("=ODD(0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(1.0))
        );
        assert_eq!(
            evaluate_formula("=ODD(1.5)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(3.0))
        );
        assert_eq!(
            evaluate_formula("=ODD(2)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(3.0))
        );
        assert_eq!(
            evaluate_formula("=ODD(-2)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(-3.0))
        );

        // FACT & FACTDOUBLE
        assert_eq!(
            evaluate_formula("=FACT(0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(1.0))
        );
        assert_eq!(
            evaluate_formula("=FACT(4)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(24.0))
        );
        assert_eq!(
            evaluate_formula("=FACT(-1)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Error("#NUM!".into()))
        );
        assert_eq!(
            evaluate_formula("=FACTDOUBLE(0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(1.0))
        );
        assert_eq!(
            evaluate_formula("=FACTDOUBLE(5)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(15.0))
        );
        assert_eq!(
            evaluate_formula("=FACTDOUBLE(6)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(48.0))
        );

        // GCD & LCM
        assert_eq!(
            evaluate_formula("=GCD(24, 36)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(12.0))
        );
        assert_eq!(
            evaluate_formula("=GCD(12, 18, 24)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(6.0))
        );
        assert_eq!(
            evaluate_formula("=LCM(4, 6)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(12.0))
        );
        assert_eq!(
            evaluate_formula("=LCM(3, 4, 5)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(60.0))
        );

        // Arithmetic De-obfuscation
        assert_eq!(
            evaluate_formula(
                "=CONCAT(CHAR(GCD(130, 195)), CHAR(QUOTIENT(232, 2)), CHAR(FACT(4) + 43))",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("AtC".into()))
        );
    }

    #[test]
    fn evaluates_exp_ln_log_combin_permut_sumproduct_functions() {
        let test_cells = vec![];

        // PI
        if let Some(FormulaValue::Number(pi)) =
            evaluate_formula("=PI()", None, &test_cells, Default::default()).value
        {
            assert!((pi - std::f64::consts::PI).abs() < 1e-10);
        } else {
            panic!("PI() did not return a number");
        }

        // EXP
        assert_eq!(
            evaluate_formula("=EXP(0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(1.0))
        );

        // LN & LOG10 & LOG
        assert_eq!(
            evaluate_formula("=LN(1)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(0.0))
        );
        assert_eq!(
            evaluate_formula("=LOG10(100)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(2.0))
        );
        assert_eq!(
            evaluate_formula("=LOG(8, 2)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(3.0))
        );
        assert_eq!(
            evaluate_formula("=LOG(100)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(2.0))
        );
        assert_eq!(
            evaluate_formula("=LN(-5)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Error("#NUM!".into()))
        );

        // COMBIN & PERMUT
        assert_eq!(
            evaluate_formula("=COMBIN(5, 2)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(10.0))
        );
        assert_eq!(
            evaluate_formula("=COMBIN(4, 0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(1.0))
        );
        assert_eq!(
            evaluate_formula("=COMBIN(4, 5)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Error("#NUM!".into()))
        );
        assert_eq!(
            evaluate_formula("=PERMUT(5, 2)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(20.0))
        );
        assert_eq!(
            evaluate_formula("=PERMUT(4, 0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(1.0))
        );
        assert_eq!(
            evaluate_formula("=PERMUT(3, 4)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Error("#NUM!".into()))
        );

        // SUMPRODUCT with array literals
        assert_eq!(
            evaluate_formula(
                "=SUMPRODUCT({1, 2, 3}, {4, 5, 6})",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(32.0))
        );
        assert_eq!(
            evaluate_formula(
                "=SUMPRODUCT({2, 3; 4, 5}, {1, 2; 3, 4})",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(40.0))
        );

        // De-obfuscation formula combining math functions
        assert_eq!(
            evaluate_formula(
                "=CHAR(SUMPRODUCT({10, 5}, {6, 1}) + COMBIN(5, 2) - PERMUT(3, 1) - 2)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("F".into()))
        );
    }

    #[test]
    fn evaluates_hyperbolic_and_sumsq_functions() {
        let test_cells = vec![];

        // SINH, COSH, TANH
        assert_eq!(
            evaluate_formula("=SINH(0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(0.0))
        );
        assert_eq!(
            evaluate_formula("=COSH(0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(1.0))
        );
        assert_eq!(
            evaluate_formula("=TANH(0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(0.0))
        );

        // ASINH, ACOSH, ATANH
        assert_eq!(
            evaluate_formula("=ASINH(0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(0.0))
        );
        assert_eq!(
            evaluate_formula("=ACOSH(1)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(0.0))
        );
        assert_eq!(
            evaluate_formula("=ACOSH(0.5)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Error("#NUM!".into()))
        );
        assert_eq!(
            evaluate_formula("=ATANH(0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(0.0))
        );
        assert_eq!(
            evaluate_formula("=ATANH(1)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Error("#NUM!".into()))
        );

        // SQRTPI
        if let Some(FormulaValue::Number(val)) =
            evaluate_formula("=SQRTPI(2)", None, &test_cells, Default::default()).value
        {
            assert!((val - (2.0 * std::f64::consts::PI).sqrt()).abs() < 1e-10);
        } else {
            panic!("SQRTPI(2) failed");
        }
        assert_eq!(
            evaluate_formula("=SQRTPI(-1)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Error("#NUM!".into()))
        );

        // SUMSQ
        assert_eq!(
            evaluate_formula("=SUMSQ(3, 4)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(25.0))
        );
        assert_eq!(
            evaluate_formula(
                "=SUMSQ({1, 2; 3, 4})",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(30.0))
        );

        // De-obfuscation combining SUMSQ and hyperbolic trig: CHAR(SUMSQ(8, 1) + COSH(0)) = CHAR(64 + 1 + 1) = CHAR(66) = "B"
        assert_eq!(
            evaluate_formula(
                "=CHAR(SUMSQ(8, 1) + COSH(0))",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("B".into()))
        );
    }

    #[test]
    fn evaluates_reciprocal_trig_and_matrix_multiplication() {
        let test_cells = vec![];

        // SEC
        assert_eq!(
            evaluate_formula("=SEC(0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(1.0))
        );

        // CSC
        assert_eq!(
            evaluate_formula("=CSC(PI() / 2)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(1.0))
        );

        // COT
        let cot_res =
            evaluate_formula("=COT(PI() / 4)", None, &test_cells, Default::default()).value;
        if let Some(FormulaValue::Number(val)) = cot_res {
            assert!((val - 1.0).abs() < 1e-9);
        } else {
            panic!("Expected Number for COT(PI()/4), got {cot_res:?}");
        }

        // SECH
        assert_eq!(
            evaluate_formula("=SECH(0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(1.0))
        );

        // CSCH & COTH zero division guard
        assert_eq!(
            evaluate_formula("=CSCH(0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Error("#DIV/0!".into()))
        );
        assert_eq!(
            evaluate_formula("=COTH(0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Error("#DIV/0!".into()))
        );

        // ACOT
        let acot_res = evaluate_formula("=ACOT(0)", None, &test_cells, Default::default()).value;
        if let Some(FormulaValue::Number(val)) = acot_res {
            assert!((val - std::f64::consts::FRAC_PI_2).abs() < 1e-9);
        } else {
            panic!("Expected Number for ACOT(0), got {acot_res:?}");
        }

        // ACOTH domain validation
        assert_eq!(
            evaluate_formula("=ACOTH(0.5)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Error("#NUM!".into()))
        );

        // MUNIT identity matrix
        assert_eq!(
            evaluate_formula("=MUNIT(1)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(1.0))
        );

        // MMULT scalar dot product: {1, 2} x {3; 4} = 1*3 + 2*4 = 11
        assert_eq!(
            evaluate_formula(
                "=MMULT({1, 2}, {3; 4})",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(11.0))
        );

        // De-obfuscation: CHAR(MMULT({10, 5}, {6; 1}) + SEC(0)) = CHAR(65 + 1) = CHAR(66) = "B"
        assert_eq!(
            evaluate_formula(
                "=CHAR(MMULT({10, 5}, {6; 1}) + SEC(0))",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("B".into()))
        );
    }

    #[test]
    fn evaluates_matrix_determinants_inversion_and_series() {
        let test_cells: Vec<WorkbookCellInfo> = vec![];

        // INT
        assert_eq!(
            evaluate_formula("=INT(8.9)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(8.0))
        );
        assert_eq!(
            evaluate_formula("=INT(-8.9)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(-9.0))
        );

        // SERIESSUM: 1*2^0 + 2*2^1 + 3*2^2 = 1 + 4 + 12 = 17
        assert_eq!(
            evaluate_formula(
                "=SERIESSUM(2, 0, 1, {1, 2, 3})",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(17.0))
        );

        // MDETERM 2x2: 5*4 - 2*3 = 14
        assert_eq!(
            evaluate_formula(
                "=MDETERM({5, 2; 3, 4})",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(14.0))
        );

        // MDETERM 3x3: 1*(24-0) - 2*(0-5) + 3*(0-4) = 24 + 10 - 12 = 22
        assert_eq!(
            evaluate_formula(
                "=MDETERM({1, 2, 3; 0, 4, 5; 1, 0, 6})",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(22.0))
        );

        // MINVERSE 1x1: 1/4 = 0.25
        assert_eq!(
            evaluate_formula("=MINVERSE(4)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(0.25))
        );

        // De-obfuscation: CHAR(MDETERM({10, 5; 3, 8}) - INT(-5.4)) = CHAR(65 - (-6)) = CHAR(71) = "G"
        assert_eq!(
            evaluate_formula(
                "=CHAR(MDETERM({10, 5; 3, 8}) - INT(-5.4))",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("G".into()))
        );
    }

    #[test]
    fn evaluates_complex_numbers_difference_sums_and_multinomial() {
        let test_cells = vec![];

        // COMPLEX
        assert_eq!(
            evaluate_formula("=COMPLEX(3, 4)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::String("3+4i".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=COMPLEX(3, -4, \"j\")",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("3-4j".into()))
        );
        assert_eq!(
            evaluate_formula("=COMPLEX(0, 1)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::String("i".into()))
        );
        assert_eq!(
            evaluate_formula("=COMPLEX(0, -1)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::String("-i".into()))
        );

        // IMREAL & IMAGINARY & IMABS & IMCONJG
        assert_eq!(
            evaluate_formula("=IMREAL(\"3+4i\")", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(3.0))
        );
        assert_eq!(
            evaluate_formula(
                "=IMAGINARY(\"3+4i\")",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(4.0))
        );
        assert_eq!(
            evaluate_formula("=IMABS(\"3+4i\")", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(5.0))
        );
        assert_eq!(
            evaluate_formula("=IMCONJG(\"3+4i\")", None, &test_cells, Default::default()).value,
            Some(FormulaValue::String("3-4i".into()))
        );

        // SUMXMY2, SUMX2MY2, SUMX2PY2
        assert_eq!(
            evaluate_formula(
                "=SUMXMY2({2, 3}, {4, 1})",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(8.0))
        );
        assert_eq!(
            evaluate_formula(
                "=SUMX2MY2({2, 3}, {4, 1})",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(-4.0))
        );
        assert_eq!(
            evaluate_formula(
                "=SUMX2PY2({2, 3}, {4, 1})",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(30.0))
        );

        // MULTINOMIAL
        assert_eq!(
            evaluate_formula(
                "=MULTINOMIAL(2, 3, 4)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(1260.0))
        );

        // De-obfuscation: CHAR(IMREAL("65+10i")) = "A"
        assert_eq!(
            evaluate_formula(
                "=CHAR(IMREAL(\"65+10i\"))",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("A".into()))
        );
    }

    #[test]
    fn evaluates_complex_arithmetic_combinatorics_and_predicates() {
        let test_cells = vec![];

        // IMSUM & IMSUB
        assert_eq!(
            evaluate_formula(
                "=IMSUM(\"3+4i\", \"1+2i\")",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("4+6i".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=IMSUB(\"5+7i\", \"2+3i\")",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("3+4i".into()))
        );

        // IMPRODUCT & IMDIV
        assert_eq!(
            evaluate_formula(
                "=IMPRODUCT(\"1+2i\", \"3+4i\")",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("-5+10i".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=IMDIV(\"-5+10i\", \"1+2i\")",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("3+4i".into()))
        );

        // IMPOWER & IMSQRT
        assert_eq!(
            evaluate_formula(
                "=IMPOWER(\"0+2i\", 2)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("-4".into()))
        );
        assert_eq!(
            evaluate_formula("=IMSQRT(\"-4\")", None, &test_cells, Default::default()).value,
            Some(FormulaValue::String("2i".into()))
        );

        // IMEXP & IMLN
        assert_eq!(
            evaluate_formula("=IMEXP(\"0\")", None, &test_cells, Default::default()).value,
            Some(FormulaValue::String("1".into()))
        );
        assert_eq!(
            evaluate_formula("=IMLN(\"1\")", None, &test_cells, Default::default()).value,
            Some(FormulaValue::String("0".into()))
        );

        // COMBINA & PERMUTATIONA
        assert_eq!(
            evaluate_formula("=COMBINA(4, 3)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(20.0))
        );
        assert_eq!(
            evaluate_formula("=PERMUTATIONA(3, 2)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(9.0))
        );

        // ISODD & ISEVEN
        assert_eq!(
            evaluate_formula("=ISODD(3)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Boolean(true))
        );
        assert_eq!(
            evaluate_formula("=ISODD(4)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Boolean(false))
        );
        assert_eq!(
            evaluate_formula("=ISEVEN(4)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Boolean(true))
        );
        assert_eq!(
            evaluate_formula("=ISEVEN(5)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Boolean(false))
        );

        // De-obfuscation: CHAR(IMREAL(IMSUM("60+2i", "5+3i"))) = CHAR(65) = "A"
        assert_eq!(
            evaluate_formula(
                "=CHAR(IMREAL(IMSUM(\"60+2i\", \"5+3i\")))",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("A".into()))
        );
    }

    #[test]
    fn evaluates_complex_trigonometric_logarithmic_and_gamma_functions() {
        let test_cells = vec![];

        // IMSIN, IMCOS, IMTAN, IMSINH, IMCOSH, IMSEC
        assert_eq!(
            evaluate_formula("=IMSIN(0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::String("0".into()))
        );
        assert_eq!(
            evaluate_formula("=IMCOS(0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::String("1".into()))
        );
        assert_eq!(
            evaluate_formula("=IMTAN(0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::String("0".into()))
        );
        assert_eq!(
            evaluate_formula("=IMSINH(0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::String("0".into()))
        );
        assert_eq!(
            evaluate_formula("=IMCOSH(0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::String("1".into()))
        );
        assert_eq!(
            evaluate_formula("=IMSEC(0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::String("1".into()))
        );

        // IMLOG10 & IMLOG2
        assert_eq!(
            evaluate_formula("=IMLOG10(100)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::String("2".into()))
        );
        assert_eq!(
            evaluate_formula("=IMLOG2(8)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::String("3".into()))
        );

        // GAMMA & GAMMALN
        assert_eq!(
            evaluate_formula("=GAMMA(5)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(24.0))
        );
        assert_eq!(
            evaluate_formula("=GAMMA(1)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(1.0))
        );
        assert_eq!(
            evaluate_formula("=GAMMALN(1)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(0.0))
        );

        // Dynamic formula de-obfuscation resolving to "A" (ASCII 65):
        // 3 * 10 + 2 * 17 + 1 = 30 + 34 + 1 = 65
        assert_eq!(
            evaluate_formula(
                "=CHAR(IMREAL(IMLOG2(8)) * 10 + IMREAL(IMLOG10(100)) * 17 + GAMMA(1))",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("A".into()))
        );
    }

    #[test]
    fn evaluates_bessel_error_and_distribution_functions() {
        let test_cells = vec![];

        // IMARGUMENT & IMCONJUGATE
        assert_eq!(
            evaluate_formula(
                "=IMCONJUGATE(\"3+4i\")",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("3-4i".into()))
        );
        let arg_val = evaluate_formula(
            "=IMARGUMENT(\"0+1i\")",
            None,
            &test_cells,
            Default::default(),
        )
        .value;
        if let Some(FormulaValue::Number(theta)) = arg_val {
            assert!((theta - std::f64::consts::FRAC_PI_2).abs() < 1e-10);
        } else {
            panic!("Expected Number for IMARGUMENT");
        }

        // ERF & ERFC
        assert_eq!(
            evaluate_formula("=ERF(0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(0.0))
        );
        assert_eq!(
            evaluate_formula("=ERFC(0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(1.0))
        );
        assert_eq!(
            evaluate_formula("=ERF.PRECISE(0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(0.0))
        );
        assert_eq!(
            evaluate_formula("=ERFC.PRECISE(0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(1.0))
        );

        // GAUSS & PHI
        assert_eq!(
            evaluate_formula("=GAUSS(0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(0.0))
        );
        let phi_zero = evaluate_formula("=PHI(0)", None, &test_cells, Default::default()).value;
        if let Some(FormulaValue::Number(p)) = phi_zero {
            assert!((p - 0.398_942_280_401_432_7).abs() < 1e-10);
        } else {
            panic!("Expected Number for PHI(0)");
        }

        // BESSELJ, BESSELI, BESSELY, BESSELK
        assert_eq!(
            evaluate_formula("=BESSELJ(0, 0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(1.0))
        );
        assert_eq!(
            evaluate_formula("=BESSELI(0, 0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(1.0))
        );

        // De-obfuscation: CHAR(BESSELJ(0, 0) * 64 + ERFC(0)) = CHAR(65) = "A"
        assert_eq!(
            evaluate_formula(
                "=CHAR(BESSELJ(0, 0) * 64 + ERFC(0))",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("A".into()))
        );
    }

    #[test]
    fn evaluates_distribution_convert_and_error_type_functions() {
        let test_cells = vec![
            WorkbookCellInfo {
                sheet_index: 0,
                sheet_name: "Sheet1".into(),
                cell_ref: "A1".into(),
                row: Some(1),
                column: Some(1),
                cell_type: "n".into(),
                formula: Some("=1+1".into()),
                value: Some("2".into()),
                ..WorkbookCellInfo::default()
            },
            WorkbookCellInfo {
                sheet_index: 0,
                sheet_name: "Sheet1".into(),
                cell_ref: "A2".into(),
                row: Some(2),
                column: Some(1),
                cell_type: "s".into(),
                formula: None,
                value: Some("hello".into()),
                ..WorkbookCellInfo::default()
            },
        ];

        // ERROR.TYPE
        assert_eq!(
            evaluate_formula("=ERROR.TYPE(#REF!)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(4.0))
        );
        assert_eq!(
            evaluate_formula(
                "=ERROR.TYPE(#DIV/0!)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(2.0))
        );
        assert_eq!(
            evaluate_formula("=ERROR.TYPE(123)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Error("#N/A".into()))
        );

        // ISFORMULA
        assert_eq!(
            evaluate_formula(
                "=ISFORMULA(Sheet1!A1)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Boolean(true))
        );
        assert_eq!(
            evaluate_formula(
                "=ISFORMULA(Sheet1!A2)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Boolean(false))
        );

        // STANDARDIZE
        assert_eq!(
            evaluate_formula(
                "=STANDARDIZE(10, 2, 2)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(4.0))
        );

        // NORMSDIST & NORM.S.DIST
        assert_eq!(
            evaluate_formula("=NORMSDIST(0)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(0.5))
        );
        assert_eq!(
            evaluate_formula(
                "=NORM.S.DIST(0, TRUE)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(0.5))
        );

        // EXPONDIST
        assert_eq!(
            evaluate_formula(
                "=EXPONDIST(0, 1, TRUE)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(0.0))
        );

        // WEIBULL
        assert_eq!(
            evaluate_formula(
                "=WEIBULL(0, 1, 1, TRUE)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(0.0))
        );

        // CONVERT
        assert_eq!(
            evaluate_formula(
                "=CONVERT(1, \"km\", \"m\")",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(1000.0))
        );
        assert_eq!(
            evaluate_formula(
                "=CONVERT(100, \"C\", \"F\")",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(212.0))
        );
        assert_eq!(
            evaluate_formula(
                "=CONVERT(1, \"byte\", \"bit\")",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(8.0))
        );

        // De-obfuscation: CHAR(ERROR.TYPE(#REF!) * 10 + CONVERT(25, "km", "km")) = CHAR(40 + 25) = CHAR(65) = "A"
        assert_eq!(
            evaluate_formula(
                "=CHAR(ERROR.TYPE(#REF!) * 10 + CONVERT(25, \"km\", \"km\"))",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("A".into()))
        );

        // SLN & SYD
        assert_eq!(
            evaluate_formula(
                "=SLN(10000, 2000, 5)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(1600.0))
        );
        assert_eq!(
            evaluate_formula("=SYD(100, 10, 3, 1)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(45.0))
        );

        // NPV
        let npv_val =
            evaluate_formula("=NPV(0.1, 110, 121)", None, &test_cells, Default::default()).value;
        if let Some(FormulaValue::Number(n)) = npv_val {
            assert!((n - 200.0).abs() < 1e-6);
        } else {
            panic!("Expected NPV number result");
        }

        // PV, FV, PMT
        assert_eq!(
            evaluate_formula("=PV(0, 10, 50, 100)", None, &test_cells, Default::default()).value,
            Some(FormulaValue::Number(-600.0))
        );
        assert_eq!(
            evaluate_formula(
                "=FV(0, 10, -100, -500)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(1500.0))
        );
        assert_eq!(
            evaluate_formula(
                "=PMT(0, 10, -560, 0)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::Number(56.0))
        );

        // POISSON & BINOM.DIST
        let pois = evaluate_formula(
            "=POISSON(0, 2, FALSE)",
            None,
            &test_cells,
            Default::default(),
        )
        .value;
        if let Some(FormulaValue::Number(n)) = pois {
            assert!((n - (-2.0f64).exp()).abs() < 1e-6);
        } else {
            panic!("Expected POISSON number result");
        }

        let binom = evaluate_formula(
            "=BINOM.DIST(2, 2, 0.5, TRUE)",
            None,
            &test_cells,
            Default::default(),
        )
        .value;
        if let Some(FormulaValue::Number(n)) = binom {
            assert!((n - 1.0).abs() < 1e-6);
        } else {
            panic!("Expected BINOM.DIST number result");
        }

        // Financial de-obfuscation: CHAR(SLN(100, 10, 10) + PMT(0, 10, -560, 0)) = CHAR(9 + 56) = CHAR(65) = "A"
        assert_eq!(
            evaluate_formula(
                "=CHAR(SLN(100, 10, 10) + PMT(0, 10, -560, 0))",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("A".into()))
        );

        // IRR & MIRR
        let irr_val =
            evaluate_formula("=IRR({-100, 110})", None, &test_cells, Default::default()).value;
        if let Some(FormulaValue::Number(n)) = irr_val {
            assert!((n - 0.10).abs() < 1e-4);
        } else {
            panic!("Expected IRR number result: {irr_val:?}");
        }

        let mirr_val = evaluate_formula(
            "=MIRR({-100, 110}, 0.1, 0.1)",
            None,
            &test_cells,
            Default::default(),
        )
        .value;
        if let Some(FormulaValue::Number(n)) = mirr_val {
            assert!((n - 0.10).abs() < 1e-4);
        } else {
            panic!("Expected MIRR number result: {mirr_val:?}");
        }

        // DISC, PRICEDISC, RECEIVED
        let disc_val = evaluate_formula(
            "=DISC(1, 91, 97.5, 100, 2)",
            None,
            &test_cells,
            Default::default(),
        )
        .value;
        if let Some(FormulaValue::Number(n)) = disc_val {
            assert!((n - 0.10).abs() < 1e-4);
        } else {
            panic!("Expected DISC number result: {disc_val:?}");
        }

        let price_val = evaluate_formula(
            "=PRICEDISC(1, 91, 0.10, 100, 2)",
            None,
            &test_cells,
            Default::default(),
        )
        .value;
        if let Some(FormulaValue::Number(n)) = price_val {
            assert!((n - 97.5).abs() < 1e-4);
        } else {
            panic!("Expected PRICEDISC number result: {price_val:?}");
        }

        let rec_val = evaluate_formula(
            "=RECEIVED(1, 91, 97.5, 0.10, 2)",
            None,
            &test_cells,
            Default::default(),
        )
        .value;
        if let Some(FormulaValue::Number(n)) = rec_val {
            assert!((n - 100.0).abs() < 1e-4);
        } else {
            panic!("Expected RECEIVED number result: {rec_val:?}");
        }

        // HYPGEOM.DIST
        let hyp_val = evaluate_formula(
            "=HYPGEOM.DIST(1, 1, 1, 1, FALSE)",
            None,
            &test_cells,
            Default::default(),
        )
        .value;
        if let Some(FormulaValue::Number(n)) = hyp_val {
            assert!((n - 1.0).abs() < 1e-6);
        } else {
            panic!("Expected HYPGEOM.DIST number result: {hyp_val:?}");
        }

        // Advanced financial de-obfuscation: CHAR(RECEIVED(1, 91, 97.5, 0.10, 2) - 35) = CHAR(100 - 35) = CHAR(65) = "A"
        assert_eq!(
            evaluate_formula(
                "=CHAR(RECEIVED(1, 91, 97.5, 0.10, 2) - 35)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("A".into()))
        );

        // EFFECT & NOMINAL
        let eff_val =
            evaluate_formula("=EFFECT(0.04, 1)", None, &test_cells, Default::default()).value;
        if let Some(FormulaValue::Number(n)) = eff_val {
            assert!((n - 0.04).abs() < 1e-6);
        } else {
            panic!("Expected EFFECT number result: {eff_val:?}");
        }

        let nom_val = evaluate_formula(
            "=NOMINAL(EFFECT(0.0525, 4), 4)",
            None,
            &test_cells,
            Default::default(),
        )
        .value;
        if let Some(FormulaValue::Number(n)) = nom_val {
            assert!((n - 0.0525).abs() < 1e-6);
        } else {
            panic!("Expected NOMINAL number result: {nom_val:?}");
        }

        // IPMT & PPMT
        let ipmt_val = evaluate_formula(
            "=IPMT(0.1 / 12, 1, 36, 10000)",
            None,
            &test_cells,
            Default::default(),
        )
        .value;
        if let Some(FormulaValue::Number(n)) = ipmt_val {
            assert!((n - (-83.333333)).abs() < 1e-3);
        } else {
            panic!("Expected IPMT number result: {ipmt_val:?}");
        }

        let ppmt_val = evaluate_formula(
            "=PPMT(0, 1, 10, -650)",
            None,
            &test_cells,
            Default::default(),
        )
        .value;
        assert_eq!(ppmt_val, Some(FormulaValue::Number(65.0)));

        // CUMIPMT & CUMPRINC
        let cumipmt_val = evaluate_formula(
            "=CUMIPMT(0.1 / 12, 36, 10000, 1, 1, 0)",
            None,
            &test_cells,
            Default::default(),
        )
        .value;
        if let Some(FormulaValue::Number(n)) = cumipmt_val {
            assert!((n - (-83.333333)).abs() < 1e-3);
        } else {
            panic!("Expected CUMIPMT number result: {cumipmt_val:?}");
        }

        // CRITBINOM / BINOM.INV
        let crit_val = evaluate_formula(
            "=CRITBINOM(6, 0.5, 0.5)",
            None,
            &test_cells,
            Default::default(),
        )
        .value;
        assert_eq!(crit_val, Some(FormulaValue::Number(3.0)));

        // De-obfuscation with PPMT and CRITBINOM
        assert_eq!(
            evaluate_formula(
                "=CHAR(PPMT(0, 1, 10, -650))",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("A".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=CHAR(CRITBINOM(6, 0.5, 0.5) * 21 + 2)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("A".into()))
        );

        // INTRATE
        let intrate_val = evaluate_formula(
            "=INTRATE(1, 91, 100, 105, 2)",
            None,
            &test_cells,
            Default::default(),
        )
        .value;
        assert_eq!(intrate_val, Some(FormulaValue::Number(0.20)));

        // DURATION & MDURATION
        let dur_val = evaluate_formula(
            "=DURATION(0, 360, 0.08, 0.08, 1, 2)",
            None,
            &test_cells,
            Default::default(),
        )
        .value;
        assert_eq!(dur_val, Some(FormulaValue::Number(1.0)));

        let mdur_val = evaluate_formula(
            "=MDURATION(0, 360, 0.08, 0.08, 1, 2)",
            None,
            &test_cells,
            Default::default(),
        )
        .value;
        if let Some(FormulaValue::Number(md)) = mdur_val {
            assert!((md - (1.0 / 1.08)).abs() < 1e-4);
        } else {
            panic!("Expected MDURATION number: {mdur_val:?}");
        }

        // CHISQ.DIST & CHIDIST
        let chisq_pdf = evaluate_formula(
            "=CHISQ.DIST(0, 2, FALSE)",
            None,
            &test_cells,
            Default::default(),
        )
        .value;
        assert_eq!(chisq_pdf, Some(FormulaValue::Number(0.5)));

        let chidist_val =
            evaluate_formula("=CHIDIST(2, 2)", None, &test_cells, Default::default()).value;
        if let Some(FormulaValue::Number(p)) = chidist_val {
            assert!((p - (-1.0f64).exp()).abs() < 1e-3);
        } else {
            panic!("Expected CHIDIST number: {chidist_val:?}");
        }

        // CHISQ.INV
        let chisq_inv_val =
            evaluate_formula("=CHISQ.INV(0.5, 2)", None, &test_cells, Default::default()).value;
        if let Some(FormulaValue::Number(x)) = chisq_inv_val {
            assert!((x - 2.0 * (2.0f64).ln()).abs() < 1e-3);
        } else {
            panic!("Expected CHISQ.INV number: {chisq_inv_val:?}");
        }

        // De-obfuscation with INTRATE and DURATION
        assert_eq!(
            evaluate_formula(
                "=CHAR(INTRATE(1, 91, 100, 105, 2) * 325)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("A".into()))
        );
        assert_eq!(
            evaluate_formula(
                "=CHAR(DURATION(0, 360, 0.08, 0.08, 1, 2) * 65)",
                None,
                &test_cells,
                Default::default()
            )
            .value,
            Some(FormulaValue::String("A".into()))
        );
    }
}
