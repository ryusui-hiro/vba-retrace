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
        Ok(EvalValue::Range(_)) => output.status = "unsupported".into(),
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
                if name.eq_ignore_ascii_case("true") {
                    return Ok(Expr::Value(FormulaValue::Boolean(true)));
                }
                if name.eq_ignore_ascii_case("false") {
                    return Ok(Expr::Value(FormulaValue::Boolean(false)));
                }
                if name.starts_with('#') {
                    return Ok(Expr::Value(FormulaValue::Error(name)));
                }
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

#[derive(Clone, Debug, PartialEq)]
enum EvalValue {
    Scalar(FormulaValue),
    Range(Vec<FormulaValue>),
}

impl EvalValue {
    fn into_scalar(self) -> Option<FormulaValue> {
        match self {
            Self::Scalar(value) => Some(value),
            Self::Range(_) => None,
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
                let rows = first.row.min(last.row)..=first.row.max(last.row);
                let columns = first.column.min(last.column)..=first.column.max(last.column);
                let count = rows.clone().count().saturating_mul(columns.clone().count());
                if count > self.limits.max_range_cells {
                    return Err("resource_limit");
                }
                let mut values = Vec::with_capacity(count);
                for row in rows {
                    for column in columns.clone() {
                        values.push(self.lookup(sheet.as_deref(), CellAddress { row, column })?);
                    }
                }
                Ok(EvalValue::Range(values))
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
                        EvalValue::Range(values) => values,
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
            "sum" | "average" | "min" | "max" | "count" | "counta" => {
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
            "len" | "left" | "right" | "mid" | "concatenate" | "value" | "trim" | "upper"
            | "lower" => self.evaluate_string_function(name, arguments, depth + 1),
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
                EvalValue::Range(range) => values.extend(range),
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
            "left" | "right" if arguments.len() == 2 => {
                let text = to_string(&self.eval_scalar(&arguments[0], depth + 1)?)?;
                let count = nonnegative_count(&self.eval_scalar(&arguments[1], depth + 1)?)?;
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
            "concatenate" if !arguments.is_empty() => {
                let mut value = String::new();
                for argument in arguments {
                    value.push_str(&to_string(&self.eval_scalar(argument, depth + 1)?)?);
                    self.check_string_size(&value)?;
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
            "s" | "str" | "inline_str" | "string" => Ok(FormulaValue::String(value.to_owned())),
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
            evaluate_formula("=INDIRECT(\"A1\")", Some("Data"), &[], Default::default());
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
}
