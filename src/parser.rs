use crate::lexer::{Token, TokenKind, lex};
use crate::model::{
    Declaration, Diagnostic, Expr, MemberAccessKind, Module, Parameter, Procedure, Severity, Span,
    Statement,
};

pub fn parse_module(
    name: &str,
    source_name: &str,
    text: &str,
    max_tokens: usize,
    max_nesting: usize,
) -> Module {
    let (tokens, lex_errors) = lex(text, max_tokens);
    let member_id_attributes = parse_member_id_attributes(&tokens);
    let module_name =
        parse_quoted_module_attribute(&tokens, "VB_Name").unwrap_or_else(|| name.to_owned());
    let predeclared_id = parse_boolean_module_attribute(&tokens, "VB_PredeclaredId");
    let global_namespace = parse_boolean_module_attribute(&tokens, "VB_GlobalNameSpace");
    let mut lines: Vec<Vec<Token>> = vec![Vec::new()];
    for t in tokens {
        if t.kind == TokenKind::Eof {
            break;
        }
        if t.kind == TokenKind::Newline {
            lines.push(Vec::new());
        } else {
            lines.last_mut().unwrap().push(t);
        }
    }
    lines.retain(|l| !l.is_empty());
    let mut parser = Parser {
        lines,
        at: 0,
        source_name: source_name.into(),
        diagnostics: Vec::new(),
        max_nesting,
    };
    for (span, message) in lex_errors {
        parser.error("VBA1001", span, message);
    }
    let mut module = Module {
        name: module_name,
        source_name: source_name.to_owned(),
        predeclared_id,
        global_namespace,
        text: text.to_owned(),
        analysis_text: text.to_owned(),
        ..Module::default()
    };
    while parser.at < parser.lines.len() {
        let line = parser.lines[parser.at].clone();
        if is_proc_start(&line) {
            match parse_proc_header(&line) {
                Some(mut p) => {
                    parser.at += 1;
                    let (body, end_span) = parser.parse_block(0, Some(&p.kind));
                    p.statements = body;
                    if let Some(s) = end_span {
                        p.span = p.span.join(s);
                    } else {
                        parser.error(
                            "VBA1002",
                            p.span,
                            format!("procedure '{}' is not terminated", p.name),
                        );
                    }
                    module.procedures.push(p);
                }
                None => {
                    parser.error(
                        "VBA1003",
                        line[0].span,
                        "invalid procedure declaration".into(),
                    );
                    parser.at += 1;
                }
            }
        } else if is_aggregate_start(&line) {
            let (decls, diagnostics) = parser.parse_aggregate();
            module.declarations.extend(decls);
            parser.diagnostics.extend(diagnostics);
        } else if let Some(d) = parse_event_or_external(&line) {
            module.declarations.push(d);
            parser.at += 1;
        } else if let Some(interface) = parse_implements(&line) {
            module.implemented_interfaces.push(interface);
            parser.at += 1;
        } else if is_ignorable_header(&line) {
            parser.at += 1;
        } else if let Some(ds) = parse_declaration_line(&line, "module") {
            module.declarations.extend(ds);
            parser.at += 1;
        } else {
            let t = line[0].text.to_ascii_lowercase();
            if t.starts_with("#") || (t == "if" && line.iter().any(|x| x.text == "#")) {
                parser.error(
                    "VBA1004",
                    line[0].span,
                    "conditional-compilation directive retained as unparsed text".into(),
                );
            } else if t == "end" || t == "else" || t == "elseif" {
                parser.error(
                    "VBA1005",
                    line[0].span,
                    "unexpected block terminator".into(),
                );
            } else {
                parser.error(
                    "VBA1006",
                    line[0].span,
                    format!("unrecognized module-level statement: {}", render(&line)),
                );
            }
            parser.at += 1;
        }
    }
    for procedure in &module.procedures {
        collect_call_syntax_diagnostics(
            &procedure.statements,
            &module.source_name,
            &mut parser.diagnostics,
        );
        collect_computed_jump_diagnostics(
            &procedure.statements,
            &module.source_name,
            &mut parser.diagnostics,
        );
    }
    for procedure in &mut module.procedures {
        procedure.automation_member_id = member_id_attributes
            .get(&attribute_identifier_key(&procedure.name))
            .copied();
    }
    module.diagnostics = parser.diagnostics;
    module
}

fn parse_member_id_attributes(tokens: &[Token]) -> std::collections::HashMap<String, i32> {
    let mut attributes = std::collections::HashMap::new();
    let mut line: Vec<&Token> = Vec::new();
    for token in tokens {
        if matches!(token.kind, TokenKind::Newline | TokenKind::Eof) {
            if line.len() >= 6
                && line[0].text.eq_ignore_ascii_case("attribute")
                && line[2].text == "."
                && line[3].text.eq_ignore_ascii_case("vb_usermemid")
                && line[4].text == "="
                && let Some(member_id) = parse_attribute_integer(&line[5..])
            {
                attributes.insert(attribute_identifier_key(&line[1].text), member_id);
            }
            line.clear();
        } else {
            line.push(token);
        }
    }
    attributes
}

fn parse_boolean_module_attribute(tokens: &[Token], name: &str) -> Option<bool> {
    let value = module_header_attribute_value(tokens, name)?;
    if value.text.eq_ignore_ascii_case("true") {
        Some(true)
    } else if value.text.eq_ignore_ascii_case("false") {
        Some(false)
    } else {
        None
    }
}

fn parse_quoted_module_attribute(tokens: &[Token], name: &str) -> Option<String> {
    let value = module_header_attribute_value(tokens, name)?;
    (value.kind == TokenKind::String).then(|| value.text.clone())
}

fn module_header_attribute_value<'a>(tokens: &'a [Token], name: &str) -> Option<&'a Token> {
    let mut value = None;
    let mut line: Vec<&Token> = Vec::new();
    for token in tokens {
        if matches!(token.kind, TokenKind::Newline | TokenKind::Eof) {
            if line.is_empty() {
                continue;
            }
            if !line[0].text.eq_ignore_ascii_case("attribute") {
                break;
            }
            if line.len() == 4 && line[1].text.eq_ignore_ascii_case(name) && line[2].text == "=" {
                value = Some(line[3]);
            }
            line.clear();
        } else {
            line.push(token);
        }
    }
    value
}

fn attribute_identifier_key(name: &str) -> String {
    name.trim_end_matches(['%', '&', '^', '@', '!', '#', '$'])
        .to_lowercase()
}

fn parse_attribute_integer(tokens: &[&Token]) -> Option<i32> {
    let (negative, token) = match tokens {
        [token] => (false, token),
        [sign, token] if sign.text == "-" => (true, token),
        [sign, token] if sign.text == "+" => (false, token),
        _ => return None,
    };
    if token.kind != TokenKind::Number {
        return None;
    }
    let number = token
        .text
        .trim_end_matches(['&', '^'])
        .parse::<i32>()
        .ok()?;
    if negative {
        number.checked_neg()
    } else {
        Some(number)
    }
}

fn collect_call_syntax_diagnostics(
    statements: &[Statement],
    source_name: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for statement in statements {
        if statement.kind == "call"
            && let Some(text) = statement.expression.as_deref()
        {
            let (tokens, _) = lex(text, 4096);
            if explicit_call_has_unparenthesized_arguments(&tokens) {
                diagnostics.push(Diagnostic {
                    code: "VBA1040",
                    severity: Severity::Error,
                    message: "Call with an explicit keyword accepts arguments only as a parenthesized index-expression; trailing unparenthesized arguments are invalid".into(),
                    source: source_name.into(),
                    span: statement.span,
                });
            }
        }
        collect_call_syntax_diagnostics(&statement.children, source_name, diagnostics);
    }
}

fn collect_computed_jump_diagnostics(
    statements: &[Statement],
    source_name: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for statement in statements {
        if matches!(statement.kind.as_str(), "on_goto" | "on_gosub")
            && statement.parsed_expression.is_none()
        {
            diagnostics.push(Diagnostic {
                code: "VBA1014",
                severity: Severity::Warning,
                message: "computed-jump selector was retained as source text but its expression syntax is unresolved".into(),
                source: source_name.into(),
                span: statement.span,
            });
        }
        collect_computed_jump_diagnostics(&statement.children, source_name, diagnostics);
    }
}

fn explicit_call_has_unparenthesized_arguments(tokens: &[Token]) -> bool {
    if !tokens
        .first()
        .is_some_and(|token| token.text.eq_ignore_ascii_case("call"))
    {
        return false;
    }
    let end = tokens
        .iter()
        .position(|token| token.kind == TokenKind::Eof)
        .unwrap_or(tokens.len());
    let mut argument_start = if tokens
        .get(1)
        .is_some_and(|token| matches!(token.text.as_str(), "." | "!"))
    {
        3
    } else {
        2
    };
    while argument_start + 1 < end && matches!(tokens[argument_start].text.as_str(), "." | "!") {
        argument_start += 2;
    }
    argument_start < end && tokens[argument_start].text != "("
}

struct Parser {
    lines: Vec<Vec<Token>>,
    at: usize,
    source_name: String,
    diagnostics: Vec<Diagnostic>,
    max_nesting: usize,
}

impl Parser {
    fn error(&mut self, code: &'static str, span: Span, message: String) {
        self.diagnostics.push(Diagnostic {
            code,
            severity: Severity::Warning,
            message,
            source: self.source_name.clone(),
            span,
        });
    }

    fn parse_block(
        &mut self,
        depth: usize,
        current_proc: Option<&str>,
    ) -> (Vec<Statement>, Option<Span>) {
        let mut out = Vec::new();
        if depth > self.max_nesting {
            if let Some(l) = self.lines.get(self.at) {
                self.error("VBA1010", l[0].span, "block nesting limit exceeded".into());
            }
            return (out, None);
        }
        while self.at < self.lines.len() {
            let line = self.lines[self.at].clone();
            let low = lower_line(&line);
            if is_proc_end(&line, current_proc) {
                let span = line.last().unwrap().span;
                if current_proc.is_some() {
                    self.at += 1;
                    return (out, Some(span));
                } else {
                    return (out, None);
                }
            }
            if is_loop_end(&low) {
                return (out, None);
            }
            if low.starts_with("elseif ")
                || low == "else"
                || low == "end if"
                || low == "case"
                || low.starts_with("case ")
                || low == "end select"
            {
                return (out, None);
            }
            if low.starts_with("if ") && contains_word(&line, "then") {
                let (stmt, consumed) = self.parse_if(depth + 1);
                out.push(stmt);
                if consumed {
                    continue;
                }
            } else if low.starts_with("select case") {
                out.push(self.parse_select(depth + 1));
            } else if starts_block(&line) {
                out.push(self.parse_loop_or_with(depth + 1));
            } else {
                for stmt in parse_body_line(&line) {
                    if stmt.kind == "on_error" {
                        self.error("VBA1011",stmt.span,"possible On Error transfers are added conservatively; statement faultability and handler CFG paths remain incomplete".into());
                    }
                    if stmt.kind == "conditional_compilation" {
                        self.error("VBA1012",stmt.span,"conditional compilation is not evaluated; conditional branches may differ by host".into());
                    }
                    if stmt.kind == "unknown" {
                        self.error(
                            "VBA1013",
                            stmt.span,
                            format!(
                                "statement syntax is not classified: {}",
                                stmt.expression.clone().unwrap_or_default()
                            ),
                        );
                    }
                    out.push(stmt);
                }
                self.at += 1;
            }
        }
        (out, None)
    }

    fn parse_if(&mut self, depth: usize) -> (Statement, bool) {
        let start_line = self.lines[self.at].clone();
        let span = line_span(&start_line);
        let then_pos = start_line
            .iter()
            .enumerate()
            .position(|(index, _)| clause_keyword_at(&start_line, index, "then"))
            .unwrap_or(start_line.len());
        let cond_tokens = &start_line[1..then_pos];
        let tail = &start_line[then_pos.saturating_add(1)..];
        let cond = render(cond_tokens);
        self.at += 1;
        if !tail.is_empty() {
            let else_at = find_top_level_else(tail);
            let then_end = else_at.unwrap_or(tail.len());
            let then_children = parse_simple_sequence(&tail[..then_end]);
            let mut children = vec![Statement {
                kind: "then_branch".into(),
                span,
                children: then_children,
                ..Statement::default()
            }];
            if let Some(e) = else_at {
                children.push(Statement {
                    kind: "else_branch".into(),
                    span,
                    children: parse_simple_sequence(&tail[e + 1..]),
                    ..Statement::default()
                });
            }
            return (
                Statement {
                    kind: "if".into(),
                    expression: Some(cond),
                    parsed_expression: parse_expr_tokens(cond_tokens),
                    span,
                    children,
                    ..Statement::default()
                },
                true,
            );
        }
        let mut stmt = Statement {
            kind: "if".into(),
            expression: Some(cond),
            parsed_expression: parse_expr_tokens(cond_tokens),
            span,
            ..Statement::default()
        };
        let (yes, _) = self.parse_block(depth, None);
        stmt.children.push(Statement {
            kind: "then_branch".into(),
            span,
            children: yes,
            ..Statement::default()
        });
        if self.at < self.lines.len() && lower_line(&self.lines[self.at]).starts_with("elseif ") {
            while self.at < self.lines.len()
                && lower_line(&self.lines[self.at]).starts_with("elseif ")
            {
                let branch = self.lines[self.at].clone();
                let branch_span = line_span(&branch);
                let tp = branch
                    .iter()
                    .enumerate()
                    .position(|(index, _)| clause_keyword_at(&branch, index, "then"))
                    .unwrap_or(branch.len());
                let expr = render(&branch[1..tp]);
                self.at += 1;
                let (body, _) = self.parse_block(depth, None);
                stmt.children.push(Statement {
                    kind: "elseif_branch".into(),
                    expression: Some(expr),
                    parsed_expression: parse_expr_tokens(&branch[1..tp]),
                    span: branch_span,
                    children: body,
                    ..Statement::default()
                });
            }
        }
        if self.at < self.lines.len() && lower_line(&self.lines[self.at]) == "else" {
            let else_span = line_span(&self.lines[self.at]);
            self.at += 1;
            let (body, _) = self.parse_block(depth, None);
            stmt.children.push(Statement {
                kind: "else_branch".into(),
                span: else_span,
                children: body,
                ..Statement::default()
            });
        }
        if self.at < self.lines.len() && lower_line(&self.lines[self.at]) == "end if" {
            stmt.span = stmt.span.join(line_span(&self.lines[self.at]));
            self.at += 1;
        } else {
            self.error("VBA1020", span, "If block has no matching End If".into());
        }
        (stmt, true)
    }

    fn parse_select(&mut self, depth: usize) -> Statement {
        let first = self.lines[self.at].clone();
        let mut stmt = Statement {
            kind: "select_case".into(),
            expression: Some(render(&first[2..])),
            parsed_expression: parse_expr_tokens(&first[2..]),
            span: line_span(&first),
            ..Statement::default()
        };
        self.at += 1;
        let mut saw_case_else = false;
        while self.at < self.lines.len() {
            let line = self.lines[self.at].clone();
            let low = lower_line(&line);
            if low == "end select" {
                stmt.span = stmt.span.join(line_span(&line));
                self.at += 1;
                return stmt;
            }
            if low == "case else" || low.starts_with("case ") {
                let case_span = line_span(&line);
                let is_else = low == "case else";
                if saw_case_else {
                    self.error(
                        "VBA1024",
                        case_span,
                        if is_else {
                            "Select Case contains more than one Case Else clause".into()
                        } else {
                            "Case Else must be the final Select Case clause".into()
                        },
                    );
                }
                if is_else {
                    saw_case_else = true;
                }
                let case_expr = render(&line);
                let case_ranges = if is_else {
                    Vec::new()
                } else {
                    let ranges = parse_case_ranges(&line[1..]);
                    if ranges.iter().any(|range| !range.valid) {
                        self.error(
                            "VBA1025",
                            case_span,
                            "one or more Case range clauses could not be parsed".into(),
                        );
                    }
                    ranges
                };
                self.at += 1;
                let (body, _) = self.parse_block(depth, None);
                stmt.children.push(Statement {
                    kind: "case".into(),
                    expression: Some(case_expr),
                    case_ranges,
                    span: case_span,
                    children: body,
                    ..Statement::default()
                });
            } else {
                self.error(
                    "VBA1021",
                    line[0].span,
                    "expected Case or End Select".into(),
                );
                self.at += 1;
            }
        }
        self.error(
            "VBA1022",
            stmt.span,
            "Select Case has no matching End Select".into(),
        );
        stmt
    }

    fn parse_loop_or_with(&mut self, depth: usize) -> Statement {
        let first = self.lines[self.at].clone();
        let low = lower_line(&first);
        let kind = if keyword_at(&first, 0, "for") && keyword_at(&first, 1, "each") {
            "for_each"
        } else if keyword_at(&first, 0, "for") {
            "for"
        } else if low.starts_with("do while ") || low.starts_with("do until ") {
            "do_pre"
        } else if low == "do" {
            "do"
        } else if low.starts_with("while ") {
            "while"
        } else if keyword_at(&first, 0, "with") {
            "with"
        } else {
            "loop"
        };
        let mut stmt = Statement {
            kind: kind.into(),
            expression: Some(render(&first)),
            parsed_expression: match kind {
                "with" | "while" => parse_expr_tokens(&first[1..]),
                "do_pre" => parse_expr_tokens(&first[2..]),
                _ => None,
            },
            span: line_span(&first),
            ..Statement::default()
        };
        if kind == "for_each" {
            if let Some((control_variable, collection)) = parse_for_each_header(&first) {
                stmt.loop_control_variable = Some(render(control_variable));
                stmt.parsed_expression = parse_expr_tokens(collection);
            } else {
                self.error(
                    "VBA1026",
                    stmt.span,
                    "For Each clause needs a control variable and a collection after In".into(),
                );
            }
        } else if kind == "for" {
            if let Some(header) = parse_for_loop_header(&first) {
                stmt.loop_control_variable = Some(render(header.control_variable));
                stmt.loop_start = Some(render(header.start));
                stmt.loop_end = Some(render(header.end));
                stmt.loop_step = header.step.map(render);
                stmt.parsed_loop_start = parse_expr_tokens(header.start);
                stmt.parsed_loop_end = parse_expr_tokens(header.end);
                stmt.parsed_loop_step = header.step.and_then(parse_expr_tokens);
            } else {
                self.error(
                    "VBA1027",
                    stmt.span,
                    "For clause needs a counter, start value, and end value separated by = and To"
                        .into(),
                );
            }
        }
        self.at += 1;
        let (body, _) = self.parse_block(depth, None);
        stmt.children = body;
        if kind == "with"
            && let Some(with_expression) = stmt.parsed_expression.clone()
            && !contains_with_member(&with_expression)
        {
            bind_with_context(&mut stmt.children, &with_expression);
        }
        if self.at < self.lines.len() {
            let end = self.lines[self.at].clone();
            let e = lower_line(&end);
            let closes = match kind {
                "for" | "for_each" => e == "next" || e.starts_with("next "),
                "do" => e == "loop" || e.starts_with("loop "),
                "while" => e == "wend" || e == "end while",
                "with" => e == "end with",
                _ => false,
            };
            if closes {
                stmt.span = stmt.span.join(line_span(&end));
                let mut consume_terminator = true;
                if matches!(kind, "for" | "for_each")
                    && end
                        .first()
                        .is_some_and(|token| token.text.eq_ignore_ascii_case("next"))
                    && end.len() > 1
                {
                    if let Some(comma) = top_level_delimiter_index(&end[1..], ",") {
                        let current_control = &end[1..comma + 1];
                        let remaining = &end[comma + 2..];
                        if !current_control.is_empty() && !remaining.is_empty() {
                            stmt.next_control_variable = Some(render(current_control));
                            let mut deferred_next = vec![end[0].clone()];
                            deferred_next.extend_from_slice(remaining);
                            self.lines[self.at] = deferred_next;
                            consume_terminator = false;
                        } else {
                            stmt.next_control_variable = Some(render(&end[1..]));
                        }
                    } else {
                        stmt.next_control_variable = Some(render(&end[1..]));
                    }
                }
                if kind == "do" && e.starts_with("loop ") {
                    stmt.exit_condition = Some(render(&end[1..]));
                    let condition = if end.get(1).is_some_and(|token| {
                        token.text.eq_ignore_ascii_case("while")
                            || token.text.eq_ignore_ascii_case("until")
                    }) {
                        &end[2..]
                    } else {
                        &end[1..]
                    };
                    stmt.parsed_exit_condition = parse_expr_tokens(condition);
                }
                if consume_terminator {
                    self.at += 1;
                }
            } else {
                self.error(
                    "VBA1023",
                    stmt.span,
                    format!("{} block has no matching terminator", kind),
                );
            }
        } else {
            self.error(
                "VBA1023",
                stmt.span,
                format!("{} block has no matching terminator", kind),
            );
        }
        stmt
    }

    fn parse_aggregate(&mut self) -> (Vec<Declaration>, Vec<Diagnostic>) {
        let first = self.lines[self.at].clone();
        let span = line_span(&first);
        let mut i = 0;
        let mut visibility = "Public".to_string();
        while i < first.len()
            && matches!(
                first[i].text.to_ascii_lowercase().as_str(),
                "public" | "private" | "friend" | "global"
            )
        {
            visibility = first[i].text.clone();
            i += 1;
        }
        let kind = first
            .get(i)
            .map(|t| t.text.to_ascii_lowercase())
            .unwrap_or_default();
        let name = first.get(i + 1).map(|t| t.text.clone()).unwrap_or_default();
        let end_kind = if kind == "type" { "type" } else { "enum" };
        let mut decls = vec![Declaration {
            name: name.clone(),
            kind: if end_kind == "type" {
                "user_type"
            } else {
                "enum"
            }
            .into(),
            visibility,
            span,
            ..Declaration::default()
        }];
        let mut diags = Vec::new();
        let mut udt_member_names = Vec::new();
        let mut udt_member_count = 0usize;
        let mut enum_member_names = Vec::new();
        let mut enum_member_count = 0usize;
        self.at += 1;
        while self.at < self.lines.len() {
            let line = self.lines[self.at].clone();
            let low = lower_line(&line);
            if low == format!("end {end_kind}") {
                if end_kind == "type" && udt_member_count == 0 {
                    diags.push(Diagnostic {
                        code: "VBA1033",
                        severity: Severity::Error,
                        message: format!("UDT '{}' must declare at least one member", name),
                        source: self.source_name.clone(),
                        span: span.join(line_span(&line)),
                    });
                }
                if end_kind == "enum" && enum_member_count == 0 {
                    diags.push(Diagnostic {
                        code: "VBA1041",
                        severity: Severity::Error,
                        message: format!("Enum '{}' must declare at least one member", name),
                        source: self.source_name.clone(),
                        span: span.join(line_span(&line)),
                    });
                }
                decls[0].span = decls[0].span.join(line_span(&line));
                self.at += 1;
                return (decls, diags);
            }
            if end_kind == "type" {
                let mut fields = parse_field_declarations(&line, &name);
                for field in &fields {
                    udt_member_count += 1;
                    if field.type_name.is_none() {
                        diags.push(Diagnostic {
                            code: "VBA1031",
                            severity: Severity::Error,
                            message: format!(
                                "UDT member '{}' requires an As type clause",
                                field.name
                            ),
                            source: self.source_name.clone(),
                            span: field.span,
                        });
                    }
                    let key = field.name.to_ascii_lowercase();
                    if udt_member_names.iter().any(|existing| existing == &key) {
                        diags.push(Diagnostic {
                            code: "VBA1032",
                            severity: Severity::Error,
                            message: format!(
                                "UDT '{}' declares member '{}' more than once",
                                name, field.name
                            ),
                            source: self.source_name.clone(),
                            span: field.span,
                        });
                    } else {
                        udt_member_names.push(key);
                    }
                }
                decls.append(&mut fields);
            } else if !line.is_empty() {
                let member = line[0].text.clone();
                let eq = line.iter().position(|t| t.text == "=");
                if end_kind == "enum" {
                    enum_member_count += 1;
                    let key = member.to_ascii_lowercase();
                    if enum_member_names.iter().any(|existing| existing == &key) {
                        diags.push(Diagnostic {
                            code: "VBA1042",
                            severity: Severity::Error,
                            message: format!(
                                "Enum '{}' declares member '{}' more than once",
                                name, member
                            ),
                            source: self.source_name.clone(),
                            span: line_span(&line),
                        });
                    } else {
                        enum_member_names.push(key);
                    }
                }
                decls.push(Declaration {
                    name: member,
                    type_name: Some(name.clone()),
                    kind: "enum_member".into(),
                    visibility: "Public".into(),
                    span: line_span(&line),
                    initializer: eq.map(|x| render(&line[x + 1..])),
                    ..Declaration::default()
                });
            }
            self.at += 1;
        }
        if end_kind == "type" && udt_member_count == 0 {
            diags.push(Diagnostic {
                code: "VBA1033",
                severity: Severity::Error,
                message: format!("UDT '{}' must declare at least one member", name),
                source: self.source_name.clone(),
                span,
            });
        }
        if end_kind == "enum" && enum_member_count == 0 {
            diags.push(Diagnostic {
                code: "VBA1041",
                severity: Severity::Error,
                message: format!("Enum '{}' must declare at least one member", name),
                source: self.source_name.clone(),
                span,
            });
        }
        diags.push(Diagnostic {
            code: "VBA1030",
            severity: Severity::Warning,
            message: format!(
                "{} '{}' has no matching End {}",
                if kind == "type" { "Type" } else { "Enum" },
                name,
                end_kind
            ),
            source: self.source_name.clone(),
            span,
        });
        (decls, diags)
    }
}

fn parse_for_each_header(line: &[Token]) -> Option<(&[Token], &[Token])> {
    if line.len() < 5 || !keyword_at(line, 0, "for") || !keyword_at(line, 1, "each") {
        return None;
    }
    let positions = top_level_keyword_positions(&line[2..], "in");
    if positions.len() != 1 {
        return None;
    }
    let in_index = positions[0] + 2;
    let control_variable = &line[2..in_index];
    let collection = &line[in_index + 1..];
    (!control_variable.is_empty() && !collection.is_empty())
        .then_some((control_variable, collection))
}

struct ForLoopHeader<'a> {
    control_variable: &'a [Token],
    start: &'a [Token],
    end: &'a [Token],
    step: Option<&'a [Token]>,
}

fn parse_for_loop_header(line: &[Token]) -> Option<ForLoopHeader<'_>> {
    if line.len() < 4 || !keyword_at(line, 0, "for") {
        return None;
    }
    let equals = top_level_delimiter_index(&line[1..], "=")? + 1;
    if equals <= 1 || equals + 1 >= line.len() {
        return None;
    }
    let control_variable = &line[1..equals];
    let values = &line[equals + 1..];
    let to_positions = top_level_keyword_positions(values, "to");
    if to_positions.len() != 1 || to_positions[0] == 0 || to_positions[0] + 1 >= values.len() {
        return None;
    }
    let to = to_positions[0];
    let start = &values[..to];
    let end_and_step = &values[to + 1..];
    let step_positions = top_level_keyword_positions(end_and_step, "step");
    if step_positions.len() > 1 {
        return None;
    }
    let (end, step) = if let Some(step_index) = step_positions.first().copied() {
        if step_index == 0 || step_index + 1 >= end_and_step.len() {
            return None;
        }
        (
            &end_and_step[..step_index],
            Some(&end_and_step[step_index + 1..]),
        )
    } else {
        (end_and_step, None)
    };
    (!control_variable.is_empty() && !start.is_empty() && !end.is_empty()).then_some(
        ForLoopHeader {
            control_variable,
            start,
            end,
            step,
        },
    )
}

fn top_level_delimiter_index(tokens: &[Token], delimiter: &str) -> Option<usize> {
    let mut depth = 0i32;
    for (index, token) in tokens.iter().enumerate() {
        if depth == 0 && token.text == delimiter {
            return Some(index);
        }
        match token.text.as_str() {
            "(" | "[" => depth += 1,
            ")" | "]" => depth -= 1,
            _ => {}
        }
    }
    None
}

fn parse_case_ranges(tokens: &[Token]) -> Vec<crate::model::CaseRange> {
    split_top_level(tokens, ",")
        .into_iter()
        .map(parse_case_range)
        .collect()
}

fn parse_case_range(tokens: &[Token]) -> crate::model::CaseRange {
    let span = line_span(tokens);
    if tokens.is_empty() {
        return crate::model::CaseRange {
            kind: "unresolved".into(),
            span,
            valid: false,
            ..crate::model::CaseRange::default()
        };
    }
    let expression_start = usize::from(is_keyword_token(&tokens[0], "is"));
    if expression_start == 1 {
        let Some((operator, operator_length)) = case_comparison_operator(tokens, expression_start)
        else {
            return unresolved_case_range(tokens, span);
        };
        let expression_tokens = &tokens[expression_start + operator_length..];
        let parsed_expression = parse_expr_tokens(expression_tokens);
        if expression_tokens.is_empty() || parsed_expression.is_none() {
            return unresolved_case_range(tokens, span);
        }
        return crate::model::CaseRange {
            kind: "comparison".into(),
            expression: Some(render(expression_tokens)),
            parsed_expression,
            comparison_operator: Some(operator),
            span,
            valid: true,
            ..crate::model::CaseRange::default()
        };
    }
    let to_positions = top_level_keyword_positions(tokens, "to");
    if !to_positions.is_empty() {
        if to_positions.len() != 1 || to_positions[0] == 0 || to_positions[0] + 1 >= tokens.len() {
            return unresolved_case_range(tokens, span);
        }
        let to = to_positions[0];
        let start = &tokens[..to];
        let end = &tokens[to + 1..];
        let parsed_start_value = parse_expr_tokens(start);
        let parsed_end_value = parse_expr_tokens(end);
        if parsed_start_value.is_none() || parsed_end_value.is_none() {
            return unresolved_case_range(tokens, span);
        }
        return crate::model::CaseRange {
            kind: "range".into(),
            start_value: Some(render(start)),
            parsed_start_value,
            end_value: Some(render(end)),
            parsed_end_value,
            span,
            valid: true,
            ..crate::model::CaseRange::default()
        };
    }
    let parsed_expression = parse_expr_tokens(tokens);
    if parsed_expression.is_none() {
        return unresolved_case_range(tokens, span);
    }
    crate::model::CaseRange {
        kind: "value".into(),
        expression: Some(render(tokens)),
        parsed_expression,
        span,
        valid: true,
        ..crate::model::CaseRange::default()
    }
}

fn unresolved_case_range(tokens: &[Token], span: Span) -> crate::model::CaseRange {
    crate::model::CaseRange {
        kind: "unresolved".into(),
        expression: Some(render(tokens)),
        span,
        valid: false,
        ..crate::model::CaseRange::default()
    }
}

fn case_comparison_operator(tokens: &[Token], at: usize) -> Option<(String, usize)> {
    let first = tokens.get(at)?;
    if first.kind != TokenKind::Symbol {
        return None;
    }
    let operator = first.text.to_ascii_lowercase();
    if matches!(operator.as_str(), "=" | "<>" | "<" | ">" | "<=" | ">=") {
        return Some((operator, 1));
    }
    None
}

fn top_level_keyword_positions(tokens: &[Token], keyword: &str) -> Vec<usize> {
    let mut positions = Vec::new();
    let mut depth = 0i32;
    for (index, token) in tokens.iter().enumerate() {
        if depth == 0 && clause_keyword_at(tokens, index, keyword) {
            positions.push(index);
        }
        match token.text.as_str() {
            "(" | "[" => depth += 1,
            ")" | "]" => depth -= 1,
            _ => {}
        }
    }
    positions
}

fn bind_with_context(statements: &mut [Statement], base: &Expr) {
    for statement in statements {
        if statement.kind == "with" {
            if let Some(expression) = &mut statement.parsed_expression {
                substitute_with_member(expression, base);
                let nested_base = expression.clone();
                bind_with_context(&mut statement.children, &nested_base);
            } else {
                bind_with_context(&mut statement.children, base);
            }
            continue;
        }
        if let Some(expression) = &mut statement.parsed_expression {
            substitute_with_member(expression, base);
        }
        if let Some(target) = &mut statement.parsed_target {
            substitute_with_member(target, base);
        }
        bind_with_context(&mut statement.children, base);
    }
}

fn contains_with_member(expression: &Expr) -> bool {
    match expression {
        Expr::Unknown(name, _) => name == "with-member",
        Expr::Unary { value, .. } | Expr::Group(value, _) => contains_with_member(value),
        Expr::TypeOfIs { expression, .. } => contains_with_member(expression),
        Expr::Binary { left, right, .. } => {
            contains_with_member(left) || contains_with_member(right)
        }
        Expr::Member { object, .. } => contains_with_member(object),
        Expr::Call { callee, args, .. } => {
            contains_with_member(callee) || args.iter().any(contains_with_member)
        }
        Expr::NamedArgument { value, .. } => contains_with_member(value),
        Expr::Identifier(..) | Expr::Literal(..) => false,
    }
}

fn substitute_with_member(expression: &mut Expr, base: &Expr) {
    match expression {
        Expr::Member { object, .. } if matches!(object.as_ref(), Expr::Unknown(name, _) if name == "with-member") =>
        {
            **object = base.clone();
        }
        Expr::Unary { value, .. } | Expr::Group(value, _) => {
            substitute_with_member(value, base);
        }
        Expr::TypeOfIs { expression, .. } => substitute_with_member(expression, base),
        Expr::Binary { left, right, .. } => {
            substitute_with_member(left, base);
            substitute_with_member(right, base);
        }
        Expr::Member { object, .. } => substitute_with_member(object, base),
        Expr::Call { callee, args, .. } => {
            substitute_with_member(callee, base);
            for argument in args {
                substitute_with_member(argument, base);
            }
        }
        Expr::NamedArgument { value, .. } => substitute_with_member(value, base),
        Expr::Identifier(..) | Expr::Literal(..) | Expr::Unknown(..) => {}
    }
}

fn is_proc_start(line: &[Token]) -> bool {
    let x = lower_line(line);
    let words: Vec<_> = x.split_whitespace().collect();
    words
        .iter()
        .any(|w| matches!(*w, "sub" | "function" | "property"))
        && !words.contains(&"declare")
        && words.first().is_none_or(|w| *w != "end")
}

fn parse_proc_header(line: &[Token]) -> Option<Procedure> {
    let mut i = 0;
    let mut visibility = "Public".to_string();
    let mut is_static = false;
    while let Some(t) = line.get(i) {
        match t.text.to_ascii_lowercase().as_str() {
            "public" | "private" | "friend" => {
                visibility = t.text.clone();
                i += 1;
            }
            "static" => {
                is_static = true;
                i += 1;
            }
            _ => break,
        }
    }
    let kind;
    if line.get(i)?.text.eq_ignore_ascii_case("property") {
        i += 1;
        kind = format!("Property {}", line.get(i)?.text);
        i += 1;
    } else {
        kind = line.get(i)?.text.clone();
        i += 1;
    }
    let name = line.get(i)?.text.clone();
    let name_span = line[i].span;
    i += 1;
    let mut params = Vec::new();
    if line.get(i).is_some_and(|t| t.text == "(") {
        let open = i;
        i += 1;
        let mut close = i;
        let mut nesting = 0;
        while close < line.len() {
            if line[close].text == "(" {
                nesting += 1;
            } else if line[close].text == ")" {
                if nesting == 0 {
                    break;
                }
                nesting -= 1;
            }
            close += 1;
        }
        if close >= line.len() {
            return None;
        }
        for part in split_top_level(&line[open + 1..close], ",") {
            if !part.is_empty() {
                params.push(parse_parameter(part));
            }
        }
        i = close + 1;
    }
    let mut ret = None;
    while i < line.len() {
        if line[i].text.eq_ignore_ascii_case("as") {
            ret = Some(render(&line[i + 1..]));
            break;
        }
        i += 1;
    }
    Some(Procedure {
        name,
        kind,
        return_type: ret,
        parameters: params,
        span: name_span.join(line_span(line)),
        visibility,
        is_static,
        ..Procedure::default()
    })
}

fn parse_parameter(ts: &[Token]) -> Parameter {
    let span = line_span(ts);
    let mut i = 0;
    let mut optional = false;
    let mut is_param_array = false;
    let mut passing = "ByRef".to_string();
    let mut passing_explicit = false;
    while i < ts.len() {
        match ts[i].text.to_ascii_lowercase().as_str() {
            "optional" => {
                optional = true;
                i += 1
            }
            "paramarray" => {
                is_param_array = true;
                i += 1
            }
            "byval" | "byref" => {
                passing = ts[i].text.clone();
                passing_explicit = true;
                i += 1
            }
            "array" => i += 1,
            _ => break,
        }
    }
    let name = ts.get(i).map(|t| t.text.clone()).unwrap_or_default();
    i += usize::from(!name.is_empty());
    let mut is_array = false;
    if ts.get(i).is_some_and(|t| t.text == "(") {
        is_array = true;
        let mut depth = 0i32;
        while i < ts.len() {
            match ts[i].text.as_str() {
                "(" => depth += 1,
                ")" => {
                    depth -= 1;
                    i += 1;
                    if depth == 0 {
                        break;
                    }
                    continue;
                }
                _ => {}
            }
            i += 1;
        }
    }
    let as_i = ts[i..]
        .iter()
        .position(|t| t.text.eq_ignore_ascii_case("as"))
        .map(|n| n + i);
    let eq_i = ts[i..].iter().position(|t| t.text == "=").map(|n| n + i);
    let type_name = as_i.map(|a| render(&ts[a + 1..eq_i.unwrap_or(ts.len())]));
    let default_value = eq_i.map(|e| render(&ts[e + 1..]));
    Parameter {
        name,
        type_name,
        passing,
        passing_explicit,
        is_array,
        optional,
        is_param_array,
        default_value,
        span,
    }
}

fn parse_declaration_line(line: &[Token], scope: &str) -> Option<Vec<Declaration>> {
    if line.is_empty() {
        return None;
    }
    let mut i = 0;
    let mut visibility = if scope == "module" { "Private" } else { "Dim" }.to_string();
    let mut kind = "variable".to_string();
    while i < line.len() {
        let x = line[i].text.to_ascii_lowercase();
        match x.as_str() {
            "public" | "private" | "friend" | "global" => {
                visibility = line[i].text.clone();
                if x == "global" {
                    kind = "global".into();
                }
                i += 1;
            }
            "static" => {
                kind = "static".into();
                i += 1;
            }
            "dim" => {
                if kind == "variable" {
                    visibility = "Dim".into();
                }
                i += 1;
            }
            "const" => {
                kind = "constant".into();
                i += 1;
            }
            "declare" => return None,
            "withevents" => {
                kind = "with_events".into();
                i += 1;
            }
            _ => break,
        }
    }
    if i == 0 || i >= line.len() {
        return None;
    }
    if !matches!(
        kind.as_str(),
        "variable" | "global" | "static" | "constant" | "with_events"
    ) {
        return None;
    }
    let rest = &line[i..];
    let mut out = Vec::new();
    for part in split_top_level(rest, ",") {
        if part.is_empty() {
            continue;
        }
        let name = part
            .iter()
            .take_while(|t| t.text != "(" && !t.text.eq_ignore_ascii_case("as") && t.text != "=")
            .map(|t| t.text.as_str())
            .collect::<String>();
        if name.is_empty() {
            continue;
        }
        let as_i = part.iter().position(|t| t.text.eq_ignore_ascii_case("as"));
        let eq_i = part.iter().position(|t| t.text == "=");
        let name_end = part
            .iter()
            .position(|t| t.text == "(" || t.text.eq_ignore_ascii_case("as") || t.text == "=")
            .unwrap_or(part.len());
        let is_array = part[..name_end].iter().any(|t| t.text == "(")
            || part.get(name_end).is_some_and(|t| t.text == "(");
        let array_dimensions = parse_array_dimensions(part);
        let type_name = as_i.map(|a| render(&part[a + 1..eq_i.unwrap_or(part.len())]));
        let initializer = eq_i.map(|e| render(&part[e + 1..]));
        out.push(Declaration {
            name,
            type_name,
            kind: kind.clone(),
            visibility: visibility.clone(),
            span: line_span(part),
            initializer,
            is_array,
            array_dimensions,
            ..Declaration::default()
        });
    }
    (!out.is_empty()).then_some(out)
}

fn is_aggregate_start(line: &[Token]) -> bool {
    if line
        .first()
        .is_some_and(|token| token.text.eq_ignore_ascii_case("global"))
    {
        return line
            .get(1)
            .is_some_and(|token| token.text.eq_ignore_ascii_case("enum"));
    }
    let mut i = 0;
    while i < line.len()
        && matches!(
            line[i].text.to_ascii_lowercase().as_str(),
            "public" | "private" | "friend"
        )
    {
        i += 1;
    }
    line.get(i)
        .is_some_and(|t| matches!(t.text.to_ascii_lowercase().as_str(), "type" | "enum"))
}
fn parse_implements(line: &[Token]) -> Option<String> {
    if line
        .first()
        .is_some_and(|token| token.text.eq_ignore_ascii_case("implements"))
        && line
            .get(1)
            .is_some_and(|token| token.kind == TokenKind::Identifier)
        && line.len() == 2
    {
        Some(line[1].text.clone())
    } else {
        None
    }
}
fn parse_event_or_external(line: &[Token]) -> Option<Declaration> {
    let mut i = 0;
    let mut visibility = "Public".to_string();
    while i < line.len()
        && matches!(
            line[i].text.to_ascii_lowercase().as_str(),
            "public" | "private" | "friend"
        )
    {
        visibility = line[i].text.clone();
        i += 1;
    }
    let first = line.get(i)?.text.to_ascii_lowercase();
    if first == "event" {
        let name_index = i + 1;
        let name = line.get(name_index)?.text.clone();
        return Some(Declaration {
            name,
            kind: "event".into(),
            visibility,
            span: line_span(line),
            initializer: Some(render(line)),
            parameters: declaration_parameters(line, name_index),
            ..Declaration::default()
        });
    }
    if first != "declare" {
        return None;
    }
    let start = i;
    i += 1;
    while i < line.len()
        && matches!(
            line[i].text.to_ascii_lowercase().as_str(),
            "ptrsafe" | "wide" | "ansi"
        )
    {
        i += 1;
    }
    if i < line.len()
        && matches!(
            line[i].text.to_ascii_lowercase().as_str(),
            "sub" | "function"
        )
    {
        i += 1;
    }
    let name = line.get(i)?.text.clone();
    let name_index = i;
    let is_ptr_safe = line[start..name_index]
        .iter()
        .any(|token| token.text.eq_ignore_ascii_case("ptrsafe"));
    let as_i = line.iter().position(|t| t.text.eq_ignore_ascii_case("as"));
    let ty = as_i.map(|a| render(&line[a + 1..]));
    let external_library = line
        .iter()
        .position(|token| token.text.eq_ignore_ascii_case("lib"))
        .and_then(|index| line.get(index + 1))
        .filter(|token| token.kind == TokenKind::String)
        .map(|token| token.text.clone());
    let external_alias = line
        .iter()
        .position(|token| token.text.eq_ignore_ascii_case("alias"))
        .and_then(|index| line.get(index + 1))
        .filter(|token| token.kind == TokenKind::String)
        .map(|token| token.text.clone());
    Some(Declaration {
        name,
        type_name: ty,
        kind: "external_declare".into(),
        visibility,
        span: line_span(line),
        initializer: Some(render(&line[start..])),
        is_ptr_safe,
        external_library,
        external_alias,
        parameters: declaration_parameters(line, name_index),
        ..Declaration::default()
    })
}

fn declaration_parameters(line: &[Token], name_index: usize) -> Vec<Parameter> {
    let Some(open) = line
        .iter()
        .enumerate()
        .skip(name_index + 1)
        .find_map(|(i, t)| (t.text == "(").then_some(i))
    else {
        return Vec::new();
    };
    let mut depth = 0i32;
    let close = line.iter().enumerate().skip(open + 1).find_map(|(i, t)| {
        match t.text.as_str() {
            "(" => depth += 1,
            ")" if depth == 0 => return Some(i),
            ")" => depth -= 1,
            _ => {}
        }
        None
    });
    let Some(close) = close else {
        return Vec::new();
    };
    split_top_level(&line[open + 1..close], ",")
        .into_iter()
        .filter(|part| !part.is_empty())
        .map(parse_parameter)
        .collect()
}
fn parse_field_declarations(line: &[Token], type_name: &str) -> Vec<Declaration> {
    let mut out = Vec::new();
    for part in split_top_level(line, ",") {
        if part.is_empty() {
            continue;
        }
        let name = part
            .iter()
            .take_while(|t| t.text != "(" && !t.text.eq_ignore_ascii_case("as"))
            .map(|t| t.text.as_str())
            .collect::<String>();
        if name.is_empty() {
            continue;
        }
        let as_i = part.iter().position(|t| t.text.eq_ignore_ascii_case("as"));
        let name_end = part
            .iter()
            .position(|t| t.text == "(" || t.text.eq_ignore_ascii_case("as"))
            .unwrap_or(part.len());
        let is_array = part.get(name_end).is_some_and(|t| t.text == "(");
        let array_dimensions = parse_array_dimensions(part);
        out.push(Declaration {
            name,
            type_name: as_i.map(|i| render(&part[i + 1..])),
            kind: "field".into(),
            visibility: type_name.into(),
            span: line_span(part),
            is_array,
            array_dimensions,
            ..Declaration::default()
        });
    }
    out
}

fn parse_array_dimensions(tokens: &[Token]) -> Vec<crate::model::ArrayDimension> {
    let Some(open) = tokens.iter().position(|token| token.text == "(") else {
        return Vec::new();
    };
    let mut depth = 0i32;
    let Some(close) = tokens
        .iter()
        .enumerate()
        .skip(open)
        .find_map(|(index, token)| {
            match token.text.as_str() {
                "(" => depth += 1,
                ")" => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(index);
                    }
                }
                _ => {}
            }
            None
        })
    else {
        return Vec::new();
    };
    split_top_level(&tokens[open + 1..close], ",")
        .into_iter()
        .filter(|dimension| !dimension.is_empty())
        .map(|dimension| {
            let mut depth = 0i32;
            let to = dimension.iter().enumerate().find_map(|(index, token)| {
                match token.text.as_str() {
                    "(" | "[" => depth += 1,
                    ")" | "]" => depth -= 1,
                    _ => {}
                }
                (depth == 0 && token.text.eq_ignore_ascii_case("to")).then_some(index)
            });
            if let Some(to) = to {
                crate::model::ArrayDimension {
                    lower_bound: Some(render(&dimension[..to])),
                    upper_bound: Some(render(&dimension[to + 1..])),
                }
            } else {
                crate::model::ArrayDimension {
                    lower_bound: None,
                    upper_bound: Some(render(dimension)),
                }
            }
        })
        .collect()
}

fn is_ignorable_header(line: &[Token]) -> bool {
    let x = lower_line(line);
    x.starts_with("option ")
        || x.starts_with("attribute ")
        || x.starts_with("implements ")
        || x.starts_with("#if ")
        || x.starts_with("#const ")
        || line.first().is_some_and(|token| {
            token.kind == TokenKind::Identifier
                && !token.bracket_delimited
                && is_def_type_directive_keyword(&token.text)
        })
}

pub(crate) fn is_def_type_directive_keyword(keyword: &str) -> bool {
    matches!(
        keyword.to_ascii_lowercase().as_str(),
        "defbool"
            | "defbyte"
            | "defcur"
            | "defdate"
            | "defdbl"
            | "defdec"
            | "defint"
            | "deflng"
            | "deflnglng"
            | "deflngptr"
            | "defobj"
            | "defsng"
            | "defstr"
            | "defvar"
    )
}

fn is_proc_end(line: &[Token], expected: Option<&str>) -> bool {
    let x = lower_line(line);
    if !x.starts_with("end ") {
        return false;
    }
    let words: Vec<_> = x.split_whitespace().collect();
    if words.len() < 2 || !matches!(words[1], "sub" | "function" | "property") {
        return false;
    }
    expected
        .map(|k| {
            let e = k.to_ascii_lowercase();
            if e.starts_with("property") {
                words[1] == "property"
            } else {
                words[1] == e
            }
        })
        .unwrap_or(true)
}
fn starts_block(line: &[Token]) -> bool {
    let x = lower_line(line);
    x.starts_with("for ")
        || x == "do"
        || x.starts_with("do while ")
        || x.starts_with("do until ")
        || x.starts_with("while ")
        || keyword_at(line, 0, "with")
}
fn is_loop_end(s: &str) -> bool {
    s == "next"
        || s.starts_with("next ")
        || s == "loop"
        || s.starts_with("loop ")
        || s == "wend"
        || s == "end while"
        || s == "end with"
}
fn contains_word(line: &[Token], word: &str) -> bool {
    line.iter()
        .enumerate()
        .any(|(index, _)| clause_keyword_at(line, index, word))
}
fn lower_line(line: &[Token]) -> String {
    render(line).to_ascii_lowercase()
}
fn keyword_at(tokens: &[Token], index: usize, keyword: &str) -> bool {
    tokens
        .get(index)
        .is_some_and(|token| is_keyword_token(token, keyword))
}
fn is_keyword_token(token: &Token, keyword: &str) -> bool {
    token.kind == TokenKind::Identifier
        && !token.bracket_delimited
        && token.text.eq_ignore_ascii_case(keyword)
}
fn clause_keyword_at(tokens: &[Token], index: usize, keyword: &str) -> bool {
    tokens
        .get(index)
        .is_some_and(|token| is_keyword_token(token, keyword))
        && !index
            .checked_sub(1)
            .and_then(|previous| tokens.get(previous))
            .is_some_and(|previous| matches!(previous.text.as_str(), "." | "!"))
}
fn line_span(line: &[Token]) -> Span {
    if line.is_empty() {
        Span::default()
    } else {
        line.first().unwrap().span.join(line.last().unwrap().span)
    }
}
fn split_top_level<'a>(ts: &'a [Token], delim: &str) -> Vec<&'a [Token]> {
    let (mut out, mut start, mut depth) = (Vec::new(), 0usize, 0i32);
    for (i, t) in ts.iter().enumerate() {
        match t.text.as_str() {
            "(" | "[" => depth += 1,
            ")" | "]" => depth -= 1,
            _ => {}
        }
        if depth == 0 && t.text == delim {
            out.push(&ts[start..i]);
            start = i + 1;
        }
    }
    out.push(&ts[start..]);
    out
}
fn render(ts: &[Token]) -> String {
    let mut s = String::new();
    let mut prev = "";
    for t in ts {
        let tight = (matches!(t.text.as_str(), ")" | "." | "," | ":" | "!" | "(")
            || matches!(prev, "." | "!" | "("))
            && !(t.text == "." && prev.eq_ignore_ascii_case("with"));
        if !s.is_empty() && !tight {
            s.push(' ');
        }
        let rendered = if t.bracket_delimited {
            format!("[{}]", t.text)
        } else if t.kind == TokenKind::String {
            format!("\"{}\"", t.text.replace('"', "\"\""))
        } else {
            t.text.clone()
        };
        s.push_str(&rendered);
        prev = &t.text;
    }
    s
}

fn parse_simple(line: &[Token]) -> Statement {
    if let Some(statement) = parse_on_jump_statement(line) {
        return statement;
    }
    let span = line_span(line);
    let text = render(line);
    let low = text.to_ascii_lowercase();
    let direct_jump = jump_keyword_at(line, 0).filter(|jump| matches!(jump.kind, "goto" | "gosub"));
    let valid_direct_jump = direct_jump.filter(|jump| {
        let target = &line[jump.token_count..];
        target.len() == 1 && is_statement_label_token(&target[0])
    });
    let kind = if line.first().is_some_and(|token| {
        token.kind == TokenKind::Identifier
            && !token.bracket_delimited
            && is_def_type_directive_keyword(&token.text)
    }) {
        "def_type_directive"
    } else if low.starts_with("on error") {
        "on_error"
    } else if low.starts_with("#if") || low.starts_with("#else") || low.starts_with("#end if") {
        "conditional_compilation"
    } else if low.starts_with("exit ") {
        "exit"
    } else if valid_direct_jump.is_some_and(|jump| jump.kind == "goto") {
        "goto"
    } else if valid_direct_jump.is_some_and(|jump| jump.kind == "gosub") {
        "gosub"
    } else if low == "return" {
        "gosub_return"
    } else if keyword_at(line, 0, "resume") {
        "resume"
    } else if low.starts_with("raiseevent ") {
        "raise_event"
    } else if low.starts_with("redim ") || low.starts_with("redim preserve ") {
        "redim"
    } else if low.starts_with("erase ") {
        "erase"
    } else if keyword_at(line, 0, "stop") {
        if line.len() == 1 { "stop" } else { "unknown" }
    } else if keyword_at(line, 0, "end") {
        if line.len() == 1 {
            "end_statement"
        } else {
            "unknown"
        }
    } else if keyword_at(line, 0, "call") {
        "call"
    } else if assignment_rhs(line).is_some() {
        "assignment"
    } else if low.ends_with(":") {
        "label"
    } else if low.starts_with("case ") {
        "case"
    } else if line
        .first()
        .is_some_and(|token| token.text.eq_ignore_ascii_case("on"))
        || direct_jump.is_some()
    {
        "unknown"
    } else if low.starts_with("debug.print") {
        "call"
    } else if line.first().is_some_and(|token| {
        matches!(token.kind, TokenKind::Identifier) || matches!(token.text.as_str(), "." | "!")
    }) {
        "call_or_expression"
    } else {
        "unknown"
    };
    let expression = if matches!(kind, "goto" | "gosub") {
        None
    } else if matches!(kind, "call" | "call_or_expression" | "raise_event") {
        parse_call_statement(line, kind)
    } else if kind == "assignment" {
        assignment_rhs(line).and_then(parse_expr_tokens)
    } else {
        parse_expr_tokens(line)
    };
    let parsed_target = (kind == "assignment")
        .then(|| assignment_lhs(line))
        .flatten()
        .map(|target| {
            if target.first().is_some_and(|token| {
                matches!(token.text.to_ascii_lowercase().as_str(), "let" | "set")
            }) {
                &target[1..]
            } else {
                target
            }
        })
        .and_then(parse_expr_tokens);
    let mut statement = Statement {
        kind: kind.into(),
        expression: Some(text),
        parsed_expression: expression,
        parsed_target,
        span,
        ..Statement::default()
    };
    if matches!(kind, "goto" | "gosub")
        && let Some(jump) = valid_direct_jump
    {
        let target = &line[jump.token_count..];
        if target.len() == 1 && is_statement_label_token(&target[0]) {
            statement.children.push(Statement {
                kind: "jump_target".into(),
                expression: Some(target[0].text.clone()),
                span: target[0].span,
                ..Statement::default()
            });
        }
    }
    statement
}

#[derive(Clone, Copy)]
struct JumpKeyword {
    kind: &'static str,
    token_count: usize,
}

fn jump_keyword_at(tokens: &[Token], at: usize) -> Option<JumpKeyword> {
    let first = tokens.get(at)?.text.to_ascii_lowercase();
    match first.as_str() {
        "goto" => Some(JumpKeyword {
            kind: "goto",
            token_count: 1,
        }),
        "gosub" => Some(JumpKeyword {
            kind: "gosub",
            token_count: 1,
        }),
        "go" => match tokens.get(at + 1)?.text.to_ascii_lowercase().as_str() {
            "to" => Some(JumpKeyword {
                kind: "goto",
                token_count: 2,
            }),
            "sub" => Some(JumpKeyword {
                kind: "gosub",
                token_count: 2,
            }),
            _ => None,
        },
        _ => None,
    }
}

fn is_statement_label_token(token: &Token) -> bool {
    token.kind == TokenKind::Identifier
        || (token.kind == TokenKind::Number
            && !token.text.is_empty()
            && token.text.bytes().all(|byte| byte.is_ascii_digit()))
}

fn parse_on_jump_statement(tokens: &[Token]) -> Option<Statement> {
    if !tokens
        .first()
        .is_some_and(|token| token.text.eq_ignore_ascii_case("on"))
        || tokens
            .get(1)
            .is_some_and(|token| token.text.eq_ignore_ascii_case("error"))
    {
        return None;
    }
    let (keyword_index, jump) = find_on_jump_keyword(tokens)?;
    let expression = tokens.get(1..keyword_index)?;
    if expression.is_empty() {
        return None;
    }
    let destinations = split_top_level(tokens.get(keyword_index + jump.token_count..)?, ",");
    if destinations.is_empty()
        || destinations
            .iter()
            .any(|destination| destination.len() != 1 || !is_statement_label_token(&destination[0]))
    {
        return None;
    }
    let span = line_span(tokens);
    Some(Statement {
        kind: if jump.kind == "goto" {
            "on_goto".into()
        } else {
            "on_gosub".into()
        },
        expression: Some(render(expression)),
        parsed_expression: parse_expr_tokens(expression),
        span,
        children: destinations
            .into_iter()
            .map(|destination| Statement {
                kind: "jump_target".into(),
                expression: Some(destination[0].text.clone()),
                span: destination[0].span,
                ..Statement::default()
            })
            .collect(),
        ..Statement::default()
    })
}

fn find_on_jump_keyword(tokens: &[Token]) -> Option<(usize, JumpKeyword)> {
    let mut nesting = 0i32;
    let mut index = 1;
    while index < tokens.len() {
        let is_member_name = index > 1 && matches!(tokens[index - 1].text.as_str(), "." | "!");
        if nesting == 0
            && !is_member_name
            && let Some(jump) = jump_keyword_at(tokens, index)
        {
            return Some((index, jump));
        }
        match tokens[index].text.as_str() {
            "(" | "[" => nesting += 1,
            ")" | "]" => nesting -= 1,
            _ => {}
        }
        index += 1;
    }
    None
}

fn find_top_level_else(ts: &[Token]) -> Option<usize> {
    let mut depth = 0i32;
    for (i, t) in ts.iter().enumerate() {
        match t.text.as_str() {
            "(" | "[" => depth += 1,
            ")" | "]" => depth -= 1,
            _ => {}
        }
        if depth == 0 && clause_keyword_at(ts, i, "else") {
            return Some(i);
        }
    }
    None
}
fn parse_simple_sequence(ts: &[Token]) -> Vec<Statement> {
    let (label, parts) = split_label_prefix(ts);
    let mut out = Vec::new();
    if let Some(label) = label {
        out.push(Statement {
            kind: "label".into(),
            expression: Some(format!("{}:", label.text)),
            span: label.span,
            ..Statement::default()
        });
    }
    out.extend(
        parts
            .into_iter()
            .filter(|part| !part.is_empty())
            .map(|part| attach_array_operation_details(parse_simple(part), part)),
    );
    out
}

fn parse_body_line(ts: &[Token]) -> Vec<Statement> {
    let (label, parts) = split_label_prefix(ts);
    let mut out = Vec::new();
    if let Some(label) = label {
        out.push(Statement {
            kind: "label".into(),
            expression: Some(format!("{}:", label.text)),
            span: label.span,
            ..Statement::default()
        });
    }
    for part in parts.into_iter().filter(|part| !part.is_empty()) {
        let mut stmt = attach_array_operation_details(parse_simple(part), part);
        if stmt.kind != "redim"
            && let Some(declarations) = parse_declaration_line(part, "procedure")
        {
            stmt.kind = "declaration".into();
            stmt.children = declarations
                .into_iter()
                .map(|d| Statement {
                    kind: "declared_name".into(),
                    expression: Some(d.name.clone()),
                    span: d.span,
                    declaration: Some(d),
                    ..Statement::default()
                })
                .collect();
        }
        out.push(stmt);
    }
    out
}

fn attach_array_operation_details(mut statement: Statement, line: &[Token]) -> Statement {
    if statement.kind == "redim" {
        statement.children = parse_redim_declarations(line)
            .into_iter()
            .map(|declaration| Statement {
                kind: "redim_array".into(),
                expression: Some(declaration.name.clone()),
                span: declaration.span,
                declaration: Some(declaration),
                ..Statement::default()
            })
            .collect();
    } else if statement.kind == "erase" {
        statement.children = parse_erase_targets(line)
            .into_iter()
            .map(|target| Statement {
                kind: "erase_target".into(),
                expression: Some(render(target)),
                parsed_expression: parse_expr_tokens(target),
                span: line_span(target),
                ..Statement::default()
            })
            .collect();
    }
    statement
}

fn parse_erase_targets(line: &[Token]) -> Vec<&[Token]> {
    if !line
        .first()
        .is_some_and(|token| token.text.eq_ignore_ascii_case("erase"))
    {
        return Vec::new();
    }
    split_top_level(&line[1..], ",")
        .into_iter()
        .filter(|target| !target.is_empty())
        .collect()
}

fn parse_redim_declarations(line: &[Token]) -> Vec<Declaration> {
    let Some(first) = line.first() else {
        return Vec::new();
    };
    if !first.text.eq_ignore_ascii_case("redim") {
        return Vec::new();
    }
    let preserve = line
        .get(1)
        .is_some_and(|token| token.text.eq_ignore_ascii_case("preserve"));
    let operands = &line[if preserve { 2 } else { 1 }..];
    split_top_level(operands, ",")
        .into_iter()
        .filter(|part| !part.is_empty())
        .filter_map(|part| {
            let name_end = part
                .iter()
                .position(|token| token.text == "(" || token.text.eq_ignore_ascii_case("as"))
                .unwrap_or(part.len());
            let name = render(&part[..name_end]);
            if name.is_empty() {
                return None;
            }
            let is_array = part.get(name_end).is_some_and(|token| token.text == "(");
            let as_index = part
                .iter()
                .position(|token| token.text.eq_ignore_ascii_case("as"));
            Some(Declaration {
                name,
                type_name: as_index.map(|index| render(&part[index + 1..])),
                kind: if preserve {
                    "redim_preserve".into()
                } else {
                    "redim".into()
                },
                span: line_span(part),
                is_array,
                array_dimensions: parse_array_dimensions(part),
                ..Declaration::default()
            })
        })
        .collect()
}

fn split_label_prefix(ts: &[Token]) -> (Option<Token>, Vec<&[Token]>) {
    let parts = split_top_level(ts, ":");
    if parts.len() > 1 && parts[0].len() == 1 && is_statement_label_token(&parts[0][0]) {
        (
            Some(parts[0][0].clone()),
            parts.into_iter().skip(1).collect(),
        )
    } else if ts.first().is_some_and(is_statement_label_token) && ts[0].kind == TokenKind::Number {
        (
            Some(ts[0].clone()),
            if ts.len() > 1 {
                vec![&ts[1..]]
            } else {
                Vec::new()
            },
        )
    } else {
        (None, parts)
    }
}

fn parse_expr_tokens(ts: &[Token]) -> Option<Expr> {
    if ts.is_empty() {
        return None;
    }
    let mut p = ExprParser { ts, at: 0 };
    let e = p.expr(0)?;
    (p.at == ts.len()).then_some(e)
}

pub(crate) fn parse_expression_source(source: &str) -> Option<Expr> {
    let (tokens, _) = lex(source, 4096);
    let tokens = tokens
        .into_iter()
        .filter(|token| !matches!(token.kind, TokenKind::Newline | TokenKind::Eof))
        .collect::<Vec<_>>();
    parse_expr_tokens(&tokens)
}

fn assignment_rhs(ts: &[Token]) -> Option<&[Token]> {
    let mut depth = 0i32;
    for (i, t) in ts.iter().enumerate() {
        match t.text.as_str() {
            "(" | "[" => depth += 1,
            ")" | "]" => depth -= 1,
            "=" if depth == 0 && t.kind == TokenKind::Symbol => return ts.get(i + 1..),
            _ => {}
        }
    }
    None
}

fn assignment_lhs(ts: &[Token]) -> Option<&[Token]> {
    let mut depth = 0i32;
    for (i, token) in ts.iter().enumerate() {
        match token.text.as_str() {
            "(" | "[" => depth += 1,
            ")" | "]" => depth -= 1,
            "=" if depth == 0 && token.kind == TokenKind::Symbol => return Some(&ts[..i]),
            _ => {}
        }
    }
    None
}

fn parse_call_statement(ts: &[Token], kind: &str) -> Option<Expr> {
    let mut start = usize::from(keyword_at(ts, 0, "call"));
    if kind == "raise_event" {
        start = 1;
    }
    if start >= ts.len() {
        return None;
    }
    let callee_start = start;
    let leading_with_member = ts
        .get(start)
        .is_some_and(|token| matches!(token.text.as_str(), "." | "!"));
    let mut args_start = start + if leading_with_member { 2 } else { 1 };
    while args_start + 1 < ts.len() && matches!(ts[args_start].text.as_str(), "." | "!") {
        args_start += 2;
    }
    if ts.get(args_start).is_some_and(|t| t.text == "(") {
        return parse_expr_tokens(&ts[callee_start..]);
    }
    let callee = parse_expr_tokens(&ts[callee_start..args_start])?;
    let args = if kind == "call" {
        Vec::new()
    } else if args_start < ts.len() {
        split_top_level(&ts[args_start..], ",")
            .into_iter()
            .map(parse_argument)
            .collect::<Option<Vec<_>>>()?
    } else {
        Vec::new()
    };
    let end = ts.last()?.span;
    Some(Expr::Call {
        span: callee.span().join(end),
        callee: Box::new(callee),
        args,
    })
}

fn parse_argument(ts: &[Token]) -> Option<Expr> {
    if ts.is_empty() {
        return Some(Expr::Unknown("missing argument".into(), Span::default()));
    }
    let mut depth = 0i32;
    for (i, t) in ts.iter().enumerate() {
        match t.text.as_str() {
            "(" | "[" => depth += 1,
            ")" | "]" => depth -= 1,
            _ => {}
        }
        if depth == 0 && t.text == ":=" {
            let name = render(&ts[..i]);
            let value = parse_expr_tokens(&ts[i + 1..])?;
            return Some(Expr::NamedArgument {
                name,
                value: Box::new(value),
                span: line_span(ts),
            });
        }
    }
    parse_expr_tokens(ts)
}
struct ExprParser<'a> {
    ts: &'a [Token],
    at: usize,
}
impl<'a> ExprParser<'a> {
    fn expr(&mut self, min: u8) -> Option<Expr> {
        let tok = self.ts.get(self.at)?.clone();
        self.at += 1;
        let typeof_expression = tok.kind == TokenKind::Identifier
            && !tok.bracket_delimited
            && tok.text.eq_ignore_ascii_case("typeof");
        let mut left = if typeof_expression {
            let expression = self.expr(7)?;
            let is_token = self.ts.get(self.at)?;
            if !is_keyword_token(is_token, "is") {
                return None;
            }
            self.at += 1;
            let (type_name, type_span) = self.type_expression()?;
            Expr::TypeOfIs {
                span: tok.span.join(type_span),
                expression: Box::new(expression),
                type_name,
                type_span,
            }
        } else {
            let unary = if tok.kind == TokenKind::Symbol && matches!(tok.text.as_str(), "+" | "-") {
                Some((tok.text.clone(), 11))
            } else if tok.kind == TokenKind::Identifier {
                match tok.text.to_ascii_lowercase().as_str() {
                    "not" => Some((tok.text.clone(), 6)),
                    "addressof" | "new" => Some((tok.text.clone(), 11)),
                    _ => None,
                }
            } else {
                None
            };
            if let Some((op, precedence)) = unary {
                let value = self.expr(precedence)?;
                Expr::Unary {
                    op,
                    span: tok.span.join(value.span()),
                    value: Box::new(value),
                }
            } else {
                match tok.kind {
                    TokenKind::Identifier if tok.bracket_delimited => {
                        Expr::Unknown(format!("[{}]", tok.text), tok.span)
                    }
                    TokenKind::Identifier => Expr::Identifier(tok.text, tok.span),
                    TokenKind::Number => {
                        Expr::Literal(tok.text, crate::model::LiteralKind::Number, tok.span)
                    }
                    TokenKind::String => {
                        Expr::Literal(tok.text, crate::model::LiteralKind::String, tok.span)
                    }
                    TokenKind::Date => {
                        Expr::Literal(tok.text, crate::model::LiteralKind::Date, tok.span)
                    }
                    _ => match tok.text.as_str() {
                        "(" => {
                            let v = self.expr(0)?;
                            if self.ts.get(self.at).is_some_and(|t| t.text == ")") {
                                let end = self.ts[self.at].span;
                                self.at += 1;
                                Expr::Group(Box::new(v), tok.span.join(end))
                            } else {
                                return None;
                            }
                        }
                        "." | "!" => {
                            let member = self.ts.get(self.at).cloned()?;
                            if member.kind != TokenKind::Identifier || member.text.is_empty() {
                                return None;
                            }
                            self.at += 1;
                            if tok.text == "." && member.bracket_delimited {
                                Expr::Unknown(
                                    "host bracket expression".into(),
                                    tok.span.join(member.span),
                                )
                            } else {
                                Expr::Member {
                                    span: tok.span.join(member.span),
                                    object: Box::new(Expr::Unknown("with-member".into(), tok.span)),
                                    member: member.text,
                                    access: if tok.text == "." {
                                        MemberAccessKind::Dot
                                    } else {
                                        MemberAccessKind::Bang
                                    },
                                }
                            }
                        }
                        _ if tok.kind == TokenKind::Symbol => return None,
                        _ => Expr::Unknown(tok.text, tok.span),
                    },
                }
            }
        };
        loop {
            let Some(op) = self.ts.get(self.at).cloned() else {
                break;
            };
            if op.text == "." || op.text == "!" {
                if 12 < min {
                    break;
                }
                self.at += 1;
                let m = self.ts.get(self.at).cloned()?;
                if m.kind != TokenKind::Identifier || m.text.is_empty() {
                    return None;
                }
                self.at += 1;
                if op.text == "." && m.bracket_delimited {
                    left =
                        Expr::Unknown("host bracket expression".into(), left.span().join(m.span));
                } else {
                    left = Expr::Member {
                        span: left.span().join(m.span),
                        object: Box::new(left),
                        member: m.text,
                        access: if op.text == "." {
                            MemberAccessKind::Dot
                        } else {
                            MemberAccessKind::Bang
                        },
                    };
                }
                continue;
            }
            if op.text == "(" {
                if 12 < min {
                    break;
                }
                self.at += 1;
                let open = self.at - 1;
                let mut depth = 0i32;
                let mut close = None;
                for (j, t) in self.ts.iter().enumerate().skip(self.at) {
                    match t.text.as_str() {
                        "(" => depth += 1,
                        ")" if depth == 0 => {
                            close = Some(j);
                            break;
                        }
                        ")" => depth -= 1,
                        _ => {}
                    }
                }
                let (end, args) = if let Some(j) = close {
                    let parts = split_top_level(&self.ts[open + 1..j], ",");
                    let args = if parts.len() == 1 && parts[0].is_empty() {
                        Vec::new()
                    } else {
                        parts
                            .into_iter()
                            .map(parse_argument)
                            .collect::<Option<Vec<_>>>()?
                    };
                    self.at = j + 1;
                    (self.ts[j].span, args)
                } else {
                    return None;
                };
                left = Expr::Call {
                    span: left.span().join(end),
                    callee: Box::new(left),
                    args,
                };
                continue;
            }
            let Some((prec, right_assoc)) = precedence(&op.text) else {
                break;
            };
            if prec < min {
                break;
            }
            self.at += 1;
            let right = self.expr(if right_assoc { prec } else { prec + 1 })?;
            let s = left.span().join(right.span());
            left = Expr::Binary {
                left: Box::new(left),
                op: op.text,
                right: Box::new(right),
                span: s,
            };
        }
        Some(left)
    }

    fn type_expression(&mut self) -> Option<(String, Span)> {
        let first = self.ts.get(self.at)?.clone();
        if first.kind != TokenKind::Identifier || first.bracket_delimited {
            return None;
        }
        self.at += 1;
        let mut name = first.text;
        let mut span = first.span;
        while self.ts.get(self.at).is_some_and(|token| token.text == ".") {
            self.at += 1;
            let member = self.ts.get(self.at)?.clone();
            if member.kind != TokenKind::Identifier || member.bracket_delimited {
                return None;
            }
            self.at += 1;
            name.push('.');
            name.push_str(&member.text);
            span = span.join(member.span);
        }
        Some((name, span))
    }
}
fn precedence(op: &str) -> Option<(u8, bool)> {
    let x = op.to_ascii_lowercase();
    Some(match x.as_str() {
        "imp" => (1, false),
        "eqv" => (2, false),
        "xor" => (3, false),
        "or" => (4, false),
        "and" => (5, false),
        "=" | "<>" | "<" | ">" | "<=" | ">=" | "is" | "like" => (6, false),
        "&" => (7, false),
        "+" | "-" => (8, false),
        "mod" | "\\" => (9, false),
        "*" | "/" => (10, false),
        "^" => (11, true),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn uses_vb_name_attribute_as_the_module_name() {
        let module = parse_module(
            "Filename",
            "Filename.bas",
            "Attribute VB_Name = \"ActualModule\"\nPublic Sub Run()\nEnd Sub\n",
            10_000,
            100,
        );
        assert_eq!(module.name, "ActualModule");
    }
    #[test]
    fn parses_procedures_control_blocks_and_types() {
        let src = "Option Explicit\nPrivate limit As Long\nPublic Function Check(ByVal amount As Currency, Optional ok As Boolean = False) As Boolean\n If amount >= limit Then\n Check = ok\n Else\n Check = False\n End If\nEnd Function\n";
        let m = parse_module("M", "M.bas", src, 10000, 100);
        assert_eq!(m.procedures.len(), 1);
        assert_eq!(m.procedures[0].parameters.len(), 2);
        assert_eq!(m.procedures[0].statements[0].kind, "if");
        assert_eq!(m.declarations[0].name, "limit");
    }

    #[test]
    fn validates_enum_nonempty_and_member_name_uniqueness() {
        let valid = parse_module(
            "ValidEnum",
            "ValidEnum.bas",
            "Public Enum Color\nRed = 0\nGreen = 1\nEnd Enum\n",
            10_000,
            100,
        );
        assert!(
            !valid
                .diagnostics
                .iter()
                .any(|diagnostic| matches!(diagnostic.code, "VBA1041" | "VBA1042")),
            "{:?}",
            valid.diagnostics
        );

        let empty = parse_module(
            "EmptyEnum",
            "EmptyEnum.bas",
            "Public Enum Color\nEnd Enum\n",
            10_000,
            100,
        );
        assert_eq!(
            empty
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "VBA1041")
                .count(),
            1,
            "{:?}",
            empty.diagnostics
        );

        let duplicate = parse_module(
            "DuplicateEnum",
            "DuplicateEnum.bas",
            "Public Enum Color\nRed = 0\nred = 1\nEnd Enum\n",
            10_000,
            100,
        );
        assert_eq!(
            duplicate
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "VBA1042")
                .count(),
            1,
            "{:?}",
            duplicate.diagnostics
        );
    }

    #[test]
    fn terminal_keywords_require_exact_unbracketed_tokens() {
        let source = "Public Sub Main()\nStopwatch = 1\nEndDate = Stopwatch\n[Stop] = EndDate\n[End] = [Stop]\nStop\nEnd\nEnd Sub\n";
        let module = parse_module("M", "M.bas", source, 10_000, 100);
        let statements = &module.procedures[0].statements;
        assert_eq!(
            statements
                .iter()
                .map(|statement| statement.kind.as_str())
                .collect::<Vec<_>>(),
            [
                "assignment",
                "assignment",
                "assignment",
                "assignment",
                "stop",
                "end_statement"
            ]
        );
        assert!(module.diagnostics.is_empty(), "{:?}", module.diagnostics);
    }

    #[test]
    fn resume_keyword_does_not_capture_prefixed_names_or_bracket_expressions() {
        let source = "Public Sub Main()\nResumeCount = 1\n[Resume] = ResumeCount\nResume Next\nRetryLabel:\nResume RetryLabel\nResume 0\nEnd Sub\n";
        let module = parse_module("M", "M.bas", source, 10_000, 100);
        let statements = &module.procedures[0].statements;
        assert_eq!(
            statements
                .iter()
                .map(|statement| statement.kind.as_str())
                .collect::<Vec<_>>(),
            [
                "assignment",
                "assignment",
                "resume",
                "label",
                "resume",
                "resume"
            ]
        );
        assert!(module.diagnostics.is_empty(), "{:?}", module.diagnostics);
    }

    #[test]
    fn loop_and_statement_keywords_respect_token_boundaries_and_brackets() {
        let source = "Public Sub Main()\n[With] = 1\n[Call] = 2\n[DefBool] = 3\nFor EachItem = 1 To 2\n[With] = EachItem\nNext EachItem\nFor Each item In values\n[DefBool] = item\nNext item\nEnd Sub\n";
        let module = parse_module("M", "M.bas", source, 10_000, 100);
        let statements = &module.procedures[0].statements;
        assert_eq!(
            statements
                .iter()
                .map(|statement| statement.kind.as_str())
                .collect::<Vec<_>>(),
            ["assignment", "assignment", "assignment", "for", "for_each"]
        );
        assert_eq!(
            statements[3].loop_control_variable.as_deref(),
            Some("EachItem")
        );
        assert_eq!(statements[4].loop_control_variable.as_deref(), Some("item"));
        assert!(module.diagnostics.is_empty(), "{:?}", module.diagnostics);
    }

    #[test]
    fn bracket_expressions_remain_unresolved_but_bang_keys_are_members() {
        assert!(matches!(
            parse_expression_source("[A1]"),
            Some(Expr::Unknown(text, _)) if text == "[A1]"
        ));
        assert!(matches!(
            parse_expression_source("sheet.[A1]"),
            Some(Expr::Unknown(text, _)) if text == "host bracket expression"
        ));
        assert!(matches!(
            parse_expression_source(".[A1]"),
            Some(Expr::Unknown(text, _)) if text == "host bracket expression"
        ));
        assert!(matches!(
            parse_expression_source("records![Order Form]"),
            Some(Expr::Member { access: MemberAccessKind::Bang, member, .. }) if member == "Order Form"
        ));
    }

    #[test]
    fn clause_boundaries_ignore_prefixed_bracketed_and_member_names() {
        let source = "Public Sub Main()\nIf [Then] = 1 Then\nElsewhere = [Then]\nElse\nEndValue = 0\nEnd If\nIf obj.Then = True Then\nobj.Else = 4\nEnd If\nIf flag Then [Else] = 2 Else EndValue = 3\nIf flag Then obj.Else = 5 Else EndValue = 6\nFor Each item In collection.In\nitem = 1\nNext item\nFor index = 0 To object.To\nEndValue = index\nNext index\nEnd Sub\n";
        let module = parse_module("M", "M.bas", source, 10_000, 100);
        let statements = &module.procedures[0].statements;
        assert_eq!(
            statements
                .iter()
                .map(|statement| statement.kind.as_str())
                .collect::<Vec<_>>(),
            ["if", "if", "if", "if", "for_each", "for"]
        );
        assert_eq!(statements[0].children[0].children[0].kind, "assignment");
        assert_eq!(statements[0].children[1].kind, "else_branch");
        assert_eq!(statements[0].children[1].children[0].kind, "assignment");
        assert_eq!(statements[1].children[0].children[0].kind, "assignment");
        assert!(matches!(
            statements[1].parsed_expression.as_ref(),
            Some(Expr::Binary { left, op, .. })
                if op == "=" && matches!(left.as_ref(), Expr::Member { member, .. } if member == "Then")
        ));
        assert!(matches!(
            statements[1].children[0].children[0].parsed_target.as_ref(),
            Some(Expr::Member { member, .. }) if member == "Else"
        ));
        assert_eq!(statements[2].children[0].children[0].kind, "assignment");
        assert_eq!(statements[2].children[1].children[0].kind, "assignment");
        assert_eq!(statements[3].children[0].children[0].kind, "assignment");
        assert_eq!(statements[3].children[1].children[0].kind, "assignment");
        assert!(matches!(
            statements[4].parsed_expression.as_ref(),
            Some(Expr::Member { object, member, .. })
                if member == "In" && matches!(object.as_ref(), Expr::Identifier(name, _) if name == "collection")
        ));
        assert_eq!(statements[5].loop_end.as_deref(), Some("object.To"));
        assert!(module.diagnostics.is_empty(), "{:?}", module.diagnostics);
    }

    #[test]
    fn parses_select_case_value_range_and_comparison_alternatives() {
        let source = "Public Sub Choose(ByVal value As Long)\nSelect Case value\nCase 1, 2 To 4, Is >= 5, Is <> 0\nresult = True\nCase 1 To\nresult = False\nEnd Select\nEnd Sub\n";
        let module = parse_module("M", "M.bas", source, 10_000, 100);
        let select_case = &module.procedures[0].statements[0];
        let ranges = &select_case.children[0].case_ranges;
        assert_eq!(ranges.len(), 4);
        assert_eq!(ranges[0].kind, "value");
        assert_eq!(ranges[0].expression.as_deref(), Some("1"));
        assert!(ranges[0].valid);
        assert_eq!(ranges[1].kind, "range");
        assert_eq!(ranges[1].start_value.as_deref(), Some("2"));
        assert_eq!(ranges[1].end_value.as_deref(), Some("4"));
        assert!(ranges[1].valid);
        assert_eq!(ranges[2].kind, "comparison");
        assert_eq!(ranges[2].comparison_operator.as_deref(), Some(">="));
        assert_eq!(ranges[2].expression.as_deref(), Some("5"));
        assert!(ranges[2].valid);
        assert_eq!(ranges[3].comparison_operator.as_deref(), Some("<>"));
        assert_eq!(ranges[3].expression.as_deref(), Some("0"));
        assert!(ranges[3].valid);

        let malformed = &select_case.children[1].case_ranges;
        assert_eq!(malformed.len(), 1);
        assert_eq!(malformed[0].kind, "unresolved");
        assert!(!malformed[0].valid);
        assert_eq!(
            module
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "VBA1025")
                .count(),
            1
        );
    }

    #[test]
    fn retains_for_each_control_and_next_variables() {
        let (next_tokens, _) = lex("Next item, outer", 32);
        assert_eq!(
            top_level_delimiter_index(&next_tokens[1..], ","),
            Some(1),
            "{next_tokens:#?}"
        );
        let module = parse_module(
            "M",
            "M.bas",
            "Public Sub Walk()\nDim values(1 To 3) As Long\nDim item As Variant\nFor Each item In values\nDebug.Print item\nNext item\nEnd Sub\n",
            10_000,
            100,
        );
        let loop_statement = &module.procedures[0].statements[2];
        assert_eq!(loop_statement.kind, "for_each");
        assert_eq!(
            loop_statement.loop_control_variable.as_deref(),
            Some("item")
        );
        assert_eq!(
            loop_statement.next_control_variable.as_deref(),
            Some("item")
        );
        assert!(matches!(
            loop_statement.parsed_expression.as_ref(),
            Some(Expr::Identifier(name, _)) if name == "values"
        ));

        let counted = parse_module(
            "Counted",
            "Counted.bas",
            "Public Sub Count()\nDim counter As Long\nFor counter = 1 To 3\nDebug.Print counter\nNext counter\nFor counter = 3 To 1 Step -1\nNext counter\nEnd Sub\n",
            10_000,
            100,
        );
        let for_statement = &counted.procedures[0].statements[1];
        assert_eq!(for_statement.kind, "for");
        assert_eq!(
            for_statement.loop_control_variable.as_deref(),
            Some("counter")
        );
        assert_eq!(
            for_statement.next_control_variable.as_deref(),
            Some("counter")
        );
        assert_eq!(for_statement.loop_start.as_deref(), Some("1"));
        assert_eq!(for_statement.loop_end.as_deref(), Some("3"));
        assert!(for_statement.loop_step.is_none());
        let stepped_loop = &counted.procedures[0].statements[2];
        assert_eq!(stepped_loop.loop_step.as_deref(), Some("- 1"));

        let nested = parse_module(
            "Nested",
            "Nested.bas",
            "Public Sub Count()\nDim values(1 To 2) As Long\nDim outer As Long\nDim item As Variant\nFor outer = 1 To 2\nFor Each item In values\nDebug.Print item\nNext item, outer\nEnd Sub\n",
            10_000,
            100,
        );
        let outer_loop = &nested.procedures[0].statements[3];
        let inner_loop = &outer_loop.children[0];
        assert_eq!(
            outer_loop.next_control_variable.as_deref(),
            Some("outer"),
            "{nested:#?}"
        );
        assert_eq!(inner_loop.next_control_variable.as_deref(), Some("item"));
        assert!(
            !nested
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "VBA1023")
        );

        let malformed = parse_module(
            "Bad",
            "Bad.bas",
            "Public Sub Walk()\nFor Each item values\nNext item\nEnd Sub\n",
            10_000,
            100,
        );
        assert!(
            malformed
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "VBA1026")
        );
    }

    #[test]
    fn parses_parenthesized_and_named_arguments_as_expression_nodes() {
        let src = "Public Sub S()\nMsgBox Prompt:=\"hello\", Buttons:=vbOKOnly\nEnd Sub\n";
        let m = parse_module("M", "M.bas", src, 10000, 100);
        let call = m.procedures[0].statements[0]
            .parsed_expression
            .as_ref()
            .unwrap();
        let Expr::Call { args, .. } = call else {
            panic!("expected a call expression")
        };
        assert_eq!(args.len(), 2);
        assert!(matches!(args[0], Expr::NamedArgument { .. }));
    }
    #[test]
    fn explicit_call_keyword_requires_parenthesized_arguments() {
        let source = "Public Sub S(ByVal box As Box)\nCall Save(1)\nWith box\nCall .Save(2)\nCall .Save 3\nEnd With\nIf True Then Call Save 4\nEnd Sub\n";
        let module = parse_module("M", "M.bas", source, 10_000, 100);
        let procedure = &module.procedures[0];
        let direct = procedure.statements[0].parsed_expression.as_ref().unwrap();
        assert!(matches!(direct, Expr::Call { args, .. } if args.len() == 1));
        let with = &procedure.statements[1];
        let parenthesized = with.children[0].parsed_expression.as_ref().unwrap();
        assert!(matches!(parenthesized, Expr::Call { args, .. } if args.len() == 1));
        let unparenthesized = with.children[1].parsed_expression.as_ref().unwrap();
        assert!(
            matches!(unparenthesized, Expr::Call { args, .. } if args.is_empty()),
            "{unparenthesized:?}"
        );
        assert_eq!(
            module
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "VBA1040")
                .count(),
            2
        );
    }
    #[test]
    fn binds_omitted_with_member_method_calls_and_nested_bases() {
        let src = "Public Sub S(ByVal box As Box)\nWith box\n.Save 1\nWith .Child\n.Refresh 2\nEnd With\nEnd With\nEnd Sub\n";
        let m = parse_module("M", "M.bas", src, 10000, 100);
        assert!(m.diagnostics.is_empty(), "{:?}", m.diagnostics);
        let outer = &m.procedures[0].statements[0];
        let save = &outer.children[0].parsed_expression;
        let Some(Expr::Call { callee, args, .. }) = save.as_ref() else {
            panic!("expected .Save to parse as a call")
        };
        assert!(
            matches!(callee.as_ref(), Expr::Member { object, member, .. } if matches!(object.as_ref(), Expr::Identifier(name, _) if name == "box") && member == "Save")
        );
        assert_eq!(args.len(), 1);
        let nested = &outer.children[1];
        assert!(
            matches!(nested.parsed_expression.as_ref(), Some(Expr::Member { object, member, .. }) if matches!(object.as_ref(), Expr::Identifier(name, _) if name == "box") && member == "Child")
        );
        let refresh = &nested.children[0].parsed_expression;
        let Some(Expr::Call { callee, args, .. }) = refresh.as_ref() else {
            panic!("expected nested .Refresh to parse as a call")
        };
        assert!(
            matches!(callee.as_ref(), Expr::Member { object, member, .. } if matches!(object.as_ref(), Expr::Member { object, member, .. } if matches!(object.as_ref(), Expr::Identifier(name, _) if name == "box") && member == "Child") && member == "Refresh")
        );
        assert_eq!(args.len(), 1);
    }
    #[test]
    fn parses_case_insensitive_not_as_an_unary_operator() {
        let src = "Public Function F(ByVal x As Long) As Boolean\nIf not x = 0 Then\nF = True\nEnd If\nEnd Function\n";
        let m = parse_module("M", "M.bas", src, 10000, 100);
        let condition = m.procedures[0].statements[0]
            .parsed_expression
            .as_ref()
            .unwrap();
        assert!(
            matches!(condition,Expr::Unary{op,value,..} if op.eq_ignore_ascii_case("not") && matches!(value.as_ref(), Expr::Binary{op,..} if op == "="))
        );
    }

    #[test]
    fn parses_typeof_is_as_a_boolean_type_test_with_qualified_type_operand() {
        let expression = parse_expression_source("TypeOf widget Is Excel.Range").unwrap();
        let Expr::TypeOfIs {
            expression: object,
            type_name,
            ..
        } = expression
        else {
            panic!("expected a TypeOf...Is expression")
        };
        assert!(matches!(object.as_ref(), Expr::Identifier(name, _) if name == "widget"));
        assert_eq!(type_name, "Excel.Range");

        let negated = parse_expression_source("Not TypeOf widget Is Excel.Range").unwrap();
        assert!(matches!(
            negated,
            Expr::Unary { op, value, .. }
                if op.eq_ignore_ascii_case("not")
                    && matches!(value.as_ref(), Expr::TypeOfIs { .. })
        ));
    }

    #[test]
    fn rejects_expressions_with_trailing_or_unbalanced_tokens() {
        let valid = parse_expression_source("amount + 1").unwrap();
        assert!(matches!(valid, Expr::Binary { .. }));
        assert!(matches!(
            parse_expression_source("amount!").unwrap(),
            Expr::Identifier(name, _) if name == "amount!"
        ));
        assert!(matches!(
            parse_expression_source("records!Customer").unwrap(),
            Expr::Member { access: MemberAccessKind::Bang, member, .. } if member == "Customer"
        ));
        assert!(matches!(
            parse_expression_source("records![Order Form]").unwrap(),
            Expr::Member { access: MemberAccessKind::Bang, member, .. } if member == "Order Form"
        ));
        let (tokens, _) = lex("records![Order Form]", 32);
        let source_tokens = tokens
            .iter()
            .filter(|token| !matches!(token.kind, TokenKind::Newline | TokenKind::Eof))
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(render(&source_tokens), "records![Order Form]");
        assert!(matches!(
            parse_expression_source("records.Customer").unwrap(),
            Expr::Member { access: MemberAccessKind::Dot, member, .. } if member == "Customer"
        ));

        for source in [
            "amount + 1 trailing",
            "amount @ other",
            "(amount + 1",
            "amount + 1)",
            "object.",
            "object.!member",
            "CallTarget(",
        ] {
            assert!(
                parse_expression_source(source).is_none(),
                "partially accepted expression {source:?}"
            );
        }
    }

    #[test]
    fn parses_event_and_external_declaration_parameters() {
        let src = "Public Event Changed(ByVal value As Long, Optional note As String = \"\")\nPrivate Declare PtrSafe Function GetValue Lib \"native\" Alias \"get_value\" (ByVal key As Long, Optional flags As Long = 0) As Long\n";
        let m = parse_module("M", "M.cls", src, 10000, 100);
        let event = m.declarations.iter().find(|d| d.kind == "event").unwrap();
        let external = m
            .declarations
            .iter()
            .find(|d| d.kind == "external_declare")
            .unwrap();
        assert_eq!(event.parameters.len(), 2);
        assert!(event.parameters[1].optional);
        assert_eq!(event.parameters[0].type_name.as_deref(), Some("Long"));
        assert_eq!(external.parameters.len(), 2);
        assert_eq!(external.parameters[0].passing, "ByVal");
        assert!(external.parameters[1].optional);
        assert!(external.is_ptr_safe);
        assert_eq!(external.external_library.as_deref(), Some("native"));
        assert_eq!(external.external_alias.as_deref(), Some("get_value"));
    }
    #[test]
    fn retains_automation_member_ids_for_default_members_and_enumerators() {
        let source = "Attribute VB_PredeclaredId = True\nAttribute VB_GlobalNameSpace = False\nPublic Property Get Item(ByVal index As Long) As String\nEnd Property\nAttribute Item.VB_UserMemId = 0\nPublic Property Let Item(ByVal index As Long, ByVal value As String)\nEnd Property\nAttribute Item.VB_UserMemId = 0\nPublic Function NewEnum() As IUnknown\nEnd Function\nAttribute NewEnum.VB_UserMemId = -4\n";
        let module = parse_module("Collection", "Collection.cls", source, 10_000, 100);
        assert_eq!(module.predeclared_id, Some(true));
        assert_eq!(module.global_namespace, Some(false));
        assert_eq!(module.procedures.len(), 3);
        assert!(
            module.procedures[..2]
                .iter()
                .all(|procedure| procedure.automation_member_id == Some(0))
        );
        assert_eq!(module.procedures[2].automation_member_id, Some(-4));
    }
    #[test]
    fn retains_each_elseif_and_else_branch_body() {
        let src = "Public Sub Choose(ByVal x As Long)\nIf x = 1 Then\na = 1\nElseIf x = 2 Then\na = 2\nElse\na = 3\nEnd If\nEnd Sub\n";
        let m = parse_module("M", "M.bas", src, 10000, 100);
        let branches = &m.procedures[0].statements[0].children;
        assert_eq!(branches.len(), 3);
        assert_eq!(branches[0].children[0].expression.as_deref(), Some("a = 1"));
        assert_eq!(branches[1].kind, "elseif_branch");
        assert_eq!(branches[1].children[0].expression.as_deref(), Some("a = 2"));
        assert_eq!(branches[2].kind, "else_branch");
        assert_eq!(branches[2].children[0].expression.as_deref(), Some("a = 3"));
    }
    #[test]
    fn preserves_array_parameter_shape_and_passing_modifiers() {
        let m = parse_module(
            "M",
            "M.bas",
            "Public Sub Take(ByVal values() As Long, ParamArray rest() As Variant)\nEnd Sub\n",
            10000,
            100,
        );
        let params = &m.procedures[0].parameters;
        assert!(params[0].is_array);
        assert!(params[0].passing_explicit);
        assert!(!params[0].is_param_array);
        assert!(params[1].is_array);
        assert!(params[1].is_param_array);
        assert!(!params[1].passing_explicit);
    }
    #[test]
    fn retains_implements_declarations() {
        let module = parse_module(
            "Widget",
            "Widget.cls",
            "Implements ICounter\nPrivate Function ICounter_Value() As Long\nICounter_Value = 1\nEnd Function\n",
            10000,
            100,
        );
        assert_eq!(module.implemented_interfaces, ["ICounter"]);
        assert_eq!(module.procedures[0].name, "ICounter_Value");
    }

    #[test]
    fn parses_array_declaration_dimensions_and_distinguishes_dynamic_arrays() {
        let module = parse_module(
            "M",
            "M.bas",
            "Public values(5) As Long\nPublic bounds(1 To 5, 0 To 2) As Long\nPublic dynamic_values() As Variant\nPublic Sub Run()\nDim local_values(5) As Long\nDim local_bounds(1 To 5, 0 To 2) As Long\nDim local_dynamic() As Variant\nEnd Sub\n",
            10_000,
            100,
        );

        let values = module
            .declarations
            .iter()
            .find(|declaration| declaration.name == "values")
            .unwrap();
        assert!(values.is_array);
        assert_eq!(values.array_dimensions.len(), 1);
        assert_eq!(values.array_dimensions[0].lower_bound, None);
        assert_eq!(values.array_dimensions[0].upper_bound.as_deref(), Some("5"));

        let bounds = module
            .declarations
            .iter()
            .find(|declaration| declaration.name == "bounds")
            .unwrap();
        assert_eq!(
            bounds.array_dimensions,
            [
                crate::model::ArrayDimension {
                    lower_bound: Some("1".into()),
                    upper_bound: Some("5".into()),
                },
                crate::model::ArrayDimension {
                    lower_bound: Some("0".into()),
                    upper_bound: Some("2".into()),
                },
            ]
        );

        let dynamic = module
            .declarations
            .iter()
            .find(|declaration| declaration.name == "dynamic_values")
            .unwrap();
        assert!(dynamic.is_array);
        assert!(dynamic.array_dimensions.is_empty());

        let local_declarations = &module.procedures[0].statements;
        let local_values = local_declarations
            .iter()
            .flat_map(|statement| &statement.children)
            .find(|statement| {
                statement
                    .declaration
                    .as_ref()
                    .is_some_and(|declaration| declaration.name == "local_values")
            })
            .unwrap()
            .declaration
            .as_ref()
            .unwrap();
        assert!(local_values.is_array);
        assert_eq!(
            local_values.array_dimensions[0].upper_bound.as_deref(),
            Some("5")
        );

        let local_dynamic = local_declarations
            .iter()
            .flat_map(|statement| &statement.children)
            .find(|statement| {
                statement
                    .declaration
                    .as_ref()
                    .is_some_and(|declaration| declaration.name == "local_dynamic")
            })
            .unwrap()
            .declaration
            .as_ref()
            .unwrap();
        assert!(local_dynamic.is_array);
        assert!(local_dynamic.array_dimensions.is_empty());
    }

    #[test]
    fn parses_array_dimensions_in_user_defined_type_fields() {
        let module = parse_module(
            "M",
            "M.bas",
            "Public Type Record\nvalue(1 To 4) As Integer\nmatrix(0 To 2, 1 To 3) As Long\nEnd Type\n",
            10_000,
            100,
        );
        let value = module
            .declarations
            .iter()
            .find(|declaration| declaration.name == "value")
            .unwrap();
        assert_eq!(value.kind, "field");
        assert_eq!(value.array_dimensions[0].lower_bound.as_deref(), Some("1"));
        assert_eq!(value.array_dimensions[0].upper_bound.as_deref(), Some("4"));

        let matrix = module
            .declarations
            .iter()
            .find(|declaration| declaration.name == "matrix")
            .unwrap();
        assert_eq!(matrix.array_dimensions.len(), 2);
        assert_eq!(matrix.array_dimensions[1].lower_bound.as_deref(), Some("1"));
        assert_eq!(matrix.array_dimensions[1].upper_bound.as_deref(), Some("3"));
    }

    #[test]
    fn diagnoses_missing_duplicate_and_empty_udt_members() {
        let module = parse_module(
            "Records",
            "Records.bas",
            "Private Type InvalidRecord\nmissingType\ncode As Long\nCode As Currency\nEnd Type\nPrivate Type EmptyRecord\nEnd Type\n",
            1024,
            32,
        );
        assert_eq!(
            module
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "VBA1031")
                .count(),
            1
        );
        assert_eq!(
            module
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "VBA1032")
                .count(),
            1
        );
        assert_eq!(
            module
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "VBA1033")
                .count(),
            1
        );
        let missing = module
            .declarations
            .iter()
            .find(|declaration| declaration.name == "missingType")
            .unwrap();
        assert_eq!(missing.type_name, None);
    }

    #[test]
    fn retains_redim_and_redim_preserve_array_bounds() {
        let module = parse_module(
            "M",
            "M.bas",
            "Public Sub Resize()\nDim values() As Long\nReDim values(UPPER_BOUND), matrix(1 To ROW_LIMIT, 0 To COLUMN_LIMIT)\nReDim Preserve values(0 To NEW_UPPER_BOUND)\nEnd Sub\n",
            10_000,
            100,
        );
        let statements = &module.procedures[0].statements;
        let redim = statements
            .iter()
            .find(|statement| statement.kind == "redim")
            .unwrap();
        assert_eq!(redim.children.len(), 2);
        let values = redim.children[0].declaration.as_ref().unwrap();
        assert_eq!(values.name, "values");
        assert_eq!(values.kind, "redim");
        assert_eq!(
            values.array_dimensions[0].upper_bound.as_deref(),
            Some("UPPER_BOUND")
        );
        let matrix = redim.children[1].declaration.as_ref().unwrap();
        assert_eq!(matrix.array_dimensions.len(), 2);
        assert_eq!(matrix.array_dimensions[0].lower_bound.as_deref(), Some("1"));
        assert_eq!(
            matrix.array_dimensions[1].upper_bound.as_deref(),
            Some("COLUMN_LIMIT")
        );

        let preserve = statements
            .iter()
            .filter(|statement| statement.kind == "redim")
            .nth(1)
            .unwrap();
        let preserved_values = preserve.children[0].declaration.as_ref().unwrap();
        assert_eq!(preserved_values.kind, "redim_preserve");
        assert_eq!(
            preserved_values.array_dimensions[0].upper_bound.as_deref(),
            Some("NEW_UPPER_BOUND")
        );
    }

    #[test]
    fn retains_redim_bounds_inside_single_line_if_statements() {
        let module = parse_module(
            "M",
            "M.bas",
            "Public Sub Resize(ByVal ready As Boolean)\nDim values() As Long\nIf ready Then ReDim Preserve values(0 To NEXT_UPPER)\nEnd Sub\n",
            10_000,
            100,
        );
        let redim = &module.procedures[0].statements[1].children[0].children[0];
        assert_eq!(redim.kind, "redim");
        let declaration = redim.children[0].declaration.as_ref().unwrap();
        assert_eq!(declaration.kind, "redim_preserve");
        assert_eq!(
            declaration.array_dimensions[0].upper_bound.as_deref(),
            Some("NEXT_UPPER")
        );
    }

    #[test]
    fn retains_each_erase_target() {
        let module = parse_module(
            "M",
            "M.bas",
            "Public Sub Clear()\nDim values() As Long\nErase values, cache\nEnd Sub\n",
            10_000,
            100,
        );
        let erase = module.procedures[0]
            .statements
            .iter()
            .find(|statement| statement.kind == "erase")
            .unwrap();
        assert_eq!(erase.children.len(), 2);
        assert_eq!(erase.children[0].kind, "erase_target");
        assert_eq!(erase.children[0].expression.as_deref(), Some("values"));
        assert_eq!(erase.children[1].expression.as_deref(), Some("cache"));
    }

    #[test]
    fn parses_on_goto_and_on_gosub_destination_lists_and_spaced_jump_keywords() {
        let module = parse_module(
            "M",
            "M.bas",
            "Public Sub Choose(ByVal index As Integer)\nOn index GoTo FirstLabel, 200\nOn index GoSub SecondLabel, 200\nGo To Finish\nGo Sub SecondLabel\nFirstLabel:\nExit Sub\nSecondLabel:\nReturn\n200 Return\nFinish:\nEnd Sub\n",
            10_000,
            100,
        );
        let statements = &module.procedures[0].statements;
        let on_goto = statements
            .iter()
            .find(|statement| statement.kind == "on_goto")
            .unwrap();
        assert_eq!(on_goto.expression.as_deref(), Some("index"));
        assert_eq!(
            on_goto
                .children
                .iter()
                .map(|child| child.expression.as_deref().unwrap())
                .collect::<Vec<_>>(),
            ["FirstLabel", "200"]
        );
        let on_gosub = statements
            .iter()
            .find(|statement| statement.kind == "on_gosub")
            .unwrap();
        assert_eq!(on_gosub.expression.as_deref(), Some("index"));
        assert_eq!(on_gosub.children.len(), 2);
        assert!(statements.iter().any(|statement| {
            statement.kind == "goto"
                && statement
                    .children
                    .first()
                    .is_some_and(|target| target.expression.as_deref() == Some("Finish"))
        }));
        assert!(statements.iter().any(|statement| {
            statement.kind == "gosub"
                && statement
                    .children
                    .first()
                    .is_some_and(|target| target.expression.as_deref() == Some("SecondLabel"))
        }));
        assert!(
            !module
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "VBA1013")
        );
    }

    #[test]
    fn diagnoses_case_else_that_is_not_unique_and_final() {
        let module = parse_module(
            "M",
            "M.bas",
            "Public Sub Choose()\nSelect Case value\nCase Else\na = 0\nCase 1\na = 1\nCase Else\na = 2\nEnd Select\nEnd Sub\n",
            10_000,
            100,
        );
        assert_eq!(
            module
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "VBA1024")
                .count(),
            2,
            "{:?}",
            module.diagnostics
        );
    }
}
