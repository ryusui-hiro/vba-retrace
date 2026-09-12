use crate::lexer::{Token, TokenKind, lex};
use crate::model::{
    Declaration, Diagnostic, Expr, Module, Parameter, Procedure, Severity, Span, Statement,
};

pub fn parse_module(
    name: &str,
    source_name: &str,
    text: &str,
    max_tokens: usize,
    max_nesting: usize,
) -> Module {
    let (tokens, lex_errors) = lex(text, max_tokens);
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
        name: name.to_owned(),
        source_name: source_name.to_owned(),
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
    module.diagnostics = parser.diagnostics;
    module
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
                || low.starts_with("else ")
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
                let stmt = parse_simple(&line);
                if stmt.kind == "on_error" {
                    self.error("VBA1011", stmt.span, "On Error changes control-flow semantics; handler behavior remains unresolved".into());
                }
                if stmt.kind == "conditional_compilation" {
                    self.error("VBA1012", stmt.span, "conditional compilation is not evaluated; conditional branches may differ by host".into());
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
                if let Some(ds) = parse_declaration_line(&line, "procedure") {
                    let mut dstmt = stmt;
                    dstmt.kind = "declaration".into();
                    dstmt.children = ds
                        .into_iter()
                        .map(|d| Statement {
                            kind: "declared_name".into(),
                            expression: Some(d.name.clone()),
                            span: d.span,
                            declaration: Some(d),
                            ..Statement::default()
                        })
                        .collect();
                    out.push(dstmt);
                } else {
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
            .position(|t| t.text.eq_ignore_ascii_case("then"))
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
                    .position(|t| t.text.eq_ignore_ascii_case("then"))
                    .unwrap_or(branch.len());
                let expr = render(&branch[1..tp]);
                self.at += 1;
                let (body, _) = self.parse_block(depth, None);
                stmt.children.push(Statement {
                    kind: "elseif_branch".into(),
                    expression: Some(expr),
                    span: branch_span,
                    children: body,
                    ..Statement::default()
                });
            }
        }
        if self.at < self.lines.len() && lower_line(&self.lines[self.at]).starts_with("else") {
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
                let case_expr = render(&line[1..]);
                self.at += 1;
                let (body, _) = self.parse_block(depth, None);
                stmt.children.push(Statement {
                    kind: "case".into(),
                    expression: Some(case_expr),
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
        let kind = if low.starts_with("for each") {
            "for_each"
        } else if low.starts_with("for ") {
            "for"
        } else if low.starts_with("do while ") || low.starts_with("do until ") {
            "do_pre"
        } else if low == "do" {
            "do"
        } else if low.starts_with("while ") {
            "while"
        } else if low.starts_with("with ") {
            "with"
        } else {
            "loop"
        };
        let mut stmt = Statement {
            kind: kind.into(),
            expression: Some(render(&first)),
            span: line_span(&first),
            ..Statement::default()
        };
        self.at += 1;
        let (body, _) = self.parse_block(depth, None);
        stmt.children = body;
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
                if kind == "do" && e.starts_with("loop ") {
                    stmt.exit_condition = Some(render(&end[1..]));
                }
                self.at += 1;
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
                "public" | "private" | "friend"
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
        self.at += 1;
        while self.at < self.lines.len() {
            let line = self.lines[self.at].clone();
            let low = lower_line(&line);
            if low == format!("end {end_kind}") {
                decls[0].span = decls[0].span.join(line_span(&line));
                self.at += 1;
                return (decls, diags);
            }
            if end_kind == "type" {
                let mut fields = parse_field_declarations(&line, &name);
                decls.append(&mut fields);
            } else if !line.is_empty() {
                let member = line[0].text.clone();
                let eq = line.iter().position(|t| t.text == "=");
                decls.push(Declaration {
                    name: member,
                    type_name: Some(name.clone()),
                    kind: "enum_member".into(),
                    visibility: "Public".into(),
                    span: line_span(&line),
                    initializer: eq.map(|x| render(&line[x + 1..])),
                });
            }
            self.at += 1;
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
                i += 1
            }
            "array" => i += 1,
            _ => break,
        }
    }
    let name = ts.get(i).map(|t| t.text.clone()).unwrap_or_default();
    i += usize::from(!name.is_empty());
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
            "withEvents" => {
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
        let type_name = as_i.map(|a| render(&part[a + 1..eq_i.unwrap_or(part.len())]));
        let initializer = eq_i.map(|e| render(&part[e + 1..]));
        out.push(Declaration {
            name,
            type_name,
            kind: kind.clone(),
            visibility: visibility.clone(),
            span: line_span(part),
            initializer,
        });
    }
    (!out.is_empty()).then_some(out)
}

fn is_aggregate_start(line: &[Token]) -> bool {
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
        let name = line.get(i + 1)?.text.clone();
        return Some(Declaration {
            name,
            kind: "event".into(),
            visibility,
            span: line_span(line),
            initializer: Some(render(line)),
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
    let as_i = line.iter().position(|t| t.text.eq_ignore_ascii_case("as"));
    let ty = as_i.map(|a| render(&line[a + 1..]));
    Some(Declaration {
        name,
        type_name: ty,
        kind: "external_declare".into(),
        visibility,
        span: line_span(line),
        initializer: Some(render(&line[start..])),
    })
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
        out.push(Declaration {
            name,
            type_name: as_i
                .map(|i| render(&part[i + 1..]))
                .or_else(|| Some("Variant".into())),
            kind: "field".into(),
            visibility: type_name.into(),
            span: line_span(part),
            ..Declaration::default()
        });
    }
    out
}

fn is_ignorable_header(line: &[Token]) -> bool {
    let x = lower_line(line);
    x.starts_with("option ")
        || x.starts_with("attribute ")
        || x.starts_with("implements ")
        || x.starts_with("#if ")
        || x.starts_with("#const ")
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
        || x.starts_with("with ")
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
    line.iter().any(|t| t.text.eq_ignore_ascii_case(word))
}
fn lower_line(line: &[Token]) -> String {
    render(line).to_ascii_lowercase()
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
        let tight = matches!(t.text.as_str(), ")" | "." | "," | ":" | "!" | "(")
            || matches!(prev, "." | "!" | "(");
        if !s.is_empty() && !tight {
            s.push(' ');
        }
        s.push_str(&if t.kind == TokenKind::String {
            format!("\"{}\"", t.text.replace('"', "\"\""))
        } else {
            t.text.clone()
        });
        prev = &t.text;
    }
    s
}

fn parse_simple(line: &[Token]) -> Statement {
    let span = line_span(line);
    let text = render(line);
    let low = text.to_ascii_lowercase();
    let kind = if low.starts_with("on error") {
        "on_error"
    } else if low.starts_with("#if") || low.starts_with("#else") || low.starts_with("#end if") {
        "conditional_compilation"
    } else if low.starts_with("exit ") {
        "exit"
    } else if low.starts_with("goto ") {
        "goto"
    } else if low.starts_with("gosub ") {
        "gosub"
    } else if low == "return" {
        "gosub_return"
    } else if low.starts_with("resume") {
        "resume"
    } else if low.starts_with("raiseevent ") {
        "raise_event"
    } else if low.starts_with("redim ") || low.starts_with("redim preserve ") {
        "redim"
    } else if low.starts_with("erase ") {
        "erase"
    } else if low.starts_with("stop") {
        "stop"
    } else if low.starts_with("end") {
        "end_statement"
    } else if low.starts_with("call ") {
        "call"
    } else if assignment_rhs(line).is_some() {
        "assignment"
    } else if low.ends_with(":") {
        "label"
    } else if low.starts_with("case ") {
        "case"
    } else if low.starts_with("debug.print") {
        "call"
    } else if line
        .first()
        .is_some_and(|t| matches!(t.kind, TokenKind::Identifier))
    {
        "call_or_expression"
    } else {
        "unknown"
    };
    let expression = if matches!(kind, "call" | "call_or_expression" | "raise_event") {
        parse_call_statement(line, kind)
    } else if kind == "assignment" {
        assignment_rhs(line).and_then(parse_expr_tokens)
    } else {
        parse_expr_tokens(line)
    };
    Statement {
        kind: kind.into(),
        expression: Some(text),
        parsed_expression: expression,
        span,
        ..Statement::default()
    }
}

fn find_top_level_else(ts: &[Token]) -> Option<usize> {
    let mut depth = 0i32;
    for (i, t) in ts.iter().enumerate() {
        match t.text.as_str() {
            "(" | "[" => depth += 1,
            ")" | "]" => depth -= 1,
            _ => {}
        }
        if depth == 0 && t.kind == TokenKind::Identifier && t.text.eq_ignore_ascii_case("else") {
            return Some(i);
        }
    }
    None
}
fn parse_simple_sequence(ts: &[Token]) -> Vec<Statement> {
    split_top_level(ts, ":")
        .into_iter()
        .filter(|part| !part.is_empty())
        .map(parse_simple)
        .collect()
}

fn parse_expr_tokens(ts: &[Token]) -> Option<Expr> {
    if ts.is_empty() {
        return None;
    }
    let mut p = ExprParser { ts, at: 0 };
    let e = p.expr(0)?;
    Some(e)
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

fn parse_call_statement(ts: &[Token], kind: &str) -> Option<Expr> {
    let mut start = usize::from(
        ts.first()
            .is_some_and(|t| t.text.eq_ignore_ascii_case("call")),
    );
    if kind == "raise_event" {
        start = 1;
    }
    if start >= ts.len() {
        return None;
    }
    let callee_start = start;
    let mut args_start = start + 1;
    while args_start + 1 < ts.len() && matches!(ts[args_start].text.as_str(), "." | "!") {
        args_start += 2;
    }
    if ts.get(args_start).is_some_and(|t| t.text == "(") {
        return parse_expr_tokens(&ts[callee_start..]);
    }
    let callee = parse_expr_tokens(&ts[callee_start..args_start])?;
    let args = if args_start < ts.len() {
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
        let unary = if tok.kind == TokenKind::Symbol && matches!(tok.text.as_str(), "+" | "-") {
            Some((tok.text.clone(), 11))
        } else if tok.kind == TokenKind::Identifier {
            match tok.text.to_ascii_lowercase().as_str() {
                "not" | "typeof" => Some((tok.text.clone(), 6)),
                "addressof" | "new" => Some((tok.text.clone(), 11)),
                _ => None,
            }
        } else {
            None
        };
        let mut left = if let Some((op, precedence)) = unary {
            let value = self.expr(precedence)?;
            Expr::Unary {
                op,
                span: tok.span.join(value.span()),
                value: Box::new(value),
            }
        } else {
            match tok.kind {
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
                            Expr::Group(Box::new(v), tok.span)
                        }
                    }
                    _ => Expr::Unknown(tok.text, tok.span),
                },
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
                let Some(m) = self.ts.get(self.at).cloned() else {
                    break;
                };
                self.at += 1;
                left = Expr::Member {
                    span: left.span().join(m.span),
                    object: Box::new(left),
                    member: m.text,
                };
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
                    return Some(Expr::Unknown("unterminated argument list".into(), op.span));
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
    fn parses_procedures_control_blocks_and_types() {
        let src = "Option Explicit\nPrivate limit As Long\nPublic Function Check(ByVal amount As Currency, Optional ok As Boolean = False) As Boolean\n If amount >= limit Then\n Check = ok\n Else\n Check = False\n End If\nEnd Function\n";
        let m = parse_module("M", "M.bas", src, 10000, 100);
        assert_eq!(m.procedures.len(), 1);
        assert_eq!(m.procedures[0].parameters.len(), 2);
        assert_eq!(m.procedures[0].statements[0].kind, "if");
        assert_eq!(m.declarations[0].name, "limit");
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
    fn parses_case_insensitive_not_as_an_unary_operator() {
        let src = "Public Function F(ByVal x As Long) As Boolean\nIf not x = 0 Then\nF = True\nEnd If\nEnd Function\n";
        let m = parse_module("M", "M.bas", src, 10000, 100);
        let condition = m.procedures[0].statements[0]
            .parsed_expression
            .as_ref()
            .unwrap();
        assert!(matches!(condition,Expr::Unary{op,..} if op.eq_ignore_ascii_case("not")));
    }
}
