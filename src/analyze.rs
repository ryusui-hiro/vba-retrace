use crate::flow::build_graph;
use crate::host::{HostProfile, excel};
use crate::lexer::{Token, TokenKind, lex};
use crate::model::*;
use crate::parser::parse_module;
use crate::preprocessor::{PreprocessOptions, preprocess};
use crate::typecheck::infer_assignment_types;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, Default)]
pub struct AnalysisOptions {
    pub limits: Limits,
    pub conditional_constants: std::collections::BTreeMap<String, String>,
    pub host_profile: HostProfile,
}

pub fn analyze(sources: &[SourceUnit], options: &AnalysisOptions) -> Result<Analysis, String> {
    if sources.is_empty() {
        return Err("at least one VBA source unit is required".into());
    }
    let mut project = Project {
        input_kind: "exported_vba_text".into(),
        ..Project::default()
    };
    let mut diagnostics = Vec::new();
    let mut names = HashSet::new();
    let mut option_explicit = Vec::new();
    let mut conditional_unknown = Vec::new();
    for source in sources {
        if source.text.len() > options.limits.max_input_bytes {
            return Err(format!(
                "source unit {} exceeds configured input limit",
                source.name
            ));
        }
        let base = source
            .name
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(&source.name);
        let name = base.rsplit_once('.').map(|x| x.0).unwrap_or(base);
        let preprocessed = preprocess(
            &source.name,
            &source.text,
            &PreprocessOptions {
                constants: options.conditional_constants.clone(),
            },
        );
        option_explicit.push(
            preprocessed
                .text
                .lines()
                .any(|l| l.trim().eq_ignore_ascii_case("Option Explicit")),
        );
        conditional_unknown.push(preprocessed.had_unknown_condition);
        let mut module = parse_module(
            name,
            &source.name,
            &preprocessed.text,
            options.limits.max_tokens,
            options.limits.max_nesting,
        );
        module.analysis_text = preprocessed.text;
        module.text = source.text.clone();
        module.diagnostics.extend(preprocessed.diagnostics);
        if !names.insert(canon(&module.name)) {
            diagnostics.push(Diagnostic {
                code: "VBA2001",
                severity: Severity::Error,
                message: format!("duplicate module name '{}'", module.name),
                source: source.name.clone(),
                span: Span::default(),
            });
        }
        diagnostics.append(&mut module.diagnostics);
        project.modules.push(module);
    }
    let mut procedure_index: HashMap<String, Vec<(usize, usize)>> = HashMap::new();
    for (mi, m) in project.modules.iter().enumerate() {
        for (pi, p) in m.procedures.iter().enumerate() {
            procedure_index
                .entry(canon(&p.name))
                .or_default()
                .push((mi, pi));
        }
    }
    for (module_index, m) in project.modules.iter().enumerate() {
        let mut seen = HashMap::<String, Span>::new();
        for p in &m.procedures {
            let mut procedure_labels = HashMap::new();
            validate_label_definitions(
                &p.statements,
                &mut procedure_labels,
                &mut diagnostics,
                &m.source_name,
            );
            let labels = procedure_labels.keys().cloned().collect::<HashSet<_>>();
            validate_jump_targets(&p.statements, &labels, &mut diagnostics, &m.source_name);
            let n = canon(&p.name);
            if let Some(previous) = seen.get(&n) {
                diagnostics.push(Diagnostic {
                    code: "VBA2002",
                    severity: if conditional_unknown[module_index]{Severity::Warning}else{Severity::Error},
                    message: if conditional_unknown[module_index]{format!("procedure '{}' may be duplicated across unresolved conditional-compilation branches (first declaration at line {})",p.name,previous.line)}else{format!("duplicate procedure '{}' (first declaration at line {})",p.name,previous.line)},
                    source: m.source_name.clone(),
                    span: p.span,
                });
            } else {
                seen.insert(n, p.span);
            }
        }
        for d in &m.declarations {
            if let Some(t) = &d.type_name {
                let base = t.trim().trim_end_matches("()");
                if !type_is_known(&project, base, options.host_profile) {
                    diagnostics.push(Diagnostic {
                        code: "VBA2003",
                        severity: Severity::Warning,
                        message: format!(
                            "type '{}' needs a project declaration or referenced type library",
                            base
                        ),
                        source: m.source_name.clone(),
                        span: d.span,
                    });
                }
            }
        }
        for p in &m.procedures {
            for t in p
                .parameters
                .iter()
                .filter_map(|a| a.type_name.as_deref())
                .chain(p.return_type.as_deref())
            {
                let base = t.trim().trim_start_matches("New ").trim_end_matches("()");
                if !type_is_known(&project, base, options.host_profile) {
                    diagnostics.push(Diagnostic {
                        code: "VBA2003",
                        severity: Severity::Warning,
                        message: format!(
                            "type '{}' needs a project declaration or referenced type library",
                            base
                        ),
                        source: m.source_name.clone(),
                        span: p.span,
                    });
                }
            }
        }
        project.metadata.insert(
            format!("module:{}:option_explicit", m.name),
            option_explicit[module_index].to_string(),
        );
        project.metadata.insert(
            format!("module:{}:conditional_compile_unknown", m.name),
            conditional_unknown[module_index].to_string(),
        );
    }
    let facts = collect_facts(
        &project,
        &procedure_index,
        &mut diagnostics,
        &options.limits,
        options.host_profile,
    );
    let control_flow = project
        .modules
        .iter()
        .flat_map(|m| {
            m.procedures.iter().map(|p| {
                let mut graph = build_graph(m, p);
                if project
                    .metadata
                    .get(&format!("module:{}:conditional_compile_unknown", m.name))
                    .is_some_and(|v| v == "true")
                {
                    graph.complete = false;
                }
                graph
            })
        })
        .collect();
    let type_facts = infer_assignment_types(&project, options.host_profile);
    let error_handling = collect_error_handling_facts(&project);
    for fact in &error_handling {
        if matches!(fact.operation.as_str(), "goto_label" | "resume_label")
            && fact.target_resolved == Some(false)
        {
            diagnostics.push(Diagnostic {
                code: "VBA2041",
                severity: Severity::Error,
                message: format!(
                    "label '{}' referenced by {} is not defined in this procedure",
                    fact.target.as_deref().unwrap_or(""),
                    fact.operation
                ),
                source: project
                    .modules
                    .iter()
                    .find(|m| m.name == fact.module)
                    .map(|m| m.source_name.clone())
                    .unwrap_or_default(),
                span: fact.span,
            });
        }
    }
    let semantic_analysis_complete = false; // VBA host libraries and some dynamic/runtime semantics remain open-world.
    Ok(Analysis {
        project,
        diagnostics,
        procedures: facts.procedures,
        references: facts.references,
        calls: facts.calls,
        data_accesses: facts.data_accesses,
        semantic_analysis_complete,
        control_flow,
        data_flow: facts.data_flow,
        type_facts,
        error_handling,
        host_profile: options.host_profile,
    })
}

#[derive(Default)]
struct FactSet {
    procedures: Vec<ProcedureFact>,
    references: Vec<ReferenceFact>,
    calls: Vec<CallFact>,
    data_accesses: Vec<DataAccessFact>,
    data_flow: Vec<DataFlowFact>,
}

fn collect_facts(
    project: &Project,
    index: &HashMap<String, Vec<(usize, usize)>>,
    diagnostics: &mut Vec<Diagnostic>,
    limits: &Limits,
    host_profile: HostProfile,
) -> FactSet {
    let mut pf = Vec::new();
    let mut rf = Vec::new();
    let mut cf = Vec::new();
    let mut df = Vec::new();
    let mut data_flow = Vec::new();
    for (mi, m) in project.modules.iter().enumerate() {
        for p in &m.procedures {
            pf.push(ProcedureFact {
                module: m.name.clone(),
                name: p.name.clone(),
                kind: p.kind.clone(),
                visibility: p.visibility.clone(),
                span: p.span,
            });
        }
        let (tokens, lex_errors) = lex(&m.analysis_text, limits.max_tokens);
        for (span, msg) in lex_errors {
            diagnostics.push(Diagnostic {
                code: "VBA1001",
                severity: Severity::Warning,
                message: msg,
                source: m.source_name.clone(),
                span,
            });
        }
        collect_assignment_facts(m, &mut data_flow);
        let explicit = m
            .analysis_text
            .lines()
            .any(|l| l.trim().eq_ignore_ascii_case("Option Explicit"));
        let mut labels = HashSet::new();
        for p in &m.procedures {
            collect_labels(&p.statements, &mut labels);
        }
        let mut i = 0;
        while i < tokens.len() {
            let tok = &tokens[i];
            if tok.kind != TokenKind::Identifier {
                i += 1;
                continue;
            }
            let name = canon(&tok.text);
            let prev = i.checked_sub(1).and_then(|x| tokens.get(x));
            let next = tokens.get(i + 1);
            let proc = m
                .procedures
                .iter()
                .find(|p| tok.span.start >= p.span.start && tok.span.start <= p.span.end)
                .map(|p| p.name.clone());
            if line_starts_with(&tokens, i, "attribute") {
                i += 1;
                continue;
            }
            if next.is_some_and(|t| t.text == ":=") {
                i += 1;
                continue;
            }
            if prev.is_some_and(|x| x.text == "." || x.text == "!") {
                let excel_member = host_profile == HostProfile::Excel && excel::is_known_member(&name);
                rf.push(ReferenceFact {
                    module: m.name.clone(),
                    procedure: proc.clone(),
                    name: tok.text.clone(),
                    resolution: if excel_member {"excel_object_model_member_candidate"} else {"member_or_host_property_unresolved"}.into(),
                    span: tok.span,
                });
                if excel_member && next.is_some_and(|t| t.text == "(") {
                    let arguments=call_arguments(&tokens,i);
                    cf.push(CallFact{module:m.name.clone(),procedure:proc.clone(),target:tok.text.clone(),resolution:"excel_object_model_call_candidate".into(),argument_count:arguments.as_ref().map(Vec::len),arguments:arguments.unwrap_or_default(),span:tok.span});
                }
                if host_profile==HostProfile::Excel&&excel::is_data_access_name(&name){let eq=statement_assignment_eq(&tokens,i);df.push(DataAccessFact{module:m.name.clone(),procedure:proc.clone(),operation:if eq.is_some_and(|e|i<e){"write_candidate"}else{"read_candidate"}.into(),target:call_target(&tokens,i),host_dependent:true,span:tok.span});}
                i+=1;
                continue;
            }
            if is_declaration_position(prev) || is_keyword(&tok.text) {
                i += 1;
                continue;
            }
            if is_function_result_assignment(m, proc.as_deref(), &tokens, i, &tok.text) {
                rf.push(ReferenceFact {
                    module: m.name.clone(),
                    procedure: proc.clone(),
                    name: tok.text.clone(),
                    resolution: "function_result_assignment".into(),
                    span: tok.span,
                });
                i += 1;
                continue;
            }
            let is_lvalue = is_assignment_lvalue(&tokens, i);
            if prev.is_some_and(|x| matches!(canon(&x.text).as_str(), "goto" | "gosub" | "resume"))
            {
                rf.push(ReferenceFact {
                    module: m.name.clone(),
                    procedure: proc.clone(),
                    name: tok.text.clone(),
                    resolution: if labels.contains(&name) {
                        "resolved_local_label"
                    } else {
                        "unresolved_label"
                    }
                    .into(),
                    span: tok.span,
                });
                i += 1;
                continue;
            }
            let declared_variable = module_or_procedure_variable(m, proc.as_deref(), &name);
            let explicit_call = prev.is_some_and(|t| t.text.eq_ignore_ascii_case("call"));
            let call = explicit_call
                || (!is_lvalue
                    && !declared_variable
                    && (index.contains_key(&name)
                        || next.is_some_and(|t| t.text == "(")
                        || is_bare_call(&tokens, i)));
            if call {
                let mut resolution = match index.get(&name) {
                    Some(v) if v.len() == 1 => {
                        if v[0].0 == mi {
                            "resolved_project_procedure"
                        } else {
                            "resolved_cross_module_procedure"
                        }
                    }
                    Some(_) => "ambiguous_procedure_name",
                    None if host_profile == HostProfile::Excel && excel::is_known_member(&name) => {
                        "excel_object_model_call_candidate"
                    }
                    None => {
                        if intrinsic_names().contains(name.as_str()) {
                            "intrinsic_or_host_function"
                        } else {
                            "unresolved_external_or_host_call"
                        }
                    }
                };
                let arguments = call_arguments(&tokens, i);
                let argument_count = arguments.as_ref().map(Vec::len);
                if let Some(candidates) = index.get(&name)
                    && candidates.len() == 1
                {
                    let (target_module, target_proc) = candidates[0];
                    let callee = &project.modules[target_module].procedures[target_proc];
                    if target_module != mi && callee.visibility.eq_ignore_ascii_case("private") {
                        resolution = "inaccessible_private_procedure";
                        diagnostics.push(Diagnostic{code:"VBA2021",severity:Severity::Warning,message:format!("call to private procedure '{}' from another module is not accessible",callee.name),source:m.source_name.clone(),span:tok.span});
                    }
                    if let Some(n) = argument_count {
                        let required = callee
                            .parameters
                            .iter()
                            .filter(|a| !a.optional && !a.is_param_array)
                            .count();
                        let maximum = callee.parameters.len();
                        let has_params = callee.parameters.iter().any(|a| a.is_param_array);
                        if n < required || (!has_params && n > maximum) {
                            let max = if has_params {
                                "unbounded".to_string()
                            } else {
                                maximum.to_string()
                            };
                            diagnostics.push(Diagnostic{code:"VBA2020",severity:Severity::Warning,message:format!("call to '{}' supplies {n} arguments; declaration accepts {required}..{max}",callee.name),source:m.source_name.clone(),span:tok.span});
                        }
                    }
                    if let Some(arguments) = &arguments {
                        for (formal, actual) in callee.parameters.iter().zip(arguments) {
                            let by_ref = !formal.is_param_array
                                && formal.passing.eq_ignore_ascii_case("ByRef");
                            if by_ref
                                && parameter_is_written(callee, &formal.name)
                                && is_assignable_argument(actual)
                            {
                                data_flow.push(DataFlowFact {
                                    module: m.name.clone(),
                                    procedure: proc.clone(),
                                    target: actual.clone(),
                                    inputs: vec![callee.name.clone(), formal.name.clone()],
                                    transfer: "byref_argument_write".into(),
                                    span: tok.span,
                                });
                            }
                        }
                    }
                }
                cf.push(CallFact {
                    module: m.name.clone(),
                    procedure: proc.clone(),
                    target: tok.text.clone(),
                    resolution: resolution.into(),
                    argument_count,
                    arguments: arguments.unwrap_or_default(),
                    span: tok.span,
                });
                if let Some(op) = external_operation(&tok.text) {
                    df.push(DataAccessFact {
                        module: m.name.clone(),
                        procedure: proc.clone(),
                        operation: op.into(),
                        target: call_target(&tokens, i),
                        host_dependent: true,
                        span: tok.span,
                    });
                }
            } else {
                let resolution = if is_intrinsic_constant(&tok.text) {
                    "intrinsic_constant"
                } else if host_profile == HostProfile::Excel && excel::is_constant(&tok.text) {
                    "excel_type_library_constant_candidate"
                } else if declared_variable {
                    "declared_symbol"
                } else {
                    "unresolved_name_or_implicit_variant"
                };
                if explicit && resolution == "unresolved_name_or_implicit_variant" {
                    diagnostics.push(Diagnostic{code:"VBA2030",severity:Severity::Warning,message:format!("'{}' is unresolved under Option Explicit; a referenced or host-provided symbol may still exist",tok.text),source:m.source_name.clone(),span:tok.span});
                }
                rf.push(ReferenceFact {
                    module: m.name.clone(),
                    procedure: proc.clone(),
                    name: tok.text.clone(),
                    resolution: resolution.into(),
                    span: tok.span,
                });
            }
            if host_profile == HostProfile::Excel && excel::is_data_access_name(&name) {
                let eq = statement_assignment_eq(&tokens, i);
                df.push(DataAccessFact {
                    module: m.name.clone(),
                    procedure: proc.clone(),
                    operation: if eq.is_some_and(|e| i < e) {
                        "write_candidate"
                    } else {
                        "read_candidate"
                    }
                    .into(),
                    target: call_target(&tokens, i),
                    host_dependent: true,
                    span: tok.span,
                });
            }
            if name == "iif" {
                diagnostics.push(Diagnostic{code:"VBA2010",severity:Severity::Note,message:"VBA IIf evaluates both result expressions; both operands are retained rather than modeled as short-circuit branches".into(),source:m.source_name.clone(),span:tok.span});
            }
            i += 1;
        }
        if m.procedures
            .iter()
            .any(|p| contains_statement(&p.statements, "on_error"))
        {
            diagnostics.push(Diagnostic{code:"VBA2012",severity:Severity::Warning,message:"On Error handler state and transfers are not proven by these control-flow facts".into(),source:m.source_name.clone(),span:Span::default()});
        }
    }
    FactSet {
        procedures: pf,
        references: rf,
        calls: cf,
        data_accesses: df,
        data_flow,
    }
}

fn collect_assignment_facts(m: &Module, out: &mut Vec<DataFlowFact>) {
    for p in &m.procedures {
        collect_assignments_in(m, p, &p.statements, out);
    }
}
fn collect_assignments_in(
    m: &Module,
    p: &Procedure,
    statements: &[Statement],
    out: &mut Vec<DataFlowFact>,
) {
    for s in statements {
        if s.kind == "assignment"
            && let Some(source) = &s.expression
        {
            let (tokens, _) = lex(source, 16_384);
            let tokens = tokens
                .into_iter()
                .filter(|t| t.kind != TokenKind::Newline && t.kind != TokenKind::Eof)
                .collect::<Vec<_>>();
            let mut depth = 0i32;
            let mut eq = None;
            for (i, t) in tokens.iter().enumerate() {
                match t.text.as_str() {
                    "(" | "[" => depth += 1,
                    ")" | "]" => depth -= 1,
                    "=" if depth == 0 && t.kind == TokenKind::Symbol => {
                        eq = Some(i);
                        break;
                    }
                    _ => {}
                }
            }
            if let Some(e) = eq
                && e > 0
                && e + 1 < tokens.len()
            {
                let first = canon(&tokens[0].text);
                let lhs_start = if matches!(first.as_str(), "set" | "let") {
                    1
                } else {
                    0
                };
                let target = render_ids(&tokens[lhs_start..e]);
                if !target.is_empty() {
                    let mut inputs = Vec::new();
                    let mut seen = HashSet::new();
                    for (i, t) in tokens[e + 1..].iter().enumerate() {
                        if t.kind != TokenKind::Identifier
                            || i > 0 && tokens[e + i].text == "."
                            || is_keyword(&t.text)
                            || intrinsic_names().contains(canon(&t.text).as_str())
                        {
                            continue;
                        }
                        if seen.insert(canon(&t.text)) {
                            inputs.push(t.text.clone());
                        }
                    }
                    out.push(DataFlowFact {
                        module: m.name.clone(),
                        procedure: Some(p.name.clone()),
                        target,
                        inputs,
                        transfer: if first == "set" {
                            "object_assignment"
                        } else {
                            "assignment"
                        }
                        .into(),
                        span: s.span,
                    });
                }
            }
        }
        collect_assignments_in(m, p, &s.children, out);
    }
}
fn render_ids(ts: &[Token]) -> String {
    let mut s = String::new();
    for t in ts {
        if t.kind == TokenKind::Newline {
            continue;
        }
        if !s.is_empty()
            && !matches!(t.text.as_str(), "." | "!" | "(" | ")" | "[")
            && !s.ends_with('.')
            && !s.ends_with('!')
        {
            s.push(' ');
        }
        s.push_str(&t.text);
    }
    s.trim().to_string()
}
fn module_or_procedure_variable(m: &Module, procedure: Option<&str>, name: &str) -> bool {
    if m.declarations.iter().any(|d| canon(&d.name) == name) {
        return true;
    }
    let Some(p) =
        procedure.and_then(|n| m.procedures.iter().find(|p| p.name.eq_ignore_ascii_case(n)))
    else {
        return false;
    };
    p.parameters.iter().any(|a| canon(&a.name) == name) || contains_decl(&p.statements, name)
}
fn type_is_known(project: &Project, name: &str, host_profile: HostProfile) -> bool {
    known_type(name)
        || (host_profile == HostProfile::Excel && excel::is_known_type(name))
        || project.modules.iter().any(|m| {
            m.declarations.iter().any(|d| {
                matches!(d.kind.as_str(), "user_type" | "enum") && canon(&d.name) == canon(name)
            })
        })
}
fn collect_labels(statements: &[Statement], labels: &mut HashSet<String>) {
    for s in statements {
        if s.kind == "label"
            && let Some(n) = &s.expression
        {
            labels.insert(canon(n.trim_end_matches(':')));
        }
        collect_labels(&s.children, labels);
    }
}
fn validate_label_definitions(
    statements: &[Statement],
    labels: &mut HashMap<String, Span>,
    diagnostics: &mut Vec<Diagnostic>,
    source: &str,
) {
    for s in statements {
        if s.kind == "label"
            && let Some(raw) = &s.expression
        {
            let name = raw.trim_end_matches(':');
            let key = canon(name);
            if let Some(previous) = labels.insert(key, s.span) {
                diagnostics.push(Diagnostic {
                    code: "VBA2042",
                    severity: Severity::Error,
                    message: format!(
                        "duplicate label '{}' (first declared at line {})",
                        name, previous.line
                    ),
                    source: source.into(),
                    span: s.span,
                });
            }
        }
        validate_label_definitions(&s.children, labels, diagnostics, source);
    }
}
fn validate_jump_targets(
    statements: &[Statement],
    labels: &HashSet<String>,
    diagnostics: &mut Vec<Diagnostic>,
    source: &str,
) {
    for s in statements {
        if matches!(s.kind.as_str(), "goto" | "gosub") {
            let target = s
                .expression
                .as_deref()
                .unwrap_or("")
                .split_whitespace()
                .nth(1)
                .unwrap_or("")
                .trim_end_matches(':');
            if !target.is_empty() && !labels.contains(&canon(target)) {
                diagnostics.push(Diagnostic {
                    code: "VBA2041",
                    severity: Severity::Error,
                    message: format!("label '{}' is not defined in this procedure", target),
                    source: source.into(),
                    span: s.span,
                });
            }
        }
        validate_jump_targets(&s.children, labels, diagnostics, source);
    }
}
fn collect_error_handling_facts(project: &Project) -> Vec<ErrorHandlingFact> {
    let mut out = Vec::new();
    for m in &project.modules {
        for p in &m.procedures {
            let mut labels = HashSet::new();
            collect_labels(&p.statements, &mut labels);
            collect_error_facts_in(&m.name, &p.name, &p.statements, &labels, &mut out);
        }
    }
    out
}
fn collect_error_facts_in(
    module: &str,
    procedure: &str,
    statements: &[Statement],
    labels: &HashSet<String>,
    out: &mut Vec<ErrorHandlingFact>,
) {
    for s in statements {
        if matches!(s.kind.as_str(), "on_error" | "resume") {
            let text = s.expression.as_deref().unwrap_or("");
            let words = text.split_whitespace().collect::<Vec<_>>();
            let low = text.to_ascii_lowercase();
            if s.kind == "on_error" {
                let (operation, target, resolved) = if low.starts_with("on error resume next") {
                    ("resume_next", None, None)
                } else if low.starts_with("on error goto 0") {
                    ("disable", None, None)
                } else if low.starts_with("on error goto -1") {
                    ("clear_active_error", None, None)
                } else if low.starts_with("on error goto ") {
                    let t = words.get(3).map(|x| x.trim_end_matches(':').to_string());
                    (
                        "goto_label",
                        t.clone(),
                        t.as_ref().map(|x| labels.contains(&canon(x))),
                    )
                } else {
                    ("unknown_policy", None, None)
                };
                out.push(ErrorHandlingFact {
                    module: module.into(),
                    procedure: procedure.into(),
                    operation: operation.into(),
                    target,
                    target_resolved: resolved,
                    path_state_verified: false,
                    span: s.span,
                });
            } else {
                let (operation, target) = if low == "resume" || low == "resume 0" {
                    ("retry_fault", None)
                } else if low == "resume next" {
                    ("resume_next", None)
                } else {
                    (
                        "resume_label",
                        words.get(1).map(|x| x.trim_end_matches(':').to_string()),
                    )
                };
                out.push(ErrorHandlingFact {
                    module: module.into(),
                    procedure: procedure.into(),
                    operation: operation.into(),
                    target: target.clone(),
                    target_resolved: target.as_ref().map(|x| labels.contains(&canon(x))),
                    path_state_verified: false,
                    span: s.span,
                });
            }
        }
        collect_error_facts_in(module, procedure, &s.children, labels, out);
    }
}
fn line_starts_with(tokens: &[Token], at: usize, word: &str) -> bool {
    let mut start = at;
    while start > 0 && tokens[start - 1].kind != TokenKind::Newline {
        start -= 1;
    }
    tokens
        .get(start)
        .is_some_and(|t| t.text.eq_ignore_ascii_case(word))
}
fn is_function_result_assignment(
    module: &Module,
    procedure: Option<&str>,
    tokens: &[Token],
    at: usize,
    name: &str,
) -> bool {
    let Some(p) = procedure.and_then(|n| {
        module
            .procedures
            .iter()
            .find(|p| p.name.eq_ignore_ascii_case(n))
    }) else {
        return false;
    };
    if !matches!(
        p.kind.to_ascii_lowercase().as_str(),
        "function" | "property get"
    ) || canon(&p.name) != canon(name)
    {
        return false;
    }
    let mut start = at;
    while start > 0 && tokens[start - 1].kind != TokenKind::Newline && tokens[start - 1].text != ":"
    {
        start -= 1;
    }
    let target = if tokens
        .get(start)
        .is_some_and(|t| matches!(t.text.to_ascii_lowercase().as_str(), "set" | "let"))
    {
        start + 1
    } else {
        start
    };
    target == at && statement_assignment_eq(tokens, at).is_some_and(|eq| eq > at)
}
fn is_assignment_lvalue(tokens: &[Token], at: usize) -> bool {
    let mut start = at;
    while start > 0 && tokens[start - 1].kind != TokenKind::Newline && tokens[start - 1].text != ":"
    {
        start -= 1;
    }
    let Some(first) = tokens.get(start) else {
        return false;
    };
    if matches!(
        canon(&first.text).as_str(),
        "if" | "elseif" | "for" | "case" | "const" | "dim" | "public" | "private" | "option"
    ) {
        return false;
    }
    let target = if matches!(canon(&first.text).as_str(), "set" | "let") {
        start + 1
    } else {
        start
    };
    let Some(eq) = statement_assignment_eq(tokens, at) else {
        return false;
    };
    target == at && eq > at
}
fn contains_decl(ss: &[Statement], name: &str) -> bool {
    ss.iter().any(|s| {
        (s.kind == "declaration"
            && s.children
                .iter()
                .any(|c| c.expression.as_deref().is_some_and(|n| canon(n) == name)))
            || contains_decl(&s.children, name)
    })
}
fn contains_statement(ss: &[Statement], kind: &str) -> bool {
    ss.iter()
        .any(|s| s.kind == kind || contains_statement(&s.children, kind))
}
fn is_declaration_position(prev: Option<&Token>) -> bool {
    prev.is_some_and(|t| {
        matches!(
            canon(&t.text).as_str(),
            "sub"
                | "function"
                | "get"
                | "let"
                | "set"
                | "dim"
                | "const"
                | "as"
                | "byval"
                | "byref"
                | "optional"
                | "paramarray"
                | "withevents"
                | "event"
                | "type"
                | "enum"
                | "declare"
                | "lib"
                | "alias"
        )
    })
}
fn is_bare_call(ts: &[Token], i: usize) -> bool {
    let mut start = i;
    while start > 0 && ts[start - 1].kind != TokenKind::Newline && ts[start - 1].text != ":" {
        start -= 1;
    }
    if start != i {
        return false;
    }
    let Some(n) = ts.get(i + 1) else {
        return false;
    };
    !matches!(
        n.text.as_str(),
        "=" | ":="
            | "."
            | "!"
            | "+"
            | "-"
            | "*"
            | "/"
            | "&"
            | "<"
            | ">"
            | "<="
            | ">="
            | "<>"
            | "as"
            | ","
            | ":"
    )
}
fn statement_assignment_eq(ts: &[Token], at: usize) -> Option<usize> {
    let mut depth = 0i32;
    let mut start = at;
    while start > 0 && ts[start - 1].kind != TokenKind::Newline && ts[start - 1].text != ":" {
        start -= 1;
    }
    for (i, token) in ts.iter().enumerate().skip(start) {
        if token.kind == TokenKind::Newline || token.text == ":" {
            break;
        }
        match token.text.as_str() {
            "(" | "[" => depth += 1,
            ")" | "]" => depth -= 1,
            "=" if depth == 0 => return Some(i),
            _ => {}
        }
    }
    None
}
fn call_target(ts: &[Token], at: usize) -> String {
    let mut out = ts.get(at).map(|t| t.text.clone()).unwrap_or_default();
    let mut i = at + 1;
    if ts.get(i).is_some_and(|t| t.text == "(") {
        let mut d = 0i32;
        while i < ts.len() {
            if ts[i].text == "(" {
                d += 1;
            } else if ts[i].text == ")" {
                d -= 1;
            }
            out.push_str(&ts[i].text);
            i += 1;
            if d == 0 {
                break;
            }
        }
    }
    out
}
fn call_arguments(ts: &[Token], at: usize) -> Option<Vec<String>> {
    let next = at + 1;
    if ts.get(next).is_some_and(|t| t.text == "(") {
        let mut depth = 0i32;
        let mut close = None;
        for (i, t) in ts.iter().enumerate().skip(next + 1) {
            match t.text.as_str() {
                "(" => depth += 1,
                ")" if depth == 0 => {
                    close = Some(i);
                    break;
                }
                ")" => depth -= 1,
                _ => {}
            }
        }
        let end = close?;
        Some(
            split_tokens(&ts[next + 1..end], ",")
                .into_iter()
                .map(render_call_argument)
                .collect(),
        )
    } else {
        let mut end = next;
        while end < ts.len()
            && ts[end].kind != TokenKind::Newline
            && ts[end].kind != TokenKind::Eof
            && ts[end].text != ":"
        {
            end += 1;
        }
        if end == next {
            return Some(Vec::new());
        }
        Some(
            split_tokens(&ts[next..end], ",")
                .into_iter()
                .map(render_call_argument)
                .collect(),
        )
    }
}
fn split_tokens<'a>(ts: &'a [Token], separator: &str) -> Vec<&'a [Token]> {
    let mut out = Vec::new();
    let (mut start, mut depth) = (0usize, 0i32);
    for (i, t) in ts.iter().enumerate() {
        match t.text.as_str() {
            "(" | "[" => depth += 1,
            ")" | "]" => depth -= 1,
            _ => {}
        }
        if depth == 0 && t.text == separator {
            out.push(&ts[start..i]);
            start = i + 1;
        }
    }
    out.push(&ts[start..]);
    out
}
fn render_call_argument(ts: &[Token]) -> String {
    let mut s = String::new();
    let mut prev = "";
    for t in ts {
        let tight = matches!(t.text.as_str(), ")" | "." | "," | ":" | "!" | "(")
            || matches!(prev, "." | "!" | "(");
        if !s.is_empty() && !tight {
            s.push(' ');
        }
        if t.kind == TokenKind::String {
            s.push('"');
            s.push_str(&t.text.replace('"', "\"\""));
            s.push('"');
        } else {
            s.push_str(&t.text);
        }
        prev = &t.text;
    }
    s
}
fn is_assignable_argument(arg: &str) -> bool {
    let text = arg.split_once(":=").map(|x| x.1).unwrap_or(arg).trim();
    if text.is_empty() || text.to_ascii_lowercase().starts_with("byval ") {
        return false;
    }
    let (tokens, _) = lex(text, 1024);
    let ids = tokens
        .into_iter()
        .filter(|t| t.kind != TokenKind::Newline && t.kind != TokenKind::Eof)
        .collect::<Vec<_>>();
    ids.first().is_some_and(|t| t.kind == TokenKind::Identifier)
        && !ids.iter().any(|t| {
            matches!(
                t.text.as_str(),
                "+" | "-" | "*" | "/" | "&" | "=" | "<>" | "<" | ">"
            )
        })
}
fn parameter_is_written(procedure: &Procedure, name: &str) -> bool {
    statements_write_name(&procedure.statements, name)
}
fn statements_write_name(statements: &[Statement], name: &str) -> bool {
    statements.iter().any(|s| {
        let direct = if s.kind == "assignment" {
            assignment_lhs_name(s.expression.as_deref().unwrap_or(""))
                .is_some_and(|n| canon(&n) == canon(name))
        } else if s.kind == "redim" || s.kind == "erase" || s.kind == "for" || s.kind == "for_each"
        {
            statement_declared_target(s.expression.as_deref().unwrap_or(""))
                .is_some_and(|n| canon(&n) == canon(name))
        } else {
            false
        };
        direct || statements_write_name(&s.children, name)
    })
}
fn assignment_lhs_name(source: &str) -> Option<String> {
    let mut lhs = source.split_once('=')?.0.trim().to_owned();
    if lhs.to_ascii_lowercase().starts_with("set ") || lhs.to_ascii_lowercase().starts_with("let ")
    {
        lhs = lhs[4..].trim().to_owned();
    }
    statement_declared_target(&lhs)
}
fn statement_declared_target(source: &str) -> Option<String> {
    let (tokens, _) = lex(source, 128);
    tokens
        .into_iter()
        .find(|t| {
            t.kind == TokenKind::Identifier
                && !matches!(
                    canon(&t.text).as_str(),
                    "redim"
                        | "preserve"
                        | "erase"
                        | "for"
                        | "each"
                        | "next"
                        | "let"
                        | "set"
                        | "byref"
                        | "byval"
                        | "optional"
                        | "paramarray"
                        | "in"
                        | "to"
                        | "step"
                        | "while"
                        | "until"
                        | "do"
                )
        })
        .map(|t| t.text)
}
fn canon(s: &str) -> String {
    s.trim_end_matches(['%', '&', '@', '!', '#', '$'])
        .to_lowercase()
}
fn known_type(s: &str) -> bool {
    matches!(
        s.trim().to_ascii_lowercase().as_str(),
        "variant"
            | "boolean"
            | "byte"
            | "integer"
            | "long"
            | "longlong"
            | "longptr"
            | "single"
            | "double"
            | "currency"
            | "decimal"
            | "date"
            | "string"
            | "object"
            | "error"
    )
}
fn is_intrinsic_constant(s: &str) -> bool {
    matches!(
        canon(s).as_str(),
        "true"
            | "false"
            | "nothing"
            | "empty"
            | "null"
            | "vbnullstring"
            | "vbcr"
            | "vbcrlf"
            | "vblf"
            | "vbtab"
            | "vbnewline"
            | "vbobjecterror"
            | "me"
            | "app"
            | "thisworkbook"
    )
}
fn external_operation(s: &str) -> Option<&'static str> {
    Some(match canon(s).as_str() {
        "shell" => "process_execution_candidate",
        "createobject" | "getobject" => "automation_or_com_object_candidate",
        "open" | "close" | "print" | "put" | "get" => "file_io_candidate",
        "kill" | "filecopy" | "mkdir" | "rmdir" | "chdir" => "filesystem_operation_candidate",
        "callbyname" | "run" => "dynamic_invocation_candidate",
        "environ" => "environment_read_candidate",
        "executeexcel4macro" => "legacy_macro_execution_candidate",
        _ => return None,
    })
}
fn intrinsic_names() -> HashSet<&'static str> {
    [
        "abs",
        "array",
        "asc",
        "ascw",
        "atn",
        "callbyname",
        "cbool",
        "cbyte",
        "ccur",
        "cdate",
        "cdbl",
        "cdec",
        "choose",
        "chr",
        "chrw",
        "cint",
        "clng",
        "clngptr",
        "cos",
        "createobject",
        "csng",
        "cstr",
        "cvar",
        "date",
        "dateadd",
        "datediff",
        "datepart",
        "dateserial",
        "datevalue",
        "day",
        "dir",
        "doevents",
        "environ",
        "eof",
        "err",
        "error",
        "eval",
        "exp",
        "fileattr",
        "filedatetime",
        "filelen",
        "filter",
        "format",
        "freefile",
        "getallsettings",
        "getattr",
        "hex",
        "hour",
        "iif",
        "input",
        "instr",
        "instrrev",
        "int",
        "ipmt",
        "irr",
        "isarray",
        "isdate",
        "isempty",
        "iserror",
        "ismissing",
        "isnull",
        "isnumeric",
        "isobject",
        "join",
        "lbound",
        "lcase",
        "left",
        "len",
        "loc",
        "lof",
        "log",
        "ltrim",
        "mid",
        "minute",
        "month",
        "msgbox",
        "now",
        "nper",
        "npv",
        "oct",
        "partition",
        "pmt",
        "ppmt",
        "pv",
        "qbcolor",
        "randomize",
        "rate",
        "replace",
        "rgb",
        "right",
        "rnd",
        "round",
        "rtrim",
        "second",
        "seek",
        "sgn",
        "sin",
        "space",
        "split",
        "sqr",
        "str",
        "strcomp",
        "string",
        "strreverse",
        "switch",
        "tan",
        "time",
        "timeserial",
        "timevalue",
        "trim",
        "typename",
        "ubound",
        "ucase",
        "val",
        "vartype",
        "weekday",
        "year",
        "shell",
        "loadpicture",
        "getobject",
    ]
    .into_iter()
    .collect()
}
fn is_keyword(s: &str) -> bool {
    matches!(
        canon(s).as_str(),
        "and"
            | "as"
            | "byref"
            | "byval"
            | "call"
            | "case"
            | "class"
            | "const"
            | "dim"
            | "do"
            | "each"
            | "else"
            | "elseif"
            | "end"
            | "enum"
            | "erase"
            | "exit"
            | "explicit"
            | "false"
            | "for"
            | "friend"
            | "function"
            | "get"
            | "global"
            | "goto"
            | "gosub"
            | "if"
            | "implements"
            | "in"
            | "is"
            | "let"
            | "loop"
            | "me"
            | "mod"
            | "new"
            | "next"
            | "not"
            | "nothing"
            | "on"
            | "option"
            | "optional"
            | "or"
            | "paramarray"
            | "preserve"
            | "private"
            | "property"
            | "public"
            | "raiseevent"
            | "return"
            | "redim"
            | "rem"
            | "resume"
            | "select"
            | "set"
            | "static"
            | "step"
            | "stop"
            | "sub"
            | "then"
            | "to"
            | "true"
            | "until"
            | "wend"
            | "while"
            | "with"
            | "xor"
            | "imp"
            | "eqv"
            | "type"
            | "attribute"
            | "declare"
            | "lib"
            | "alias"
            | "event"
            | "like"
            | "variant"
            | "boolean"
            | "byte"
            | "integer"
            | "long"
            | "longlong"
            | "longptr"
            | "single"
            | "double"
            | "currency"
            | "decimal"
            | "date"
            | "string"
            | "object"
            | "any"
            | "ptrsafe"
            | "withevents"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resolves_calls_and_keeps_ambiguity_explicit() {
        let a=analyze(&[SourceUnit{name:"A.bas".into(),text:"Public Sub Start()\nWork 2\nEnd Sub\nPrivate Sub Work(ByVal x As Long)\nEnd Sub\n".into()}],&AnalysisOptions::default()).unwrap();
        assert!(
            a.calls
                .iter()
                .any(|c| c.target == "Work" && c.resolution == "resolved_project_procedure")
        );
        assert!(!a.semantic_analysis_complete);
    }
    #[test]
    fn distinguishes_function_result_from_call_and_finds_excel_access() {
        let source=SourceUnit{name:"M.bas".into(),text:"Attribute VB_Name = \"M\"\nPublic Function Total(ByVal amount As Long) As Long\nTotal = amount\nEnd Function\nPublic Sub Save(ByVal amount As Long)\nWorksheets(\"Orders\").Range(\"A1\").Value = amount\nEnd Sub\n".into()};
        let generic = analyze(std::slice::from_ref(&source), &AnalysisOptions::default()).unwrap();
        assert!(generic.data_accesses.is_empty());
        let options = AnalysisOptions {
            host_profile: HostProfile::Excel,
            ..AnalysisOptions::default()
        };
        let a = analyze(&[source], &options).unwrap();
        assert!(!a.calls.iter().any(|c| c.target == "Total"));
        assert!(
            a.references
                .iter()
                .any(|r| r.resolution == "function_result_assignment")
        );
        assert!(
            a.data_accesses
                .iter()
                .any(|d| d.operation == "write_candidate" && d.target.starts_with("Worksheets"))
        );
        assert!(!a.data_flow.iter().any(|f| f.procedure.is_none()));
    }
    #[test]
    fn evaluates_known_conditional_branches_and_marks_unknown_cfgs_incomplete() {
        let source=SourceUnit{name:"Conditional.bas".into(),text:"#If Win64 Then\nPublic Sub NewTarget()\nEnd Sub\n#Else\nPublic Sub OldTarget()\nEnd Sub\n#End If\n".into()};
        let mut options = AnalysisOptions::default();
        options
            .conditional_constants
            .insert("Win64".into(), "False".into());
        let known = analyze(std::slice::from_ref(&source), &options).unwrap();
        assert_eq!(known.project.modules[0].procedures.len(), 1);
        assert_eq!(known.project.modules[0].procedures[0].name, "OldTarget");
        assert!(!known.diagnostics.iter().any(|d| d.code == "VBA3001"));
        let unknown = analyze(&[source], &AnalysisOptions::default()).unwrap();
        assert_eq!(unknown.project.modules[0].procedures.len(), 2);
        assert!(unknown.diagnostics.iter().any(|d| d.code == "VBA3001"));
        assert!(unknown.control_flow.iter().all(|g| !g.complete));
    }
    #[test]
    fn reports_undeclared_names_under_option_explicit_and_respects_array_variables() {
        let source=SourceUnit{name:"Explicit.bas".into(),text:"Option Explicit\nPrivate values(2) As Long\nPublic Sub Fill()\nvalues(1) = missingValue\nEnd Sub\n".into()};
        let a = analyze(&[source], &AnalysisOptions::default()).unwrap();
        assert!(
            a.diagnostics
                .iter()
                .any(|d| d.code == "VBA2030" && d.message.contains("missingValue"))
        );
        assert!(!a.calls.iter().any(|c| c.target == "values"));
    }
    #[test]
    fn keeps_both_arms_of_single_line_if_in_flow_and_dataflow() {
        let a = analyze(
            &[SourceUnit {
                name: "Inline.bas".into(),
                text: "Public Sub S()\nIf flag Then amount = 5 Else amount = 0\nEnd Sub\n".into(),
            }],
            &AnalysisOptions::default(),
        )
        .unwrap();
        assert_eq!(
            a.project.modules[0].procedures[0].statements[0]
                .children
                .len(),
            2
        );
        assert_eq!(a.data_flow.len(), 2);
        assert_eq!(
            a.control_flow[0]
                .edges
                .iter()
                .filter(|e| e.condition.is_some())
                .count(),
            2
        );
    }
    #[test]
    fn tracks_writes_through_byref_arguments_but_not_byval_arguments() {
        let source=SourceUnit{name:"ByRef.bas".into(),text:"Option Explicit\nPrivate Sub Bump(ByRef value As Long)\nvalue = value + 1\nEnd Sub\nPrivate Sub ReadOnly(ByVal value As Long)\nvalue = value + 1\nEnd Sub\nPublic Sub Caller()\nDim amount As Long\nBump amount\nReadOnly amount\nEnd Sub\n".into()};
        let a = analyze(&[source], &AnalysisOptions::default()).unwrap();
        assert_eq!(
            a.data_flow
                .iter()
                .filter(|f| f.transfer == "byref_argument_write")
                .count(),
            1
        );
        assert!(
            a.data_flow
                .iter()
                .any(|f| f.transfer == "byref_argument_write" && f.target == "amount")
        );
    }
    #[test]
    fn preserves_omitted_optional_argument_slots() {
        let src = "Public Sub Run()\nTarget(1,)\nEnd Sub\nPrivate Sub Target(ByVal required As Long, Optional extra As Long = 2)\nEnd Sub\n";
        let a = analyze(
            &[SourceUnit {
                name: "Optional.bas".into(),
                text: src.into(),
            }],
            &AnalysisOptions::default(),
        )
        .unwrap();
        let call = a.calls.iter().find(|c| c.target == "Target").unwrap();
        assert_eq!(call.argument_count, Some(2));
        assert_eq!(call.arguments.len(), 2);
        assert_eq!(call.arguments[1], "");
        assert!(!a.diagnostics.iter().any(|d| d.code == "VBA2020"));
    }
    #[test]
    fn resolves_error_handler_labels_but_keeps_path_state_unverified() {
        let source=SourceUnit{name:"Errors.bas".into(),text:"Public Sub Work()\nOn Error GoTo Handler\nvalue = 1\nExit Sub\nHandler:\nResume Next\nEnd Sub\n".into()};
        let a = analyze(&[source], &AnalysisOptions::default()).unwrap();
        assert_eq!(a.error_handling.len(), 2);
        assert_eq!(a.error_handling[0].operation, "goto_label");
        assert_eq!(a.error_handling[0].target_resolved, Some(true));
        assert_eq!(a.error_handling[1].operation, "resume_next");
        assert!(a.error_handling.iter().all(|f| !f.path_state_verified));
        assert!(!a.control_flow[0].complete);
    }
    #[test]
    fn diagnoses_undefined_jump_and_error_handler_labels() {
        let src = "Public Sub Broken()\nGoTo Missing\nOn Error GoTo AlsoMissing\nResume NeverDefined\nEnd Sub\n";
        let a = analyze(
            &[SourceUnit {
                name: "Broken.bas".into(),
                text: src.into(),
            }],
            &AnalysisOptions::default(),
        )
        .unwrap();
        assert!(a.diagnostics.iter().filter(|d| d.code == "VBA2041").count() >= 3);
    }
}
