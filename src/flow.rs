use crate::model::{
    ControlFlowGraph, Expr, FlowEdge, FlowNode, MAX_GOSUB_RESUMPTION_DEPTH,
    MAX_GOSUB_RESUMPTION_STATES, Module, Procedure, Statement, canonical_statement_label,
};
use std::collections::{HashMap, HashSet, VecDeque};

pub fn build_graph(module: &Module, procedure: &Procedure) -> ControlFlowGraph {
    let mut b = Builder {
        graph: ControlFlowGraph {
            module: module.name.clone(),
            procedure: procedure.name.clone(),
            complete: true,
            ..ControlFlowGraph::default()
        },
        labels: HashMap::new(),
        gotos: Vec::new(),
        gosubs: Vec::new(),
        gosub_invocations: Vec::new(),
        on_jumps: Vec::new(),
        loop_exits: Vec::new(),
    };
    b.graph.entry = b.node("entry", "entry", procedure.span);
    b.graph.exit = b.node("exit", "exit", procedure.span);
    let entry = b.graph.entry;
    let ends = b.process(&procedure.statements, vec![entry]);
    for n in ends {
        b.edge(n, b.graph.exit, None);
    }
    for (id, label) in b.gotos.clone() {
        if let Some(target) = b.labels.get(&canon_label(&label)) {
            b.edge(id, *target, None);
        } else {
            b.graph.complete = false;
        }
    }
    for gosub in b.gosubs.clone() {
        let mut destinations = Vec::new();
        if let Some(target) = b.labels.get(&canon_label(&gosub.destination)) {
            destinations.push(*target);
            b.edge(
                gosub.call_node,
                *target,
                Some(format!("GoSub enters {}", gosub.destination)),
            );
        } else {
            b.graph.complete = false;
            b.edge(
                gosub.call_node,
                b.graph.exit,
                Some(format!("GoSub target {} is unresolved", gosub.destination)),
            );
        }
        b.gosub_invocations.push(GosubInvocation {
            call_node: gosub.call_node,
            continuation_node: gosub.continuation_node,
            destination_nodes: destinations,
            fallthrough_node: None,
        });
    }
    for jump in b.on_jumps.clone() {
        let mut destination_nodes = Vec::new();
        for (index, label) in jump.destinations.iter().enumerate() {
            let Some(index) = index.checked_add(1) else {
                b.graph.complete = false;
                continue;
            };
            if index > 255 {
                // On...GoTo/GoSub raises an error for branch indexes above 255.
                continue;
            }
            let condition = format!(
                "Integer({}) = {} selects destination {}",
                jump.expression, index, label
            );
            if let Some(target) = b.labels.get(&canon_label(label)) {
                destination_nodes.push(*target);
                b.edge(jump.node, *target, Some(condition));
            } else {
                b.graph.complete = false;
                b.edge(
                    jump.node,
                    b.graph.exit,
                    Some(format!("{}; target unresolved", condition)),
                );
            }
        }
        if jump.kind == "on_gosub" {
            b.gosub_invocations.push(GosubInvocation {
                call_node: jump.node,
                continuation_node: jump.fallthrough_node,
                destination_nodes,
                fallthrough_node: Some(jump.fallthrough_node),
            });
        }
    }
    expand_gosub_resumptions(
        &mut b.graph,
        &b.gosub_invocations,
        MAX_GOSUB_RESUMPTION_STATES,
        MAX_GOSUB_RESUMPTION_DEPTH,
    );
    b.graph
}

fn loop_condition_clause(statement: &Statement) -> Option<(bool, String)> {
    let source = match statement.kind.as_str() {
        "while" | "do_pre" => statement.expression.as_deref()?,
        "do" => statement.exit_condition.as_deref()?,
        _ => return None,
    };
    let source = if statement.kind == "do_pre" {
        strip_leading_vba_keyword(source, "Do")?
    } else {
        source
    };
    if let Some(expression) = strip_leading_vba_keyword(source, "Until") {
        return Some((true, expression.to_owned()));
    }
    strip_leading_vba_keyword(source, "While").map(|expression| (false, expression.to_owned()))
}

fn for_initial_entry_predicate(statement: &Statement) -> Option<String> {
    let start = statement.loop_start.as_deref()?;
    let end = statement.loop_end.as_deref()?;
    let step = statement.loop_step.as_deref().unwrap_or("1");
    Some(format!(
        "(({step}) >= 0 And ({start}) <= ({end})) Or (({step}) < 0 And ({start}) >= ({end}))"
    ))
}

fn strip_leading_vba_keyword<'a>(source: &'a str, keyword: &str) -> Option<&'a str> {
    let source = source.trim_start();
    let prefix = source.get(..keyword.len())?;
    if !prefix.eq_ignore_ascii_case(keyword) {
        return None;
    }
    let remainder = source.get(keyword.len()..)?;
    remainder
        .chars()
        .next()
        .is_some_and(char::is_whitespace)
        .then(|| remainder.trim_start())
}

fn loop_edge_condition(label: &str, expression: &str, expected_true: bool) -> String {
    format!(
        "{label} [predicate: ({expression}) = {}]",
        if expected_true { "True" } else { "False" }
    )
}

struct Builder {
    graph: ControlFlowGraph,
    labels: HashMap<String, usize>,
    gotos: Vec<(usize, String)>,
    gosubs: Vec<PendingGosub>,
    gosub_invocations: Vec<GosubInvocation>,
    on_jumps: Vec<OnJump>,
    loop_exits: Vec<usize>,
}

#[derive(Clone)]
struct OnJump {
    node: usize,
    kind: String,
    expression: String,
    destinations: Vec<String>,
    fallthrough_node: usize,
}

#[derive(Clone)]
struct PendingGosub {
    call_node: usize,
    continuation_node: usize,
    destination: String,
}

#[derive(Clone)]
struct GosubInvocation {
    call_node: usize,
    continuation_node: usize,
    destination_nodes: Vec<usize>,
    fallthrough_node: Option<usize>,
}
impl Builder {
    fn node(&mut self, kind: &str, label: &str, span: crate::model::Span) -> usize {
        let id = self.graph.nodes.len();
        self.graph.nodes.push(FlowNode {
            id,
            kind: kind.into(),
            label: label.into(),
            span,
        });
        id
    }
    fn edge(&mut self, from: usize, to: usize, condition: Option<String>) {
        self.graph.edges.push(FlowEdge {
            from,
            to,
            condition,
        });
    }
    fn process(&mut self, ss: &[Statement], mut incoming: Vec<usize>) -> Vec<usize> {
        for s in ss {
            match s.kind.as_str() {
                "then_branch" | "else_branch" | "elseif_branch" | "case" => {
                    incoming = self.process(&s.children, incoming);
                }
                "if" | "single_line_if" => {
                    let mut exits = Vec::new();
                    let mut last_condition =
                        s.expression.as_deref().unwrap_or("condition").to_owned();
                    let mut current_test = self.node("decision", &last_condition, s.span);
                    for &n in &incoming {
                        self.edge(n, current_test, None);
                    }
                    let mut has_else = false;
                    for (index, branch) in s.children.iter().enumerate() {
                        if branch.kind == "else_branch" {
                            has_else = true;
                            let gate = self.node("branch", "Else", branch.span);
                            self.edge(
                                current_test,
                                gate,
                                Some(format!("({last_condition}) = False")),
                            );
                            exits.extend(self.process(&branch.children, vec![gate]));
                            continue;
                        }
                        let condition = if branch.kind == "elseif_branch" {
                            branch
                                .expression
                                .as_deref()
                                .unwrap_or("unknown condition")
                                .to_owned()
                        } else if branch.kind == "then_branch" {
                            last_condition.clone()
                        } else {
                            self.graph.complete = false;
                            "unknown condition".to_owned()
                        };
                        if branch.kind == "elseif_branch" {
                            let next_test = self.node("decision", &condition, branch.span);
                            self.edge(
                                current_test,
                                next_test,
                                Some(format!("({last_condition}) = False")),
                            );
                            current_test = next_test;
                            last_condition = condition.clone();
                        }
                        let gate = self.node(
                            "branch",
                            branch.expression.as_deref().unwrap_or(&branch.kind),
                            branch.span,
                        );
                        self.edge(current_test, gate, Some(format!("({condition}) = True")));
                        exits.extend(self.process(&branch.children, vec![gate]));
                        let next = s.children.get(index + 1);
                        if next.is_none() {
                            let bypass =
                                self.node("implicit_else", "all conditions false", branch.span);
                            self.edge(
                                current_test,
                                bypass,
                                Some(format!("({last_condition}) = False")),
                            );
                            exits.push(bypass);
                        } else if next
                            .is_some_and(|b| b.kind != "elseif_branch" && b.kind != "else_branch")
                        {
                            self.graph.complete = false;
                        }
                    }
                    if !has_else && s.children.is_empty() {
                        self.graph.complete = false;
                    }
                    incoming = exits;
                }
                "select_case" => {
                    let selector_is_null = s
                        .parsed_expression
                        .as_ref()
                        .is_some_and(is_explicit_null_expression);
                    let selector = self.node(
                        "select_expression",
                        s.expression.as_deref().unwrap_or("Select Case"),
                        s.span,
                    );
                    for &n in &incoming {
                        self.edge(n, selector, None);
                    }
                    let mut exits = Vec::new();
                    let mut tests = Vec::with_capacity(s.children.len());
                    let mut case_ranges = Vec::with_capacity(s.children.len());
                    let mut gates = Vec::with_capacity(s.children.len());
                    let mut clauses = Vec::with_capacity(s.children.len());
                    let mut else_clauses = Vec::with_capacity(s.children.len());
                    for branch in &s.children {
                        let cond = branch
                            .expression
                            .clone()
                            .unwrap_or_else(|| "Case value".into());
                        let is_else = cond.eq_ignore_ascii_case("Case Else");
                        let case_values = cond
                            .strip_prefix("Case")
                            .or_else(|| {
                                cond.get(..4)
                                    .filter(|prefix| prefix.eq_ignore_ascii_case("case"))
                            })
                            .map(str::trim)
                            .unwrap_or(cond.as_str());
                        let ranges = if is_else {
                            Vec::new()
                        } else if branch.case_ranges.is_empty() {
                            self.graph.complete = false;
                            vec![crate::model::CaseRange {
                                kind: "unresolved".into(),
                                expression: Some(case_values.to_owned()),
                                span: branch.span,
                                valid: false,
                                ..crate::model::CaseRange::default()
                            }]
                        } else {
                            branch.case_ranges.clone()
                        };
                        let range_tests = ranges
                            .iter()
                            .map(|range| {
                                if !range.valid {
                                    self.graph.complete = false;
                                }
                                let label = format!("Case test: {}", case_range_label(range));
                                let span = if range.span.start < range.span.end {
                                    range.span
                                } else {
                                    branch.span
                                };
                                self.node("case_test", &label, span)
                            })
                            .collect::<Vec<_>>();
                        let gate = self.node(
                            "case",
                            &format!("Case body: {case_values}"),
                            crate::model::Span::default(),
                        );
                        tests.push(range_tests);
                        case_ranges.push(ranges);
                        gates.push(gate);
                        clauses.push(case_values.to_owned());
                        else_clauses.push(is_else);
                        exits.extend(self.process(&branch.children, vec![gate]));
                    }

                    for index in 0..s.children.len() {
                        if else_clauses[index] {
                            if index + 1 < s.children.len() {
                                self.graph.complete = false;
                            }
                            if index == 0 {
                                self.edge(
                                    selector,
                                    gates[index],
                                    Some("no previous Case clause matched".into()),
                                );
                            } else if tests[..index].iter().all(Vec::is_empty) {
                                self.graph.complete = false;
                            }
                            if index + 1 < s.children.len() {
                                // Case Else consumes all values; later clauses are invalid.
                                break;
                            }
                            continue;
                        }

                        let select_value =
                            s.expression.as_deref().unwrap_or("Select Case expression");
                        for (range_index, &test) in tests[index].iter().enumerate() {
                            let range = case_ranges[index][range_index].clone();
                            let predicate = case_range_predicate(select_value, &range);
                            if index == 0 && range_index == 0 {
                                self.edge(selector, test, None);
                            }
                            if !selector_is_null {
                                self.edge(
                                    test,
                                    gates[index],
                                    Some(case_match_condition(select_value, &range, &predicate)),
                                );
                            }

                            let miss_condition = case_miss_condition(select_value, &range);
                            if let Some(next_test) = tests[index].get(range_index + 1) {
                                self.edge(test, *next_test, Some(miss_condition));
                            } else if index + 1 == s.children.len() {
                                let no_match =
                                    self.node("no_case_match", "no Case matched", s.span);
                                self.edge(test, no_match, Some(miss_condition));
                                exits.push(no_match);
                            } else if else_clauses[index + 1] {
                                self.edge(test, gates[index + 1], Some(miss_condition));
                            } else if let Some(next_test) = tests[index + 1].first() {
                                self.edge(test, *next_test, Some(miss_condition));
                            } else {
                                self.graph.complete = false;
                            }
                        }
                    }
                    if s.children.is_empty() {
                        let no_match = self.node("no_case_match", "no Case matched", s.span);
                        self.edge(
                            selector,
                            no_match,
                            Some("Select Case has no Case clauses".into()),
                        );
                        exits.push(no_match);
                    }
                    incoming = exits;
                }
                "for" | "for_each" | "while" | "do_pre" => {
                    if s.kind == "for" {
                        let initial_test = self.node("loop_test", "For initial bound test", s.span);
                        let repeat_test =
                            self.node("for_repeat_test", "For continuation test", s.span);
                        for &n in &incoming {
                            self.edge(n, initial_test, None);
                        }
                        let body = self.node("loop_body", "loop body", s.span);
                        let done = self.node("loop_exit", "loop complete", s.span);
                        let initial_entry = for_initial_entry_predicate(s);
                        let initial_body_condition = initial_entry
                            .as_deref()
                            .map(|predicate| {
                                loop_edge_condition(
                                    "For initial bounds enter body",
                                    predicate,
                                    true,
                                )
                            })
                            .unwrap_or_else(|| "continue condition holds".into());
                        let initial_done_condition = initial_entry
                            .as_deref()
                            .map(|predicate| {
                                loop_edge_condition(
                                    "For initial bounds skip body",
                                    predicate,
                                    false,
                                )
                            })
                            .unwrap_or_else(|| "continue condition is false".into());
                        self.edge(initial_test, body, Some(initial_body_condition));
                        self.edge(initial_test, done, Some(initial_done_condition));
                        self.edge(repeat_test, body, Some("continue condition holds".into()));
                        self.edge(
                            repeat_test,
                            done,
                            Some("continue condition is false".into()),
                        );
                        self.loop_exits.push(done);
                        let body_out = self.process(&s.children, vec![body]);
                        self.loop_exits.pop();
                        for n in body_out {
                            self.edge(n, repeat_test, Some("next iteration".into()));
                        }
                        incoming = vec![done];
                        continue;
                    }
                    let test = self.node(
                        "loop_test",
                        s.expression.as_deref().unwrap_or(&s.kind),
                        s.span,
                    );
                    for &n in &incoming {
                        self.edge(n, test, None);
                    }
                    let body = self.node("loop_body", "loop body", s.span);
                    let done = self.node("loop_exit", "loop complete", s.span);
                    let condition_clause = loop_condition_clause(s);
                    let until = condition_clause
                        .as_ref()
                        .is_some_and(|(is_until, _)| *is_until);
                    let body_condition_label = if until {
                        "condition false"
                    } else {
                        "continue condition holds"
                    };
                    let done_condition_label = if until {
                        "condition true"
                    } else {
                        "continue condition is false"
                    };
                    let body_condition = condition_clause
                        .as_ref()
                        .map(|(_, expression)| {
                            loop_edge_condition(body_condition_label, expression, !until)
                        })
                        .unwrap_or_else(|| body_condition_label.into());
                    let done_condition = condition_clause
                        .as_ref()
                        .map(|(_, expression)| {
                            loop_edge_condition(done_condition_label, expression, until)
                        })
                        .unwrap_or_else(|| done_condition_label.into());
                    self.edge(test, body, Some(body_condition));
                    self.edge(test, done, Some(done_condition));
                    self.loop_exits.push(done);
                    let body_out = self.process(&s.children, vec![body]);
                    self.loop_exits.pop();
                    for n in body_out {
                        self.edge(n, test, Some("next iteration".into()));
                    }
                    incoming = vec![done];
                }
                "do" => {
                    let body = self.node("loop_body", "Do body", s.span);
                    for &n in &incoming {
                        self.edge(n, body, None);
                    }
                    let test = self.node(
                        "loop_test",
                        s.exit_condition.as_deref().unwrap_or("Loop"),
                        s.span,
                    );
                    let done = self.node("loop_exit", "loop complete", s.span);
                    self.loop_exits.push(done);
                    let body_out = self.process(&s.children, vec![body]);
                    self.loop_exits.pop();
                    for n in body_out {
                        self.edge(n, test, None);
                    }
                    if s.exit_condition.is_some() {
                        let condition_clause = loop_condition_clause(s);
                        let until = condition_clause
                            .as_ref()
                            .is_some_and(|(is_until, _)| *is_until);
                        let body_condition_label = if until {
                            "condition false"
                        } else {
                            "condition true"
                        };
                        let done_condition_label = if until {
                            "condition true"
                        } else {
                            "condition false"
                        };
                        let body_condition = condition_clause
                            .as_ref()
                            .map(|(_, expression)| {
                                loop_edge_condition(body_condition_label, expression, !until)
                            })
                            .unwrap_or_else(|| body_condition_label.into());
                        let done_condition = condition_clause
                            .as_ref()
                            .map(|(_, expression)| {
                                loop_edge_condition(done_condition_label, expression, until)
                            })
                            .unwrap_or_else(|| done_condition_label.into());
                        self.edge(test, body, Some(body_condition));
                        self.edge(test, done, Some(done_condition));
                        incoming = vec![done];
                    } else {
                        self.edge(test, body, Some("next iteration".into()));
                        incoming = vec![done];
                    }
                }
                "with" => {
                    let n = self.node("with", s.expression.as_deref().unwrap_or("With"), s.span);
                    for &x in &incoming {
                        self.edge(x, n, None);
                    }
                    incoming = self.process(&s.children, vec![n]);
                }
                "label" => {
                    let name = s
                        .expression
                        .as_deref()
                        .unwrap_or("")
                        .trim()
                        .trim_end_matches(':');
                    let n = self.node("label", name, s.span);
                    for &x in &incoming {
                        self.edge(x, n, None);
                    }
                    self.labels.insert(canon_label(name), n);
                    incoming = vec![n];
                }
                "goto" => {
                    let n = self.node("goto", s.expression.as_deref().unwrap_or("GoTo"), s.span);
                    for &x in &incoming {
                        self.edge(x, n, None);
                    }
                    let label = jump_target(s).unwrap_or_else(|| {
                        s.expression
                            .as_deref()
                            .unwrap_or("")
                            .split_whitespace()
                            .nth(1)
                            .unwrap_or("")
                            .trim_end_matches(':')
                            .to_owned()
                    });
                    self.gotos.push((n, label));
                    incoming.clear();
                }
                "gosub" => {
                    let n = self.node(&s.kind, s.expression.as_deref().unwrap_or(&s.kind), s.span);
                    for &x in &incoming {
                        self.edge(x, n, None);
                    }
                    if let Some(label) = jump_target(s) {
                        let continuation = self.node("gosub_resume", "GoSub continuation", s.span);
                        self.gosubs.push(PendingGosub {
                            call_node: n,
                            continuation_node: continuation,
                            destination: label,
                        });
                        incoming = vec![continuation];
                    } else {
                        self.graph.complete = false;
                        incoming.clear();
                    }
                }
                "on_goto" | "on_gosub" => {
                    let expression = s.expression.clone().unwrap_or_default();
                    let n = self.node(&s.kind, &expression, s.span);
                    for &x in &incoming {
                        self.edge(x, n, None);
                    }
                    let destinations = jump_targets(s);
                    if destinations.is_empty() {
                        self.graph.complete = false;
                    }
                    let destination_count = destinations.len();
                    // Destination edges are candidates until Integer coercion and invalid-index
                    // error cases are proven unreachable.
                    self.graph.complete = false;
                    let fallthrough = self.node(
                        if s.kind == "on_gosub" {
                            "gosub_resume"
                        } else {
                            "on_jump_fallthrough"
                        },
                        &format!("{} continuation", s.kind),
                        s.span,
                    );
                    self.on_jumps.push(OnJump {
                        node: n,
                        kind: s.kind.clone(),
                        expression: expression.clone(),
                        destinations,
                        fallthrough_node: fallthrough,
                    });
                    self.edge(
                        n,
                        fallthrough,
                        Some(format!(
                            "Integer({expression}) = 0 or Integer({expression}) > {}",
                            destination_count
                        )),
                    );
                    incoming = vec![fallthrough];
                }
                "gosub_return" => {
                    let n = self.node(&s.kind, s.expression.as_deref().unwrap_or(&s.kind), s.span);
                    for &x in &incoming {
                        self.edge(x, n, None);
                    }
                    let resume_next = self.node(
                        "gosub_return_next",
                        "statement after Return when error handling resumes next",
                        s.span,
                    );
                    incoming = vec![resume_next];
                }
                "exit" | "end_statement" => {
                    let n = self.node(
                        "termination",
                        s.expression.as_deref().unwrap_or(&s.kind),
                        s.span,
                    );
                    for &x in &incoming {
                        self.edge(x, n, None);
                    }
                    let text = s.expression.as_deref().unwrap_or("").to_ascii_lowercase();
                    if s.kind == "end_statement"
                        || text.starts_with("exit sub")
                        || text.starts_with("exit function")
                        || text.starts_with("exit property")
                    {
                        self.edge(n, self.graph.exit, None);
                    } else if text.starts_with("exit for") || text.starts_with("exit do") {
                        if let Some(target) = self.loop_exits.last().copied() {
                            self.edge(n, target, None);
                        } else {
                            self.graph.complete = false;
                        }
                    } else {
                        self.graph.complete = false;
                    }
                    incoming.clear();
                }
                _ => {
                    let n = self.node(&s.kind, s.expression.as_deref().unwrap_or(&s.kind), s.span);
                    for x in incoming {
                        self.edge(x, n, None);
                    }
                    if s.kind == "on_error"
                        || s.kind == "unknown"
                        || s.kind == "resume"
                        || s.kind == "stop"
                    {
                        self.graph.complete = false;
                    }
                    incoming = vec![n];
                }
            }
        }
        incoming
    }
}

fn jump_target(statement: &Statement) -> Option<String> {
    statement
        .children
        .iter()
        .find(|child| child.kind == "jump_target")
        .and_then(|child| child.expression.as_deref())
        .map(|target| target.trim_end_matches(':').to_owned())
}

fn jump_targets(statement: &Statement) -> Vec<String> {
    statement
        .children
        .iter()
        .filter(|child| child.kind == "jump_target")
        .filter_map(|child| child.expression.as_deref())
        .map(|target| target.trim_end_matches(':').to_owned())
        .collect()
}

fn case_range_label(range: &crate::model::CaseRange) -> String {
    match range.kind.as_str() {
        "value" => range.expression.clone().unwrap_or_else(|| "?".into()),
        "range" => format!(
            "{} To {}",
            range.start_value.as_deref().unwrap_or("?"),
            range.end_value.as_deref().unwrap_or("?")
        ),
        "comparison" => format!(
            "Is {} {}",
            range.comparison_operator.as_deref().unwrap_or("?"),
            range.expression.as_deref().unwrap_or("?")
        ),
        _ => range
            .expression
            .clone()
            .unwrap_or_else(|| "unresolved".into()),
    }
}

fn case_range_predicate(select_value: &str, range: &crate::model::CaseRange) -> String {
    match range.kind.as_str() {
        "value" => format!(
            "({select_value}) = ({})",
            range.expression.as_deref().unwrap_or("?")
        ),
        "range" => format!(
            "({select_value}) >= ({}) And ({select_value}) <= ({})",
            range.start_value.as_deref().unwrap_or("?"),
            range.end_value.as_deref().unwrap_or("?")
        ),
        "comparison" => format!(
            "({select_value}) {} ({})",
            range.comparison_operator.as_deref().unwrap_or("?"),
            range.expression.as_deref().unwrap_or("?")
        ),
        _ => format!(
            "unresolved Case range test for ({select_value}): {}",
            range.expression.as_deref().unwrap_or("?")
        ),
    }
}

fn case_match_condition(
    select_value: &str,
    range: &crate::model::CaseRange,
    predicate: &str,
) -> String {
    format!(
        "Select Case ({select_value}) matches Case {} [predicate: {predicate}]",
        case_range_label(range)
    )
}

fn case_miss_condition(select_value: &str, range: &crate::model::CaseRange) -> String {
    format!(
        "Select Case ({select_value}) does not match Case {} [predicate: NOT ({})]",
        case_range_label(range),
        case_range_predicate(select_value, range)
    )
}

fn is_explicit_null_expression(expression: &Expr) -> bool {
    match expression {
        Expr::Identifier(name, _) => name.eq_ignore_ascii_case("Null"),
        Expr::Group(inner, _) => is_explicit_null_expression(inner),
        _ => false,
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct GosubState {
    node: usize,
    resumptions: Vec<usize>,
}

fn expand_gosub_resumptions(
    graph: &mut ControlFlowGraph,
    invocations: &[GosubInvocation],
    max_states: usize,
    max_stack_depth: usize,
) {
    let has_error_policy = graph
        .nodes
        .iter()
        .any(|node| matches!(node.kind.as_str(), "on_error" | "resume"));
    if has_error_policy {
        // Error handlers and Gosub return stacks have to be propagated together.
        // Keep the candidate dispatch edges and explicitly retain an incomplete CFG.
        graph.complete = false;
        return;
    }

    let source_nodes = graph.nodes.clone();
    let source_edges = graph.edges.clone();
    let source_entry = graph.entry;
    let source_exit = graph.exit;
    if invocations.is_empty() {
        let reachable = reachable_node_ids(graph);
        let unmatched_returns = source_nodes
            .iter()
            .filter(|node| node.kind == "gosub_return" && reachable.contains(&node.id))
            .collect::<Vec<_>>();
        if !unmatched_returns.is_empty() {
            graph.complete = false;
            for source in unmatched_returns {
                graph.edges.push(FlowEdge {
                    from: source.id,
                    to: source_exit,
                    condition: Some("Return without an active GoSub may raise error 3".into()),
                });
            }
        }
        return;
    }

    let mut outgoing: HashMap<usize, Vec<FlowEdge>> = HashMap::new();
    for edge in source_edges {
        outgoing.entry(edge.from).or_default().push(edge);
    }
    let invocations_by_node = invocations
        .iter()
        .map(|invocation| (invocation.call_node, invocation))
        .collect::<HashMap<_, _>>();
    let mut expanded = ControlFlowGraph {
        module: graph.module.clone(),
        procedure: graph.procedure.clone(),
        complete: graph.complete,
        ..ControlFlowGraph::default()
    };
    let mut state_to_node = HashMap::new();
    let mut queue = VecDeque::new();
    let start = GosubState {
        node: source_entry,
        resumptions: Vec::new(),
    };
    let Some(entry) = intern_gosub_state(
        start,
        source_exit,
        &source_nodes,
        &mut expanded,
        &mut state_to_node,
        &mut queue,
        max_states,
    ) else {
        graph.complete = false;
        return;
    };
    expanded.entry = entry;
    let Some(exit) = intern_gosub_state(
        GosubState {
            node: source_exit,
            resumptions: Vec::new(),
        },
        source_exit,
        &source_nodes,
        &mut expanded,
        &mut state_to_node,
        &mut queue,
        max_states,
    ) else {
        graph.complete = false;
        return;
    };
    expanded.exit = exit;

    while let Some(state) = queue.pop_front() {
        let Some(source) = source_nodes.get(state.node) else {
            expanded.complete = false;
            continue;
        };
        if state.node == source_exit {
            continue;
        }
        let Some(&from) = state_to_node.get(&state) else {
            expanded.complete = false;
            continue;
        };
        if source.kind == "gosub_return" {
            if let Some(resume_node) = state.resumptions.last().copied() {
                let mut resumed = state.clone();
                resumed.resumptions.pop();
                if let Some(to) = intern_gosub_state(
                    GosubState {
                        node: resume_node,
                        resumptions: resumed.resumptions,
                    },
                    source_exit,
                    &source_nodes,
                    &mut expanded,
                    &mut state_to_node,
                    &mut queue,
                    max_states,
                ) {
                    expanded.edges.push(FlowEdge {
                        from,
                        to,
                        condition: Some("Return resumes the most recent GoSub".into()),
                    });
                }
            } else {
                expanded.complete = false;
                expanded.edges.push(FlowEdge {
                    from,
                    to: expanded.exit,
                    condition: Some("Return without an active GoSub may raise error 3".into()),
                });
            }
            continue;
        }

        let Some(edges) = outgoing.get(&state.node) else {
            expanded.complete = false;
            continue;
        };
        if let Some(invocation) = invocations_by_node.get(&state.node) {
            for edge in edges {
                if invocation.destination_nodes.contains(&edge.to) {
                    if state.resumptions.len() >= max_stack_depth {
                        expanded.complete = false;
                        continue;
                    }
                    let mut resumptions = state.resumptions.clone();
                    resumptions.push(invocation.continuation_node);
                    if let Some(to) = intern_gosub_state(
                        GosubState {
                            node: edge.to,
                            resumptions,
                        },
                        source_exit,
                        &source_nodes,
                        &mut expanded,
                        &mut state_to_node,
                        &mut queue,
                        max_states,
                    ) {
                        expanded.edges.push(FlowEdge {
                            from,
                            to,
                            condition: edge.condition.clone(),
                        });
                    }
                } else if invocation.fallthrough_node == Some(edge.to) {
                    if let Some(to) = intern_gosub_state(
                        GosubState {
                            node: edge.to,
                            resumptions: state.resumptions.clone(),
                        },
                        source_exit,
                        &source_nodes,
                        &mut expanded,
                        &mut state_to_node,
                        &mut queue,
                        max_states,
                    ) {
                        expanded.edges.push(FlowEdge {
                            from,
                            to,
                            condition: edge.condition.clone(),
                        });
                    }
                } else if let Some(to) = intern_gosub_state(
                    GosubState {
                        node: edge.to,
                        resumptions: state.resumptions.clone(),
                    },
                    source_exit,
                    &source_nodes,
                    &mut expanded,
                    &mut state_to_node,
                    &mut queue,
                    max_states,
                ) {
                    expanded.edges.push(FlowEdge {
                        from,
                        to,
                        condition: edge.condition.clone(),
                    });
                }
            }
            continue;
        }

        for edge in edges {
            if let Some(to) = intern_gosub_state(
                GosubState {
                    node: edge.to,
                    resumptions: state.resumptions.clone(),
                },
                source_exit,
                &source_nodes,
                &mut expanded,
                &mut state_to_node,
                &mut queue,
                max_states,
            ) {
                expanded.edges.push(FlowEdge {
                    from,
                    to,
                    condition: edge.condition.clone(),
                });
            }
        }
    }

    *graph = expanded;
}

fn reachable_node_ids(graph: &ControlFlowGraph) -> HashSet<usize> {
    let mut outgoing = HashMap::<usize, Vec<usize>>::new();
    for edge in &graph.edges {
        outgoing.entry(edge.from).or_default().push(edge.to);
    }
    let mut reachable = HashSet::from([graph.entry]);
    let mut queue = VecDeque::from([graph.entry]);
    while let Some(node) = queue.pop_front() {
        for next in outgoing.get(&node).into_iter().flatten() {
            if reachable.insert(*next) {
                queue.push_back(*next);
            }
        }
    }
    reachable
}

fn intern_gosub_state(
    mut state: GosubState,
    source_exit: usize,
    source_nodes: &[FlowNode],
    graph: &mut ControlFlowGraph,
    state_to_node: &mut HashMap<GosubState, usize>,
    queue: &mut VecDeque<GosubState>,
    max_states: usize,
) -> Option<usize> {
    if state.node == source_exit {
        // Procedure completion discards the invocation's remaining GoSub stack.
        state.resumptions.clear();
    }
    if let Some(node) = state_to_node.get(&state) {
        return Some(*node);
    }
    if state_to_node.len() >= max_states {
        graph.complete = false;
        return None;
    }
    let original = source_nodes.get(state.node)?;
    let node = graph.nodes.len();
    graph.nodes.push(FlowNode {
        id: node,
        kind: original.kind.clone(),
        label: original.label.clone(),
        span: original.span,
    });
    state_to_node.insert(state.clone(), node);
    queue.push_back(state);
    Some(node)
}

fn canon_label(s: &str) -> String {
    canonical_statement_label(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_module;
    #[test]
    fn builds_branched_flow_with_exit() {
        let m = parse_module(
            "M",
            "M.bas",
            "Public Sub S()\nIf x Then\nGoTo Done\nElse\ny = 2\nEnd If\nDone:\nEnd Sub\n",
            1000,
            32,
        );
        let g = build_graph(&m, &m.procedures[0]);
        assert!(g.nodes.iter().any(|n| n.kind == "decision"));
        assert!(
            g.edges
                .iter()
                .any(|e| e.condition.as_deref() == Some("(x) = True"))
        );
        assert!(g.complete, "{g:#?}");
    }

    #[test]
    fn select_case_clauses_are_tested_in_order_and_only_the_first_match_executes() {
        let module = parse_module(
            "M",
            "M.bas",
            "Public Sub Choose(ByVal value As Long)\nSelect Case value\nCase 1, 2\nfirst = 1\nCase 2 To 4\nsecond = 1\nCase Is >= 5\nthird = 1\nCase Else\nother = 1\nEnd Select\nEnd Sub\n",
            10_000,
            100,
        );
        let graph = build_graph(&module, &module.procedures[0]);
        let selector = graph
            .nodes
            .iter()
            .find(|node| node.kind == "select_expression")
            .unwrap();
        let case_gates = graph
            .nodes
            .iter()
            .filter(|node| node.kind == "case")
            .collect::<Vec<_>>();
        assert_eq!(case_gates.len(), 4);
        let case_tests = graph
            .nodes
            .iter()
            .filter(|node| node.kind == "case_test")
            .collect::<Vec<_>>();
        assert_eq!(case_tests.len(), 4);
        assert!(graph.edges.iter().any(|edge| {
            edge.from == selector.id && edge.to == case_tests[0].id && edge.condition.is_none()
        }));
        let first_gate = case_gates[0];
        let second_gate = case_gates[1];
        assert!(graph.edges.iter().any(|edge| {
            edge.from == case_tests[0].id
                && edge.to == first_gate.id
                && edge
                    .condition
                    .as_deref()
                    .is_some_and(|condition| condition.contains("matches Case 1"))
        }));
        assert!(
            !graph
                .edges
                .iter()
                .any(|edge| { edge.from == selector.id && edge.to == second_gate.id })
        );
        assert!(graph.edges.iter().any(|edge| {
            edge.from == case_tests[0].id
                && edge.to == case_tests[1].id
                && edge
                    .condition
                    .as_deref()
                    .is_some_and(|condition| condition.contains("does not match Case 1"))
        }));
        assert!(graph.edges.iter().any(|edge| {
            edge.from == case_tests[1].id
                && edge.to == first_gate.id
                && edge
                    .condition
                    .as_deref()
                    .is_some_and(|condition| condition.contains("matches Case 2"))
        }));
        assert!(
            graph
                .edges
                .iter()
                .any(|edge| { edge.from == case_tests[1].id && edge.to == case_tests[2].id })
        );
        assert!(graph.edges.iter().any(|edge| {
            edge.from == case_tests[2].id
                && edge.to == second_gate.id
                && edge.condition.as_deref().is_some_and(|condition| {
                    condition.contains("matches Case 2 To 4")
                        && condition.contains("(value) >= (2) And (value) <= (4)")
                })
        }));
        assert!(
            graph
                .edges
                .iter()
                .any(|edge| { edge.from == case_tests[2].id && edge.to == case_tests[3].id })
        );
        let else_edge = graph
            .edges
            .iter()
            .find(|edge| edge.to == case_gates[3].id)
            .unwrap();
        assert!(
            else_edge
                .condition
                .as_deref()
                .is_some_and(|condition| condition.contains("does not match Case Is >= 5")),
            "{graph:#?}"
        );
        assert!(graph.complete, "{graph:#?}");
    }

    #[test]
    fn malformed_case_range_is_retained_as_incomplete_flow() {
        let module = parse_module(
            "M",
            "M.bas",
            "Public Sub Choose(ByVal value As Long)\nSelect Case value\nCase 1 To\nresult = True\nEnd Select\nEnd Sub\n",
            10_000,
            100,
        );
        let graph = build_graph(&module, &module.procedures[0]);
        assert!(!graph.complete, "{graph:#?}");
        assert!(
            module
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "VBA1025")
        );
    }

    #[test]
    fn select_case_without_else_falls_through_when_no_clause_matches() {
        let module = parse_module(
            "M",
            "M.bas",
            "Public Sub Choose(ByVal value As Long)\nSelect Case value\nCase 1\na = 1\nCase 2\na = 2\nEnd Select\na = 3\nEnd Sub\n",
            10_000,
            100,
        );
        let graph = build_graph(&module, &module.procedures[0]);
        let no_match = graph
            .nodes
            .iter()
            .find(|node| node.kind == "no_case_match")
            .unwrap();
        let after = graph
            .nodes
            .iter()
            .find(|node| node.kind == "assignment" && node.label == "a = 3")
            .unwrap();
        assert!(graph.edges.iter().any(|edge| {
            edge.from == no_match.id && edge.to == after.id && edge.condition.is_none()
        }));
        assert!(graph.complete, "{graph:#?}");
    }

    #[test]
    fn null_select_expression_skips_case_bodies_and_uses_only_case_else() {
        let module = parse_module(
            "M",
            "M.bas",
            "Public Sub Choose()\nSelect Case Null\nCase 1\na = 1\nCase Else\nb = 2\nEnd Select\nEnd Sub\n",
            1000,
            32,
        );
        let graph = build_graph(&module, &module.procedures[0]);
        let case_test = graph
            .nodes
            .iter()
            .find(|node| node.kind == "case_test")
            .unwrap();
        let matched_case = graph
            .nodes
            .iter()
            .find(|node| node.kind == "case" && node.label.contains("Case body: 1"))
            .unwrap();
        let case_else = graph
            .nodes
            .iter()
            .find(|node| node.kind == "case" && node.label.contains("Case body: Else"))
            .unwrap();
        assert!(
            !graph
                .edges
                .iter()
                .any(|edge| edge.from == case_test.id && edge.to == matched_case.id)
        );
        assert!(graph.edges.iter().any(|edge| {
            edge.from == case_test.id
                && edge.to == case_else.id
                && edge
                    .condition
                    .as_deref()
                    .is_some_and(|condition| condition.contains("does not match Case 1"))
        }));
        let paths = crate::paths::enumerate_graph_paths(&graph, &crate::model::Limits::default());
        assert!(!paths.paths.iter().any(|path| {
            path.nodes
                .iter()
                .any(|node_id| graph.nodes[*node_id].label == "a = 1")
        }));
        assert!(graph.complete, "{graph:#?}");
    }

    #[test]
    fn invalid_nonfinal_case_else_keeps_the_cfg_incomplete() {
        let module = parse_module(
            "M",
            "M.bas",
            "Public Sub Choose(ByVal value As Long)\nSelect Case value\nCase Else\na = 0\nCase 1\na = 1\nEnd Select\nEnd Sub\n",
            10_000,
            100,
        );
        assert!(
            module
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "VBA1024")
        );
        let graph = build_graph(&module, &module.procedures[0]);
        assert!(!graph.complete);
    }

    #[test]
    fn models_elseif_as_sequential_tests() {
        let m = parse_module(
            "M",
            "M.bas",
            "Public Sub Choose(ByVal x As Long)\nIf x = 1 Then\na = 1\nElseIf x = 2 Then\na = 2\nElse\na = 3\nEnd If\nEnd Sub\n",
            1000,
            32,
        );
        let g = build_graph(&m, &m.procedures[0]);
        let decisions = g.nodes.iter().filter(|n| n.kind == "decision").count();
        assert_eq!(decisions, 2, "{g:#?}");
        assert!(g.complete, "{g:#?}");
        let paths = crate::paths::enumerate_graph_paths(&g, &crate::model::Limits::default());
        assert_eq!(paths.paths.len(), 3, "{:#?}", paths.paths);
        assert!(paths.paths.iter().any(|p| {
            p.conditions.len() == 2
                && p.conditions[0].contains("x = 1")
                && p.conditions[0].contains("False")
                && p.conditions[1].contains("x = 2")
                && p.conditions[1].contains("True")
        }));
        assert!(paths.paths.iter().any(|p| {
            p.conditions.len() == 2
                && p.conditions[0].contains("x = 1")
                && p.conditions[0].contains("False")
                && p.conditions[1].contains("x = 2")
                && p.conditions[1].contains("False")
        }));
    }

    #[test]
    fn models_on_goto_destinations_and_index_fallthrough() {
        let module = parse_module(
            "M",
            "M.bas",
            "Public Sub Choose(ByVal index As Integer)\nOn index GoTo FirstLabel, SecondLabel\nafter = 1\nExit Sub\nFirstLabel:\nfirst = 1\nExit Sub\nSecondLabel:\nsecond = 2\nEnd Sub\n",
            10_000,
            100,
        );
        let graph = build_graph(&module, &module.procedures[0]);
        let dispatch = graph
            .nodes
            .iter()
            .find(|node| node.kind == "on_goto")
            .unwrap();
        let first = graph
            .nodes
            .iter()
            .find(|node| node.kind == "label" && node.label == "FirstLabel")
            .unwrap();
        let second = graph
            .nodes
            .iter()
            .find(|node| node.kind == "label" && node.label == "SecondLabel")
            .unwrap();
        assert!(graph.edges.iter().any(|edge| {
            edge.from == dispatch.id
                && edge.to == first.id
                && edge
                    .condition
                    .as_deref()
                    .is_some_and(|condition| condition.contains("= 1"))
        }));
        assert!(graph.edges.iter().any(|edge| {
            edge.from == dispatch.id
                && edge.to == second.id
                && edge
                    .condition
                    .as_deref()
                    .is_some_and(|condition| condition.contains("= 2"))
        }));
        assert!(graph.edges.iter().any(|edge| {
            edge.from == dispatch.id
                && graph
                    .nodes
                    .get(edge.to)
                    .is_some_and(|node| node.kind == "on_jump_fallthrough")
                && edge
                    .condition
                    .as_deref()
                    .is_some_and(|condition| condition.contains("= 0") && condition.contains("> 2"))
        }));
        assert!(
            !graph.complete,
            "computed-jump value and error states are unresolved: {graph:#?}"
        );
    }

    #[test]
    fn expands_on_gosub_returns_but_marks_selector_state_incomplete() {
        let module = parse_module(
            "M",
            "M.bas",
            "Public Sub Choose(ByVal index As Integer)\nOn index GoSub FirstSub, SecondSub\nafter = 1\nExit Sub\nFirstSub:\nReturn\nSecondSub:\nReturn\nEnd Sub\n",
            10_000,
            100,
        );
        let graph = build_graph(&module, &module.procedures[0]);
        let dispatch = graph
            .nodes
            .iter()
            .find(|node| node.kind == "on_gosub")
            .unwrap();
        assert!(!graph.complete);
        for (index, label) in ["FirstSub", "SecondSub"].iter().enumerate() {
            let target = graph
                .nodes
                .iter()
                .find(|node| node.kind == "label" && node.label == *label)
                .unwrap();
            assert!(graph.edges.iter().any(|edge| {
                edge.from == dispatch.id
                    && edge.to == target.id
                    && edge
                        .condition
                        .as_deref()
                        .is_some_and(|condition| condition.contains(&format!("= {}", index + 1)))
            }));
        }
        let return_node = graph
            .nodes
            .iter()
            .find(|node| node.kind == "gosub_return")
            .unwrap();
        assert!(graph.edges.iter().any(|edge| {
            edge.from == return_node.id
                && graph
                    .nodes
                    .get(edge.to)
                    .is_some_and(|node| node.kind == "gosub_resume")
                && edge.condition.as_deref() == Some("Return resumes the most recent GoSub")
        }));
    }

    #[test]
    fn resumes_nested_gosubs_to_the_most_recent_call_site() {
        let module = parse_module(
            "M",
            "M.bas",
            "Public Sub Work()\nGoSub Outer\nafterOuter = 1\nExit Sub\nOuter:\nGoSub Inner\nafterInner = 2\nReturn\nInner:\nReturn\nEnd Sub\n",
            10_000,
            100,
        );
        let graph = build_graph(&module, &module.procedures[0]);
        let outer_resume = graph
            .nodes
            .iter()
            .find(|node| node.kind == "gosub_resume" && node.span.line == 2)
            .unwrap();
        let inner_resume = graph
            .nodes
            .iter()
            .find(|node| node.kind == "gosub_resume" && node.span.line == 6)
            .unwrap();
        let outer_return = graph
            .nodes
            .iter()
            .find(|node| node.kind == "gosub_return" && node.span.line == 8)
            .unwrap();
        let inner_return = graph
            .nodes
            .iter()
            .find(|node| node.kind == "gosub_return" && node.span.line == 10)
            .unwrap();
        assert!(graph.edges.iter().any(|edge| {
            edge.from == outer_return.id
                && edge.to == outer_resume.id
                && edge.condition.as_deref() == Some("Return resumes the most recent GoSub")
        }));
        assert!(graph.edges.iter().any(|edge| {
            edge.from == inner_return.id
                && edge.to == inner_resume.id
                && edge.condition.as_deref() == Some("Return resumes the most recent GoSub")
        }));
        assert!(graph.complete, "{graph:#?}");
    }

    #[test]
    fn routes_return_without_a_gosub_to_an_unresolved_runtime_error_exit() {
        let module = parse_module(
            "M",
            "M.bas",
            "Public Sub Work()\nReturn\nEnd Sub\n",
            1000,
            32,
        );
        let graph = build_graph(&module, &module.procedures[0]);
        let returned = graph
            .nodes
            .iter()
            .find(|node| node.kind == "gosub_return")
            .unwrap();
        assert!(graph.edges.iter().any(|edge| {
            edge.from == returned.id
                && edge.to == graph.exit
                && edge
                    .condition
                    .as_deref()
                    .is_some_and(|condition| condition.contains("error 3"))
        }));
        assert!(!graph.complete);
    }

    #[test]
    fn bounds_recursive_gosub_resumption_expansion() {
        let module = parse_module(
            "M",
            "M.bas",
            "Public Sub Recurse()\nGoSub Again\nExit Sub\nAgain:\nGoSub Again\nReturn\nEnd Sub\n",
            1000,
            32,
        );
        let graph = build_graph(&module, &module.procedures[0]);
        assert!(!graph.complete);
        assert!(graph.nodes.len() > 50, "bounded recursion was not explored");
        assert!(graph.nodes.len() < 200);
    }
}
