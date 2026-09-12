use crate::model::{ControlFlowGraph, FlowEdge, FlowNode, Module, Procedure, Statement};
use std::collections::HashMap;

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
    b.graph
}

struct Builder {
    graph: ControlFlowGraph,
    labels: HashMap<String, usize>,
    gotos: Vec<(usize, String)>,
    loop_exits: Vec<usize>,
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
                    let test =
                        self.node("decision", s.expression.as_deref().unwrap_or("If"), s.span);
                    for &n in &incoming {
                        self.edge(n, test, None);
                    }
                    let mut exits = Vec::new();
                    let mut has_else = false;
                    for branch in &s.children {
                        if branch.kind == "else_branch" {
                            has_else = true;
                        }
                        let gate = self.node(
                            "branch",
                            branch.expression.as_deref().unwrap_or(&branch.kind),
                            branch.span,
                        );
                        let cond = if branch.kind == "then_branch" {
                            format!("{} = True", s.expression.as_deref().unwrap_or("condition"))
                        } else if branch.kind == "else_branch" {
                            format!("{} = False", s.expression.as_deref().unwrap_or("condition"))
                        } else {
                            self.graph.complete = false;
                            format!(
                                "branch condition: {}",
                                branch.expression.as_deref().unwrap_or("unknown")
                            )
                        };
                        self.edge(test, gate, Some(cond));
                        let branch_out = self.process(&branch.children, vec![gate]);
                        exits.extend(branch_out);
                    }
                    if !has_else {
                        let bypass = self.node("implicit_else", "condition false", s.span);
                        self.edge(
                            test,
                            bypass,
                            Some(format!(
                                "{} = False",
                                s.expression.as_deref().unwrap_or("condition")
                            )),
                        );
                        exits.push(bypass);
                    }
                    incoming = exits;
                }
                "select_case" => {
                    let test = self.node(
                        "decision",
                        s.expression.as_deref().unwrap_or("Select Case"),
                        s.span,
                    );
                    for &n in &incoming {
                        self.edge(n, test, None);
                    }
                    let mut exits = Vec::new();
                    let mut has_else = false;
                    for branch in &s.children {
                        let gate = self.node(
                            "case",
                            branch.expression.as_deref().unwrap_or("Case"),
                            branch.span,
                        );
                        let cond = branch
                            .expression
                            .clone()
                            .unwrap_or_else(|| "case value".into());
                        if cond.eq_ignore_ascii_case("Case Else") {
                            has_else = true;
                        }
                        self.edge(test, gate, Some(cond));
                        exits.extend(self.process(&branch.children, vec![gate]));
                    }
                    if !has_else {
                        let no_match = self.node("no_case_match", "no Case matched", s.span);
                        self.edge(test, no_match, Some("no case matched".into()));
                        exits.push(no_match);
                    }
                    incoming = exits;
                }
                "for" | "for_each" | "while" | "do_pre" => {
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
                    let until = s.kind == "do_pre"
                        && s.expression
                            .as_deref()
                            .is_some_and(|x| x.to_ascii_lowercase().starts_with("do until "));
                    self.edge(
                        test,
                        body,
                        Some(
                            if until {
                                "condition false"
                            } else {
                                "continue condition holds"
                            }
                            .into(),
                        ),
                    );
                    self.edge(
                        test,
                        done,
                        Some(
                            if until {
                                "condition true"
                            } else {
                                "continue condition is false"
                            }
                            .into(),
                        ),
                    );
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
                    if let Some(condition) = &s.exit_condition {
                        let until = condition.to_ascii_lowercase().starts_with("until ");
                        self.edge(
                            test,
                            body,
                            Some(
                                if until {
                                    "condition false"
                                } else {
                                    "condition true"
                                }
                                .into(),
                            ),
                        );
                        self.edge(
                            test,
                            done,
                            Some(
                                if until {
                                    "condition true"
                                } else {
                                    "condition false"
                                }
                                .into(),
                            ),
                        );
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
                    let label = s
                        .expression
                        .as_deref()
                        .unwrap_or("")
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("")
                        .trim_end_matches(':')
                        .to_owned();
                    self.gotos.push((n, label));
                    incoming.clear();
                }
                "gosub" | "gosub_return" => {
                    let n = self.node(&s.kind, s.expression.as_deref().unwrap_or(&s.kind), s.span);
                    for &x in &incoming {
                        self.edge(x, n, None);
                    }
                    self.graph.complete = false;
                    incoming.clear();
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
                    if s.kind == "on_error" || s.kind == "unknown" || s.kind == "resume" {
                        self.graph.complete = false;
                    }
                    incoming = vec![n];
                }
            }
        }
        incoming
    }
}
fn canon_label(s: &str) -> String {
    s.trim().trim_end_matches(':').to_ascii_lowercase()
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
                .any(|e| e.condition.as_deref() == Some("x = True"))
        );
        assert!(g.complete, "{g:#?}");
    }
}
