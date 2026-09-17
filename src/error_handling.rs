//! Per-procedure VBA error-policy state transitions.
//!
//! This models the language policy transitions independently of CFG path
//! feasibility. It does not guess which statements can raise host/runtime errors.

use crate::model::{
    ControlFlowGraph, FlowEdge, MAX_GOSUB_RESUMPTION_DEPTH, canonical_statement_label,
};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OnErrorMode {
    ResumeNext,
    GoToLabel(String),
    Disable,
    ClearActiveError,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResumeMode {
    RetryFault,
    NextStatement,
    GoToLabel(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ErrorTransfer {
    ContinueAfterFault { fault: usize },
    TransferToHandler { label: String, fault: usize },
    PropagateToCaller { fault: usize },
    TerminateHost { fault: usize },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResumeTransfer {
    Retry { fault: usize },
    ContinueAfterFault { fault: usize },
    GoToLabel { label: String, fault: usize },
    ResumeWithoutActiveError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorFlowFindingKind {
    ResumeWithoutActiveError,
    ReturnWithoutGoSub,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErrorFlowFinding {
    pub node_id: usize,
    pub kind: ErrorFlowFindingKind,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum Policy {
    Default,
    ResumeNext,
    GoTo(String),
    Unknown,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ProcedureErrorState {
    policy: Policy,
    active_fault: Option<usize>,
    handler_active: bool,
    directly_invoked_by_host: bool,
    gosub_resumptions: Vec<usize>,
}

impl ProcedureErrorState {
    pub fn new(directly_invoked_by_host: bool) -> Self {
        Self {
            policy: Policy::Default,
            active_fault: None,
            handler_active: false,
            directly_invoked_by_host,
            gosub_resumptions: Vec::new(),
        }
    }

    /// Executing `On Error` resets `Err`; `GoTo 0` disables the current handler.
    pub fn configure(&mut self, mode: OnErrorMode) {
        match mode {
            OnErrorMode::ResumeNext => self.policy = Policy::ResumeNext,
            OnErrorMode::GoToLabel(label) => self.policy = Policy::GoTo(label),
            OnErrorMode::Disable => self.policy = Policy::Default,
            OnErrorMode::ClearActiveError => {
                self.active_fault = None;
                self.handler_active = false;
            }
            OnErrorMode::Unknown => self.policy = Policy::Unknown,
        }
        self.active_fault = None;
        self.handler_active = false;
    }

    /// Route one possible fault according to this activation's current policy.
    pub fn raise(&mut self, fault: usize) -> ErrorTransfer {
        if self.handler_active {
            return self.unhandled(fault);
        }
        match &self.policy {
            Policy::ResumeNext => ErrorTransfer::ContinueAfterFault { fault },
            Policy::GoTo(label) => {
                let label = label.clone();
                self.active_fault = Some(fault);
                self.handler_active = true;
                ErrorTransfer::TransferToHandler { label, fault }
            }
            Policy::Default | Policy::Unknown => self.unhandled(fault),
        }
    }

    /// A `Resume` is valid only while this activation is handling an active error.
    pub fn resume(&mut self, mode: ResumeMode) -> ResumeTransfer {
        let Some(fault) = self.active_fault else {
            return ResumeTransfer::ResumeWithoutActiveError;
        };
        self.active_fault = None;
        self.handler_active = false;
        match mode {
            ResumeMode::RetryFault => ResumeTransfer::Retry { fault },
            ResumeMode::NextStatement => ResumeTransfer::ContinueAfterFault { fault },
            ResumeMode::GoToLabel(label) => ResumeTransfer::GoToLabel { label, fault },
        }
    }

    pub fn handler_is_active(&self) -> bool {
        self.handler_active
    }

    pub fn active_fault(&self) -> Option<usize> {
        self.active_fault
    }

    fn unhandled(&self, fault: usize) -> ErrorTransfer {
        if self.directly_invoked_by_host {
            ErrorTransfer::TerminateHost { fault }
        } else {
            ErrorTransfer::PropagateToCaller { fault }
        }
    }
}

/// Add conservative possible-fault transfers to a structural procedure CFG.
/// Policy state is propagated over known control-flow edges. Faultability and
/// host/runtime error behavior remain an over-approximation.
pub fn add_error_flow_edges(graph: &mut ControlFlowGraph, max_states: usize) {
    add_error_flow_edges_with_host_entry_candidate(graph, max_states, false);
}

/// Seed both possible invocation contexts for a recognized host-entry
/// candidate: a direct host activation starts with Terminate, while a normal
/// VBA call starts with Default. The graph remains incomplete because the
/// entry-point candidate does not prove which activation created this graph.
pub fn add_error_flow_edges_with_host_entry_candidate(
    graph: &mut ControlFlowGraph,
    max_states: usize,
    host_entry_candidate: bool,
) {
    let _ = add_error_flow_edges_with_host_entry_candidate_and_findings(
        graph,
        max_states,
        host_entry_candidate,
    );
}

/// Add possible error transfers and return findings discovered while propagating
/// per-activation policy state. A finding records only a modeled reachable
/// state; possible statement faultability and path feasibility remain unknown.
pub fn add_error_flow_edges_with_host_entry_candidate_and_findings(
    graph: &mut ControlFlowGraph,
    max_states: usize,
    host_entry_candidate: bool,
) -> Vec<ErrorFlowFinding> {
    let mut findings = Vec::new();
    let mut reported_resume_nodes = HashSet::new();
    let mut reported_return_nodes = HashSet::new();
    let resume_nodes = graph
        .nodes
        .iter()
        .filter(|node| node.kind == "resume")
        .map(|node| node.id)
        .collect::<HashSet<_>>();
    let mut resume_fallthroughs = HashMap::new();
    for node in &resume_nodes {
        resume_fallthroughs.insert(
            *node,
            graph
                .edges
                .iter()
                .filter(|edge| edge.from == *node)
                .cloned()
                .collect::<Vec<_>>(),
        );
    }
    graph
        .edges
        .retain(|edge| !resume_nodes.contains(&edge.from));
    let base_edges = graph.edges.clone();
    let mut base_outgoing: HashMap<usize, Vec<usize>> = HashMap::new();
    for (edge_index, edge) in base_edges.iter().enumerate() {
        base_outgoing.entry(edge.from).or_default().push(edge_index);
    }
    let mut labels = HashMap::new();
    for node in &graph.nodes {
        if node.kind == "label" {
            labels.insert(canon(&node.label), node.id);
        }
    }
    let mut queue = VecDeque::from([(graph.entry, ProcedureErrorState::new(false))]);
    if host_entry_candidate {
        queue.push_back((graph.entry, ProcedureErrorState::new(true)));
        graph.complete = false;
    }
    let mut visited = HashSet::new();
    while let Some((node_id, mut state)) = queue.pop_front() {
        if !visited.insert((node_id, state.clone())) {
            continue;
        }
        if visited.len() > max_states {
            graph.complete = false;
            break;
        }
        let Some(node) = graph.nodes.get(node_id) else {
            graph.complete = false;
            continue;
        };
        if node.kind == "on_error" {
            match parse_on_error_mode(&node.label) {
                Some(OnErrorMode::GoToLabel(label)) => {
                    if labels.contains_key(&canon(&label)) {
                        state.configure(OnErrorMode::GoToLabel(label));
                    } else {
                        state.configure(OnErrorMode::Unknown);
                        graph.complete = false;
                    }
                }
                Some(mode) => state.configure(mode),
                None => {
                    state.configure(OnErrorMode::Unknown);
                    graph.complete = false;
                }
            }
        }
        if node.kind == "resume" {
            match state.resume(parse_resume_mode(&node.label)) {
                ResumeTransfer::Retry { fault } => add_error_edge(
                    graph,
                    node_id,
                    fault,
                    "Resume retries the faulting statement".into(),
                    &mut queue,
                    state,
                ),
                ResumeTransfer::ContinueAfterFault { fault } => {
                    let successors =
                        resume_fallthroughs.get(&fault).cloned().unwrap_or_else(|| {
                            base_outgoing
                                .get(&fault)
                                .into_iter()
                                .flatten()
                                .map(|edge_index| base_edges[*edge_index].clone())
                                .collect::<Vec<_>>()
                        });
                    if successors.is_empty() {
                        graph.complete = false;
                    }
                    for successor in successors {
                        let condition = format!(
                            "Resume Next continues after fault node {fault}{}",
                            successor
                                .condition
                                .map(|condition| format!(" when {condition}"))
                                .unwrap_or_default()
                        );
                        add_error_edge(
                            graph,
                            node_id,
                            successor.to,
                            condition,
                            &mut queue,
                            state.clone(),
                        );
                    }
                }
                ResumeTransfer::GoToLabel { label, .. } => {
                    if let Some(target) = labels.get(&canon(&label)).copied() {
                        add_error_edge(
                            graph,
                            node_id,
                            target,
                            format!("Resume transfers to {label}"),
                            &mut queue,
                            state,
                        );
                    } else {
                        graph.complete = false;
                    }
                }
                ResumeTransfer::ResumeWithoutActiveError => {
                    if reported_resume_nodes.insert(node_id) {
                        findings.push(ErrorFlowFinding {
                            node_id,
                            kind: ErrorFlowFindingKind::ResumeWithoutActiveError,
                        });
                    }
                    graph.complete = false;
                    route_fault(
                        &mut ErrorGraphContext {
                            graph,
                            labels: &labels,
                            base_edges: &base_edges,
                            base_outgoing: &base_outgoing,
                            resume_fallthroughs: &resume_fallthroughs,
                            queue: &mut queue,
                        },
                        node_id,
                        state,
                    );
                }
            }
            continue;
        }

        if node.kind == "gosub_return" {
            if let Some(continuation) = state.gosub_resumptions.pop() {
                add_error_edge(
                    graph,
                    node_id,
                    continuation,
                    "Return resumes the most recent GoSub".into(),
                    &mut queue,
                    state,
                );
            } else {
                if reported_return_nodes.insert(node_id) {
                    findings.push(ErrorFlowFinding {
                        node_id,
                        kind: ErrorFlowFindingKind::ReturnWithoutGoSub,
                    });
                }
                graph.complete = false;
                route_fault(
                    &mut ErrorGraphContext {
                        graph,
                        labels: &labels,
                        base_edges: &base_edges,
                        base_outgoing: &base_outgoing,
                        resume_fallthroughs: &resume_fallthroughs,
                        queue: &mut queue,
                    },
                    node_id,
                    state,
                );
            }
            continue;
        }

        if matches!(node.kind.as_str(), "gosub" | "on_gosub") {
            let continuation = gosub_continuation(graph, node_id);
            if continuation.is_none() {
                graph.complete = false;
            }
            if let Some(edges) = base_outgoing.get(&node_id) {
                for edge_index in edges {
                    let edge = &base_edges[*edge_index];
                    if continuation == Some(edge.to) && node.kind == "on_gosub" {
                        queue.push_back((edge.to, state.clone()));
                    } else if graph
                        .nodes
                        .get(edge.to)
                        .is_some_and(|target| target.kind == "label")
                    {
                        if let Some(continuation) = continuation {
                            if state.gosub_resumptions.len() >= MAX_GOSUB_RESUMPTION_DEPTH {
                                graph.complete = false;
                                continue;
                            }
                            let mut called = state.clone();
                            called.gosub_resumptions.push(continuation);
                            queue.push_back((edge.to, called));
                        }
                    } else {
                        queue.push_back((edge.to, state.clone()));
                    }
                }
            }
            if may_raise_error(&node.kind) {
                route_fault(
                    &mut ErrorGraphContext {
                        graph,
                        labels: &labels,
                        base_edges: &base_edges,
                        base_outgoing: &base_outgoing,
                        resume_fallthroughs: &resume_fallthroughs,
                        queue: &mut queue,
                    },
                    node_id,
                    state,
                );
            }
            continue;
        }

        if let Some(edges) = base_outgoing.get(&node_id) {
            for edge_index in edges {
                queue.push_back((base_edges[*edge_index].to, state.clone()));
            }
        }
        if may_raise_error(&node.kind) {
            route_fault(
                &mut ErrorGraphContext {
                    graph,
                    labels: &labels,
                    base_edges: &base_edges,
                    base_outgoing: &base_outgoing,
                    resume_fallthroughs: &resume_fallthroughs,
                    queue: &mut queue,
                },
                node_id,
                state,
            );
        }
    }
    findings
}

struct ErrorGraphContext<'a> {
    graph: &'a mut ControlFlowGraph,
    labels: &'a HashMap<String, usize>,
    base_edges: &'a [FlowEdge],
    base_outgoing: &'a HashMap<usize, Vec<usize>>,
    resume_fallthroughs: &'a HashMap<usize, Vec<FlowEdge>>,
    queue: &'a mut VecDeque<(usize, ProcedureErrorState)>,
}

fn route_fault(context: &mut ErrorGraphContext<'_>, source: usize, mut state: ProcedureErrorState) {
    match state.raise(source) {
        ErrorTransfer::ContinueAfterFault { fault } => {
            let successors = match context
                .graph
                .nodes
                .get(fault)
                .map(|node| node.kind.as_str())
            {
                Some("gosub" | "on_gosub") => gosub_continuation(context.graph, fault)
                    .map(|to| {
                        vec![FlowEdge {
                            from: fault,
                            to,
                            condition: Some("Resume Next continues after failed GoSub".into()),
                        }]
                    })
                    .unwrap_or_default(),
                Some("gosub_return") => gosub_return_fallthrough(context.graph, fault)
                    .map(|to| {
                        vec![FlowEdge {
                            from: fault,
                            to,
                            condition: Some("Resume Next continues after failed Return".into()),
                        }]
                    })
                    .unwrap_or_default(),
                _ => context
                    .resume_fallthroughs
                    .get(&fault)
                    .cloned()
                    .unwrap_or_else(|| {
                        context
                            .base_outgoing
                            .get(&fault)
                            .into_iter()
                            .flatten()
                            .map(|edge_index| context.base_edges[*edge_index].clone())
                            .collect::<Vec<_>>()
                    }),
            };
            for successor in successors {
                let condition = format!(
                    "possible fault; On Error Resume Next{}",
                    successor
                        .condition
                        .map(|condition| format!("; then {condition}"))
                        .unwrap_or_default()
                );
                add_error_edge(
                    context.graph,
                    source,
                    successor.to,
                    condition,
                    context.queue,
                    state.clone(),
                );
            }
        }
        ErrorTransfer::TransferToHandler { label, .. } => {
            if let Some(target) = context.labels.get(&canon(&label)).copied() {
                add_error_edge(
                    context.graph,
                    source,
                    target,
                    format!("possible fault; transfer to handler {label}"),
                    context.queue,
                    state,
                );
            } else {
                context.graph.complete = false;
                let exit = context.graph.exit;
                add_error_edge(
                    context.graph,
                    source,
                    exit,
                    "possible fault; unresolved error handler".into(),
                    context.queue,
                    state,
                );
            }
        }
        ErrorTransfer::PropagateToCaller { .. } => {
            let exit = context.graph.exit;
            add_error_edge(
                context.graph,
                source,
                exit,
                "possible unhandled error leaves this procedure".into(),
                context.queue,
                state,
            );
        }
        ErrorTransfer::TerminateHost { .. } => {
            let exit = context.graph.exit;
            add_error_edge(
                context.graph,
                source,
                exit,
                "possible unhandled error terminates host entry".into(),
                context.queue,
                state,
            );
        }
    }
}

fn add_error_edge(
    graph: &mut ControlFlowGraph,
    from: usize,
    to: usize,
    condition: String,
    queue: &mut VecDeque<(usize, ProcedureErrorState)>,
    state: ProcedureErrorState,
) {
    graph.edges.push(FlowEdge {
        from,
        to,
        condition: Some(condition),
    });
    queue.push_back((to, state));
}

fn gosub_continuation(graph: &ControlFlowGraph, call_node: usize) -> Option<usize> {
    let span = graph.nodes.get(call_node)?.span;
    let mut candidates = graph
        .nodes
        .iter()
        .filter(|node| node.kind == "gosub_resume" && node.span == span)
        .map(|node| node.id);
    let candidate = candidates.next()?;
    candidates.next().is_none().then_some(candidate)
}

fn gosub_return_fallthrough(graph: &ControlFlowGraph, return_node: usize) -> Option<usize> {
    let span = graph.nodes.get(return_node)?.span;
    let mut candidates = graph
        .nodes
        .iter()
        .filter(|node| node.kind == "gosub_return_next" && node.span == span)
        .map(|node| node.id);
    let candidate = candidates.next()?;
    candidates.next().is_none().then_some(candidate)
}

fn parse_on_error_mode(text: &str) -> Option<OnErrorMode> {
    let low = text.trim().to_ascii_lowercase();
    if low == "on error resume next" {
        Some(OnErrorMode::ResumeNext)
    } else if low == "on error goto 0" {
        Some(OnErrorMode::Disable)
    } else if low == "on error goto -1" {
        Some(OnErrorMode::ClearActiveError)
    } else if low.starts_with("on error goto ") {
        low.split_whitespace()
            .nth(3)
            .map(|label| OnErrorMode::GoToLabel(label.to_owned()))
    } else {
        None
    }
}

fn parse_resume_mode(text: &str) -> ResumeMode {
    let low = text.trim().to_ascii_lowercase();
    if low == "resume next" {
        ResumeMode::NextStatement
    } else if low == "resume" || low == "resume 0" {
        ResumeMode::RetryFault
    } else {
        ResumeMode::GoToLabel(low.split_whitespace().nth(1).unwrap_or("").to_owned())
    }
}

pub(crate) fn may_raise_error(kind: &str) -> bool {
    matches!(
        kind,
        "assignment"
            | "call"
            | "call_or_expression"
            | "raise_event"
            | "redim"
            | "erase"
            | "declaration"
            | "decision"
            | "case_test"
            | "select_expression"
            | "loop_test"
            | "with"
            | "unknown"
            | "gosub"
            | "gosub_return"
            | "on_goto"
            | "on_gosub"
    )
}

fn canon(text: &str) -> String {
    canonical_statement_label(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{flow::build_graph, parser::parse_module};

    #[test]
    fn distinguishes_resume_next_from_goto_handler_and_active_handler_failure() {
        let mut state = ProcedureErrorState::new(false);
        state.configure(OnErrorMode::ResumeNext);
        assert_eq!(
            state.raise(3),
            ErrorTransfer::ContinueAfterFault { fault: 3 }
        );

        state.configure(OnErrorMode::GoToLabel("Handler".into()));
        assert_eq!(
            state.raise(8),
            ErrorTransfer::TransferToHandler {
                label: "Handler".into(),
                fault: 8
            }
        );
        assert!(state.handler_is_active());
        assert_eq!(
            state.raise(9),
            ErrorTransfer::PropagateToCaller { fault: 9 }
        );
        assert_eq!(
            state.resume(ResumeMode::NextStatement),
            ResumeTransfer::ContinueAfterFault { fault: 8 }
        );
        assert!(!state.handler_is_active());
        assert_eq!(
            state.raise(10),
            ErrorTransfer::TransferToHandler {
                label: "Handler".into(),
                fault: 10
            }
        );
    }

    #[test]
    fn default_error_policy_depends_on_host_entry_and_go_to_zero_disables_handler() {
        let mut called = ProcedureErrorState::new(false);
        assert_eq!(
            called.raise(1),
            ErrorTransfer::PropagateToCaller { fault: 1 }
        );
        called.configure(OnErrorMode::GoToLabel("E".into()));
        let _ = called.raise(2);
        let _ = called.resume(ResumeMode::RetryFault);
        called.configure(OnErrorMode::Disable);
        assert_eq!(
            called.raise(3),
            ErrorTransfer::PropagateToCaller { fault: 3 }
        );

        let mut host = ProcedureErrorState::new(true);
        assert_eq!(host.raise(4), ErrorTransfer::TerminateHost { fault: 4 });
        assert_eq!(
            called.resume(ResumeMode::RetryFault),
            ResumeTransfer::ResumeWithoutActiveError
        );
    }

    #[test]
    fn augments_cfg_with_possible_handler_and_resume_edges() {
        let source = "Public Sub Work()\nOn Error GoTo Handler\nFail()\nvalue = 1\nExit Sub\nHandler:\nLogError()\nResume Next\nEnd Sub\n";
        let module = parse_module("M", "M.bas", source, 10000, 100);
        let mut graph = build_graph(&module, &module.procedures[0]);
        let fault = graph
            .nodes
            .iter()
            .find(|node| node.kind == "call_or_expression" && node.span.line == 3)
            .unwrap()
            .id;
        let handler = graph
            .nodes
            .iter()
            .find(|node| node.kind == "label" && node.label == "Handler")
            .unwrap()
            .id;
        let resume = graph
            .nodes
            .iter()
            .find(|node| node.kind == "resume")
            .unwrap()
            .id;
        let after_fault = graph
            .nodes
            .iter()
            .find(|node| node.kind == "assignment" && node.span.line == 4)
            .unwrap()
            .id;

        add_error_flow_edges(&mut graph, 10000);

        assert!(graph.edges.iter().any(|edge| {
            edge.from == fault
                && edge.to == handler
                && edge
                    .condition
                    .as_deref()
                    .is_some_and(|condition| condition.contains("possible fault"))
        }));
        assert!(graph.edges.iter().any(|edge| {
            edge.from == resume
                && edge.to == after_fault
                && edge
                    .condition
                    .as_deref()
                    .is_some_and(|condition| condition.contains("Resume Next"))
        }));
        assert!(!graph.edges.iter().any(|edge| {
            edge.from == resume && edge.to == graph.exit && edge.condition.is_none()
        }));
        assert!(graph.edges.iter().any(|edge| {
            edge.from != graph.exit
                && edge.to == graph.exit
                && edge
                    .condition
                    .as_deref()
                    .is_some_and(|condition| condition.contains("leaves this procedure"))
        }));
        assert!(!graph.complete);
    }
    #[test]
    fn resume_next_policy_adds_a_possible_fault_edge_to_the_next_statement() {
        let source = "Public Sub Work()\nOn Error Resume Next\nFail()\nvalue = 1\nEnd Sub\n";
        let module = parse_module("M", "M.bas", source, 10000, 100);
        let mut graph = build_graph(&module, &module.procedures[0]);
        let fault = graph
            .nodes
            .iter()
            .find(|node| node.kind == "call_or_expression" && node.span.line == 3)
            .unwrap()
            .id;
        let next_statement = graph
            .nodes
            .iter()
            .find(|node| node.kind == "assignment" && node.span.line == 4)
            .unwrap()
            .id;
        add_error_flow_edges(&mut graph, 10000);
        assert!(graph.edges.iter().any(|edge| {
            edge.from == fault
                && edge.to == next_statement
                && edge
                    .condition
                    .as_deref()
                    .is_some_and(|c| c.contains("Resume Next"))
        }));
    }
    #[test]
    fn invalid_resume_under_resume_next_policy_uses_resume_fallthrough() {
        let source = "Public Sub Work()\nOn Error Resume Next\nResume Next\nvalue = 1\nEnd Sub\n";
        let module = parse_module("M", "M.bas", source, 10000, 100);
        let mut graph = build_graph(&module, &module.procedures[0]);
        let resume = graph
            .nodes
            .iter()
            .find(|node| node.kind == "resume")
            .unwrap()
            .id;
        let next_statement = graph
            .nodes
            .iter()
            .find(|node| node.kind == "assignment" && node.span.line == 4)
            .unwrap()
            .id;
        add_error_flow_edges(&mut graph, 10000);
        assert!(graph.edges.iter().any(|edge| {
            edge.from == resume
                && edge.to == next_statement
                && edge
                    .condition
                    .as_deref()
                    .is_some_and(|c| c.contains("Resume Next"))
        }));
    }

    #[test]
    fn preserves_gosub_resumption_stack_through_error_handler_resume_next() {
        let source = "Public Sub Work()\nOn Error GoTo Handler\nGoSub Worker\nafterCall = 1\nExit Sub\nWorker:\nFail()\nReturn\nHandler:\nResume Next\nEnd Sub\n";
        let module = parse_module("M", "M.bas", source, 10000, 100);
        let mut graph = build_graph(&module, &module.procedures[0]);
        let gosub = graph
            .nodes
            .iter()
            .find(|node| node.kind == "gosub")
            .unwrap()
            .id;
        let fault = graph
            .nodes
            .iter()
            .find(|node| node.kind == "call_or_expression" && node.span.line == 7)
            .unwrap()
            .id;
        let return_node = graph
            .nodes
            .iter()
            .find(|node| node.kind == "gosub_return")
            .unwrap()
            .id;
        let handler = graph
            .nodes
            .iter()
            .find(|node| node.kind == "label" && node.label == "Handler")
            .unwrap()
            .id;
        let resume = graph
            .nodes
            .iter()
            .find(|node| node.kind == "resume")
            .unwrap()
            .id;
        let continuation = graph
            .nodes
            .iter()
            .find(|node| node.kind == "gosub_resume")
            .unwrap()
            .id;

        add_error_flow_edges(&mut graph, 10000);

        assert!(graph.edges.iter().any(|edge| {
            edge.from == fault
                && edge.to == handler
                && edge
                    .condition
                    .as_deref()
                    .is_some_and(|condition| condition.contains("possible fault"))
        }));
        assert!(graph.edges.iter().any(|edge| {
            edge.from == resume
                && edge.to == return_node
                && edge
                    .condition
                    .as_deref()
                    .is_some_and(|condition| condition.contains("Resume Next"))
        }));
        assert!(graph.edges.iter().any(|edge| {
            edge.from == return_node
                && edge.to == continuation
                && edge.condition.as_deref() == Some("Return resumes the most recent GoSub")
        }));
        assert!(!graph.complete);
        assert!(graph.nodes[gosub].kind == "gosub");
    }

    #[test]
    fn resume_next_after_failed_gosub_skips_its_target_and_continues_after_the_call() {
        let source = "Public Sub Work()\nOn Error Resume Next\nGoSub Worker\nafterCall = 1\nExit Sub\nWorker:\nReturn\nEnd Sub\n";
        let module = parse_module("M", "M.bas", source, 10000, 100);
        let mut graph = build_graph(&module, &module.procedures[0]);
        let gosub = graph
            .nodes
            .iter()
            .find(|node| node.kind == "gosub")
            .unwrap()
            .id;
        let continuation = graph
            .nodes
            .iter()
            .find(|node| node.kind == "gosub_resume")
            .unwrap()
            .id;
        add_error_flow_edges(&mut graph, 10000);
        assert!(graph.edges.iter().any(|edge| {
            edge.from == gosub
                && edge.to == continuation
                && edge.condition.as_deref().is_some_and(|condition| {
                    condition.contains("Resume Next continues after failed GoSub")
                })
        }));
        assert!(!graph.complete);
    }
}
