use crate::host::HostProfile;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub line: u32,
    pub column: u32,
}

impl Span {
    pub fn join(self, other: Span) -> Span {
        Span {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
            line: self.line,
            column: self.column,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Severity {
    Note,
    Warning,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Diagnostic {
    pub code: &'static str,
    pub severity: Severity,
    pub message: String,
    pub source: String,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct Limits {
    pub max_input_bytes: usize,
    pub max_decompressed_bytes: usize,
    pub max_zip_entries: usize,
    pub max_cfb_sectors: usize,
    pub max_modules: usize,
    pub max_tokens: usize,
    pub max_nesting: usize,
}

impl Limits {
    pub fn bounded() -> Self {
        Self {
            max_input_bytes: 128 * 1024 * 1024,
            max_decompressed_bytes: 64 * 1024 * 1024,
            max_zip_entries: 16_384,
            max_cfb_sectors: 262_144,
            max_modules: 4_096,
            max_tokens: 4_000_000,
            max_nesting: 512,
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::bounded()
    }
}

#[derive(Clone, Debug)]
pub struct SourceUnit {
    pub name: String,
    pub text: String,
}

#[derive(Clone, Debug, Default)]
pub struct Project {
    pub name: Option<String>,
    pub modules: Vec<Module>,
    pub references: Vec<String>,
    pub code_page: Option<u16>,
    pub system_kind: Option<u32>,
    pub conditional_constants: BTreeMap<String, String>,
    pub input_kind: String,
    pub code_executed: bool,
    pub compiled_representation_verified: bool,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default)]
pub struct Module {
    pub name: String,
    pub source_name: String,
    pub text: String,
    pub analysis_text: String,
    pub procedures: Vec<Procedure>,
    pub declarations: Vec<Declaration>,
    pub statements: Vec<Statement>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Clone, Debug, Default)]
pub struct Procedure {
    pub name: String,
    pub kind: String,
    pub return_type: Option<String>,
    pub parameters: Vec<Parameter>,
    pub span: Span,
    pub statements: Vec<Statement>,
    pub visibility: String,
    pub is_static: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Parameter {
    pub name: String,
    pub type_name: Option<String>,
    pub passing: String,
    pub optional: bool,
    pub is_param_array: bool,
    pub default_value: Option<String>,
    pub span: Span,
}

#[derive(Clone, Debug, Default)]
pub struct Declaration {
    pub name: String,
    pub type_name: Option<String>,
    pub kind: String,
    pub visibility: String,
    pub span: Span,
    pub initializer: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct Statement {
    pub kind: String,
    pub expression: Option<String>,
    pub parsed_expression: Option<Expr>,
    pub exit_condition: Option<String>,
    pub declaration: Option<Declaration>,
    pub span: Span,
    pub children: Vec<Statement>,
}

#[derive(Clone, Debug)]
pub enum Expr {
    Identifier(String, Span),
    Literal(String, LiteralKind, Span),
    Unary {
        op: String,
        value: Box<Expr>,
        span: Span,
    },
    Binary {
        left: Box<Expr>,
        op: String,
        right: Box<Expr>,
        span: Span,
    },
    Member {
        object: Box<Expr>,
        member: String,
        span: Span,
    },
    Call {
        callee: Box<Expr>,
        args: Vec<Expr>,
        span: Span,
    },
    NamedArgument {
        name: String,
        value: Box<Expr>,
        span: Span,
    },
    Group(Box<Expr>, Span),
    Unknown(String, Span),
}

impl Expr {
    pub fn span(&self) -> Span {
        match self {
            Self::Identifier(_, s)
            | Self::Literal(_, _, s)
            | Self::Group(_, s)
            | Self::Unknown(_, s) => *s,
            Self::Unary { span, .. }
            | Self::Binary { span, .. }
            | Self::Member { span, .. }
            | Self::Call { span, .. } => *span,
            Self::NamedArgument { span, .. } => *span,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiteralKind {
    Number,
    String,
    Date,
}

#[derive(Clone, Debug, Default)]
pub struct Analysis {
    pub project: Project,
    pub diagnostics: Vec<Diagnostic>,
    pub procedures: Vec<ProcedureFact>,
    pub references: Vec<ReferenceFact>,
    pub calls: Vec<CallFact>,
    pub data_accesses: Vec<DataAccessFact>,
    pub semantic_analysis_complete: bool,
    pub control_flow: Vec<ControlFlowGraph>,
    pub data_flow: Vec<DataFlowFact>,
    pub type_facts: Vec<TypeFact>,
    pub error_handling: Vec<ErrorHandlingFact>,
    pub host_profile: HostProfile,
}

#[derive(Clone, Debug, Default)]
pub struct ErrorHandlingFact {
    pub module: String,
    pub procedure: String,
    pub operation: String,
    pub target: Option<String>,
    pub target_resolved: Option<bool>,
    pub path_state_verified: bool,
    pub span: Span,
}

#[derive(Clone, Debug, Default)]
pub struct TypeFact {
    pub module: String,
    pub procedure: Option<String>,
    pub target: String,
    pub target_type: Option<String>,
    pub value_type: String,
    pub status: String,
    pub span: Span,
}

#[derive(Clone, Debug, Default)]
pub struct DataFlowFact {
    pub module: String,
    pub procedure: Option<String>,
    pub target: String,
    pub inputs: Vec<String>,
    pub transfer: String,
    pub span: Span,
}

#[derive(Clone, Debug, Default)]
pub struct ControlFlowGraph {
    pub module: String,
    pub procedure: String,
    pub nodes: Vec<FlowNode>,
    pub edges: Vec<FlowEdge>,
    pub entry: usize,
    pub exit: usize,
    pub complete: bool,
}

#[derive(Clone, Debug, Default)]
pub struct FlowNode {
    pub id: usize,
    pub kind: String,
    pub label: String,
    pub span: Span,
}

#[derive(Clone, Debug, Default)]
pub struct FlowEdge {
    pub from: usize,
    pub to: usize,
    pub condition: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct ProcedureFact {
    pub module: String,
    pub name: String,
    pub kind: String,
    pub visibility: String,
    pub span: Span,
}

#[derive(Clone, Debug, Default)]
pub struct ReferenceFact {
    pub module: String,
    pub procedure: Option<String>,
    pub name: String,
    pub resolution: String,
    pub span: Span,
}

#[derive(Clone, Debug, Default)]
pub struct CallFact {
    pub module: String,
    pub procedure: Option<String>,
    pub target: String,
    pub resolution: String,
    pub argument_count: Option<usize>,
    pub arguments: Vec<String>,
    pub span: Span,
}

#[derive(Clone, Debug, Default)]
pub struct DataAccessFact {
    pub module: String,
    pub procedure: Option<String>,
    pub operation: String,
    pub target: String,
    pub host_dependent: bool,
    pub span: Span,
}
