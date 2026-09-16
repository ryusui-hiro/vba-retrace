use crate::host::HostProfile;
use std::collections::BTreeMap;

pub(crate) const MAX_GOSUB_RESUMPTION_STATES: usize = 100_000;
pub(crate) const MAX_GOSUB_RESUMPTION_DEPTH: usize = 64;

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

pub(crate) fn canonical_statement_label(label: &str) -> String {
    let label = label.trim().trim_end_matches(':');
    if !label.is_empty() && label.bytes().all(|byte| byte.is_ascii_digit()) {
        let number = label
            .parse::<u64>()
            .map(|value| value.to_string())
            .unwrap_or_else(|_| {
                let without_zeroes = label.trim_start_matches('0');
                if without_zeroes.is_empty() {
                    "0".into()
                } else {
                    without_zeroes.into()
                }
            });
        format!("line:{number}")
    } else {
        format!(
            "name:{}",
            label
                .trim_end_matches(['%', '&', '^', '@', '!', '#', '$'])
                .to_ascii_lowercase()
        )
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
    /// Maximum populated worksheet cells retained from an `.xlsm` workbook.
    pub max_workbook_cells: usize,
    /// Maximum worksheet tables retained from an `.xlsm` workbook.
    pub max_workbook_tables: usize,
    /// Maximum worksheet-access to cell-inventory links emitted per project.
    pub max_workbook_cell_links: usize,
    /// Maximum formula reference candidates retained across an extracted workbook.
    pub max_workbook_formula_references: usize,
    /// Maximum formula-reference to populated-cell links emitted per workbook.
    pub max_workbook_formula_cell_links: usize,
    pub max_cfb_sectors: usize,
    pub max_modules: usize,
    pub max_tokens: usize,
    pub max_nesting: usize,
    pub max_paths: usize,
    pub max_path_depth: usize,
    /// Maximum transfer-to-path records for each fact family.
    pub max_path_fact_associations: usize,
    /// Maximum graph-node containment checks for path-fact associations.
    pub max_path_fact_association_steps: usize,
    /// Maximum path-specific simple-variable definition-use links.
    pub max_path_value_flows: usize,
    /// Maximum input names examined while deriving path value links.
    pub max_path_value_flow_steps: usize,
    /// Maximum same-statement links between data access and value facts.
    pub max_data_access_value_flows: usize,
    /// Maximum data-access/value fact pairs examined while linking them.
    pub max_data_access_value_flow_steps: usize,
}

impl Limits {
    pub fn bounded() -> Self {
        Self {
            max_input_bytes: 128 * 1024 * 1024,
            max_decompressed_bytes: 64 * 1024 * 1024,
            max_zip_entries: 16_384,
            max_workbook_cells: 100_000,
            max_workbook_tables: 16_384,
            max_workbook_cell_links: 200_000,
            max_workbook_formula_references: 200_000,
            max_workbook_formula_cell_links: 200_000,
            max_cfb_sectors: 262_144,
            max_modules: 4_096,
            max_tokens: 4_000_000,
            max_nesting: 512,
            max_paths: 256,
            max_path_depth: 128,
            max_path_fact_associations: 65_536,
            max_path_fact_association_steps: 2_000_000,
            max_path_value_flows: 65_536,
            max_path_value_flow_steps: 1_000_000,
            max_data_access_value_flows: 65_536,
            max_data_access_value_flow_steps: 1_000_000,
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

/// Sheet identity metadata extracted from an OOXML workbook package.
///
/// Part resolution remains a structural relationship fact; it does not bind
/// VBA object-model expressions to runtime worksheet instances.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WorkbookSheetInfo {
    pub name: String,
    /// Stable VBA/SpreadsheetML sheet codename when present in `sheetPr`.
    pub code_name: Option<String>,
    pub sheet_id: Option<u32>,
    pub state: Option<String>,
    pub kind: String,
    pub relationship_id: Option<String>,
    pub part_name: Option<String>,
    pub resolution: String,
}

/// Defined-name metadata parsed from the workbook part. Formula text can refer
/// to a range, a formula, a constant, or an external workbook; it is preserved
/// but not evaluated by the extractor.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WorkbookDefinedNameInfo {
    pub name: String,
    pub formula: String,
    pub local_sheet_id: Option<u32>,
    pub local_sheet_name: Option<String>,
    pub hidden: Option<bool>,
    pub built_in: bool,
    pub scope_resolution: String,
    /// Bounded operand-scan result for the stored name formula; not evaluation.
    pub formula_reference_resolution: String,
    pub formula_reference_candidates: Vec<WorkbookFormulaReferenceInfo>,
    pub formula_references_truncated: bool,
}

/// Table metadata stored in a worksheet's related SpreadsheetML table part.
/// Range/column matches remain candidates and never execute a formula.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WorkbookTableInfo {
    pub name: String,
    pub display_name: String,
    pub sheet_index: usize,
    pub sheet_name: String,
    pub part_name: Option<String>,
    pub cell_range_bounds: Option<CellRangeBounds>,
    pub header_row_count: u32,
    pub totals_row_count: u32,
    pub columns: Vec<String>,
    pub resolution: String,
}

/// Stored worksheet cell content and formula metadata from OOXML. Formula
/// cached values are snapshots from the workbook and are never recalculated.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WorkbookCellInfo {
    pub sheet_index: usize,
    pub sheet_name: String,
    pub cell_ref: String,
    pub row: Option<u32>,
    pub column: Option<u32>,
    pub cell_type: String,
    pub formula: Option<String>,
    pub formula_type: Option<String>,
    pub formula_ref: Option<String>,
    pub formula_shared_index: Option<u32>,
    pub stored_value: Option<String>,
    pub value: Option<String>,
    pub resolution: String,
    /// Scope of the bounded formula-address scan; this is not formula validation.
    pub formula_reference_resolution: String,
    /// Workbook-cell index holding the formula text used for the candidate scan.
    /// Shared-formula followers point to the group master.
    pub formula_reference_source_cell_index: Option<usize>,
    pub formula_reference_candidates: Vec<WorkbookFormulaReferenceInfo>,
    pub formula_references_truncated: bool,
}

/// A statically recognized address or defined-name operand in a stored
/// worksheet formula. It describes a candidate dependency only; the formula
/// is not evaluated.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WorkbookFormulaReferenceInfo {
    /// Byte offsets within the parent cell or defined-name formula text. Cell
    /// records identify the source formula cell separately when shared.
    pub start_byte: usize,
    pub end_byte: usize,
    /// Original formula token spelling (or translated shared-formula token).
    pub reference: String,
    pub reference_kind: String,
    pub defined_name_index_candidate: Option<usize>,
    pub defined_name_resolution: Option<String>,
    pub table_index_candidate: Option<usize>,
    pub table_column_index_candidate: Option<usize>,
    pub table_resolution: Option<String>,
    pub table_section: Option<String>,
    pub sheet_selector: Option<String>,
    pub sheet_index_candidate: Option<usize>,
    pub sheet_name_candidate: Option<String>,
    pub sheet_resolution: String,
    pub cell_range_bounds: Option<CellRangeBounds>,
    /// Indices into the workbook cell inventory for matching populated cells.
    pub workbook_cell_indices: Vec<usize>,
    pub workbook_cell_matches_truncated: bool,
}

/// Coordinates for a statically parsed, single-area A1-style range. Bounds
/// are one-based; the range still remains a candidate, not a runtime object.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CellRangeBounds {
    pub first_row: u32,
    pub first_column: u32,
    pub last_row: u32,
    pub last_column: u32,
}

#[derive(Clone, Debug, Default)]
pub struct Module {
    pub name: String,
    pub source_name: String,
    pub module_kind: Option<String>,
    pub predeclared_id: Option<bool>,
    pub global_namespace: Option<bool>,
    pub options: ModuleOptions,
    pub implicit_types: ImplicitTypeRules,
    pub implemented_interfaces: Vec<String>,
    pub text: String,
    pub analysis_text: String,
    pub procedures: Vec<Procedure>,
    pub declarations: Vec<Declaration>,
    pub conditional_constants: BTreeMap<String, String>,
    pub statements: Vec<Statement>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImplicitTypeRules {
    pub by_initial: BTreeMap<char, String>,
    pub universal_type: Option<String>,
    pub valid: bool,
}

impl Default for ImplicitTypeRules {
    fn default() -> Self {
        Self {
            by_initial: BTreeMap::new(),
            universal_type: None,
            valid: true,
        }
    }
}

impl ImplicitTypeRules {
    pub fn type_for_identifier(&self, name: &str) -> Option<String> {
        if !self.valid {
            return None;
        }
        if let Some(type_name) = &self.universal_type {
            return Some(type_name.clone());
        }
        let first = name.chars().next()?.to_ascii_uppercase();
        self.by_initial.get(&first).cloned()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleOptions {
    pub explicit: bool,
    pub compare_mode: String,
    pub compare_explicit: bool,
    pub compare_valid: bool,
    pub array_base: u8,
    pub array_base_explicit: bool,
    pub array_base_valid: bool,
    pub private_module: bool,
}

impl Default for ModuleOptions {
    fn default() -> Self {
        Self {
            explicit: false,
            compare_mode: "Binary".into(),
            compare_explicit: false,
            compare_valid: true,
            array_base: 0,
            array_base_explicit: false,
            array_base_valid: true,
            private_module: false,
        }
    }
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
    pub automation_member_id: Option<i32>,
}

#[derive(Clone, Debug, Default)]
pub struct Parameter {
    pub name: String,
    pub type_name: Option<String>,
    pub passing: String,
    pub passing_explicit: bool,
    pub is_array: bool,
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
    /// Folded Long value for an Enum member, when its initializer and any
    /// preceding implicit values are statically supported.
    pub enum_value: Option<i32>,
    pub is_array: bool,
    pub array_dimensions: Vec<ArrayDimension>,
    pub is_ptr_safe: bool,
    pub external_library: Option<String>,
    pub external_alias: Option<String>,
    pub parameters: Vec<Parameter>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ArrayDimension {
    pub lower_bound: Option<String>,
    pub upper_bound: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct CaseRange {
    pub kind: String,
    pub expression: Option<String>,
    pub parsed_expression: Option<Expr>,
    pub start_value: Option<String>,
    pub parsed_start_value: Option<Expr>,
    pub end_value: Option<String>,
    pub parsed_end_value: Option<Expr>,
    pub comparison_operator: Option<String>,
    pub span: Span,
    pub valid: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Statement {
    pub kind: String,
    pub expression: Option<String>,
    pub parsed_expression: Option<Expr>,
    pub parsed_target: Option<Expr>,
    pub exit_condition: Option<String>,
    pub declaration: Option<Declaration>,
    pub case_ranges: Vec<CaseRange>,
    pub loop_control_variable: Option<String>,
    pub next_control_variable: Option<String>,
    pub loop_start: Option<String>,
    pub loop_end: Option<String>,
    pub loop_step: Option<String>,
    pub parsed_loop_start: Option<Expr>,
    pub parsed_loop_end: Option<Expr>,
    pub parsed_loop_step: Option<Expr>,
    pub parsed_exit_condition: Option<Expr>,
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
        access: MemberAccessKind,
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
    TypeOfIs {
        expression: Box<Expr>,
        type_name: String,
        type_span: Span,
        span: Span,
    },
    Group(Box<Expr>, Span),
    Unknown(String, Span),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemberAccessKind {
    Dot,
    Bang,
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
            Self::TypeOfIs { span, .. } => *span,
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
    pub excel_worksheet_accesses: Vec<ExcelWorksheetAccessFact>,
    pub semantic_analysis_complete: bool,
    pub control_flow: Vec<ControlFlowGraph>,
    pub data_flow: Vec<DataFlowFact>,
    pub data_flow_paths: Vec<DataFlowPathFact>,
    pub data_flow_paths_truncated: bool,
    pub data_flow_path_unassociated_count: usize,
    pub interprocedural_data_flow_paths: Vec<InterproceduralDataFlowPathFact>,
    pub interprocedural_data_flow_paths_truncated: bool,
    pub interprocedural_argument_value_paths: Vec<InterproceduralArgumentValuePathFact>,
    pub interprocedural_argument_value_paths_truncated: bool,
    pub interprocedural_argument_composition_paths: Vec<InterproceduralArgumentCompositionPathFact>,
    pub interprocedural_argument_composition_paths_truncated: bool,
    pub interprocedural_return_paths: Vec<InterproceduralReturnPathFact>,
    pub interprocedural_return_paths_truncated: bool,
    pub interprocedural_return_compositions: Vec<InterproceduralReturnCompositionPathFact>,
    pub interprocedural_return_compositions_truncated: bool,
    pub interprocedural_byref_write_paths: Vec<InterproceduralByRefWritePathFact>,
    pub interprocedural_byref_write_paths_truncated: bool,
    pub interprocedural_byref_value_paths: Vec<InterproceduralByRefValuePathFact>,
    pub interprocedural_byref_value_paths_truncated: bool,
    pub interprocedural_error_paths: Vec<InterproceduralErrorPathFact>,
    pub interprocedural_error_paths_truncated: bool,
    pub data_access_paths: Vec<DataAccessPathFact>,
    pub data_access_paths_truncated: bool,
    pub data_access_path_unassociated_count: usize,
    pub path_value_flows: Vec<PathValueFlowFact>,
    pub path_value_flows_truncated: bool,
    pub path_aliases: Vec<PathAliasFact>,
    pub path_aliases_truncated: bool,
    pub path_alias_dispatches: Vec<PathAliasDispatchFact>,
    pub path_alias_dispatches_truncated: bool,
    pub data_access_value_flows: Vec<DataAccessValueFlowFact>,
    pub data_access_value_flows_truncated: bool,
    pub data_access_predicates: Vec<DataAccessPredicateFact>,
    pub data_access_predicate_unassociated_count: usize,
    pub type_facts: Vec<TypeFact>,
    pub error_handling: Vec<ErrorHandlingFact>,
    pub host_profile: HostProfile,
    pub paths: Vec<ControlFlowPath>,
    pub decision_table: Vec<DecisionRow>,
    pub path_enumeration_truncated: bool,
    pub entry_points: Vec<EntryPointFact>,
}

#[derive(Clone, Debug, Default)]
pub struct EntryPointFact {
    pub module: String,
    pub procedure: String,
    pub trigger: String,
    pub reason: String,
    pub span: Span,
}

#[derive(Clone, Debug, Default)]
pub struct ControlFlowPath {
    pub module: String,
    pub procedure: String,
    pub nodes: Vec<usize>,
    pub conditions: Vec<String>,
    pub stop_reason: String,
    pub feasibility: String,
    pub complete: bool,
}

#[derive(Clone, Debug, Default)]
pub struct DecisionRow {
    pub module: String,
    pub procedure: String,
    pub conditions: Vec<String>,
    pub actions: Vec<String>,
    pub outcome: String,
    pub feasibility: String,
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
    /// Zero-based positional slot when this fact represents one actual value
    /// supplied to a `ParamArray`; ordinary arguments and non-argument facts
    /// leave this unset.  Keeping the slot on the source fact prevents equal
    /// textual expressions in different slots from being cross-associated.
    pub argument_slot_index: Option<usize>,
    /// Source expression used when a call supplies a declaration default
    /// instead of an explicit argument; JSON reveals it only with source
    /// disclosure enabled.
    pub value_expression: Option<String>,
    pub call_callee_module: Option<String>,
    pub call_callee_procedure: Option<String>,
    pub span: Span,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DataFlowPathFact {
    pub data_flow_index: usize,
    pub path_index: usize,
    pub path_position: usize,
    pub flow_node_id: usize,
    pub module: String,
    pub procedure: String,
    pub conditions: Vec<String>,
    pub feasibility: String,
    pub path_complete: bool,
    pub span: Span,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InterproceduralDataFlowPathFact {
    pub argument_data_flow_index: usize,
    pub callee_use_data_flow_index: usize,
    pub caller_path_index: usize,
    pub caller_path_position: usize,
    pub callee_path_index: usize,
    pub callee_path_position: usize,
    pub caller_module: String,
    pub caller_procedure: String,
    pub callee_module: String,
    pub callee_procedure: String,
    pub parameter: String,
    pub caller_conditions: Vec<String>,
    pub callee_conditions: Vec<String>,
    pub feasibility: String,
    pub caller_path_complete: bool,
    pub callee_path_complete: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InterproceduralArgumentValuePathFact {
    pub argument_data_flow_index: usize,
    pub argument_slot_index: Option<usize>,
    pub caller_call_index: Option<usize>,
    pub caller_path_index: usize,
    pub caller_path_position: usize,
    pub caller_module: String,
    pub caller_procedure: String,
    pub callee_module: String,
    pub callee_procedure: String,
    pub parameter: String,
    pub actual_expression: Option<String>,
    pub resolved_value: Option<String>,
    pub resolution: String,
    pub conditions: Vec<String>,
    pub feasibility: String,
    pub path_complete: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InterproceduralArgumentCompositionPathFact {
    pub argument_data_flow_index: usize,
    pub argument_slot_index: Option<usize>,
    pub caller_call_index: Option<usize>,
    pub caller_path_index: usize,
    pub caller_path_position: usize,
    pub callee_path_index: usize,
    pub callee_path_position: usize,
    pub caller_module: String,
    pub caller_procedure: String,
    pub callee_module: String,
    pub callee_procedure: String,
    pub parameter: String,
    pub actual_expression: Option<String>,
    pub resolved_value: Option<String>,
    pub caller_conditions: Vec<String>,
    pub callee_conditions: Vec<String>,
    pub caller_feasibility: String,
    pub callee_feasibility: String,
    pub feasibility: String,
    pub caller_path_complete: bool,
    pub callee_path_complete: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InterproceduralReturnPathFact {
    pub caller_return_data_flow_index: usize,
    pub callee_return_data_flow_index: usize,
    pub caller_path_index: usize,
    pub caller_path_position: usize,
    pub callee_path_index: usize,
    pub callee_path_position: usize,
    pub caller_module: String,
    pub caller_procedure: String,
    pub callee_module: String,
    pub callee_procedure: String,
    pub caller_conditions: Vec<String>,
    pub callee_conditions: Vec<String>,
    pub callee_return_expression: Option<String>,
    /// Bounded literal value derived from the callee return expression when
    /// it is independent of unresolved runtime state.
    pub resolved_return_value: Option<String>,
    pub caller_post_return_conditions: Vec<String>,
    pub post_return_feasibility: String,
    pub feasibility: String,
    pub caller_path_complete: bool,
    pub callee_path_complete: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InterproceduralReturnCompositionPathFact {
    pub outer_return_data_flow_index: usize,
    pub inner_return_data_flow_index: usize,
    pub composition_depth: usize,
    pub outer_path_index: usize,
    pub outer_path_position: usize,
    pub intermediate_path_index: usize,
    pub intermediate_path_position: usize,
    pub inner_path_index: usize,
    pub inner_path_position: usize,
    pub outer_module: String,
    pub outer_procedure: String,
    pub intermediate_module: String,
    pub intermediate_procedure: String,
    pub inner_module: String,
    pub inner_procedure: String,
    pub outer_conditions: Vec<String>,
    pub intermediate_conditions: Vec<String>,
    pub inner_conditions: Vec<String>,
    pub inner_return_expression: Option<String>,
    /// Literal value carried through the innermost return assignment when it
    /// can be evaluated without dynamic calls or host state.
    pub resolved_return_value: Option<String>,
    pub outer_post_return_conditions: Vec<String>,
    pub post_return_feasibility: String,
    pub feasibility: String,
    pub outer_path_complete: bool,
    pub intermediate_path_complete: bool,
    pub inner_path_complete: bool,
    /// Full bounded caller-to-leaf chain. The legacy outer/intermediate/inner
    /// fields remain populated for two-hop consumers; longer compositions use
    /// these vectors to retain every wrapper without collapsing identities.
    pub chain_return_data_flow_indices: Vec<usize>,
    pub chain_modules: Vec<String>,
    pub chain_procedures: Vec<String>,
    pub chain_path_indices: Vec<usize>,
    pub chain_path_positions: Vec<usize>,
    pub chain_conditions: Vec<Vec<String>>,
    pub chain_path_complete: Vec<bool>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InterproceduralByRefWritePathFact {
    pub caller_write_data_flow_index: usize,
    pub argument_data_flow_index: usize,
    pub callee_write_data_flow_index: usize,
    pub caller_path_index: usize,
    pub caller_path_position: usize,
    pub callee_path_index: usize,
    pub callee_path_position: usize,
    pub caller_module: String,
    pub caller_procedure: String,
    pub callee_module: String,
    pub callee_procedure: String,
    pub parameter: String,
    pub caller_conditions: Vec<String>,
    pub callee_conditions: Vec<String>,
    pub feasibility: String,
    pub caller_path_complete: bool,
    pub callee_path_complete: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InterproceduralByRefValuePathFact {
    pub composition_depth: usize,
    pub caller_write_data_flow_index: usize,
    pub argument_data_flow_index: usize,
    pub callee_write_data_flow_index: usize,
    pub caller_path_index: usize,
    pub caller_path_position: usize,
    pub callee_path_index: usize,
    pub callee_path_position: usize,
    pub caller_module: String,
    pub caller_procedure: String,
    pub callee_module: String,
    pub callee_procedure: String,
    pub parameter: String,
    pub caller_value: Option<String>,
    pub callee_write_expression: Option<String>,
    pub resolved_value: Option<String>,
    pub resolution: String,
    pub caller_conditions: Vec<String>,
    pub callee_conditions: Vec<String>,
    pub feasibility: String,
    pub caller_path_complete: bool,
    pub callee_path_complete: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InterproceduralErrorPathFact {
    pub caller_call_index: usize,
    pub caller_path_index: usize,
    pub caller_path_position: usize,
    pub callee_path_index: usize,
    pub callee_fault_path_position: usize,
    pub callee_fault_node_id: usize,
    pub caller_module: String,
    pub caller_procedure: String,
    pub callee_module: String,
    pub callee_procedure: String,
    pub caller_host_entry_candidate: bool,
    pub caller_error_response: String,
    pub caller_recovery_path_position: Option<usize>,
    pub caller_recovery_node_id: Option<usize>,
    pub caller_conditions: Vec<String>,
    pub callee_conditions: Vec<String>,
    pub propagation: String,
    pub feasibility: String,
    pub caller_path_complete: bool,
    pub callee_path_complete: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DataAccessPathFact {
    pub data_access_index: usize,
    /// Exact-token link into `Analysis::excel_worksheet_accesses` when present.
    pub excel_worksheet_access_index: Option<usize>,
    pub path_index: usize,
    pub path_position: usize,
    pub flow_node_id: usize,
    pub module: String,
    pub procedure: String,
    pub conditions: Vec<String>,
    pub feasibility: String,
    pub path_complete: bool,
    pub span: Span,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PathValueFlowFact {
    pub path_index: usize,
    pub source_data_flow_index: Option<usize>,
    pub target_data_flow_index: usize,
    pub variable: String,
    pub resolution: String,
    pub conditions: Vec<String>,
    pub feasibility: String,
    pub path_complete: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PathAliasFact {
    pub data_flow_index: usize,
    pub path_index: usize,
    pub path_position: usize,
    pub module: String,
    pub procedure: String,
    pub target: String,
    pub source: String,
    pub conditions: Vec<String>,
    pub feasibility: String,
    pub path_complete: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PathAliasDispatchFact {
    pub call_index: usize,
    pub alias_data_flow_index: usize,
    pub path_index: usize,
    pub path_position: usize,
    pub module: String,
    pub procedure: String,
    pub receiver: String,
    pub alias_source: String,
    pub member: String,
    pub dispatch_candidates: Vec<String>,
    pub resolution: String,
    pub conditions: Vec<String>,
    pub feasibility: String,
    pub path_complete: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DataAccessValueFlowFact {
    pub path_index: usize,
    pub data_access_index: usize,
    /// Exact-token link into `Analysis::excel_worksheet_accesses` when present.
    pub excel_worksheet_access_index: Option<usize>,
    pub data_flow_index: usize,
    pub role: String,
    pub variable: String,
    pub conditions: Vec<String>,
    pub feasibility: String,
    pub path_complete: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DataAccessPredicateFact {
    pub path_index: usize,
    pub data_access_index: usize,
    /// Exact-token link into `Analysis::excel_worksheet_accesses` when present.
    pub excel_worksheet_access_index: Option<usize>,
    pub flow_node_id: usize,
    pub module: String,
    pub procedure: String,
    pub conditions_before: Vec<String>,
    pub outcome_condition: String,
    pub feasibility: String,
    pub path_complete: bool,
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
    pub implicit_type: Option<String>,
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
    pub external_library: Option<String>,
    pub external_alias: Option<String>,
    pub dispatch_candidates: Vec<String>,
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

/// Excel worksheet-qualified Range/Cells access candidate linked to the
/// workbook sheet inventory. The saved workbook is only a static snapshot;
/// the fact does not prove a runtime sheet or cell binding.
#[derive(Clone, Debug, Default)]
pub struct ExcelWorksheetAccessFact {
    pub module: String,
    pub procedure: Option<String>,
    pub sheet_selector_kind: String,
    pub sheet_selector: Option<String>,
    /// Zero-based candidate position in the extracted workbook sheet list.
    pub sheet_index_candidate: Option<usize>,
    pub sheet_candidate: Option<String>,
    pub sheet_resolution: String,
    pub access_kind: String,
    pub member_selector_candidate: Option<String>,
    pub cell_range_bounds: Option<CellRangeBounds>,
    pub defined_name_candidate: Option<String>,
    pub defined_name_resolution: Option<String>,
    pub table_index_candidate: Option<usize>,
    pub table_column_index_candidate: Option<usize>,
    pub table_row_index_candidate: Option<usize>,
    pub table_candidate: Option<String>,
    pub table_column_candidate: Option<String>,
    pub table_resolution: Option<String>,
    pub table_section: Option<String>,
    /// Exact token access facts connected to this worksheet-qualified object,
    /// including terminal Value/Formula members whose receiver contains it.
    pub data_access_indices: Vec<usize>,
    pub workbook_cell_indices: Vec<usize>,
    pub workbook_cell_matches_truncated: bool,
    pub span: Span,
}
