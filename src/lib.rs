//! Static analysis primitives for VBA source and macro-enabled Office files.
//!
//! The crate never executes macros and never performs network access. Findings
//! distinguish facts from unresolved or host-dependent behavior.

pub mod analyze;
pub mod cfb;
pub mod compiled;
pub mod deflate;
pub mod error_handling;
pub(crate) mod excel_formula;
pub mod export;
pub mod extract;
pub mod flow;
pub mod formula_eval;
pub mod host;
pub mod lexer;
pub mod model;
pub(crate) mod opc;
pub mod ovba;
pub mod parser;
pub mod paths;
pub mod pcode;
pub mod preprocessor;
pub mod source;
pub mod stomping;
pub mod typecheck;
pub mod zip;

pub use analyze::{AnalysisOptions, analyze, detect_entry_points};
pub use extract::{
    ExtractedModulePCodeAnalysis, ExtractedProjectPCodeAnalysis, PCodeAnalysisOptions,
    detect_project_stomping, disassemble_extracted_module, disassemble_extracted_project,
    extract_macro_container,
};
pub use formula_eval::{
    FormulaEvaluation, FormulaEvaluationLimits, FormulaValue, evaluate_formula,
};
pub use host::HostProfile;
pub use model::{Analysis, Diagnostic, Limits, Module, Project, Severity, SourceUnit, Span};
pub use pcode::{
    DisassembledInstruction, DisassembledPCodeLine, DisassembledPCodeModule,
    disassemble_pcode_module, parse_vba_project_identifiers, standard_vba6_instruction_schema,
    standard_vba7_instruction_schema,
};
pub use stomping::{
    ModuleStompingReport, ProjectStompingReport, StompingFinding, StompingFindingKind,
    StompingSeverity, detect_vba_stomping, detect_vba_stomping_with_error,
};

/// Analyze already-decoded VBA text units using default resource limits.
pub fn analyze_sources(sources: &[SourceUnit]) -> Result<Analysis, String> {
    analyze(sources, &AnalysisOptions::default())
}

/// Extract and analyze a macro-enabled Excel workbook without executing it.
///
/// The returned extraction retains project metadata and opaque compiled-cache
/// bytes alongside the source analysis. Caller-supplied compile constants take
/// precedence over constants stored in the workbook.
pub fn analyze_xlsm(
    data: &[u8],
    options: &AnalysisOptions,
) -> Result<(Analysis, extract::ExtractedProject), String> {
    let extracted = extract::extract_xlsm(data, &options.limits)?;
    let mut workbook_options = options.clone();
    if workbook_options.host_profile == HostProfile::Unknown {
        workbook_options.host_profile = HostProfile::Excel;
    }
    let analysis = analyze_extracted_project(&extracted, &workbook_options)?;
    Ok((analysis, extracted))
}

/// Comprehensive inspection result holding static analysis, project structure,
/// disassembled P-code modules, and VBA Stomping / tampering diagnostics.
#[derive(Clone, Debug)]
pub struct ComprehensiveInspection {
    pub analysis: Analysis,
    pub extracted: extract::ExtractedProject,
    pub pcode_disassembly: Vec<pcode::DisassembledPCodeModule>,
    pub stomping_report: stomping::ProjectStompingReport,
}

/// Extract and analyze any Office macro container (.xlsm, .xlsb, .docm, .pptm, legacy .xls,
/// or raw vbaProject.bin) with complete VBA semantic analysis, standard P-code disassembly,
/// and automated VBA Stomping detection.
pub fn inspect_macro_file(
    data: &[u8],
    options: &AnalysisOptions,
) -> Result<ComprehensiveInspection, String> {
    let extracted = extract::extract_macro_container(data, &options.limits)?;
    let mut workbook_options = options.clone();
    if workbook_options.host_profile == HostProfile::Unknown {
        workbook_options.host_profile = HostProfile::Excel;
    }
    let analysis = analyze_extracted_project(&extracted, &workbook_options)?;
    let pcode_disassembly = extract::disassemble_extracted_project(&extracted)?;
    let stomping_report = extract::detect_project_stomping(&extracted)?;

    Ok(ComprehensiveInspection {
        analysis,
        extracted,
        pcode_disassembly,
        stomping_report,
    })
}

/// Extract and analyze an `.xlsm` while applying a caller-selected observed
/// p-code line-map profile to every extracted module. The semantic VBA report
/// and compiled-cache metadata are returned together; opcode meanings remain
/// caller-supplied through the `compiled` APIs.
pub fn analyze_xlsm_with_pcode_profile(
    data: &[u8],
    options: &AnalysisOptions,
    profile: crate::compiled::PCodeLayoutProfile,
    max_lines: usize,
) -> Result<(Analysis, extract::ExtractedProject), String> {
    let extracted =
        extract::extract_xlsm_with_pcode_profile(data, &options.limits, profile, max_lines)?;
    let mut workbook_options = options.clone();
    if workbook_options.host_profile == HostProfile::Unknown {
        workbook_options.host_profile = HostProfile::Excel;
    }
    let analysis = analyze_extracted_project(&extracted, &workbook_options)?;
    Ok((analysis, extracted))
}

/// End-to-end `.xlsm` analysis returning the VBA semantic report, extracted
/// workbook/project metadata, and bounded caller-supplied p-code semantic
/// reports for modules with selected line maps.
#[allow(clippy::too_many_arguments)]
pub fn analyze_xlsm_with_pcode_semantics(
    data: &[u8],
    options: &AnalysisOptions,
    profile: crate::compiled::PCodeLayoutProfile,
    instruction_schema: &crate::compiled::PCodeInstructionSchema,
    semantic_schema: &crate::compiled::PCodeSemanticSchema,
    max_lines: usize,
    max_modules: usize,
    max_instructions: usize,
    max_paths: usize,
    max_steps: usize,
    branch_base: crate::compiled::PCodeBranchBase,
) -> Result<
    (
        Analysis,
        extract::ExtractedProject,
        extract::ExtractedProjectPCodeAnalysis,
    ),
    String,
> {
    let (analysis, extracted) = analyze_xlsm_with_pcode_profile(data, options, profile, max_lines)?;
    let pcode = extract::analyze_extracted_project_pcode(
        &extracted,
        instruction_schema,
        semantic_schema,
        max_modules,
        max_instructions,
        max_paths,
        max_steps,
        branch_base,
    )?;
    Ok((analysis, extracted, pcode))
}

/// End-to-end analysis for a raw VBA project binary (the CFB payload inside an
/// `.xlsm`). This mirrors `analyze_xlsm_with_pcode_semantics` without requiring
/// the surrounding OOXML package.
#[allow(clippy::too_many_arguments)]
pub fn analyze_vba_project_with_pcode_semantics(
    data: &[u8],
    options: &AnalysisOptions,
    profile: crate::compiled::PCodeLayoutProfile,
    instruction_schema: &crate::compiled::PCodeInstructionSchema,
    semantic_schema: &crate::compiled::PCodeSemanticSchema,
    max_lines: usize,
    max_modules: usize,
    max_instructions: usize,
    max_paths: usize,
    max_steps: usize,
    branch_base: crate::compiled::PCodeBranchBase,
) -> Result<
    (
        Analysis,
        extract::ExtractedProject,
        extract::ExtractedProjectPCodeAnalysis,
    ),
    String,
> {
    let extracted =
        extract::extract_vba_project_with_pcode_profile(data, &options.limits, profile, max_lines)?;
    let analysis = analyze_extracted_project(&extracted, options)?;
    let pcode = extract::analyze_extracted_project_pcode(
        &extracted,
        instruction_schema,
        semantic_schema,
        max_modules,
        max_instructions,
        max_paths,
        max_steps,
        branch_base,
    )?;
    Ok((analysis, extracted, pcode))
}

/// Options-struct variant of `analyze_xlsm_with_pcode_semantics` for public
/// callers that want one bounded configuration value.
pub fn analyze_xlsm_with_pcode_options(
    data: &[u8],
    options: &AnalysisOptions,
    instruction_schema: &crate::compiled::PCodeInstructionSchema,
    semantic_schema: &crate::compiled::PCodeSemanticSchema,
    pcode_options: &extract::PCodeAnalysisOptions,
) -> Result<
    (
        Analysis,
        extract::ExtractedProject,
        extract::ExtractedProjectPCodeAnalysis,
    ),
    String,
> {
    analyze_xlsm_with_pcode_semantics(
        data,
        options,
        pcode_options.profile,
        instruction_schema,
        semantic_schema,
        pcode_options.max_lines,
        pcode_options.max_modules,
        pcode_options.max_instructions,
        pcode_options.max_paths,
        pcode_options.max_steps,
        pcode_options.branch_base,
    )
}

/// Options-struct variant of `analyze_vba_project_with_pcode_semantics`.
pub fn analyze_vba_project_with_pcode_options(
    data: &[u8],
    options: &AnalysisOptions,
    instruction_schema: &crate::compiled::PCodeInstructionSchema,
    semantic_schema: &crate::compiled::PCodeSemanticSchema,
    pcode_options: &extract::PCodeAnalysisOptions,
) -> Result<
    (
        Analysis,
        extract::ExtractedProject,
        extract::ExtractedProjectPCodeAnalysis,
    ),
    String,
> {
    analyze_vba_project_with_pcode_semantics(
        data,
        options,
        pcode_options.profile,
        instruction_schema,
        semantic_schema,
        pcode_options.max_lines,
        pcode_options.max_modules,
        pcode_options.max_instructions,
        pcode_options.max_paths,
        pcode_options.max_steps,
        pcode_options.branch_base,
    )
}

/// Analyze source modules from an already-extracted Office VBA project.
pub fn analyze_extracted_project(
    extracted: &extract::ExtractedProject,
    options: &AnalysisOptions,
) -> Result<Analysis, String> {
    let sources = extract::sources_from_extracted(extracted);
    let mut project_options = options.clone();
    for reference in &extracted.references {
        if !project_options
            .project_references
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(reference))
        {
            project_options.project_references.push(reference.clone());
        }
    }
    for (name, value) in &extracted.conditional_constants {
        project_options
            .conditional_constants
            .entry(name.clone())
            .or_insert_with(|| value.clone());
    }
    let module_kinds = extracted
        .modules
        .iter()
        .filter_map(|module| {
            Some((
                module.name.to_ascii_lowercase(),
                extracted_module_kind(extracted, module)?,
            ))
        })
        .collect::<std::collections::HashMap<_, _>>();
    let mut report = if sources.is_empty() {
        Analysis::default()
    } else {
        crate::analyze::analyze_with_project_metadata(
            &sources,
            &project_options,
            extracted.name.clone(),
            "xlsm_vba_project",
            &module_kinds,
        )?
    };
    report.project.references = project_options.project_references.clone();
    report.project.name = extracted.name.clone();
    report.project.code_page = extracted.code_page;
    report.project.system_kind = extracted.system_kind;
    for (name, value) in &extracted.metadata {
        report.project.metadata.insert(name.clone(), value.clone());
    }
    report.project.input_kind = "xlsm_vba_project".into();
    report.host_profile = options.host_profile;
    if options.host_profile == HostProfile::Excel {
        append_workbook_sheet_name_candidates(&mut report, &extracted.workbook_sheets);
        append_excel_worksheet_access_candidates(
            &mut report,
            &extracted.workbook_sheets,
            &extracted.workbook_defined_names,
            &extracted.workbook_tables,
            options.limits.max_tokens,
        );
        append_excel_value_member_links(&mut report, options.limits.max_tokens);
        link_workbook_cells_to_excel_accesses(
            &mut report,
            &extracted.workbook_cells,
            extracted.workbook_cells_truncated,
            options.limits.max_workbook_cell_links,
            options.limits.max_path_fact_association_steps,
        );
        append_workbook_defined_name_candidates(&mut report, &extracted.workbook_defined_names);
    }
    link_excel_worksheet_access_paths(&mut report);
    report.entry_points = detect_entry_points(&report.project, options.host_profile);
    Ok(report)
}

fn extracted_module_kind(
    extracted: &extract::ExtractedProject,
    module: &extract::ExtractedModule,
) -> Option<String> {
    match module.module_type.as_deref() {
        Some("procedural") => Some("standard".into()),
        Some("document_or_class") => {
            let workbook_code_name = extracted
                .workbook_code_name
                .as_deref()
                .unwrap_or("ThisWorkbook");
            let workbook_match = workbook_code_name.eq_ignore_ascii_case(&module.name);
            let worksheet_match_count = extracted
                .workbook_sheets
                .iter()
                .filter(|sheet| {
                    sheet.kind.eq_ignore_ascii_case("worksheet")
                        && sheet
                            .code_name
                            .as_deref()
                            .is_some_and(|name| name.eq_ignore_ascii_case(&module.name))
                })
                .count();
            match (workbook_match, worksheet_match_count) {
                (true, 0) => Some("workbook_document".into()),
                (false, 1) => Some("worksheet_document".into()),
                (true, _) | (false, 2..) => Some("class_or_document".into()),
                (false, 0) if module.name.eq_ignore_ascii_case("ThisWorkbook") => {
                    Some("workbook_document".into())
                }
                (false, 0) if module.name.to_ascii_lowercase().starts_with("sheet") => {
                    Some("worksheet_document".into())
                }
                (false, 0) => Some("class_or_document".into()),
            }
        }
        Some(kind) => Some(kind.to_owned()),
        None => None,
    }
}

fn append_workbook_sheet_name_candidates(
    analysis: &mut Analysis,
    sheets: &[model::WorkbookSheetInfo],
) {
    let mut candidates = Vec::new();
    for module in &analysis.project.modules {
        for procedure in &module.procedures {
            if this_workbook_shadowed(module, procedure) {
                continue;
            }
            collect_sheet_candidates_in_statements(
                &procedure.statements,
                &module.name,
                &procedure.name,
                sheets,
                &mut candidates,
            );
        }
    }
    let mut seen = std::collections::HashSet::new();
    for candidate in candidates {
        let key = (
            candidate.module.to_ascii_lowercase(),
            candidate
                .procedure
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase(),
            candidate.span.start,
            candidate.span.end,
        );
        if seen.insert(key) {
            analysis.references.push(candidate);
        }
    }
}

fn this_workbook_shadowed(module: &model::Module, procedure: &model::Procedure) -> bool {
    let module_shadow = module.declarations.iter().any(|declaration| {
        declaration.name.eq_ignore_ascii_case("thisworkbook")
            && matches!(
                declaration.kind.as_str(),
                "variable" | "global" | "static" | "constant" | "with_events" | "external_declare"
            )
    }) || module
        .procedures
        .iter()
        .any(|candidate| candidate.name.eq_ignore_ascii_case("thisworkbook"));
    let procedure_shadow = procedure
        .parameters
        .iter()
        .any(|parameter| parameter.name.eq_ignore_ascii_case("thisworkbook"))
        || statements_declare_name(&procedure.statements, "thisworkbook");
    module_shadow || procedure_shadow
}

fn append_excel_worksheet_access_candidates(
    analysis: &mut Analysis,
    sheets: &[model::WorkbookSheetInfo],
    defined_names: &[model::WorkbookDefinedNameInfo],
    tables: &[model::WorkbookTableInfo],
    max_tokens: usize,
) {
    let mut accesses = Vec::new();
    for module in &analysis.project.modules {
        let (tokens, _) = lexer::lex(&module.text, max_tokens.max(1));
        for procedure in &module.procedures {
            if this_workbook_shadowed(module, procedure) {
                continue;
            }
            collect_excel_accesses_in_statements(
                &procedure.statements,
                &module.name,
                &procedure.name,
                sheets,
                &tokens,
                &mut accesses,
            );
            collect_excel_defined_name_range_accesses_in_statements(
                &procedure.statements,
                &module.name,
                &procedure.name,
                sheets,
                defined_names,
                &tokens,
                &mut accesses,
            );
            collect_excel_table_range_accesses_in_statements(
                &procedure.statements,
                &module.name,
                &procedure.name,
                sheets,
                tables,
                &tokens,
                &mut accesses,
            );
        }
    }
    let mut seen = std::collections::HashSet::new();
    for mut access in accesses {
        let key = (
            access.module.to_ascii_lowercase(),
            access
                .procedure
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase(),
            access.span.start,
            access.span.end,
        );
        if seen.insert(key) {
            if access.access_kind == "listrows_add"
                && let Some(data_access_index) = data_access_fact_index(
                    &analysis.data_accesses,
                    &access.module,
                    access.procedure.as_deref().unwrap_or_default(),
                    access.span,
                )
            {
                access.data_access_indices.push(data_access_index);
            }
            if access.access_kind == "range"
                && let Some((name, resolution)) = resolve_defined_name_range_selector(
                    access.member_selector_candidate.as_deref(),
                    access.sheet_candidate.as_deref(),
                    defined_names,
                )
            {
                access.defined_name_candidate = Some(name);
                access.defined_name_resolution = Some(resolution);
            }
            analysis.excel_worksheet_accesses.push(access);
        }
    }
}

fn link_excel_worksheet_access_paths(analysis: &mut Analysis) {
    let mut worksheet_access_by_data_access = vec![None; analysis.data_accesses.len()];
    let mut assigned = vec![false; analysis.data_accesses.len()];
    let mut ambiguous = vec![false; analysis.data_accesses.len()];
    for (worksheet_access_index, worksheet_access) in
        analysis.excel_worksheet_accesses.iter().enumerate()
    {
        for data_access_index in &worksheet_access.data_access_indices {
            if *data_access_index >= worksheet_access_by_data_access.len() {
                continue;
            }
            if assigned[*data_access_index]
                && worksheet_access_by_data_access[*data_access_index]
                    != Some(worksheet_access_index)
            {
                worksheet_access_by_data_access[*data_access_index] = None;
                ambiguous[*data_access_index] = true;
            } else if !ambiguous[*data_access_index] {
                worksheet_access_by_data_access[*data_access_index] = Some(worksheet_access_index);
                assigned[*data_access_index] = true;
            }
        }
    }
    for path in &mut analysis.data_access_paths {
        path.excel_worksheet_access_index = worksheet_access_by_data_access
            .get(path.data_access_index)
            .copied()
            .flatten();
    }
    for value_flow in &mut analysis.data_access_value_flows {
        value_flow.excel_worksheet_access_index = worksheet_access_by_data_access
            .get(value_flow.data_access_index)
            .copied()
            .flatten();
    }
    for predicate in &mut analysis.data_access_predicates {
        predicate.excel_worksheet_access_index = worksheet_access_by_data_access
            .get(predicate.data_access_index)
            .copied()
            .flatten();
    }
}

fn append_excel_value_member_links(analysis: &mut Analysis, max_tokens: usize) {
    for access in &mut analysis.excel_worksheet_accesses {
        if let Some(data_access_index) = data_access_fact_index(
            &analysis.data_accesses,
            &access.module,
            access.procedure.as_deref().unwrap_or_default(),
            access.span,
        ) && !access.data_access_indices.contains(&data_access_index)
        {
            access.data_access_indices.push(data_access_index);
        }
    }

    let mut related = Vec::new();
    for module in &analysis.project.modules {
        let (tokens, _) = lexer::lex(&module.text, max_tokens.max(1));
        for procedure in &module.procedures {
            if this_workbook_shadowed(module, procedure) {
                continue;
            }
            collect_excel_value_member_links_in_statements(
                &procedure.statements,
                &module.name,
                &procedure.name,
                &analysis.data_accesses,
                &analysis.excel_worksheet_accesses,
                &tokens,
                &mut related,
            );
        }
    }
    for (worksheet_access_index, data_access_index) in related {
        if let Some(access) = analysis
            .excel_worksheet_accesses
            .get_mut(worksheet_access_index)
            && !access.data_access_indices.contains(&data_access_index)
        {
            access.data_access_indices.push(data_access_index);
        }
    }
}

fn link_workbook_cells_to_excel_accesses(
    analysis: &mut Analysis,
    cells: &[model::WorkbookCellInfo],
    cell_inventory_truncated: bool,
    link_limit: usize,
    step_limit: usize,
) {
    let mut cells_by_sheet = std::collections::HashMap::<String, Vec<usize>>::new();
    let mut cells_by_sheet_index = std::collections::HashMap::<usize, Vec<usize>>::new();
    for (cell_index, cell) in cells.iter().enumerate() {
        cells_by_sheet
            .entry(cell.sheet_name.to_lowercase())
            .or_default()
            .push(cell_index);
        cells_by_sheet_index
            .entry(cell.sheet_index)
            .or_default()
            .push(cell_index);
    }

    let mut links = 0usize;
    let mut steps = 0usize;
    let mut exhausted = false;
    for access in &mut analysis.excel_worksheet_accesses {
        access.workbook_cell_matches_truncated = cell_inventory_truncated;
        access.workbook_cell_indices.clear();
        if !worksheet_cell_link_candidate(&access.sheet_resolution) {
            continue;
        }
        let Some(bounds) = access.cell_range_bounds else {
            continue;
        };
        if exhausted {
            access.workbook_cell_matches_truncated = true;
            continue;
        }
        let sheet_cells = if let Some(sheet_index) = access.sheet_index_candidate {
            cells_by_sheet_index.get(&sheet_index)
        } else if let Some(sheet_name) = access.sheet_candidate.as_deref() {
            cells_by_sheet.get(&sheet_name.to_lowercase())
        } else {
            None
        };
        let Some(sheet_cells) = sheet_cells else {
            continue;
        };
        for cell_index in sheet_cells {
            if steps >= step_limit {
                access.workbook_cell_matches_truncated = true;
                exhausted = true;
                break;
            }
            steps += 1;
            let Some(cell) = cells.get(*cell_index) else {
                continue;
            };
            let (Some(row), Some(column)) = (cell.row, cell.column) else {
                continue;
            };
            if row < bounds.first_row
                || row > bounds.last_row
                || column < bounds.first_column
                || column > bounds.last_column
            {
                continue;
            }
            if links >= link_limit {
                access.workbook_cell_matches_truncated = true;
                exhausted = true;
                break;
            }
            access.workbook_cell_indices.push(*cell_index);
            links += 1;
        }
    }
}

fn worksheet_cell_link_candidate(resolution: &str) -> bool {
    matches!(
        resolution,
        "workbook_worksheet_name_candidate"
            | "workbook_worksheet_index_candidate"
            | "workbook_sheet_name_candidate"
            | "workbook_sheet_index_candidate"
            | "workbook_sheet_metadata_candidate"
            | "workbook_sheet_index_metadata_candidate"
            | "defined_name_target_worksheet_candidate"
            | "defined_name_target_worksheet_metadata_candidate"
    )
}

fn collect_excel_value_member_links_in_statements(
    statements: &[model::Statement],
    module: &str,
    procedure: &str,
    data_accesses: &[model::DataAccessFact],
    worksheet_accesses: &[model::ExcelWorksheetAccessFact],
    tokens: &[lexer::Token],
    out: &mut Vec<(usize, usize)>,
) {
    for statement in statements {
        for expression in [
            statement.parsed_expression.as_ref(),
            statement.parsed_target.as_ref(),
            statement.parsed_loop_start.as_ref(),
            statement.parsed_loop_end.as_ref(),
            statement.parsed_loop_step.as_ref(),
            statement.parsed_exit_condition.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            collect_excel_value_member_links_in_expression(
                expression,
                module,
                procedure,
                data_accesses,
                worksheet_accesses,
                tokens,
                out,
            );
        }
        for range in &statement.case_ranges {
            for expression in [
                range.parsed_expression.as_ref(),
                range.parsed_start_value.as_ref(),
                range.parsed_end_value.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                collect_excel_value_member_links_in_expression(
                    expression,
                    module,
                    procedure,
                    data_accesses,
                    worksheet_accesses,
                    tokens,
                    out,
                );
            }
        }
        collect_excel_value_member_links_in_statements(
            &statement.children,
            module,
            procedure,
            data_accesses,
            worksheet_accesses,
            tokens,
            out,
        );
    }
}

fn collect_excel_value_member_links_in_expression(
    expression: &model::Expr,
    module: &str,
    procedure: &str,
    data_accesses: &[model::DataAccessFact],
    worksheet_accesses: &[model::ExcelWorksheetAccessFact],
    tokens: &[lexer::Token],
    out: &mut Vec<(usize, usize)>,
) {
    use model::{Expr, MemberAccessKind};
    match expression {
        Expr::Member {
            object,
            member,
            access: MemberAccessKind::Dot,
            span,
        } => {
            collect_excel_value_member_links_in_expression(
                object,
                module,
                procedure,
                data_accesses,
                worksheet_accesses,
                tokens,
                out,
            );
            if matches!(
                member.to_ascii_lowercase().as_str(),
                "value" | "value2" | "formula" | "formula2" | "formular1c1" | "formula2r1c1"
            ) && let Some(member_span) = member_token_span(span, member, tokens)
                && let Some(data_access_index) =
                    data_access_fact_index(data_accesses, module, procedure, member_span)
            {
                let receiver_span = object.span();
                for (worksheet_access_index, worksheet_access) in
                    worksheet_accesses.iter().enumerate()
                {
                    if worksheet_access.module.eq_ignore_ascii_case(module)
                        && worksheet_access
                            .procedure
                            .as_deref()
                            .is_some_and(|name| name.eq_ignore_ascii_case(procedure))
                        && receiver_span.start <= worksheet_access.span.start
                        && worksheet_access.span.end <= receiver_span.end
                    {
                        out.push((worksheet_access_index, data_access_index));
                    }
                }
            }
        }
        Expr::Call { callee, args, .. } => {
            collect_excel_value_member_links_in_expression(
                callee,
                module,
                procedure,
                data_accesses,
                worksheet_accesses,
                tokens,
                out,
            );
            for argument in args {
                collect_excel_value_member_links_in_expression(
                    argument,
                    module,
                    procedure,
                    data_accesses,
                    worksheet_accesses,
                    tokens,
                    out,
                );
            }
        }
        Expr::Unary { value, .. } | Expr::Group(value, _) => {
            collect_excel_value_member_links_in_expression(
                value,
                module,
                procedure,
                data_accesses,
                worksheet_accesses,
                tokens,
                out,
            );
        }
        Expr::TypeOfIs { expression, .. } => {
            collect_excel_value_member_links_in_expression(
                expression,
                module,
                procedure,
                data_accesses,
                worksheet_accesses,
                tokens,
                out,
            );
        }
        Expr::Binary { left, right, .. } => {
            collect_excel_value_member_links_in_expression(
                left,
                module,
                procedure,
                data_accesses,
                worksheet_accesses,
                tokens,
                out,
            );
            collect_excel_value_member_links_in_expression(
                right,
                module,
                procedure,
                data_accesses,
                worksheet_accesses,
                tokens,
                out,
            );
        }
        Expr::NamedArgument { value, .. } => {
            collect_excel_value_member_links_in_expression(
                value,
                module,
                procedure,
                data_accesses,
                worksheet_accesses,
                tokens,
                out,
            );
        }
        Expr::Identifier(_, _)
        | Expr::Literal(_, _, _)
        | Expr::Member { .. }
        | Expr::Unknown(_, _) => {}
    }
}

fn data_access_fact_index(
    data_accesses: &[model::DataAccessFact],
    module: &str,
    procedure: &str,
    span: model::Span,
) -> Option<usize> {
    data_accesses.iter().position(|access| {
        access.module.eq_ignore_ascii_case(module)
            && access
                .procedure
                .as_deref()
                .is_some_and(|name| name.eq_ignore_ascii_case(procedure))
            && access.span.start == span.start
            && access.span.end == span.end
    })
}

fn collect_excel_accesses_in_statements(
    statements: &[model::Statement],
    module: &str,
    procedure: &str,
    sheets: &[model::WorkbookSheetInfo],
    tokens: &[lexer::Token],
    out: &mut Vec<model::ExcelWorksheetAccessFact>,
) {
    for statement in statements {
        for expression in [
            statement.parsed_expression.as_ref(),
            statement.parsed_target.as_ref(),
            statement.parsed_loop_start.as_ref(),
            statement.parsed_loop_end.as_ref(),
            statement.parsed_loop_step.as_ref(),
            statement.parsed_exit_condition.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            collect_excel_accesses_in_expression(
                expression, module, procedure, sheets, tokens, out,
            );
        }
        for range in &statement.case_ranges {
            for expression in [
                range.parsed_expression.as_ref(),
                range.parsed_start_value.as_ref(),
                range.parsed_end_value.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                collect_excel_accesses_in_expression(
                    expression, module, procedure, sheets, tokens, out,
                );
            }
        }
        collect_excel_accesses_in_statements(
            &statement.children,
            module,
            procedure,
            sheets,
            tokens,
            out,
        );
    }
}

fn collect_excel_accesses_in_expression(
    expression: &model::Expr,
    module: &str,
    procedure: &str,
    sheets: &[model::WorkbookSheetInfo],
    tokens: &[lexer::Token],
    out: &mut Vec<model::ExcelWorksheetAccessFact>,
) {
    use model::{Expr, MemberAccessKind};
    match expression {
        Expr::Call { callee, args, .. } => {
            if let Expr::Member {
                object,
                member,
                access: MemberAccessKind::Dot,
                span: member_span,
            } = callee.as_ref()
                && (member.eq_ignore_ascii_case("range") || member.eq_ignore_ascii_case("cells"))
                && let Some((collection, selector)) = worksheet_collection_receiver(object)
                && let Some(resolution) =
                    resolve_workbook_sheet_selector(collection, selector, sheets)
                && let Some(span) = member_token_span(member_span, member, tokens)
            {
                let (sheet_resolution, sheet_candidate) =
                    worksheet_access_resolution(collection, &resolution);
                out.push(model::ExcelWorksheetAccessFact {
                    module: module.into(),
                    procedure: Some(procedure.into()),
                    sheet_selector_kind: resolution.selector_kind,
                    sheet_selector: resolution.selector,
                    sheet_index_candidate: resolution.sheet_index_candidate,
                    sheet_candidate,
                    sheet_resolution,
                    access_kind: member.to_ascii_lowercase(),
                    member_selector_candidate: range_or_cells_selector(member, args),
                    cell_range_bounds: excel_cell_range_bounds(member, args),
                    defined_name_candidate: None,
                    defined_name_resolution: None,
                    table_index_candidate: None,
                    table_column_index_candidate: None,
                    table_row_index_candidate: None,
                    table_candidate: None,
                    table_column_candidate: None,
                    table_resolution: None,
                    table_section: None,
                    data_access_indices: Vec::new(),
                    workbook_cell_indices: Vec::new(),
                    workbook_cell_matches_truncated: false,
                    span,
                });
            }
            collect_excel_accesses_in_expression(callee, module, procedure, sheets, tokens, out);
            for argument in args {
                collect_excel_accesses_in_expression(
                    argument, module, procedure, sheets, tokens, out,
                );
            }
        }
        Expr::Member {
            object,
            access: MemberAccessKind::Dot,
            ..
        }
        | Expr::Unary { value: object, .. }
        | Expr::Group(object, _) => {
            collect_excel_accesses_in_expression(object, module, procedure, sheets, tokens, out);
        }
        Expr::TypeOfIs { expression, .. } => {
            collect_excel_accesses_in_expression(
                expression, module, procedure, sheets, tokens, out,
            );
        }
        Expr::Binary { left, right, .. } => {
            collect_excel_accesses_in_expression(left, module, procedure, sheets, tokens, out);
            collect_excel_accesses_in_expression(right, module, procedure, sheets, tokens, out);
        }
        Expr::NamedArgument { value, .. } => {
            collect_excel_accesses_in_expression(value, module, procedure, sheets, tokens, out);
        }
        Expr::Identifier(_, _)
        | Expr::Literal(_, _, _)
        | Expr::Member { .. }
        | Expr::Unknown(_, _) => {}
    }
}

fn collect_excel_table_range_accesses_in_statements(
    statements: &[model::Statement],
    module: &str,
    procedure: &str,
    sheets: &[model::WorkbookSheetInfo],
    tables: &[model::WorkbookTableInfo],
    tokens: &[lexer::Token],
    out: &mut Vec<model::ExcelWorksheetAccessFact>,
) {
    for statement in statements {
        for expression in [
            statement.parsed_expression.as_ref(),
            statement.parsed_target.as_ref(),
            statement.parsed_loop_start.as_ref(),
            statement.parsed_loop_end.as_ref(),
            statement.parsed_loop_step.as_ref(),
            statement.parsed_exit_condition.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            collect_excel_table_range_accesses_in_expression(
                expression, module, procedure, sheets, tables, tokens, out,
            );
        }
        for range in &statement.case_ranges {
            for expression in [
                range.parsed_expression.as_ref(),
                range.parsed_start_value.as_ref(),
                range.parsed_end_value.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                collect_excel_table_range_accesses_in_expression(
                    expression, module, procedure, sheets, tables, tokens, out,
                );
            }
        }
        collect_excel_table_range_accesses_in_statements(
            &statement.children,
            module,
            procedure,
            sheets,
            tables,
            tokens,
            out,
        );
    }
}

fn collect_excel_table_range_accesses_in_expression(
    expression: &model::Expr,
    module: &str,
    procedure: &str,
    sheets: &[model::WorkbookSheetInfo],
    tables: &[model::WorkbookTableInfo],
    tokens: &[lexer::Token],
    out: &mut Vec<model::ExcelWorksheetAccessFact>,
) {
    use model::{Expr, MemberAccessKind};
    match expression {
        Expr::Member {
            object,
            member,
            access: MemberAccessKind::Dot,
            span,
        } => {
            let member_lower = member.to_ascii_lowercase();
            if matches!(
                member_lower.as_str(),
                "range" | "databodyrange" | "headerrowrange" | "totalsrowrange"
            ) && let Some(member_span) = member_token_span(span, member, tokens)
                && let Some(access) = excel_table_range_access_fact(
                    object,
                    &member_lower,
                    module,
                    procedure,
                    member_span,
                    sheets,
                    tables,
                )
            {
                out.push(access);
            }
            if member_lower == "add"
                && let Some(member_span) = member_token_span(span, member, tokens)
                && let Some(access) = excel_table_add_access_fact(
                    object,
                    &[],
                    module,
                    procedure,
                    member_span,
                    sheets,
                    tables,
                )
            {
                out.push(access);
            }
            if member_lower == "delete"
                && let Some(member_span) = member_token_span(span, member, tokens)
                && let Some(access) = excel_table_delete_access_fact(
                    object,
                    module,
                    procedure,
                    member_span,
                    sheets,
                    tables,
                )
            {
                out.push(access);
            }
            collect_excel_table_range_accesses_in_expression(
                object, module, procedure, sheets, tables, tokens, out,
            );
        }
        Expr::Call { callee, args, .. } => {
            if let Expr::Member {
                object,
                member,
                access: MemberAccessKind::Dot,
                span,
            } = callee.as_ref()
                && member.eq_ignore_ascii_case("add")
                && let Some(member_span) = member_token_span(span, member, tokens)
                && let Some(access) = excel_table_add_access_fact(
                    object,
                    args,
                    module,
                    procedure,
                    member_span,
                    sheets,
                    tables,
                )
            {
                out.push(access);
            }
            if let Expr::Member {
                object,
                member,
                access: MemberAccessKind::Dot,
                span,
            } = callee.as_ref()
                && member.eq_ignore_ascii_case("resize")
                && let Some(member_span) = member_token_span(span, member, tokens)
                && let Some(access) = excel_table_resize_access_fact(
                    object,
                    args,
                    module,
                    procedure,
                    member_span,
                    sheets,
                    tables,
                )
            {
                out.push(access);
            }
            if let Expr::Member {
                object,
                member,
                access: MemberAccessKind::Dot,
                span,
            } = callee.as_ref()
                && member.eq_ignore_ascii_case("delete")
                && args.is_empty()
                && let Some(member_span) = member_token_span(span, member, tokens)
                && let Some(access) = excel_table_delete_access_fact(
                    object,
                    module,
                    procedure,
                    member_span,
                    sheets,
                    tables,
                )
            {
                out.push(access);
            }
            collect_excel_table_range_accesses_in_expression(
                callee, module, procedure, sheets, tables, tokens, out,
            );
            for argument in args {
                collect_excel_table_range_accesses_in_expression(
                    argument, module, procedure, sheets, tables, tokens, out,
                );
            }
        }
        Expr::Unary { value, .. } | Expr::Group(value, _) => {
            collect_excel_table_range_accesses_in_expression(
                value, module, procedure, sheets, tables, tokens, out,
            );
        }
        Expr::TypeOfIs { expression, .. } => {
            collect_excel_table_range_accesses_in_expression(
                expression, module, procedure, sheets, tables, tokens, out,
            );
        }
        Expr::Binary { left, right, .. } => {
            collect_excel_table_range_accesses_in_expression(
                left, module, procedure, sheets, tables, tokens, out,
            );
            collect_excel_table_range_accesses_in_expression(
                right, module, procedure, sheets, tables, tokens, out,
            );
        }
        Expr::NamedArgument { value, .. } => {
            collect_excel_table_range_accesses_in_expression(
                value, module, procedure, sheets, tables, tokens, out,
            );
        }
        Expr::Member { object, .. } => {
            collect_excel_table_range_accesses_in_expression(
                object, module, procedure, sheets, tables, tokens, out,
            );
        }
        Expr::Identifier(_, _) | Expr::Literal(_, _, _) | Expr::Unknown(_, _) => {}
    }
}

fn excel_collection_item_arguments<'a>(
    expression: &'a model::Expr,
    collection: &str,
) -> Option<(&'a model::Expr, &'a model::Expr)> {
    let model::Expr::Call { callee, args, .. } = expression else {
        return None;
    };
    if args.len() != 1 {
        return None;
    }
    match callee.as_ref() {
        model::Expr::Member { object, member, .. } if member.eq_ignore_ascii_case(collection) => {
            Some((object, &args[0]))
        }
        model::Expr::Member {
            object,
            member,
            access: model::MemberAccessKind::Dot,
            ..
        } if member.eq_ignore_ascii_case("item") => match object.as_ref() {
            model::Expr::Member {
                object: owner,
                member: collection_member,
                access: model::MemberAccessKind::Dot,
                ..
            } if collection_member.eq_ignore_ascii_case(collection) => Some((owner, &args[0])),
            _ => None,
        },
        _ => None,
    }
}

fn excel_table_range_access_fact(
    range_receiver: &model::Expr,
    range_member: &str,
    module: &str,
    procedure: &str,
    span: model::Span,
    sheets: &[model::WorkbookSheetInfo],
    tables: &[model::WorkbookTableInfo],
) -> Option<model::ExcelWorksheetAccessFact> {
    let (list_object_expression, column_selector, row_selector) =
        if let Some((list_object, selector)) =
            excel_collection_item_arguments(range_receiver, "listcolumns")
        {
            (list_object, Some(selector), None)
        } else if let Some((list_object, selector)) =
            excel_collection_item_arguments(range_receiver, "listrows")
        {
            (list_object, None, Some(selector))
        } else {
            (range_receiver, None, None)
        };
    let (worksheet_expression, table_selector) =
        excel_collection_item_arguments(list_object_expression, "listobjects")?;
    let (worksheet_collection, worksheet_selector) =
        worksheet_collection_receiver(worksheet_expression)?;
    let sheet_lookup =
        resolve_workbook_sheet_selector(worksheet_collection, worksheet_selector, sheets)?;
    let (sheet_resolution, sheet_candidate) =
        worksheet_access_resolution(worksheet_collection, &sheet_lookup);

    let sheet_index = sheet_lookup.sheet_index_candidate;
    let (table_index, table_candidate, mut table_resolution) =
        resolve_excel_table_selector(table_selector, sheet_index, tables);
    let table = table_index.and_then(|index| tables.get(index));
    let (table_column_index, table_column_candidate, column_resolution) =
        if let Some(column_selector) = column_selector {
            if let Some(table) = table {
                resolve_excel_table_column(column_selector, table)
            } else {
                (None, None, "table_metadata_unresolved")
            }
        } else {
            (None, None, "not_applicable")
        };
    if column_resolution != "not_applicable" && column_resolution != "resolved" {
        table_resolution = column_resolution.into();
    }
    let (table_row_index, row_resolution) = if let Some(selector) = row_selector {
        match numeric_index_argument(selector) {
            Some((index, _)) if index > 0 => (Some(index), "resolved"),
            Some(_) => (None, "invalid_table_row_index"),
            None => (None, "dynamic_table_row_selector_unresolved"),
        }
    } else {
        (None, "not_applicable")
    };
    if row_resolution != "not_applicable" && row_resolution != "resolved" {
        table_resolution = row_resolution.into();
    }

    let (section, bounds_status) = if row_selector.is_some() {
        ("row", "resolved")
    } else {
        match range_member {
            "range" => ("all", "resolved"),
            "databodyrange" => ("data", "resolved"),
            "headerrowrange" => ("headers", "resolved"),
            "totalsrowrange" => ("totals", "resolved"),
            _ => ("unknown", "unresolved"),
        }
    };
    let is_list_column = column_selector.is_some();
    let is_list_row = row_selector.is_some();
    let supports_member = if is_list_row {
        range_member == "range"
    } else {
        !is_list_column || matches!(range_member, "range" | "databodyrange")
    };
    let (cell_range_bounds, range_resolution) = if !supports_member {
        (None, "listcolumn_member_not_supported".to_owned())
    } else if table_resolution != "resolved_table_candidate" {
        (None, table_resolution.clone())
    } else if column_resolution != "not_applicable" && column_resolution != "resolved" {
        (None, column_resolution.to_owned())
    } else if bounds_status != "resolved" {
        (None, "unresolved_table_range_member".into())
    } else if let Some(table) = table {
        table_range_bounds_for_object_model(table, section, table_column_index, table_row_index)
    } else {
        (None, "table_metadata_unresolved".into())
    };
    if table_index.is_some() && range_resolution != "resolved" {
        table_resolution = range_resolution.clone();
    }
    Some(model::ExcelWorksheetAccessFact {
        module: module.into(),
        procedure: Some(procedure.into()),
        sheet_selector_kind: sheet_lookup.selector_kind,
        sheet_selector: sheet_lookup.selector,
        sheet_index_candidate: sheet_index,
        sheet_candidate,
        sheet_resolution,
        access_kind: if is_list_row {
            "listrow_range".into()
        } else if is_list_column {
            format!("listcolumn_{range_member}")
        } else {
            format!("listobject_{range_member}")
        },
        member_selector_candidate: Some(match (&table_candidate, &table_column_candidate) {
            (Some(table_name), Some(column_name)) => format!("{table_name}[{column_name}]"),
            (Some(table_name), None) if is_list_row => {
                format!(
                    "{table_name}[data row {}]",
                    table_row_index.unwrap_or_default()
                )
            }
            (Some(table_name), None) => table_name.clone(),
            _ => "unresolved_table_selector".into(),
        }),
        cell_range_bounds,
        defined_name_candidate: None,
        defined_name_resolution: None,
        table_index_candidate: table_index,
        table_column_index_candidate: table_column_index,
        table_row_index_candidate: table_row_index,
        table_candidate,
        table_column_candidate,
        table_resolution: Some(table_resolution),
        table_section: Some(section.into()),
        data_access_indices: Vec::new(),
        workbook_cell_indices: Vec::new(),
        workbook_cell_matches_truncated: false,
        span,
    })
}

fn excel_table_add_access_fact(
    list_rows_expression: &model::Expr,
    arguments: &[model::Expr],
    module: &str,
    procedure: &str,
    span: model::Span,
    sheets: &[model::WorkbookSheetInfo],
    tables: &[model::WorkbookTableInfo],
) -> Option<model::ExcelWorksheetAccessFact> {
    let list_rows_expression = match list_rows_expression {
        model::Expr::Group(inner, _) => inner.as_ref(),
        other => other,
    };
    let model::Expr::Member {
        object: list_object_expression,
        member: collection,
        access: model::MemberAccessKind::Dot,
        ..
    } = list_rows_expression
    else {
        return None;
    };
    if !collection.eq_ignore_ascii_case("listrows") {
        return None;
    }
    let (worksheet_expression, table_selector) =
        excel_collection_item_arguments(list_object_expression, "listobjects")?;
    let (worksheet_collection, worksheet_selector) =
        worksheet_collection_receiver(worksheet_expression)?;
    let sheet_lookup =
        resolve_workbook_sheet_selector(worksheet_collection, worksheet_selector, sheets)?;
    let (sheet_resolution, sheet_candidate) =
        worksheet_access_resolution(worksheet_collection, &sheet_lookup);
    let (table_index, table_candidate, mut table_resolution) =
        resolve_excel_table_selector(table_selector, sheet_lookup.sheet_index_candidate, tables);
    let table = table_index.and_then(|index| tables.get(index));

    let position_argument = if arguments.len() > 2 {
        table_resolution = "invalid_listrows_add_argument_count".into();
        None
    } else {
        let mut positional = arguments
            .iter()
            .filter(|argument| !matches!(argument, model::Expr::NamedArgument { .. }));
        let named_position = arguments.iter().find_map(|argument| match argument {
            model::Expr::NamedArgument { name, value, .. }
                if name.eq_ignore_ascii_case("position") =>
            {
                Some(value.as_ref())
            }
            _ => None,
        });
        let named_always_insert = arguments.iter().any(|argument| {
            matches!(argument,
            model::Expr::NamedArgument { name, .. } if name.eq_ignore_ascii_case("alwaysinsert"))
        });
        named_position.or_else(|| {
            if named_always_insert {
                None
            } else {
                positional.next()
            }
        })
    };
    let (table_row_index_candidate, insertion_resolution) =
        if let Some(position) = position_argument {
            match numeric_index_argument(position) {
                Some((index, _)) if index > 0 => {
                    let row_count = table
                        .and_then(|table| {
                            table_range_bounds_for_object_model(table, "data", None, None).0
                        })
                        .map(|bounds| (bounds.last_row - bounds.first_row + 1) as usize);
                    if row_count.is_some_and(|count| index <= count + 1) {
                        (Some(index), "table_insert_row_candidate")
                    } else if row_count.is_some() {
                        (None, "table_insert_position_out_of_range")
                    } else {
                        (None, "table_insert_position_unresolved")
                    }
                }
                Some(_) => (None, "invalid_table_insert_position"),
                None => (None, "dynamic_table_insert_position_unresolved"),
            }
        } else if arguments.len() <= 2 && table_resolution == "resolved_table_candidate" {
            (None, "table_append_row_candidate")
        } else {
            (None, "table_row_add_unresolved")
        };
    if table_resolution == "resolved_table_candidate" {
        table_resolution = insertion_resolution.into();
    }
    let table_name = table_candidate.clone();
    Some(model::ExcelWorksheetAccessFact {
        module: module.into(),
        procedure: Some(procedure.into()),
        sheet_selector_kind: sheet_lookup.selector_kind,
        sheet_selector: sheet_lookup.selector,
        sheet_index_candidate: sheet_lookup.sheet_index_candidate,
        sheet_candidate,
        sheet_resolution,
        access_kind: "listrows_add".into(),
        member_selector_candidate: table_name.as_ref().map(|name| {
            table_row_index_candidate.map_or_else(
                || format!("{name}[add]"),
                |index| format!("{name}[insert row {index}]"),
            )
        }),
        cell_range_bounds: None,
        defined_name_candidate: None,
        defined_name_resolution: None,
        table_index_candidate: table_index,
        table_column_index_candidate: None,
        table_row_index_candidate,
        table_candidate,
        table_column_candidate: None,
        table_resolution: Some(table_resolution),
        table_section: Some("insert_row".into()),
        data_access_indices: Vec::new(),
        workbook_cell_indices: Vec::new(),
        workbook_cell_matches_truncated: false,
        span,
    })
}

fn excel_table_delete_access_fact(
    receiver: &model::Expr,
    module: &str,
    procedure: &str,
    span: model::Span,
    sheets: &[model::WorkbookSheetInfo],
    tables: &[model::WorkbookTableInfo],
) -> Option<model::ExcelWorksheetAccessFact> {
    let mut access =
        excel_table_range_access_fact(receiver, "range", module, procedure, span, sheets, tables)?;
    if access.access_kind == "listrow_range" {
        access.access_kind = "listrow_delete".into();
        access.table_section = Some("delete_row".into());
    } else if access.access_kind == "listobject_range" {
        access.access_kind = "listobject_delete".into();
        access.table_section = Some("delete_table".into());
    } else {
        return None;
    }
    Some(access)
}

fn excel_table_resize_access_fact(
    receiver: &model::Expr,
    arguments: &[model::Expr],
    module: &str,
    procedure: &str,
    span: model::Span,
    sheets: &[model::WorkbookSheetInfo],
    tables: &[model::WorkbookTableInfo],
) -> Option<model::ExcelWorksheetAccessFact> {
    let mut access =
        excel_table_range_access_fact(receiver, "range", module, procedure, span, sheets, tables)?;
    access.access_kind = "listobject_resize".into();
    access.table_section = Some("resize_target".into());

    if access.table_resolution.as_deref() != Some("resolved_table_candidate") {
        return Some(access);
    }
    if arguments.len() != 1 {
        access.table_resolution = Some("invalid_listobject_resize_argument_count".into());
        access.cell_range_bounds = None;
        return Some(access);
    }

    let target = match &arguments[0] {
        model::Expr::NamedArgument { name, value, .. } if name.eq_ignore_ascii_case("range") => {
            value.as_ref()
        }
        value => value,
    };
    let target = match target {
        model::Expr::Group(inner, _) => inner.as_ref(),
        other => other,
    };
    let model::Expr::Call {
        callee,
        args: range_arguments,
        ..
    } = target
    else {
        access.table_resolution = Some("dynamic_resize_target_unresolved".into());
        access.cell_range_bounds = None;
        return Some(access);
    };
    let model::Expr::Member {
        object: range_receiver,
        member,
        access: model::MemberAccessKind::Dot,
        ..
    } = callee.as_ref()
    else {
        access.table_resolution = Some("dynamic_resize_target_unresolved".into());
        access.cell_range_bounds = None;
        return Some(access);
    };
    if !member.eq_ignore_ascii_case("range") {
        access.table_resolution = Some("dynamic_resize_target_unresolved".into());
        access.cell_range_bounds = None;
        return Some(access);
    }
    let Some((collection, sheet_selector)) = worksheet_collection_receiver(range_receiver) else {
        access.table_resolution = Some("resize_range_worksheet_unresolved".into());
        access.cell_range_bounds = None;
        return Some(access);
    };
    let Some(target_sheet) = resolve_workbook_sheet_selector(collection, sheet_selector, sheets)
    else {
        access.table_resolution = Some("resize_range_worksheet_unresolved".into());
        access.cell_range_bounds = None;
        return Some(access);
    };
    if target_sheet.sheet_index_candidate != access.sheet_index_candidate {
        access.table_resolution = Some("resize_range_sheet_mismatch_unresolved".into());
        access.cell_range_bounds = None;
        return Some(access);
    }
    let Some(bounds) = excel_cell_range_bounds("range", range_arguments) else {
        access.table_resolution = Some("dynamic_resize_target_unresolved".into());
        access.cell_range_bounds = None;
        return Some(access);
    };
    let Some(selector) = range_or_cells_selector("range", range_arguments) else {
        access.table_resolution = Some("dynamic_resize_target_unresolved".into());
        access.cell_range_bounds = None;
        return Some(access);
    };
    access.member_selector_candidate = access
        .table_candidate
        .as_ref()
        .map(|table| format!("{table} resize to {selector}"));
    access.cell_range_bounds = Some(bounds);
    access.table_resolution = Some("table_resize_target_candidate".into());
    Some(access)
}

fn resolve_excel_table_selector(
    selector: &model::Expr,
    sheet_index: Option<usize>,
    tables: &[model::WorkbookTableInfo],
) -> (Option<usize>, Option<String>, String) {
    let Some(sheet_index) = sheet_index else {
        return (
            None,
            string_argument(selector).map(|(name, _)| name.into()),
            "worksheet_selector_unresolved".into(),
        );
    };
    let sheet_tables = tables
        .iter()
        .enumerate()
        .filter(|(_, table)| table.sheet_index == sheet_index)
        .collect::<Vec<_>>();
    if let Some((name, _)) = string_argument(selector) {
        let matches = sheet_tables
            .into_iter()
            .filter(|(_, table)| {
                table.name.eq_ignore_ascii_case(name)
                    || table.display_name.eq_ignore_ascii_case(name)
            })
            .collect::<Vec<_>>();
        return match matches.as_slice() {
            [(index, table)] => (
                Some(*index),
                Some(table.display_name.clone()),
                if table.resolution == "resolved_internal" {
                    "resolved_table_candidate".into()
                } else {
                    table.resolution.clone()
                },
            ),
            [] => (None, Some(name.into()), "unresolved_table_name".into()),
            _ => (None, Some(name.into()), "ambiguous_table_name".into()),
        };
    }
    if let Some((one_based_index, _)) = numeric_index_argument(selector) {
        if one_based_index == 0 {
            return (None, None, "invalid_table_index".into());
        }
        return match sheet_tables.get(one_based_index - 1) {
            Some((index, table)) => (
                Some(*index),
                Some(table.display_name.clone()),
                if table.resolution == "resolved_internal" {
                    "resolved_table_candidate".into()
                } else {
                    table.resolution.clone()
                },
            ),
            None => (None, None, "unresolved_table_index".into()),
        };
    }
    (None, None, "dynamic_table_selector_unresolved".into())
}

fn resolve_excel_table_column(
    selector: &model::Expr,
    table: &model::WorkbookTableInfo,
) -> (Option<usize>, Option<String>, &'static str) {
    if let Some((name, _)) = string_argument(selector) {
        let matches = table
            .columns
            .iter()
            .enumerate()
            .filter(|(_, column)| column.eq_ignore_ascii_case(name))
            .collect::<Vec<_>>();
        return match matches.as_slice() {
            [(index, column)] => (Some(*index), Some((*column).clone()), "resolved"),
            [] => (None, Some(name.into()), "unresolved_table_column"),
            _ => (None, Some(name.into()), "ambiguous_table_column"),
        };
    }
    if let Some((one_based_index, _)) = numeric_index_argument(selector) {
        if one_based_index == 0 {
            return (None, None, "invalid_table_column_index");
        }
        return table
            .columns
            .get(one_based_index - 1)
            .map(|name| (Some(one_based_index - 1), Some(name.clone()), "resolved"))
            .unwrap_or((None, None, "unresolved_table_column_index"));
    }
    (None, None, "dynamic_table_column_selector_unresolved")
}

fn table_range_bounds_for_object_model(
    table: &model::WorkbookTableInfo,
    section: &str,
    column_index: Option<usize>,
    row_index: Option<usize>,
) -> (Option<model::CellRangeBounds>, String) {
    if table.resolution != "resolved_internal" {
        return (None, table.resolution.clone());
    }
    let Some(table_bounds) = table.cell_range_bounds else {
        return (None, "table_range_unresolved".into());
    };
    let (first_column, last_column) = if let Some(column_index) = column_index {
        let Some(column) = u32::try_from(column_index).ok() else {
            return (None, "table_column_index_out_of_range".into());
        };
        let Some(column) = table_bounds.first_column.checked_add(column) else {
            return (None, "table_column_index_out_of_range".into());
        };
        if column > table_bounds.last_column {
            return (None, "table_column_index_out_of_range".into());
        }
        (column, column)
    } else {
        (table_bounds.first_column, table_bounds.last_column)
    };
    let (first_row, last_row) = match section {
        "all" => (table_bounds.first_row, table_bounds.last_row),
        "row" => {
            let Some(row_index) = row_index else {
                return (None, "unresolved_table_row_index".into());
            };
            if row_index == 0 {
                return (None, "invalid_table_row_index".into());
            }
            let first_data_row = table_bounds
                .first_row
                .saturating_add(table.header_row_count);
            let last_data_row = table_bounds.last_row.saturating_sub(table.totals_row_count);
            let Some(offset) = u32::try_from(row_index - 1).ok() else {
                return (None, "table_row_index_out_of_range".into());
            };
            let Some(row) = first_data_row.checked_add(offset) else {
                return (None, "table_row_index_out_of_range".into());
            };
            if row > last_data_row {
                return (None, "table_row_index_out_of_range".into());
            }
            (row, row)
        }
        "data" => {
            let first = table_bounds
                .first_row
                .saturating_add(table.header_row_count);
            let last = table_bounds.last_row.saturating_sub(table.totals_row_count);
            if first > last {
                return (None, "table_data_rows_empty".into());
            }
            (first, last)
        }
        "headers" if table.header_row_count > 0 => (
            table_bounds.first_row,
            table_bounds.first_row + table.header_row_count - 1,
        ),
        "headers" => return (None, "table_has_no_header_row".into()),
        "totals" if table.totals_row_count > 0 => (
            table_bounds.last_row - table.totals_row_count + 1,
            table_bounds.last_row,
        ),
        "totals" => return (None, "table_has_no_totals_row".into()),
        _ => return (None, "unresolved_table_range_member".into()),
    };
    (
        Some(model::CellRangeBounds {
            first_row,
            first_column,
            last_row,
            last_column,
        }),
        "resolved".into(),
    )
}

fn collect_excel_defined_name_range_accesses_in_statements(
    statements: &[model::Statement],
    module: &str,
    procedure: &str,
    sheets: &[model::WorkbookSheetInfo],
    defined_names: &[model::WorkbookDefinedNameInfo],
    tokens: &[lexer::Token],
    out: &mut Vec<model::ExcelWorksheetAccessFact>,
) {
    for statement in statements {
        for expression in [
            statement.parsed_expression.as_ref(),
            statement.parsed_target.as_ref(),
            statement.parsed_loop_start.as_ref(),
            statement.parsed_loop_end.as_ref(),
            statement.parsed_loop_step.as_ref(),
            statement.parsed_exit_condition.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            collect_excel_defined_name_range_accesses_in_expression(
                expression,
                module,
                procedure,
                sheets,
                defined_names,
                tokens,
                out,
            );
        }
        for range in &statement.case_ranges {
            for expression in [
                range.parsed_expression.as_ref(),
                range.parsed_start_value.as_ref(),
                range.parsed_end_value.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                collect_excel_defined_name_range_accesses_in_expression(
                    expression,
                    module,
                    procedure,
                    sheets,
                    defined_names,
                    tokens,
                    out,
                );
            }
        }
        collect_excel_defined_name_range_accesses_in_statements(
            &statement.children,
            module,
            procedure,
            sheets,
            defined_names,
            tokens,
            out,
        );
    }
}

fn collect_excel_defined_name_range_accesses_in_expression(
    expression: &model::Expr,
    module: &str,
    procedure: &str,
    sheets: &[model::WorkbookSheetInfo],
    defined_names: &[model::WorkbookDefinedNameInfo],
    tokens: &[lexer::Token],
    out: &mut Vec<model::ExcelWorksheetAccessFact>,
) {
    use model::{Expr, MemberAccessKind};
    match expression {
        Expr::Member {
            object,
            member,
            access: MemberAccessKind::Dot,
            span,
        } => {
            if member.eq_ignore_ascii_case("referstorange")
                && let Some((name, _)) = workbook_defined_name_collection_receiver(object)
                && let Some(member_span) = member_token_span(span, member, tokens)
            {
                out.push(defined_name_range_access_fact(
                    module,
                    procedure,
                    name,
                    member_span,
                    sheets,
                    defined_names,
                ));
            }
            collect_excel_defined_name_range_accesses_in_expression(
                object,
                module,
                procedure,
                sheets,
                defined_names,
                tokens,
                out,
            );
        }
        Expr::Call { callee, args, .. } => {
            collect_excel_defined_name_range_accesses_in_expression(
                callee,
                module,
                procedure,
                sheets,
                defined_names,
                tokens,
                out,
            );
            for argument in args {
                collect_excel_defined_name_range_accesses_in_expression(
                    argument,
                    module,
                    procedure,
                    sheets,
                    defined_names,
                    tokens,
                    out,
                );
            }
        }
        Expr::Unary { value, .. } | Expr::Group(value, _) => {
            collect_excel_defined_name_range_accesses_in_expression(
                value,
                module,
                procedure,
                sheets,
                defined_names,
                tokens,
                out,
            );
        }
        Expr::TypeOfIs { expression, .. } => {
            collect_excel_defined_name_range_accesses_in_expression(
                expression,
                module,
                procedure,
                sheets,
                defined_names,
                tokens,
                out,
            );
        }
        Expr::Binary { left, right, .. } => {
            collect_excel_defined_name_range_accesses_in_expression(
                left,
                module,
                procedure,
                sheets,
                defined_names,
                tokens,
                out,
            );
            collect_excel_defined_name_range_accesses_in_expression(
                right,
                module,
                procedure,
                sheets,
                defined_names,
                tokens,
                out,
            );
        }
        Expr::NamedArgument { value, .. } => {
            collect_excel_defined_name_range_accesses_in_expression(
                value,
                module,
                procedure,
                sheets,
                defined_names,
                tokens,
                out,
            );
        }
        Expr::Identifier(_, _)
        | Expr::Literal(_, _, _)
        | Expr::Member { .. }
        | Expr::Unknown(_, _) => {}
    }
}

fn workbook_defined_name_collection_receiver(
    expression: &model::Expr,
) -> Option<(&str, model::Span)> {
    let expression = match expression {
        model::Expr::Group(inner, _) => inner.as_ref(),
        other => other,
    };
    if let model::Expr::Call { callee, args, .. } = expression
        && args.len() == 1
        && this_workbook_collection_member(callee)
            .is_some_and(|member| member.eq_ignore_ascii_case("names"))
    {
        string_argument(&args[0])
    } else {
        None
    }
}

fn defined_name_range_access_fact(
    module: &str,
    procedure: &str,
    name: &str,
    span: model::Span,
    sheets: &[model::WorkbookSheetInfo],
    defined_names: &[model::WorkbookDefinedNameInfo],
) -> model::ExcelWorksheetAccessFact {
    let matches = defined_names
        .iter()
        .filter(|defined_name| defined_name.name.eq_ignore_ascii_case(name))
        .collect::<Vec<_>>();
    let mut fact = model::ExcelWorksheetAccessFact {
        module: module.into(),
        procedure: Some(procedure.into()),
        sheet_selector_kind: "defined_name".into(),
        sheet_selector: Some(name.into()),
        sheet_index_candidate: None,
        sheet_candidate: None,
        sheet_resolution: "unresolved_defined_name_target".into(),
        access_kind: "defined_name_range".into(),
        member_selector_candidate: None,
        cell_range_bounds: None,
        defined_name_candidate: matches.first().map(|item| item.name.clone()),
        defined_name_resolution: Some("unresolved_workbook_defined_name".into()),
        table_index_candidate: None,
        table_column_index_candidate: None,
        table_row_index_candidate: None,
        table_candidate: None,
        table_column_candidate: None,
        table_resolution: None,
        table_section: None,
        data_access_indices: Vec::new(),
        workbook_cell_indices: Vec::new(),
        workbook_cell_matches_truncated: false,
        span,
    };
    let defined_name = match matches.as_slice() {
        [defined_name] => *defined_name,
        [] => return fact,
        _ => {
            fact.defined_name_candidate = None;
            fact.defined_name_resolution = Some("ambiguous_workbook_defined_name".into());
            return fact;
        }
    };
    if !matches!(
        defined_name.scope_resolution.as_str(),
        "workbook_scope" | "sheet_scope_candidate"
    ) {
        fact.defined_name_resolution = Some("workbook_defined_name_metadata_candidate".into());
        return fact;
    }
    let Some((sheet_name, range_selector)) = parse_simple_defined_name_range(
        &defined_name.formula,
        defined_name.local_sheet_name.as_deref(),
    ) else {
        fact.defined_name_resolution = Some("defined_name_formula_target_unresolved".into());
        return fact;
    };
    fact.cell_range_bounds = parse_simple_a1_range_bounds(&range_selector);
    fact.member_selector_candidate = Some(range_selector);
    let sheet_matches = sheets
        .iter()
        .enumerate()
        .filter(|(_, sheet)| sheet.name.eq_ignore_ascii_case(&sheet_name))
        .collect::<Vec<_>>();
    match sheet_matches.as_slice() {
        [(sheet_index, sheet)] if !sheet.kind.eq_ignore_ascii_case("worksheet") => {
            fact.sheet_resolution = "known_nonworksheet_sheet_candidate".into();
            fact.sheet_index_candidate = Some(*sheet_index);
            fact.sheet_candidate = Some(sheet.name.clone());
            fact.defined_name_resolution =
                Some("defined_name_target_nonworksheet_candidate".into());
        }
        [(sheet_index, sheet)] => {
            fact.sheet_index_candidate = Some(*sheet_index);
            fact.sheet_candidate = Some(sheet.name.clone());
            fact.sheet_resolution = if sheet.resolution == "resolved_internal" {
                "defined_name_target_worksheet_candidate"
            } else {
                "defined_name_target_worksheet_metadata_candidate"
            }
            .into();
            fact.defined_name_resolution = Some(
                if sheet.resolution == "resolved_internal" {
                    if defined_name.scope_resolution == "sheet_scope_candidate" {
                        "sheet_scoped_defined_name_a1_target_candidate"
                    } else {
                        "defined_name_a1_target_candidate"
                    }
                } else {
                    "defined_name_target_sheet_metadata_candidate"
                }
                .into(),
            );
        }
        [] => {
            fact.defined_name_resolution = Some("unresolved_defined_name_target_sheet".into());
            fact.sheet_resolution = "unresolved_defined_name_target_sheet".into();
        }
        _ => {
            fact.defined_name_resolution = Some("ambiguous_defined_name_target_sheet".into());
            fact.sheet_resolution = "ambiguous_defined_name_target_sheet".into();
        }
    }
    fact
}

fn parse_simple_defined_name_range(
    formula: &str,
    local_sheet_name: Option<&str>,
) -> Option<(String, String)> {
    let formula = formula
        .trim()
        .strip_prefix('=')
        .unwrap_or(formula.trim())
        .trim();
    if formula.is_empty() || formula.contains(['[', ']', '#', ',', '\t', '\r', '\n']) {
        return None;
    }
    let (sheet_name, address) = if let Some((qualifier, address)) = formula.split_once('!') {
        if address.contains('!') {
            return None;
        }
        (parse_defined_name_sheet_qualifier(qualifier)?, address)
    } else {
        (local_sheet_name?.to_owned(), formula)
    };
    if address.contains([' ', '\t', '\r', '\n']) {
        return None;
    }
    let mut cells = address.split(':');
    let first = cells.next()?;
    if !is_simple_a1_cell_reference(first) {
        return None;
    }
    if let Some(second) = cells.next()
        && (cells.next().is_some() || !is_simple_a1_cell_reference(second))
    {
        return None;
    }
    Some((sheet_name, address.to_owned()))
}

fn parse_defined_name_sheet_qualifier(qualifier: &str) -> Option<String> {
    if qualifier.starts_with('\'') && qualifier.ends_with('\'') && qualifier.len() >= 2 {
        let mut chars = qualifier[1..qualifier.len() - 1].chars();
        let mut sheet_name = String::new();
        while let Some(character) = chars.next() {
            if character == '\'' {
                if chars.next() != Some('\'') {
                    return None;
                }
                sheet_name.push('\'');
            } else {
                sheet_name.push(character);
            }
        }
        return (!sheet_name.is_empty()).then_some(sheet_name);
    }
    if qualifier.is_empty()
        || qualifier
            .chars()
            .any(|character| matches!(character, '\'' | '[' | ']' | '!' | ':' | ' ' | '\t'))
    {
        return None;
    }
    Some(qualifier.to_owned())
}

fn is_simple_a1_cell_reference(reference: &str) -> bool {
    let reference = reference.strip_prefix('$').unwrap_or(reference);
    let column_length = reference
        .bytes()
        .take_while(u8::is_ascii_alphabetic)
        .count();
    if column_length == 0 || column_length > 3 || column_length >= reference.len() {
        return false;
    }
    let column = reference[..column_length]
        .bytes()
        .fold(0usize, |value, byte| {
            value * 26 + usize::from(byte.to_ascii_uppercase() - b'A' + 1)
        });
    if column > 16_384 {
        return false;
    }
    let row = reference[column_length..]
        .strip_prefix('$')
        .unwrap_or(&reference[column_length..]);
    if row.is_empty() || !row.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    row.parse::<u32>()
        .is_ok_and(|number| (1..=1_048_576).contains(&number))
}

fn worksheet_collection_receiver(expression: &model::Expr) -> Option<(&'static str, &model::Expr)> {
    if let model::Expr::Call { callee, args, .. } = expression
        && args.len() == 1
        && let Some(collection) = this_workbook_sheet_collection(callee)
    {
        Some((collection, &args[0]))
    } else {
        None
    }
}

struct WorkbookSheetSelectorResolution {
    selector_kind: String,
    selector: Option<String>,
    sheet_index_candidate: Option<usize>,
    candidate: Option<String>,
    resolution: String,
    candidate_kind: Option<String>,
}

fn resolve_workbook_sheet_selector(
    collection: &str,
    selector: &model::Expr,
    sheets: &[model::WorkbookSheetInfo],
) -> Option<WorkbookSheetSelectorResolution> {
    let eligible: Vec<_> = sheets
        .iter()
        .enumerate()
        .filter(|(_, sheet)| collection == "sheets" || sheet.kind.eq_ignore_ascii_case("worksheet"))
        .collect();
    if let Some((name, _)) = string_argument(selector) {
        let matches: Vec<_> = eligible
            .into_iter()
            .filter(|(_, sheet)| sheet.name.eq_ignore_ascii_case(name))
            .collect();
        let (candidate, sheet_index_candidate, resolution, candidate_kind) =
            match matches.as_slice() {
                [(sheet_index, sheet)] => (
                    Some(sheet.name.clone()),
                    Some(*sheet_index),
                    if sheet.resolution == "resolved_internal" {
                        if collection == "worksheets" {
                            "workbook_worksheet_name_candidate"
                        } else {
                            "workbook_sheet_name_candidate"
                        }
                    } else {
                        "workbook_sheet_metadata_candidate"
                    },
                    Some(sheet.kind.clone()),
                ),
                [] => (
                    None,
                    None,
                    if collection == "worksheets" {
                        "unresolved_workbook_worksheet_name"
                    } else {
                        "unresolved_workbook_sheet_name"
                    },
                    None,
                ),
                _ => (None, None, "ambiguous_workbook_sheet_name", None),
            };
        return Some(WorkbookSheetSelectorResolution {
            selector_kind: "name".into(),
            selector: Some(name.into()),
            sheet_index_candidate,
            candidate,
            resolution: resolution.into(),
            candidate_kind,
        });
    }
    if let Some((index, _)) = numeric_index_argument(selector) {
        let (candidate, sheet_index_candidate, resolution, candidate_kind) = if index == 0 {
            (None, None, "invalid_workbook_sheet_index", None)
        } else if let Some((sheet_index, sheet)) = eligible.get(index - 1) {
            (
                Some(sheet.name.clone()),
                Some(*sheet_index),
                if sheet.resolution == "resolved_internal" {
                    if collection == "worksheets" {
                        "workbook_worksheet_index_candidate"
                    } else {
                        "workbook_sheet_index_candidate"
                    }
                } else {
                    "workbook_sheet_index_metadata_candidate"
                },
                Some(sheet.kind.clone()),
            )
        } else {
            (
                None,
                None,
                if collection == "worksheets" {
                    "unresolved_workbook_worksheet_index"
                } else {
                    "unresolved_workbook_sheet_index"
                },
                None,
            )
        };
        return Some(WorkbookSheetSelectorResolution {
            selector_kind: "index".into(),
            selector: Some(index.to_string()),
            sheet_index_candidate,
            candidate,
            resolution: resolution.into(),
            candidate_kind,
        });
    }
    Some(WorkbookSheetSelectorResolution {
        selector_kind: "dynamic".into(),
        selector: None,
        sheet_index_candidate: None,
        candidate: None,
        resolution: "dynamic_workbook_sheet_selector_unresolved".into(),
        candidate_kind: None,
    })
}

fn worksheet_access_resolution(
    collection: &str,
    lookup: &WorkbookSheetSelectorResolution,
) -> (String, Option<String>) {
    if collection == "sheets" {
        match lookup.candidate_kind.as_deref() {
            Some("worksheet") => {}
            Some("chartsheet" | "dialogsheet") => {
                return (
                    "known_nonworksheet_sheet_candidate".into(),
                    lookup.candidate.clone(),
                );
            }
            Some(_) => {
                return (
                    "workbook_sheet_kind_unresolved_candidate".into(),
                    lookup.candidate.clone(),
                );
            }
            None => {}
        }
    }
    (lookup.resolution.clone(), lookup.candidate.clone())
}

fn member_token_span(
    member_span: &model::Span,
    member: &str,
    tokens: &[lexer::Token],
) -> Option<model::Span> {
    tokens
        .iter()
        .find(|token| {
            token.span.end == member_span.end
                && token.span.line == member_span.line
                && token.text.eq_ignore_ascii_case(member)
        })
        .map(|token| token.span)
}

fn range_or_cells_selector(member: &str, arguments: &[model::Expr]) -> Option<String> {
    if member.eq_ignore_ascii_case("range") {
        if arguments.len() == 1 {
            return string_argument(&arguments[0]).map(|(value, _)| value.to_owned());
        }
        if arguments.len() == 2
            && let Some((start, _)) = string_argument(&arguments[0])
            && let Some((end, _)) = string_argument(&arguments[1])
        {
            return Some(format!("{start},{end}"));
        }
    }
    if member.eq_ignore_ascii_case("cells") {
        if arguments.len() == 1 {
            let index = numeric_index_argument(&arguments[0])?.0;
            return Some(format!("index={index}"));
        }
        if arguments.len() == 2 {
            let row = numeric_index_argument(&arguments[0])?.0;
            let column = numeric_index_argument(&arguments[1])?.0;
            return Some(format!("row={row},column={column}"));
        }
    }
    None
}

fn excel_cell_range_bounds(
    member: &str,
    arguments: &[model::Expr],
) -> Option<model::CellRangeBounds> {
    if member.eq_ignore_ascii_case("range") {
        if arguments.len() == 1 {
            return string_argument(&arguments[0])
                .and_then(|(selector, _)| parse_simple_a1_range_bounds(selector));
        }
        if arguments.len() == 2 {
            let (first, _) = string_argument(&arguments[0])?;
            let (second, _) = string_argument(&arguments[1])?;
            let (first_row, first_column) = parse_a1_cell_coordinates(first)?;
            let (last_row, last_column) = parse_a1_cell_coordinates(second)?;
            if first_row > last_row || first_column > last_column {
                return None;
            }
            return Some(model::CellRangeBounds {
                first_row,
                first_column,
                last_row,
                last_column,
            });
        }
    }
    if member.eq_ignore_ascii_case("cells") && arguments.len() == 2 {
        let row = u32::try_from(numeric_index_argument(&arguments[0])?.0).ok()?;
        let column = u32::try_from(numeric_index_argument(&arguments[1])?.0).ok()?;
        if !(1..=1_048_576).contains(&row) || !(1..=16_384).contains(&column) {
            return None;
        }
        return Some(model::CellRangeBounds {
            first_row: row,
            first_column: column,
            last_row: row,
            last_column: column,
        });
    }
    None
}

fn parse_simple_a1_range_bounds(reference: &str) -> Option<model::CellRangeBounds> {
    let mut endpoints = reference.split(':');
    let first = endpoints.next()?;
    let second = endpoints.next();
    if endpoints.next().is_some() {
        return None;
    }

    let first = parse_a1_range_endpoint(first)?;
    let Some(second) = second else {
        let A1RangeEndpoint::Cell(row, column) = first else {
            // A bare letter or number can be a defined name. Whole rows and
            // columns require their explicit range operator (A:A, 1:1).
            return None;
        };
        return Some(model::CellRangeBounds {
            first_row: row,
            first_column: column,
            last_row: row,
            last_column: column,
        });
    };
    let second = parse_a1_range_endpoint(second)?;
    match (first, second) {
        (
            A1RangeEndpoint::Cell(first_row, first_column),
            A1RangeEndpoint::Cell(last_row, last_column),
        ) if first_row <= last_row && first_column <= last_column => Some(model::CellRangeBounds {
            first_row,
            first_column,
            last_row,
            last_column,
        }),
        (A1RangeEndpoint::Column(first_column), A1RangeEndpoint::Column(last_column))
            if first_column <= last_column =>
        {
            Some(model::CellRangeBounds {
                first_row: 1,
                first_column,
                last_row: 1_048_576,
                last_column,
            })
        }
        (A1RangeEndpoint::Row(first_row), A1RangeEndpoint::Row(last_row))
            if first_row <= last_row =>
        {
            Some(model::CellRangeBounds {
                first_row,
                first_column: 1,
                last_row,
                last_column: 16_384,
            })
        }
        _ => None,
    }
}

#[derive(Clone, Copy)]
enum A1RangeEndpoint {
    Cell(u32, u32),
    Column(u32),
    Row(u32),
}

fn parse_a1_range_endpoint(reference: &str) -> Option<A1RangeEndpoint> {
    if let Some((row, column)) = parse_a1_cell_coordinates(reference) {
        return Some(A1RangeEndpoint::Cell(row, column));
    }
    if let Some(column) = parse_a1_column_coordinate(reference) {
        return Some(A1RangeEndpoint::Column(column));
    }
    parse_a1_row_coordinate(reference).map(A1RangeEndpoint::Row)
}

fn parse_a1_column_coordinate(reference: &str) -> Option<u32> {
    let reference = reference.strip_prefix('$').unwrap_or(reference);
    let length = reference.len();
    if !(1..=3).contains(&length) || !reference.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        return None;
    }
    let column = reference.bytes().fold(0u32, |value, byte| {
        value * 26 + u32::from(byte.to_ascii_uppercase() - b'A' + 1)
    });
    (1..=16_384).contains(&column).then_some(column)
}

fn parse_a1_row_coordinate(reference: &str) -> Option<u32> {
    let reference = reference.strip_prefix('$').unwrap_or(reference);
    if reference.is_empty() || !reference.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let row = reference.parse::<u32>().ok()?;
    (1..=1_048_576).contains(&row).then_some(row)
}

fn parse_a1_cell_coordinates(reference: &str) -> Option<(u32, u32)> {
    let reference = reference.strip_prefix('$').unwrap_or(reference);
    let column_length = reference
        .bytes()
        .take_while(u8::is_ascii_alphabetic)
        .count();
    if column_length == 0 || column_length > 3 || column_length >= reference.len() {
        return None;
    }
    let column = reference[..column_length]
        .bytes()
        .fold(0u32, |value, byte| {
            value * 26 + u32::from(byte.to_ascii_uppercase() - b'A' + 1)
        });
    if column > 16_384 {
        return None;
    }
    let row_reference = reference[column_length..]
        .strip_prefix('$')
        .unwrap_or(&reference[column_length..]);
    if row_reference.is_empty() || !row_reference.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let row = row_reference.parse::<u32>().ok()?;
    (1..=1_048_576).contains(&row).then_some((row, column))
}

fn statements_declare_name(statements: &[model::Statement], name: &str) -> bool {
    statements.iter().any(|statement| {
        statement
            .declaration
            .as_ref()
            .is_some_and(|declaration| declaration.name.eq_ignore_ascii_case(name))
            || statements_declare_name(&statement.children, name)
    })
}

fn collect_sheet_candidates_in_statements(
    statements: &[model::Statement],
    module: &str,
    procedure: &str,
    sheets: &[model::WorkbookSheetInfo],
    out: &mut Vec<model::ReferenceFact>,
) {
    for statement in statements {
        for expression in [
            statement.parsed_expression.as_ref(),
            statement.parsed_target.as_ref(),
            statement.parsed_loop_start.as_ref(),
            statement.parsed_loop_end.as_ref(),
            statement.parsed_loop_step.as_ref(),
            statement.parsed_exit_condition.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            collect_sheet_candidate_in_expression(expression, module, procedure, sheets, out);
        }
        for range in &statement.case_ranges {
            for expression in [
                range.parsed_expression.as_ref(),
                range.parsed_start_value.as_ref(),
                range.parsed_end_value.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                collect_sheet_candidate_in_expression(expression, module, procedure, sheets, out);
            }
        }
        collect_sheet_candidates_in_statements(&statement.children, module, procedure, sheets, out);
    }
}

fn collect_sheet_candidate_in_expression(
    expression: &model::Expr,
    module: &str,
    procedure: &str,
    sheets: &[model::WorkbookSheetInfo],
    out: &mut Vec<model::ReferenceFact>,
) {
    use model::{Expr, MemberAccessKind};
    match expression {
        Expr::Call { callee, args, .. } => {
            if args.len() == 1
                && let Some(collection) = this_workbook_sheet_collection(callee)
            {
                let eligible: Vec<_> = sheets
                    .iter()
                    .filter(|sheet| {
                        collection == "sheets" || sheet.kind.eq_ignore_ascii_case("worksheet")
                    })
                    .collect();
                if let Some((name, span)) = string_argument(&args[0]) {
                    let matches: Vec<_> = eligible
                        .iter()
                        .copied()
                        .filter(|sheet| sheet.name.eq_ignore_ascii_case(name))
                        .collect();
                    let resolution = match matches.as_slice() {
                        [sheet] if sheet.resolution == "resolved_internal" => {
                            if collection == "worksheets" {
                                "workbook_worksheet_name_candidate"
                            } else {
                                "workbook_sheet_name_candidate"
                            }
                        }
                        [_] => "workbook_sheet_metadata_candidate",
                        [] => {
                            if collection == "worksheets" {
                                "unresolved_workbook_worksheet_name"
                            } else {
                                "unresolved_workbook_sheet_name"
                            }
                        }
                        _ => "ambiguous_workbook_sheet_name",
                    };
                    out.push(model::ReferenceFact {
                        module: module.into(),
                        procedure: Some(procedure.into()),
                        name: name.into(),
                        resolution: resolution.into(),
                        implicit_type: None,
                        span,
                    });
                } else if let Some((index, span)) = numeric_index_argument(&args[0]) {
                    let selected = index.checked_sub(1).and_then(|offset| eligible.get(offset));
                    let (name, resolution) = if index == 0 {
                        (
                            index.to_string(),
                            "invalid_workbook_sheet_index".to_string(),
                        )
                    } else if let Some(sheet) = selected {
                        let resolution = if sheet.resolution == "resolved_internal" {
                            if collection == "worksheets" {
                                "workbook_worksheet_index_candidate"
                            } else {
                                "workbook_sheet_index_candidate"
                            }
                        } else {
                            "workbook_sheet_index_metadata_candidate"
                        };
                        (sheet.name.clone(), resolution.to_string())
                    } else {
                        let resolution = if collection == "worksheets" {
                            "unresolved_workbook_worksheet_index"
                        } else {
                            "unresolved_workbook_sheet_index"
                        };
                        (index.to_string(), resolution.to_string())
                    };
                    out.push(model::ReferenceFact {
                        module: module.into(),
                        procedure: Some(procedure.into()),
                        name,
                        resolution,
                        implicit_type: None,
                        span,
                    });
                }
            }
            collect_sheet_candidate_in_expression(callee, module, procedure, sheets, out);
            for argument in args {
                collect_sheet_candidate_in_expression(argument, module, procedure, sheets, out);
            }
        }
        Expr::Member {
            object,
            access: MemberAccessKind::Dot,
            ..
        }
        | Expr::Unary { value: object, .. }
        | Expr::Group(object, _) => {
            collect_sheet_candidate_in_expression(object, module, procedure, sheets, out);
        }
        Expr::TypeOfIs { expression, .. } => {
            collect_sheet_candidate_in_expression(expression, module, procedure, sheets, out);
        }
        Expr::Binary { left, right, .. } => {
            collect_sheet_candidate_in_expression(left, module, procedure, sheets, out);
            collect_sheet_candidate_in_expression(right, module, procedure, sheets, out);
        }
        Expr::NamedArgument { value, .. } => {
            collect_sheet_candidate_in_expression(value, module, procedure, sheets, out);
        }
        Expr::Identifier(_, _)
        | Expr::Literal(_, _, _)
        | Expr::Member { .. }
        | Expr::Unknown(_, _) => {}
    }
}

fn this_workbook_sheet_collection(callee: &model::Expr) -> Option<&'static str> {
    let member = this_workbook_collection_member(callee)?;
    if member.eq_ignore_ascii_case("worksheets") {
        Some("worksheets")
    } else if member.eq_ignore_ascii_case("sheets") {
        Some("sheets")
    } else {
        None
    }
}

fn this_workbook_collection_member(callee: &model::Expr) -> Option<&str> {
    use model::{Expr, MemberAccessKind};
    match callee {
        Expr::Member {
            object,
            member,
            access: MemberAccessKind::Dot,
            ..
        } if member.eq_ignore_ascii_case("item") => match object.as_ref() {
            Expr::Member {
                object: owner,
                member: collection,
                access: MemberAccessKind::Dot,
                ..
            } if is_this_workbook(owner) => Some(collection.as_str()),
            _ => None,
        },
        Expr::Member {
            object,
            member,
            access: MemberAccessKind::Dot,
            ..
        } if is_this_workbook(object) => Some(member.as_str()),
        _ => None,
    }
}

fn is_this_workbook(expression: &model::Expr) -> bool {
    match expression {
        model::Expr::Identifier(name, _) => name.eq_ignore_ascii_case("thisworkbook"),
        model::Expr::Member {
            object,
            member,
            access: model::MemberAccessKind::Dot,
            ..
        } => {
            member.eq_ignore_ascii_case("thisworkbook")
                && matches!(object.as_ref(), model::Expr::Identifier(name, _) if name.eq_ignore_ascii_case("application"))
        }
        model::Expr::Group(inner, _) => is_this_workbook(inner),
        _ => false,
    }
}

fn string_argument(expression: &model::Expr) -> Option<(&str, model::Span)> {
    match expression {
        model::Expr::Literal(value, model::LiteralKind::String, span) => Some((value, *span)),
        model::Expr::NamedArgument { value, .. } | model::Expr::Group(value, _) => {
            string_argument(value)
        }
        _ => None,
    }
}

fn numeric_index_argument(expression: &model::Expr) -> Option<(usize, model::Span)> {
    match expression {
        model::Expr::Literal(value, model::LiteralKind::Number, span) => {
            let integer = value
                .strip_suffix('%')
                .or_else(|| value.strip_suffix('&'))
                .or_else(|| value.strip_suffix('^'))
                .unwrap_or(value);
            if integer.is_empty() || !integer.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            Some((integer.parse().ok()?, *span))
        }
        model::Expr::NamedArgument { value, .. } | model::Expr::Group(value, _) => {
            numeric_index_argument(value)
        }
        _ => None,
    }
}

fn resolve_defined_name_range_selector(
    selector: Option<&str>,
    sheet_candidate: Option<&str>,
    defined_names: &[model::WorkbookDefinedNameInfo],
) -> Option<(String, String)> {
    let selector = selector?;
    let matching = defined_names
        .iter()
        .filter(|defined_name| defined_name.name.eq_ignore_ascii_case(selector))
        .collect::<Vec<_>>();
    let applicable = matching
        .iter()
        .copied()
        .filter(
            |defined_name| match defined_name.scope_resolution.as_str() {
                "workbook_scope" => true,
                "sheet_scope_candidate" => defined_name
                    .local_sheet_name
                    .as_deref()
                    .zip(sheet_candidate)
                    .is_some_and(|(local_sheet, selected_sheet)| {
                        local_sheet.eq_ignore_ascii_case(selected_sheet)
                    }),
                _ => false,
            },
        )
        .collect::<Vec<_>>();
    match applicable.as_slice() {
        [defined_name] => Some((
            defined_name.name.clone(),
            if defined_name.scope_resolution == "workbook_scope" {
                "workbook_defined_name_selector_candidate".into()
            } else {
                "sheet_scoped_defined_name_selector_candidate".into()
            },
        )),
        [] if matching
            .iter()
            .any(|defined_name| defined_name.scope_resolution == "invalid_local_sheet_id") =>
        {
            Some((
                selector.into(),
                "workbook_defined_name_metadata_candidate".into(),
            ))
        }
        [] => None,
        _ => Some((
            selector.into(),
            "ambiguous_workbook_defined_name_selector".into(),
        )),
    }
}

fn append_workbook_defined_name_candidates(
    analysis: &mut Analysis,
    defined_names: &[model::WorkbookDefinedNameInfo],
) {
    let mut candidates = Vec::new();
    for module in &analysis.project.modules {
        for procedure in &module.procedures {
            if this_workbook_shadowed(module, procedure) {
                continue;
            }
            collect_defined_name_candidates_in_statements(
                &procedure.statements,
                &module.name,
                &procedure.name,
                defined_names,
                &mut candidates,
            );
        }
    }
    let mut seen = std::collections::HashSet::new();
    for candidate in candidates {
        let key = (
            candidate.module.to_ascii_lowercase(),
            candidate
                .procedure
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase(),
            candidate.span.start,
            candidate.span.end,
        );
        if seen.insert(key) {
            analysis.references.push(candidate);
        }
    }
}

fn collect_defined_name_candidates_in_statements(
    statements: &[model::Statement],
    module: &str,
    procedure: &str,
    defined_names: &[model::WorkbookDefinedNameInfo],
    out: &mut Vec<model::ReferenceFact>,
) {
    for statement in statements {
        for expression in [
            statement.parsed_expression.as_ref(),
            statement.parsed_target.as_ref(),
            statement.parsed_loop_start.as_ref(),
            statement.parsed_loop_end.as_ref(),
            statement.parsed_loop_step.as_ref(),
            statement.parsed_exit_condition.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            collect_defined_name_candidate_in_expression(
                expression,
                module,
                procedure,
                defined_names,
                out,
            );
        }
        for range in &statement.case_ranges {
            for expression in [
                range.parsed_expression.as_ref(),
                range.parsed_start_value.as_ref(),
                range.parsed_end_value.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                collect_defined_name_candidate_in_expression(
                    expression,
                    module,
                    procedure,
                    defined_names,
                    out,
                );
            }
        }
        collect_defined_name_candidates_in_statements(
            &statement.children,
            module,
            procedure,
            defined_names,
            out,
        );
    }
}

fn collect_defined_name_candidate_in_expression(
    expression: &model::Expr,
    module: &str,
    procedure: &str,
    defined_names: &[model::WorkbookDefinedNameInfo],
    out: &mut Vec<model::ReferenceFact>,
) {
    use model::{Expr, LiteralKind};
    match expression {
        Expr::Call { callee, args, .. } => {
            if args.len() == 1
                && this_workbook_collection_member(callee)
                    .is_some_and(|member| member.eq_ignore_ascii_case("names"))
                && let Some((name, span)) = string_argument(&args[0])
            {
                let matches = defined_names
                    .iter()
                    .filter(|defined_name| defined_name.name.eq_ignore_ascii_case(name))
                    .collect::<Vec<_>>();
                let resolution = match matches.as_slice() {
                    [defined_name] if defined_name.scope_resolution == "workbook_scope" => {
                        "workbook_defined_name_candidate"
                    }
                    [defined_name] if defined_name.scope_resolution == "sheet_scope_candidate" => {
                        "worksheet_scoped_defined_name_candidate"
                    }
                    [_] => "workbook_defined_name_metadata_candidate",
                    [] => "unresolved_workbook_defined_name",
                    _ => "ambiguous_workbook_defined_name",
                };
                out.push(model::ReferenceFact {
                    module: module.into(),
                    procedure: Some(procedure.into()),
                    name: name.into(),
                    resolution: resolution.into(),
                    implicit_type: None,
                    span,
                });
            }
            collect_defined_name_candidate_in_expression(
                callee,
                module,
                procedure,
                defined_names,
                out,
            );
            for argument in args {
                collect_defined_name_candidate_in_expression(
                    argument,
                    module,
                    procedure,
                    defined_names,
                    out,
                );
            }
        }
        Expr::Member { object, .. }
        | Expr::Unary { value: object, .. }
        | Expr::Group(object, _) => {
            collect_defined_name_candidate_in_expression(
                object,
                module,
                procedure,
                defined_names,
                out,
            );
        }
        Expr::TypeOfIs { expression, .. } => {
            collect_defined_name_candidate_in_expression(
                expression,
                module,
                procedure,
                defined_names,
                out,
            );
        }
        Expr::Binary { left, right, .. } => {
            collect_defined_name_candidate_in_expression(
                left,
                module,
                procedure,
                defined_names,
                out,
            );
            collect_defined_name_candidate_in_expression(
                right,
                module,
                procedure,
                defined_names,
                out,
            );
        }
        Expr::NamedArgument { value, .. } => {
            collect_defined_name_candidate_in_expression(
                value,
                module,
                procedure,
                defined_names,
                out,
            );
        }
        Expr::Identifier(_, _)
        | Expr::Literal(_, LiteralKind::Number | LiteralKind::Date, _)
        | Expr::Literal(_, LiteralKind::String, _)
        | Expr::Unknown(_, _) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracted_reference_names_reach_project_semantic_checks() {
        let extracted = extract::ExtractedProject {
            modules: vec![extract::ExtractedModule {
                name: "Records".into(),
                source_text: Some(
                    "Public Type ExtendedLibrary\n    Value As Long\nEnd Type\nPublic Type CallerLibrary\n    Value As Long\nEnd Type\n".into(),
                ),
                ..extract::ExtractedModule::default()
            }],
            references: vec!["ExtendedLibrary".into()],
            ..extract::ExtractedProject::default()
        };
        let analysis = analyze_extracted_project(
            &extracted,
            &AnalysisOptions {
                project_references: vec!["CallerLibrary".into()],
                ..AnalysisOptions::default()
            },
        )
        .unwrap();
        assert_eq!(
            analysis.project.references,
            vec!["CallerLibrary", "ExtendedLibrary"]
        );
        assert!(analysis.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "VBA1035"
                && diagnostic.message.contains("ExtendedLibrary")
                && diagnostic.message.contains("library")
        }));
        assert!(analysis.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "VBA1035"
                && diagnostic.message.contains("CallerLibrary")
                && diagnostic.message.contains("library")
        }));
    }

    #[test]
    fn extracted_project_metadata_is_applied_before_semantic_validation() {
        let extracted = extract::ExtractedProject {
            name: Some("MetadataProject".into()),
            modules: vec![extract::ExtractedModule {
                name: "Form1".into(),
                module_type: Some("form".into()),
                source_text: Some(
                    "Attribute VB_GlobalNameSpace = True\nOption Private Module\nGlobal Enum LegacyMode\nReady = 1\nEnd Enum\n".into(),
                ),
                ..extract::ExtractedModule::default()
            }],
            ..extract::ExtractedProject::default()
        };
        let analysis = analyze_extracted_project(&extracted, &AnalysisOptions::default()).unwrap();
        assert_eq!(analysis.project.name.as_deref(), Some("MetadataProject"));
        assert_eq!(analysis.project.input_kind, "xlsm_vba_project");
        assert_eq!(
            analysis.project.modules[0].module_kind.as_deref(),
            Some("form")
        );
        assert!(analysis.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "VBA2070" && diagnostic.severity == Severity::Error
        }));
        assert!(analysis.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "VBA1050" && diagnostic.severity == Severity::Error
        }));
        assert!(analysis.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "VBA2121" && diagnostic.severity == Severity::Error
        }));
    }

    #[test]
    fn spreadsheet_codenames_resolve_renamed_workbook_and_worksheet_modules() {
        let extracted = extract::ExtractedProject {
            workbook_code_name: Some("BookObject".into()),
            workbook_sheets: vec![model::WorkbookSheetInfo {
                name: "User visible tab".into(),
                code_name: Some("InputObject".into()),
                kind: "worksheet".into(),
                resolution: "resolved_internal".into(),
                ..model::WorkbookSheetInfo::default()
            }],
            modules: vec![
                extract::ExtractedModule {
                    name: "BookObject".into(),
                    module_type: Some("document_or_class".into()),
                    source_text: Some("Private Sub Workbook_Open()\nEnd Sub\n".into()),
                    ..extract::ExtractedModule::default()
                },
                extract::ExtractedModule {
                    name: "InputObject".into(),
                    module_type: Some("document_or_class".into()),
                    source_text: Some(
                        "Private Sub Worksheet_Change(ByVal Target As Range)\nEnd Sub\n".into(),
                    ),
                    ..extract::ExtractedModule::default()
                },
            ],
            ..extract::ExtractedProject::default()
        };
        let analysis = analyze_extracted_project(
            &extracted,
            &AnalysisOptions {
                host_profile: HostProfile::Excel,
                ..AnalysisOptions::default()
            },
        )
        .unwrap();
        assert_eq!(
            analysis.project.modules[0].module_kind.as_deref(),
            Some("workbook_document")
        );
        assert_eq!(
            analysis.project.modules[1].module_kind.as_deref(),
            Some("worksheet_document")
        );
        assert!(analysis.entry_points.iter().any(|entry| {
            entry.module == "BookObject"
                && entry.procedure == "Workbook_Open"
                && entry.trigger == "workbook_event_candidate"
        }));
        assert!(analysis.entry_points.iter().any(|entry| {
            entry.module == "InputObject"
                && entry.procedure == "Worksheet_Change"
                && entry.trigger == "worksheet_event_candidate"
        }));
    }

    #[test]
    fn extracted_project_name_participates_in_call_qualification_rules() {
        let extracted = extract::ExtractedProject {
            name: Some("MacroProject".into()),
            modules: vec![
                extract::ExtractedModule {
                    name: "SourceA".into(),
                    module_type: Some("procedural".into()),
                    source_text: Some("Public Sub MacroProject()\nEnd Sub\n".into()),
                    ..extract::ExtractedModule::default()
                },
                extract::ExtractedModule {
                    name: "Caller".into(),
                    module_type: Some("procedural".into()),
                    source_text: Some(
                        "Public Sub Run()\nCall MacroProject()\nCall SourceA.MacroProject()\nEnd Sub\n".into(),
                    ),
                    ..extract::ExtractedModule::default()
                },
            ],
            ..extract::ExtractedProject::default()
        };
        let analysis = analyze_extracted_project(&extracted, &AnalysisOptions::default()).unwrap();
        let qualification_errors = analysis
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "VBA2138")
            .collect::<Vec<_>>();
        assert_eq!(qualification_errors.len(), 1, "{:?}", analysis.diagnostics);
        assert_eq!(qualification_errors[0].source, "Caller.bas");
        assert_eq!(qualification_errors[0].span.line, 2);
        assert!(analysis.calls.iter().any(|call| {
            call.module == "Caller"
                && call.target == "MacroProject"
                && call.resolution == "unqualified_procedure_requires_qualification"
        }));
        assert!(analysis.calls.iter().any(|call| {
            call.module == "Caller"
                && call.target == "MacroProject"
                && call.resolution == "resolved_qualified_module_procedure"
        }));
    }

    #[test]
    fn extracted_excel_sheet_names_are_linked_as_static_candidates() {
        let extracted = extract::ExtractedProject {
            modules: vec![extract::ExtractedModule {
                name: "Module1".into(),
                module_type: Some("procedural".into()),
                source_text: Some(
                    "Public Type Sample\nThisWorkbook As Long\nEnd Type\nPublic Sub Inspect()\nDim value As String\nvalue = ThisWorkbook.Worksheets(\"Orders\").Name\nvalue = ThisWorkbook.Sheets.Item(\"Archive\").Name\nvalue = ThisWorkbook.Worksheets(\"Missing\").Name\nvalue = ThisWorkbook.Worksheets(sheetName).Name\nvalue = ActiveWorkbook.Worksheets(\"Orders\").Name\nvalue = Application.ThisWorkbook.Worksheets(\"Orders\").Name\nvalue = ThisWorkbook.Worksheets(1).Name\nvalue = ThisWorkbook.Sheets.Item(2).Name\nvalue = ThisWorkbook.Worksheets(2).Name\nvalue = ThisWorkbook.Sheets(0).Name\nvalue = ThisWorkbook.Sheets(2 + 0).Name\nEnd Sub\nPublic Sub Shadow(ThisWorkbook As Object)\nDim value As String\nvalue = ThisWorkbook.Worksheets(\"Orders\").Name\nEnd Sub\n".into(),
                ),
                ..extract::ExtractedModule::default()
            }],
            workbook_sheets: vec![
                model::WorkbookSheetInfo {
                    name: "Orders".into(),
                    kind: "worksheet".into(),
                    resolution: "resolved_internal".into(),
                    ..model::WorkbookSheetInfo::default()
                },
                model::WorkbookSheetInfo {
                    name: "Archive".into(),
                    kind: "chartsheet".into(),
                    resolution: "resolved_internal".into(),
                    ..model::WorkbookSheetInfo::default()
                },
            ],
            ..extract::ExtractedProject::default()
        };
        let analysis = analyze_extracted_project(
            &extracted,
            &AnalysisOptions {
                host_profile: HostProfile::Excel,
                ..AnalysisOptions::default()
            },
        )
        .unwrap();
        let candidates: Vec<_> = analysis
            .references
            .iter()
            .filter(|reference| {
                reference.resolution.contains("workbook_")
                    || reference.resolution.starts_with("unresolved_workbook_")
                    || reference.resolution == "ambiguous_workbook_sheet_name"
            })
            .map(|reference| (reference.name.as_str(), reference.resolution.as_str()))
            .collect();
        assert_eq!(
            candidates,
            vec![
                ("Orders", "workbook_worksheet_name_candidate"),
                ("Archive", "workbook_sheet_name_candidate"),
                ("Missing", "unresolved_workbook_worksheet_name"),
                ("Orders", "workbook_worksheet_name_candidate"),
                ("Orders", "workbook_worksheet_index_candidate"),
                ("Archive", "workbook_sheet_index_candidate"),
                ("2", "unresolved_workbook_worksheet_index"),
                ("0", "invalid_workbook_sheet_index"),
            ]
        );
        let structure = export::to_json(
            &analysis,
            Some(&extracted),
            export::Disclosure::StructureOnly,
        );
        assert!(structure.contains("workbook_worksheet_name_candidate"));
        assert!(!structure.contains("Orders"));
        let full = export::to_json(
            &analysis,
            Some(&extracted),
            export::Disclosure::IncludeSource,
        );
        assert!(full.contains("Orders"));
    }

    #[test]
    fn workbook_sheet_candidates_require_excel_host_profile() {
        let extracted = extract::ExtractedProject {
            modules: vec![extract::ExtractedModule {
                name: "Module1".into(),
                module_type: Some("procedural".into()),
                source_text: Some(
                    "Public Sub Inspect()\nThisWorkbook.Worksheets(\"Orders\").Activate\nEnd Sub\n"
                        .into(),
                ),
                ..extract::ExtractedModule::default()
            }],
            workbook_sheets: vec![model::WorkbookSheetInfo {
                name: "Orders".into(),
                kind: "worksheet".into(),
                resolution: "resolved_internal".into(),
                ..model::WorkbookSheetInfo::default()
            }],
            ..extract::ExtractedProject::default()
        };
        let analysis = analyze_extracted_project(&extracted, &AnalysisOptions::default()).unwrap();
        assert!(
            !analysis
                .references
                .iter()
                .any(|reference| reference.resolution == "workbook_worksheet_name_candidate")
        );
        let excel_analysis = analyze_extracted_project(
            &extracted,
            &AnalysisOptions {
                host_profile: HostProfile::Excel,
                ..AnalysisOptions::default()
            },
        )
        .unwrap();
        assert!(
            excel_analysis
                .references
                .iter()
                .any(|reference| { reference.resolution == "workbook_worksheet_name_candidate" })
        );
        let missing_metadata = extract::ExtractedProject {
            modules: extracted.modules.clone(),
            ..extract::ExtractedProject::default()
        };
        let unresolved = analyze_extracted_project(
            &missing_metadata,
            &AnalysisOptions {
                host_profile: HostProfile::Excel,
                ..AnalysisOptions::default()
            },
        )
        .unwrap();
        assert!(
            unresolved
                .references
                .iter()
                .any(|reference| { reference.resolution == "unresolved_workbook_worksheet_name" })
        );
    }

    #[test]
    fn workbook_names_collection_calls_match_saved_defined_names_as_candidates() {
        let extracted = extract::ExtractedProject {
            modules: vec![extract::ExtractedModule {
                name: "Module1".into(),
                module_type: Some("procedural".into()),
                source_text: Some(
                    "Public Sub ReadNames()\nDim value As Variant\nvalue = ThisWorkbook.Names(\"TaxRate\").Name\nvalue = ThisWorkbook.Names.Item(\"InputBlock\").RefersToRange.Value\nvalue = ThisWorkbook.Names(\"SharedName\").Name\nvalue = ThisWorkbook.Names(\"TaxRate\").RefersToRange.Value\nvalue = Application.ThisWorkbook.Names(\"MissingName\").Name\nEnd Sub\n".into(),
                ),
                ..extract::ExtractedModule::default()
            }],
            workbook_defined_names: vec![
                model::WorkbookDefinedNameInfo {
                    name: "TaxRate".into(),
                    formula: "0.075".into(),
                    scope_resolution: "workbook_scope".into(),
                    ..model::WorkbookDefinedNameInfo::default()
                },
                model::WorkbookDefinedNameInfo {
                    name: "InputBlock".into(),
                    formula: "'Orders'!$A$1:$A$10".into(),
                    local_sheet_id: Some(0),
                    local_sheet_name: Some("Orders".into()),
                    scope_resolution: "sheet_scope_candidate".into(),
                    ..model::WorkbookDefinedNameInfo::default()
                },
                model::WorkbookDefinedNameInfo {
                    name: "SharedName".into(),
                    formula: "1".into(),
                    scope_resolution: "workbook_scope".into(),
                    ..model::WorkbookDefinedNameInfo::default()
                },
                model::WorkbookDefinedNameInfo {
                    name: "SharedName".into(),
                    formula: "2".into(),
                    local_sheet_id: Some(0),
                    local_sheet_name: Some("Orders".into()),
                    scope_resolution: "sheet_scope_candidate".into(),
                    ..model::WorkbookDefinedNameInfo::default()
                },
            ],
            workbook_sheets: vec![model::WorkbookSheetInfo {
                name: "Orders".into(),
                kind: "worksheet".into(),
                resolution: "resolved_internal".into(),
                ..model::WorkbookSheetInfo::default()
            }],
            ..extract::ExtractedProject::default()
        };
        let analysis = analyze_extracted_project(
            &extracted,
            &AnalysisOptions {
                host_profile: HostProfile::Excel,
                ..AnalysisOptions::default()
            },
        )
        .unwrap();
        let candidates = analysis
            .references
            .iter()
            .filter(|reference| reference.resolution.contains("defined_name"))
            .map(|reference| (reference.name.as_str(), reference.resolution.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(
            candidates,
            vec![
                ("TaxRate", "workbook_defined_name_candidate"),
                ("InputBlock", "worksheet_scoped_defined_name_candidate"),
                ("SharedName", "ambiguous_workbook_defined_name"),
                ("TaxRate", "workbook_defined_name_candidate"),
                ("MissingName", "unresolved_workbook_defined_name"),
            ]
        );
        let range_accesses = analysis
            .excel_worksheet_accesses
            .iter()
            .filter(|access| access.access_kind == "defined_name_range")
            .collect::<Vec<_>>();
        assert_eq!(range_accesses.len(), 2);
        let input_block = range_accesses
            .iter()
            .find(|access| access.defined_name_candidate.as_deref() == Some("InputBlock"))
            .unwrap();
        assert_eq!(input_block.sheet_candidate.as_deref(), Some("Orders"));
        assert_eq!(input_block.sheet_index_candidate, Some(0));
        assert_eq!(
            input_block.member_selector_candidate.as_deref(),
            Some("$A$1:$A$10")
        );
        assert_eq!(
            input_block.cell_range_bounds,
            Some(model::CellRangeBounds {
                first_row: 1,
                first_column: 1,
                last_row: 10,
                last_column: 1,
            })
        );
        assert_eq!(
            input_block.defined_name_resolution.as_deref(),
            Some("sheet_scoped_defined_name_a1_target_candidate")
        );
        let source = &analysis.project.modules[0].text;
        let value_data_access_index = input_block
            .data_access_indices
            .iter()
            .copied()
            .find(|data_index| {
                analysis.data_accesses.get(*data_index).is_some_and(|fact| {
                    fact.span.start > 0
                        && source[..fact.span.start].trim_end().ends_with('.')
                        && source[fact.span.start..fact.span.end].eq_ignore_ascii_case("Value")
                })
            })
            .expect("RefersToRange.Value data-access fact");
        let input_block_access_index = analysis
            .excel_worksheet_accesses
            .iter()
            .position(|access| {
                access.access_kind == "defined_name_range"
                    && access.defined_name_candidate.as_deref() == Some("InputBlock")
            })
            .expect("InputBlock RefersToRange candidate");
        assert!(analysis.data_access_paths.iter().any(|path| {
            path.data_access_index == value_data_access_index
                && path.excel_worksheet_access_index == Some(input_block_access_index)
        }));
        assert!(analysis.data_access_value_flows.iter().any(|flow| {
            flow.data_access_index == value_data_access_index
                && flow.excel_worksheet_access_index == Some(input_block_access_index)
        }));
        let tax_rate = range_accesses
            .iter()
            .find(|access| access.defined_name_candidate.as_deref() == Some("TaxRate"))
            .unwrap();
        assert_eq!(
            tax_rate.defined_name_resolution.as_deref(),
            Some("defined_name_formula_target_unresolved")
        );
        let structure = export::to_json(
            &analysis,
            Some(&extracted),
            export::Disclosure::StructureOnly,
        );
        assert!(structure.contains("workbook_defined_name_candidate"));
        assert!(!structure.contains("TaxRate"));
        assert!(!structure.contains("'Orders'!$A$1:$A$10"));
        let full = export::to_json(
            &analysis,
            Some(&extracted),
            export::Disclosure::IncludeSource,
        );
        assert!(full.contains("TaxRate"));
        assert!(full.contains("'Orders'!$A$1:$A$10"));
    }

    #[test]
    fn simple_defined_name_a1_targets_preserve_local_scope_and_reject_formulas() {
        assert_eq!(
            parse_simple_defined_name_range("'Orders Data'!$A$1:$B$10", None),
            Some(("Orders Data".into(), "$A$1:$B$10".into()))
        );
        assert_eq!(
            parse_simple_defined_name_range("'Bob''s Sheet'!$A$1", None),
            Some(("Bob's Sheet".into(), "$A$1".into()))
        );
        assert_eq!(
            parse_simple_defined_name_range("=$C$5", Some("Input Sheet")),
            Some(("Input Sheet".into(), "$C$5".into()))
        );
        assert_eq!(
            parse_simple_a1_range_bounds("XFD1048576"),
            Some(model::CellRangeBounds {
                first_row: 1_048_576,
                first_column: 16_384,
                last_row: 1_048_576,
                last_column: 16_384,
            })
        );
        assert_eq!(
            parse_simple_a1_range_bounds("$A:$C"),
            Some(model::CellRangeBounds {
                first_row: 1,
                first_column: 1,
                last_row: 1_048_576,
                last_column: 3,
            })
        );
        assert_eq!(
            parse_simple_a1_range_bounds("$1:$3"),
            Some(model::CellRangeBounds {
                first_row: 1,
                first_column: 1,
                last_row: 3,
                last_column: 16_384,
            })
        );
        assert_eq!(
            parse_simple_a1_range_bounds("A:A"),
            Some(model::CellRangeBounds {
                first_row: 1,
                first_column: 1,
                last_row: 1_048_576,
                last_column: 1,
            })
        );
        assert_eq!(
            parse_simple_a1_range_bounds("1:1"),
            Some(model::CellRangeBounds {
                first_row: 1,
                first_column: 1,
                last_row: 1,
                last_column: 16_384,
            })
        );
        assert_eq!(parse_simple_a1_range_bounds("A"), None);
        assert_eq!(parse_simple_a1_range_bounds("1"), None);
        assert_eq!(parse_simple_a1_range_bounds("C:A"), None);
        assert_eq!(parse_simple_a1_range_bounds("3:1"), None);
        assert_eq!(parse_simple_a1_range_bounds("A1:C"), None);
        assert_eq!(parse_simple_a1_range_bounds("A:A,C:C"), None);
        assert_eq!(parse_simple_a1_range_bounds("XFE:XFE"), None);
        assert_eq!(parse_simple_a1_range_bounds("1048577:1048577"), None);
        assert_eq!(parse_simple_a1_range_bounds("XFE1"), None);
        assert_eq!(parse_simple_defined_name_range("=SUM(A1:A3)", None), None);
        assert_eq!(
            parse_simple_defined_name_range("=[Book.xlsx]Sheet1!A1", None),
            None
        );
        assert_eq!(
            parse_simple_defined_name_range("=$A$0", Some("Input")),
            None
        );
    }

    #[test]
    fn vba_listobject_and_listcolumn_ranges_link_to_workbook_table_cells() {
        let source = "Public Sub Inspect()\nDim value As Variant\nDim rowIndex As Long\nvalue = ThisWorkbook.Worksheets(\"Orders\").ListObjects(\"OrdersTable\").ListColumns(\"Amount\").DataBodyRange.Value\nThisWorkbook.Worksheets(\"Orders\").ListObjects.Item(\"OrdersTable\").HeaderRowRange.Value = value\nvalue = ThisWorkbook.Worksheets(\"Orders\").ListObjects(\"OrdersTable\").Range.Value\nvalue = ThisWorkbook.Worksheets(\"Orders\").ListObjects(\"OrdersTable\").ListRows(1).Range.Value\nThisWorkbook.Worksheets(\"Orders\").ListObjects(\"OrdersTable\").ListRows.Add\nSet inserted = ThisWorkbook.Worksheets(\"Orders\").ListObjects(\"OrdersTable\").ListRows.Add(1)\nSet dynamicRow = ThisWorkbook.Worksheets(\"Orders\").ListObjects(\"OrdersTable\").ListRows.Add(rowPosition)\nThisWorkbook.Worksheets(\"Orders\").ListObjects(\"OrdersTable\").ListRows(1).Delete\nThisWorkbook.Worksheets(\"Orders\").ListObjects(\"OrdersTable\").ListRows(rowIndex).Delete\nThisWorkbook.Worksheets(\"Orders\").ListObjects(\"OrdersTable\").Delete\nCall ThisWorkbook.Worksheets(\"Orders\").ListObjects(\"OrdersTable\").Resize(ThisWorkbook.Worksheets(\"Orders\").Range(\"A1:B4\"))\nCall ThisWorkbook.Worksheets(\"Orders\").ListObjects(\"OrdersTable\").Resize(ThisWorkbook.Worksheets(\"Archive\").Range(\"A1:B4\"))\nCall ThisWorkbook.Worksheets(\"Orders\").ListObjects(\"OrdersTable\").Resize(targetRange)\nEnd Sub\n";
        let extracted = extract::ExtractedProject {
            modules: vec![extract::ExtractedModule {
                name: "Module1".into(),
                module_type: Some("procedural".into()),
                source_text: Some(source.into()),
                ..extract::ExtractedModule::default()
            }],
            workbook_sheets: vec![
                model::WorkbookSheetInfo {
                    name: "Orders".into(),
                    kind: "worksheet".into(),
                    resolution: "resolved_internal".into(),
                    ..model::WorkbookSheetInfo::default()
                },
                model::WorkbookSheetInfo {
                    name: "Archive".into(),
                    kind: "worksheet".into(),
                    resolution: "resolved_internal".into(),
                    ..model::WorkbookSheetInfo::default()
                },
            ],
            workbook_tables: vec![model::WorkbookTableInfo {
                name: "OrdersTable".into(),
                display_name: "OrdersTable".into(),
                sheet_index: 0,
                sheet_name: "Orders".into(),
                cell_range_bounds: Some(model::CellRangeBounds {
                    first_row: 1,
                    first_column: 1,
                    last_row: 3,
                    last_column: 2,
                }),
                header_row_count: 1,
                totals_row_count: 1,
                columns: vec!["Order".into(), "Amount".into()],
                resolution: "resolved_internal".into(),
                ..model::WorkbookTableInfo::default()
            }],
            workbook_cells: vec![
                model::WorkbookCellInfo {
                    sheet_index: 0,
                    sheet_name: "Orders".into(),
                    cell_ref: "A1".into(),
                    row: Some(1),
                    column: Some(1),
                    value: Some("Order".into()),
                    ..model::WorkbookCellInfo::default()
                },
                model::WorkbookCellInfo {
                    sheet_index: 0,
                    sheet_name: "Orders".into(),
                    cell_ref: "B1".into(),
                    row: Some(1),
                    column: Some(2),
                    value: Some("Amount".into()),
                    ..model::WorkbookCellInfo::default()
                },
                model::WorkbookCellInfo {
                    sheet_index: 0,
                    sheet_name: "Orders".into(),
                    cell_ref: "A2".into(),
                    row: Some(2),
                    column: Some(1),
                    value: Some("ORD-1".into()),
                    ..model::WorkbookCellInfo::default()
                },
                model::WorkbookCellInfo {
                    sheet_index: 0,
                    sheet_name: "Orders".into(),
                    cell_ref: "B2".into(),
                    row: Some(2),
                    column: Some(2),
                    value: Some("10".into()),
                    ..model::WorkbookCellInfo::default()
                },
                model::WorkbookCellInfo {
                    sheet_index: 0,
                    sheet_name: "Orders".into(),
                    cell_ref: "A3".into(),
                    row: Some(3),
                    column: Some(1),
                    value: Some("Total".into()),
                    ..model::WorkbookCellInfo::default()
                },
                model::WorkbookCellInfo {
                    sheet_index: 0,
                    sheet_name: "Orders".into(),
                    cell_ref: "B3".into(),
                    row: Some(3),
                    column: Some(2),
                    value: Some("10".into()),
                    ..model::WorkbookCellInfo::default()
                },
            ],
            ..extract::ExtractedProject::default()
        };
        let analysis = analyze_extracted_project(
            &extracted,
            &AnalysisOptions {
                host_profile: HostProfile::Excel,
                ..AnalysisOptions::default()
            },
        )
        .unwrap();
        let table_accesses = analysis
            .excel_worksheet_accesses
            .iter()
            .filter(|access| access.table_index_candidate == Some(0))
            .collect::<Vec<_>>();
        assert_eq!(table_accesses.len(), 13);
        assert!(table_accesses.iter().any(|access| {
            access.access_kind == "listcolumn_databodyrange"
                && access.table_column_index_candidate == Some(1)
                && access.cell_range_bounds
                    == Some(model::CellRangeBounds {
                        first_row: 2,
                        first_column: 2,
                        last_row: 2,
                        last_column: 2,
                    })
                && access.workbook_cell_indices == vec![3]
                && !access.data_access_indices.is_empty()
        }));
        assert!(table_accesses.iter().any(|access| {
            access.access_kind == "listobject_headerrowrange"
                && access.workbook_cell_indices == vec![0, 1]
        }));
        assert!(table_accesses.iter().any(|access| {
            access.access_kind == "listobject_range"
                && access.workbook_cell_indices == vec![0, 1, 2, 3, 4, 5]
        }));
        assert!(table_accesses.iter().any(|access| {
            access.access_kind == "listrow_range"
                && access.table_row_index_candidate == Some(1)
                && access.cell_range_bounds
                    == Some(model::CellRangeBounds {
                        first_row: 2,
                        first_column: 1,
                        last_row: 2,
                        last_column: 2,
                    })
                && access.workbook_cell_indices == vec![2, 3]
        }));
        assert!(table_accesses.iter().any(|access| {
            access.access_kind == "listrows_add"
                && access.table_resolution.as_deref() == Some("table_append_row_candidate")
                && access.cell_range_bounds.is_none()
                && access.table_row_index_candidate.is_none()
        }));
        assert!(table_accesses.iter().any(|access| {
            access.access_kind == "listrows_add"
                && access.table_resolution.as_deref() == Some("table_insert_row_candidate")
                && access.table_row_index_candidate == Some(1)
                && access.cell_range_bounds.is_none()
        }));
        assert!(table_accesses.iter().any(|access| {
            access.access_kind == "listrows_add"
                && access.table_resolution.as_deref()
                    == Some("dynamic_table_insert_position_unresolved")
                && access.table_row_index_candidate.is_none()
        }));
        let add_accesses = table_accesses
            .iter()
            .filter(|access| access.access_kind == "listrows_add")
            .collect::<Vec<_>>();
        assert_eq!(add_accesses.len(), 3);
        assert!(add_accesses.iter().all(|access| {
            access.data_access_indices.iter().any(|index| {
                analysis
                    .data_accesses
                    .get(*index)
                    .is_some_and(|fact| fact.operation == "write_candidate")
            })
        }));
        assert!(table_accesses.iter().any(|access| {
            access.access_kind == "listrow_delete"
                && access.table_row_index_candidate == Some(1)
                && access.table_resolution.as_deref() == Some("resolved_table_candidate")
                && access.cell_range_bounds
                    == Some(model::CellRangeBounds {
                        first_row: 2,
                        first_column: 1,
                        last_row: 2,
                        last_column: 2,
                    })
                && access.workbook_cell_indices == vec![2, 3]
                && access.data_access_indices.iter().any(|index| {
                    analysis
                        .data_accesses
                        .get(*index)
                        .is_some_and(|fact| fact.operation == "write_candidate")
                })
        }));
        assert!(table_accesses.iter().any(|access| {
            access.access_kind == "listrow_delete"
                && access.table_row_index_candidate.is_none()
                && access.table_resolution.as_deref()
                    == Some("dynamic_table_row_selector_unresolved")
                && access.cell_range_bounds.is_none()
        }));
        assert!(table_accesses.iter().any(|access| {
            access.access_kind == "listobject_delete"
                && access.table_resolution.as_deref() == Some("resolved_table_candidate")
                && access.cell_range_bounds
                    == Some(model::CellRangeBounds {
                        first_row: 1,
                        first_column: 1,
                        last_row: 3,
                        last_column: 2,
                    })
                && access.workbook_cell_indices == vec![0, 1, 2, 3, 4, 5]
                && access.data_access_indices.iter().any(|index| {
                    analysis
                        .data_accesses
                        .get(*index)
                        .is_some_and(|fact| fact.operation == "write_candidate")
                })
        }));
        let resize_accesses = table_accesses
            .iter()
            .filter(|access| access.access_kind == "listobject_resize")
            .collect::<Vec<_>>();
        assert_eq!(resize_accesses.len(), 3);
        assert!(resize_accesses.iter().any(|access| {
            access.table_resolution.as_deref() == Some("table_resize_target_candidate")
                && access.member_selector_candidate.as_deref()
                    == Some("OrdersTable resize to A1:B4")
                && access.cell_range_bounds
                    == Some(model::CellRangeBounds {
                        first_row: 1,
                        first_column: 1,
                        last_row: 4,
                        last_column: 2,
                    })
                && access.workbook_cell_indices == vec![0, 1, 2, 3, 4, 5]
                && access.data_access_indices.iter().any(|index| {
                    analysis
                        .data_accesses
                        .get(*index)
                        .is_some_and(|fact| fact.operation == "write_candidate")
                })
        }));
        assert!(resize_accesses.iter().any(|access| {
            access.table_resolution.as_deref() == Some("resize_range_sheet_mismatch_unresolved")
                && access.cell_range_bounds.is_none()
        }));
        assert!(resize_accesses.iter().any(|access| {
            access.table_resolution.as_deref() == Some("dynamic_resize_target_unresolved")
                && access.cell_range_bounds.is_none()
        }));
        let body_access_index = analysis
            .excel_worksheet_accesses
            .iter()
            .position(|access| access.access_kind == "listcolumn_databodyrange")
            .unwrap();
        assert!(
            analysis
                .data_access_paths
                .iter()
                .any(|path| { path.excel_worksheet_access_index == Some(body_access_index) })
        );
        assert!(
            analysis
                .data_access_value_flows
                .iter()
                .any(|flow| { flow.excel_worksheet_access_index == Some(body_access_index) })
        );
        let structure = export::to_json(
            &analysis,
            Some(&extracted),
            export::Disclosure::StructureOnly,
        );
        assert!(!structure.contains("OrdersTable"));
        assert!(!structure.contains("Amount"));
        let source_json = export::to_json(
            &analysis,
            Some(&extracted),
            export::Disclosure::IncludeSource,
        );
        assert!(source_json.contains("\"table_id_candidate\":0"));
        assert!(source_json.contains("\"table_column_id_candidate\":1"));
        assert!(source_json.contains("\"table_candidate\":\"OrdersTable\""));
        assert!(source_json.contains("\"table_column_candidate\":\"Amount\""));
        assert!(source_json.contains("\"table_row_index_candidate\":1"));
    }

    #[test]
    fn worksheet_range_and_cells_accesses_link_to_saved_sheet_candidates() {
        let source = "Public Sub Inspect()\nDim value As Variant\nvalue = ThisWorkbook.Worksheets(\"Orders\").Range(\"A1:B2\").Value\nThisWorkbook.Worksheets(\"Orders\").Cells(2, 3).Value = value\nvalue = ThisWorkbook.Worksheets(\"Orders\").Cells(5).Value\nvalue = ThisWorkbook.Sheets(\"ChartOne\").Range(\"A1\").Value\nvalue = ThisWorkbook.Sheets(\"LegacyMacro\").Cells(1, 1).Value\nvalue = ThisWorkbook.Worksheets(sheetName).Range(address).Value\nIf ThisWorkbook.Worksheets(\"Orders\").Cells(1, 1).Value > 0 Then\nvalue = value + 1\nEnd If\nThisWorkbook.Worksheets(\"Orders\").Range(\"C1\").Formula = \"=1+1\"\nThisWorkbook.Worksheets(\"Orders\").Range(\"D1\").FormulaR1C1 = \"=R1C1\"\nvalue = ThisWorkbook.Worksheets(\"Orders\").Range(\"TaxRate\").Value\nvalue = ThisWorkbook.Worksheets(\"Orders\").Range(\"InputBlock\").Value\nvalue = ThisWorkbook.Worksheets(\"Orders\").Range(\"UnresolvedInput\").Value\nvalue = ThisWorkbook.Worksheets(\"Orders\").Range(\"A1\", \"B2\").Value\nvalue = ThisWorkbook.Worksheets(\"Orders\").Range(\"A:A\").Value\nvalue = ThisWorkbook.Worksheets(\"Orders\").Range(\"1:1\").Value\nEnd Sub\n";
        let extracted = extract::ExtractedProject {
            modules: vec![extract::ExtractedModule {
                name: "Module1".into(),
                module_type: Some("procedural".into()),
                source_text: Some(source.into()),
                ..extract::ExtractedModule::default()
            }],
            workbook_sheets: vec![
                model::WorkbookSheetInfo {
                    name: "Orders".into(),
                    kind: "worksheet".into(),
                    resolution: "resolved_internal".into(),
                    ..model::WorkbookSheetInfo::default()
                },
                model::WorkbookSheetInfo {
                    name: "ChartOne".into(),
                    kind: "chartsheet".into(),
                    resolution: "resolved_internal".into(),
                    ..model::WorkbookSheetInfo::default()
                },
                model::WorkbookSheetInfo {
                    name: "LegacyMacro".into(),
                    kind: "macrosheet".into(),
                    resolution: "resolved_internal".into(),
                    ..model::WorkbookSheetInfo::default()
                },
            ],
            workbook_defined_names: vec![
                model::WorkbookDefinedNameInfo {
                    name: "TaxRate".into(),
                    formula: "0.075".into(),
                    scope_resolution: "workbook_scope".into(),
                    ..model::WorkbookDefinedNameInfo::default()
                },
                model::WorkbookDefinedNameInfo {
                    name: "InputBlock".into(),
                    formula: "'Orders'!$A$1:$A$10".into(),
                    local_sheet_id: Some(0),
                    local_sheet_name: Some("Orders".into()),
                    scope_resolution: "sheet_scope_candidate".into(),
                    ..model::WorkbookDefinedNameInfo::default()
                },
            ],
            workbook_cells: vec![
                model::WorkbookCellInfo {
                    sheet_index: 0,
                    sheet_name: "Orders".into(),
                    cell_ref: "A1".into(),
                    row: Some(1),
                    column: Some(1),
                    cell_type: "n".into(),
                    stored_value: Some("10".into()),
                    value: Some("10".into()),
                    resolution: "stored_numeric_value".into(),
                    ..model::WorkbookCellInfo::default()
                },
                model::WorkbookCellInfo {
                    sheet_index: 0,
                    sheet_name: "Orders".into(),
                    cell_ref: "B2".into(),
                    row: Some(2),
                    column: Some(2),
                    cell_type: "s".into(),
                    stored_value: Some("0".into()),
                    value: Some("Approved".into()),
                    resolution: "shared_string".into(),
                    ..model::WorkbookCellInfo::default()
                },
                model::WorkbookCellInfo {
                    sheet_index: 0,
                    sheet_name: "Orders".into(),
                    cell_ref: "C2".into(),
                    row: Some(2),
                    column: Some(3),
                    cell_type: "n".into(),
                    stored_value: Some("3".into()),
                    value: Some("3".into()),
                    resolution: "stored_numeric_value".into(),
                    ..model::WorkbookCellInfo::default()
                },
                model::WorkbookCellInfo {
                    sheet_index: 0,
                    sheet_name: "Orders".into(),
                    cell_ref: "C1".into(),
                    row: Some(1),
                    column: Some(3),
                    cell_type: "n".into(),
                    formula: Some("1+1".into()),
                    stored_value: Some("2".into()),
                    value: Some("2".into()),
                    resolution: "formula_cached_value".into(),
                    ..model::WorkbookCellInfo::default()
                },
                model::WorkbookCellInfo {
                    sheet_index: 0,
                    sheet_name: "Orders".into(),
                    cell_ref: "D1".into(),
                    row: Some(1),
                    column: Some(4),
                    cell_type: "n".into(),
                    formula: Some("R1C1".into()),
                    stored_value: Some("2".into()),
                    value: Some("2".into()),
                    resolution: "formula_cached_value".into(),
                    ..model::WorkbookCellInfo::default()
                },
                model::WorkbookCellInfo {
                    sheet_index: 1,
                    sheet_name: "ChartOne".into(),
                    cell_ref: "A1".into(),
                    row: Some(1),
                    column: Some(1),
                    cell_type: "n".into(),
                    stored_value: Some("99".into()),
                    value: Some("99".into()),
                    resolution: "stored_numeric_value".into(),
                    ..model::WorkbookCellInfo::default()
                },
            ],
            ..extract::ExtractedProject::default()
        };
        let analysis = analyze_extracted_project(
            &extracted,
            &AnalysisOptions {
                host_profile: HostProfile::Excel,
                ..AnalysisOptions::default()
            },
        )
        .unwrap();
        let accesses = &analysis.excel_worksheet_accesses;
        assert_eq!(accesses.len(), 15);
        assert_eq!(accesses[0].access_kind, "range");
        assert_eq!(accesses[0].sheet_candidate.as_deref(), Some("Orders"));
        assert_eq!(accesses[0].sheet_index_candidate, Some(0));
        assert_eq!(
            accesses[0].sheet_resolution,
            "workbook_worksheet_name_candidate"
        );
        assert_eq!(
            accesses[0].member_selector_candidate.as_deref(),
            Some("A1:B2")
        );
        assert_eq!(
            accesses[0].cell_range_bounds,
            Some(model::CellRangeBounds {
                first_row: 1,
                first_column: 1,
                last_row: 2,
                last_column: 2,
            })
        );
        assert_eq!(accesses[0].workbook_cell_indices, vec![0, 1]);
        let read_fact = analysis
            .data_accesses
            .iter()
            .find(|fact| fact.span.start == accesses[0].span.start)
            .expect("the Range token should have a matching Excel data-access fact");
        assert_eq!(read_fact.operation, "read_candidate");
        assert_eq!(accesses[1].access_kind, "cells");
        assert_eq!(accesses[1].sheet_candidate.as_deref(), Some("Orders"));
        assert_eq!(
            accesses[1].member_selector_candidate.as_deref(),
            Some("row=2,column=3")
        );
        assert_eq!(
            accesses[1].cell_range_bounds,
            Some(model::CellRangeBounds {
                first_row: 2,
                first_column: 3,
                last_row: 2,
                last_column: 3,
            })
        );
        assert_eq!(accesses[1].workbook_cell_indices, vec![2]);
        let write_fact = analysis
            .data_accesses
            .iter()
            .find(|fact| fact.span.start == accesses[1].span.start)
            .expect("the Cells token should have a matching Excel data-access fact");
        assert_eq!(write_fact.operation, "write_candidate");
        assert_eq!(accesses[2].access_kind, "cells");
        assert_eq!(
            accesses[2].member_selector_candidate.as_deref(),
            Some("index=5")
        );
        assert_eq!(accesses[2].cell_range_bounds, None);
        assert_eq!(
            accesses[3].sheet_resolution,
            "known_nonworksheet_sheet_candidate"
        );
        assert_eq!(accesses[3].sheet_candidate.as_deref(), Some("ChartOne"));
        assert_eq!(accesses[3].sheet_index_candidate, Some(1));
        assert!(accesses[3].workbook_cell_indices.is_empty());
        assert_eq!(
            accesses[4].sheet_resolution,
            "workbook_sheet_kind_unresolved_candidate"
        );
        assert_eq!(accesses[4].sheet_candidate.as_deref(), Some("LegacyMacro"));
        assert_eq!(accesses[4].sheet_index_candidate, Some(2));
        assert_eq!(accesses[5].sheet_selector_kind, "dynamic");
        assert_eq!(
            accesses[5].sheet_resolution,
            "dynamic_workbook_sheet_selector_unresolved"
        );
        assert_eq!(accesses[5].sheet_candidate, None);
        assert_eq!(accesses[5].sheet_index_candidate, None);
        assert_eq!(accesses[6].access_kind, "cells");
        assert_eq!(accesses[6].sheet_candidate.as_deref(), Some("Orders"));
        assert_eq!(
            accesses[6].member_selector_candidate.as_deref(),
            Some("row=1,column=1")
        );
        assert_eq!(accesses[7].access_kind, "range");
        assert_eq!(accesses[7].member_selector_candidate.as_deref(), Some("C1"));
        assert_eq!(accesses[7].workbook_cell_indices, vec![3]);
        let formula_data_access_index = analysis
            .data_accesses
            .iter()
            .position(|fact| {
                fact.span.line == accesses[7].span.line
                    && fact.span.start > 0
                    && source[..fact.span.start].trim_end().ends_with('.')
                    && source[fact.span.start..fact.span.end].eq_ignore_ascii_case("Formula")
            })
            .expect("Range.Formula data-access fact");
        assert!(
            accesses[7]
                .data_access_indices
                .contains(&formula_data_access_index)
        );
        assert!(analysis.data_access_paths.iter().any(|path| {
            path.data_access_index == formula_data_access_index
                && path.excel_worksheet_access_index == Some(7)
        }));
        assert_eq!(accesses[8].member_selector_candidate.as_deref(), Some("D1"));
        assert_eq!(accesses[8].workbook_cell_indices, vec![4]);
        let formula_r1c1_data_access_index = analysis
            .data_accesses
            .iter()
            .position(|fact| {
                fact.span.line == accesses[8].span.line
                    && fact.span.start > 0
                    && source[..fact.span.start].trim_end().ends_with('.')
                    && source[fact.span.start..fact.span.end].eq_ignore_ascii_case("FormulaR1C1")
            })
            .expect("Range.FormulaR1C1 data-access fact");
        assert!(
            accesses[8]
                .data_access_indices
                .contains(&formula_r1c1_data_access_index)
        );
        assert_eq!(
            accesses[9].member_selector_candidate.as_deref(),
            Some("TaxRate")
        );
        assert_eq!(
            accesses[9].defined_name_candidate.as_deref(),
            Some("TaxRate")
        );
        assert_eq!(
            accesses[9].defined_name_resolution.as_deref(),
            Some("workbook_defined_name_selector_candidate")
        );
        assert_eq!(
            accesses[10].member_selector_candidate.as_deref(),
            Some("InputBlock")
        );
        assert_eq!(
            accesses[10].defined_name_candidate.as_deref(),
            Some("InputBlock")
        );
        assert_eq!(
            accesses[10].defined_name_resolution.as_deref(),
            Some("sheet_scoped_defined_name_selector_candidate")
        );
        assert_eq!(accesses[11].defined_name_candidate, None);
        assert_eq!(
            accesses[12].cell_range_bounds,
            Some(model::CellRangeBounds {
                first_row: 1,
                first_column: 1,
                last_row: 2,
                last_column: 2,
            })
        );
        assert_eq!(
            accesses[13].member_selector_candidate.as_deref(),
            Some("A:A")
        );
        assert_eq!(
            accesses[13].cell_range_bounds,
            Some(model::CellRangeBounds {
                first_row: 1,
                first_column: 1,
                last_row: 1_048_576,
                last_column: 1,
            })
        );
        assert_eq!(accesses[13].workbook_cell_indices, vec![0]);
        assert_eq!(
            accesses[14].cell_range_bounds,
            Some(model::CellRangeBounds {
                first_row: 1,
                first_column: 1,
                last_row: 1,
                last_column: 16_384,
            })
        );
        assert_eq!(accesses[14].workbook_cell_indices, vec![0, 3, 4]);
        let link_limited = analyze_extracted_project(
            &extracted,
            &AnalysisOptions {
                limits: Limits {
                    max_workbook_cell_links: 1,
                    ..Limits::default()
                },
                host_profile: HostProfile::Excel,
                ..AnalysisOptions::default()
            },
        )
        .unwrap();
        assert_eq!(
            link_limited.excel_worksheet_accesses[0].workbook_cell_indices,
            vec![0]
        );
        assert!(link_limited.excel_worksheet_accesses[0].workbook_cell_matches_truncated);
        assert!(link_limited.excel_worksheet_accesses[1].workbook_cell_matches_truncated);

        let read_access_index = analysis
            .data_accesses
            .iter()
            .position(|fact| fact.span.start == accesses[0].span.start)
            .expect("Range data-access fact");
        let read_value_access_index = analysis
            .data_accesses
            .iter()
            .position(|fact| {
                fact.span.line == accesses[0].span.line
                    && fact.span.start > 0
                    && source[..fact.span.start].trim_end().ends_with('.')
                    && source[fact.span.start..fact.span.end].eq_ignore_ascii_case("Value")
            })
            .expect("Range.Value data-access fact");
        assert!(
            accesses[0]
                .data_access_indices
                .contains(&read_value_access_index)
        );
        assert!(analysis.data_access_paths.iter().any(|path| {
            path.data_access_index == read_access_index
                && path.excel_worksheet_access_index == Some(0)
        }));
        assert!(analysis.data_access_paths.iter().any(|path| {
            path.data_access_index == read_value_access_index
                && path.excel_worksheet_access_index == Some(0)
        }));
        assert!(analysis.data_access_value_flows.iter().any(|flow| {
            flow.data_access_index == read_value_access_index
                && flow.excel_worksheet_access_index == Some(0)
        }));
        let write_access_index = analysis
            .data_accesses
            .iter()
            .position(|fact| fact.span.start == accesses[1].span.start)
            .expect("Cells data-access fact");
        assert!(analysis.data_access_paths.iter().any(|path| {
            path.data_access_index == write_access_index
                && path.excel_worksheet_access_index == Some(1)
        }));
        assert!(analysis.data_access_value_flows.iter().any(|flow| {
            flow.data_access_index == write_access_index
                && flow.excel_worksheet_access_index == Some(1)
        }));
        let write_value_access_index = analysis
            .data_accesses
            .iter()
            .position(|fact| {
                fact.span.line == accesses[1].span.line
                    && fact.span.start > 0
                    && source[..fact.span.start].trim_end().ends_with('.')
                    && source[fact.span.start..fact.span.end].eq_ignore_ascii_case("Value")
            })
            .expect("Cells.Value data-access fact");
        assert!(
            accesses[1]
                .data_access_indices
                .contains(&write_value_access_index)
        );
        assert!(analysis.data_access_paths.iter().any(|path| {
            path.data_access_index == write_value_access_index
                && path.excel_worksheet_access_index == Some(1)
        }));
        assert!(analysis.data_access_value_flows.iter().any(|flow| {
            flow.data_access_index == write_value_access_index
                && flow.excel_worksheet_access_index == Some(1)
        }));
        assert!(
            analysis
                .data_access_predicates
                .iter()
                .any(|predicate| { predicate.excel_worksheet_access_index == Some(6) })
        );
        let predicate_value_access_index = analysis
            .data_accesses
            .iter()
            .position(|fact| {
                fact.span.line == accesses[6].span.line
                    && fact.span.start > 0
                    && source[..fact.span.start].trim_end().ends_with('.')
                    && source[fact.span.start..fact.span.end].eq_ignore_ascii_case("Value")
            })
            .expect("worksheet-qualified predicate Value data-access fact");
        assert!(
            accesses[6]
                .data_access_indices
                .contains(&predicate_value_access_index)
        );
        assert!(analysis.data_access_predicates.iter().any(|predicate| {
            predicate.data_access_index == predicate_value_access_index
                && predicate.excel_worksheet_access_index == Some(6)
        }));
        for access in accesses {
            assert!(
                source[access.span.start..access.span.end]
                    .eq_ignore_ascii_case(&access.access_kind)
            );
        }

        let structure = export::to_json(
            &analysis,
            Some(&extracted),
            export::Disclosure::StructureOnly,
        );
        assert!(structure.contains("excel_worksheet_access_candidates"));
        assert!(structure.contains("known_nonworksheet_sheet_candidate"));
        assert!(structure.contains("\"excel_worksheet_access_id\":0"));
        assert!(structure.contains("\"cell_range_bounds\":null"));
        assert!(!structure.contains("\"cell_ref\":\"A1\""));
        assert!(!structure.contains("\"value\":\"10\""));
        assert!(!structure.contains("A1:B2"));
        assert!(!structure.contains("Orders"));
        let full = export::to_json(
            &analysis,
            Some(&extracted),
            export::Disclosure::IncludeSource,
        );
        assert!(full.contains("A1:B2"));
        assert!(full.contains("row=2,column=3"));
        assert!(full.contains("Orders"));
        assert!(full.contains("\"cell_ref\":\"A1\""));
        assert!(full.contains("\"value\":\"Approved\""));
        assert!(
            full.contains("\"first_row\":1,\"first_column\":1,\"last_row\":2,\"last_column\":2")
        );
        let data_access_ids = format!(
            "\"data_access_ids\":[{}]",
            accesses[0]
                .data_access_indices
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(full.contains(&data_access_ids));
    }

    #[test]
    fn inspect_macro_file_rejects_non_container() {
        let err =
            inspect_macro_file(b"just some plain text", &AnalysisOptions::default()).unwrap_err();
        assert!(err.contains("unrecognized macro container format"));
    }
}
