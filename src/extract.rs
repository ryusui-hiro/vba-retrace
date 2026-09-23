//! Direct read-only extraction of VBA sources and cache metadata from `.xlsm` files.

use crate::cfb::CompoundFile;
use crate::compiled::{
    PCodeBranchBase, PCodeInstructionSchema, PCodeLineMap, PCodeSemanticPathReport,
    PCodeSemanticSchema, analyze_pcode_semantic_paths, decode_pcode_lines_with_schema,
    fingerprint_fnv1a64, inspect_vba7_line_map,
};
use crate::model::{Limits, WorkbookCellInfo, WorkbookDefinedNameInfo, WorkbookSheetInfo};
use crate::ovba::{OvbaProject, parse_project};
use crate::source::decode_text;
use crate::zip::ZipArchive;

#[derive(Clone, Debug, Default)]
pub struct CacheRecord {
    pub module: String,
    pub byte_length: usize,
    pub fingerprint: u64,
    pub interpretation: String,
}

#[derive(Clone, Debug, Default)]
pub struct SrpCacheRecord {
    pub stream_name: String,
    pub byte_length: usize,
    pub fingerprint: u64,
}
#[derive(Clone, Debug, Default)]
pub struct ExtractedModule {
    pub name: String,
    pub stream_name: String,
    pub source_text: Option<String>,
    pub source_bytes: Vec<u8>,
    pub performance_cache: Vec<u8>,
    pub cache: CacheRecord,
    pub pcode_layout: Option<PCodeLineMap>,
    pub pcode_layout_status: String,
    pub module_type: Option<String>,
    pub text_offset: u32,
    pub diagnostic: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellThreat {
    pub sheet_name: String,
    pub cell_ref: String,
    pub coordinate: String,
    pub threat_kind: String,
    pub severity: String,
    pub formula: String,
    pub description: String,
}

#[derive(Clone, Debug, Default)]
pub struct ExtractedProject {
    pub name: Option<String>,
    /// Workbook VBA codename from SpreadsheetML `workbookPr`, when present.
    pub workbook_code_name: Option<String>,
    pub code_page: Option<u16>,
    pub system_kind: Option<u32>,
    pub project_version_tag: Option<u16>,
    pub modules: Vec<ExtractedModule>,
    pub workbook_sheets: Vec<WorkbookSheetInfo>,
    pub workbook_defined_names: Vec<WorkbookDefinedNameInfo>,
    pub workbook_tables: Vec<crate::model::WorkbookTableInfo>,
    pub workbook_tables_truncated: bool,
    pub workbook_cells: Vec<WorkbookCellInfo>,
    pub workbook_cells_truncated: bool,
    pub references: Vec<String>,
    pub project_references: Vec<crate::ovba::OvbaReference>,
    pub identifiers: Vec<String>,
    pub conditional_constants: std::collections::BTreeMap<String, String>,
    pub project_cache: CacheRecord,
    pub srp_caches: Vec<SrpCacheRecord>,
    pub metadata: Vec<(String, String)>,
    pub diagnostics: Vec<String>,
    pub compiled_representation_status: String,
    pub project_protection_cmg: Option<String>,
    pub project_protection_dpb: Option<String>,
    pub project_protection_gc: Option<String>,
    pub is_locked_or_unviewable: bool,
    pub hidden_gui_modules: Vec<String>,
    pub cell_threats: Vec<CellThreat>,
}

#[derive(Clone, Debug)]
pub struct ExtractedModulePCodeAnalysis {
    pub module_name: String,
    pub decoded: crate::compiled::PCodeDecodeReport,
    pub semantic_paths: PCodeSemanticPathReport,
}

#[derive(Clone, Debug, Default)]
pub struct ExtractedProjectPCodeAnalysis {
    pub modules: Vec<ExtractedModulePCodeAnalysis>,
    pub truncated: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PCodeAnalysisOptions {
    pub profile: crate::compiled::PCodeLayoutProfile,
    pub max_lines: usize,
    pub max_modules: usize,
    pub max_instructions: usize,
    pub max_paths: usize,
    pub max_steps: usize,
    pub branch_base: PCodeBranchBase,
}

impl Default for PCodeAnalysisOptions {
    fn default() -> Self {
        Self {
            profile: crate::compiled::PCodeLayoutProfile::Vba7Observed,
            max_lines: 65_535,
            max_modules: 1_024,
            max_instructions: 100_000,
            max_paths: 10_000,
            max_steps: 100_000,
            branch_base: PCodeBranchBase::InstructionStart,
        }
    }
}

/// Decode and semantically explore one extracted module's observed compiled
/// representation with caller-supplied, version-specific schemas. A missing
/// line map returns `Ok(None)`; no opcode or operand meanings are inferred.
pub fn analyze_extracted_module_pcode(
    module: &ExtractedModule,
    instruction_schema: &PCodeInstructionSchema,
    semantic_schema: &PCodeSemanticSchema,
    max_instructions: usize,
    max_paths: usize,
    max_steps: usize,
    branch_base: PCodeBranchBase,
) -> Result<Option<(crate::compiled::PCodeDecodeReport, PCodeSemanticPathReport)>, String> {
    let Some(line_map) = module.pcode_layout.as_ref() else {
        return Ok(None);
    };
    let decoded = decode_pcode_lines_with_schema(line_map, instruction_schema, max_instructions)?;
    let semantic =
        analyze_pcode_semantic_paths(&decoded, semantic_schema, max_paths, max_steps, branch_base)?;
    Ok(Some((decoded, semantic)))
}

/// Options-struct variant of `analyze_extracted_module_pcode`.
pub fn analyze_extracted_module_pcode_with_options(
    module: &ExtractedModule,
    instruction_schema: &PCodeInstructionSchema,
    semantic_schema: &PCodeSemanticSchema,
    options: &PCodeAnalysisOptions,
) -> Result<Option<(crate::compiled::PCodeDecodeReport, PCodeSemanticPathReport)>, String> {
    analyze_extracted_module_pcode(
        module,
        instruction_schema,
        semantic_schema,
        options.max_instructions,
        options.max_paths,
        options.max_steps,
        options.branch_base,
    )
}

/// Analyze all extracted modules that have a selected p-code line map. Modules
/// without a map are skipped; the result is bounded by `max_modules` and keeps
/// the caller-supplied schema status explicit.
#[allow(clippy::too_many_arguments)]
pub fn analyze_extracted_project_pcode(
    project: &ExtractedProject,
    instruction_schema: &PCodeInstructionSchema,
    semantic_schema: &PCodeSemanticSchema,
    max_modules: usize,
    max_instructions: usize,
    max_paths: usize,
    max_steps: usize,
    branch_base: PCodeBranchBase,
) -> Result<ExtractedProjectPCodeAnalysis, String> {
    let mut result = ExtractedProjectPCodeAnalysis::default();
    for module in &project.modules {
        if result.modules.len() >= max_modules {
            result.truncated = true;
            break;
        }
        let Some((decoded, semantic_paths)) = analyze_extracted_module_pcode(
            module,
            instruction_schema,
            semantic_schema,
            max_instructions,
            max_paths,
            max_steps,
            branch_base,
        )?
        else {
            continue;
        };
        result.modules.push(ExtractedModulePCodeAnalysis {
            module_name: module.name.clone(),
            decoded,
            semantic_paths,
        });
    }
    Ok(result)
}

/// Options-struct variant of `analyze_extracted_project_pcode`.
pub fn analyze_extracted_project_pcode_with_options(
    project: &ExtractedProject,
    instruction_schema: &PCodeInstructionSchema,
    semantic_schema: &PCodeSemanticSchema,
    options: &PCodeAnalysisOptions,
) -> Result<ExtractedProjectPCodeAnalysis, String> {
    analyze_extracted_project_pcode(
        project,
        instruction_schema,
        semantic_schema,
        options.max_modules,
        options.max_instructions,
        options.max_paths,
        options.max_steps,
        options.branch_base,
    )
}

pub fn extract_xlsm(data: &[u8], limits: &Limits) -> Result<ExtractedProject, String> {
    let zip = ZipArchive::open(data, limits)?;
    let package = crate::opc::resolve_xlsm_package(
        &zip,
        limits.max_zip_entries,
        limits.max_workbook_cells,
        limits.max_workbook_formula_references,
        limits.max_workbook_formula_cell_links,
        limits.max_workbook_tables,
    )?;
    let entry = zip.find(&package.vba_project_part).ok_or_else(|| {
        format!(
            "OOXML VBA project part is missing: {}",
            package.vba_project_part
        )
    })?;
    let bin = zip.read(entry)?;
    let mut extracted = extract_vba_project(&bin, limits)?;
    extracted.workbook_code_name = package.workbook_code_name;
    extracted.workbook_sheets = package.workbook_sheets;
    extracted.workbook_defined_names = package.workbook_defined_names;
    extracted.workbook_tables = package.workbook_tables;
    extracted.workbook_tables_truncated = package.workbook_tables_truncated;
    extracted.workbook_cells = package.workbook_cells;
    extracted.workbook_cells_truncated = package.workbook_cells_truncated;
    extracted.diagnostics.extend(package.workbook_diagnostics);

    fn normalize_formula_chars(formula: &str) -> String {
        formula
            .chars()
            .map(|c| match c {
                '\u{3000}' => ' ',
                '\u{FF01}'..='\u{FF5E}' => char::from_u32((c as u32) - 0xFEE0).unwrap_or(c),
                _ => c,
            })
            .collect()
    }

    for sheet in &extracted.workbook_sheets {
        let is_macrosheet = sheet.kind.eq_ignore_ascii_case("macrosheet");
        let is_very_hidden = sheet
            .state
            .as_deref()
            .is_some_and(|s| s.eq_ignore_ascii_case("veryHidden"));

        if is_macrosheet {
            extracted.diagnostics.push(format!(
                "Security warning: Workbook contains Excel 4.0 (XLM) macro sheet '{}' (state: {})",
                sheet.name,
                sheet.state.as_deref().unwrap_or("visible")
            ));
            extracted.cell_threats.push(CellThreat {
                sheet_name: sheet.name.clone(),
                cell_ref: "Sheet".into(),
                coordinate: format!("sheet:{}", sheet.name),
                threat_kind: "XlmMacroSheet".into(),
                severity: "Critical".into(),
                formula: String::new(),
                description: format!(
                    "Workbook contains Excel 4.0 (XLM) macro sheet '{}' (state: {})",
                    sheet.name,
                    sheet.state.as_deref().unwrap_or("visible")
                ),
            });
        } else if is_very_hidden {
            extracted.diagnostics.push(format!(
                "Security warning: Worksheet '{}' is set to 'veryHidden' (hidden from standard Excel UI)",
                sheet.name
            ));
            extracted.cell_threats.push(CellThreat {
                sheet_name: sheet.name.clone(),
                cell_ref: "Sheet".into(),
                coordinate: format!("sheet:{}", sheet.name),
                threat_kind: "VeryHiddenSheet".into(),
                severity: "Low".into(),
                formula: String::new(),
                description: format!(
                    "Worksheet '{}' is set to 'veryHidden' (hidden from standard Excel UI)",
                    sheet.name
                ),
            });
        }
    }

    for defined_name in &extracted.workbook_defined_names {
        let name_lower = defined_name.name.to_ascii_lowercase();
        let is_auto_exec_name = matches!(
            name_lower.as_str(),
            "auto_open"
                | "_xlnm.auto_open"
                | "auto_close"
                | "_xlnm.auto_close"
                | "auto_activate"
                | "_xlnm.auto_activate"
                | "auto_deactivate"
                | "_xlnm.auto_deactivate"
        );
        if is_auto_exec_name {
            extracted.diagnostics.push(format!(
                "Security warning: Workbook defined name '{}' triggers auto-execution on open/close (target: '{}', hidden: {})",
                defined_name.name,
                defined_name.formula,
                defined_name.hidden.unwrap_or(false)
            ));
            extracted.cell_threats.push(CellThreat {
                sheet_name: defined_name
                    .local_sheet_name
                    .clone()
                    .unwrap_or_else(|| "Workbook".into()),
                cell_ref: defined_name.name.clone(),
                coordinate: format!("definedName:{}", defined_name.name),
                threat_kind: "AutoExecDefinedName".into(),
                severity: "High".into(),
                formula: defined_name.formula.clone(),
                description: format!(
                    "Workbook defined name '{}' triggers auto-execution on open/close (target: '{}', hidden: {})",
                    defined_name.name,
                    defined_name.formula,
                    defined_name.hidden.unwrap_or(false)
                ),
            });
        }

        let norm_fn = normalize_formula_chars(&defined_name.formula);
        let f_clean = norm_fn
            .trim()
            .trim_start_matches(|c: char| {
                c.is_whitespace() || c == '=' || c == '+' || c == '-' || c == '@'
            })
            .trim();
        let f_norm = f_clean.replace("_xlfn.", "").replace("_xlws.", "");
        let f_lower = f_norm.to_ascii_lowercase();

        let is_dde_name = if let Some((target, _)) = f_clean.split_once('|') {
            let target_clean = target
                .trim()
                .trim_matches(|c: char| c == '"' || c == '\'' || c.is_whitespace());
            let target_lower = target_clean.to_ascii_lowercase();
            let file_name = target_lower
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or(&target_lower);
            let base = file_name.strip_suffix(".exe").unwrap_or(file_name);
            matches!(
                base,
                "cmd"
                    | "powershell"
                    | "pwsh"
                    | "mshta"
                    | "cscript"
                    | "wscript"
                    | "rundll32"
                    | "regsvr32"
                    | "certutil"
                    | "bitsadmin"
                    | "msiexec"
                    | "msdt"
                    | "control"
                    | "explorer"
                    | "wmic"
                    | "msxsl"
            ) || f_lower.contains("|'")
        } else {
            false
        };

        let is_xlm_name = f_lower.contains("exec(")
            || f_lower.contains("call(")
            || f_lower.contains("register(")
            || f_lower.contains("run(");

        if is_dde_name {
            extracted.diagnostics.push(format!(
                "Security warning: Potential DDE execution formula in defined name '{}': '{}'",
                defined_name.name, defined_name.formula
            ));
            extracted.cell_threats.push(CellThreat {
                sheet_name: defined_name
                    .local_sheet_name
                    .clone()
                    .unwrap_or_else(|| "Workbook".into()),
                cell_ref: defined_name.name.clone(),
                coordinate: format!("definedName:{}", defined_name.name),
                threat_kind: "DDE".into(),
                severity: "Critical".into(),
                formula: defined_name.formula.clone(),
                description: format!(
                    "Potential DDE execution formula in defined name '{}': '{}'",
                    defined_name.name, defined_name.formula
                ),
            });
        } else if is_xlm_name {
            extracted.diagnostics.push(format!(
                "Security warning: Potential Excel 4.0 (XLM) macro execution formula in defined name '{}': '{}'",
                defined_name.name, defined_name.formula
            ));
            extracted.cell_threats.push(CellThreat {
                sheet_name: defined_name
                    .local_sheet_name
                    .clone()
                    .unwrap_or_else(|| "Workbook".into()),
                cell_ref: defined_name.name.clone(),
                coordinate: format!("definedName:{}", defined_name.name),
                threat_kind: "XLM".into(),
                severity: "Critical".into(),
                formula: defined_name.formula.clone(),
                description: format!(
                    "Potential Excel 4.0 (XLM) macro execution formula in defined name '{}': '{}'",
                    defined_name.name, defined_name.formula
                ),
            });
        } else if f_lower.contains("rtd(") {
            let is_dangerous_rtd = f_lower.contains("wscript")
                || f_lower.contains("shell")
                || f_lower.contains("scripting.filesystemobject")
                || f_lower.contains("system.diagnostics")
                || f_lower.contains("cmd")
                || f_lower.contains("powershell")
                || f_lower.contains("\\\\");
            let sev = if is_dangerous_rtd { "Critical" } else { "High" };
            let desc = format!(
                "Potential COM Real-Time Data (RTD) execution formula in defined name '{}': '{}'",
                defined_name.name, defined_name.formula
            );
            extracted
                .diagnostics
                .push(format!("Security warning: {desc}"));
            extracted.cell_threats.push(CellThreat {
                sheet_name: defined_name
                    .local_sheet_name
                    .clone()
                    .unwrap_or_else(|| "Workbook".into()),
                cell_ref: defined_name.name.clone(),
                coordinate: format!("definedName:{}", defined_name.name),
                threat_kind: "RealTimeData".into(),
                severity: sev.into(),
                formula: defined_name.formula.clone(),
                description: desc,
            });
        }
    }

    for cell in &extracted.workbook_cells {
        if let Some(formula) = &cell.formula {
            let norm_formula = normalize_formula_chars(formula);
            let f_clean = norm_formula
                .trim()
                .trim_start_matches(|c: char| {
                    c.is_whitespace() || c == '=' || c == '+' || c == '-' || c == '@'
                })
                .trim();
            let f_norm = f_clean.replace("_xlfn.", "").replace("_xlws.", "");
            let f_lower = f_norm.to_ascii_lowercase();

            // Helper to check for function calls with whitespace tolerance before parenthesis
            let has_fn = |name: &str| -> bool {
                let mut search_from = 0;
                while let Some(idx) = f_lower[search_from..].find(name) {
                    let abs_idx = search_from + idx;
                    let prefix_ok = abs_idx == 0
                        || (!f_lower.as_bytes()[abs_idx - 1].is_ascii_alphanumeric()
                            && f_lower.as_bytes()[abs_idx - 1] != b'_'
                            && f_lower.as_bytes()[abs_idx - 1] != b'.');
                    if prefix_ok {
                        let rest = f_lower[abs_idx + name.len()..].trim_start();
                        if rest.starts_with('(') {
                            return true;
                        }
                    }
                    search_from = abs_idx + name.len();
                }
                false
            };

            // Helper to check DDE executable target
            let check_dde_target = |target: &str| -> bool {
                let target_clean = target
                    .trim()
                    .trim_matches(|c: char| c == '"' || c == '\'' || c.is_whitespace());
                let target_lower = target_clean.to_ascii_lowercase();
                let file_name = target_lower
                    .rsplit(['/', '\\'])
                    .next()
                    .unwrap_or(&target_lower);
                let base = file_name.strip_suffix(".exe").unwrap_or(file_name);
                matches!(
                    base,
                    "cmd"
                        | "powershell"
                        | "pwsh"
                        | "mshta"
                        | "cscript"
                        | "wscript"
                        | "rundll32"
                        | "regsvr32"
                        | "certutil"
                        | "certreq"
                        | "bitsadmin"
                        | "msiexec"
                        | "msexcel"
                        | "excel"
                        | "hh"
                        | "bash"
                        | "sh"
                        | "python"
                        | "python3"
                        | "pythonw"
                        | "wsl"
                        | "tar"
                        | "conhost"
                        | "wt"
                        | "schtasks"
                        | "reg"
                        | "at"
                        | "curl"
                        | "msdt"
                        | "control"
                        | "explorer"
                        | "wmic"
                        | "msxsl"
                        | "finger"
                        | "nltest"
                        | "whoami"
                        | "systeminfo"
                        | "tasklist"
                        | "taskkill"
                        | "sc"
                        | "net"
                        | "net1"
                )
            };

            // Attempt bounded evaluation of formula to detect de-obfuscated payload strings
            let evaluated_text: Option<String> = if f_lower.contains("char")
                || f_lower.contains('&')
                || f_lower.contains("concat")
                || f_lower.contains("substitute")
                || f_lower.contains("replace")
                || f_lower.contains("mid")
                || f_lower.contains("left")
                || f_lower.contains("right")
                || f_lower.contains("choose")
                || f_lower.contains("proper")
                || f_lower.contains("unichar")
                || f_lower.contains("unicode")
                || f_lower.contains("hex2dec")
                || f_lower.contains("dec2hex")
                || f_lower.contains("bin2dec")
                || f_lower.contains("dec2bin")
                || f_lower.contains("oct2dec")
                || f_lower.contains("dec2oct")
                || f_lower.contains("textjoin")
                || f_lower.contains("index")
                || f_lower.contains("vlookup")
                || f_lower.contains("hlookup")
                || f_lower.contains("match")
                || f_lower.contains("indirect")
                || f_lower.contains("offset")
                || f_lower.contains("address")
                || f_lower.contains("bitand")
                || f_lower.contains("bitor")
                || f_lower.contains("bitxor")
                || f_lower.contains("bitlshift")
                || f_lower.contains("bitrshift")
                || f_lower.contains("xlookup")
                || f_lower.contains("xmatch")
                || f_lower.contains("textbefore")
                || f_lower.contains("textafter")
                || f_lower.contains("textsplit")
                || f_lower.contains("base")
                || f_lower.contains("decimal")
                || f_lower.contains("delta")
                || f_lower.contains("gestep")
                || f_lower.contains("take")
                || f_lower.contains("drop")
                || f_lower.contains("chooserows")
                || f_lower.contains("choosecols")
                || f_lower.contains("torow")
                || f_lower.contains("tocol")
                || f_lower.contains("expand")
                || f_lower.contains("wraprows")
                || f_lower.contains("wrapcols")
                || f_lower.contains("filter")
                || f_lower.contains("sort")
                || f_lower.contains("sortby")
                || f_lower.contains("unique")
                || f_lower.contains("rows")
                || f_lower.contains("columns")
                || f_lower.contains("mround")
                || f_lower.contains("arraytotext")
                || f_lower.contains("valuetotext")
                || f_lower.contains("formulatext")
                || f_lower.contains("roman")
                || f_lower.contains("arabic")
                || f_lower.contains("type")
                || f_lower.contains("isnontext")
                || f_lower.contains("let")
                || f_lower.contains("lambda")
                || f_lower.contains("encodeurl")
                || f_lower.contains("bin2hex")
                || f_lower.contains("hex2bin")
                || f_lower.contains("oct2hex")
                || f_lower.contains("hex2oct")
                || f_lower.contains("numbervalue")
                || f_lower.contains("map")
                || f_lower.contains("reduce")
                || f_lower.contains("scan")
                || f_lower.contains("byrow")
                || f_lower.contains("bycol")
                || f_lower.contains("makearray")
                || f_lower.contains("isomitted")
                || f_lower.contains("vstack")
                || f_lower.contains("hstack")
                || f_lower.contains("ifs")
                || f_lower.contains("switch")
                || f_lower.contains("xor")
                || f_lower.contains("sequence")
                || f_lower.contains("single")
                || f_lower.contains("transpose")
                || f_lower.contains("lookup")
                || f_lower.contains("delta")
                || f_lower.contains("gestep")
                || f_lower.contains("sign")
                || f_lower.contains("lenb")
                || f_lower.contains("leftb")
                || f_lower.contains("rightb")
                || f_lower.contains("midb")
                || f_lower.contains("quotient")
                || f_lower.contains("even")
                || f_lower.contains("odd")
                || f_lower.contains("fact")
                || f_lower.contains("gcd")
                || f_lower.contains("lcm")
                || f_lower.contains("combin")
                || f_lower.contains("permut")
                || f_lower.contains("sumproduct")
                || f_lower.contains("exp")
                || f_lower.contains("log")
                || f_lower.contains("ln")
                || f_lower.contains("sinh")
                || f_lower.contains("cosh")
                || f_lower.contains("tanh")
                || f_lower.contains("asinh")
                || f_lower.contains("acosh")
                || f_lower.contains("atanh")
                || f_lower.contains("sqrtpi")
                || f_lower.contains("sumsq")
                || f_lower.contains("sec")
                || f_lower.contains("csc")
                || f_lower.contains("cot")
                || f_lower.contains("sech")
                || f_lower.contains("csch")
                || f_lower.contains("coth")
                || f_lower.contains("acot")
                || f_lower.contains("acoth")
                || f_lower.contains("mmult")
                || f_lower.contains("munit")
                || f_lower.contains("mdeterm")
                || f_lower.contains("minverse")
                || f_lower.contains("int")
                || f_lower.contains("seriessum")
                || f_lower.contains("complex")
                || f_lower.contains("imreal")
                || f_lower.contains("imaginary")
                || f_lower.contains("imabs")
                || f_lower.contains("imconjg")
                || f_lower.contains("sumxmy2")
                || f_lower.contains("sumx2my2")
                || f_lower.contains("sumx2py2")
                || f_lower.contains("multinomial")
                || f_lower.contains("imsum")
                || f_lower.contains("imsub")
                || f_lower.contains("improduct")
                || f_lower.contains("imdiv")
                || f_lower.contains("impower")
                || f_lower.contains("imexp")
                || f_lower.contains("imln")
                || f_lower.contains("imsqrt")
                || f_lower.contains("combina")
                || f_lower.contains("permutationa")
                || f_lower.contains("isodd")
                || f_lower.contains("iseven")
                || f_lower.contains("imsin")
                || f_lower.contains("imcos")
                || f_lower.contains("imtan")
                || f_lower.contains("imsinh")
                || f_lower.contains("imcosh")
                || f_lower.contains("imsec")
                || f_lower.contains("imcsc")
                || f_lower.contains("imcot")
                || f_lower.contains("imlog10")
                || f_lower.contains("imlog2")
                || f_lower.contains("gamma")
                || f_lower.contains("gammaln")
                || f_lower.contains("imargument")
                || f_lower.contains("imconjugate")
                || f_lower.contains("erf")
                || f_lower.contains("erfc")
                || f_lower.contains("gauss")
                || f_lower.contains("phi")
                || f_lower.contains("besselj")
                || f_lower.contains("besseli")
                || f_lower.contains("bessely")
                || f_lower.contains("besselk")
                || f_lower.contains("error.type")
                || f_lower.contains("isformula")
                || f_lower.contains("standardize")
                || f_lower.contains("normsdist")
                || f_lower.contains("norm.s.dist")
                || f_lower.contains("normdist")
                || f_lower.contains("norm.dist")
                || f_lower.contains("expondist")
                || f_lower.contains("expon.dist")
                || f_lower.contains("weibull")
                || f_lower.contains("convert")
                || f_lower.contains("sln")
                || f_lower.contains("syd")
                || f_lower.contains("npv")
                || f_lower.contains("pv")
                || f_lower.contains("fv")
                || f_lower.contains("pmt")
                || f_lower.contains("lognorm")
                || f_lower.contains("poisson")
                || f_lower.contains("binom")
                || f_lower.contains("irr")
                || f_lower.contains("mirr")
                || f_lower.contains("disc")
                || f_lower.contains("pricedisc")
                || f_lower.contains("received")
                || f_lower.contains("hypgeom")
                || f_lower.contains("effect")
                || f_lower.contains("nominal")
                || f_lower.contains("ipmt")
                || f_lower.contains("ppmt")
                || f_lower.contains("cumipmt")
                || f_lower.contains("cumprinc")
                || f_lower.contains("critbinom")
                || f_lower.contains("duration")
                || f_lower.contains("mduration")
                || f_lower.contains("intrate")
                || f_lower.contains("chisq")
                || f_lower.contains("chidist")
                || f_lower.contains("chiinv")
                || f_lower.contains("tbillprice")
                || f_lower.contains("tbillyield")
                || f_lower.contains("dollarde")
                || f_lower.contains("dollarfr")
                || f_lower.contains("accrintm")
                || f_lower.contains("gamma")
                || f_lower.contains("beta")
                || f_lower.contains("pricemat")
                || f_lower.contains("yieldmat")
                || f_lower.contains("coup")
                || has_fn("hyperlink")
            {
                let eval_res = crate::formula_eval::evaluate_formula(
                    formula,
                    Some(&cell.sheet_name),
                    &extracted.workbook_cells,
                    crate::formula_eval::FormulaEvaluationLimits::default(),
                );
                if eval_res.status == "resolved" {
                    if let Some(crate::formula_eval::FormulaValue::String(s)) = eval_res.value {
                        Some(s)
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            // 1. DDE binary and execution detection
            let is_dde_func = has_fn("dde") || has_fn("dde.execute");
            let is_raw_dde_pipe = if let Some((target, _)) = f_clean.split_once('|') {
                check_dde_target(target) || f_lower.contains("|'")
            } else {
                false
            };
            let is_deobfuscated_dde = if let Some(ref ev) = evaluated_text {
                if let Some((target, _)) = ev.split_once('|') {
                    check_dde_target(target) || ev.contains("|'")
                } else {
                    false
                }
            } else {
                false
            };
            let is_dde = is_dde_func || is_raw_dde_pipe || is_deobfuscated_dde;

            // 2. Excel 4.0 (XLM) macro functions
            let is_xlm = has_fn("exec")
                || has_fn("call")
                || has_fn("register")
                || has_fn("register.id")
                || has_fn("run")
                || has_fn("formula")
                || has_fn("alert")
                || has_fn("halt")
                || has_fn("popen")
                || has_fn("fcall")
                || has_fn("fopen")
                || has_fn("fwrite")
                || has_fn("fclose")
                || has_fn("initiate")
                || has_fn("terminate")
                || has_fn("request")
                || has_fn("poke");

            // 3. Remote workbook link injection (UNC, HTTP, HTTPS, FTP)
            let is_remote_link = (f_lower.contains("[http://")
                || f_lower.contains("[https://")
                || f_lower.contains("[ftp://")
                || f_lower.contains("['http://")
                || f_lower.contains("['https://")
                || f_lower.contains("['ftp://")
                || f_lower.contains("['\\\\")
                || f_lower.contains("[\\\\"))
                && (f_lower.contains("]") || f_lower.contains("']"));

            // 4. External web service request / data exfiltration
            let is_webservice = has_fn("webservice") || has_fn("filterxml");

            // 5. COM Real-Time Data (RTD) server execution
            let is_rtd = has_fn("rtd");
            let is_dangerous_rtd = f_lower.contains("wscript")
                || f_lower.contains("shell")
                || f_lower.contains("scripting.filesystemobject")
                || f_lower.contains("system.diagnostics")
                || f_lower.contains("cmd")
                || f_lower.contains("powershell")
                || f_lower.contains("\\\\");

            // 6. Suspicious executable download hyperlink or protocol handler
            let check_suspicious_hyperlink = |text: &str| -> bool {
                let t = text.to_ascii_lowercase();
                t.contains(".exe")
                    || t.contains(".scr")
                    || t.contains(".vbs")
                    || t.contains(".vbe")
                    || t.contains(".js")
                    || t.contains(".jse")
                    || t.contains(".wsf")
                    || t.contains(".wsh")
                    || t.contains(".hta")
                    || t.contains(".bat")
                    || t.contains(".cmd")
                    || t.contains(".ps1")
                    || t.contains(".iso")
                    || t.contains(".img")
                    || t.contains(".vhd")
                    || t.contains(".vhdx")
                    || t.contains(".zip")
                    || t.contains(".dll")
                    || {
                        let mut pos = 0;
                        let mut found = false;
                        while let Some(idx) = t[pos..].find(".com") {
                            let abs = pos + idx;
                            let after = &t[abs + 4..];
                            if !after.starts_with('/')
                                && !after.starts_with('.')
                                && !after
                                    .chars()
                                    .next()
                                    .is_some_and(|c| c.is_ascii_alphanumeric() || c == '-')
                            {
                                found = true;
                                break;
                            }
                            pos = abs + 4;
                        }
                        found
                    }
                    || t.contains(".pif")
                    || t.contains(".cpl")
                    || t.contains(".msc")
                    || t.contains(".inf")
                    || t.contains(".reg")
                    || t.contains(".lnk")
                    || t.contains(".chm")
                    || t.contains(".jar")
                    || t.contains("ms-appinstaller:")
                    || t.contains("search-ms:")
                    || t.contains("ms-officecmd:")
                    || t.contains("ms-excel:")
                    || t.contains("ms-word:")
                    || t.contains("ms-powerpoint:")
                    || t.contains("shell:")
                    || t.contains("file://")
                    || t.contains("file:\\\\")
            };

            let is_raw_hyperlink = has_fn("hyperlink") && check_suspicious_hyperlink(&f_lower);
            let is_deobfuscated_hyperlink = !is_raw_hyperlink
                && has_fn("hyperlink")
                && evaluated_text
                    .as_ref()
                    .is_some_and(|s| check_suspicious_hyperlink(s));
            let is_suspicious_hyperlink = is_raw_hyperlink || is_deobfuscated_hyperlink;

            let is_deobfuscated_threat = if !is_dde
                && !is_xlm
                && !is_remote_link
                && !is_webservice
                && !is_rtd
                && !is_suspicious_hyperlink
            {
                if let Some(ref ev) = evaluated_text {
                    let ev_lower = ev.to_ascii_lowercase();
                    let has_cmd = ev_lower.contains("powershell")
                        || ev_lower.contains("cmd.exe")
                        || ev_lower.contains("mshta")
                        || ev_lower.contains("cscript")
                        || ev_lower.contains("wscript")
                        || ev_lower.contains("rundll32")
                        || ev_lower.contains("regsvr32")
                        || ev_lower.contains("certutil")
                        || ev_lower.contains("bitsadmin")
                        || ev_lower.contains("wmic")
                        || ev_lower.contains("curl ")
                        || ev_lower.contains("msdt ")
                        || ev_lower.contains("hh.exe")
                        || ev_lower.contains("installutil")
                        || ev_lower.contains("regasm")
                        || ev_lower.contains("regsvcs")
                        || ev_lower.contains("msconfig")
                        || ev_lower.contains("control.exe")
                        || ev_lower.contains("bash.exe")
                        || ev_lower.contains("wsl.exe");
                    let has_payload_url = (ev_lower.contains("http://")
                        || ev_lower.contains("https://"))
                        && (ev_lower.ends_with(".exe")
                            || ev_lower.ends_with(".ps1")
                            || ev_lower.ends_with(".bat")
                            || ev_lower.ends_with(".vbs")
                            || ev_lower.ends_with(".dll"));
                    has_cmd || has_payload_url
                } else {
                    false
                }
            } else {
                false
            };

            if is_dde {
                let is_raw_target_clean = f_clean
                    .split_once('|')
                    .is_some_and(|(t, _)| check_dde_target(t));
                let is_deobfuscated = is_deobfuscated_dde
                    && (!is_raw_target_clean || evaluated_text.as_deref() != Some(formula));
                let desc = if is_deobfuscated {
                    format!(
                        "De-obfuscated DDE execution formula in cell '{}'!{}: '{}' resolves to '{}'",
                        cell.sheet_name,
                        cell.cell_ref,
                        formula,
                        evaluated_text.as_deref().unwrap_or("")
                    )
                } else {
                    format!(
                        "Potential DDE execution formula in cell '{}'!{}: '{}'",
                        cell.sheet_name, cell.cell_ref, formula
                    )
                };
                extracted
                    .diagnostics
                    .push(format!("Security warning: {}", desc));
                extracted.cell_threats.push(CellThreat {
                    sheet_name: cell.sheet_name.clone(),
                    cell_ref: cell.cell_ref.clone(),
                    coordinate: format!("'{}'!{}", cell.sheet_name, cell.cell_ref),
                    threat_kind: "DDE".into(),
                    severity: "Critical".into(),
                    formula: formula.clone(),
                    description: desc,
                });
            } else if is_xlm {
                let desc = format!(
                    "Potential Excel 4.0 (XLM) macro execution formula in cell '{}'!{}: '{}'",
                    cell.sheet_name, cell.cell_ref, formula
                );
                extracted
                    .diagnostics
                    .push(format!("Security warning: {}", desc));
                extracted.cell_threats.push(CellThreat {
                    sheet_name: cell.sheet_name.clone(),
                    cell_ref: cell.cell_ref.clone(),
                    coordinate: format!("'{}'!{}", cell.sheet_name, cell.cell_ref),
                    threat_kind: "XLM".into(),
                    severity: "Critical".into(),
                    formula: formula.clone(),
                    description: desc,
                });
            } else if is_remote_link {
                let desc = format!(
                    "Potential remote workbook link injection in cell '{}'!{}: '{}'",
                    cell.sheet_name, cell.cell_ref, formula
                );
                extracted
                    .diagnostics
                    .push(format!("Security warning: {}", desc));
                extracted.cell_threats.push(CellThreat {
                    sheet_name: cell.sheet_name.clone(),
                    cell_ref: cell.cell_ref.clone(),
                    coordinate: format!("'{}'!{}", cell.sheet_name, cell.cell_ref),
                    threat_kind: "RemoteLink".into(),
                    severity: "High".into(),
                    formula: formula.clone(),
                    description: desc,
                });
            } else if is_webservice {
                let desc = format!(
                    "Potential external data request / exfiltration formula in cell '{}'!{}: '{}'",
                    cell.sheet_name, cell.cell_ref, formula
                );
                extracted
                    .diagnostics
                    .push(format!("Security warning: {}", desc));
                extracted.cell_threats.push(CellThreat {
                    sheet_name: cell.sheet_name.clone(),
                    cell_ref: cell.cell_ref.clone(),
                    coordinate: format!("'{}'!{}", cell.sheet_name, cell.cell_ref),
                    threat_kind: "WebService".into(),
                    severity: "Medium".into(),
                    formula: formula.clone(),
                    description: desc,
                });
            } else if is_rtd {
                let sev = if is_dangerous_rtd { "Critical" } else { "High" };
                let desc = format!(
                    "Potential COM Real-Time Data (RTD) server execution formula in cell '{}'!{}: '{}'",
                    cell.sheet_name, cell.cell_ref, formula
                );
                extracted
                    .diagnostics
                    .push(format!("Security warning: {}", desc));
                extracted.cell_threats.push(CellThreat {
                    sheet_name: cell.sheet_name.clone(),
                    cell_ref: cell.cell_ref.clone(),
                    coordinate: format!("'{}'!{}", cell.sheet_name, cell.cell_ref),
                    threat_kind: "RealTimeData".into(),
                    severity: sev.into(),
                    formula: formula.clone(),
                    description: desc,
                });
            } else if is_suspicious_hyperlink {
                let desc = if is_deobfuscated_hyperlink {
                    format!(
                        "Suspicious executable download hyperlink de-obfuscated in cell '{}'!{}: '{}' resolves to '{}'",
                        cell.sheet_name,
                        cell.cell_ref,
                        formula,
                        evaluated_text.as_deref().unwrap_or("")
                    )
                } else {
                    format!(
                        "Suspicious executable download hyperlink in cell '{}'!{}: '{}'",
                        cell.sheet_name, cell.cell_ref, formula
                    )
                };
                extracted
                    .diagnostics
                    .push(format!("Security warning: {}", desc));
                extracted.cell_threats.push(CellThreat {
                    sheet_name: cell.sheet_name.clone(),
                    cell_ref: cell.cell_ref.clone(),
                    coordinate: format!("'{}'!{}", cell.sheet_name, cell.cell_ref),
                    threat_kind: "SuspiciousHyperlink".into(),
                    severity: "High".into(),
                    formula: formula.clone(),
                    description: desc,
                });
            } else if is_deobfuscated_threat {
                let resolved = evaluated_text.as_deref().unwrap_or("");
                let desc = format!(
                    "De-obfuscated threat formula in cell '{}'!{}: '{}' resolves to malicious payload '{}'",
                    cell.sheet_name, cell.cell_ref, formula, resolved
                );
                extracted
                    .diagnostics
                    .push(format!("Security warning: {}", desc));
                extracted.cell_threats.push(CellThreat {
                    sheet_name: cell.sheet_name.clone(),
                    cell_ref: cell.cell_ref.clone(),
                    coordinate: format!("'{}'!{}", cell.sheet_name, cell.cell_ref),
                    threat_kind: "DeobfuscatedThreat".into(),
                    severity: "Critical".into(),
                    formula: formula.clone(),
                    description: desc,
                });
            }
        }
    }
    scan_ooxml_package_threats(
        &zip,
        &mut extracted.cell_threats,
        &mut extracted.diagnostics,
        limits.max_zip_entries,
    );
    Ok(extracted)
}

/// Extract an `.xlsm` and attach a caller-selected observed p-code line-map
/// profile to each module. The raw cache remains unverified; this only applies
/// the structural profile and preserves malformed/no-map states as metadata.
pub fn extract_xlsm_with_pcode_profile(
    data: &[u8],
    limits: &Limits,
    profile: crate::compiled::PCodeLayoutProfile,
    max_lines: usize,
) -> Result<ExtractedProject, String> {
    let mut project = extract_xlsm(data, limits)?;
    attach_pcode_profile(&mut project, profile, max_lines);
    Ok(project)
}

fn attach_pcode_profile(
    project: &mut ExtractedProject,
    profile: crate::compiled::PCodeLayoutProfile,
    max_lines: usize,
) {
    project.compiled_representation_status =
        "vba7_observed_line_map_only; opcode semantics are not decoded".into();
    for module in &mut project.modules {
        match inspect_vba7_line_map(&module.performance_cache, profile, max_lines) {
            Ok(Some(map)) => {
                module.pcode_layout_status = "line_map_parsed_raw_bytes_only".into();
                module.pcode_layout = Some(map);
            }
            Ok(None) => {
                module.pcode_layout_status = "no_valid_line_map_found_for_selected_profile".into();
            }
            Err(error) => {
                module.pcode_layout_status = "malformed_line_map".into();
                project
                    .diagnostics
                    .push(format!("{} p-code layout: {error}", module.name));
            }
        }
    }
}

/// Extract a raw VBA project binary and attach a caller-selected observed
/// p-code line-map profile to its modules.
pub fn extract_vba_project_with_pcode_profile(
    data: &[u8],
    limits: &Limits,
    profile: crate::compiled::PCodeLayoutProfile,
    max_lines: usize,
) -> Result<ExtractedProject, String> {
    let mut project = extract_vba_project(data, limits)?;
    attach_pcode_profile(&mut project, profile, max_lines);
    Ok(project)
}

pub fn extract_vba_project(data: &[u8], limits: &Limits) -> Result<ExtractedProject, String> {
    let cfb = CompoundFile::open(data, limits)?;

    // Locate the `dir` stream and determine the VBA storage prefix.
    // Standard path is "VBA/dir", but legacy files (e.g. .xls) or custom packages
    // may nest it under "_VBA_PROJECT_CUR/VBA/dir", "Macros/VBA/dir", etc.
    let (vba_prefix, dir) = match cfb.stream_by_path("VBA/dir")? {
        Some(d) => ("VBA/".to_string(), d),
        None => {
            let mut found = None;
            for e in &cfb.entries {
                if e.kind != 2 {
                    continue;
                }
                let p_lower = e.path.to_ascii_lowercase();
                let is_dir = p_lower == "vba/dir"
                    || p_lower.ends_with("/vba/dir")
                    || e.name.eq_ignore_ascii_case("dir");
                if !is_dir {
                    continue;
                }
                if let Ok(bytes) = cfb.stream(e) {
                    let prefix = if let Some(idx) = p_lower.rfind("dir") {
                        e.path[..idx].to_string()
                    } else {
                        String::new()
                    };
                    found = Some((prefix, bytes));
                    break;
                }
            }
            match found {
                Some((p, d)) => (p, d),
                None => {
                    let is_encrypted = cfb.entries.iter().any(|e| {
                        let clean = e.name.trim_start_matches('\x06').trim_matches('\0').trim();
                        clean.eq_ignore_ascii_case("EncryptionInfo")
                            || clean.eq_ignore_ascii_case("EncryptedPackage")
                    });
                    if is_encrypted {
                        return Err(
                            "encrypted Office container detected (contains EncryptedPackage/EncryptionInfo); password decryption required to inspect macros"
                                .to_string(),
                        );
                    }
                    return Err("VBA storage has no dir stream".to_string());
                }
            }
        }
    };

    let project_path = if vba_prefix.is_empty() || vba_prefix == "VBA/" {
        "PROJECT".to_string()
    } else {
        let parent_prefix = vba_prefix
            .strip_suffix("VBA/")
            .or_else(|| vba_prefix.strip_suffix("vba/"))
            .unwrap_or("");
        format!("{parent_prefix}PROJECT")
    };
    let project = cfb
        .stream_by_path(&project_path)
        .ok()
        .flatten()
        .or_else(|| cfb.stream_by_path("PROJECT").ok().flatten());
    let cache_path = format!("{vba_prefix}_VBA_PROJECT");
    let cache = cfb
        .stream_by_path(&cache_path)
        .ok()
        .flatten()
        .or_else(|| cfb.stream_by_path("VBA/_VBA_PROJECT").ok().flatten());

    let mut streams = Vec::new();
    let mut srp_caches = Vec::new();
    let mut total = 0usize;
    let vba_prefix_lower = vba_prefix.to_ascii_lowercase();
    let dir_path_lower = format!("{vba_prefix_lower}dir");
    let cache_path_lower = format!("{vba_prefix_lower}_vba_project");

    for e in &cfb.entries {
        let p_lower = e.path.to_ascii_lowercase();
        if e.kind != 2
            || !p_lower.starts_with(&vba_prefix_lower)
            || p_lower == dir_path_lower
            || p_lower == cache_path_lower
            || p_lower.ends_with("/dir")
            || p_lower.ends_with("/_vba_project")
        {
            continue;
        }
        let bytes = cfb.stream(e)?;
        total = total
            .checked_add(bytes.len())
            .ok_or("VBA streams size overflow")?;
        if total > limits.max_decompressed_bytes {
            return Err("total VBA streams exceed configured limit".into());
        }
        if is_srp_stream_name(&e.name) {
            srp_caches.push(SrpCacheRecord {
                stream_name: e.name.clone(),
                byte_length: bytes.len(),
                fingerprint: fingerprint_fnv1a64(&bytes),
            });
            continue;
        }
        let name = e.path.rsplit('/').next().unwrap_or(&e.name).to_string();
        streams.push((name, bytes));
    }
    let ovba = parse_project(
        &dir,
        project.as_deref(),
        cache.as_deref(),
        &streams,
        limits.max_decompressed_bytes,
        limits.max_modules,
    )?;
    let mut extracted = convert(ovba);
    extracted.srp_caches = srp_caches;
    if let Some(Ok(idents)) = cache
        .as_deref()
        .map(crate::pcode::parse_vba_project_identifiers)
    {
        extracted.identifiers = idents;
    }
    Ok(extracted)
}

#[cfg_attr(not(test), allow(dead_code))]
fn is_srp_stream_path(path: &str) -> bool {
    let mut parts = path.split('/');
    matches!((parts.next(), parts.next(), parts.next()), (Some(storage), Some(name), None)
        if storage.eq_ignore_ascii_case("VBA") && is_srp_stream_name(name))
}

fn is_srp_stream_name(name: &str) -> bool {
    let Some(hex) = name.strip_prefix("__SRP_").or_else(|| {
        name.get(..6)
            .filter(|prefix| prefix.eq_ignore_ascii_case("__SRP_"))
            .map(|_| &name[6..])
    }) else {
        return false;
    };
    (1..=25).contains(&hex.len()) && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn convert(p: OvbaProject) -> ExtractedProject {
    let mut result = ExtractedProject {
        name: p.name,
        code_page: p.code_page,
        system_kind: p.system_kind,
        project_version_tag: p.project_version,
        references: p.references,
        project_references: p.project_references,
        conditional_constants: p.compile_constants,
        ..ExtractedProject::default()
    };
    result.compiled_representation_status =
        "opaque_version_dependent_performance_cache; SRP streams inventoried; not disassembled or verified".into();
    result.project_cache=CacheRecord{module:"<project>".into(),byte_length:p.project_performance_cache_len,fingerprint:p.project_performance_cache_fingerprint,interpretation:"MS-OVBA performance cache is implementation/version dependent and MUST be ignored on read".into()};
    result.metadata.push((
        "VBA project version field".into(),
        p.project_version
            .map(|v| format!("0x{v:04X}"))
            .unwrap_or_else(|| "unavailable".into()),
    ));
    result.project_protection_cmg = p.project_protection_cmg.clone();
    result.project_protection_dpb = p.project_protection_dpb.clone();
    result.project_protection_gc = p.project_protection_gc.clone();
    result.is_locked_or_unviewable = p.project_protection_cmg.is_some()
        || p.project_protection_dpb.is_some()
        || p.project_protection_gc.is_some();
    result.hidden_gui_modules = p.hidden_gui_modules.clone();

    if result.is_locked_or_unviewable {
        result.diagnostics.push(
            "VBA project has protection/lock attributes (CMG/DPB/GC); project may appear locked or unviewable in VBA IDE"
                .into(),
        );
    }
    for hidden in &result.hidden_gui_modules {
        result.diagnostics.push(format!(
            "Module '{hidden}' is present in dir stream but omitted from PROJECT stream manifest (hidden in VBA IDE)"
        ));
    }
    for m in p.modules {
        if m.name.contains('\0') {
            result.diagnostics.push(format!(
                "Security warning: Module name contains null byte (evasion attempt): '{}'",
                m.name.escape_default()
            ));
        }
        let diagnostic = m.source_error.clone();
        if let Some(e) = &diagnostic {
            result.diagnostics.push(format!("{}: {e}", m.name));
        }
        result.modules.push(ExtractedModule {
            name: m.name.clone(),
            stream_name: m.stream_name,
            source_text: m.source_text,
            source_bytes: m.source_bytes,
            performance_cache: m.performance_cache,
            cache: CacheRecord {
                module: m.name,
                byte_length: m.performance_cache_len,
                fingerprint: m.performance_cache_fingerprint,
                interpretation:
                    "opaque module performance cache; ignored for interoperable source analysis"
                        .into(),
            },
            pcode_layout: None,
            pcode_layout_status: "not_requested".into(),
            module_type: m.module_type,
            text_offset: m.text_offset,
            diagnostic,
        });
    }
    result
}

pub fn sources_from_extracted(project: &ExtractedProject) -> Vec<crate::model::SourceUnit> {
    project
        .modules
        .iter()
        .filter_map(|m| {
            m.source_text.as_ref().map(|text| {
                let extension = match m.module_type.as_deref() {
                    Some("procedural") => Some("bas"),
                    Some("document_or_class") => Some("cls"),
                    _ => None,
                };
                let name = extension
                    .map(|ext| format!("{}.{}", m.name, ext))
                    .unwrap_or_else(|| m.name.clone());
                crate::model::SourceUnit {
                    name,
                    text: text.clone(),
                }
            })
        })
        .collect()
}

pub fn decode_extracted_bytes(
    module: &ExtractedModule,
    code_page: Option<u16>,
) -> Result<String, String> {
    decode_text(&module.source_bytes, code_page).map_err(|e| e.to_string())
}

/// Automatically determine whether input bytes are an OOXML ZIP package
/// (`.xlsm`, `.xlsb`, `.docm`, `.pptm`, etc.) or a raw CFB compound binary
/// (`vbaProject.bin`, legacy `.xls`), and extract the VBA project accordingly.
pub fn extract_macro_container(data: &[u8], limits: &Limits) -> Result<ExtractedProject, String> {
    if data.starts_with(b"PK\x03\x04") {
        match extract_xlsm(data, limits) {
            Ok(project) => Ok(project),
            Err(orig_err) => {
                // Fallback: If standard OPC resolution fails, look for direct vbaProject.bin in the ZIP archive
                // (e.g. stripped or non-standard macro-enabled packages, malware containers, or raw zips)
                if let Ok(zip) = ZipArchive::open(data, limits) {
                    let candidate_paths = [
                        "vbaProject.bin",
                        "xl/vbaProject.bin",
                        "word/vbaProject.bin",
                        "ppt/vbaProject.bin",
                    ];
                    let mut found_entry = None;
                    for path in candidate_paths {
                        if let Some(entry) = zip.find(path) {
                            found_entry = Some(entry);
                            break;
                        }
                    }
                    if found_entry.is_none() {
                        for entry in &zip.entries {
                            if entry.name.to_ascii_lowercase().ends_with("vbaproject.bin") {
                                found_entry = Some(entry);
                                break;
                            }
                        }
                    }
                    if let Some(entry) = found_entry {
                        let extracted_res = zip
                            .read(entry)
                            .and_then(|bin| extract_vba_project(&bin, limits));
                        if let Ok(mut extracted) = extracted_res {
                            extracted.diagnostics.push(format!(
                                "OPC resolution failed ({orig_err}); extracted directly from entry '{}'",
                                entry.name
                            ));
                            scan_ooxml_package_threats(
                                &zip,
                                &mut extracted.cell_threats,
                                &mut extracted.diagnostics,
                                limits.max_zip_entries,
                            );
                            return Ok(extracted);
                        }
                    }
                    let mut package_threats = Vec::new();
                    let mut package_diagnostics = Vec::new();
                    scan_ooxml_package_threats(
                        &zip,
                        &mut package_threats,
                        &mut package_diagnostics,
                        limits.max_zip_entries,
                    );
                    if !package_threats.is_empty() {
                        let mut project = ExtractedProject::default();
                        project.diagnostics.push(format!(
                            "No VBA macro code found in container, but detected {} package-level threat(s)",
                            package_threats.len()
                        ));
                        project.diagnostics.extend(package_diagnostics);
                        project.cell_threats = package_threats;
                        return Ok(project);
                    }
                }
                Err(orig_err)
            }
        }
    } else if data.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        extract_vba_project(data, limits)
    } else {
        Err("unrecognized macro container format (expected ZIP or CFB/OLE header)".into())
    }
}

/// Scan an OOXML ZIP package for container-level security threats, including:
/// - Remote Template Injection (`VBA-CELL-010`, Critical)
/// - Embedded OLE / executable package (`VBA-CELL-011`, High)
/// - External OLE object reference (`VBA-CELL-012`, High)
/// - Embedded ActiveX control (`VBA-CELL-013`, Medium)
/// - External subdocument / frame reference (`VBA-CELL-014`, High)
/// - Suspicious printer settings with UNC path or external target (`VBA-CELL-015`, High)
/// - Custom XML payload / executable / XXE smuggling (`VBA-CELL-016`, High)
/// - Suspicious protocol handlers (ms-msdt, search-ms, etc.) in relationships (`VBA-CELL-017`, Critical)
/// - Suspicious drawing/shape action, hover trigger, or VML macro (`VBA-CELL-018`, High)
/// - External data connection, web query, or NTLM coercion (`VBA-CELL-019`, High)
/// - Real-Time Data (RTD) COM automation formula (`VBA-CELL-020`, High)
/// - Suspicious SVG vector graphic with scripts/XXE/protocols (`VBA-CELL-021`, Critical)
/// - Tampered, corrupted, or stripped VBA project signature (`VBA-CELL-022`, High)
/// - Word field code execution via DDE/INCLUDETEXT/MACROBUTTON (`VBA-CELL-023`, Critical)
/// - PowerPoint slide action or mouse-over hover trigger (`VBA-CELL-024`, Critical)
/// - Suspicious Alternative Format Chunk (AltChunk) payload (`VBA-CELL-025`, Critical)
/// - Custom UI Ribbon onLoad auto-execution and onAction callbacks (`VBA-CELL-026`, Critical)
/// - Legacy Excel 5.0/95 Dialog Sheet macro bindings (`VBA-CELL-027`, High)
/// - Content Types package anomaly, path traversal, and MIME spoofing (`VBA-CELL-028`, Critical)
/// - External link cache, remote UNC, DDE/OLE link anomaly (`VBA-CELL-029`, Critical)
/// - Word web settings remote frameset or reload injection (`VBA-CELL-030`, Critical)
/// - Workbook protection evasion and locked structure cloaking (`VBA-CELL-031`, High)
/// - Smuggled container payload binary, cloaked PE, or staged script (`VBA-CELL-032`, Critical)
/// - Worksheet view evasion, hidden row/col cloaking, displaced view (`VBA-CELL-033`, High)
/// - ActiveX XML object declaration anomaly and weaponized CLSID (`VBA-CELL-034`, Critical)
/// - Word glossary document payload, template injection, or field codes (`VBA-CELL-035`, Critical)
/// - Embedded font obfuscation, payload smuggling, or external font links (`VBA-CELL-036`, High)
/// - Digital ink definition anomaly, interactive action trigger, or CLSID (`VBA-CELL-037`, High)
/// - Document property payload smuggling, Base64 PE, or staged scripts (`VBA-CELL-038`, Critical)
/// - Office web extension or taskpane auto-show anomaly (`VBA-CELL-039`, Critical)
/// - PivotCache data connection anomaly, UNC, or shell command injection (`VBA-CELL-040`, Critical)
pub fn scan_ooxml_package_threats(
    zip: &ZipArchive<'_>,
    threats: &mut Vec<CellThreat>,
    diagnostics: &mut Vec<String>,
    max_entries: usize,
) {
    fn is_external_target(target: &str, mode: crate::opc::TargetMode) -> bool {
        if mode == crate::opc::TargetMode::External {
            return true;
        }
        let t = target.trim();
        let lower = t.to_ascii_lowercase();
        lower.starts_with("http://")
            || lower.starts_with("https://")
            || lower.starts_with("ftp://")
            || lower.starts_with("file://")
            || lower.starts_with("\\\\")
            || lower.starts_with("//")
            || lower.starts_with("mhtml:")
            || lower.starts_with("ms-msdt:")
            || lower.starts_with("search-ms:")
            || lower.starts_with("javascript:")
    }

    fn scan_printer_settings_bytes(data: &[u8]) -> Option<String> {
        // 1. Look for ASCII UNC: "\\" or "//" followed by at least 2 characters and "\" or "/"
        for (i, w) in data.windows(2).enumerate() {
            if (w == b"\\\\" || w == b"//") && i + 4 < data.len() {
                let rest = &data[i..];
                let end = rest
                    .iter()
                    .position(|&b| {
                        b == 0
                            || b == b' '
                            || b == b'"'
                            || b == b'\''
                            || b == b'\r'
                            || b == b'\n'
                            || b == b'<'
                            || b == b'>'
                    })
                    .unwrap_or(rest.len().min(128));
                if end < 4 {
                    continue;
                }
                if let Some(s) = std::str::from_utf8(&rest[..end])
                    .ok()
                    .filter(|s| s.contains('\\') || s.contains('/'))
                {
                    return Some(format!("UNC path '{s}'"));
                }
            }
        }
        // 2. Look for UTF-16LE UNC: &[0x5c, 0x00, 0x5c, 0x00] or &[0x2f, 0x00, 0x2f, 0x00]
        for (i, w) in data.windows(4).enumerate() {
            if (w == [0x5c, 0x00, 0x5c, 0x00] || w == [0x2f, 0x00, 0x2f, 0x00])
                && i + 8 <= data.len()
            {
                let rest = &data[i..];
                let mut u16s = Vec::new();
                for chunk in rest.chunks_exact(2) {
                    let code = u16::from_le_bytes([chunk[0], chunk[1]]);
                    if code == 0
                        || code == b' ' as u16
                        || code == b'"' as u16
                        || code == b'\'' as u16
                        || code == b'\r' as u16
                        || code == b'\n' as u16
                        || code == b'<' as u16
                        || code == b'>' as u16
                        || u16s.len() >= 128
                    {
                        break;
                    }
                    u16s.push(code);
                }
                if let Some(s) = String::from_utf16(&u16s)
                    .ok()
                    .filter(|s| s.len() >= 4 && (s.contains('\\') || s.contains('/')))
                {
                    return Some(format!("UTF-16LE UNC path '{s}'"));
                }
            }
        }
        // 3. URLs in ASCII or UTF-16LE
        let data_str_lossy = String::from_utf8_lossy(data);
        let lower = data_str_lossy.to_ascii_lowercase();
        if let Some(idx) = lower.find("http://").or_else(|| lower.find("https://")) {
            let snippet = &lower[idx..lower.len().min(idx + 100)];
            let end = snippet
                .find(|c: char| c.is_whitespace() || c == '\0' || c == '"' || c == '\'')
                .unwrap_or(snippet.len());
            return Some(format!("URL '{}'", &snippet[..end]));
        }
        let u16_chars: Vec<u16> = data
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        if let Ok(u16_str) = String::from_utf16(&u16_chars) {
            let u16_lower = u16_str.to_ascii_lowercase();
            if let Some(idx) = u16_lower
                .find("http://")
                .or_else(|| u16_lower.find("https://"))
            {
                let snippet = &u16_lower[idx..u16_lower.len().min(idx + 100)];
                let end = snippet
                    .find(|c: char| c.is_whitespace() || c == '\0' || c == '"' || c == '\'')
                    .unwrap_or(snippet.len());
                return Some(format!("UTF-16LE URL '{}'", &snippet[..end]));
            }
        }
        // 4. Shell / command execution keywords
        for &kw in &[
            "powershell",
            "cmd.exe",
            "mshta",
            "rundll32",
            "cscript",
            "wscript",
        ] {
            if lower.contains(kw) {
                return Some(format!("Command trigger '{kw}'"));
            }
        }
        None
    }

    fn scan_custom_xml_content(data: &[u8]) -> Option<(&'static str, String)> {
        let s = String::from_utf8_lossy(data);
        let lower = s.to_ascii_lowercase();

        // 1. Base64 PE DOS stub
        for pe_sig in &["tvqqaamaaaaeaaaa", "tvoaaa", "tvpaaa", "tvpbaa"] {
            if lower.contains(pe_sig) {
                return Some((
                    "Base64 PE Executable Header",
                    format!("Matched PE DOS stub '{pe_sig}'"),
                ));
            }
        }

        // 2. XXE / XML External Entity
        if lower.contains("<!entity") && (lower.contains("system") || lower.contains("public")) {
            let start = lower.find("<!entity").unwrap_or(0);
            let end = s[start..]
                .find('>')
                .map(|e| start + e + 1)
                .unwrap_or(s.len().min(start + 80));
            return Some((
                "XML External Entity (XXE) Injection",
                s[start..end].trim().to_string(),
            ));
        }

        // 3. Script / Shell commands
        for &kw in &[
            "<script",
            "wscript.shell",
            "powershell",
            "cmd.exe",
            "mshta",
            "rundll32",
            "cscript",
            "certutil",
        ] {
            if lower.contains(kw) {
                return Some((
                    "Smuggled Script / Shell Execution Tag",
                    format!("Found execution trigger '{kw}'"),
                ));
            }
        }

        // 4. Dangerous protocol handlers in XML
        for &proto in &["ms-msdt:", "search-ms:", "ms-appinstaller:", "mhtml:"] {
            if lower.contains(proto) {
                return Some((
                    "Dangerous Protocol Handler Smuggling",
                    format!("Found exploit scheme '{proto}'"),
                ));
            }
        }

        // 5. HTML Smuggling
        if lower.contains("data:text/html;base64,") {
            return Some((
                "HTML Smuggling Payload",
                "Found 'data:text/html;base64,' data URI".into(),
            ));
        }

        None
    }

    fn decode_xml_entities(s: &str) -> String {
        s.replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
    }

    fn inspect_word_instruction(instr: &str) -> Option<(&'static str, String)> {
        let trimmed = instr.trim();
        let lower = trimmed.to_ascii_lowercase();

        // 1. DDE / DDEAUTO command execution
        if lower.starts_with("ddeauto")
            || lower.starts_with("dde ")
            || lower.starts_with("dde\t")
            || lower.starts_with("dde\"")
            || lower == "dde"
        {
            return Some((
                "Critical",
                format!("Word DDE/DDEAUTO command execution field code: '{trimmed}'"),
            ));
        }

        // 2. Dangerous Protocol Handler smuggling
        for &proto in &[
            "ms-msdt:",
            "search-ms:",
            "ms-appinstaller:",
            "mhtml:",
            "javascript:",
        ] {
            if lower.contains(proto) {
                return Some((
                    "Critical",
                    format!("Dangerous protocol handler '{proto}' in Word field code: '{trimmed}'"),
                ));
            }
        }

        // 3. INCLUDETEXT / LINK remote document injection or NTLM coercion
        if (lower.starts_with("includetext")
            || lower.starts_with("link ")
            || lower.starts_with("link\t"))
            && (lower.contains("http://")
                || lower.contains("https://")
                || lower.contains("ftp://")
                || lower.contains("\\\\")
                || lower.contains("//"))
        {
            return Some((
                "High",
                format!("Word remote document injection / NTLM coercion field code: '{trimmed}'"),
            ));
        }

        // 4. MACROBUTTON social engineering lure
        if lower.starts_with("macrobutton") {
            let suspicious = lower.contains("autoopen")
                || lower.contains("document_open")
                || lower.contains("autoexec")
                || lower.contains("autoclose")
                || lower.contains("powershell")
                || lower.contains("cmd");
            if suspicious {
                return Some((
                    "High",
                    format!(
                        "Word MACROBUTTON field code targeting auto-exec or script macro: '{trimmed}'"
                    ),
                ));
            }
        }

        // 5. FILENAME with UNC path
        if lower.starts_with("filename") && (lower.contains("\\\\") || lower.contains("//")) {
            return Some((
                "High",
                format!(
                    "Word FILENAME field code pointing to UNC path (NTLM coercion): '{trimmed}'"
                ),
            ));
        }

        None
    }

    fn scan_word_field_codes(xml_str: &str) -> Vec<(String, &'static str, String)> {
        let mut results = Vec::new();
        let s_lower = xml_str.to_ascii_lowercase();

        // 1. Simple fields: <w:fldSimple ... w:instr="..." ...>
        let mut search_idx = 0;
        let mut field_num = 1;
        while let Some(start) = s_lower[search_idx..].find("<w:fldsimple") {
            let abs_start = search_idx + start;
            let tag_end = xml_str[abs_start..]
                .find('>')
                .map(|e| abs_start + e)
                .unwrap_or(xml_str.len());
            let tag_content = &xml_str[abs_start..tag_end];
            let tag_lower = &s_lower[abs_start..tag_end];
            if let Some(instr_start) = tag_lower.find("w:instr=") {
                let rest = &tag_content[instr_start + 8..];
                let quote = rest.chars().next().unwrap_or('"');
                if quote == '"' || quote == '\'' {
                    let rest = &rest[1..];
                    if let Some(q_end) = rest.find(quote) {
                        let raw_instr = &rest[..q_end];
                        let decoded = decode_xml_entities(raw_instr);
                        if let Some((sev, reason)) = inspect_word_instruction(&decoded) {
                            results.push((format!("fldSimple{field_num}"), sev, reason));
                            field_num += 1;
                        }
                    }
                }
            }
            search_idx = tag_end;
        }

        // 2. Complex fields: from <w:fldChar w:fldCharType="begin" to <w:fldChar w:fldCharType="end"
        let mut in_complex = false;
        let mut complex_instr = String::new();
        let mut cursor = 0;
        let mut complex_num = 1;

        while cursor < xml_str.len() {
            if let Some(tag_open) = xml_str[cursor..].find('<') {
                let tag_start = cursor + tag_open;
                let Some(tag_close) = xml_str[tag_start..].find('>') else {
                    break;
                };
                let tag_end = tag_start + tag_close + 1;
                let tag_text = &xml_str[tag_start..tag_end];
                let tag_lower = tag_text.to_ascii_lowercase();

                if tag_lower.contains("fldchartype=\"begin\"")
                    || tag_lower.contains("fldchartype='begin'")
                {
                    if in_complex && !complex_instr.is_empty() {
                        let decoded = decode_xml_entities(&complex_instr);
                        if let Some((sev, reason)) = inspect_word_instruction(&decoded) {
                            results.push((format!("complexField{complex_num}"), sev, reason));
                            complex_num += 1;
                        }
                    }
                    in_complex = true;
                    complex_instr.clear();
                } else if tag_lower.contains("fldchartype=\"end\"")
                    || tag_lower.contains("fldchartype='end'")
                {
                    if in_complex && !complex_instr.is_empty() {
                        let decoded = decode_xml_entities(&complex_instr);
                        if let Some((sev, reason)) = inspect_word_instruction(&decoded) {
                            results.push((format!("complexField{complex_num}"), sev, reason));
                            complex_num += 1;
                        }
                    }
                    in_complex = false;
                    complex_instr.clear();
                } else if in_complex
                    && (tag_lower.starts_with("<w:instrtext")
                        || tag_lower.starts_with("<instrtext"))
                {
                    let text_start = tag_end;
                    let text_end = xml_str[text_start..]
                        .find("</")
                        .map(|e| text_start + e)
                        .unwrap_or(text_start);
                    complex_instr.push_str(&xml_str[text_start..text_end]);
                    cursor = text_end;
                    continue;
                }
                cursor = tag_end;
            } else {
                break;
            }
        }
        if in_complex && !complex_instr.is_empty() {
            let decoded = decode_xml_entities(&complex_instr);
            if let Some((sev, reason)) = inspect_word_instruction(&decoded) {
                results.push((format!("complexField{complex_num}"), sev, reason));
            }
        }

        results
    }

    fn scan_ppt_slide_actions(xml_str: &str) -> Vec<(&'static str, &'static str, String)> {
        let mut results = Vec::new();
        let s_lower = xml_str.to_ascii_lowercase();

        // 1. ppaction://program (external program launch)
        if s_lower.contains("ppaction://program") {
            let detail = if let Some(idx) = s_lower.find("ppaction://program") {
                let rest = &xml_str[idx..xml_str.len().min(idx + 120)];
                let end = rest.find(['"', '\'', '<', '>']).unwrap_or(rest.len());
                &rest[..end]
            } else {
                "ppaction://program"
            };
            results.push((
                "ProgramLaunch",
                "Critical",
                format!("Slide action launches external program or command ('{detail}')"),
            ));
        }

        // 2. Mouse-over hover trigger (<a:hlinkHover>)
        if s_lower.contains("<a:hlinkhover") || s_lower.contains(":hlinkhover") {
            results.push((
                "MouseHoverTrigger",
                "Critical",
                "Slide shape configured with mouse-over hover trigger ('<a:hlinkHover>') executing without click".into(),
            ));
        }

        // 3. ppaction://macro (macro invocation)
        if s_lower.contains("ppaction://macro") {
            let macro_name = if let Some(idx) = s_lower.find("ppaction://macro") {
                let rest = &xml_str[idx..xml_str.len().min(idx + 80)];
                let end = rest.find(['"', '\'', '<', '>']).unwrap_or(rest.len());
                &rest[..end]
            } else {
                "ppaction://macro"
            };
            results.push((
                "MacroTrigger",
                "High",
                format!("Slide action triggers macro execution ('{macro_name}')"),
            ));
        }

        // 4. Dangerous protocol in slide action or hyperlink
        for &proto in &[
            "ms-msdt:",
            "search-ms:",
            "ms-appinstaller:",
            "mhtml:",
            "javascript:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "DangerousProtocol",
                    "Critical",
                    format!("Slide action contains exploit protocol handler '{proto}'"),
                ));
            }
        }

        // 5. Direct executable reference in slide XML
        for &ext in &[
            ".exe\"", ".bat\"", ".cmd\"", ".ps1\"", ".vbs\"", ".hta\"", ".cpl\"", ".msi\"",
        ] {
            if s_lower.contains(ext) {
                results.push((
                    "ExecutableLink",
                    "Critical",
                    format!("Slide action links directly to executable payload ('{ext}')"),
                ));
            }
        }

        results
    }

    fn scan_altchunk_content(data: &[u8]) -> Option<(&'static str, &'static str, String)> {
        // 1. Raw PE header
        if data.starts_with(b"MZ") {
            return Some((
                "RawExecutableHeader",
                "Critical",
                "AltChunk contains raw 'MZ' DOS executable binary".into(),
            ));
        }

        let s = String::from_utf8_lossy(data);
        let lower = s.to_ascii_lowercase();

        // 2. Base64 PE header
        for pe_sig in &["tvqqaamaaaaeaaaa", "tvoaaa", "tvpaaa", "tvpbaa"] {
            if lower.contains(pe_sig) {
                return Some((
                    "Base64Executable",
                    "Critical",
                    format!("AltChunk contains Base64 encoded PE executable ('{pe_sig}')"),
                ));
            }
        }

        // 3. RTF exploit headers and OLE object streams
        if lower.starts_with("{\\rtf")
            && (lower.contains("\\objdata")
                || lower.contains("\\object")
                || lower.contains("0002ce02-0000-0000-c000-000000000046")
                || lower.contains("\\bin"))
        {
            return Some((
                "RtfExploitPayload",
                "Critical",
                "AltChunk contains RTF payload with embedded OLE object or equation exploit".into(),
            ));
        }

        // 4. HTML smuggling
        if lower.contains("data:text/html;base64,") {
            return Some((
                "HtmlSmuggling",
                "Critical",
                "AltChunk contains HTML smuggling payload ('data:text/html;base64,')".into(),
            ));
        }

        // 5. Embedded script tags
        if lower.contains("<script") {
            return Some((
                "EmbeddedScript",
                "Critical",
                "AltChunk contains embedded HTML/XML <script> element".into(),
            ));
        }

        // 6. Dangerous protocol handlers
        for &proto in &["ms-msdt:", "search-ms:", "ms-appinstaller:", "mhtml:"] {
            if lower.contains(proto) {
                return Some((
                    "DangerousProtocol",
                    "Critical",
                    format!("AltChunk contains exploit protocol handler '{proto}'"),
                ));
            }
        }

        // 7. Shell execution triggers
        for &kw in &[
            "wscript.shell",
            "powershell",
            "cmd.exe",
            "mshta",
            "rundll32",
            "cscript",
        ] {
            if lower.contains(kw) {
                return Some((
                    "ShellCommandTrigger",
                    "High",
                    format!("AltChunk contains shell execution trigger '{kw}'"),
                ));
            }
        }

        None
    }

    fn extract_attribute_value(tag_str: &str, attr_name: &str) -> Option<String> {
        let tag_lower = tag_str.to_ascii_lowercase();
        let target = attr_name.to_ascii_lowercase();
        let mut search_idx = 0;
        while let Some(pos) = tag_lower[search_idx..].find(&target) {
            let abs_pos = search_idx + pos;
            if abs_pos > 0 {
                let prev = tag_str.as_bytes()[abs_pos - 1];
                if !prev.is_ascii_whitespace() && prev != b'<' {
                    search_idx = abs_pos + target.len();
                    continue;
                }
            }
            let rest = tag_str[abs_pos + target.len()..].trim_start();
            if let Some(after_eq) = rest.strip_prefix('=') {
                let after_eq_trimmed = after_eq.trim_start();
                if let Some(quote @ ('"' | '\'')) = after_eq_trimmed.chars().next() {
                    let after_quote = &after_eq_trimmed[1..];
                    if let Some(end) = after_quote.find(quote) {
                        return Some(decode_xml_entities(&after_quote[..end]));
                    }
                }
            }
            search_idx = abs_pos + target.len();
        }
        None
    }

    fn scan_customui_content(xml_str: &str) -> Vec<(&'static str, &'static str, String, String)> {
        let mut results = Vec::new();
        let s_lower = xml_str.to_ascii_lowercase();

        // 1. Scan tags for onLoad and onAction callbacks
        let mut cursor = 0;
        while cursor < xml_str.len() {
            if let Some(tag_open) = xml_str[cursor..].find('<') {
                let tag_start = cursor + tag_open;
                let Some(tag_close) = xml_str[tag_start..].find('>') else {
                    break;
                };
                let tag_end = tag_start + tag_close + 1;
                let tag_str = &xml_str[tag_start..tag_end];

                if let Some(onload_val) = extract_attribute_value(tag_str, "onload") {
                    let trimmed = onload_val.trim();
                    if !trimmed.is_empty() {
                        results.push((
                            "onLoad",
                            "Critical",
                            trimmed.to_string(),
                            format!("Custom UI Ribbon registers 'onLoad' automatic execution callback ('{trimmed}')"),
                        ));
                    }
                }

                if let Some(onaction_val) = extract_attribute_value(tag_str, "onaction") {
                    let trimmed = onaction_val.trim();
                    if !trimmed.is_empty() {
                        results.push((
                            "onAction",
                            "High",
                            trimmed.to_string(),
                            format!("Custom UI Ribbon binds control action to macro callback ('{trimmed}')"),
                        ));
                    }
                }

                cursor = tag_end;
            } else {
                break;
            }
        }

        // 2. Check for shell keywords in customUI XML
        for &kw in &[
            "powershell",
            "cmd.exe",
            "mshta",
            "rundll32",
            "cscript",
            "wscript",
        ] {
            if s_lower.contains(kw) {
                results.push((
                    "ShellCommand",
                    "Critical",
                    kw.to_string(),
                    format!("Custom UI Ribbon contains shell command trigger '{kw}'"),
                ));
            }
        }

        // 3. Check for exploit protocol handlers
        for &proto in &["ms-msdt:", "search-ms:", "ms-appinstaller:", "mhtml:"] {
            if s_lower.contains(proto) {
                results.push((
                    "ExploitProtocol",
                    "Critical",
                    proto.to_string(),
                    format!("Custom UI Ribbon contains exploit protocol handler '{proto}'"),
                ));
            }
        }

        results
    }

    fn scan_legacy_dialogsheet_content(xml_str: &str) -> Vec<(&'static str, String, String)> {
        let mut results = Vec::new();
        let s_lower = xml_str.to_ascii_lowercase();

        let mut fmla_cursor = 0;
        let mut found_macro = false;
        while let Some(start) = s_lower[fmla_cursor..].find("fmlamacro>") {
            let abs_start = fmla_cursor + start + 10;
            let end = xml_str[abs_start..]
                .find("</")
                .map(|e| abs_start + e)
                .unwrap_or(xml_str.len().min(abs_start + 120));
            let macro_name = decode_xml_entities(&xml_str[abs_start..end])
                .trim()
                .to_string();
            if !macro_name.is_empty() {
                let macro_lower = macro_name.to_ascii_lowercase();
                let is_suspicious = macro_lower.contains("auto_open")
                    || macro_lower.contains("autoexec")
                    || macro_lower.contains("workbook_open")
                    || macro_lower.contains("shell")
                    || macro_lower.contains("cmd")
                    || macro_lower.contains("powershell");
                let sev = if is_suspicious { "Critical" } else { "High" };
                results.push((
                    sev,
                    macro_name.clone(),
                    format!("Legacy Excel 5.0/95 Dialog Sheet binds control to macro execution ('{macro_name}')"),
                ));
                found_macro = true;
            }
            fmla_cursor = end;
        }

        if !found_macro && (s_lower.contains("<dialogsheet") || s_lower.contains("<x:dialogsheet"))
        {
            results.push((
                "Medium",
                String::new(),
                "Legacy Excel 5.0/95 Dialog Sheet present in container".into(),
            ));
        }

        results
    }

    fn scan_content_types_content(xml_str: &str) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let mut cursor = 0;

        while cursor < xml_str.len() {
            if let Some(tag_open) = xml_str[cursor..].find('<') {
                let tag_start = cursor + tag_open;
                let Some(tag_close) = xml_str[tag_start..].find('>') else {
                    break;
                };
                let tag_end = tag_start + tag_close + 1;
                let tag_str = &xml_str[tag_start..tag_end];
                let tag_lower = tag_str.to_ascii_lowercase();

                let is_default = tag_lower.starts_with("<default");
                let is_override = tag_lower.starts_with("<override");

                if is_default {
                    let ext_opt = extract_attribute_value(tag_str, "extension");
                    let ct_opt = extract_attribute_value(tag_str, "contenttype");

                    if let Some(ref ext) = ext_opt {
                        // 1. Path traversal in extension
                        if ext.contains("..")
                            || ext.contains('/')
                            || ext.contains('\\')
                            || ext.contains("%2e%2e")
                            || ext.contains("%2E%2E")
                        {
                            results.push((
                                "Critical",
                                ext.clone(),
                                format!("ext:{}", ext),
                                format!("Path traversal anomaly in [Content_Types].xml Extension '{ext}'"),
                            ));
                        }
                    }

                    if let (Some(ref ext), Some(ref ct)) = (ext_opt, ct_opt) {
                        let ct_lower = ct.to_ascii_lowercase();
                        let ext_lower = ext.to_ascii_lowercase();

                        // 2. Dangerous executable MIME type
                        for &dang_ct in &[
                            "application/x-msdownload",
                            "application/x-msdos-program",
                            "application/hta",
                            "application/x-bat",
                            "application/x-executable",
                            "application/x-sh",
                            "application/x-csh",
                            "application/x-powershell",
                        ] {
                            if ct_lower == dang_ct {
                                results.push((
                                    "Critical",
                                    ext.clone(),
                                    format!("mime:{}", ct),
                                    format!("Dangerous executable MIME content type '{ct}' declared in [Content_Types].xml for extension '{ext}'"),
                                ));
                            }
                        }

                        // 3. MIME extension spoofing
                        let is_sensitive_macro_type = ct_lower
                            == "application/vnd.ms-office.vbaproject"
                            || ct_lower == "application/vnd.ms-office.vbaprojectsignature"
                            || ct_lower.contains("application/vnd.ms-excel.macrosheet");
                        if is_sensitive_macro_type {
                            let is_innocuous_ext = matches!(
                                ext_lower.as_str(),
                                "png"
                                    | "jpg"
                                    | "jpeg"
                                    | "gif"
                                    | "bmp"
                                    | "ico"
                                    | "svg"
                                    | "txt"
                                    | "xml"
                                    | "rels"
                                    | "dat"
                                    | "htm"
                                    | "html"
                                    | "pdf"
                                    | "wav"
                                    | "mp3"
                            );
                            if is_innocuous_ext
                                || (ct_lower.contains("vbaproject") && ext_lower != "bin")
                            {
                                results.push((
                                    "Critical",
                                    ext.clone(),
                                    format!("default:{}", ext),
                                    format!("MIME extension spoofing in [Content_Types].xml: extension '.{ext}' is mapped to sensitive type '{ct}'"),
                                ));
                            }
                        }
                    }
                } else if is_override {
                    let part_opt = extract_attribute_value(tag_str, "partname");
                    let ct_opt = extract_attribute_value(tag_str, "contenttype");

                    if let Some(ref part_name) = part_opt {
                        // 1. Path traversal in PartName
                        if part_name.contains("..")
                            || part_name.contains('\\')
                            || part_name.contains("%2e%2e")
                            || part_name.contains("%2E%2E")
                        {
                            results.push((
                                "Critical",
                                part_name.clone(),
                                format!("part:{}", part_name),
                                format!("Path traversal anomaly in [Content_Types].xml PartName '{part_name}'"),
                            ));
                        }
                    }

                    if let (Some(ref part_name), Some(ref ct)) = (part_opt, ct_opt) {
                        let ct_lower = ct.to_ascii_lowercase();

                        // 2. Dangerous executable MIME type
                        for &dang_ct in &[
                            "application/x-msdownload",
                            "application/x-msdos-program",
                            "application/hta",
                            "application/x-bat",
                            "application/x-executable",
                            "application/x-sh",
                            "application/x-csh",
                            "application/x-powershell",
                        ] {
                            if ct_lower == dang_ct {
                                results.push((
                                    "Critical",
                                    part_name.clone(),
                                    format!("mime:{}", ct),
                                    format!("Dangerous executable MIME content type '{ct}' declared in [Content_Types].xml for PartName '{part_name}'"),
                                ));
                            }
                        }

                        // 3. MIME extension spoofing
                        let is_sensitive_macro_type = ct_lower
                            == "application/vnd.ms-office.vbaproject"
                            || ct_lower == "application/vnd.ms-office.vbaprojectsignature"
                            || ct_lower.contains("application/vnd.ms-excel.macrosheet");
                        if is_sensitive_macro_type {
                            let ext_lower = part_name
                                .rsplit('.')
                                .next()
                                .unwrap_or("")
                                .to_ascii_lowercase();
                            let is_innocuous_ext = matches!(
                                ext_lower.as_str(),
                                "png"
                                    | "jpg"
                                    | "jpeg"
                                    | "gif"
                                    | "bmp"
                                    | "ico"
                                    | "svg"
                                    | "txt"
                                    | "pdf"
                                    | "wav"
                                    | "mp3"
                            );
                            if is_innocuous_ext
                                || (ct_lower.contains("vbaproject") && ext_lower != "bin")
                            {
                                results.push((
                                    "Critical",
                                    part_name.clone(),
                                    format!("override:{}", part_name),
                                    format!("MIME extension spoofing in [Content_Types].xml: part '{part_name}' with non-macro extension is declared as '{ct}'"),
                                ));
                            }
                        }
                    }
                }

                cursor = tag_end;
            } else {
                break;
            }
        }

        results
    }

    fn scan_external_link_content(xml_str: &str) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lower = xml_str.to_ascii_lowercase();

        // 1. Scan tags for <ddeLink> and <oleLink>
        let mut cursor = 0;
        while cursor < xml_str.len() {
            if let Some(tag_open) = xml_str[cursor..].find('<') {
                let tag_start = cursor + tag_open;
                let Some(tag_close) = xml_str[tag_start..].find('>') else {
                    break;
                };
                let tag_end = tag_start + tag_close + 1;
                let tag_str = &xml_str[tag_start..tag_end];
                let tag_lower = tag_str.to_ascii_lowercase();

                if tag_lower.starts_with("<ddelink") {
                    let dde_service =
                        extract_attribute_value(tag_str, "ddeservice").unwrap_or_default();
                    let dde_topic =
                        extract_attribute_value(tag_str, "ddetopic").unwrap_or_default();
                    let service_lower = dde_service.to_ascii_lowercase();
                    let is_dangerous = matches!(
                        service_lower.as_str(),
                        "cmd"
                            | "cmd.exe"
                            | "powershell"
                            | "powershell.exe"
                            | "pwsh"
                            | "mshta"
                            | "mshta.exe"
                            | "cscript"
                            | "wscript"
                            | "rundll32"
                            | "regsvr32"
                            | "certutil"
                            | "bitsadmin"
                            | "bash"
                            | "curl"
                    );
                    let sev = if is_dangerous { "Critical" } else { "High" };
                    results.push((
                        sev,
                        format!("{dde_service}|{dde_topic}"),
                        format!("dde:{dde_service}"),
                        format!("External link cache registers DDE server execution link ('{dde_service}|{dde_topic}')"),
                    ));
                }

                if tag_lower.starts_with("<olelink") {
                    let prog_id = extract_attribute_value(tag_str, "progid")
                        .unwrap_or_else(|| "Unknown".into());
                    results.push((
                        "High",
                        prog_id.clone(),
                        format!("ole:{prog_id}"),
                        format!("External link cache registers OLE object link ('{prog_id}')"),
                    ));
                }

                cursor = tag_end;
            } else {
                break;
            }
        }

        // 2. Scan for exploit protocols directly in XML
        for &proto in &["ms-msdt:", "search-ms:", "ms-appinstaller:", "mhtml:"] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    proto.to_string(),
                    format!("proto:{proto}"),
                    format!("External link cache contains exploit protocol handler '{proto}'"),
                ));
            }
        }

        results
    }

    fn scan_websettings_content(xml_str: &str) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lower = xml_str.to_ascii_lowercase();

        // 1. Scan for <w:frame> or <w:frameset> or <w:source>
        let mut cursor = 0;
        while cursor < xml_str.len() {
            if let Some(tag_open) = xml_str[cursor..].find('<') {
                let tag_start = cursor + tag_open;
                let Some(tag_close) = xml_str[tag_start..].find('>') else {
                    break;
                };
                let tag_end = tag_start + tag_close + 1;
                let tag_str = &xml_str[tag_start..tag_end];
                let tag_lower = tag_str.to_ascii_lowercase();

                if tag_lower.starts_with("<w:source") || tag_lower.starts_with("<w:frame ") {
                    let source_val = extract_attribute_value(tag_str, "w:val")
                        .or_else(|| extract_attribute_value(tag_str, "target"))
                        .unwrap_or_default();
                    let trimmed = source_val.trim();
                    if !trimmed.is_empty() {
                        let t_lower = trimmed.to_ascii_lowercase();
                        let is_dangerous = t_lower.starts_with("ms-msdt:")
                            || t_lower.starts_with("search-ms:")
                            || t_lower.starts_with("mhtml:")
                            || t_lower.starts_with("\\\\")
                            || t_lower.starts_with("//")
                            || t_lower.starts_with("file:////")
                            || t_lower.starts_with("file://\\\\")
                            || [".exe", ".dll", ".hta", ".ps1", ".bat", ".cmd", ".vbs"]
                                .iter()
                                .any(|ext| {
                                    t_lower.ends_with(ext) || t_lower.contains(&format!("{ext}?"))
                                });
                        let sev = if is_dangerous { "Critical" } else { "High" };
                        results.push((
                            sev,
                            trimmed.to_string(),
                            format!("frame:{trimmed}"),
                            format!("Word web settings defines frameset linking to external source ('{trimmed}')"),
                        ));
                    }
                }

                cursor = tag_end;
            } else {
                break;
            }
        }

        // 2. Scan for script tags or reload directives
        if s_lower.contains("<script") {
            results.push((
                "Critical",
                "script".into(),
                "script:embedded".into(),
                "Word web settings contains embedded script tag ('<script')".into(),
            ));
        }
        if s_lower.contains("<w:reload") || s_lower.contains("<w:refresh") {
            results.push((
                "High",
                "reload".into(),
                "reload:directive".into(),
                "Word web settings contains automatic frame reload/refresh directive".into(),
            ));
        }

        results
    }

    fn scan_workbook_protection_and_evasion(
        xml_str: &str,
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lower = xml_str.to_ascii_lowercase();

        // Collect veryHidden sheets
        let mut very_hidden_sheets = Vec::new();
        let mut cursor = 0;
        while cursor < xml_str.len() {
            if let Some(tag_open) = xml_str[cursor..].find('<') {
                let tag_start = cursor + tag_open;
                let Some(tag_close) = xml_str[tag_start..].find('>') else {
                    break;
                };
                let tag_end = tag_start + tag_close + 1;
                let tag_str = &xml_str[tag_start..tag_end];
                let tag_lower = tag_str.to_ascii_lowercase();

                if (tag_lower.starts_with("<sheet ") || tag_lower.starts_with("<sheet>"))
                    && let Some(state) = extract_attribute_value(tag_str, "state")
                    && state.eq_ignore_ascii_case("veryhidden")
                {
                    let name = extract_attribute_value(tag_str, "name")
                        .unwrap_or_else(|| "Unknown".into());
                    very_hidden_sheets.push(name);
                }

                cursor = tag_end;
            } else {
                break;
            }
        }

        // Scan for <workbookProtection>
        if let Some(prot_start) = s_lower.find("<workbookprotection") {
            let prot_rest = &xml_str[prot_start..];
            if let Some(prot_end_idx) = prot_rest.find('>') {
                let prot_tag = &prot_rest[..=prot_end_idx];
                let prot_lower = prot_tag.to_ascii_lowercase();

                let lock_struct = extract_attribute_value(prot_tag, "lockstructure")
                    .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
                let lock_windows = extract_attribute_value(prot_tag, "lockwindows")
                    .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));

                let has_hash = extract_attribute_value(prot_tag, "hashvalue");
                let has_pwd = extract_attribute_value(prot_tag, "password");

                if lock_struct || lock_windows {
                    if !very_hidden_sheets.is_empty() {
                        for sheet_name in &very_hidden_sheets {
                            results.push((
                                "High",
                                sheet_name.clone(),
                                format!("evasion:veryHidden:{sheet_name}"),
                                format!("Workbook protection locks structure ('lockStructure=1') while cloaking veryHidden sheet '{sheet_name}' to prevent user inspection"),
                            ));
                        }
                    } else if let Some(ref hash) = has_hash {
                        if hash.is_empty() || hash.chars().all(|c| c == '0' || c == 'F') {
                            results.push((
                                "High",
                                "dummy_hash".into(),
                                "protection:dummyHash".into(),
                                "Workbook protection locks structure with dummy or hollowed hash to prevent UI inspection".into(),
                            ));
                        }
                    } else if has_pwd.is_some() || prot_lower.contains("workbookalgorithmname") {
                        results.push((
                            "Medium",
                            "lockStructure".into(),
                            "protection:lockStructure".into(),
                            "Workbook protection locks workbook structure to impede sheet inspection".into(),
                        ));
                    }
                }
            }
        }

        results
    }

    fn col_letters_to_num(letters: &str) -> Option<u32> {
        let mut num = 0u32;
        for b in letters.bytes() {
            if !b.is_ascii_alphabetic() {
                return None;
            }
            let val = (b.to_ascii_uppercase() - b'A' + 1) as u32;
            num = num.checked_mul(26)?.checked_add(val)?;
        }
        if num > 0 { Some(num) } else { None }
    }

    fn scan_container_smuggled_payload(
        name: &str,
        data: Option<&[u8]>,
    ) -> Option<(&'static str, &'static str, String)> {
        let name_lower = name.to_ascii_lowercase();

        // 1. Dangerous executable / script / package file extensions
        let dangerous_extensions: &[(&str, &'static str, &'static str)] = &[
            (".exe", "Critical", "Windows Executable (.exe)"),
            (".dll", "Critical", "Dynamic Link Library (.dll)"),
            (".sys", "Critical", "System Driver (.sys)"),
            (".drv", "Critical", "System Driver (.drv)"),
            (".ocx", "Critical", "OLE Control Extension (.ocx)"),
            (".cpl", "Critical", "Control Panel Applet (.cpl)"),
            (".scr", "Critical", "Screensaver Executable (.scr)"),
            (".pif", "Critical", "Program Information File (.pif)"),
            (".com", "Critical", "DOS Executable (.com)"),
            (".bat", "Critical", "Batch script (.bat)"),
            (".cmd", "Critical", "Command script (.cmd)"),
            (".ps1", "Critical", "PowerShell script (.ps1)"),
            (".psm1", "Critical", "PowerShell module (.psm1)"),
            (".vbs", "Critical", "VBScript file (.vbs)"),
            (".vbe", "Critical", "Encoded VBScript file (.vbe)"),
            (".js", "Critical", "JavaScript file (.js)"),
            (".jse", "Critical", "Encoded JavaScript file (.jse)"),
            (".wsf", "Critical", "Windows Script File (.wsf)"),
            (".wsh", "Critical", "Windows Script Host settings (.wsh)"),
            (".hta", "Critical", "HTML Application (.hta)"),
            (".msi", "Critical", "Windows Installer package (.msi)"),
            (".msp", "Critical", "Windows Installer patch (.msp)"),
            (".mst", "Critical", "Windows Installer transform (.mst)"),
            (".inf", "Critical", "Setup Information script (.inf)"),
            (".reg", "Critical", "Registry script (.reg)"),
            (".lnk", "Critical", "Windows Shell Link shortcut (.lnk)"),
            (".iso", "Critical", "Disk image (.iso)"),
            (".img", "Critical", "Disk image (.img)"),
            (".vhd", "Critical", "Virtual Hard Disk (.vhd)"),
            (".vhdx", "Critical", "Virtual Hard Disk (.vhdx)"),
        ];

        for (ext, sev, desc) in dangerous_extensions {
            if name_lower.ends_with(ext) {
                return Some((
                    *sev,
                    "SmuggledExecutableExtension",
                    format!(
                        "Dangerous standalone payload file with extension '{ext}' ({desc}) bundled inside OOXML container"
                    ),
                ));
            }
        }

        // 2. Binary Magic Header Analysis on all non-OLE-package parts
        let is_standard_ole_package =
            name_lower.contains("oleobject") || name_lower.contains("package");
        if let Some(bytes) = data {
            if !is_standard_ole_package && bytes.len() >= 64 {
                // A. Windows PE Header: MZ header at 0, and e_lfanew at 0x3C pointing to PE\0\0
                if bytes.starts_with(b"MZ") {
                    let e_lfanew =
                        u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]])
                            as usize;
                    if e_lfanew + 4 <= bytes.len() && &bytes[e_lfanew..e_lfanew + 4] == b"PE\0\0" {
                        return Some((
                            "Critical",
                            "SmuggledPeExecutableBinary",
                            "Smuggled Windows PE executable binary (MZ/PE header) detected in container part".into(),
                        ));
                    }
                }
                // B. Windows Shell Link (.LNK) magic header
                if bytes.len() >= 20
                    && bytes[0..8] == [0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00]
                {
                    return Some((
                        "Critical",
                        "SmuggledShellLinkShortcut",
                        "Smuggled Windows Shell Link shortcut (.lnk binary) detected in container part".into(),
                    ));
                }
                // C. ELF or Mach-O executable
                if bytes.starts_with(b"\x7fELF") {
                    return Some((
                        "Critical",
                        "SmuggledElfBinary",
                        "Smuggled Linux/Unix ELF binary detected in container part".into(),
                    ));
                }
                if bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
                    || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
                    || bytes.starts_with(&[0xce, 0xfa, 0xed, 0xfe])
                    || bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
                {
                    return Some((
                        "Critical",
                        "SmuggledMachOBinary",
                        "Smuggled macOS Mach-O executable binary detected in container part".into(),
                    ));
                }
            }

            // 3. Staged script payload in arbitrary non-standard non-XML part
            if !name_lower.ends_with(".xml")
                && !name_lower.ends_with(".rels")
                && !name_lower.ends_with(".bin")
                && bytes.len() >= 10
                && bytes.len() <= 100_000
            {
                let s = String::from_utf8_lossy(bytes);
                let s_lower = s.to_ascii_lowercase();
                if s_lower.starts_with("#!/bin/") || s_lower.starts_with("#!/usr/bin/") {
                    return Some((
                        "High",
                        "SmuggledUnixScript",
                        "Smuggled Unix shell script with shebang directive detected in container part".into(),
                    ));
                }
                if (s_lower.contains("powershell")
                    || s_lower.contains("cmd.exe")
                    || s_lower.contains("wscript.shell"))
                    && (s_lower.contains("-enc")
                        || s_lower.contains("-encodedcommand")
                        || s_lower.contains("invoke-expression")
                        || s_lower.contains("downloadstring")
                        || s_lower.contains("wscript.sleep"))
                {
                    return Some((
                        "High",
                        "SmuggledScriptPayload",
                        "Smuggled command execution script payload detected in container part"
                            .into(),
                    ));
                }
            }
        }

        None
    }

    fn scan_worksheet_view_evasion(xml_str: &str) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lower = xml_str.to_ascii_lowercase();

        // 1. Scan <cols> for hidden columns
        let mut hidden_cols: Vec<(u32, u32)> = Vec::new();
        if let Some(cols_start) = s_lower.find("<cols") {
            let cols_end = s_lower[cols_start..]
                .find("</cols>")
                .map(|idx| cols_start + idx)
                .unwrap_or(xml_str.len());
            let cols_slice = &xml_str[cols_start..cols_end];
            let mut c_cursor = 0;
            while c_cursor < cols_slice.len() {
                if let Some(tag_open) = cols_slice[c_cursor..].find("<col ") {
                    let start = c_cursor + tag_open;
                    let Some(tag_close) = cols_slice[start..].find('>') else {
                        break;
                    };
                    let tag = &cols_slice[start..=start + tag_close];
                    let is_hidden = extract_attribute_value(tag, "hidden")
                        .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                        || extract_attribute_value(tag, "width")
                            .is_some_and(|v| v == "0" || v == "0.0");
                    if is_hidden {
                        let min = extract_attribute_value(tag, "min")
                            .and_then(|v| v.parse::<u32>().ok())
                            .unwrap_or(0);
                        let max = extract_attribute_value(tag, "max")
                            .and_then(|v| v.parse::<u32>().ok())
                            .unwrap_or(min);
                        if min > 0 {
                            hidden_cols.push((min, max));
                        }
                    }
                    c_cursor = start + tag_close + 1;
                } else {
                    break;
                }
            }
        }

        // 2. Scan <sheetData> for hidden rows
        let mut hidden_rows = std::collections::BTreeSet::new();
        let mut cursor = 0;
        while cursor < xml_str.len() {
            if let Some(pos) = xml_str[cursor..].find("<row ") {
                let start = cursor + pos;
                let Some(end_idx) = xml_str[start..].find('>') else {
                    break;
                };
                let tag = &xml_str[start..=start + end_idx];
                let is_hidden = extract_attribute_value(tag, "hidden")
                    .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    || extract_attribute_value(tag, "ht").is_some_and(|v| v == "0" || v == "0.0");
                if is_hidden
                    && let Some(r_str) = extract_attribute_value(tag, "r")
                    && let Ok(r_num) = r_str.parse::<u32>()
                {
                    hidden_rows.insert(r_num);
                }
                cursor = start + end_idx + 1;
            } else {
                break;
            }
        }

        // 3. Scan for formula cells in hidden rows/cols
        if !hidden_rows.is_empty() || !hidden_cols.is_empty() {
            let mut cell_cursor = 0;
            let mut findings_count = 0;
            while cell_cursor < xml_str.len() && findings_count < 10 {
                if let Some(pos) = xml_str[cell_cursor..].find("<c ") {
                    let start = cell_cursor + pos;
                    let cell_close = if let Some(close_idx) = xml_str[start..].find("</c>") {
                        start + close_idx + 4
                    } else if let Some(self_close) = xml_str[start..].find("/>") {
                        start + self_close + 2
                    } else {
                        break;
                    };
                    let cell_content = &xml_str[start..cell_close];
                    let cell_lower = cell_content.to_ascii_lowercase();

                    if let Some(f_start) = cell_lower.find("<f")
                        && let Some(f_tag_close) = cell_content[f_start..].find('>')
                    {
                        let f_body_start = f_start + f_tag_close + 1;
                        let f_body_end = cell_lower[f_body_start..]
                            .find("</f>")
                            .map(|idx| f_body_start + idx)
                            .unwrap_or(cell_content.len());
                        let formula_text = cell_content[f_body_start..f_body_end].trim();

                        if !formula_text.is_empty() {
                            let tag_end = cell_content.find('>').unwrap_or(cell_content.len());
                            let open_tag = &cell_content[..tag_end];
                            if let Some(cell_ref) = extract_attribute_value(open_tag, "r") {
                                let split_idx = cell_ref
                                    .find(|c: char| c.is_ascii_digit())
                                    .unwrap_or(cell_ref.len());
                                let (col_part, row_part) = cell_ref.split_at(split_idx);
                                let row_num = row_part.parse::<u32>().ok();
                                let col_num = col_letters_to_num(col_part);

                                let in_hidden_row =
                                    row_num.is_some_and(|r| hidden_rows.contains(&r));
                                let in_hidden_col = col_num.is_some_and(|c| {
                                    hidden_cols.iter().any(|(min, max)| c >= *min && c <= *max)
                                });

                                if in_hidden_row || in_hidden_col {
                                    let f_low = formula_text.to_ascii_lowercase();
                                    let is_suspicious = f_low.contains("dde")
                                        || f_low.contains("cmd")
                                        || f_low.contains("powershell")
                                        || f_low.contains("http:")
                                        || f_low.contains("https:")
                                        || f_low.contains("\\\\")
                                        || f_low.contains("wscript")
                                        || f_low.contains("cscript")
                                        || f_low.contains("mshta")
                                        || f_low.contains("certutil")
                                        || f_low.contains("shell")
                                        || f_low.contains("exec")
                                        || f_low.contains("char(")
                                        || f_low.contains("unichar(")
                                        || f_low.contains("xor(")
                                        || f_low.contains("bitxor(");

                                    let sev = if is_suspicious { "High" } else { "Medium" };
                                    let reason = if in_hidden_row && in_hidden_col {
                                        format!(
                                            "Worksheet cloaks formula in both hidden row and column at {cell_ref} ('{formula_text}')"
                                        )
                                    } else if in_hidden_row {
                                        format!(
                                            "Worksheet cloaks formula in hidden row at {cell_ref} ('{formula_text}')"
                                        )
                                    } else {
                                        format!(
                                            "Worksheet cloaks formula in hidden column at {cell_ref} ('{formula_text}')"
                                        )
                                    };
                                    results.push((
                                        sev,
                                        cell_ref.clone(),
                                        format!("evasion:hiddenCell:{cell_ref}"),
                                        reason,
                                    ));
                                    findings_count += 1;
                                }
                            }
                        }
                    }

                    cell_cursor = cell_close;
                } else {
                    break;
                }
            }
        }

        // 4. Scan <sheetViews> for extreme scrolling or cloaked layout
        let mut sv_cursor = 0;
        while sv_cursor < xml_str.len() {
            if let Some(pos) = s_lower[sv_cursor..].find("<sheetview ") {
                let sv_start = sv_cursor + pos;
                let Some(end_idx) = xml_str[sv_start..].find('>') else {
                    break;
                };
                let sv_tag = &xml_str[sv_start..=sv_start + end_idx];

                if let Some(top_left) = extract_attribute_value(sv_tag, "topleftcell") {
                    let split_idx = top_left
                        .find(|c: char| c.is_ascii_digit())
                        .unwrap_or(top_left.len());
                    let (col_part, row_part) = top_left.split_at(split_idx);
                    let row_num = row_part.parse::<u32>().unwrap_or(0);
                    let col_num = col_letters_to_num(col_part).unwrap_or(0);

                    if row_num >= 1000 || col_num >= 50 {
                        results.push((
                            "High",
                            top_left.clone(),
                            format!("sheetView:topLeftCell:{top_left}"),
                            format!("Worksheet view sets extreme topLeftCell scroll ('{top_left}') displacing viewport to evade visual inspection"),
                        ));
                    }
                }

                let hide_grid = extract_attribute_value(sv_tag, "showgridlines")
                    .is_some_and(|v| v == "0" || v.eq_ignore_ascii_case("false"));
                let hide_headers = extract_attribute_value(sv_tag, "showrowcolheaders")
                    .is_some_and(|v| v == "0" || v.eq_ignore_ascii_case("false"));
                if hide_grid && hide_headers {
                    results.push((
                        "Medium",
                        "view".into(),
                        "sheetView:cloakedHeaders".into(),
                        "Worksheet view suppresses row/column headers and grid lines to conceal layout and coordinates".into(),
                    ));
                }

                sv_cursor = sv_start + end_idx + 1;
            } else {
                break;
            }
        }

        results
    }

    fn scan_activex_xml_declarations(xml_str: &str) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lower = xml_str.to_ascii_lowercase();

        // 1. Weaponized ActiveX CLSIDs
        let weaponized_clsids: &[(&str, &'static str, &'static str)] = &[
            (
                "{72c24dd5-d70a-438b-8a42-98424b88afb8}",
                "Critical",
                "WScript.Shell command execution COM object",
            ),
            (
                "{f935dc22-1cf0-11d0-adb9-00c04fd58a0b}",
                "Critical",
                "WScript.Network COM automation object",
            ),
            (
                "{bd96c556-65a3-11d0-983a-00c04fc29e30}",
                "Critical",
                "RDS.DataSpace / XMLHTTP drive-by command execution",
            ),
            (
                "{13709620-c279-11ce-a49e-444553540000}",
                "Critical",
                "Shell.Explorer web browser / script execution control",
            ),
            (
                "{233c1501-e770-11ce-9f5b-00aa00402709}",
                "Critical",
                "Scriptlet.TypeLib scriptlet moniker execution (CVE-2017-0199)",
            ),
            (
                "{00000566-0000-0010-8000-00aa006d2ea4}",
                "Critical",
                "ADODB.Stream binary payload drop and write object",
            ),
            (
                "{00021a20-0000-0000-c000-000000000046}",
                "Critical",
                "Equation Editor 3.0 vulnerability exploit (CVE-2017-11882 / CVE-2018-0802)",
            ),
            (
                "{d27cdb6e-ae6d-11cf-96b8-444553540000}",
                "Critical",
                "Shockwave Flash remote code execution vector",
            ),
            (
                "{0002e005-0000-0000-c000-000000000046}",
                "Critical",
                "MSComctlLib TreeView/ListView control vulnerability (CVE-2012-0158)",
            ),
            (
                "{27909e9c-03a0-47a6-8415-352c57eb1f9b}",
                "Critical",
                ".NET Windows Forms deserialization attack vector",
            ),
        ];

        for (clsid, sev, desc) in weaponized_clsids {
            if s_lower.contains(clsid) {
                results.push((
                    *sev,
                    clsid.to_string(),
                    format!("clsid:{clsid}"),
                    format!(
                        "ActiveX control declaration specifies weaponized CLSID {clsid} ({desc})"
                    ),
                ));
            }
        }

        // 2. Scan properties in <ocx:ocxPr ...>, <ax:ocxPr ...>, or <param ...>
        let mut cursor = 0;
        while cursor < xml_str.len() {
            if let Some(pos) = xml_str[cursor..].find('<') {
                let start = cursor + pos;
                let Some(end_idx) = xml_str[start..].find('>') else {
                    break;
                };
                let tag = &xml_str[start..=start + end_idx];
                let tag_lower = tag.to_ascii_lowercase();

                if tag_lower.contains("ocxpr")
                    || tag_lower.starts_with("<param ")
                    || tag_lower.contains(":param ")
                {
                    let prop_name =
                        extract_attribute_value(tag, "name").unwrap_or_else(|| "property".into());
                    let prop_val = extract_attribute_value(tag, "value").unwrap_or_default();
                    let v_lower = prop_val.to_ascii_lowercase();

                    if v_lower.starts_with("\\\\") || v_lower.starts_with("//") {
                        results.push((
                            "High",
                            prop_name.clone(),
                            format!("prop:{prop_name}"),
                            format!("ActiveX property '{prop_name}' specifies remote UNC path '{prop_val}' (NTLM coercion vector)"),
                        ));
                    } else if v_lower.starts_with("http://")
                        || v_lower.starts_with("https://")
                        || v_lower.starts_with("ftp://")
                    {
                        results.push((
                            "High",
                            prop_name.clone(),
                            format!("prop:{prop_name}"),
                            format!("ActiveX property '{prop_name}' specifies remote URL payload '{prop_val}'"),
                        ));
                    } else if v_lower.contains(".exe")
                        || v_lower.contains(".dll")
                        || v_lower.contains(".ps1")
                        || v_lower.contains(".vbs")
                        || v_lower.contains(".hta")
                        || v_lower.contains("powershell")
                        || v_lower.contains("cmd.exe")
                    {
                        results.push((
                            "High",
                            prop_name.clone(),
                            format!("prop:{prop_name}"),
                            format!("ActiveX property '{prop_name}' references executable file or shell command ('{prop_val}')"),
                        ));
                    } else if v_lower.starts_with("ms-msdt:")
                        || v_lower.starts_with("search-ms:")
                        || v_lower.starts_with("mhtml:")
                        || v_lower.starts_with("javascript:")
                        || v_lower.starts_with("vbscript:")
                    {
                        results.push((
                            "Critical",
                            prop_name.clone(),
                            format!("prop:{prop_name}"),
                            format!("ActiveX property '{prop_name}' references dangerous exploit protocol scheme ('{prop_val}')"),
                        ));
                    }
                }
                cursor = start + end_idx + 1;
            } else {
                break;
            }
        }

        results
    }

    fn scan_word_glossary_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let name_lower = entry_name.to_ascii_lowercase();

        if name_lower.ends_with(".rels") {
            let s = String::from_utf8_lossy(data);
            let mut cursor = 0;
            while cursor < s.len() {
                if let Some(pos) = s[cursor..].find("<Relationship ") {
                    let start = cursor + pos;
                    let tag_end = s[start..].find('>').unwrap_or(s.len() - start);
                    let tag = &s[start..start + tag_end];
                    cursor = start + tag_end;

                    let target = extract_attribute_value(tag, "Target").unwrap_or_default();
                    let rel_type = extract_attribute_value(tag, "Type").unwrap_or_default();
                    let target_mode =
                        extract_attribute_value(tag, "TargetMode").unwrap_or_default();
                    let t_lower = target.to_ascii_lowercase();
                    let is_external = target_mode.eq_ignore_ascii_case("External")
                        || t_lower.starts_with("http:")
                        || t_lower.starts_with("https:")
                        || t_lower.starts_with("\\\\");

                    if rel_type.contains("attachedTemplate")
                        || t_lower.ends_with(".dotm")
                        || t_lower.ends_with(".dot")
                    {
                        results.push((
                            "Critical",
                            target.clone(),
                            "glossary:templateInjection".into(),
                            format!("Word glossary relationship specifies remote external template injection ('{target}')"),
                        ));
                    } else if t_lower.starts_with("ms-msdt:")
                        || t_lower.starts_with("search-ms:")
                        || t_lower.starts_with("ms-appinstaller:")
                        || t_lower.starts_with("mhtml:")
                        || t_lower.starts_with("javascript:")
                        || t_lower.starts_with("vbscript:")
                        || t_lower.starts_with("cmd:")
                        || t_lower.starts_with("powershell:")
                    {
                        results.push((
                            "Critical",
                            target.clone(),
                            "glossary:protocolHandler".into(),
                            format!("Word glossary relationship references dangerous exploit protocol scheme ('{target}')"),
                        ));
                    } else if t_lower.ends_with(".exe")
                        || t_lower.ends_with(".dll")
                        || t_lower.ends_with(".sys")
                        || t_lower.ends_with(".scr")
                        || t_lower.ends_with(".bat")
                        || t_lower.ends_with(".cmd")
                        || t_lower.ends_with(".ps1")
                        || t_lower.ends_with(".vbs")
                        || t_lower.ends_with(".hta")
                    {
                        results.push((
                            "Critical",
                            target.clone(),
                            "glossary:executableTarget".into(),
                            format!("Word glossary relationship references executable or script target ('{target}')"),
                        ));
                    } else if t_lower.starts_with("\\\\") || t_lower.starts_with("//") {
                        results.push((
                            "High",
                            target.clone(),
                            "glossary:uncPath".into(),
                            format!("Word glossary relationship references remote UNC path ('{target}') (NTLM coercion vector)"),
                        ));
                    } else if rel_type.contains("oleObject") && is_external {
                        results.push((
                            "High",
                            target.clone(),
                            "glossary:externalOle".into(),
                            format!("Word glossary relationship references external OLE object ('{target}')"),
                        ));
                    } else if (rel_type.contains("subDocument") || rel_type.contains("frame"))
                        && is_external
                    {
                        results.push((
                            "High",
                            target.clone(),
                            "glossary:externalSubdoc".into(),
                            format!("Word glossary relationship references external subdocument or frame ('{target}')"),
                        ));
                    }
                } else {
                    break;
                }
            }
        } else if name_lower.ends_with(".xml") {
            let s = String::from_utf8_lossy(data);
            let s_lower = s.to_ascii_lowercase();

            // Check field codes <w:fldSimple ...>
            let mut cursor = 0;
            while cursor < s.len() {
                if let Some(pos) = s_lower[cursor..].find("<w:fldsimple") {
                    let start = cursor + pos;
                    let tag_end = s[start..].find('>').unwrap_or(s.len() - start);
                    let tag = &s[start..start + tag_end];
                    cursor = start + tag_end;

                    if let Some(instr) = extract_attribute_value(tag, "w:instr") {
                        let i_low = instr.to_ascii_lowercase();
                        if i_low.contains("dde")
                            || i_low.contains("exec")
                            || i_low.contains("cmd")
                            || i_low.contains("powershell")
                            || i_low.contains("mshta")
                        {
                            results.push((
                                "Critical",
                                instr.clone(),
                                "glossary:fieldCodeDDE".into(),
                                format!("Word glossary field code specifies command execution via DDE/shell ('{instr}')"),
                            ));
                        } else if i_low.contains("includetext") || i_low.contains("link") {
                            results.push((
                                "High",
                                instr.clone(),
                                "glossary:fieldCodeInject".into(),
                                format!("Word glossary field code specifies remote document injection ('{instr}')"),
                            ));
                        } else if i_low.contains("macrobutton") {
                            results.push((
                                "High",
                                instr.clone(),
                                "glossary:fieldCodeMacro".into(),
                                format!("Word glossary field code specifies macrobutton trigger ('{instr}')"),
                            ));
                        } else if i_low.contains("filename \\p") || i_low.contains("\\\\") {
                            results.push((
                                "High",
                                instr.clone(),
                                "glossary:fieldCodeUNC".into(),
                                format!(
                                    "Word glossary field code specifies UNC path leak ('{instr}')"
                                ),
                            ));
                        }
                    }
                } else {
                    break;
                }
            }

            // Check <w:instrText> runs
            let mut text_cursor = 0;
            while text_cursor < s.len() {
                if let Some(pos) = s_lower[text_cursor..].find("<w:instrtext") {
                    let start = text_cursor + pos;
                    let open_close = s[start..].find('>').unwrap_or(s.len() - start);
                    let body_start = start + open_close + 1;
                    let body_end = s_lower[body_start..]
                        .find("</w:instrtext>")
                        .map(|idx| body_start + idx)
                        .unwrap_or(s.len());
                    text_cursor = body_end;

                    let instr = s[body_start..body_end].trim();
                    let i_low = instr.to_ascii_lowercase();
                    if i_low.contains("dde")
                        || i_low.contains("exec")
                        || i_low.contains("cmd")
                        || i_low.contains("powershell")
                        || i_low.contains("mshta")
                    {
                        results.push((
                            "Critical",
                            instr.to_string(),
                            "glossary:instrTextDDE".into(),
                            format!("Word glossary instruction text specifies command execution via DDE/shell ('{instr}')"),
                        ));
                    } else if i_low.contains("includetext") || i_low.contains("link") {
                        results.push((
                            "High",
                            instr.to_string(),
                            "glossary:instrTextInject".into(),
                            format!("Word glossary instruction text specifies remote document injection ('{instr}')"),
                        ));
                    } else if i_low.contains("macrobutton") {
                        results.push((
                            "High",
                            instr.to_string(),
                            "glossary:instrTextMacro".into(),
                            format!("Word glossary instruction text specifies macrobutton trigger ('{instr}')"),
                        ));
                    } else if i_low.contains("filename \\p") || i_low.contains("\\\\") {
                        results.push((
                            "High",
                            instr.to_string(),
                            "glossary:instrTextUNC".into(),
                            format!(
                                "Word glossary instruction text specifies UNC path leak ('{instr}')"
                            ),
                        ));
                    }
                } else {
                    break;
                }
            }

            // Check <w:altChunk>
            if s_lower.contains("<w:altchunk") {
                results.push((
                    "High",
                    "altChunk".into(),
                    "glossary:altChunk".into(),
                    "Word glossary document contains AltChunk payload reference".into(),
                ));
            }
        }

        results
    }

    fn scan_embedded_font_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let name_lower = entry_name.to_ascii_lowercase();

        if name_lower.ends_with(".rels") {
            let s = String::from_utf8_lossy(data);
            let mut cursor = 0;
            while cursor < s.len() {
                if let Some(pos) = s[cursor..].find("<Relationship ") {
                    let start = cursor + pos;
                    let tag_end = s[start..].find('>').unwrap_or(s.len() - start);
                    let tag = &s[start..start + tag_end];
                    cursor = start + tag_end;

                    let target = extract_attribute_value(tag, "Target").unwrap_or_default();
                    let target_mode =
                        extract_attribute_value(tag, "TargetMode").unwrap_or_default();
                    let t_lower = target.to_ascii_lowercase();
                    let is_external = target_mode.eq_ignore_ascii_case("External")
                        || t_lower.starts_with("http:")
                        || t_lower.starts_with("https:")
                        || t_lower.starts_with("\\\\");

                    if is_external {
                        if t_lower.starts_with("\\\\") || t_lower.starts_with("//") {
                            results.push((
                                "High",
                                target.clone(),
                                "font:uncShare".into(),
                                format!("Font relationship specifies remote UNC path '{target}' (NTLM coercion vector)"),
                            ));
                        } else if t_lower.starts_with("http:") || t_lower.starts_with("https:") {
                            results.push((
                                "High",
                                target.clone(),
                                "font:remoteUrl".into(),
                                format!("Font relationship specifies remote external font download '{target}'"),
                            ));
                        } else if t_lower.ends_with(".exe")
                            || t_lower.ends_with(".dll")
                            || t_lower.ends_with(".scr")
                            || t_lower.ends_with(".bat")
                            || t_lower.ends_with(".ps1")
                        {
                            results.push((
                                "Critical",
                                target.clone(),
                                "font:executableTarget".into(),
                                format!(
                                    "Font relationship references executable target '{target}'"
                                ),
                            ));
                        }
                    }
                } else {
                    break;
                }
            }
        } else if name_lower.ends_with(".odttf")
            || name_lower.ends_with(".ttf")
            || name_lower.ends_with(".woff")
        {
            // 1. Check raw PE binary
            if data.starts_with(b"MZ") && data.len() >= 0x40 {
                let pe_off =
                    u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap_or_default()) as usize;
                if pe_off + 4 <= data.len() && &data[pe_off..pe_off + 4] == b"PE\0\0" {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "font:pePayload".into(),
                        format!("Embedded font stream contains cloaked Windows PE executable binary (size: {} bytes)", data.len()),
                    ));
                    return results;
                }
            }

            // 2. Check Windows Shell Link shortcut (.lnk)
            if data.len() >= 0x4c && data[0..8] == [0x4c, 0x00, 0x02, 0x00, 0x01, 0x14, 0x02, 0x00]
            {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "font:lnkPayload".into(),
                    format!("Embedded font stream contains Windows Shell Link shortcut payload (size: {} bytes)", data.len()),
                ));
                return results;
            }

            // 3. Check Linux ELF
            if data.starts_with(b"\x7fELF") {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "font:elfPayload".into(),
                    format!("Embedded font stream contains Linux ELF executable binary (size: {} bytes)", data.len()),
                ));
                return results;
            }

            // 4. Check Staged script
            if data.starts_with(b"#!/bin/")
                || (data.len() > 10
                    && data[..100.min(data.len())]
                        .to_ascii_lowercase()
                        .windows(10)
                        .any(|w| w == b"powershell"))
            {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "font:scriptPayload".into(),
                    format!(
                        "Embedded font stream contains staged script payload (size: {} bytes)",
                        data.len()
                    ),
                ));
                return results;
            }

            // 5. Check Obfuscated OpenType Font (.odttf) XOR de-masking
            if name_lower.ends_with(".odttf") && data.len() >= 32 {
                let filename = entry_name.rsplit(['/', '\\']).next().unwrap_or(entry_name);
                let stem = filename.strip_suffix(".odttf").unwrap_or(filename);
                let mut hex_bytes = Vec::new();
                for b in stem.bytes() {
                    if b.is_ascii_hexdigit() {
                        hex_bytes.push(b);
                    }
                }
                if hex_bytes.len() >= 32 {
                    let mut guid = [0u8; 16];
                    for i in 0..16 {
                        let hi = match hex_bytes[i * 2] {
                            b'0'..=b'9' => hex_bytes[i * 2] - b'0',
                            b'a'..=b'f' => hex_bytes[i * 2] - b'a' + 10,
                            b'A'..=b'F' => hex_bytes[i * 2] - b'A' + 10,
                            _ => 0,
                        };
                        let lo = match hex_bytes[i * 2 + 1] {
                            b'0'..=b'9' => hex_bytes[i * 2 + 1] - b'0',
                            b'a'..=b'f' => hex_bytes[i * 2 + 1] - b'a' + 10,
                            b'A'..=b'F' => hex_bytes[i * 2 + 1] - b'A' + 10,
                            _ => 0,
                        };
                        guid[i] = (hi << 4) | lo;
                    }
                    let mut key = [0u8; 16];
                    for i in 0..16 {
                        key[i] = guid[15 - i];
                    }
                    let mut demasked = [0u8; 32];
                    for i in 0..32 {
                        demasked[i] = data[i] ^ key[i % 16];
                    }
                    if &demasked[0..2] == b"MZ" {
                        results.push((
                            "Critical",
                            entry_name.to_string(),
                            "font:odttfPePayload".into(),
                            format!("Obfuscated font stream (.odttf) de-masks to Windows PE executable binary (size: {} bytes)", data.len()),
                        ));
                    }
                }
            }
        }

        results
    }

    fn scan_digital_ink_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let name_lower = entry_name.to_ascii_lowercase();

        if name_lower.ends_with(".rels") {
            let s = String::from_utf8_lossy(data);
            let mut cursor = 0;
            while cursor < s.len() {
                if let Some(pos) = s[cursor..].find("<Relationship ") {
                    let start = cursor + pos;
                    let tag_end = s[start..].find('>').unwrap_or(s.len() - start);
                    let tag = &s[start..start + tag_end];
                    cursor = start + tag_end;

                    let target = extract_attribute_value(tag, "Target").unwrap_or_default();
                    let target_mode =
                        extract_attribute_value(tag, "TargetMode").unwrap_or_default();
                    let t_lower = target.to_ascii_lowercase();
                    let is_external = target_mode.eq_ignore_ascii_case("External")
                        || t_lower.starts_with("http:")
                        || t_lower.starts_with("https:")
                        || t_lower.starts_with("\\\\");

                    if is_external {
                        if t_lower.starts_with("\\\\") || t_lower.starts_with("//") {
                            results.push((
                                "High",
                                target.clone(),
                                "ink:uncPath".into(),
                                format!("Digital Ink relationship references remote UNC path '{target}' (NTLM coercion vector)"),
                            ));
                        } else if t_lower.starts_with("ms-msdt:")
                            || t_lower.starts_with("search-ms:")
                            || t_lower.starts_with("mhtml:")
                            || t_lower.starts_with("javascript:")
                            || t_lower.starts_with("vbscript:")
                        {
                            results.push((
                                "Critical",
                                target.clone(),
                                "ink:protocolHandler".into(),
                                format!("Digital Ink relationship references dangerous exploit protocol scheme ('{target}')"),
                            ));
                        } else if t_lower.ends_with(".exe")
                            || t_lower.ends_with(".dll")
                            || t_lower.ends_with(".scr")
                            || t_lower.ends_with(".bat")
                            || t_lower.ends_with(".ps1")
                            || t_lower.ends_with(".vbs")
                        {
                            results.push((
                                "Critical",
                                target.clone(),
                                "ink:executableTarget".into(),
                                format!("Digital Ink relationship references executable or script target '{target}'"),
                            ));
                        }
                    }
                } else {
                    break;
                }
            }
        } else if name_lower.ends_with(".xml") {
            let s = String::from_utf8_lossy(data);
            let s_lower = s.to_ascii_lowercase();

            if s_lower.contains("<a:hlinkclick")
                || s_lower.contains("<a:hlinkhover")
                || s_lower.contains("ppaction://")
            {
                let is_command = s_lower.contains("ppaction://program")
                    || s_lower.contains(".exe")
                    || s_lower.contains(".bat")
                    || s_lower.contains(".cmd")
                    || s_lower.contains(".ps1")
                    || s_lower.contains("powershell")
                    || s_lower.contains("cmd.exe")
                    || s_lower.contains("mshta");
                let sev = if is_command { "Critical" } else { "High" };
                results.push((
                    sev,
                    entry_name.to_string(),
                    "ink:actionTrigger".into(),
                    "Digital Ink annotation defines interactive action/hover trigger (command execution vector)".into(),
                ));
            }

            if s_lower.contains("{72c24dd5-d70a-438b-8a42-98424b88afb8}")
                || s_lower.contains("{0002ce02-0000-0000-c000-000000000046}")
            {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "ink:clsidAnomaly".into(),
                    "Digital Ink markup references weaponized ActiveX / OLE CLSID".into(),
                ));
            }
        } else if (name_lower.ends_with(".bin") || name_lower.ends_with(".isf"))
            && data.starts_with(b"MZ")
            && data.len() >= 0x40
        {
            let pe_off =
                u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap_or_default()) as usize;
            if pe_off + 4 <= data.len() && &data[pe_off..pe_off + 4] == b"PE\0\0" {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "ink:pePayload".into(),
                    format!("Digital Ink binary stream contains cloaked Windows PE executable binary (size: {} bytes)", data.len()),
                ));
            }
        }

        results
    }

    fn scan_document_property_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let name_lower = entry_name.to_ascii_lowercase();
        let is_docprops = name_lower.starts_with("docprops/")
            || name_lower.contains("/docprops/")
            || name_lower.contains("\\docprops\\")
            || name_lower.ends_with("core.xml")
            || name_lower.ends_with("app.xml")
            || name_lower.ends_with("custom.xml");

        if !is_docprops {
            return results;
        }

        let s = String::from_utf8_lossy(data);
        let s_lower = s.to_ascii_lowercase();

        // 1. Base64 PE header markers
        'b64: for marker in &["tvqq", "tvoa", "tvpb", "tvpq"] {
            let mut pos = 0;
            while let Some(idx) = s_lower[pos..].find(marker) {
                let abs = pos + idx;
                let candidate = &s[abs..];
                let b64_len = candidate
                    .bytes()
                    .take_while(|b| {
                        b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/' || *b == b'='
                    })
                    .count();
                if b64_len >= 64 {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "docProps:base64PePayload".into(),
                        format!(
                            "Document property contains smuggled Base64 Windows PE executable payload (length: {} chars)",
                            b64_len
                        ),
                    ));
                    break 'b64;
                }
                pos = abs + 4;
            }
        }

        // 2. Hex-encoded PE header (4d5a9000)
        if s_lower.contains("4d5a9000")
            || (s_lower.contains("4d5a")
                && s_lower.contains("this program cannot be run in dos mode"))
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "docProps:hexPePayload".into(),
                "Document property contains hex-encoded Windows PE executable binary header".into(),
            ));
        }

        // 3. Dangerous protocol handlers
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "mhtml:",
            "ms-appinstaller:",
            "javascript:",
            "vbscript:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "docProps:dangerousProtocol".into(),
                    format!("Document property contains dangerous URI scheme '{proto}'"),
                ));
            }
        }

        // 4. Staged commands and script execution triggers
        for cmd in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
            "bitsadmin",
            "bash.exe",
            "wsl.exe",
            "regsvr32",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "docProps:stagedScriptOrCommand".into(),
                    format!("Document property contains staged shell execution command or script trigger: '{cmd}'"),
                ));
                break;
            }
        }

        // 5. External UNC paths for NTLM credential coercion
        for (i, w) in data.windows(2).enumerate() {
            if (w == b"\\\\" || w == b"//") && i + 4 < data.len() {
                let rest = &data[i..];
                let end = rest
                    .iter()
                    .position(|&b| {
                        b == 0
                            || b == b' '
                            || b == b'"'
                            || b == b'\''
                            || b == b'<'
                            || b == b'>'
                            || b == b'\r'
                            || b == b'\n'
                    })
                    .unwrap_or(rest.len().min(128));
                if let Some(unc) = (end > 4)
                    .then(|| std::str::from_utf8(&rest[..end]).ok())
                    .flatten()
                    .filter(|u| u.contains('\\') || u.contains('/'))
                {
                    results.push((
                        "High",
                        entry_name.to_string(),
                        "docProps:uncCoercion".into(),
                        format!(
                            "Document property contains external UNC path '{unc}' (NTLM coercion vector)"
                        ),
                    ));
                    break;
                }
            }
        }

        results
    }

    fn scan_web_extension_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let name_lower = entry_name.to_ascii_lowercase();
        let is_webext = name_lower.contains("webextension") || name_lower.contains("taskpane");

        if !is_webext {
            return results;
        }

        if name_lower.ends_with(".rels") {
            let mut pos = 0;
            while let Some(idx) = data[pos..]
                .windows(8)
                .position(|w| w.eq_ignore_ascii_case(b"<relatio"))
            {
                let rel_start = pos + idx;
                pos = rel_start + 8;
                let rel_end = match data[rel_start..]
                    .windows(2)
                    .position(|w| w == b"/>" || w == b"\">")
                {
                    Some(p) => rel_start + p + 2,
                    None => break,
                };
                let rel_bytes = &data[rel_start..rel_end];
                let rel_str = String::from_utf8_lossy(rel_bytes);
                let target = extract_attribute_value(&rel_str, "Target").unwrap_or_default();
                let target_mode =
                    extract_attribute_value(&rel_str, "TargetMode").unwrap_or_default();

                if !target.is_empty() {
                    let t_lower = target.to_ascii_lowercase();
                    let is_external = target_mode.eq_ignore_ascii_case("External")
                        || t_lower.starts_with("http:")
                        || t_lower.starts_with("https:")
                        || t_lower.starts_with("\\\\")
                        || t_lower.starts_with("//");

                    if is_external {
                        if t_lower.starts_with("\\\\") || t_lower.starts_with("//") {
                            results.push((
                                "High",
                                target.clone(),
                                "webext:uncPath".into(),
                                format!("Web extension / taskpane relationship references remote UNC path '{target}' (NTLM coercion vector)"),
                            ));
                        } else if t_lower.starts_with("ms-msdt:")
                            || t_lower.starts_with("search-ms:")
                            || t_lower.starts_with("mhtml:")
                            || t_lower.starts_with("javascript:")
                        {
                            results.push((
                                "Critical",
                                target.clone(),
                                "webext:protocolHandler".into(),
                                format!("Web extension / taskpane relationship references dangerous exploit URI scheme '{target}'"),
                            ));
                        } else {
                            results.push((
                                "High",
                                target.clone(),
                                "webext:remoteTarget".into(),
                                format!("Web extension / taskpane relationship targets external remote web server '{target}'"),
                            ));
                        }
                    }
                }
            }
        } else if name_lower.ends_with(".xml") {
            let s = String::from_utf8_lossy(data);
            let s_lower = s.to_ascii_lowercase();

            // Auto-show taskpane check
            if s_lower.contains("canautoshow=\"1\"")
                || s_lower.contains("canautoshow=\"true\"")
                || s_lower.contains("autoshow=\"1\"")
                || s_lower.contains("autoshow=\"true\"")
                || s_lower.contains("visibility=\"visible\"")
            {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "taskpane:autoShowTrigger".into(),
                    "Office taskpane defines automatic display trigger (canAutoShow/visible), launching webview without user interaction".into(),
                ));
            }

            // Dangerous protocol or URL in webextension XML
            for proto in &[
                "ms-msdt:",
                "search-ms:",
                "mhtml:",
                "javascript:",
                "powershell:",
            ] {
                if s_lower.contains(proto) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "webext:dangerousUri".into(),
                        format!("Web extension markup contains dangerous protocol URI '{proto}'"),
                    ));
                }
            }

            // Script tags in web extension parts
            if s_lower.contains("<script") || s_lower.contains("javascript:") {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "webext:embeddedScript".into(),
                    "Web extension markup contains embedded script elements or JavaScript triggers"
                        .into(),
                ));
            }
        }

        results
    }

    fn scan_pivot_cache_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let name_lower = entry_name.to_ascii_lowercase();
        let is_pivot_cache = name_lower.contains("pivotcache");

        if !is_pivot_cache {
            return results;
        }

        if name_lower.ends_with(".rels") {
            let mut pos = 0;
            while let Some(idx) = data[pos..]
                .windows(8)
                .position(|w| w.eq_ignore_ascii_case(b"<relatio"))
            {
                let rel_start = pos + idx;
                pos = rel_start + 8;
                let rel_end = match data[rel_start..]
                    .windows(2)
                    .position(|w| w == b"/>" || w == b"\">")
                {
                    Some(p) => rel_start + p + 2,
                    None => break,
                };
                let rel_bytes = &data[rel_start..rel_end];
                let rel_str = String::from_utf8_lossy(rel_bytes);
                let target = extract_attribute_value(&rel_str, "Target").unwrap_or_default();
                let target_mode =
                    extract_attribute_value(&rel_str, "TargetMode").unwrap_or_default();

                if !target.is_empty() {
                    let t_lower = target.to_ascii_lowercase();
                    let is_external = target_mode.eq_ignore_ascii_case("External")
                        || t_lower.starts_with("http:")
                        || t_lower.starts_with("https:")
                        || t_lower.starts_with("\\\\")
                        || t_lower.starts_with("//");

                    if is_external {
                        if t_lower.starts_with("\\\\") || t_lower.starts_with("//") {
                            results.push((
                                "High",
                                target.clone(),
                                "pivotCache:uncPath".into(),
                                format!("PivotCache relationship references remote UNC path '{target}' (NTLM coercion vector)"),
                            ));
                        } else if t_lower.starts_with("ms-msdt:")
                            || t_lower.starts_with("search-ms:")
                        {
                            results.push((
                                "Critical",
                                target.clone(),
                                "pivotCache:protocolHandler".into(),
                                format!("PivotCache relationship references dangerous exploit URI scheme '{target}'"),
                            ));
                        } else {
                            results.push((
                                "High",
                                target.clone(),
                                "pivotCache:externalTarget".into(),
                                format!("PivotCache relationship targets external remote data source '{target}'"),
                            ));
                        }
                    }
                }
            }
        } else if name_lower.ends_with(".xml") {
            let s = String::from_utf8_lossy(data);
            let s_lower = s.to_ascii_lowercase();

            // 1. Database command execution
            for cmd in &[
                "xp_cmdshell",
                "sp_oacreate",
                "openrowset",
                "bulk insert",
                "powershell",
                "cmd.exe",
            ] {
                if s_lower.contains(cmd) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "pivotCache:commandExecution".into(),
                        format!("PivotCache definition contains database shell command execution trigger: '{cmd}'"),
                    ));
                    break;
                }
            }

            // 2. UNC connection path
            if s_lower.contains("data source=\\\\")
                || s_lower.contains("data source=//")
                || s_lower.contains("server=\\\\")
                || s_lower.contains("server=//")
                || s_lower.contains("location=\\\\")
            {
                results.push((
                    "High",
                    entry_name.to_string(),
                    "pivotCache:uncConnection".into(),
                    "PivotCache connection definition contains remote UNC path (NTLM credential coercion vector)".into(),
                ));
            }

            // 3. Dangerous protocol or file targets
            for proto in &["ms-msdt:", "search-ms:", "mhtml:"] {
                if s_lower.contains(proto) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "pivotCache:dangerousProtocol".into(),
                        format!(
                            "PivotCache connection references dangerous URI protocol '{proto}'"
                        ),
                    ));
                }
            }
        }

        results
    }

    fn percent_decode_simple(input: &str) -> String {
        let mut out = String::with_capacity(input.len());
        let bytes = input.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if let Some(val) = (bytes[i] == b'%' && i + 2 < bytes.len())
                .then(|| std::str::from_utf8(&bytes[i + 1..i + 3]).ok())
                .flatten()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                out.push(val as char);
                i += 3;
                continue;
            }
            out.push(bytes[i] as char);
            i += 1;
        }
        out
    }

    fn scan_metafile_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let name_lower = entry_name.to_ascii_lowercase();

        // 1. WMF SetAbortProc Exploit (CVE-2005-4560)
        let is_wmf = name_lower.ends_with(".wmf")
            || (data.len() >= 4 && data[0..4] == [0xD7, 0xCD, 0xC6, 0x9A])
            || (data.len() >= 2 && (data[0..2] == [0x01, 0x00] || data[0..2] == [0x02, 0x00]));

        if is_wmf && data.windows(2).any(|w| w == [0x2F, 0x05]) {
            results.push((
                "Critical",
                entry_name.to_string(),
                "metafile:setAbortProcExploit".into(),
                "Windows Metafile (WMF) contains META_SETABORTPROC record (CVE-2005-4560 arbitrary code execution exploit)".into(),
            ));
        }

        // 2. Embedded / cloaked Windows PE Executable
        if let Some(mz_idx) = data.windows(2).position(|w| w == b"MZ") {
            let scan_window = &data[mz_idx..data.len().min(mz_idx + 1024)];
            if scan_window.windows(4).any(|w| w == b"PE\0\0") {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "metafile:cloakedPeExecutable".into(),
                    "Metafile graphic stream contains cloaked Windows PE executable binary".into(),
                ));
            }
        }

        // 3. Embedded Windows Shell Link (.lnk) Payload
        const LNK_GUID: [u8; 16] = [
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x46,
        ];
        if data.windows(16).any(|w| w == LNK_GUID) {
            results.push((
                "Critical",
                entry_name.to_string(),
                "metafile:embeddedShellLink".into(),
                "Metafile graphic stream contains embedded Windows Shell Link (.lnk) shortcut payload".into(),
            ));
        }

        // 4. Shell Execution Commands or Staged Scripts
        let s_lossy = String::from_utf8_lossy(data);
        let s_lower = s_lossy.to_ascii_lowercase();
        for kw in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
        ] {
            if s_lower.contains(kw) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "metafile:embeddedShellCommand".into(),
                    format!(
                        "Metafile graphic stream contains embedded shell execution command '{kw}'"
                    ),
                ));
                break;
            }
        }

        results
    }

    fn scan_xslt_transform_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lossy = String::from_utf8_lossy(data);
        let s_lower = s_lossy.to_ascii_lowercase();

        // 1. Executable MSXSL Script Elements
        if s_lower.contains("<msxsl:script")
            || s_lower.contains("<ms:script")
            || s_lower.contains("<xsl:script")
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "xslt:scriptExecution".into(),
                "XML part contains executable MSXSL script element (macro-less arbitrary script execution)".into(),
            ));
        }

        // 2. SaveThroughXslt or Remote Transform References
        if s_lower.contains("<w:savethroughxslt")
            || s_lower.contains("<w:transform")
            || ((s_lower.contains("<xsl:stylesheet") || s_lower.contains("<xsl:transform"))
                && (s_lower.contains("http://")
                    || s_lower.contains("https://")
                    || s_lower.contains(r"\\")))
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "xslt:remoteTransformTarget".into(),
                "XML part configures XSLT transform targeting remote external URI or UNC path"
                    .into(),
            ));
        }

        // 3. Dangerous XPath / XSLT Functions (document() SSRF / NTLM coercion)
        if s_lower.contains("document('http")
            || s_lower.contains("document(\"http")
            || s_lower.contains("document('file")
            || s_lower.contains("document(\"file")
            || s_lower.contains("document('\\\\")
            || s_lower.contains("document(\"\\\\")
        {
            results.push((
                "High",
                entry_name.to_string(),
                "xslt:dangerousDocumentCall".into(),
                "XSLT markup contains dangerous external document() invocation (SSRF / NTLM coercion vector)".into(),
            ));
        }

        // 4. Windows Shell Automation Objects in XSLT Context
        if (s_lower.contains("wscript.shell") || s_lower.contains("shell.application"))
            && (s_lower.contains("xsl") || s_lower.contains("transform"))
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "xslt:shellAutomationObject".into(),
                "XSLT markup references Windows Shell COM automation object (WScript.Shell / Shell.Application)".into(),
            ));
        }

        results
    }

    fn scan_relationship_cloaking_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();

        let mut pos = 0;
        while let Some(idx) = data[pos..]
            .windows(13)
            .position(|w| w.eq_ignore_ascii_case(b"<relationship"))
        {
            let rel_start = pos + idx;
            pos = rel_start + 13;
            let rel_end = match data[rel_start..]
                .windows(2)
                .position(|w| w == b"/>" || w == b"\">")
            {
                Some(p) => rel_start + p + 2,
                None => break,
            };
            let rel_bytes = &data[rel_start..rel_end];
            let rel_str = String::from_utf8_lossy(rel_bytes);
            let target = extract_attribute_value(&rel_str, "Target").unwrap_or_default();
            let target_id = extract_attribute_value(&rel_str, "Id").unwrap_or_default();

            if !target.is_empty() {
                // 1. Null-byte or Unicode bidirectional override cloaking
                let has_null = target.contains('\0') || target.contains("%00");
                let has_override = target.chars().any(|c| {
                    matches!(
                        c,
                        '\u{202A}'..='\u{202E}' | '\u{200B}'..='\u{200D}'
                    )
                });
                if has_null || has_override {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        format!("rels:cloakingCharacter:{}", target_id),
                        format!("Relationship Target contains evasion characters (null-byte or Unicode override) in '{target}'"),
                    ));
                }

                // 2. Percent-encoded dangerous protocol evasion
                let decoded = percent_decode_simple(&target);
                let d_lower = decoded.to_ascii_lowercase();
                let t_lower = target.to_ascii_lowercase();
                for proto in &[
                    "ms-msdt:",
                    "search-ms:",
                    "mhtml:",
                    "javascript:",
                    "vbscript:",
                    "ms-appinstaller:",
                ] {
                    if d_lower.contains(proto) && !t_lower.contains(proto) {
                        results.push((
                            "Critical",
                            entry_name.to_string(),
                            format!("rels:percentEncodedProtocol:{}", target_id),
                            format!("Relationship Target obfuscates dangerous protocol handler via percent-encoding '{proto}'"),
                        ));
                        break;
                    }
                }

                // 3. Local IPC Named Pipe or Loopback Coercion
                if target.starts_with(r"\\.\pipe\")
                    || target.starts_with(r"\\.\PIPE\")
                    || target.starts_with(r"\\127.0.0.1\")
                    || target.starts_with(r"\\localhost\")
                {
                    results.push((
                        "High",
                        entry_name.to_string(),
                        format!("rels:localIpcCoercion:{}", target_id),
                        format!("Relationship Target references local IPC named pipe or loopback resource '{target}'"),
                    ));
                }
            }
        }

        results
    }

    fn scan_smartart_diagram_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lossy = String::from_utf8_lossy(data);
        let s_lower = s_lossy.to_ascii_lowercase();

        // 1. Interactive click or hover actions
        if s_lower.contains("<dgm:hlinkclick")
            || s_lower.contains("<a:hlinkclick")
            || s_lower.contains("<a:hlinkhover")
            || s_lower.contains("ppaction://program")
            || s_lower.contains("ppaction://macro")
        {
            let sev = if s_lower.contains("ppaction://program")
                || s_lower.contains("powershell")
                || s_lower.contains("cmd.exe")
            {
                "Critical"
            } else {
                "High"
            };
            results.push((
                sev,
                entry_name.to_string(),
                "diagram:interactiveAction".into(),
                "SmartArt diagram markup defines interactive click or hover action trigger".into(),
            ));
        }

        // 2. Dangerous URI protocol handlers
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "ms-appinstaller:",
            "mhtml:",
            "powershell:",
            "cmd:",
            "wscript:",
            "cscript:",
            "javascript:",
            "vbscript:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "diagram:dangerousProtocol".into(),
                    format!("SmartArt diagram markup references dangerous URI protocol handler '{proto}'"),
                ));
                break;
            }
        }

        // 3. Remote UNC paths for NTLM credential coercion
        if s_lower.contains(r"\\") {
            let mut has_unc = false;
            let mut search_idx = 0;
            while let Some(pos) = s_lower[search_idx..].find(r"\\") {
                let actual_pos = search_idx + pos;
                let rem = &s_lower[actual_pos + 2..];
                if let Some(first_char) = rem.chars().next()
                    && (first_char.is_ascii_alphanumeric()
                        || first_char == '.'
                        || first_char == '[')
                    && rem.contains('\\')
                {
                    has_unc = true;
                    break;
                }
                search_idx = actual_pos + 2;
            }
            if has_unc {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "diagram:uncCoercion".into(),
                    "SmartArt diagram markup contains remote UNC path (NTLM credential coercion vector)".into(),
                ));
            }
        }

        // 4. Cloaked Windows PE Executable or Shell Link or Staged Script
        if let Some(mz_idx) = data.windows(2).position(|w| w == b"MZ") {
            let scan_window = &data[mz_idx..data.len().min(mz_idx + 1024)];
            if scan_window.windows(4).any(|w| w == b"PE\0\0") {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "diagram:cloakedPeExecutable".into(),
                    "SmartArt diagram part contains cloaked Windows PE executable binary".into(),
                ));
            }
        }

        const LNK_GUID: [u8; 16] = [
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x46,
        ];
        if data.windows(16).any(|w| w == LNK_GUID) {
            results.push((
                "Critical",
                entry_name.to_string(),
                "diagram:embeddedShellLink".into(),
                "SmartArt diagram part contains embedded Windows Shell Link (.lnk) shortcut payload".into(),
            ));
        }

        for kw in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
        ] {
            if s_lower.contains(kw) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "diagram:shellExecutionCommand".into(),
                    format!(
                        "SmartArt diagram part contains embedded shell execution command '{kw}'"
                    ),
                ));
                break;
            }
        }

        results
    }

    fn scan_mail_merge_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lossy = String::from_utf8_lossy(data);
        let s_lower = s_lossy.to_ascii_lowercase();

        // 1. Check for MailMerge block in settings.xml
        if s_lower.contains("<w:mailmerge") {
            let mut has_unc = false;
            let mut search_idx = 0;
            while let Some(pos) = s_lower[search_idx..].find(r"\\") {
                let actual_pos = search_idx + pos;
                let rem = &s_lower[actual_pos + 2..];
                if let Some(first_char) = rem.chars().next()
                    && (first_char.is_ascii_alphanumeric()
                        || first_char == '.'
                        || first_char == '[')
                    && rem.contains('\\')
                {
                    has_unc = true;
                    break;
                }
                search_idx = actual_pos + 2;
            }
            if has_unc {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "mailMerge:uncCoercion".into(),
                    "Word MailMerge configuration contains remote UNC path for NTLM credential coercion".into(),
                ));
            }

            for cmd in &[
                "xp_cmdshell",
                "sp_oacreate",
                "openrowset",
                "exec master",
                "exec(",
            ] {
                if s_lower.contains(cmd) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "mailMerge:commandInjection".into(),
                        format!("Word MailMerge configuration contains database execution command '{cmd}'"),
                    ));
                    break;
                }
            }

            if (s_lower.contains("destination") && s_lower.contains("newdocument"))
                || s_lower.contains("<w:linktoquery")
            {
                results.push((
                    "High",
                    entry_name.to_string(),
                    "mailMerge:autoExecution".into(),
                    "Word MailMerge configured with automatic document merge execution trigger"
                        .into(),
                ));
            }
        }

        // 2. Check for MailMerge relationships pointing to dangerous targets
        if entry_name.to_ascii_lowercase().ends_with(".rels") {
            let mut pos = 0;
            while let Some(idx) = data[pos..]
                .windows(13)
                .position(|w| w.eq_ignore_ascii_case(b"<relationship"))
            {
                let rel_start = pos + idx;
                pos = rel_start + 13;
                let rel_end = match data[rel_start..]
                    .windows(2)
                    .position(|w| w == b"/>" || w == b"\">")
                {
                    Some(p) => rel_start + p + 2,
                    None => break,
                };
                let rel_bytes = &data[rel_start..rel_end];
                let rel_str = String::from_utf8_lossy(rel_bytes);
                let rel_type = extract_attribute_value(&rel_str, "Type")
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                if rel_type.contains("mailmerge") {
                    let target = extract_attribute_value(&rel_str, "Target").unwrap_or_default();
                    let target_id = extract_attribute_value(&rel_str, "Id").unwrap_or_default();
                    let t_lower = target.to_ascii_lowercase();

                    if t_lower.starts_with(r"\\") {
                        results.push((
                            "Critical",
                            entry_name.to_string(),
                            format!("mailMerge:remoteUncTarget:{}", target_id),
                            format!("Word MailMerge relationship targets remote UNC path '{target}' (NTLM coercion vector)"),
                        ));
                    } else if t_lower.starts_with("http://") || t_lower.starts_with("https://") {
                        results.push((
                            "High",
                            entry_name.to_string(),
                            format!("mailMerge:remoteHttpTarget:{}", target_id),
                            format!("Word MailMerge relationship targets external HTTP/HTTPS data source '{target}'"),
                        ));
                    }

                    for ext in &[
                        ".iqy", ".hta", ".vbs", ".bat", ".ps1", ".exe", ".cmd", ".dll", ".scr",
                    ] {
                        if t_lower.ends_with(ext) || t_lower.contains(&format!("{ext}?")) {
                            results.push((
                                "Critical",
                                entry_name.to_string(),
                                format!("mailMerge:executableTarget:{}", target_id),
                                format!("Word MailMerge relationship targets dangerous executable or script file '{target}'"),
                            ));
                            break;
                        }
                    }
                }
            }
        }

        results
    }

    fn scan_query_table_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lossy = String::from_utf8_lossy(data);
        let s_lower = s_lossy.to_ascii_lowercase();

        let has_auto_refresh = s_lower.contains("refreshonload=\"1\"")
            || s_lower.contains("refreshonload=\"true\"")
            || s_lower.contains("autorefresh=\"1\"")
            || s_lower.contains("autorefresh=\"true\"");

        if s_lower.contains(r"\\") {
            let mut has_unc = false;
            let mut search_idx = 0;
            while let Some(pos) = s_lower[search_idx..].find(r"\\") {
                let actual_pos = search_idx + pos;
                let rem = &s_lower[actual_pos + 2..];
                if let Some(first_char) = rem.chars().next()
                    && (first_char.is_ascii_alphanumeric()
                        || first_char == '.'
                        || first_char == '[')
                    && rem.contains('\\')
                {
                    has_unc = true;
                    break;
                }
                search_idx = actual_pos + 2;
            }
            if has_unc {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "queryTable:uncCoercion".into(),
                    "Excel QueryTable connection target specifies remote UNC path (NTLM credential coercion)".into(),
                ));
            }
        }

        for ext in &[".iqy", ".dqy", ".rqy", ".oqy"] {
            if s_lower.contains(ext) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "queryTable:webQueryFile".into(),
                    format!("Excel QueryTable references external Web Query file '{ext}' (remote payload vector)"),
                ));
                break;
            }
        }

        for cmd in &[
            "xp_cmdshell",
            "sp_oacreate",
            "openrowset",
            "exec(",
            "exec master",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "queryTable:commandExecution".into(),
                    format!("Excel QueryTable contains database shell execution command '{cmd}'"),
                ));
                break;
            }
        }

        for env_token in &["%username%", "%userdomain%", "%computername%"] {
            if s_lower.contains(env_token) {
                results.push((
                    "High",
                    entry_name.to_string(),
                    "queryTable:envExfiltration".into(),
                    format!("Excel QueryTable connection URL contains environment variable exfiltration token '{env_token}'"),
                ));
                break;
            }
        }

        if has_auto_refresh
            && (s_lower.contains("http://")
                || s_lower.contains("https://")
                || s_lower.contains("connection"))
        {
            results.push((
                "High",
                entry_name.to_string(),
                "queryTable:autoRefreshEnabled".into(),
                "Excel QueryTable configured to automatically refresh external connection upon opening without user interaction".into(),
            ));
        }

        results
    }

    fn scan_power_query_mashup_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lossy = String::from_utf8_lossy(data);
        let s_lower = s_lossy.to_ascii_lowercase();

        let is_mashup_or_pq = entry_name.to_ascii_lowercase().contains("powerquery")
            || entry_name.to_ascii_lowercase().contains("datamashup")
            || entry_name.to_ascii_lowercase().contains("mashup")
            || s_lower.contains("datamashup")
            || s_lower.contains("microsoft.data.mashup")
            || s_lower.contains("section section1;");

        if !is_mashup_or_pq {
            return results;
        }

        if s_lower.contains("web.page") {
            results.push((
                "Critical",
                entry_name.to_string(),
                "powerQuery:webPageExecution".into(),
                "Power Query M formula uses Web.Page(...) enabling arbitrary HTML/JavaScript/ActiveX execution within Excel host".into(),
            ));
        }

        if s_lower.contains("web.contents")
            && (s_lower.contains("http://") || s_lower.contains("https://"))
        {
            results.push((
                "High",
                entry_name.to_string(),
                "powerQuery:webContentsOutbound".into(),
                "Power Query M formula uses Web.Contents(...) targeting external URL (remote data exfiltration or payload download)".into(),
            ));
        }

        if s_lower.contains("file.contents") || s_lower.contains(r"\\") {
            let mut has_unc = false;
            let mut search_idx = 0;
            while let Some(pos) = s_lower[search_idx..].find(r"\\") {
                let actual_pos = search_idx + pos;
                let rem = &s_lower[actual_pos + 2..];
                if let Some(first_char) = rem.chars().next()
                    && (first_char.is_ascii_alphanumeric()
                        || first_char == '.'
                        || first_char == '[')
                    && rem.contains('\\')
                {
                    has_unc = true;
                    break;
                }
                search_idx = actual_pos + 2;
            }
            if has_unc {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "powerQuery:uncCoercion".into(),
                    "Power Query M formula references remote UNC path for NTLM credential coercion"
                        .into(),
                ));
            }
        }

        if s_lower.contains("binary.fromtext")
            && s_lower.contains("binaryencoding.base64")
            && (s_lossy.contains("TVqQ")
                || s_lower.contains("this program cannot be run in dos mode"))
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "powerQuery:smuggledBinary".into(),
                "Power Query M formula reconstructs smuggled Windows executable binary via Binary.FromText".into(),
            ));
        }

        for cmd in &[
            "xp_cmdshell",
            "sp_oacreate",
            "openrowset",
            "exec master",
            "exec(",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "powerQuery:commandInjection".into(),
                    format!("Power Query M formula contains database execution command '{cmd}'"),
                ));
                break;
            }
        }

        for env_func in &[
            "environment.username",
            "environment.machinename",
            "diagnostics.activityid",
        ] {
            if s_lower.contains(env_func) {
                results.push((
                    "High",
                    entry_name.to_string(),
                    "powerQuery:envExfiltration".into(),
                    format!("Power Query M formula accesses host environment profiling token '{env_func}' for exfiltration"),
                ));
                break;
            }
        }

        results
    }

    fn scan_package_moniker_activation_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lossy = String::from_utf8_lossy(data);
        let s_lower = s_lossy.to_ascii_lowercase();

        for proto in &[
            "script:",
            "moniker:",
            "composite:",
            "file:",
            "ms-msdt:",
            "search-ms:",
            "ms-appinstaller:",
        ] {
            if s_lower.contains(proto)
                && (entry_name.to_ascii_lowercase().ends_with(".rels")
                    || s_lower.contains("<o:oleobject")
                    || s_lower.contains("<w:object")
                    || s_lower.contains("<p:oleobj")
                    || s_lower.contains("<a:hlinkclick"))
            {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    format!("moniker:suspiciousProtocol:{}", proto.trim_end_matches(':')),
                    format!("OLE object or package relationship specifies dangerous Moniker protocol handler '{proto}'"),
                ));
                break;
            }
        }

        let has_auto_activate = s_lower.contains("updatemode=\"always\"")
            || s_lower.contains("autoupdate=\"1\"")
            || s_lower.contains("autoupdate=\"true\"")
            || s_lower.contains("autoactivate=\"1\"")
            || s_lower.contains("autoactivate=\"true\"");

        if has_auto_activate
            && (s_lower.contains("<o:oleobject")
                || s_lower.contains("<w:object")
                || s_lower.contains("<p:oleobj")
                || s_lower.contains("package"))
        {
            results.push((
                "High",
                entry_name.to_string(),
                "moniker:autoActivation".into(),
                "OLE object configured with automatic silent activation upon document opening"
                    .into(),
            ));
        }

        let has_icon_aspect = s_lower.contains("drawaspect=\"icon\"");
        if has_icon_aspect {
            for ext in &[
                ".exe", ".bat", ".scr", ".vbs", ".js", ".cmd", ".ps1", ".hta",
            ] {
                if s_lower.contains(ext) {
                    results.push((
                        "High",
                        entry_name.to_string(),
                        "moniker:iconCloaking".into(),
                        format!("OLE object cloaks executable/package payload ('{ext}') with deceptive document icon aspect"),
                    ));
                    break;
                }
            }
        }

        for (clsid, name) in &[
            (
                "{f20be578-230c-1380-1a29-e3f84c071110}",
                "Packager Shell Object",
            ),
            ("{0000031a-0000-0000-c000-000000000046}", "FileMoniker"),
            ("{79eac9e0-baf9-11ce-8c82-00aa004ba90b}", "URLMoniker"),
            (
                "{00020820-0000-0000-c000-000000000046}",
                "Excel.Sheet.8 Moniker",
            ),
            (
                "{00020906-0000-0000-c000-000000000046}",
                "Word.Document.8 Moniker",
            ),
        ] {
            if s_lower.contains(clsid) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    format!("moniker:weaponizedClsid:{clsid}"),
                    format!(
                        "OLE object specifies weaponized Packager/Moniker CLSID '{clsid}' ({name})"
                    ),
                ));
                break;
            }
        }

        results
    }

    fn scan_namespace_cloaking_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lossy = String::from_utf8_lossy(data);
        let s_lower = s_lossy.to_ascii_lowercase();

        if (s_lower.contains("xmlns:") || s_lower.contains("schemalocation"))
            && s_lower.contains(r"\\")
        {
            let mut has_unc = false;
            let mut search_idx = 0;
            while let Some(pos) = s_lower[search_idx..].find(r"\\") {
                let actual_pos = search_idx + pos;
                let rem = &s_lower[actual_pos + 2..];
                if let Some(first_char) = rem.chars().next()
                    && (first_char.is_ascii_alphanumeric()
                        || first_char == '.'
                        || first_char == '[')
                    && rem.contains('\\')
                {
                    has_unc = true;
                    break;
                }
                search_idx = actual_pos + 2;
            }
            if has_unc {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "namespace:uncCoercion".into(),
                    "XML part declares namespace or schemaLocation with remote UNC path enabling NTLM credential coercion".into(),
                ));
            }
        }

        if s_lower.contains("<!doctype") || s_lower.contains("<!entity") {
            results.push((
                "Critical",
                entry_name.to_string(),
                "namespace:xxeInjection".into(),
                "XML part contains Document Type Definition (DTD) or external entity declaration (XXE injection vector)".into(),
            ));
        }

        if s_lossy.contains("schemas.") {
            let mut search_idx = 0;
            while let Some(pos) = s_lossy[search_idx..].find("xmlns") {
                let start = search_idx + pos;
                search_idx = start + 5;
                if let Some(quote_start) = s_lossy[start..]
                    .find('"')
                    .or_else(|| s_lossy[start..].find('\''))
                {
                    let q_char = s_lossy.as_bytes()[start + quote_start];
                    let uri_start = start + quote_start + 1;
                    if let Some(quote_end) = s_lossy[uri_start..].find(q_char as char) {
                        let uri_str = &s_lossy[uri_start..uri_start + quote_end];
                        let has_spoofed_keyword =
                            uri_str.to_ascii_lowercase().contains("openxmlformats")
                                || uri_str.to_ascii_lowercase().contains("microsoft.com")
                                || uri_str
                                    .to_ascii_lowercase()
                                    .contains("schemas-microsoft-com");
                        let has_non_ascii = !uri_str.is_ascii();
                        let has_zero_width = uri_str.chars().any(|c| {
                            c == '\u{200B}' || c == '\u{FEFF}' || c == '\u{200C}' || c == '\u{200D}'
                        });
                        if (has_spoofed_keyword && has_non_ascii) || has_zero_width {
                            results.push((
                                "Critical",
                                entry_name.to_string(),
                                "namespace:homoglyphCloaking".into(),
                                format!("XML namespace URI '{uri_str}' uses Unicode homoglyph or zero-width character cloaking to spoof standard Office schemas"),
                            ));
                            break;
                        }
                    }
                }
            }
        }

        results
    }

    fn scan_slicer_timeline_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let name_lower = entry_name.to_ascii_lowercase();
        let is_slicer_or_timeline =
            name_lower.contains("slicer") || name_lower.contains("timeline");

        if !is_slicer_or_timeline {
            return results;
        }

        if name_lower.ends_with(".rels") {
            let mut pos = 0;
            while let Some(idx) = data[pos..]
                .windows(8)
                .position(|w| w.eq_ignore_ascii_case(b"<relatio"))
            {
                let rel_start = pos + idx;
                pos = rel_start + 8;
                let rel_end = match data[rel_start..]
                    .windows(2)
                    .position(|w| w == b"/>" || w == b"\">")
                {
                    Some(p) => rel_start + p + 2,
                    None => break,
                };
                let rel_bytes = &data[rel_start..rel_end];
                let rel_str = String::from_utf8_lossy(rel_bytes);
                let target = extract_attribute_value(&rel_str, "Target").unwrap_or_default();
                let target_mode =
                    extract_attribute_value(&rel_str, "TargetMode").unwrap_or_default();

                if !target.is_empty() {
                    let t_lower = target.to_ascii_lowercase();
                    let is_external = target_mode.eq_ignore_ascii_case("External")
                        || t_lower.starts_with("http:")
                        || t_lower.starts_with("https:")
                        || t_lower.starts_with(r"\\")
                        || t_lower.starts_with("//");

                    if is_external {
                        if t_lower.starts_with(r"\\") || t_lower.starts_with("//") {
                            results.push((
                                "High",
                                target.clone(),
                                "slicer:uncPath".into(),
                                format!("Slicer / Timeline relationship references remote UNC path '{target}' (NTLM coercion vector)"),
                            ));
                        } else if t_lower.starts_with("ms-msdt:")
                            || t_lower.starts_with("search-ms:")
                            || t_lower.starts_with("mhtml:")
                            || t_lower.starts_with("javascript:")
                            || t_lower.starts_with("powershell:")
                        {
                            results.push((
                                "Critical",
                                target.clone(),
                                "slicer:dangerousProtocol".into(),
                                format!("Slicer / Timeline relationship references dangerous exploit URI scheme '{target}'"),
                            ));
                        } else if [".exe", ".dll", ".hta", ".ps1", ".bat", ".cmd", ".vbs"]
                            .iter()
                            .any(|ext| t_lower.ends_with(ext))
                        {
                            results.push((
                                "Critical",
                                target.clone(),
                                "slicer:executableTarget".into(),
                                format!("Slicer / Timeline relationship targets executable or script payload '{target}'"),
                            ));
                        } else {
                            results.push((
                                "High",
                                target.clone(),
                                "slicer:externalTarget".into(),
                                format!("Slicer / Timeline relationship targets external remote data source '{target}'"),
                            ));
                        }
                    }
                }
            }
        } else if name_lower.ends_with(".xml") {
            let s = String::from_utf8_lossy(data);
            let s_lower = s.to_ascii_lowercase();

            // 1. Database command execution in Slicer / Timeline custom query or connection
            for cmd in &[
                "xp_cmdshell",
                "sp_oacreate",
                "openrowset",
                "bulk insert",
                "exec(",
                "exec master",
            ] {
                if s_lower.contains(cmd) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "slicer:commandExecution".into(),
                        format!("Slicer / Timeline definition contains database shell execution command '{cmd}'"),
                    ));
                    break;
                }
            }

            // 2. UNC source workbook or external connection
            if s_lower.contains(r"sourceworkbook=\\")
                || s_lower.contains("sourceworkbook=//")
                || s_lower.contains(r#"sourceworkbook="\\"#)
                || s_lower.contains(r#"connection="\\"#)
            {
                results.push((
                    "High",
                    entry_name.to_string(),
                    "slicer:uncConnection".into(),
                    "Slicer / Timeline definition contains external UNC source workbook connection (NTLM coercion vector)".into(),
                ));
            }

            // 3. Environment variable exfiltration tokens
            for env_token in &["%username%", "%userdomain%", "%computername%"] {
                if s_lower.contains(env_token) {
                    results.push((
                        "High",
                        entry_name.to_string(),
                        "slicer:envExfiltration".into(),
                        format!("Slicer / Timeline definition contains environment variable exfiltration token '{env_token}'"),
                    ));
                    break;
                }
            }
        }

        results
    }

    fn scan_bibliography_citation_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let name_lower = entry_name.to_ascii_lowercase();
        let s_lossy = String::from_utf8_lossy(data);
        let s_lower = s_lossy.to_ascii_lowercase();

        let is_bib_candidate = name_lower.contains("bibliography")
            || name_lower.contains("sources.xml")
            || s_lower.contains("<b:sources")
            || s_lower.contains("<b:source");

        if !is_bib_candidate {
            return results;
        }

        // 1. Remote UNC paths for NTLM coercion
        if s_lower.contains(r"\\") || s_lower.contains("<b:url>") {
            let mut search_idx = 0;
            while let Some(pos) = s_lower[search_idx..].find(r"\\") {
                let actual = search_idx + pos;
                let rem = &s_lower[actual + 2..];
                if let Some(first_char) = rem.chars().next()
                    && (first_char.is_ascii_alphanumeric()
                        || first_char == '.'
                        || first_char == '[')
                    && rem.contains('\\')
                {
                    results.push((
                        "High",
                        entry_name.to_string(),
                        "bib:uncCoercion".into(),
                        "Bibliography citation contains remote UNC path enabling NTLM credential coercion".into(),
                    ));
                    break;
                }
                search_idx = actual + 2;
            }
        }

        // 2. Exploit protocol handlers in citation fields
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "ms-appinstaller:",
            "mhtml:",
            "javascript:",
            "powershell:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    format!("bib:protocolHandler:{}", proto.trim_end_matches(':')),
                    format!("Bibliography citation contains dangerous exploit protocol handler '{proto}'"),
                ));
                break;
            }
        }

        // 3. Shell execution commands
        for cmd in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "bib:shellCommand".into(),
                    format!("Bibliography citation contains shell execution command '{cmd}'"),
                ));
                break;
            }
        }

        // 4. Smuggled Base64 PE binary in citation
        if s_lossy.contains("TVqQ") || s_lower.contains("this program cannot be run in dos mode") {
            results.push((
                "Critical",
                entry_name.to_string(),
                "bib:smuggledBinary".into(),
                "Bibliography citation contains smuggled Windows PE executable binary".into(),
            ));
        }

        results
    }

    fn scan_custom_xml_databinding_xpath_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lossy = String::from_utf8_lossy(data);
        let s_lower = s_lossy.to_ascii_lowercase();

        let is_databinding_candidate = s_lower.contains("databinding")
            || s_lower.contains("xpath=")
            || s_lower.contains("storeitemid");

        if !is_databinding_candidate {
            return results;
        }

        // 1. XPath SSRF / External document entity injection (e.g. document('http://...'), document('\\host\share...'), doc('...'))
        if s_lower.contains("document(") || s_lower.contains("doc(") {
            let sev = if s_lower.contains(r"\\")
                || s_lower.contains("http://")
                || s_lower.contains("https://")
            {
                "Critical"
            } else {
                "High"
            };
            results.push((
                sev,
                entry_name.to_string(),
                "xpath:ssrfInjection".into(),
                "Custom XML data binding XPath query invokes external document resolution function (SSRF or NTLM coercion vector)".into(),
            ));
        }

        // 2. Command injection or database execution in XPath
        for cmd in &[
            "xp_cmdshell",
            "sp_oacreate",
            "openrowset",
            "exec(",
            "powershell",
            "cmd.exe",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "xpath:commandInjection".into(),
                    format!("Custom XML data binding XPath expression contains shell execution command '{cmd}'"),
                ));
                break;
            }
        }

        // 3. Remote UNC paths or exploit protocols in prefixMappings or storeItemID
        if (s_lower.contains("prefixmappings") || s_lower.contains("storeitemid"))
            && (s_lower.contains(r"\\") || s_lower.contains("//"))
        {
            let mut search_idx = 0;
            while let Some(pos) = s_lower[search_idx..].find(r"\\") {
                let actual = search_idx + pos;
                let rem = &s_lower[actual + 2..];
                if let Some(first_char) = rem.chars().next()
                    && (first_char.is_ascii_alphanumeric()
                        || first_char == '.'
                        || first_char == '[')
                    && rem.contains('\\')
                {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "xpath:uncNamespaceMapping".into(),
                        "Custom XML data binding prefixMappings contains remote UNC namespace declaration enabling NTLM credential theft".into(),
                    ));
                    break;
                }
                search_idx = actual + 2;
            }
        }

        for proto in &["ms-msdt:", "search-ms:", "ms-appinstaller:", "mhtml:"] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    format!("xpath:protocolHandler:{}", proto.trim_end_matches(':')),
                    format!("Custom XML data binding contains exploit protocol handler '{proto}'"),
                ));
                break;
            }
        }

        results
    }

    fn scan_xmlmaps_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lossy = String::from_utf8_lossy(data);
        let s_lower = s_lossy.to_ascii_lowercase();

        // 1. Remote UNC paths in SchemaRef, schemaLocation, targetNamespace, RootElement, or table column XPath
        if s_lower.contains(r"\\") {
            let mut search_idx = 0;
            while let Some(pos) = s_lower[search_idx..].find(r"\\") {
                let actual = search_idx + pos;
                let rem = &s_lower[actual + 2..];
                if let Some(first_char) = rem.chars().next()
                    && (first_char.is_ascii_alphanumeric()
                        || first_char == '.'
                        || first_char == '[')
                    && rem.contains('\\')
                {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "xmlMap:uncPath".into(),
                        "Excel XML Map or Table definition contains remote UNC path enabling NTLM credential coercion".into(),
                    ));
                    break;
                }
                search_idx = actual + 2;
            }
        }

        // 2. Dangerous exploit URI schemes / protocols
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "ms-appinstaller:",
            "mhtml:",
            "javascript:",
            "powershell:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    format!("xmlMap:dangerousProtocol:{}", proto.trim_end_matches(':')),
                    format!("Excel XML Map or Table definition contains dangerous exploit URI scheme '{proto}'"),
                ));
                break;
            }
        }

        // 3. XXE / DTD entity declarations in embedded schema
        if s_lower.contains("<!doctype") || s_lower.contains("<!entity") {
            results.push((
                "Critical",
                entry_name.to_string(),
                "xmlMap:xxeDtdDeclaration".into(),
                "Excel XML Map embedded schema contains DTD or XML entity declaration enabling XXE injection".into(),
            ));
        }

        // 4. Smuggled Base64 PE binary or shell commands in schema annotation / documentation
        if s_lossy.contains("TVqQ") || s_lower.contains("this program cannot be run in dos mode") {
            results.push((
                "Critical",
                entry_name.to_string(),
                "xmlMap:smuggledBinary".into(),
                "Excel XML Map contains smuggled Windows PE executable binary".into(),
            ));
        }

        for cmd in &[
            "xp_cmdshell",
            "sp_oacreate",
            "openrowset",
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "xmlMap:commandExecution".into(),
                    format!("Excel XML Map or Table column binding contains shell execution command '{cmd}'"),
                ));
                break;
            }
        }

        // 5. Table column XML bindings with XPath external document resolution
        if (s_lower.contains("document(") || s_lower.contains("doc("))
            && (s_lower.contains("xpath=") || s_lower.contains("xmlcolumnpr"))
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "xmlMap:xpathSsrf".into(),
                "Excel Table XML column binding contains XPath external document resolution function (SSRF or NTLM coercion vector)".into(),
            ));
        }

        // 6. External relationship targets in xmlMaps/tables .rels
        if entry_name.contains("_rels") && s_lower.contains("targetmode=\"external\"") {
            let mut search_idx = 0;
            while let Some(pos) = s_lower[search_idx..].find("target=\"") {
                let actual = search_idx + pos + 8;
                if let Some(end_quote) = s_lower[actual..].find('"') {
                    let target = &s_lossy[actual..actual + end_quote];
                    let t_lower = target.to_ascii_lowercase();
                    if t_lower.starts_with(r"\\") {
                        results.push((
                            "Critical",
                            target.to_string(),
                            "xmlMap:uncRelationship".into(),
                            format!("Excel XML Map relationship references remote UNC path '{target}' (NTLM coercion vector)"),
                        ));
                        break;
                    }
                    if t_lower.ends_with(".exe")
                        || t_lower.ends_with(".bat")
                        || t_lower.ends_with(".vbs")
                        || t_lower.ends_with(".ps1")
                        || t_lower.ends_with(".hta")
                    {
                        results.push((
                            "Critical",
                            target.to_string(),
                            "xmlMap:executableRelationship".into(),
                            format!("Excel XML Map relationship references executable or script payload '{target}'"),
                        ));
                        break;
                    }
                }
                search_idx = actual;
            }
        }

        results
    }

    fn scan_comment_annotation_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lossy = String::from_utf8_lossy(data);
        let s_lower = s_lossy.to_ascii_lowercase();

        // 1. Remote UNC paths in comments (NTLM coercion)
        if s_lower.contains(r"\\") {
            let mut search_idx = 0;
            while let Some(pos) = s_lower[search_idx..].find(r"\\") {
                let actual = search_idx + pos;
                let rem = &s_lower[actual + 2..];
                if let Some(first_char) = rem.chars().next()
                    && (first_char.is_ascii_alphanumeric()
                        || first_char == '.'
                        || first_char == '[')
                    && rem.contains('\\')
                {
                    results.push((
                        "High",
                        entry_name.to_string(),
                        "comment:uncPath".into(),
                        "Document comment or modern annotation contains remote UNC path enabling NTLM credential coercion".into(),
                    ));
                    break;
                }
                search_idx = actual + 2;
            }
        }

        // 2. Exploit protocols in comments or comment relationships
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "ms-appinstaller:",
            "mhtml:",
            "javascript:",
            "powershell:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    format!("comment:dangerousProtocol:{}", proto.trim_end_matches(':')),
                    format!("Document comment or relationship references dangerous exploit URI scheme '{proto}'"),
                ));
                break;
            }
        }

        // 3. Smuggled Base64 PE binary in comments
        if s_lossy.contains("TVqQ") || s_lower.contains("this program cannot be run in dos mode") {
            results.push((
                "Critical",
                entry_name.to_string(),
                "comment:smuggledBinary".into(),
                "Document comment contains smuggled Windows PE executable binary".into(),
            ));
        }

        // 4. Shell execution commands in comments
        for cmd in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
            "bitsadmin",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "comment:shellCommand".into(),
                    format!("Document comment contains shell execution command '{cmd}'"),
                ));
                break;
            }
        }

        // 5. Executable or script targets in comment relationship files
        if entry_name.contains("_rels") && s_lower.contains("targetmode=\"external\"") {
            let mut search_idx = 0;
            while let Some(pos) = s_lower[search_idx..].find("target=\"") {
                let actual = search_idx + pos + 8;
                if let Some(end_quote) = s_lower[actual..].find('"') {
                    let target = &s_lossy[actual..actual + end_quote];
                    let t_lower = target.to_ascii_lowercase();
                    if t_lower.starts_with(r"\\") {
                        results.push((
                            "High",
                            target.to_string(),
                            "comment:uncRelationship".into(),
                            format!("Comment relationship references remote UNC path '{target}' (NTLM coercion vector)"),
                        ));
                        break;
                    }
                    if t_lower.ends_with(".exe")
                        || t_lower.ends_with(".bat")
                        || t_lower.ends_with(".vbs")
                        || t_lower.ends_with(".ps1")
                        || t_lower.ends_with(".hta")
                        || t_lower.ends_with(".lnk")
                    {
                        results.push((
                            "Critical",
                            target.to_string(),
                            "comment:executableRelationship".into(),
                            format!("Comment relationship references executable or script payload '{target}'"),
                        ));
                        break;
                    }
                }
                search_idx = actual;
            }
        }

        results
    }

    fn scan_theme_font_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lossy = String::from_utf8_lossy(data);
        let s_lower = s_lossy.to_ascii_lowercase();

        // 1. Remote UNC paths in theme typeface declarations (NTLM coercion / DirectWrite exploit vector)
        if (s_lower.contains("typeface=\"\\\\")
            || s_lower.contains("typeface='\\\\")
            || s_lower.contains("typeface=\"//")
            || s_lower.contains("typeface='//"))
            || (s_lower.contains("typeface=") && s_lower.contains(r"\\"))
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "theme:uncTypeface".into(),
                "Office theme declares font typeface with remote UNC path enabling NTLM credential coercion or font engine exploitation".into(),
            ));
        }

        // 2. Dangerous exploit URI schemes / protocols in themes
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "ms-appinstaller:",
            "mhtml:",
            "javascript:",
            "powershell:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    format!("theme:dangerousProtocol:{}", proto.trim_end_matches(':')),
                    format!("Office theme or relationship references dangerous exploit URI scheme '{proto}'"),
                ));
                break;
            }
        }

        // 3. External theme relationships linking to remote HTTP/HTTPS/SMB target URLs
        if entry_name.contains("_rels") && s_lower.contains("targetmode=\"external\"") {
            let mut search_idx = 0;
            while let Some(pos) = s_lower[search_idx..].find("target=\"") {
                let actual = search_idx + pos + 8;
                if let Some(end_quote) = s_lower[actual..].find('"') {
                    let target = &s_lossy[actual..actual + end_quote];
                    let t_lower = target.to_ascii_lowercase();
                    if t_lower.starts_with(r"\\") {
                        results.push((
                            "Critical",
                            target.to_string(),
                            "theme:uncRelationship".into(),
                            format!("Theme relationship references remote UNC path '{target}' (NTLM coercion vector)"),
                        ));
                        break;
                    }
                    if t_lower.starts_with("http://") || t_lower.starts_with("https://") {
                        results.push((
                            "Critical",
                            target.to_string(),
                            "theme:remoteTemplateInjection".into(),
                            format!("Theme relationship references external remote template or theme '{target}'"),
                        ));
                        break;
                    }
                    if t_lower.ends_with(".exe")
                        || t_lower.ends_with(".bat")
                        || t_lower.ends_with(".vbs")
                        || t_lower.ends_with(".ps1")
                        || t_lower.ends_with(".hta")
                    {
                        results.push((
                            "Critical",
                            target.to_string(),
                            "theme:executableRelationship".into(),
                            format!("Theme relationship references executable or script payload '{target}'"),
                        ));
                        break;
                    }
                }
                search_idx = actual;
            }
        }

        // 4. Smuggled Base64 PE binary or shell commands in theme
        if s_lossy.contains("TVqQ") || s_lower.contains("this program cannot be run in dos mode") {
            results.push((
                "Critical",
                entry_name.to_string(),
                "theme:smuggledBinary".into(),
                "Office theme contains smuggled Windows PE executable binary".into(),
            ));
        }

        for cmd in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "theme:shellCommand".into(),
                    format!("Office theme contains shell execution command '{cmd}'"),
                ));
                break;
            }
        }

        results
    }

    fn scan_customxml_properties_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lossy = String::from_utf8_lossy(data);
        let s_lower = s_lossy.to_ascii_lowercase();

        // 1. Remote UNC paths in custom XML itemProps or schema definitions (NTLM coercion)
        if (s_lower.contains("ds:uri=\"\\\\")
            || s_lower.contains("ds:uri='\\\\")
            || s_lower.contains("ds:uri=\"//")
            || s_lower.contains("ds:uri='//"))
            || (s_lower.contains("schemaref") && s_lower.contains(r"\\"))
            || (s_lower.contains("targetnamespace") && s_lower.contains(r"\\"))
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "customXmlProp:uncSchema".into(),
                "Custom XML item properties or schema references remote UNC path enabling NTLM credential coercion".into(),
            ));
        }

        // 2. Dangerous exploit URI schemes / protocols in custom XML properties
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "ms-appinstaller:",
            "mhtml:",
            "javascript:",
            "powershell:",
            "vbscript:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    format!(
                        "customXmlProp:dangerousProtocol:{}",
                        proto.trim_end_matches(':')
                    ),
                    format!(
                        "Custom XML properties references dangerous exploit URI scheme '{proto}'"
                    ),
                ));
                break;
            }
        }

        // 3. External relationships in customXml/_rels/*.rels
        if entry_name.contains("_rels") && s_lower.contains("targetmode=\"external\"") {
            let mut search_idx = 0;
            while let Some(pos) = s_lower[search_idx..].find("target=\"") {
                let actual = search_idx + pos + 8;
                if let Some(end_quote) = s_lower[actual..].find('"') {
                    let target = &s_lossy[actual..actual + end_quote];
                    let t_lower = target.to_ascii_lowercase();
                    if t_lower.starts_with(r"\\") {
                        results.push((
                            "Critical",
                            target.to_string(),
                            "customXmlProp:uncRelationship".into(),
                            format!("Custom XML relationship references remote UNC path '{target}' (NTLM coercion vector)"),
                        ));
                        break;
                    }
                    if t_lower.starts_with("http://") || t_lower.starts_with("https://") {
                        results.push((
                            "High",
                            target.to_string(),
                            "customXmlProp:remoteTemplateInjection".into(),
                            format!("Custom XML relationship references remote target '{target}'"),
                        ));
                        break;
                    }
                    if t_lower.ends_with(".exe")
                        || t_lower.ends_with(".bat")
                        || t_lower.ends_with(".vbs")
                        || t_lower.ends_with(".ps1")
                        || t_lower.ends_with(".hta")
                        || t_lower.ends_with(".lnk")
                    {
                        results.push((
                            "Critical",
                            target.to_string(),
                            "customXmlProp:executableRelationship".into(),
                            format!("Custom XML relationship references executable or script payload '{target}'"),
                        ));
                        break;
                    }
                }
                search_idx = actual;
            }
        }

        // 4. Smuggled Base64 PE binary or shell commands in custom XML properties
        if s_lossy.contains("TVqQ") || s_lower.contains("this program cannot be run in dos mode") {
            results.push((
                "Critical",
                entry_name.to_string(),
                "customXmlProp:smuggledBinary".into(),
                "Custom XML properties contains smuggled Windows PE executable binary".into(),
            ));
        }

        for cmd in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "customXmlProp:shellCommand".into(),
                    format!("Custom XML properties contains shell execution command '{cmd}'"),
                ));
                break;
            }
        }

        results
    }

    fn scan_vbaproject_rels_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lossy = String::from_utf8_lossy(data);
        let s_lower = s_lossy.to_ascii_lowercase();

        // 1. External relationships in vbaProject.bin.rels or vbaProjectSignature*.bin.rels
        if entry_name.contains("_rels") && s_lower.contains("targetmode=\"external\"") {
            let mut search_idx = 0;
            while let Some(pos) = s_lower[search_idx..].find("target=\"") {
                let actual = search_idx + pos + 8;
                if let Some(end_quote) = s_lower[actual..].find('"') {
                    let target = &s_lossy[actual..actual + end_quote];
                    let t_lower = target.to_ascii_lowercase();
                    if t_lower.starts_with(r"\\") {
                        results.push((
                            "Critical",
                            target.to_string(),
                            "vbaRels:uncRelationship".into(),
                            format!("VBA project relationship references remote UNC path '{target}' enabling NTLM credential coercion"),
                        ));
                        break;
                    }
                    if t_lower.starts_with("http://") || t_lower.starts_with("https://") {
                        results.push((
                            "Critical",
                            target.to_string(),
                            "vbaRels:remoteProjectLink".into(),
                            format!("VBA project relationship references remote payload or project binary '{target}'"),
                        ));
                        break;
                    }
                    if t_lower.ends_with(".exe")
                        || t_lower.ends_with(".dll")
                        || t_lower.ends_with(".bin")
                        || t_lower.ends_with(".bat")
                        || t_lower.ends_with(".vbs")
                        || t_lower.ends_with(".ps1")
                        || t_lower.ends_with(".hta")
                        || t_lower.ends_with(".ocx")
                    {
                        results.push((
                            "Critical",
                            target.to_string(),
                            "vbaRels:executableTarget".into(),
                            format!("VBA project relationship references executable or binary component '{target}'"),
                        ));
                        break;
                    }
                }
                search_idx = actual;
            }
        }

        // 2. Dangerous URI schemes in vbaProject rels or vbaData
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "ms-appinstaller:",
            "mhtml:",
            "powershell:",
            "javascript:",
            "vbscript:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    format!("vbaRels:dangerousProtocol:{}", proto.trim_end_matches(':')),
                    format!("VBA project relationship or data part references dangerous exploit URI scheme '{proto}'"),
                ));
                break;
            }
        }

        // 3. Smuggled PE binary or shell commands in vbaData.xml
        if s_lossy.contains("TVqQ") || s_lower.contains("this program cannot be run in dos mode") {
            results.push((
                "Critical",
                entry_name.to_string(),
                "vbaData:smuggledBinary".into(),
                "VBA project data part contains smuggled Windows PE executable binary".into(),
            ));
        }

        for cmd in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "vbaData:shellCommand".into(),
                    format!("VBA project data part contains shell execution command '{cmd}'"),
                ));
                break;
            }
        }

        results
    }

    fn scan_word_glossary_rels_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lossy = String::from_utf8_lossy(data);
        let s_lower = s_lossy.to_ascii_lowercase();

        // 1. Remote UNC paths in glossary XML markup or relationships
        if s_lower.contains("target=\"\\\\")
            || s_lower.contains("target='\\\\")
            || s_lower.contains("target=\"//")
            || s_lower.contains("target='//")
            || (s_lower.contains(r"\\")
                && (s_lower.contains("attachedtemplate")
                    || s_lower.contains("hyperlink")
                    || s_lower.contains("docpart")))
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "glossaryRels:uncPath".into(),
                "Word glossary or building blocks part references remote UNC path enabling NTLM credential coercion".into(),
            ));
        }

        // 2. Remote template injection in glossary settings
        if s_lower.contains("attachedtemplate")
            && (s_lower.contains("http://") || s_lower.contains("https://"))
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "glossaryRels:remoteTemplateInjection".into(),
                "Word glossary settings references remote external template (template injection vector)".into(),
            ));
        }

        // 3. Dangerous exploit URI schemes in glossary relationships or hyperlinks
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "ms-appinstaller:",
            "mhtml:",
            "powershell:",
            "javascript:",
            "vbscript:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    format!("glossaryRels:dangerousProtocol:{}", proto.trim_end_matches(':')),
                    format!("Word glossary or building blocks references dangerous exploit URI scheme '{proto}'"),
                ));
                break;
            }
        }

        // 4. External relationships in glossary _rels targeting executable/script files
        if entry_name.contains("_rels") && s_lower.contains("targetmode=\"external\"") {
            let mut search_idx = 0;
            while let Some(pos) = s_lower[search_idx..].find("target=\"") {
                let actual = search_idx + pos + 8;
                if let Some(end_quote) = s_lower[actual..].find('"') {
                    let target = &s_lossy[actual..actual + end_quote];
                    let t_lower = target.to_ascii_lowercase();
                    if t_lower.ends_with(".exe")
                        || t_lower.ends_with(".bat")
                        || t_lower.ends_with(".vbs")
                        || t_lower.ends_with(".ps1")
                        || t_lower.ends_with(".hta")
                        || t_lower.ends_with(".lnk")
                    {
                        results.push((
                            "Critical",
                            target.to_string(),
                            "glossaryRels:executableRelationship".into(),
                            format!("Word glossary relationship references executable or script payload '{target}'"),
                        ));
                        break;
                    }
                }
                search_idx = actual;
            }
        }

        // 5. Smuggled Base64 PE binary or shell commands in glossary definitions
        if s_lossy.contains("TVqQ") || s_lower.contains("this program cannot be run in dos mode") {
            results.push((
                "Critical",
                entry_name.to_string(),
                "glossaryRels:smuggledBinary".into(),
                "Word glossary or building blocks part contains smuggled Windows PE executable binary".into(),
            ));
        }

        for cmd in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "glossaryRels:shellCommand".into(),
                    format!("Word glossary or building blocks part contains shell execution command '{cmd}'"),
                ));
                break;
            }
        }

        results
    }

    fn scan_word_docvars_and_notes_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lossy = String::from_utf8_lossy(data);
        let s_lower = s_lossy.to_ascii_lowercase();

        // 1. Document Variables in word/settings.xml (<w:docVars><w:docVar w:name="..." w:val="..."/></w:docVars>)
        if s_lower.contains("docvar") {
            let mut search_idx = 0;
            while let Some(pos) = s_lower[search_idx..].find("<w:docvar") {
                let actual = search_idx + pos;
                let end_tag = s_lower[actual..]
                    .find('>')
                    .map(|p| actual + p)
                    .unwrap_or(s_lower.len());
                let tag_str = &s_lossy[actual..end_tag];
                let tag_lower = tag_str.to_ascii_lowercase();

                // Check for smuggled PE binaries in docVar value
                if tag_str.contains("TVqQ")
                    || tag_lower.contains("this program cannot be run in dos mode")
                {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "docVars:smuggledBinary".into(),
                        "Word document variable contains smuggled Windows PE executable binary"
                            .into(),
                    ));
                }

                // Check for shell execution commands in docVar
                for cmd in &[
                    "powershell",
                    "cmd.exe",
                    "wscript.exe",
                    "cscript.exe",
                    "mshta",
                    "rundll32",
                    "certutil",
                ] {
                    if tag_lower.contains(cmd) {
                        results.push((
                            "Critical",
                            entry_name.to_string(),
                            "docVars:shellCommand".into(),
                            format!(
                                "Word document variable contains shell execution command '{cmd}'"
                            ),
                        ));
                        break;
                    }
                }

                // Check for dangerous URI schemes or remote UNC paths in docVar
                for proto in &[
                    "ms-msdt:",
                    "search-ms:",
                    "ms-appinstaller:",
                    "mhtml:",
                    "powershell:",
                    "javascript:",
                    "vbscript:",
                ] {
                    if tag_lower.contains(proto) {
                        results.push((
                            "Critical",
                            entry_name.to_string(),
                            format!("docVars:dangerousProtocol:{}", proto.trim_end_matches(':')),
                            format!(
                                "Word document variable references dangerous exploit URI scheme '{proto}'"
                            ),
                        ));
                        break;
                    }
                }

                if tag_lower.contains("w:val=\"\\\\")
                    || tag_lower.contains("w:val='\\\\")
                    || tag_lower.contains("w:val=\"//")
                    || tag_lower.contains("w:val='//")
                {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "docVars:uncPath".into(),
                        "Word document variable contains remote UNC path enabling NTLM credential coercion".into(),
                    ));
                }

                search_idx = end_tag;
            }
        }

        // 2. Footnotes and Endnotes external relationships or UNC references
        if entry_name.contains("footnote") || entry_name.contains("endnote") {
            if entry_name.contains("_rels") && s_lower.contains("targetmode=\"external\"") {
                let mut search_idx = 0;
                while let Some(pos) = s_lower[search_idx..].find("target=\"") {
                    let actual = search_idx + pos + 8;
                    if let Some(end_quote) = s_lower[actual..].find('"') {
                        let target = &s_lossy[actual..actual + end_quote];
                        let t_lower = target.to_ascii_lowercase();
                        if t_lower.starts_with(r"\\") || t_lower.starts_with("//") {
                            results.push((
                                "Critical",
                                target.to_string(),
                                "notesRels:uncRelationship".into(),
                                format!("Word footnotes/endnotes relationship references remote UNC path '{target}' (NTLM coercion vector)"),
                            ));
                            break;
                        }
                        if t_lower.ends_with(".exe")
                            || t_lower.ends_with(".bat")
                            || t_lower.ends_with(".vbs")
                            || t_lower.ends_with(".ps1")
                            || t_lower.ends_with(".hta")
                            || t_lower.ends_with(".lnk")
                        {
                            results.push((
                                "Critical",
                                target.to_string(),
                                "notesRels:executableRelationship".into(),
                                format!("Word footnotes/endnotes relationship references executable payload '{target}'"),
                            ));
                            break;
                        }
                    }
                    search_idx = actual;
                }
            }

            if s_lossy.contains("TVqQ")
                || s_lower.contains("this program cannot be run in dos mode")
            {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "notes:smuggledBinary".into(),
                    "Word footnotes or endnotes part contains smuggled Windows PE executable binary"
                        .into(),
                ));
            }

            for cmd in &[
                "powershell",
                "cmd.exe",
                "wscript.exe",
                "cscript.exe",
                "mshta",
                "rundll32",
                "certutil",
            ] {
                if s_lower.contains(cmd) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "notes:shellCommand".into(),
                        format!(
                            "Word footnotes or endnotes part contains shell execution command '{cmd}'"
                        ),
                    ));
                    break;
                }
            }
        }

        results
    }

    fn scan_powerpoint_tags_and_masters_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lossy = String::from_utf8_lossy(data);
        let s_lower = s_lossy.to_ascii_lowercase();

        // 1. PowerPoint Programmable Tags (ppt/tags/tag*.xml)
        if entry_name.contains("ppt/tags")
            || s_lower.contains("<p:tag")
            || s_lower.contains("taglst")
        {
            if s_lossy.contains("TVqQ")
                || s_lower.contains("this program cannot be run in dos mode")
            {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "pptTags:smuggledBinary".into(),
                    "PowerPoint programmable tag part contains smuggled Windows PE executable binary"
                        .into(),
                ));
            }

            for cmd in &[
                "powershell",
                "cmd.exe",
                "wscript.exe",
                "cscript.exe",
                "mshta",
                "rundll32",
                "certutil",
            ] {
                if s_lower.contains(cmd) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "pptTags:shellCommand".into(),
                        format!(
                            "PowerPoint programmable tag contains shell execution command '{cmd}'"
                        ),
                    ));
                    break;
                }
            }

            for proto in &[
                "ms-msdt:",
                "search-ms:",
                "ms-appinstaller:",
                "mhtml:",
                "powershell:",
                "javascript:",
                "vbscript:",
            ] {
                if s_lower.contains(proto) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        format!("pptTags:dangerousProtocol:{}", proto.trim_end_matches(':')),
                        format!(
                            "PowerPoint programmable tag references dangerous exploit URI scheme '{proto}'"
                        ),
                    ));
                    break;
                }
            }

            if s_lower.contains("val=\"\\\\")
                || s_lower.contains("val='\\\\")
                || s_lower.contains("val=\"//")
                || s_lower.contains("val='//")
            {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "pptTags:uncPath".into(),
                    "PowerPoint programmable tag contains remote UNC path enabling NTLM credential coercion".into(),
                ));
            }
        }

        // 2. PowerPoint Presentation Relationships or Master relationships (external templates/links)
        if (entry_name.contains("ppt/_rels")
            || entry_name.contains("handoutmaster")
            || entry_name.contains("notesmaster"))
            && s_lower.contains("targetmode=\"external\"")
        {
            let mut search_idx = 0;
            while let Some(pos) = s_lower[search_idx..].find("target=\"") {
                let actual = search_idx + pos + 8;
                if let Some(end_quote) = s_lower[actual..].find('"') {
                    let target = &s_lossy[actual..actual + end_quote];
                    let t_lower = target.to_ascii_lowercase();
                    if t_lower.starts_with(r"\\") || t_lower.starts_with("//") {
                        results.push((
                            "Critical",
                            target.to_string(),
                            "pptRels:uncRelationship".into(),
                            format!("PowerPoint presentation relationship references remote UNC path '{target}' (NTLM coercion vector)"),
                        ));
                        break;
                    }
                    if t_lower.ends_with(".potm")
                        || t_lower.ends_with(".pptm")
                        || t_lower.ends_with(".dotm")
                        || t_lower.ends_with(".exe")
                        || t_lower.ends_with(".bat")
                        || t_lower.ends_with(".vbs")
                        || t_lower.ends_with(".ps1")
                        || t_lower.ends_with(".hta")
                    {
                        results.push((
                            "Critical",
                            target.to_string(),
                            "pptRels:remoteTemplateOrExecutable".into(),
                            format!("PowerPoint relationship references remote external template or executable '{target}'"),
                        ));
                        break;
                    }
                }
                search_idx = actual;
            }
        }

        // 3. PowerPoint Font Table remote UNC typeface
        if entry_name.contains("fonttable")
            && s_lower.contains(r"\\")
            && (s_lower.contains("typeface=\"\\\\")
                || s_lower.contains("typeface='\\\\")
                || s_lower.contains("typeface=\"//")
                || s_lower.contains("typeface='//"))
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "pptFont:uncTypeface".into(),
                "PowerPoint font table references remote UNC typeface enabling NTLM credential coercion".into(),
            ));
        }

        results
    }

    fn scan_scenario_manager_consolidation_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lower = String::from_utf8_lossy(data).to_ascii_lowercase();

        // 1. Scenario definitions in sheet*.xml (<scenarios>) or xl/scenarios/scenario*.xml
        if entry_name.contains("scenarios")
            || s_lower.contains("<scenarios")
            || s_lower.contains("<scenario")
        {
            // DDE execution strings in input cells
            if s_lower.contains("cmd|")
                || s_lower.contains("powershell|")
                || s_lower.contains("mshta|")
                || s_lower.contains("cscript|")
                || s_lower.contains("wscript|")
                || s_lower.contains("certutil|")
            {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "scenario:ddeExecution".into(),
                    "Excel Scenario Manager contains cloaked DDE execution command in scenario input cells".into(),
                ));
            }

            // XLM macro execution functions
            if s_lower.contains("exec(")
                || s_lower.contains("call(")
                || s_lower.contains("register(")
                || s_lower.contains("run(")
            {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "scenario:xlmExecution".into(),
                    "Excel Scenario Manager contains Excel 4.0 (XLM) macro execution functions"
                        .into(),
                ));
            }

            // Shell execution commands
            if s_lower.contains("powershell.exe")
                || s_lower.contains("cmd.exe")
                || s_lower.contains("mshta.exe")
                || s_lower.contains("rundll32.exe")
                || s_lower.contains("cscript.exe")
                || s_lower.contains("wscript.exe")
            {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "scenario:shellExecution".into(),
                    "Excel Scenario Manager contains shell execution commands in scenario cells"
                        .into(),
                ));
            }

            // Smuggled PE binary
            if s_lower.contains("tvqqaa")
                || s_lower.contains("tvqaia")
                || (s_lower.contains("tvq") && s_lower.contains("aaaa"))
            {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "scenario:smuggledBinary".into(),
                    "Excel Scenario Manager contains smuggled Windows PE executable binary".into(),
                ));
            }
        }

        // 2. Data Consolidation references to remote UNC paths (<consolidation>)
        if (s_lower.contains("<consolidation") || entry_name.contains("consolidation"))
            && (s_lower.contains(r"[\\")
                || s_lower.contains("['\\\\")
                || s_lower.contains("[\"\\\\")
                || s_lower.contains("[//")
                || (s_lower.contains("source") && s_lower.contains(r"\\")))
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "consolidation:uncPath".into(),
                "Excel Data Consolidation references remote UNC workbook path enabling NTLM credential coercion".into(),
            ));
        }

        results
    }

    fn scan_powerpoint_animation_timenode_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lower = String::from_utf8_lossy(data).to_ascii_lowercase();

        // 1. Command execution animation nodes (<p:cmd>) in slide timing
        if s_lower.contains("<p:cmd") || s_lower.contains(":cmd") {
            for cmd in &[
                "powershell",
                "cmd.exe",
                "wscript",
                "cscript",
                "mshta",
                "rundll32",
                "certutil",
            ] {
                if s_lower.contains(cmd) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "animation:cmdCall".into(),
                        format!("PowerPoint animation timing node contains shell command '{cmd}' execution trigger"),
                    ));
                    break;
                }
            }
        }

        // 2. Media nodes or animation triggers with remote UNC or exploit protocols
        if (s_lower.contains("cmedianode")
            || s_lower.contains("<p:media")
            || s_lower.contains("<p:audio")
            || s_lower.contains("<p:video"))
            && (s_lower.contains(r"\\") || s_lower.contains("//"))
            && (s_lower.contains(r#"target="\\"#)
                || s_lower.contains(r#"target='\\"#)
                || s_lower.contains(r#"target="//"#)
                || s_lower.contains(r#"src="\\"#)
                || s_lower.contains(r#"src="//"#))
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "animation:uncMedia".into(),
                "PowerPoint animation media node references remote UNC path enabling NTLM credential coercion".into(),
            ));
        }

        for scheme in &[
            "ms-msdt:",
            "search-ms:",
            "ms-appinstaller:",
            "mhtml:",
            "powershell:",
            "vbscript:",
        ] {
            if s_lower.contains(scheme) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "animation:exploitProtocol".into(),
                    format!("PowerPoint animation media node references dangerous exploit URI scheme '{scheme}'"),
                ));
                break;
            }
        }

        // 3. Relationships of slides referencing remote UNC or executables
        if entry_name.ends_with(".rels") && entry_name.contains("slide") {
            let mut search_idx = 0;
            while let Some(target_pos) = s_lower[search_idx..].find("target=") {
                let actual = search_idx + target_pos + 7;
                if actual >= s_lower.len() {
                    break;
                }
                let quote = s_lower.as_bytes()[actual - 1];
                let end_pos = match s_lower[actual..].find(quote as char) {
                    Some(p) => actual + p,
                    None => s_lower.len(),
                };
                let target = &s_lower[actual..end_pos];
                if target.starts_with(r"\\") || target.starts_with("//") {
                    results.push((
                        "Critical",
                        target.to_string(),
                        "animation:uncMedia".into(),
                        format!("PowerPoint slide animation relationship references remote UNC path '{target}'"),
                    ));
                    break;
                }
                if target.ends_with(".exe")
                    || target.ends_with(".bat")
                    || target.ends_with(".vbs")
                    || target.ends_with(".ps1")
                    || target.ends_with(".hta")
                    || target.ends_with(".lnk")
                {
                    results.push((
                        "Critical",
                        target.to_string(),
                        "animation:executableMedia".into(),
                        format!("PowerPoint slide relationship targets executable or script payload '{target}'"),
                    ));
                    break;
                }
                search_idx = actual;
            }
        }

        // 4. Smuggled PE binary in animation or slide parts
        if s_lower.contains("tvqqaa")
            || s_lower.contains("tvqaia")
            || (s_lower.contains("tvq") && s_lower.contains("aaaa"))
            || s_lower.contains("this program cannot be run in dos mode")
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "animation:smuggledBinary".into(),
                "PowerPoint slide animation part contains smuggled Windows PE executable binary"
                    .into(),
            ));
        }

        results
    }

    fn scan_word_header_footer_watermark_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lower = String::from_utf8_lossy(data).to_ascii_lowercase();

        // 1. Remote UNC paths in header/footer relationships or VML/drawing images
        if (s_lower.contains(r"\\") || s_lower.contains("//"))
            && (s_lower.contains(r#"src="\\"#)
                || s_lower.contains(r#"src="//"#)
                || s_lower.contains(r#"target="\\"#)
                || s_lower.contains(r#"target="//"#)
                || (s_lower.contains("v:imagedata")
                    && (s_lower.contains(r"\\") || s_lower.contains("//"))))
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "headerFooter:uncReference".into(),
                "Word header, footer, or watermark references remote UNC path enabling NTLM credential coercion".into(),
            ));
        }

        // 2. Exploit URI schemes in header/footer
        for scheme in &[
            "ms-msdt:",
            "search-ms:",
            "ms-appinstaller:",
            "mhtml:",
            "javascript:",
            "powershell:",
            "vbscript:",
        ] {
            if s_lower.contains(scheme) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "headerFooter:exploitProtocol".into(),
                    format!("Word header/footer or watermark references dangerous exploit URI scheme '{scheme}'"),
                ));
                break;
            }
        }

        // 3. Header/footer relationship targeting executables or scripts
        if entry_name.ends_with(".rels") {
            let mut search_idx = 0;
            while let Some(target_pos) = s_lower[search_idx..].find("target=") {
                let actual = search_idx + target_pos + 7;
                if actual >= s_lower.len() {
                    break;
                }
                let quote = s_lower.as_bytes()[actual - 1];
                let end_pos = match s_lower[actual..].find(quote as char) {
                    Some(p) => actual + p,
                    None => s_lower.len(),
                };
                let target = &s_lower[actual..end_pos];
                if target.ends_with(".exe")
                    || target.ends_with(".bat")
                    || target.ends_with(".vbs")
                    || target.ends_with(".ps1")
                    || target.ends_with(".hta")
                    || target.ends_with(".lnk")
                {
                    results.push((
                        "Critical",
                        target.to_string(),
                        "headerFooter:executableTarget".into(),
                        format!("Word header/footer relationship references executable or script target '{target}'"),
                    ));
                    break;
                }
                search_idx = actual;
            }
        }

        // 4. Embedded shell commands in watermark shapes or text
        for cmd in &[
            "powershell.exe",
            "cmd.exe",
            "mshta.exe",
            "rundll32.exe",
            "cscript.exe",
            "wscript.exe",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "headerFooter:shellCommand".into(),
                    format!(
                        "Word header/footer or watermark contains shell execution command '{cmd}'"
                    ),
                ));
                break;
            }
        }

        // 5. Smuggled Windows PE binary in header/footer XML
        if s_lower.contains("tvqqaa")
            || s_lower.contains("tvqaia")
            || (s_lower.contains("tvq") && s_lower.contains("aaaa"))
            || s_lower.contains("this program cannot be run in dos mode")
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "headerFooter:smuggledBinary".into(),
                "Word header or footer part contains smuggled Windows PE executable binary".into(),
            ));
        }

        results
    }

    fn scan_excel_datamodel_formula_cache_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lower = String::from_utf8_lossy(data).to_ascii_lowercase();

        // 1. DataModel remote UNC connections or dangerous commands
        if entry_name.contains("datamodel") || entry_name.contains("model/") {
            if (s_lower.contains(r"\\") || s_lower.contains("//"))
                && (s_lower.contains(r#"connection="\\"#)
                    || s_lower.contains(r#"connection='\\"#)
                    || s_lower.contains(r#"source="\\"#)
                    || s_lower.contains(r#"source='\\"#)
                    || s_lower.contains(r#"catalog="\\"#)
                    || s_lower.contains(r#"catalog='\\"#)
                    || s_lower.contains(r#"target="\\"#)
                    || s_lower.contains(r#"target="//"#))
            {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "dataModel:uncConnection".into(),
                    "Excel DataModel references remote UNC connection enabling NTLM credential coercion".into(),
                ));
            }

            for cmd in &["xp_cmdshell", "sp_oacreate", "openrowset", "bulk insert"] {
                if s_lower.contains(cmd) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "dataModel:databaseCommand".into(),
                        format!(
                            "Excel DataModel contains database command execution string '{cmd}'"
                        ),
                    ));
                    break;
                }
            }

            if s_lower.contains("<!doctype") || s_lower.contains("<!entity") {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "dataModel:xxeInjection".into(),
                    "Excel DataModel contains DTD or external entity declaration (XXE vector)"
                        .into(),
                ));
            }

            if s_lower.contains("tvqqaa")
                || s_lower.contains("tvqaia")
                || (s_lower.contains("tvq") && s_lower.contains("aaaa"))
                || s_lower.contains("this program cannot be run in dos mode")
            {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "dataModel:smuggledBinary".into(),
                    "Excel DataModel contains smuggled Windows PE executable binary".into(),
                ));
            }
        }

        // 2. Shared formula and array formula caches in worksheets
        if entry_name.contains("sheet")
            && entry_name.ends_with(".xml")
            && (s_lower.contains("<f t=\"shared\"") || s_lower.contains("<f t=\"array\""))
        {
            // Cloaked DDE execution in shared formula
            if s_lower.contains("cmd|")
                || s_lower.contains("powershell|")
                || s_lower.contains("mshta|")
                || s_lower.contains("cscript|")
                || s_lower.contains("wscript|")
                || s_lower.contains("certutil|")
            {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "formulaCache:cloakedExecution".into(),
                    "Excel shared formula cache contains cloaked DDE command execution string"
                        .into(),
                ));
            }

            // XLM macro execution
            if s_lower.contains("exec(")
                || s_lower.contains("call(")
                || s_lower.contains("register(")
            {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "formulaCache:xlmMacro".into(),
                    "Excel shared formula cache contains Excel 4.0 (XLM) macro execution function"
                        .into(),
                ));
            }

            // Remote UNC workbook reference in shared formula
            if s_lower.contains(r"[\\")
                || s_lower.contains("['\\\\")
                || s_lower.contains("[\"\\\\")
                || s_lower.contains("[//")
                || s_lower.contains("ms-msdt:")
            {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "formulaCache:uncOrExploitProtocol".into(),
                    "Excel shared formula cache references remote UNC path or exploit URI scheme"
                        .into(),
                ));
            }
        }

        results
    }

    fn scan_excel_pivot_cache_and_definition_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let name_lower = entry_name.to_ascii_lowercase();

        if name_lower.ends_with(".rels") {
            let s = String::from_utf8_lossy(data);
            let s_lower = s.to_ascii_lowercase();

            for (i, w) in data.windows(2).enumerate() {
                if (w == b"\\\\" || w == b"//") && i + 4 < data.len() {
                    let rest = &data[i..];
                    let end = rest
                        .iter()
                        .position(|&b| {
                            b == 0
                                || b == b' '
                                || b == b'"'
                                || b == b'\''
                                || b == b'<'
                                || b == b'>'
                                || b == b'\r'
                                || b == b'\n'
                        })
                        .unwrap_or(rest.len().min(128));
                    if let Some(unc) = (end > 4)
                        .then(|| std::str::from_utf8(&rest[..end]).ok())
                        .flatten()
                        .filter(|u| u.contains('\\') || u.contains('/'))
                    {
                        results.push((
                            "High",
                            entry_name.to_string(),
                            "pivotCache:uncCoercion".into(),
                            format!(
                                "Pivot table or cache relationship references external UNC path '{unc}' (NTLM coercion vector)"
                            ),
                        ));
                        break;
                    }
                }
            }

            for proto in &[
                "ms-msdt:",
                "search-ms:",
                "mhtml:",
                "ms-appinstaller:",
                "file:////",
                "javascript:",
                "vbscript:",
            ] {
                if s_lower.contains(proto) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "pivotCache:dangerousProtocol".into(),
                        format!(
                            "Pivot table or cache relationship targets dangerous URI scheme '{proto}'"
                        ),
                    ));
                }
            }

            for ext in &[
                ".exe\"", ".dll\"", ".bat\"", ".cmd\"", ".ps1\"", ".vbs\"", ".js\"", ".hta\"",
                ".cpl\"", ".scr\"", ".msi\"",
            ] {
                if s_lower.contains(ext) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "pivotCache:executableTarget".into(),
                        format!(
                            "Pivot table or cache relationship targets executable payload '{ext}'"
                        ),
                    ));
                }
            }
        } else {
            let s = String::from_utf8_lossy(data);
            let s_lower = s.to_ascii_lowercase();

            for db_cmd in &["xp_cmdshell", "sp_oacreate", "openrowset"] {
                if s_lower.contains(db_cmd) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "pivotCache:databaseCommand".into(),
                        format!(
                            "Pivot table or cache definition contains database command execution procedure '{db_cmd}'"
                        ),
                    ));
                }
            }

            'b64: for marker in &["tvqq", "tvoa", "tvpb", "tvpq"] {
                let mut pos = 0;
                while let Some(idx) = s_lower[pos..].find(marker) {
                    let abs = pos + idx;
                    let candidate = &s[abs..];
                    let b64_len = candidate
                        .bytes()
                        .take_while(|b| {
                            b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/' || *b == b'='
                        })
                        .count();
                    if b64_len >= 64 {
                        results.push((
                            "Critical",
                            entry_name.to_string(),
                            "pivotCache:base64PePayload".into(),
                            format!(
                                "Pivot cache records contain smuggled Base64 Windows PE binary (length: {b64_len} chars)"
                            ),
                        ));
                        break 'b64;
                    }
                    pos = abs + 4;
                }
            }

            if s_lower.contains("4d5a9000")
                || (s_lower.contains("4d5a")
                    && s_lower.contains("this program cannot be run in dos mode"))
            {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "pivotCache:hexPePayload".into(),
                    "Pivot cache records contain hex-encoded Windows PE executable binary header"
                        .into(),
                ));
            }

            for dde_pat in &[
                "=cmd|",
                "=powershell|",
                "=mshta|",
                "=certutil|",
                "dde(",
                "dde.execute(",
            ] {
                if s_lower.contains(dde_pat) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "pivotCache:cloakedDde".into(),
                        format!(
                            "Pivot cache records contain cloaked DDE execution formula '{dde_pat}'"
                        ),
                    ));
                    break;
                }
            }

            for cmd in &[
                "powershell",
                "cmd.exe",
                "wscript.exe",
                "cscript.exe",
                "mshta",
                "rundll32",
                "certutil",
                "bitsadmin",
                "regsvr32",
            ] {
                if s_lower.contains(cmd) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "pivotCache:stagedCommand".into(),
                        format!(
                            "Pivot cache definition contains staged shell execution command '{cmd}'"
                        ),
                    ));
                    break;
                }
            }

            for (i, w) in data.windows(2).enumerate() {
                if (w == b"\\\\" || w == b"//") && i + 4 < data.len() {
                    let rest = &data[i..];
                    let end = rest
                        .iter()
                        .position(|&b| {
                            b == 0
                                || b == b' '
                                || b == b'"'
                                || b == b'\''
                                || b == b'<'
                                || b == b'>'
                                || b == b'\r'
                                || b == b'\n'
                        })
                        .unwrap_or(rest.len().min(128));
                    if let Some(unc) = (end > 4)
                        .then(|| std::str::from_utf8(&rest[..end]).ok())
                        .flatten()
                        .filter(|u| u.contains('\\') || u.contains('/'))
                    {
                        results.push((
                            "High",
                            entry_name.to_string(),
                            "pivotCache:uncCoercion".into(),
                            format!(
                                "Pivot cache definition contains external UNC path '{unc}' (NTLM coercion vector)"
                            ),
                        ));
                        break;
                    }
                }
            }
        }

        results
    }

    fn scan_word_powerpoint_embedded_package_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let name_lower = entry_name.to_ascii_lowercase();

        if name_lower.ends_with(".bin") {
            if data.starts_with(b"MZ") || data.starts_with(b"ZM") {
                let pe_valid = if data.len() >= 0x40 {
                    let pe_off = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap_or_default())
                        as usize;
                    pe_off + 4 <= data.len() && &data[pe_off..pe_off + 4] == b"PE\0\0"
                } else {
                    false
                };
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "embeddedPackage:peBinary".into(),
                    format!(
                        "Embedded OLE package is a disguised Windows PE executable binary (size: {} bytes, verified_pe: {})",
                        data.len(),
                        pe_valid
                    ),
                ));
            }

            let s = String::from_utf8_lossy(data);
            let s_lower = s.to_ascii_lowercase();
            if s_lower.starts_with("@echo off")
                || s_lower.contains("powershell -enc")
                || s_lower.contains("powershell.exe")
                || s_lower.contains("cmd.exe /c")
                || s_lower.contains("wscript.createobject")
                || s_lower.contains("wscript.shell")
            {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "embeddedPackage:stagedScript".into(),
                    "Embedded OLE package contains disguised script or shell execution payload"
                        .into(),
                ));
            }
        }

        for ext in &[
            ".exe", ".scr", ".hta", ".vbs", ".js", ".bat", ".cmd", ".ps1", ".cpl", ".msi", ".jar",
            ".lnk",
        ] {
            if name_lower.ends_with(ext) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "embeddedPackage:executableExtension".into(),
                    format!(
                        "Disguised executable or script embedded in document package directory: '{ext}'"
                    ),
                ));
            }
        }

        if name_lower.ends_with(".rels") {
            let s = String::from_utf8_lossy(data);
            let s_lower = s.to_ascii_lowercase();

            if s_lower.contains("relationships/oleobject")
                || s_lower.contains("relationships/package")
            {
                for (i, w) in data.windows(2).enumerate() {
                    if (w == b"\\\\" || w == b"//") && i + 4 < data.len() {
                        let rest = &data[i..];
                        let end = rest
                            .iter()
                            .position(|&b| {
                                b == 0
                                    || b == b' '
                                    || b == b'"'
                                    || b == b'\''
                                    || b == b'<'
                                    || b == b'>'
                                    || b == b'\r'
                                    || b == b'\n'
                            })
                            .unwrap_or(rest.len().min(128));
                        if let Some(unc) = (end > 4)
                            .then(|| std::str::from_utf8(&rest[..end]).ok())
                            .flatten()
                            .filter(|u| u.contains('\\') || u.contains('/'))
                        {
                            results.push((
                                "High",
                                entry_name.to_string(),
                                "embeddedPackage:uncCoercion".into(),
                                format!(
                                    "Embedded OLE relationship targets external UNC path '{unc}' (NTLM coercion vector)"
                                ),
                            ));
                            break;
                        }
                    }
                }

                for proto in &[
                    "ms-msdt:",
                    "search-ms:",
                    "mhtml:",
                    "ms-appinstaller:",
                    "file:////",
                    "javascript:",
                    "vbscript:",
                ] {
                    if s_lower.contains(proto) {
                        results.push((
                            "Critical",
                            entry_name.to_string(),
                            "embeddedPackage:dangerousProtocol".into(),
                            format!(
                                "Embedded OLE relationship targets dangerous URI scheme '{proto}'"
                            ),
                        ));
                    }
                }

                for ext in &[
                    ".exe\"", ".dll\"", ".bat\"", ".cmd\"", ".ps1\"", ".vbs\"", ".js\"", ".hta\"",
                    ".cpl\"", ".scr\"", ".msi\"",
                ] {
                    if s_lower.contains(ext) {
                        results.push((
                            "Critical",
                            entry_name.to_string(),
                            "embeddedPackage:executableTarget".into(),
                            format!("Embedded OLE relationship targets executable payload '{ext}'"),
                        ));
                    }
                }
            }
        }

        if name_lower.ends_with(".xml")
            && (name_lower.contains("document") || name_lower.contains("slide"))
        {
            let s = String::from_utf8_lossy(data);
            let s_lower = s.to_ascii_lowercase();

            if (s_lower.contains("updatemode=\"always\"") || s_lower.contains("autoload=\"true\""))
                && (s_lower.contains("oleobject")
                    || s_lower.contains("oleobj")
                    || s_lower.contains("progid=\"package\""))
            {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "embeddedPackage:autoActivate".into(),
                    "Auto-activating embedded OLE object configured to execute on document load"
                        .into(),
                ));
            }
        }

        results
    }

    fn scan_excel_external_book_and_sheet_path_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let name_lower = entry_name.to_ascii_lowercase();

        if name_lower.ends_with(".rels") {
            let s = String::from_utf8_lossy(data);
            let s_lower = s.to_ascii_lowercase();

            for (i, w) in data.windows(2).enumerate() {
                if (w == b"\\\\" || w == b"//") && i + 4 < data.len() {
                    let rest = &data[i..];
                    let end = rest
                        .iter()
                        .position(|&b| {
                            b == 0
                                || b == b' '
                                || b == b'"'
                                || b == b'\''
                                || b == b'<'
                                || b == b'>'
                                || b == b'\r'
                                || b == b'\n'
                        })
                        .unwrap_or(rest.len().min(128));
                    if let Some(unc) = (end > 4)
                        .then(|| std::str::from_utf8(&rest[..end]).ok())
                        .flatten()
                        .filter(|u| u.contains('\\') || u.contains('/'))
                    {
                        results.push((
                            "High",
                            entry_name.to_string(),
                            "externalBook:uncCoercion".into(),
                            format!(
                                "External workbook relationship references remote UNC path '{unc}' (NTLM coercion vector)"
                            ),
                        ));
                        break;
                    }
                }
            }

            for proto in &[
                "ms-msdt:",
                "search-ms:",
                "mhtml:",
                "ms-appinstaller:",
                "file:////",
                "powershell:",
                "cmd:",
            ] {
                if s_lower.contains(proto) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "externalBook:dangerousProtocol".into(),
                        format!(
                            "External workbook relationship references dangerous URI scheme '{proto}'"
                        ),
                    ));
                }
            }

            for ext in &[
                ".exe\"", ".dll\"", ".bat\"", ".cmd\"", ".ps1\"", ".vbs\"", ".js\"", ".hta\"",
                ".cpl\"", ".scr\"", ".msi\"",
            ] {
                if s_lower.contains(ext) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "externalBook:executableTarget".into(),
                        format!(
                            "External workbook relationship references executable target '{ext}'"
                        ),
                    ));
                }
            }
        } else {
            let s = String::from_utf8_lossy(data);
            let s_lower = s.to_ascii_lowercase();

            for dde_pat in &[
                "=cmd|",
                "=powershell|",
                "=mshta|",
                "=certutil|",
                "dde(",
                "dde.execute(",
            ] {
                if s_lower.contains(dde_pat) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "externalBook:cloakedDde".into(),
                        format!(
                            "External workbook defined names contain cloaked DDE execution formula '{dde_pat}'"
                        ),
                    ));
                    break;
                }
            }

            'b64: for marker in &["tvqq", "tvoa", "tvpb", "tvpq"] {
                let mut pos = 0;
                while let Some(idx) = s_lower[pos..].find(marker) {
                    let abs = pos + idx;
                    let candidate = &s[abs..];
                    let b64_len = candidate
                        .bytes()
                        .take_while(|b| {
                            b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/' || *b == b'='
                        })
                        .count();
                    if b64_len >= 64 {
                        results.push((
                            "Critical",
                            entry_name.to_string(),
                            "externalBook:base64PePayload".into(),
                            format!(
                                "External workbook cached dataset contains smuggled Base64 Windows PE binary (length: {b64_len} chars)"
                            ),
                        ));
                        break 'b64;
                    }
                    pos = abs + 4;
                }
            }

            if s_lower.contains("4d5a9000")
                || (s_lower.contains("4d5a")
                    && s_lower.contains("this program cannot be run in dos mode"))
            {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "externalBook:hexPePayload".into(),
                    "External workbook cached dataset contains hex-encoded Windows PE executable binary header".into(),
                ));
            }

            for cmd in &[
                "powershell",
                "cmd.exe",
                "wscript.exe",
                "cscript.exe",
                "mshta",
                "rundll32",
                "certutil",
                "regsvr32",
            ] {
                if s_lower.contains(cmd) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "externalBook:stagedCommand".into(),
                        format!(
                            "External workbook cached dataset contains staged shell execution command '{cmd}'"
                        ),
                    ));
                    break;
                }
            }

            for (i, w) in data.windows(2).enumerate() {
                if (w == b"\\\\" || w == b"//") && i + 4 < data.len() {
                    let rest = &data[i..];
                    let end = rest
                        .iter()
                        .position(|&b| {
                            b == 0
                                || b == b' '
                                || b == b'"'
                                || b == b'\''
                                || b == b'<'
                                || b == b'>'
                                || b == b'\r'
                                || b == b'\n'
                        })
                        .unwrap_or(rest.len().min(128));
                    if let Some(unc) = (end > 4)
                        .then(|| std::str::from_utf8(&rest[..end]).ok())
                        .flatten()
                        .filter(|u| u.contains('\\') || u.contains('/'))
                    {
                        results.push((
                            "High",
                            entry_name.to_string(),
                            "externalBook:uncCoercion".into(),
                            format!(
                                "External workbook definition references remote UNC path '{unc}' (NTLM coercion vector)"
                            ),
                        ));
                        break;
                    }
                }
            }
        }

        results
    }

    fn scan_activex_binary_storage_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();

        // 1. Smuggled PE executable binary
        let is_pe = if data.starts_with(b"MZ") {
            if data.len() >= 0x40 {
                let pe_offset =
                    u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
                if pe_offset + 4 <= data.len() && &data[pe_offset..pe_offset + 4] == b"PE\0\0" {
                    true
                } else {
                    data.windows(4).take(4096).any(|w| w == b"PE\0\0")
                }
            } else {
                data.windows(4).take(4096).any(|w| w == b"PE\0\0")
            }
        } else {
            false
        };
        if is_pe {
            results.push((
                "Critical",
                entry_name.to_string(),
                "activexBinary:peBinary".into(),
                "ActiveX binary storage stream contains disguised Windows PE executable binary (verified MZ/PE headers)".into(),
            ));
        }

        // 2. Staged shell scripts or execution commands
        let s_lossy = String::from_utf8_lossy(data);
        let s_lower = s_lossy.to_ascii_lowercase();
        for cmd in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
            "@echo off",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "activexBinary:stagedScript".into(),
                    format!("ActiveX binary storage stream contains staged shell execution command '{cmd}'"),
                ));
                break;
            }
        }

        // 3. Remote UNC paths forcing NTLM credential coercion
        for (i, w) in data.windows(2).enumerate() {
            if (w == b"\\\\" || w == b"//") && i + 4 < data.len() {
                let rest = &data[i..];
                let end = rest
                    .iter()
                    .position(|&b| {
                        b == 0
                            || b == b' '
                            || b == b'"'
                            || b == b'\''
                            || b == b'<'
                            || b == b'>'
                            || b == b'\r'
                            || b == b'\n'
                    })
                    .unwrap_or(rest.len().min(128));
                if let Some(unc) = (end > 4)
                    .then(|| std::str::from_utf8(&rest[..end]).ok())
                    .flatten()
                    .filter(|u| u.contains('\\') || u.contains('/'))
                {
                    results.push((
                        "High",
                        entry_name.to_string(),
                        "activexBinary:uncCoercion".into(),
                        format!("ActiveX binary storage stream references remote UNC path '{unc}' (NTLM coercion vector)"),
                    ));
                    break;
                }
            }
        }

        // 4. Dangerous exploit protocol handlers
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "mhtml:",
            "ms-appinstaller:",
            "powershell:",
            "javascript:",
            "vbscript:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "activexBinary:dangerousProtocol".into(),
                    format!("ActiveX binary storage stream references dangerous exploit URI scheme '{proto}'"),
                ));
            }
        }

        // 5. Weaponized CLSIDs
        for &(clsid, desc) in &[
            (
                "f47456e0-4d65-11ce-8874-00aa002c9f0c",
                "Shell.Explorer / WebBrowser",
            ),
            (
                "0002df01-0000-0000-c000-000000000046",
                "InternetExplorer.Application",
            ),
            ("062907d0-2222-4b7e-b400-79cf3942e30e", "Scriptlet.TypeLib"),
            (
                "0002ce02-0000-0000-c000-000000000046",
                "Equation Editor 3.0",
            ),
            (
                "18490e78-2d0a-48f0-be41-e63092892577",
                "CVE-2017-0199 HTA Moniker",
            ),
        ] {
            if s_lower.contains(clsid) {
                results.push((
                    "High",
                    entry_name.to_string(),
                    "activexBinary:weaponizedClsid".into(),
                    format!(
                        "ActiveX binary storage stream embeds weaponized CLSID '{clsid}' ({desc})"
                    ),
                ));
                break;
            }
        }

        results
    }

    fn scan_xml_digital_signature_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s = String::from_utf8_lossy(data);
        let s_lower = s.to_ascii_lowercase();

        // 1. Remote UNC paths forcing NTLM credential coercion
        for (i, w) in data.windows(2).enumerate() {
            if (w == b"\\\\" || w == b"//") && i + 4 < data.len() {
                let rest = &data[i..];
                let end = rest
                    .iter()
                    .position(|&b| {
                        b == 0
                            || b == b' '
                            || b == b'"'
                            || b == b'\''
                            || b == b'<'
                            || b == b'>'
                            || b == b'\r'
                            || b == b'\n'
                    })
                    .unwrap_or(rest.len().min(128));
                if let Some(unc) = (end > 4)
                    .then(|| std::str::from_utf8(&rest[..end]).ok())
                    .flatten()
                    .filter(|u| u.contains('\\') || u.contains('/'))
                {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "xmlSignature:uncCoercion".into(),
                        format!("Digital signature part references remote UNC path '{unc}' enabling NTLM credential coercion"),
                    ));
                    break;
                }
            }
        }

        // 2. Dangerous exploit URI schemes
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "mhtml:",
            "ms-appinstaller:",
            "powershell:",
            "javascript:",
            "vbscript:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "xmlSignature:dangerousProtocol".into(),
                    format!(
                        "Digital signature part references dangerous exploit URI scheme '{proto}'"
                    ),
                ));
            }
        }

        // 3. XSLT Transform filter in XML-DSig
        if s_lower.contains("algorithm=\"http://www.w3.org/tr/1999/rec-xslt-19991116\"")
            || s_lower.contains("<xsl:stylesheet")
            || s_lower.contains("<msxsl:script")
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "xmlSignature:xsltTransform".into(),
                "Digital signature part declares XSLT transform filter enabling code execution during signature evaluation".into(),
            ));
        }

        // 4. XXE / external entity injection in XML-DSig
        if s_lower.contains("<!doctype") || s_lower.contains("<!entity") {
            results.push((
                "Critical",
                entry_name.to_string(),
                "xmlSignature:xxeInjection".into(),
                "Digital signature part contains XXE DTD or entity declaration".into(),
            ));
        }

        // 5. Smuggled Base64 PE binary
        'b64_sig: for marker in &["tvqq", "tvoa", "tvpb", "tvpq"] {
            let mut pos = 0;
            while let Some(idx) = s_lower[pos..].find(marker) {
                let abs = pos + idx;
                let candidate = &s[abs..];
                let b64_len = candidate
                    .bytes()
                    .take_while(|b| {
                        b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/' || *b == b'='
                    })
                    .count();
                if b64_len >= 64 {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "xmlSignature:smuggledBinary".into(),
                        format!(
                            "Digital signature part contains Base64-smuggled Windows PE executable binary (length: {b64_len} chars)"
                        ),
                    ));
                    break 'b64_sig;
                }
                pos = abs + marker.len();
            }
        }

        // 6. Staged shell execution commands
        for cmd in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "xmlSignature:stagedCommand".into(),
                    format!(
                        "Digital signature part contains staged shell execution command '{cmd}'"
                    ),
                ));
                break;
            }
        }

        results
    }

    fn scan_excel_control_properties_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s = String::from_utf8_lossy(data);
        let s_lower = s.to_ascii_lowercase();

        // 1. Cloaked DDE execution in control formula bindings
        for dde in &[
            "cmd|",
            "powershell|",
            "mshta|",
            "cscript|",
            "wscript|",
            "certutil|",
            "regsvr32|",
        ] {
            if s_lower.contains(dde) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "controlProperty:cloakedDde".into(),
                    format!("Excel control property defines cloaked DDE execution command '{dde}'"),
                ));
                break;
            }
        }

        // 2. Excel 4.0 (XLM) macro functions
        for xlm in &["exec(", "call(", "register("] {
            if s_lower.contains(xlm) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "controlProperty:xlmMacro".into(),
                    format!("Excel control property defines Excel 4.0 (XLM) macro execution function '{xlm}'"),
                ));
                break;
            }
        }

        // 3. Remote UNC paths forcing NTLM credential coercion
        for (i, w) in data.windows(2).enumerate() {
            if (w == b"\\\\" || w == b"//") && i + 4 < data.len() {
                let rest = &data[i..];
                let end = rest
                    .iter()
                    .position(|&b| {
                        b == 0
                            || b == b' '
                            || b == b'"'
                            || b == b'\''
                            || b == b'<'
                            || b == b'>'
                            || b == b'\r'
                            || b == b'\n'
                    })
                    .unwrap_or(rest.len().min(128));
                if let Some(unc) = (end > 4)
                    .then(|| std::str::from_utf8(&rest[..end]).ok())
                    .flatten()
                    .filter(|u| u.contains('\\') || u.contains('/'))
                {
                    results.push((
                        "High",
                        entry_name.to_string(),
                        "controlProperty:uncCoercion".into(),
                        format!("Excel control property references remote UNC path '{unc}' (NTLM coercion vector)"),
                    ));
                    break;
                }
            }
        }

        // 4. Dangerous exploit protocol handlers
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "mhtml:",
            "ms-appinstaller:",
            "powershell:",
            "javascript:",
            "vbscript:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "controlProperty:dangerousProtocol".into(),
                    format!(
                        "Excel control property references dangerous exploit URI scheme '{proto}'"
                    ),
                ));
            }
        }

        // 5. Smuggled PE binary
        if s_lower.contains("tvqqaa")
            || s_lower.contains("tvqaia")
            || (s_lower.contains("tvq") && s_lower.contains("aaaa"))
            || s_lower.contains("this program cannot be run in dos mode")
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "controlProperty:smuggledBinary".into(),
                "Excel control property contains smuggled Windows PE executable binary".into(),
            ));
        }

        // 6. Staged shell execution commands
        for cmd in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "controlProperty:stagedCommand".into(),
                    format!(
                        "Excel control property contains staged shell execution command '{cmd}'"
                    ),
                ));
                break;
            }
        }

        results
    }

    fn scan_powerpoint_media_track_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let name_lower = entry_name.to_ascii_lowercase();

        // 1. Binary payload checks if this is a media file part (ppt/media/*)
        if name_lower.contains("media/") {
            // Disguised Windows PE executable
            let is_pe = data.starts_with(b"MZ")
                || (data.len() > 0x3c + 4 && data.windows(4).take(1024).any(|w| w == b"PE\0\0"));
            if is_pe {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "mediaTrack:peBinary".into(),
                    "PowerPoint media part disguises Windows PE executable binary (verified MZ/PE header)".into(),
                ));
            }

            // Linux ELF or Mach-O executable disguised as media
            if data.starts_with(b"\x7fELF")
                || data.starts_with(b"\xfe\xed\xfa\xce")
                || data.starts_with(b"\xfe\xed\xfa\xcf")
                || data.starts_with(b"\xcf\xfa\xed\xfe")
            {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "mediaTrack:elfMachoBinary".into(),
                    "PowerPoint media part disguises non-Windows executable binary (ELF/Mach-O header)".into(),
                ));
            }

            // LNK Shell Link shortcut disguised as media
            if data.len() >= 32
                && data.starts_with(&[0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00])
            {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "mediaTrack:shellLinkShortcut".into(),
                    "PowerPoint media part disguises Windows Shell Link (LNK) shortcut payload"
                        .into(),
                ));
            }

            // Staged shell scripts inside media stream
            for &(script_token, desc) in &[
                (b"powershell".as_slice(), "PowerShell script"),
                (b"@echo off".as_slice(), "Batch script"),
                (b"cmd.exe".as_slice(), "Command shell"),
                (b"wscript.shell".as_slice(), "WScript Shell automation"),
                (b"certutil".as_slice(), "Certutil download/decode"),
                (b"mshta".as_slice(), "MSHTA execution"),
            ] {
                if data
                    .windows(script_token.len())
                    .any(|w| w.eq_ignore_ascii_case(script_token))
                {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "mediaTrack:stagedScript".into(),
                        format!("PowerPoint media part embeds staged script payload ({desc})"),
                    ));
                    break;
                }
            }
        }

        // 2. XML text checks for slide, master, layout, or relationship parts
        let s_lower = String::from_utf8_lossy(data).to_ascii_lowercase();

        // Remote UNC media streams (NTLM coercion upon slide transition)
        for (i, w) in data.windows(2).enumerate() {
            if (w == b"\\\\" || (w == b"//" && (i == 0 || data[i - 1] != b':')))
                && i + 4 < data.len()
            {
                let rest = &data[i..];
                let end = rest
                    .iter()
                    .position(|&b| {
                        b == 0
                            || b == b' '
                            || b == b'"'
                            || b == b'\''
                            || b == b'<'
                            || b == b'>'
                            || b == b'\r'
                            || b == b'\n'
                    })
                    .unwrap_or(rest.len().min(128));
                if let Some(unc) = (end > 4)
                    .then(|| std::str::from_utf8(&rest[..end]).ok())
                    .flatten()
                    .filter(|u| u.contains('\\') || u.contains('/'))
                {
                    results.push((
                        "High",
                        entry_name.to_string(),
                        "mediaTrack:uncCoercion".into(),
                        format!("PowerPoint media track references remote UNC media stream '{unc}' (NTLM coercion vector)"),
                    ));
                    break;
                }
            }
        }

        // Dangerous exploit protocol handlers in media targets
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "mhtml:",
            "ms-appinstaller:",
            "powershell:",
            "cmd:",
            "file:////",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "mediaTrack:dangerousProtocol".into(),
                    format!("PowerPoint media relationship references dangerous exploit URI scheme '{proto}'"),
                ));
            }
        }

        // Staged command triggers in media nodes (<p:cMediaNode>, <p:media>, etc.)
        for cmd in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
        ] {
            if s_lower.contains(cmd)
                && (s_lower.contains("medianode")
                    || s_lower.contains("media")
                    || s_lower.contains("audio")
                    || s_lower.contains("video"))
            {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "mediaTrack:commandTrigger".into(),
                    format!("PowerPoint media track node contains shell execution command '{cmd}'"),
                ));
                break;
            }
        }

        results
    }

    fn scan_excel_table_or_slicer_native_connection_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lower = String::from_utf8_lossy(data).to_ascii_lowercase();

        // 1. Remote UNC paths forcing NTLM credential coercion
        for (i, w) in data.windows(2).enumerate() {
            if (w == b"\\\\" || (w == b"//" && (i == 0 || data[i - 1] != b':')))
                && i + 4 < data.len()
            {
                let rest = &data[i..];
                let end = rest
                    .iter()
                    .position(|&b| {
                        b == 0
                            || b == b' '
                            || b == b'"'
                            || b == b'\''
                            || b == b'<'
                            || b == b'>'
                            || b == b'\r'
                            || b == b'\n'
                    })
                    .unwrap_or(rest.len().min(128));
                if let Some(unc) = (end > 4)
                    .then(|| std::str::from_utf8(&rest[..end]).ok())
                    .flatten()
                    .filter(|u| u.contains('\\') || u.contains('/'))
                {
                    results.push((
                        "High",
                        entry_name.to_string(),
                        "tableConnection:uncCoercion".into(),
                        format!("Excel table or slicer definition references remote UNC data connection '{unc}' (NTLM coercion vector)"),
                    ));
                    break;
                }
            }
        }

        // 2. Dangerous exploit protocol handlers
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "mhtml:",
            "ms-appinstaller:",
            "powershell:",
            "javascript:",
            "vbscript:",
            "cmd:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "tableConnection:dangerousProtocol".into(),
                    format!("Excel table or slicer definition references dangerous exploit URI scheme '{proto}'"),
                ));
            }
        }

        // 3. Cloaked DDE execution in slicer item captions or table column formulas
        for dde in &[
            "=cmd|",
            "=powershell|",
            "=mshta|",
            "=cscript|",
            "=wscript|",
            "=certutil|",
            "=regsvr32|",
            "cmd|",
            "powershell|",
            "mshta|",
            "dde(",
        ] {
            if s_lower.contains(dde) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "tableConnection:cloakedDde".into(),
                    format!("Excel table or slicer definition contains cloaked DDE execution command '{dde}'"),
                ));
                break;
            }
        }

        // 4. Database command execution procedures in connection properties
        for sql in &[
            "xp_cmdshell",
            "sp_oacreate",
            "openrowset",
            "bulk insert",
            "exec(",
            "select into outfile",
        ] {
            if s_lower.contains(sql) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "tableConnection:databaseCommand".into(),
                    format!("Excel table or slicer data connection embeds database command execution string '{sql}'"),
                ));
                break;
            }
        }

        // 5. Smuggled PE binary
        if s_lower.contains("tvqqaa")
            || s_lower.contains("tvqaia")
            || (s_lower.contains("tvq") && s_lower.contains("aaaa"))
            || s_lower.contains("this program cannot be run in dos mode")
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "tableConnection:smuggledBinary".into(),
                "Excel table or slicer definition contains smuggled Windows PE executable binary"
                    .into(),
            ));
        }

        // 6. Staged shell execution commands
        for cmd in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "tableConnection:stagedCommand".into(),
                    format!("Excel table or slicer definition contains staged shell execution command '{cmd}'"),
                ));
                break;
            }
        }

        results
    }

    fn scan_word_mail_merge_header_source_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lower = String::from_utf8_lossy(data).to_ascii_lowercase();

        // If this part is settings.xml or settings.xml.rels, ensure it actually references mail merge
        let name_lower = entry_name.to_ascii_lowercase();
        if (name_lower.ends_with("settings.xml") || name_lower.ends_with("settings.xml.rels"))
            && !s_lower.contains("mailmerge")
        {
            return results;
        }

        // 1. Remote UNC paths in mail merge header source, query, or connect string
        for (i, w) in data.windows(2).enumerate() {
            if (w == b"\\\\" || (w == b"//" && (i == 0 || data[i - 1] != b':')))
                && i + 4 < data.len()
            {
                let rest = &data[i..];
                let end = rest
                    .iter()
                    .position(|&b| {
                        b == 0
                            || b == b' '
                            || b == b'"'
                            || b == b'\''
                            || b == b'<'
                            || b == b'>'
                            || b == b'\r'
                            || b == b'\n'
                    })
                    .unwrap_or(rest.len().min(128));
                if let Some(unc) = (end > 4)
                    .then(|| std::str::from_utf8(&rest[..end]).ok())
                    .flatten()
                    .filter(|u| u.contains('\\') || u.contains('/'))
                {
                    results.push((
                        "High",
                        entry_name.to_string(),
                        "mailMerge:uncCoercion".into(),
                        format!("Word mail merge settings reference remote UNC header source or database '{unc}' (NTLM coercion vector)"),
                    ));
                    break;
                }
            }
        }

        // 2. Dangerous exploit protocol handlers
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "mhtml:",
            "ms-appinstaller:",
            "powershell:",
            "javascript:",
            "vbscript:",
            "cmd:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "mailMerge:dangerousProtocol".into(),
                    format!("Word mail merge configuration references dangerous exploit URI scheme '{proto}'"),
                ));
            }
        }

        // 3. Database command injection or command execution procedures
        for sql in &[
            "xp_cmdshell",
            "sp_oacreate",
            "openrowset",
            "into outfile",
            "into dumpfile",
        ] {
            if s_lower.contains(sql) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "mailMerge:databaseCommand".into(),
                    format!(
                        "Word mail merge query embeds database command execution string '{sql}'"
                    ),
                ));
                break;
            }
        }

        // 4. Staged shell execution commands
        for cmd in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "mailMerge:stagedCommand".into(),
                    format!("Word mail merge configuration contains staged shell execution command '{cmd}'"),
                ));
                break;
            }
        }

        // 5. External relationship targets pointing to executable payloads
        if entry_name.ends_with(".rels") && s_lower.contains("mailmerge") {
            for ext in &[
                ".docm", ".dotm", ".xlsm", ".xltm", ".hta", ".vbs", ".bat", ".ps1", ".exe", ".iqy",
            ] {
                if s_lower.contains(ext) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "mailMerge:executableTarget".into(),
                        format!("Word mail merge relationship targets weaponized payload '{ext}'"),
                    ));
                    break;
                }
            }
        }

        // 6. Smuggled PE binary
        if s_lower.contains("tvqqaa")
            || s_lower.contains("tvqaia")
            || (s_lower.contains("tvq") && s_lower.contains("aaaa"))
            || s_lower.contains("this program cannot be run in dos mode")
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "mailMerge:smuggledBinary".into(),
                "Word mail merge part contains smuggled Windows PE executable binary".into(),
            ));
        }

        results
    }

    fn scan_powerpoint_slideshow_or_presentation_props_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lower = String::from_utf8_lossy(data).to_ascii_lowercase();

        // 1. Remote UNC paths in presentation properties or broadcast configuration
        for (i, w) in data.windows(2).enumerate() {
            if (w == b"\\\\" || (w == b"//" && (i == 0 || data[i - 1] != b':')))
                && i + 4 < data.len()
            {
                let rest = &data[i..];
                let end = rest
                    .iter()
                    .position(|&b| {
                        b == 0
                            || b == b' '
                            || b == b'"'
                            || b == b'\''
                            || b == b'<'
                            || b == b'>'
                            || b == b'\r'
                            || b == b'\n'
                    })
                    .unwrap_or(rest.len().min(128));
                if let Some(unc) = (end > 4)
                    .then(|| std::str::from_utf8(&rest[..end]).ok())
                    .flatten()
                    .filter(|u| u.contains('\\') || u.contains('/'))
                {
                    results.push((
                        "High",
                        entry_name.to_string(),
                        "presentationProps:uncCoercion".into(),
                        format!("PowerPoint presentation properties reference remote UNC resource '{unc}' (NTLM coercion vector)"),
                    ));
                    break;
                }
            }
        }

        // 2. Dangerous exploit URI schemes
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "mhtml:",
            "ms-appinstaller:",
            "powershell:",
            "javascript:",
            "vbscript:",
            "cmd:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "presentationProps:dangerousProtocol".into(),
                    format!("PowerPoint presentation properties reference dangerous exploit URI scheme '{proto}'"),
                ));
            }
        }

        // 3. Staged shell execution commands
        for cmd in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "presentationProps:stagedCommand".into(),
                    format!("PowerPoint presentation properties contain staged shell execution command '{cmd}'"),
                ));
                break;
            }
        }

        // 4. Kiosk mode lockup or forced full screen loop anomaly with external broadcast
        if (s_lower.contains("showtype=\"kiosk\"")
            || s_lower.contains("<p:kiosk")
            || s_lower.contains("kiosk=\"1\""))
            && (s_lower.contains("loop=\"1\"")
                || s_lower.contains("loop=\"true\"")
                || s_lower.contains("broadcast")
                || s_lower.contains("htmlpubpr"))
        {
            results.push((
                "High",
                entry_name.to_string(),
                "presentationProps:kioskLockup".into(),
                "PowerPoint presentation properties configure kiosk full-screen mode combined with loop/broadcast behavior (evasive UI lockup vector)".into(),
            ));
        }

        // 5. External relationship targets pointing to executable / macro payloads
        if entry_name.ends_with(".rels") {
            for ext in &[
                ".docm", ".dotm", ".xlsm", ".xltm", ".ppam", ".pptm", ".hta", ".vbs", ".bat",
                ".ps1", ".exe",
            ] {
                if s_lower.contains(ext) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "presentationProps:executableTarget".into(),
                        format!("PowerPoint presentation relationship targets weaponized payload '{ext}'"),
                    ));
                    break;
                }
            }
        }

        // 6. Smuggled PE binary
        if s_lower.contains("tvqqaa")
            || s_lower.contains("tvqaia")
            || (s_lower.contains("tvq") && s_lower.contains("aaaa"))
            || s_lower.contains("this program cannot be run in dos mode")
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "presentationProps:smuggledBinary".into(),
                "PowerPoint presentation properties contain smuggled Windows PE executable binary"
                    .into(),
            ));
        }

        results
    }

    fn scan_excel_threaded_comment_or_person_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lower = String::from_utf8_lossy(data).to_ascii_lowercase();

        // 1. Remote UNC paths in threaded comments or person identifiers
        for (i, w) in data.windows(2).enumerate() {
            if (w == b"\\\\" || (w == b"//" && (i == 0 || data[i - 1] != b':')))
                && i + 4 < data.len()
            {
                let rest = &data[i..];
                let end = rest
                    .iter()
                    .position(|&b| {
                        b == 0
                            || b == b' '
                            || b == b'"'
                            || b == b'\''
                            || b == b'<'
                            || b == b'>'
                            || b == b'\r'
                            || b == b'\n'
                    })
                    .unwrap_or(rest.len().min(128));
                if let Some(unc) = (end > 4)
                    .then(|| std::str::from_utf8(&rest[..end]).ok())
                    .flatten()
                    .filter(|u| u.contains('\\') || u.contains('/'))
                {
                    results.push((
                        "High",
                        entry_name.to_string(),
                        "threadedComment:uncCoercion".into(),
                        format!("Excel threaded comment or person metadata references remote UNC path '{unc}' (NTLM coercion vector)"),
                    ));
                    break;
                }
            }
        }

        // 2. Cloaked DDE / command execution formulas
        for dde in &[
            "=cmd|",
            "=powershell|",
            "+cmd|",
            "@powershell|",
            "=dde(",
            "cmd /c",
            "powershell.exe",
        ] {
            if s_lower.contains(dde) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "threadedComment:cloakedDde".into(),
                    format!("Excel threaded comment embeds cloaked DDE formula or execution string '{dde}'"),
                ));
                break;
            }
        }

        // 3. Dangerous exploit URI schemes
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "mhtml:",
            "ms-appinstaller:",
            "powershell:",
            "javascript:",
            "vbscript:",
            "cmd:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "threadedComment:dangerousProtocol".into(),
                    format!("Excel threaded comment or person metadata references dangerous exploit URI scheme '{proto}'"),
                ));
            }
        }

        // 4. Staged shell execution commands
        for cmd in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "threadedComment:stagedCommand".into(),
                    format!(
                        "Excel threaded comment contains staged shell execution command '{cmd}'"
                    ),
                ));
                break;
            }
        }

        // 5. Smuggled PE binary
        if s_lower.contains("tvqqaa")
            || s_lower.contains("tvqaia")
            || (s_lower.contains("tvq") && s_lower.contains("aaaa"))
            || s_lower.contains("this program cannot be run in dos mode")
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "threadedComment:smuggledBinary".into(),
                "Excel threaded comment contains smuggled Windows PE executable binary".into(),
            ));
        }

        results
    }

    fn scan_office_theme_override_or_format_scheme_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lower = String::from_utf8_lossy(data).to_ascii_lowercase();

        // 1. Remote UNC paths in theme overrides or format schemes
        for (i, w) in data.windows(2).enumerate() {
            if (w == b"\\\\" || (w == b"//" && (i == 0 || data[i - 1] != b':')))
                && i + 4 < data.len()
            {
                let rest = &data[i..];
                let end = rest
                    .iter()
                    .position(|&b| {
                        b == 0
                            || b == b' '
                            || b == b'"'
                            || b == b'\''
                            || b == b'<'
                            || b == b'>'
                            || b == b'\r'
                            || b == b'\n'
                    })
                    .unwrap_or(rest.len().min(128));
                if let Some(unc) = (end > 4)
                    .then(|| std::str::from_utf8(&rest[..end]).ok())
                    .flatten()
                    .filter(|u| u.contains('\\') || u.contains('/'))
                {
                    results.push((
                        "High",
                        entry_name.to_string(),
                        "themeOverride:uncCoercion".into(),
                        format!("Office theme override or format scheme references remote UNC resource '{unc}' (NTLM coercion vector)"),
                    ));
                    break;
                }
            }
        }

        // 2. Dangerous exploit URI schemes
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "mhtml:",
            "ms-appinstaller:",
            "powershell:",
            "javascript:",
            "vbscript:",
            "cmd:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "themeOverride:dangerousProtocol".into(),
                    format!("Office theme override or format scheme references dangerous exploit URI scheme '{proto}'"),
                ));
            }
        }

        // 3. Staged shell execution commands
        for cmd in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "themeOverride:stagedCommand".into(),
                    format!("Office theme override or format scheme contains staged shell execution command '{cmd}'"),
                ));
                break;
            }
        }

        // 4. External relationship targets pointing to executable / macro payloads
        if entry_name.ends_with(".rels") {
            for ext in &[
                ".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".hta", ".vbs", ".bat", ".ps1", ".exe",
            ] {
                if s_lower.contains(ext) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "themeOverride:executableTarget".into(),
                        format!(
                            "Office theme override relationship targets weaponized payload '{ext}'"
                        ),
                    ));
                    break;
                }
            }
        }

        // 5. Smuggled PE binary
        if s_lower.contains("tvqqaa")
            || s_lower.contains("tvqaia")
            || (s_lower.contains("tvq") && s_lower.contains("aaaa"))
            || s_lower.contains("this program cannot be run in dos mode")
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "themeOverride:smuggledBinary".into(),
                "Office theme override contains smuggled Windows PE executable binary".into(),
            ));
        }

        results
    }

    fn scan_powerpoint_sync_or_comment_authors_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lower = String::from_utf8_lossy(data).to_ascii_lowercase();

        // 1. Remote UNC paths in PowerPoint sync info or comment authors
        for (i, w) in data.windows(2).enumerate() {
            if (w == b"\\\\" || (w == b"//" && (i == 0 || data[i - 1] != b':')))
                && i + 4 < data.len()
            {
                let rest = &data[i..];
                let end = rest
                    .iter()
                    .position(|&b| {
                        b == 0
                            || b == b' '
                            || b == b'"'
                            || b == b'\''
                            || b == b'<'
                            || b == b'>'
                            || b == b'\r'
                            || b == b'\n'
                    })
                    .unwrap_or(rest.len().min(128));
                if let Some(unc) = (end > 4)
                    .then(|| std::str::from_utf8(&rest[..end]).ok())
                    .flatten()
                    .filter(|u| u.contains('\\') || u.contains('/'))
                {
                    results.push((
                        "High",
                        entry_name.to_string(),
                        "powerpointSync:uncCoercion".into(),
                        format!("PowerPoint sync info or comment authors references remote UNC resource '{unc}' (NTLM coercion vector)"),
                    ));
                    break;
                }
            }
        }

        // 2. Dangerous exploit URI schemes
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "mhtml:",
            "ms-appinstaller:",
            "powershell:",
            "javascript:",
            "vbscript:",
            "cmd:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "powerpointSync:dangerousProtocol".into(),
                    format!("PowerPoint sync info or comment authors references dangerous exploit URI scheme '{proto}'"),
                ));
            }
        }

        // 3. Staged shell execution commands
        for cmd in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "powerpointSync:stagedCommand".into(),
                    format!("PowerPoint sync info or comment authors contains staged shell execution command '{cmd}'"),
                ));
                break;
            }
        }

        // 4. External relationship targets pointing to executable / macro payloads
        if entry_name.ends_with(".rels") {
            for ext in &[
                ".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".hta", ".vbs", ".bat", ".ps1", ".exe",
            ] {
                if s_lower.contains(ext) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "powerpointSync:executableTarget".into(),
                        format!("PowerPoint sync relationship targets weaponized payload '{ext}'"),
                    ));
                    break;
                }
            }
        }

        // 5. Cloaked DDE / command formulas in author names or sync properties
        if s_lower.contains("cmd|") || s_lower.contains("powershell|") || s_lower.contains("mshta|")
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "powerpointSync:cloakedDde".into(),
                "PowerPoint comment author or sync definition contains cloaked DDE command formula"
                    .into(),
            ));
        }

        // 6. Smuggled PE binary
        if s_lower.contains("tvqqaa")
            || s_lower.contains("tvqaia")
            || (s_lower.contains("tvq") && s_lower.contains("aaaa"))
            || s_lower.contains("this program cannot be run in dos mode")
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "powerpointSync:smuggledBinary".into(),
                "PowerPoint sync info or comment authors contains smuggled Windows PE executable binary".into(),
            ));
        }

        results
    }

    fn scan_word_keymap_or_customization_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lower = String::from_utf8_lossy(data).to_ascii_lowercase();

        // 1. Remote UNC paths in keymap or customizations
        for (i, w) in data.windows(2).enumerate() {
            if (w == b"\\\\" || (w == b"//" && (i == 0 || data[i - 1] != b':')))
                && i + 4 < data.len()
            {
                let rest = &data[i..];
                let end = rest
                    .iter()
                    .position(|&b| {
                        b == 0
                            || b == b' '
                            || b == b'"'
                            || b == b'\''
                            || b == b'<'
                            || b == b'>'
                            || b == b'\r'
                            || b == b'\n'
                    })
                    .unwrap_or(rest.len().min(128));
                if let Some(unc) = (end > 4)
                    .then(|| std::str::from_utf8(&rest[..end]).ok())
                    .flatten()
                    .filter(|u| u.contains('\\') || u.contains('/'))
                {
                    results.push((
                        "High",
                        entry_name.to_string(),
                        "wordKeyMap:uncCoercion".into(),
                        format!("Word keymap or customization part references remote UNC resource '{unc}' (NTLM coercion vector)"),
                    ));
                    break;
                }
            }
        }

        // 2. Dangerous exploit URI schemes
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "mhtml:",
            "ms-appinstaller:",
            "powershell:",
            "javascript:",
            "vbscript:",
            "cmd:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "wordKeyMap:dangerousProtocol".into(),
                    format!("Word keymap or customization part references dangerous exploit URI scheme '{proto}'"),
                ));
            }
        }

        // 3. Staged shell execution commands
        for cmd in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "wordKeyMap:stagedCommand".into(),
                    format!("Word keymap or customization part contains staged shell execution command '{cmd}'"),
                ));
                break;
            }
        }

        // 4. Keyboard shortcut macro / command hook binding
        if (s_lower.contains("kcm")
            || s_lower.contains("keymap")
            || s_lower.contains("fkeyshortcut")
            || s_lower.contains("w:kcm"))
            && (s_lower.contains("macro")
                || s_lower.contains("autoopen")
                || s_lower.contains("autonew")
                || s_lower.contains("document_open")
                || s_lower.contains("shell")
                || s_lower.contains("run"))
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "wordKeyMap:macroHook".into(),
                "Word keyboard mapping binds keystrokes or shortcuts to malicious macro execution hook".into(),
            ));
        }

        // 5. External relationship targets pointing to executable / macro payloads
        if entry_name.ends_with(".rels") {
            for ext in &[
                ".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".hta", ".vbs", ".bat", ".ps1", ".exe",
            ] {
                if s_lower.contains(ext) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "wordKeyMap:executableTarget".into(),
                        format!(
                            "Word keymap or customization relationship targets weaponized payload '{ext}'"
                        ),
                    ));
                    break;
                }
            }
        }

        // 6. Smuggled PE binary
        if s_lower.contains("tvqqaa")
            || s_lower.contains("tvqaia")
            || (s_lower.contains("tvq") && s_lower.contains("aaaa"))
            || s_lower.contains("this program cannot be run in dos mode")
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "wordKeyMap:smuggledBinary".into(),
                "Word keymap or customization part contains smuggled Windows PE executable binary"
                    .into(),
            ));
        }

        results
    }

    fn scan_excel_web_publishing_or_sparkline_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lower = String::from_utf8_lossy(data).to_ascii_lowercase();

        // 1. Remote UNC paths in web publishing destinations or sparklines
        for (i, w) in data.windows(2).enumerate() {
            if (w == b"\\\\" || (w == b"//" && (i == 0 || data[i - 1] != b':')))
                && i + 4 < data.len()
            {
                let rest = &data[i..];
                let end = rest
                    .iter()
                    .position(|&b| {
                        b == 0
                            || b == b' '
                            || b == b'"'
                            || b == b'\''
                            || b == b'<'
                            || b == b'>'
                            || b == b'\r'
                            || b == b'\n'
                    })
                    .unwrap_or(rest.len().min(128));
                if let Some(unc) = (end > 4)
                    .then(|| std::str::from_utf8(&rest[..end]).ok())
                    .flatten()
                    .filter(|u| u.contains('\\') || u.contains('/'))
                {
                    results.push((
                        "High",
                        entry_name.to_string(),
                        "excelWebPublish:uncCoercion".into(),
                        format!("Excel web publishing or sparkline part references remote UNC resource '{unc}' (silent exfiltration / NTLM coercion)"),
                    ));
                    break;
                }
            }
        }

        // 2. Dangerous exploit URI schemes
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "mhtml:",
            "ms-appinstaller:",
            "powershell:",
            "javascript:",
            "vbscript:",
            "cmd:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "excelWebPublish:dangerousProtocol".into(),
                    format!("Excel web publishing or sparkline part references dangerous exploit URI scheme '{proto}'"),
                ));
            }
        }

        // 3. Staged shell execution commands
        for cmd in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "excelWebPublish:stagedCommand".into(),
                    format!("Excel web publishing or sparkline part contains staged shell execution command '{cmd}'"),
                ));
                break;
            }
        }

        // 4. External relationship targets pointing to executable / macro payloads
        if entry_name.ends_with(".rels") {
            for ext in &[
                ".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".hta", ".vbs", ".bat", ".ps1", ".exe",
            ] {
                if s_lower.contains(ext) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "excelWebPublish:executableTarget".into(),
                        format!(
                            "Excel web publishing or sparkline relationship targets weaponized payload '{ext}'"
                        ),
                    ));
                    break;
                }
            }
        }

        // 5. Smuggled PE binary
        if s_lower.contains("tvqqaa")
            || s_lower.contains("tvqaia")
            || (s_lower.contains("tvq") && s_lower.contains("aaaa"))
            || s_lower.contains("this program cannot be run in dos mode")
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "excelWebPublish:smuggledBinary".into(),
                "Excel web publishing or sparkline part contains smuggled Windows PE executable binary".into(),
            ));
        }

        results
    }

    fn scan_powerpoint_handout_or_notes_master_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lower = String::from_utf8_lossy(data).to_ascii_lowercase();

        // 1. Remote UNC paths in handout or notes master parts
        for (i, w) in data.windows(2).enumerate() {
            if (w == b"\\\\" || (w == b"//" && (i == 0 || data[i - 1] != b':')))
                && i + 4 < data.len()
            {
                let rest = &data[i..];
                let end = rest
                    .iter()
                    .position(|&b| {
                        b == 0
                            || b == b' '
                            || b == b'"'
                            || b == b'\''
                            || b == b'<'
                            || b == b'>'
                            || b == b'\r'
                            || b == b'\n'
                    })
                    .unwrap_or(rest.len().min(128));
                if let Some(unc) = (end > 4)
                    .then(|| std::str::from_utf8(&rest[..end]).ok())
                    .flatten()
                    .filter(|u| u.contains('\\') || u.contains('/'))
                {
                    results.push((
                        "High",
                        entry_name.to_string(),
                        "handoutNotesMaster:uncCoercion".into(),
                        format!("PowerPoint handout or notes master references remote UNC resource '{unc}' (NTLM coercion vector)"),
                    ));
                    break;
                }
            }
        }

        // 2. Dangerous exploit URI schemes
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "mhtml:",
            "ms-appinstaller:",
            "powershell:",
            "javascript:",
            "vbscript:",
            "cmd:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "handoutNotesMaster:dangerousProtocol".into(),
                    format!("PowerPoint handout or notes master references dangerous exploit URI scheme '{proto}'"),
                ));
            }
        }

        // 3. Staged shell execution commands
        for cmd in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "handoutNotesMaster:stagedCommand".into(),
                    format!("PowerPoint handout or notes master contains staged shell execution command '{cmd}'"),
                ));
                break;
            }
        }

        // 4. External relationship targets pointing to executable / macro payloads
        if entry_name.ends_with(".rels") {
            for ext in &[
                ".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".hta", ".vbs", ".bat", ".ps1", ".exe",
            ] {
                if s_lower.contains(ext) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "handoutNotesMaster:executableTarget".into(),
                        format!(
                            "PowerPoint handout or notes master relationship targets weaponized payload '{ext}'"
                        ),
                    ));
                    break;
                }
            }
        }

        // 5. Cloaked DDE / command formulas in master definitions
        if s_lower.contains("cmd|") || s_lower.contains("powershell|") || s_lower.contains("mshta|")
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "handoutNotesMaster:cloakedDde".into(),
                "PowerPoint handout or notes master contains cloaked DDE command formula".into(),
            ));
        }

        // 6. Smuggled PE binary
        if s_lower.contains("tvqqaa")
            || s_lower.contains("tvqaia")
            || (s_lower.contains("tvq") && s_lower.contains("aaaa"))
            || s_lower.contains("this program cannot be run in dos mode")
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "handoutNotesMaster:smuggledBinary".into(),
                "PowerPoint handout or notes master contains smuggled Windows PE executable binary"
                    .into(),
            ));
        }

        results
    }

    fn scan_word_glossary_settings_or_font_table_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lower = String::from_utf8_lossy(data).to_ascii_lowercase();

        // 1. Remote UNC paths in glossary settings or font tables
        for (i, w) in data.windows(2).enumerate() {
            if (w == b"\\\\" || (w == b"//" && (i == 0 || data[i - 1] != b':')))
                && i + 4 < data.len()
            {
                let rest = &data[i..];
                let end = rest
                    .iter()
                    .position(|&b| {
                        b == 0
                            || b == b' '
                            || b == b'"'
                            || b == b'\''
                            || b == b'<'
                            || b == b'>'
                            || b == b'\r'
                            || b == b'\n'
                    })
                    .unwrap_or(rest.len().min(128));
                if let Some(unc) = (end > 4)
                    .then(|| std::str::from_utf8(&rest[..end]).ok())
                    .flatten()
                    .filter(|u| u.contains('\\') || u.contains('/'))
                {
                    results.push((
                        "High",
                        entry_name.to_string(),
                        "glossarySettings:uncCoercion".into(),
                        format!("Word glossary settings or font table references remote UNC resource '{unc}' (NTLM coercion vector)"),
                    ));
                    break;
                }
            }
        }

        // 2. Dangerous exploit URI schemes
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "mhtml:",
            "ms-appinstaller:",
            "powershell:",
            "javascript:",
            "vbscript:",
            "cmd:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "glossarySettings:dangerousProtocol".into(),
                    format!("Word glossary settings or font table references dangerous exploit URI scheme '{proto}'"),
                ));
            }
        }

        // 3. Staged shell execution commands
        for cmd in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "glossarySettings:stagedCommand".into(),
                    format!("Word glossary settings or font table contains staged shell execution command '{cmd}'"),
                ));
                break;
            }
        }

        // 4. Macro hooks or auto-execution directives in glossary settings
        if (s_lower.contains("attachedtemplate")
            || s_lower.contains("autonew")
            || s_lower.contains("autoopen")
            || s_lower.contains("document_open"))
            && (s_lower.contains("http://")
                || s_lower.contains("https://")
                || s_lower.contains("\\\\")
                || s_lower.contains("cmd")
                || s_lower.contains("powershell"))
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "glossarySettings:macroHook".into(),
                "Word glossary settings binds template or auto-execution hooks to remote/executable payload".into(),
            ));
        }

        // 5. External relationship targets pointing to executable / macro payloads
        if entry_name.ends_with(".rels") {
            for ext in &[
                ".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".hta", ".vbs", ".bat", ".ps1", ".exe",
            ] {
                if s_lower.contains(ext) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "glossarySettings:executableTarget".into(),
                        format!(
                            "Word glossary settings relationship targets weaponized payload '{ext}'"
                        ),
                    ));
                    break;
                }
            }
        }

        // 6. Smuggled PE binary
        if s_lower.contains("tvqqaa")
            || s_lower.contains("tvqaia")
            || (s_lower.contains("tvq") && s_lower.contains("aaaa"))
            || s_lower.contains("this program cannot be run in dos mode")
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "glossarySettings:smuggledBinary".into(),
                "Word glossary settings contains smuggled Windows PE executable binary".into(),
            ));
        }

        results
    }

    fn scan_excel_custom_property_or_custom_data_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lower = String::from_utf8_lossy(data).to_ascii_lowercase();

        // 1. Remote UNC paths in custom properties or custom data
        for (i, w) in data.windows(2).enumerate() {
            if (w == b"\\\\" || (w == b"//" && (i == 0 || data[i - 1] != b':')))
                && i + 4 < data.len()
            {
                let rest = &data[i..];
                let end = rest
                    .iter()
                    .position(|&b| {
                        b == 0
                            || b == b' '
                            || b == b'"'
                            || b == b'\''
                            || b == b'<'
                            || b == b'>'
                            || b == b'\r'
                            || b == b'\n'
                    })
                    .unwrap_or(rest.len().min(128));
                if let Some(unc) = (end > 4)
                    .then(|| std::str::from_utf8(&rest[..end]).ok())
                    .flatten()
                    .filter(|u| u.contains('\\') || u.contains('/'))
                {
                    results.push((
                        "High",
                        entry_name.to_string(),
                        "customData:uncCoercion".into(),
                        format!("Excel custom property or custom data references remote UNC resource '{unc}' (NTLM coercion vector)"),
                    ));
                    break;
                }
            }
        }

        // 2. Dangerous exploit URI schemes
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "mhtml:",
            "ms-appinstaller:",
            "powershell:",
            "javascript:",
            "vbscript:",
            "cmd:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "customData:dangerousProtocol".into(),
                    format!("Excel custom property or custom data references dangerous exploit URI scheme '{proto}'"),
                ));
            }
        }

        // 3. Staged shell execution commands
        for cmd in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "customData:stagedCommand".into(),
                    format!("Excel custom property or custom data contains staged shell execution command '{cmd}'"),
                ));
                break;
            }
        }

        // 4. External relationship targets pointing to executable / macro payloads
        if entry_name.ends_with(".rels") {
            for ext in &[
                ".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".hta", ".vbs", ".bat", ".ps1", ".exe",
            ] {
                if s_lower.contains(ext) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "customData:executableTarget".into(),
                        format!(
                            "Excel custom property or custom data relationship targets weaponized payload '{ext}'"
                        ),
                    ));
                    break;
                }
            }
        }

        // 5. Serialized .NET binary formatters / type confusion markers
        if s_lower.contains("system.windows.forms")
            || s_lower.contains("aaeaaad/////")
            || s_lower.contains("binaryformatter")
            || s_lower.contains("typeconvertersupervisor")
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "customData:serializedPayload".into(),
                "Excel custom property or custom data contains serialized .NET binary formatter payload".into(),
            ));
        }

        // 6. Smuggled PE binary
        if s_lower.contains("tvqqaa")
            || s_lower.contains("tvqaia")
            || (s_lower.contains("tvq") && s_lower.contains("aaaa"))
            || s_lower.contains("this program cannot be run in dos mode")
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "customData:smuggledBinary".into(),
                "Excel custom property or custom data contains smuggled Windows PE executable binary".into(),
            ));
        }

        results
    }

    fn scan_word_subdocument_or_master_document_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lower = String::from_utf8_lossy(data).to_ascii_lowercase();

        // 1. Remote UNC paths in subdocuments or master documents
        for (i, w) in data.windows(2).enumerate() {
            if (w == b"\\\\" || (w == b"//" && (i == 0 || data[i - 1] != b':')))
                && i + 4 < data.len()
            {
                let rest = &data[i..];
                let end = rest
                    .iter()
                    .position(|&b| {
                        b == 0
                            || b == b' '
                            || b == b'"'
                            || b == b'\''
                            || b == b'<'
                            || b == b'>'
                            || b == b'\r'
                            || b == b'\n'
                    })
                    .unwrap_or(rest.len().min(128));
                if let Some(unc) = (end > 4)
                    .then(|| std::str::from_utf8(&rest[..end]).ok())
                    .flatten()
                    .filter(|u| u.contains('\\') || u.contains('/'))
                {
                    results.push((
                        "High",
                        entry_name.to_string(),
                        "subDocument:uncCoercion".into(),
                        format!("Word subdocument or master document references remote UNC resource '{unc}' (NTLM coercion vector)"),
                    ));
                    break;
                }
            }
        }

        // 2. Dangerous exploit URI schemes
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "mhtml:",
            "ms-appinstaller:",
            "powershell:",
            "javascript:",
            "vbscript:",
            "cmd:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "subDocument:dangerousProtocol".into(),
                    format!("Word subdocument or master document references dangerous exploit URI scheme '{proto}'"),
                ));
            }
        }

        // 3. Staged shell execution commands
        for cmd in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "subDocument:stagedCommand".into(),
                    format!("Word subdocument or master document contains staged shell execution command '{cmd}'"),
                ));
                break;
            }
        }

        // 4. External relationship targets pointing to executable / macro payloads
        if entry_name.ends_with(".rels") {
            for ext in &[
                ".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".hta", ".vbs", ".bat", ".ps1", ".exe",
            ] {
                if s_lower.contains(ext) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "subDocument:executableTarget".into(),
                        format!("Word subdocument relationship targets weaponized payload '{ext}'"),
                    ));
                    break;
                }
            }
            if s_lower.contains("targetmode=\"external\"")
                && (s_lower.contains("http://")
                    || s_lower.contains("https://")
                    || s_lower.contains("\\\\"))
            {
                results.push((
                    "High",
                    entry_name.to_string(),
                    "subDocument:externalTarget".into(),
                    "Word subdocument relationship specifies external remote document target"
                        .into(),
                ));
            }
        }

        // 5. Smuggled PE binary
        if s_lower.contains("tvqqaa")
            || s_lower.contains("tvqaia")
            || (s_lower.contains("tvq") && s_lower.contains("aaaa"))
            || s_lower.contains("this program cannot be run in dos mode")
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "subDocument:smuggledBinary".into(),
                "Word subdocument or master document contains smuggled Windows PE executable binary".into(),
            ));
        }

        results
    }

    fn scan_powerpoint_font_table_or_embedded_font_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lower = String::from_utf8_lossy(data).to_ascii_lowercase();

        // 1. Remote UNC paths in font table or font parts
        for (i, w) in data.windows(2).enumerate() {
            if (w == b"\\\\" || (w == b"//" && (i == 0 || data[i - 1] != b':')))
                && i + 4 < data.len()
            {
                let rest = &data[i..];
                let end = rest
                    .iter()
                    .position(|&b| {
                        b == 0
                            || b == b' '
                            || b == b'"'
                            || b == b'\''
                            || b == b'<'
                            || b == b'>'
                            || b == b'\r'
                            || b == b'\n'
                    })
                    .unwrap_or(rest.len().min(128));
                if let Some(unc) = (end > 4)
                    .then(|| std::str::from_utf8(&rest[..end]).ok())
                    .flatten()
                    .filter(|u| u.contains('\\') || u.contains('/'))
                {
                    results.push((
                        "High",
                        entry_name.to_string(),
                        "pptFontTable:uncCoercion".into(),
                        format!("PowerPoint font table or embedded font part references remote UNC resource '{unc}' (NTLM coercion vector)"),
                    ));
                    break;
                }
            }
        }

        // 2. Dangerous exploit URI schemes
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "mhtml:",
            "ms-appinstaller:",
            "powershell:",
            "javascript:",
            "vbscript:",
            "cmd:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "pptFontTable:dangerousProtocol".into(),
                    format!("PowerPoint font table or embedded font part references dangerous exploit URI scheme '{proto}'"),
                ));
            }
        }

        // 3. Staged shell execution commands
        for cmd in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "pptFontTable:stagedCommand".into(),
                    format!("PowerPoint font table or embedded font part contains staged shell execution command '{cmd}'"),
                ));
                break;
            }
        }

        // 4. External relationship targets pointing to executable / macro payloads
        if entry_name.ends_with(".rels") {
            for ext in &[
                ".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".hta", ".vbs", ".bat", ".ps1", ".exe",
            ] {
                if s_lower.contains(ext) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "pptFontTable:executableTarget".into(),
                        format!(
                            "PowerPoint font table relationship targets weaponized payload '{ext}'"
                        ),
                    ));
                    break;
                }
            }
        }

        // 5. Smuggled PE binary (raw MZ header or Base64 PE)
        let is_raw_pe = data.len() >= 64 && data.starts_with(b"MZ") && {
            let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
            pe_offset + 4 <= data.len() && &data[pe_offset..pe_offset + 4] == b"PE\0\0"
        };

        if is_raw_pe
            || s_lower.contains("tvqqaa")
            || s_lower.contains("tvqaia")
            || (s_lower.contains("tvq") && s_lower.contains("aaaa"))
            || s_lower.contains("this program cannot be run in dos mode")
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "pptFontTable:smuggledBinary".into(),
                "PowerPoint font table or embedded font part contains smuggled Windows PE executable binary".into(),
            ));
        }

        results
    }

    fn scan_excel_query_table_or_data_feed_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lower = String::from_utf8_lossy(data).to_ascii_lowercase();

        // 1. Remote UNC paths in query tables or data feeds
        for (i, w) in data.windows(2).enumerate() {
            if (w == b"\\\\" || (w == b"//" && (i == 0 || data[i - 1] != b':')))
                && i + 4 < data.len()
            {
                let rest = &data[i..];
                let end = rest
                    .iter()
                    .position(|&b| {
                        b == 0
                            || b == b' '
                            || b == b'"'
                            || b == b'\''
                            || b == b'<'
                            || b == b'>'
                            || b == b'\r'
                            || b == b'\n'
                    })
                    .unwrap_or(rest.len().min(128));
                if let Some(unc) = (end > 4)
                    .then(|| std::str::from_utf8(&rest[..end]).ok())
                    .flatten()
                    .filter(|u| u.contains('\\') || u.contains('/'))
                {
                    results.push((
                        "High",
                        entry_name.to_string(),
                        "excelQueryTable:uncCoercion".into(),
                        format!("Excel query table or data feed connection references remote UNC resource '{unc}' (NTLM coercion vector)"),
                    ));
                    break;
                }
            }
        }

        // 2. Dangerous exploit URI schemes
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "mhtml:",
            "ms-appinstaller:",
            "powershell:",
            "javascript:",
            "vbscript:",
            "cmd:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "excelQueryTable:dangerousProtocol".into(),
                    format!("Excel query table or data feed connection references dangerous exploit URI scheme '{proto}'"),
                ));
            }
        }

        // 3. Staged shell execution commands
        for cmd in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "excelQueryTable:stagedCommand".into(),
                    format!("Excel query table or data feed connection contains staged shell execution command '{cmd}'"),
                ));
                break;
            }
        }

        // 4. Database command execution / SQL injection
        for proc in &[
            "xp_cmdshell",
            "sp_oacreate",
            "openrowset",
            "bulk insert",
            "into outfile",
            "into dumpfile",
        ] {
            if s_lower.contains(proc) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "excelQueryTable:commandInjection".into(),
                    format!("Excel query table or data feed connection contains dangerous database command execution procedure '{proc}'"),
                ));
                break;
            }
        }

        // 5. Cloaked DDE / command formulas in query table definitions
        if s_lower.contains("cmd|") || s_lower.contains("powershell|") || s_lower.contains("mshta|")
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "excelQueryTable:cloakedDde".into(),
                "Excel query table or data feed connection contains cloaked DDE command formula"
                    .into(),
            ));
        }

        // 6. External relationship targets pointing to executable / macro payloads
        if entry_name.ends_with(".rels") {
            for ext in &[
                ".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".hta", ".vbs", ".bat", ".ps1", ".exe",
            ] {
                if s_lower.contains(ext) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "excelQueryTable:executableTarget".into(),
                        format!(
                            "Excel query table relationship targets weaponized payload '{ext}'"
                        ),
                    ));
                    break;
                }
            }
        }

        // 7. Smuggled PE binary
        if s_lower.contains("tvqqaa")
            || s_lower.contains("tvqaia")
            || (s_lower.contains("tvq") && s_lower.contains("aaaa"))
            || s_lower.contains("this program cannot be run in dos mode")
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "excelQueryTable:smuggledBinary".into(),
                "Excel query table or data feed connection contains smuggled Windows PE executable binary".into(),
            ));
        }

        results
    }

    fn scan_powerpoint_slide_guide_or_grid_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lower = String::from_utf8_lossy(data).to_ascii_lowercase();

        // 1. Remote UNC paths in slide guides or grid definitions
        for (i, w) in data.windows(2).enumerate() {
            if (w == b"\\\\" || (w == b"//" && (i == 0 || data[i - 1] != b':')))
                && i + 4 < data.len()
            {
                let rest = &data[i..];
                let end = rest
                    .iter()
                    .position(|&b| {
                        b == 0
                            || b == b' '
                            || b == b'"'
                            || b == b'\''
                            || b == b'<'
                            || b == b'>'
                            || b == b'\r'
                            || b == b'\n'
                    })
                    .unwrap_or(rest.len().min(128));
                if let Some(unc) = (end > 4)
                    .then(|| std::str::from_utf8(&rest[..end]).ok())
                    .flatten()
                    .filter(|u| u.contains('\\') || u.contains('/'))
                {
                    results.push((
                        "High",
                        entry_name.to_string(),
                        "slideGuide:uncCoercion".into(),
                        format!("PowerPoint slide guide or grid definition references remote UNC resource '{unc}' (NTLM coercion vector)"),
                    ));
                    break;
                }
            }
        }

        // 2. Dangerous exploit URI schemes
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "mhtml:",
            "ms-appinstaller:",
            "powershell:",
            "javascript:",
            "vbscript:",
            "cmd:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "slideGuide:dangerousProtocol".into(),
                    format!("PowerPoint slide guide or grid definition references dangerous exploit URI scheme '{proto}'"),
                ));
            }
        }

        // 3. Staged shell execution commands
        for cmd in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "slideGuide:stagedCommand".into(),
                    format!("PowerPoint slide guide or grid definition contains staged shell execution command '{cmd}'"),
                ));
                break;
            }
        }

        // 4. External relationships targeting weaponized payloads
        if entry_name.ends_with(".rels") {
            for ext in &[
                ".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".hta", ".vbs", ".bat", ".ps1", ".exe",
            ] {
                if s_lower.contains(ext) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "slideGuide:executableTarget".into(),
                        format!(
                            "PowerPoint slide guide relationship targets weaponized payload '{ext}'"
                        ),
                    ));
                    break;
                }
            }
        }

        // 5. Smuggled PE binary
        if s_lower.contains("tvqqaa")
            || s_lower.contains("tvqaia")
            || (s_lower.contains("tvq") && s_lower.contains("aaaa"))
            || s_lower.contains("this program cannot be run in dos mode")
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "slideGuide:smuggledBinary".into(),
                "PowerPoint slide guide or grid definition contains smuggled Windows PE executable binary".into(),
            ));
        }

        results
    }

    fn scan_word_mail_merge_filter_or_recipient_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lower = String::from_utf8_lossy(data).to_ascii_lowercase();

        // 1. Remote UNC paths in mail merge filter or recipient data
        for (i, w) in data.windows(2).enumerate() {
            if (w == b"\\\\" || (w == b"//" && (i == 0 || data[i - 1] != b':')))
                && i + 4 < data.len()
            {
                let rest = &data[i..];
                let end = rest
                    .iter()
                    .position(|&b| {
                        b == 0
                            || b == b' '
                            || b == b'"'
                            || b == b'\''
                            || b == b'<'
                            || b == b'>'
                            || b == b'\r'
                            || b == b'\n'
                    })
                    .unwrap_or(rest.len().min(128));
                if let Some(unc) = (end > 4)
                    .then(|| std::str::from_utf8(&rest[..end]).ok())
                    .flatten()
                    .filter(|u| u.contains('\\') || u.contains('/'))
                {
                    results.push((
                        "High",
                        entry_name.to_string(),
                        "mailMergeFilter:uncCoercion".into(),
                        format!("Word mail merge filter or recipient data references remote UNC resource '{unc}' (NTLM coercion vector)"),
                    ));
                    break;
                }
            }
        }

        // 2. Dangerous exploit URI schemes
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "mhtml:",
            "ms-appinstaller:",
            "powershell:",
            "javascript:",
            "vbscript:",
            "cmd:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "mailMergeFilter:dangerousProtocol".into(),
                    format!("Word mail merge filter or recipient data references dangerous exploit URI scheme '{proto}'"),
                ));
            }
        }

        // 3. Staged shell execution commands
        for cmd in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "mailMergeFilter:stagedCommand".into(),
                    format!("Word mail merge filter or recipient data contains staged shell execution command '{cmd}'"),
                ));
                break;
            }
        }

        // 4. Database command execution / SQL injection
        for proc in &[
            "xp_cmdshell",
            "sp_oacreate",
            "openrowset",
            "bulk insert",
            "into outfile",
            "into dumpfile",
        ] {
            if s_lower.contains(proc) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "mailMergeFilter:commandInjection".into(),
                    format!("Word mail merge filter or recipient data contains dangerous database command execution procedure '{proc}'"),
                ));
                break;
            }
        }

        // 5. External relationships targeting weaponized payloads
        if entry_name.ends_with(".rels") {
            for ext in &[
                ".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".hta", ".vbs", ".bat", ".ps1", ".exe",
            ] {
                if s_lower.contains(ext) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "mailMergeFilter:executableTarget".into(),
                        format!(
                            "Word mail merge filter relationship targets weaponized payload '{ext}'"
                        ),
                    ));
                    break;
                }
            }
        }

        // 6. Smuggled PE binary
        if s_lower.contains("tvqqaa")
            || s_lower.contains("tvqaia")
            || (s_lower.contains("tvq") && s_lower.contains("aaaa"))
            || s_lower.contains("this program cannot be run in dos mode")
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "mailMergeFilter:smuggledBinary".into(),
                "Word mail merge filter or recipient data contains smuggled Windows PE executable binary".into(),
            ));
        }

        results
    }

    fn scan_excel_external_data_feed_or_service_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lower = String::from_utf8_lossy(data).to_ascii_lowercase();

        // 1. Remote UNC endpoints in external data feeds or data services
        for (i, w) in data.windows(2).enumerate() {
            if (w == b"\\\\" || (w == b"//" && (i == 0 || data[i - 1] != b':')))
                && i + 4 < data.len()
            {
                let rest = &data[i..];
                let end = rest
                    .iter()
                    .position(|&b| {
                        b == 0
                            || b == b' '
                            || b == b'"'
                            || b == b'\''
                            || b == b'<'
                            || b == b'>'
                            || b == b'\r'
                            || b == b'\n'
                    })
                    .unwrap_or(rest.len().min(128));
                if let Some(unc) = (end > 4)
                    .then(|| std::str::from_utf8(&rest[..end]).ok())
                    .flatten()
                    .filter(|u| u.contains('\\') || u.contains('/'))
                {
                    results.push((
                        "High",
                        entry_name.to_string(),
                        "excelDataService:uncCoercion".into(),
                        format!("Excel external data feed or data service references remote UNC endpoint '{unc}' (NTLM coercion vector)"),
                    ));
                    break;
                }
            }
        }

        // 2. Dangerous exploit URI schemes
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "mhtml:",
            "ms-appinstaller:",
            "powershell:",
            "javascript:",
            "vbscript:",
            "cmd:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "excelDataService:dangerousProtocol".into(),
                    format!("Excel external data feed or data service references dangerous exploit URI scheme '{proto}'"),
                ));
            }
        }

        // 3. Staged shell execution commands
        for cmd in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "excelDataService:stagedCommand".into(),
                    format!("Excel external data feed or data service contains staged shell execution command '{cmd}'"),
                ));
                break;
            }
        }

        // 4. Database command execution / SQL injection
        for proc in &[
            "xp_cmdshell",
            "sp_oacreate",
            "openrowset",
            "bulk insert",
            "into outfile",
            "into dumpfile",
        ] {
            if s_lower.contains(proc) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "excelDataService:commandInjection".into(),
                    format!("Excel external data feed or data service contains dangerous database command execution procedure '{proc}'"),
                ));
                break;
            }
        }

        // 5. Cloaked DDE / command formulas in data services
        if s_lower.contains("cmd|") || s_lower.contains("powershell|") || s_lower.contains("mshta|")
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "excelDataService:cloakedDde".into(),
                "Excel external data feed or data service contains cloaked DDE command formula"
                    .into(),
            ));
        }

        // 6. External relationship targets pointing to executable / macro payloads
        if entry_name.ends_with(".rels") {
            for ext in &[
                ".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".hta", ".vbs", ".bat", ".ps1", ".exe",
            ] {
                if s_lower.contains(ext) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "excelDataService:executableTarget".into(),
                        format!(
                            "Excel external data feed relationship targets weaponized payload '{ext}'"
                        ),
                    ));
                    break;
                }
            }
        }

        // 7. Smuggled PE binary
        if s_lower.contains("tvqqaa")
            || s_lower.contains("tvqaia")
            || (s_lower.contains("tvq") && s_lower.contains("aaaa"))
            || s_lower.contains("this program cannot be run in dos mode")
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "excelDataService:smuggledBinary".into(),
                "Excel external data feed or data service contains smuggled Windows PE executable binary".into(),
            ));
        }

        results
    }

    fn scan_powerpoint_slide_master_or_layout_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lower = String::from_utf8_lossy(data).to_ascii_lowercase();

        // 1. Remote UNC endpoints in slide master or layout parts
        for (i, w) in data.windows(2).enumerate() {
            if (w == b"\\\\" || (w == b"//" && (i == 0 || data[i - 1] != b':')))
                && i + 4 < data.len()
            {
                let rest = &data[i..];
                let end = rest
                    .iter()
                    .position(|&b| {
                        b == 0
                            || b == b' '
                            || b == b'"'
                            || b == b'\''
                            || b == b'<'
                            || b == b'>'
                            || b == b'\r'
                            || b == b'\n'
                    })
                    .unwrap_or(rest.len().min(128));
                if let Some(unc) = (end > 4)
                    .then(|| std::str::from_utf8(&rest[..end]).ok())
                    .flatten()
                    .filter(|u| u.contains('\\') || u.contains('/'))
                {
                    results.push((
                        "High",
                        entry_name.to_string(),
                        "slideMaster:uncCoercion".into(),
                        format!("PowerPoint slide master or layout references remote UNC endpoint '{unc}' (NTLM coercion vector)"),
                    ));
                    break;
                }
            }
        }

        // 2. Dangerous exploit URI schemes
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "mhtml:",
            "ms-appinstaller:",
            "powershell:",
            "javascript:",
            "vbscript:",
            "cmd:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "slideMaster:dangerousProtocol".into(),
                    format!("PowerPoint slide master or layout references dangerous exploit URI scheme '{proto}'"),
                ));
            }
        }

        // 3. Staged shell execution commands
        for cmd in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "slideMaster:stagedCommand".into(),
                    format!("PowerPoint slide master or layout contains staged shell execution command '{cmd}'"),
                ));
                break;
            }
        }

        // 4. Cloaked DDE / command formulas
        if s_lower.contains("cmd|") || s_lower.contains("powershell|") || s_lower.contains("mshta|")
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "slideMaster:cloakedDde".into(),
                "PowerPoint slide master or layout contains cloaked DDE command formula".into(),
            ));
        }

        // 5. External relationships targeting weaponized payloads
        if entry_name.ends_with(".rels") {
            for ext in &[
                ".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".hta", ".vbs", ".bat", ".ps1", ".exe",
            ] {
                if s_lower.contains(ext) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "slideMaster:executableTarget".into(),
                        format!(
                            "PowerPoint slide master relationship targets weaponized payload '{ext}'"
                        ),
                    ));
                    break;
                }
            }
        }

        // 6. Smuggled PE binary
        if s_lower.contains("tvqqaa")
            || s_lower.contains("tvqaia")
            || (s_lower.contains("tvq") && s_lower.contains("aaaa"))
            || s_lower.contains("this program cannot be run in dos mode")
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "slideMaster:smuggledBinary".into(),
                "PowerPoint slide master or layout contains smuggled Windows PE executable binary"
                    .into(),
            ));
        }

        results
    }

    fn scan_word_document_template_or_attached_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lower = String::from_utf8_lossy(data).to_ascii_lowercase();

        // 1. Remote UNC endpoints in attached template or template settings
        for (i, w) in data.windows(2).enumerate() {
            if (w == b"\\\\" || (w == b"//" && (i == 0 || data[i - 1] != b':')))
                && i + 4 < data.len()
            {
                let rest = &data[i..];
                let end = rest
                    .iter()
                    .position(|&b| {
                        b == 0
                            || b == b' '
                            || b == b'"'
                            || b == b'\''
                            || b == b'<'
                            || b == b'>'
                            || b == b'\r'
                            || b == b'\n'
                    })
                    .unwrap_or(rest.len().min(128));
                if let Some(unc) = (end > 4)
                    .then(|| std::str::from_utf8(&rest[..end]).ok())
                    .flatten()
                    .filter(|u| u.contains('\\') || u.contains('/'))
                {
                    results.push((
                        "High",
                        entry_name.to_string(),
                        "attachedTemplate:uncCoercion".into(),
                        format!("Word attached template references remote UNC path '{unc}' (NTLM coercion vector)"),
                    ));
                    break;
                }
            }
        }

        // 2. Dangerous exploit URI schemes
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "mhtml:",
            "ms-appinstaller:",
            "powershell:",
            "javascript:",
            "vbscript:",
            "cmd:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "attachedTemplate:dangerousProtocol".into(),
                    format!(
                        "Word document template references dangerous exploit URI scheme '{proto}'"
                    ),
                ));
            }
        }

        // 3. Staged shell execution commands
        for cmd in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "attachedTemplate:stagedCommand".into(),
                    format!(
                        "Word document template contains staged shell execution command '{cmd}'"
                    ),
                ));
                break;
            }
        }

        // 4. External relationships targeting weaponized payloads
        if entry_name.ends_with(".rels") || s_lower.contains("attachedtemplate") {
            for ext in &[
                ".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".hta", ".vbs", ".bat", ".ps1", ".exe",
            ] {
                if s_lower.contains(ext) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "attachedTemplate:executableTarget".into(),
                        format!("Word attached template targets weaponized payload '{ext}'"),
                    ));
                    break;
                }
            }
        }

        // 5. Smuggled PE binary
        if s_lower.contains("tvqqaa")
            || s_lower.contains("tvqaia")
            || (s_lower.contains("tvq") && s_lower.contains("aaaa"))
            || s_lower.contains("this program cannot be run in dos mode")
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "attachedTemplate:smuggledBinary".into(),
                "Word attached template contains smuggled Windows PE executable binary".into(),
            ));
        }

        results
    }

    fn scan_excel_xml_spreadsheet_or_binding_threats(
        entry_name: &str,
        data: &[u8],
    ) -> Vec<(&'static str, String, String, String)> {
        let mut results = Vec::new();
        let s_lower = String::from_utf8_lossy(data).to_ascii_lowercase();

        // 1. Remote UNC endpoints in XML maps or data bindings
        for (i, w) in data.windows(2).enumerate() {
            if (w == b"\\\\" || (w == b"//" && (i == 0 || data[i - 1] != b':')))
                && i + 4 < data.len()
            {
                let rest = &data[i..];
                let end = rest
                    .iter()
                    .position(|&b| {
                        b == 0
                            || b == b' '
                            || b == b'"'
                            || b == b'\''
                            || b == b'<'
                            || b == b'>'
                            || b == b'\r'
                            || b == b'\n'
                    })
                    .unwrap_or(rest.len().min(128));
                if let Some(unc) = (end > 4)
                    .then(|| std::str::from_utf8(&rest[..end]).ok())
                    .flatten()
                    .filter(|u| u.contains('\\') || u.contains('/'))
                {
                    results.push((
                        "High",
                        entry_name.to_string(),
                        "xmlBinding:uncCoercion".into(),
                        format!("Excel XML data binding references remote UNC endpoint '{unc}' (NTLM coercion vector)"),
                    ));
                    break;
                }
            }
        }

        // 2. Dangerous exploit URI schemes
        for proto in &[
            "ms-msdt:",
            "search-ms:",
            "mhtml:",
            "ms-appinstaller:",
            "powershell:",
            "javascript:",
            "vbscript:",
            "cmd:",
        ] {
            if s_lower.contains(proto) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "xmlBinding:dangerousProtocol".into(),
                    format!(
                        "Excel XML data binding references dangerous exploit URI scheme '{proto}'"
                    ),
                ));
            }
        }

        // 3. Database command execution / SQL injection
        for proc in &[
            "xp_cmdshell",
            "sp_oacreate",
            "openrowset",
            "bulk insert",
            "into outfile",
            "into dumpfile",
        ] {
            if s_lower.contains(proc) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "xmlBinding:commandInjection".into(),
                    format!("Excel XML data binding contains dangerous database command execution procedure '{proc}'"),
                ));
                break;
            }
        }

        // 4. Staged shell execution commands
        for cmd in &[
            "powershell",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta",
            "rundll32",
            "certutil",
        ] {
            if s_lower.contains(cmd) {
                results.push((
                    "Critical",
                    entry_name.to_string(),
                    "xmlBinding:stagedCommand".into(),
                    format!(
                        "Excel XML data binding contains staged shell execution command '{cmd}'"
                    ),
                ));
                break;
            }
        }

        // 5. Cloaked DDE / command formulas
        if s_lower.contains("cmd|") || s_lower.contains("powershell|") || s_lower.contains("mshta|")
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "xmlBinding:cloakedDde".into(),
                "Excel XML data binding contains cloaked DDE command formula".into(),
            ));
        }

        // 6. External relationships targeting weaponized payloads
        if entry_name.ends_with(".rels") {
            for ext in &[
                ".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".hta", ".vbs", ".bat", ".ps1", ".exe",
            ] {
                if s_lower.contains(ext) {
                    results.push((
                        "Critical",
                        entry_name.to_string(),
                        "xmlBinding:executableTarget".into(),
                        format!(
                            "Excel XML data binding relationship targets weaponized payload '{ext}'"
                        ),
                    ));
                    break;
                }
            }
        }

        // 7. Smuggled PE binary
        if s_lower.contains("tvqqaa")
            || s_lower.contains("tvqaia")
            || (s_lower.contains("tvq") && s_lower.contains("aaaa"))
            || s_lower.contains("this program cannot be run in dos mode")
        {
            results.push((
                "Critical",
                entry_name.to_string(),
                "xmlBinding:smuggledBinary".into(),
                "Excel XML data binding contains smuggled Windows PE executable binary".into(),
            ));
        }

        results
    }

    // 1. Inspect package parts / entry names for embedded binaries and controls
    for entry in zip.entries.iter().take(max_entries) {
        let name_lower = entry.name.to_ascii_lowercase();
        let is_dir = entry.name.ends_with('/') || entry.name.ends_with('\\');
        if is_dir {
            continue;
        }

        // Check for smuggled standalone payload binaries or scripts (VBA-CELL-032)
        let entry_bytes_res = zip.read(entry);
        let entry_bytes_opt = entry_bytes_res.as_deref().ok();
        if let Some((sev, subtype, reason)) =
            scan_container_smuggled_payload(&entry.name, entry_bytes_opt)
        {
            let coord = format!("part:{}", entry.name);
            if !threats.iter().any(|t| t.coordinate == coord) {
                let desc = format!(
                    "Smuggled container payload or executable binary detected in part '{}': {reason}",
                    entry.name
                );
                diagnostics.push(format!("Security warning: {desc}"));
                threats.push(CellThreat {
                    sheet_name: "Package".into(),
                    cell_ref: entry.name.clone(),
                    coordinate: coord,
                    threat_kind: "SmuggledContainerPayload".into(),
                    severity: sev.into(),
                    formula: subtype.into(),
                    description: desc,
                });
            }
        }

        // Check for Worksheet View Evasion (VBA-CELL-033)
        let is_worksheet_xml = (name_lower.starts_with("xl/worksheets/sheet")
            || name_lower.contains("/xl/worksheets/sheet")
            || name_lower.contains("\\xl\\worksheets\\sheet")
            || name_lower.starts_with("worksheets/sheet"))
            && name_lower.ends_with(".xml");
        if is_worksheet_xml && let Ok(ref data) = entry_bytes_res {
            let s = String::from_utf8_lossy(data);
            for (sev, cell_ref, coord_suffix, reason) in scan_worksheet_view_evasion(&s) {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Worksheet view evasion detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: entry.name.clone(),
                        cell_ref,
                        coordinate: coord,
                        threat_kind: "WorksheetViewEvasion".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for ActiveX XML declaration anomalies (VBA-CELL-034)
        let is_activex_xml = (name_lower.contains("/activex/")
            || name_lower.starts_with("activex/")
            || name_lower.contains("\\activex\\"))
            && name_lower.ends_with(".xml");
        if is_activex_xml && let Ok(ref data) = entry_bytes_res {
            let s = String::from_utf8_lossy(data);
            for (sev, target_id, coord_suffix, reason) in scan_activex_xml_declarations(&s) {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "ActiveX object declaration anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "ActiveX".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "ActiveXObjectDeclaration".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Word Glossary Document Anomaly (VBA-CELL-035)
        let is_glossary = name_lower.starts_with("word/glossary/")
            || name_lower.contains("/glossary/")
            || name_lower.contains("\\glossary\\");
        if is_glossary && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_word_glossary_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Word glossary document anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "Glossary".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "GlossaryDocumentAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Embedded Font Obfuscation or Smuggling (VBA-CELL-036)
        let is_font_part = name_lower.contains("fonttable")
            || name_lower.ends_with(".odttf")
            || name_lower.ends_with(".ttf")
            || name_lower.ends_with(".woff")
            || name_lower.contains("/fonts/")
            || name_lower.starts_with("fonts/")
            || name_lower.contains("\\fonts\\");
        if is_font_part && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_embedded_font_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Embedded font obfuscation or payload smuggling detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "Fonts".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "EmbeddedFontSmuggling".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Digital Ink Definition Anomaly (VBA-CELL-037)
        let is_ink_part = name_lower.contains("/ink/")
            || name_lower.starts_with("ink/")
            || name_lower.contains("\\ink\\")
            || name_lower.ends_with(".isf")
            || (name_lower.contains("ink")
                && (name_lower.ends_with(".xml") || name_lower.ends_with(".bin")));
        if is_ink_part && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_digital_ink_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Digital ink definition anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "DigitalInk".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "DigitalInkDefinitionAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Document Property Payload Smuggling (VBA-CELL-038)
        let is_docprops = name_lower.starts_with("docprops/")
            || name_lower.contains("/docprops/")
            || name_lower.contains("\\docprops\\")
            || name_lower.ends_with("core.xml")
            || name_lower.ends_with("app.xml")
            || name_lower.ends_with("custom.xml");
        if is_docprops && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_document_property_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Document property payload smuggling detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "DocProps".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "DocumentPropertyPayloadSmuggling".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Web Extension or Taskpane Anomaly (VBA-CELL-039)
        let is_webext = name_lower.contains("webextension") || name_lower.contains("taskpane");
        if is_webext && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_web_extension_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Web extension or taskpane anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "WebExtension".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "WebExtensionOrTaskpaneAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for PivotCache Data Connection Anomaly (VBA-CELL-040)
        let is_pivot_cache = name_lower.contains("pivotcache");
        if is_pivot_cache && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_pivot_cache_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "PivotCache data connection anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "PivotCache".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "PivotCacheDataConnectionAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Metafile Exploit or Payload Smuggling (VBA-CELL-041)
        let is_metafile = name_lower.ends_with(".wmf")
            || name_lower.ends_with(".emf")
            || ((name_lower.starts_with("word/media/")
                || name_lower.starts_with("xl/media/")
                || name_lower.starts_with("ppt/media/"))
                && (name_lower.contains(".wmf") || name_lower.contains(".emf")));
        if is_metafile && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in scan_metafile_threats(&entry.name, data) {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Metafile exploit or payload smuggling detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "Metafile".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "MetafileExploitOrPayloadSmuggling".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for XSLT Transform or Script Injection (VBA-CELL-042)
        let is_xslt_part = name_lower.ends_with(".xsl")
            || name_lower.ends_with(".xslt")
            || name_lower.ends_with("styles.xml")
            || name_lower.ends_with("settings.xml")
            || name_lower.contains("customxml");
        if is_xslt_part && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_xslt_transform_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "XSLT transform or script injection detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "XSLT".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "XsltTransformOrScriptInjection".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Relationship Target Cloaking or Evasion (VBA-CELL-043)
        let is_rels_part = name_lower.ends_with(".rels");
        if is_rels_part && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_relationship_cloaking_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Relationship target cloaking or evasion detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "Package".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "RelationshipTargetCloakingOrEvasion".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for SmartArt / Diagram Manipulation & Payload Smuggling (VBA-CELL-044)
        let is_diagram_part = name_lower.contains("/diagrams/")
            || name_lower.starts_with("diagrams/")
            || (name_lower.contains("diagram") && name_lower.ends_with(".xml"))
            || (name_lower.contains("diagrams") && name_lower.ends_with(".rels"));
        if is_diagram_part && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_smartart_diagram_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "SmartArt diagram payload or action anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "Diagram".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "SmartArtOrDiagramPayloadAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Word MailMerge Coercion & External Source Hijacking (VBA-CELL-045)
        let is_mail_merge_part = name_lower.ends_with("settings.xml")
            || name_lower.ends_with("settings.xml.rels")
            || name_lower.contains("mailmerge");
        if is_mail_merge_part && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in scan_mail_merge_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Word MailMerge data source or coercion anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "MailMerge".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "MailMergeDataSourceOrCoercionAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Excel QueryTable & External Query Threats (VBA-CELL-046)
        let is_query_table_part = name_lower.contains("querytable");
        if is_query_table_part && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_query_table_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Excel QueryTable or external query anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "QueryTable".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "QueryTableOrExternalQueryAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Excel Data Mashup / Power Query Formula Anomaly (VBA-CELL-047)
        let is_pq_candidate = name_lower.contains("powerquery")
            || name_lower.contains("datamashup")
            || name_lower.contains("mashup")
            || name_lower.contains("customxml")
            || name_lower.contains("customdata");
        if is_pq_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_power_query_mashup_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Power Query formula or Data Mashup anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "PowerQuery".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "PowerQueryFormulaOrMashupAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for OLE Object / Package Moniker CLSID Activation Anomaly (VBA-CELL-048)
        let is_moniker_candidate = name_lower.contains("document.xml")
            || name_lower.contains("sheet")
            || name_lower.contains("slide")
            || name_lower.contains("drawing")
            || name_lower.contains("oleobject")
            || name_lower.contains("package")
            || name_lower.contains("embeddings/")
            || name_lower.ends_with(".rels");
        if is_moniker_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_package_moniker_activation_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "OLE Package Moniker or activation anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "Moniker".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "PackageMonikerOrActivationAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for XML Namespace Cloaking & Schema Spoofing Anomaly (VBA-CELL-049)
        let is_xml_part = name_lower.ends_with(".xml") || name_lower.ends_with(".rels");
        if is_xml_part && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_namespace_cloaking_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "XML namespace cloaking or schema spoofing detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "Namespace".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "NamespaceCloakingOrSchemaSpoofingAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Excel Slicer & Timeline Cache Hijacking (VBA-CELL-050)
        let is_slicer_timeline_part =
            name_lower.contains("slicer") || name_lower.contains("timeline");
        if is_slicer_timeline_part && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_slicer_timeline_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Excel Slicer or Timeline cache anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "SlicerTimeline".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "SlicerOrTimelineCacheAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Word Bibliography & Citation Threats (VBA-CELL-051)
        let is_bib_candidate = name_lower.contains("bibliography")
            || name_lower.contains("sources.xml")
            || name_lower.contains("customxml");
        if is_bib_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_bibliography_citation_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Word Bibliography or Citation anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "Bibliography".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "BibliographyOrCitationAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Custom XML Data Binding & XPath Injection (VBA-CELL-052)
        let is_databinding_candidate = name_lower.ends_with(".xml")
            && (name_lower.contains("document")
                || name_lower.contains("header")
                || name_lower.contains("footer")
                || name_lower.contains("slide")
                || name_lower.contains("sheet")
                || name_lower.contains("customxml"));
        if is_databinding_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_custom_xml_databinding_xpath_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Custom XML data binding or XPath anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "DataBinding".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "CustomXmlDataBindingOrXPathAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for XML Maps & Schema Definition Anomaly (VBA-CELL-053)
        let is_xmlmaps_candidate = name_lower.contains("xmlmap")
            || (name_lower.contains("table")
                && (name_lower.ends_with(".xml") || name_lower.ends_with(".rels")));
        if is_xmlmaps_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in scan_xmlmaps_threats(&entry.name, data) {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Excel XML Map or Schema definition anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "XmlMap".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "XmlMapsOrSchemaDefinitionAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Document Comment & Modern Annotation Anomaly (VBA-CELL-054)
        let is_comment_candidate = name_lower.contains("comment");
        if is_comment_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_comment_annotation_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Document Comment or Annotation anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "Comment".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "CommentAnnotationOrAuthorAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Office Theme Font & Effect Coercion Anomaly (VBA-CELL-055)
        let is_theme_candidate = name_lower.contains("theme");
        if is_theme_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in scan_theme_font_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Office Theme Font or Effect coercion anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "Theme".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "ThemeFontOrEffectCoercionAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for CustomXML Properties or Item Schema Anomaly (VBA-CELL-056)
        let is_customxml_candidate =
            name_lower.contains("customxml") || name_lower.contains("itemprops");
        if is_customxml_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_customxml_properties_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "CustomXML properties or item schema anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "CustomXml".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "CustomXmlPropertiesOrItemSchemaAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for VBA Project Relationship or Data Stream Anomaly (VBA-CELL-057)
        let is_vba_rels_or_data_candidate = name_lower.contains("vbaproject")
            || name_lower.contains("vbadata")
            || (name_lower.contains("vba") && name_lower.contains("_rels"));
        if is_vba_rels_or_data_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_vbaproject_rels_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "VBA Project relationship or data stream anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "VbaProject".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "VbaDataStreamOrProjectRelsAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Word Glossary or Building Blocks Relationship Anomaly (VBA-CELL-058)
        let is_glossary_candidate =
            name_lower.contains("glossary") || name_lower.contains("buildingblocks");
        if is_glossary_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_word_glossary_rels_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Word glossary or building blocks relationship anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "Glossary".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "WordGlossaryOrBuildingBlocksRelsAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Word Document Variables and Footnotes/Endnotes Anomaly (VBA-CELL-059)
        let is_word_docvars_or_notes_candidate = name_lower.contains("settings")
            || name_lower.contains("footnote")
            || name_lower.contains("endnote");
        if is_word_docvars_or_notes_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_word_docvars_and_notes_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Word document variables or footnotes/endnotes anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "WordDocVars".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "WordDocVariablesOrNotesAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for PowerPoint Tags, Masters, & Font Table Anomaly (VBA-CELL-060)
        let is_ppt_tags_or_masters_candidate = name_lower.contains("ppt/")
            || name_lower.starts_with("ppt/")
            || name_lower.contains("tag")
            || name_lower.contains("handoutmaster")
            || name_lower.contains("notesmaster");
        if is_ppt_tags_or_masters_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_powerpoint_tags_and_masters_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "PowerPoint programmable tags or masters anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "PowerPoint".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "PowerPointTagsOrMastersAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Excel Scenario Manager & Data Consolidation Anomaly (VBA-CELL-061)
        let is_scenario_consolidation_candidate = name_lower.contains("scenario")
            || name_lower.contains("consolidation")
            || (name_lower.contains("sheet") && name_lower.ends_with(".xml"));
        if is_scenario_consolidation_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_scenario_manager_consolidation_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Excel Scenario Manager or Data Consolidation anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "ScenarioManager".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "ScenarioManagerOrConsolidationAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for PowerPoint Animation & TimeNode Anomaly (VBA-CELL-062)
        let is_ppt_animation_timenode_candidate = name_lower.contains("ppt/slides/")
            || name_lower.contains("slidelayout")
            || name_lower.contains("slidemaster")
            || (name_lower.starts_with("ppt/") && name_lower.contains("timing"))
            || (name_lower.ends_with(".rels") && name_lower.contains("slide"));
        if is_ppt_animation_timenode_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_powerpoint_animation_timenode_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "PowerPoint animation or timenode anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "PowerPointAnimation".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "PowerPointAnimationOrTimeNodeAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Word Header/Footer & Watermark Anomaly (VBA-CELL-063)
        let is_word_header_footer_candidate = name_lower.contains("word/header")
            || name_lower.contains("word/footer")
            || name_lower.contains("word/_rels/header")
            || name_lower.contains("word/_rels/footer")
            || (name_lower.starts_with("word/")
                && (name_lower.contains("header") || name_lower.contains("footer")));
        if is_word_header_footer_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_word_header_footer_watermark_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Word header/footer or watermark anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "WordHeaderFooter".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "WordHeaderFooterOrWatermarkAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Excel DataModel & Formula Cache Anomaly (VBA-CELL-064)
        let is_datamodel_or_formula_cache_candidate = name_lower.contains("datamodel")
            || name_lower.contains("model/")
            || (name_lower.contains("sheet") && name_lower.ends_with(".xml"));
        if is_datamodel_or_formula_cache_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_excel_datamodel_formula_cache_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Excel DataModel or Formula Cache anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "ExcelDataModel".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "ExcelDataModelOrFormulaCacheAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Excel PivotCache and Definition Anomaly (VBA-CELL-065)
        let is_pivot_cache_candidate = name_lower.contains("pivotcache")
            || name_lower.contains("pivottable")
            || (name_lower.contains("pivot")
                && (name_lower.ends_with(".xml") || name_lower.ends_with(".rels")));
        if is_pivot_cache_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_excel_pivot_cache_and_definition_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Excel PivotCache or definition anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "PivotCache".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "ExcelPivotCacheOrDefinitionAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Word & PowerPoint Embedded Package Anomaly (VBA-CELL-066)
        let is_embedded_package_candidate = name_lower.contains("/embeddings/")
            || name_lower.contains("/embedding/")
            || name_lower.starts_with("embeddings/")
            || name_lower.starts_with("word/embeddings/")
            || name_lower.starts_with("ppt/embeddings/")
            || ((name_lower.contains("oleobject") || name_lower.contains("package"))
                && (name_lower.ends_with(".bin") || name_lower.ends_with(".rels")))
            || (name_lower.ends_with(".rels")
                && (name_lower.contains("document") || name_lower.contains("slide")))
            || (name_lower.ends_with(".xml")
                && (name_lower.contains("document") || name_lower.contains("slide")));
        if is_embedded_package_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_word_powerpoint_embedded_package_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Word or PowerPoint embedded package anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "EmbeddedPackage".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "WordOrPowerPointEmbeddedPackageAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Excel External Workbook & Sheet Path Anomaly (VBA-CELL-067)
        let is_external_link_candidate = name_lower.contains("externallink")
            || (name_lower.contains("externallinks") && name_lower.ends_with(".rels"));
        if is_external_link_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_excel_external_book_and_sheet_path_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Excel external workbook or sheet path anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "ExternalBook".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "ExcelExternalBookOrSheetPathAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for ActiveX Binary Storage or Property Stream Anomaly (VBA-CELL-068)
        let is_activex_binary_candidate = name_lower.contains("activex")
            && (name_lower.ends_with(".bin")
                || name_lower.ends_with(".dat")
                || name_lower.ends_with(".ocx")
                || name_lower.ends_with(".ole"));
        if is_activex_binary_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_activex_binary_storage_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "ActiveX binary storage or property stream anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "ActiveXBinary".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "ActiveXBinaryStorageOrPropertyStreamAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for XML Digital Signature or Origin Part Anomaly (VBA-CELL-069)
        let is_xml_sig_candidate = name_lower.contains("xmlsignatures")
            || name_lower.contains("package.sigs")
            || (name_lower.contains("sig")
                && (name_lower.ends_with(".xml")
                    || name_lower.ends_with(".sigs")
                    || name_lower.ends_with(".rels")));
        if is_xml_sig_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_xml_digital_signature_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "XML digital signature or origin part anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "DigitalSignature".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "XmlDigitalSignatureOrOriginPartAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Excel Control Properties or Form Action Anomaly (VBA-CELL-070)
        let is_ctrl_prop_candidate = name_lower.contains("ctrlprop")
            || (name_lower.contains("ctrlprops") && name_lower.ends_with(".rels"))
            || (name_lower.contains("vmldrawing") && name_lower.ends_with(".vml"));
        if is_ctrl_prop_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_excel_control_properties_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Excel control properties or form action anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "ControlProps".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "ExcelControlPropertiesOrFormActionAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for PowerPoint Media Track or Action Anomaly (VBA-CELL-071)
        let is_ppt_media_candidate = name_lower.contains("ppt/media/")
            || name_lower.contains("media/media")
            || (name_lower.contains("ppt/slides/")
                && (name_lower.ends_with(".xml") || name_lower.ends_with(".rels")))
            || name_lower.contains("slidelayout")
            || name_lower.contains("slidemaster");
        if is_ppt_media_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_powerpoint_media_track_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "PowerPoint media track or action anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "MediaTrack".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "PowerPointMediaTrackOrActionAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Excel Table or Slicer Native Connection Anomaly (VBA-CELL-072)
        let is_table_slicer_candidate = name_lower.contains("xl/tables/")
            || name_lower.contains("xl/slicers/")
            || name_lower.contains("xl/timelines/");
        if is_table_slicer_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_excel_table_or_slicer_native_connection_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Excel table or slicer native connection anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "TableConnection".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "ExcelTableOrSlicerNativeConnectionAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Word Mail Merge Header Source or Recipient Anomaly (VBA-CELL-073)
        let is_mail_merge_candidate = (name_lower.contains("settings.xml")
            && (name_lower.contains("word/") || name_lower.contains("word\\")))
            || name_lower.contains("recipientdata")
            || name_lower.contains("mailmerge");
        if is_mail_merge_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_word_mail_merge_header_source_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Word mail merge header source or recipient anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "MailMerge".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "WordMailMergeHeaderSourceOrRecipientAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for PowerPoint Slide Show or Presentation Props Anomaly (VBA-CELL-074)
        let is_pres_props_candidate = (name_lower.contains("ppt/presprops")
            || name_lower.contains("ppt/viewprops")
            || name_lower.contains("presentation.xml")
            || name_lower.contains("presprops.xml")
            || name_lower.contains("viewprops.xml"))
            && (name_lower.ends_with(".xml") || name_lower.ends_with(".rels"));
        if is_pres_props_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_powerpoint_slideshow_or_presentation_props_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "PowerPoint presentation properties or slideshow anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "PresProps".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "PowerPointSlideShowOrPresentationPropsAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Excel Threaded Comment or Person Anomaly (VBA-CELL-075)
        let is_threaded_comment_candidate = name_lower.contains("threadedcomment")
            || name_lower.contains("xl/persons/")
            || name_lower.contains("person.xml");
        if is_threaded_comment_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_excel_threaded_comment_or_person_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Excel threaded comment or person anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "ThreadedComment".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "ExcelThreadedCommentOrPersonAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Office Theme Override or Format Scheme Anomaly (VBA-CELL-076)
        let is_theme_candidate = name_lower.contains("themeoverride")
            || name_lower.contains("fmtscheme")
            || (name_lower.contains("/theme/")
                && (name_lower.ends_with(".xml") || name_lower.ends_with(".rels")));
        if is_theme_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_office_theme_override_or_format_scheme_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Office theme override or format scheme anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "ThemeOverride".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "OfficeThemeOverrideOrFormatSchemeAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for PowerPoint Sync or Comment Authors Anomaly (VBA-CELL-077)
        let is_ppt_sync_candidate = (name_lower.contains("syncinfo")
            || name_lower.contains("slidesync")
            || name_lower.contains("commentauthors"))
            && (name_lower.ends_with(".xml") || name_lower.ends_with(".rels"));
        if is_ppt_sync_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_powerpoint_sync_or_comment_authors_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "PowerPoint sync info or comment authors anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "PowerPointSync".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "PowerPointSyncOrCommentAuthorsAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Word KeyMap or Customization Anomaly (VBA-CELL-078)
        let is_word_keymap_candidate = (name_lower.contains("keymap")
            || name_lower.contains("customizations"))
            && (name_lower.ends_with(".xml")
                || name_lower.ends_with(".bin")
                || name_lower.ends_with(".rels"));
        if is_word_keymap_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_word_keymap_or_customization_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Word keymap or customization anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "WordKeyMap".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "WordKeyMapOrCustomizationAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Excel Web Publishing or Sparkline Anomaly (VBA-CELL-079)
        let is_excel_web_publish_candidate = (name_lower.contains("webpublishing")
            || name_lower.contains("webpublishitems")
            || name_lower.contains("sparklinegroup")
            || name_lower.contains("sparklines"))
            && (name_lower.ends_with(".xml") || name_lower.ends_with(".rels"));
        if is_excel_web_publish_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_excel_web_publishing_or_sparkline_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Excel web publishing or sparkline anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "ExcelWebPublish".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "ExcelWebPublishingOrSparklineAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for PowerPoint Handout or Notes Master Anomaly (VBA-CELL-080)
        let is_handout_notes_candidate = (name_lower.contains("handoutmaster")
            || name_lower.contains("notesmaster"))
            && (name_lower.ends_with(".xml") || name_lower.ends_with(".rels"));
        if is_handout_notes_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_powerpoint_handout_or_notes_master_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "PowerPoint handout or notes master anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "PowerPointHandoutNotes".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "PowerPointHandoutOrNotesMasterAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Word Glossary Settings or Font Table Anomaly (VBA-CELL-081)
        let is_glossary_candidate = (name_lower.contains("/glossary/settings")
            || name_lower.contains("/glossary/fonttable")
            || name_lower.contains("/glossary/websettings")
            || name_lower.contains("glossary/settings")
            || name_lower.contains("glossary/fonttable")
            || name_lower.contains("glossary/websettings"))
            && (name_lower.ends_with(".xml") || name_lower.ends_with(".rels"));
        if is_glossary_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_word_glossary_settings_or_font_table_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Word glossary settings or font table anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "WordGlossarySettings".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "WordGlossarySettingsOrFontTableAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Excel Custom Property or Custom Data Anomaly (VBA-CELL-082)
        let is_custom_data_candidate = (name_lower.contains("customproperty")
            || name_lower.contains("customdata")
            || name_lower.contains("model/datamodel"))
            && (name_lower.ends_with(".xml")
                || name_lower.ends_with(".bin")
                || name_lower.ends_with(".rels"));
        if is_custom_data_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_excel_custom_property_or_custom_data_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Excel custom property or custom data anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "ExcelCustomData".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "ExcelCustomPropertyOrCustomDataAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Word Subdocument or Master Document Anomaly (VBA-CELL-083)
        let is_subdoc_candidate = (name_lower.contains("subdocument")
            || name_lower.contains("subdoc")
            || name_lower.contains("masterdocument"))
            && (name_lower.ends_with(".xml") || name_lower.ends_with(".rels"));
        if is_subdoc_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_word_subdocument_or_master_document_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Word subdocument or master document anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "WordSubDocument".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "WordSubDocumentOrMasterDocumentAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for PowerPoint Font Table or Embedded Font Anomaly (VBA-CELL-084)
        let is_ppt_font_candidate = (name_lower.contains("ppt/fonttable")
            || name_lower.contains("ppt/fonts/")
            || name_lower.contains("ppt/_rels/fonttable")
            || name_lower.contains("ppt/fonts/_rels/"))
            && (name_lower.ends_with(".xml")
                || name_lower.ends_with(".fntdata")
                || name_lower.ends_with(".bin")
                || name_lower.ends_with(".rels"));
        if is_ppt_font_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_powerpoint_font_table_or_embedded_font_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "PowerPoint font table or embedded font anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "PowerPointFontTable".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "PowerPointFontTableOrEmbeddedFontAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Excel Query Table or Data Feed Connection Anomaly (VBA-CELL-085)
        let is_query_table_candidate = (name_lower.contains("querytable")
            || name_lower.contains("datafeed")
            || name_lower.contains("datafeeds"))
            && (name_lower.ends_with(".xml") || name_lower.ends_with(".rels"));
        if is_query_table_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_excel_query_table_or_data_feed_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Excel query table or data feed anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "ExcelQueryTable".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "ExcelQueryTableOrDataFeedAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for PowerPoint Slide Guide or Grid Anomaly (VBA-CELL-086)
        let is_slide_guide_candidate = (name_lower.contains("slideguide")
            || name_lower.contains("slideguides")
            || (name_lower.contains("guides") && name_lower.starts_with("ppt/"))
            || (name_lower.contains("viewprops") && name_lower.starts_with("ppt/")))
            && (name_lower.ends_with(".xml") || name_lower.ends_with(".rels"));
        if is_slide_guide_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_powerpoint_slide_guide_or_grid_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "PowerPoint slide guide or grid anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "PowerPointSlideGuide".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "PowerPointSlideGuideOrGridAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Word Mail Merge Header Filter or Recipient Item Anomaly (VBA-CELL-087)
        let is_mail_merge_filter_candidate = (name_lower.contains("mailmergefilter")
            || name_lower.contains("recipientdata"))
            && (name_lower.ends_with(".xml") || name_lower.ends_with(".rels"));
        if is_mail_merge_filter_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_word_mail_merge_filter_or_recipient_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Word mail merge filter or recipient data anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "WordMailMergeFilter".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "WordMailMergeHeaderFilterOrRecipientItemAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Excel External Data Feed or Data Service Anomaly (VBA-CELL-088)
        let is_data_service_candidate = (name_lower.contains("dataservice")
            || name_lower.contains("dataservices")
            || name_lower.contains("externaldatafeed")
            || name_lower.contains("externaldatafeeds"))
            && (name_lower.ends_with(".xml") || name_lower.ends_with(".rels"));
        if is_data_service_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_excel_external_data_feed_or_service_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Excel external data feed or data service anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "ExcelDataService".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "ExcelExternalDataFeedOrDataServiceAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for PowerPoint Slide Master or Layout Anomaly (VBA-CELL-089)
        let is_slide_master_candidate = (name_lower.contains("slidemaster")
            || name_lower.contains("slidelayout")
            || name_lower.contains("slide_master")
            || name_lower.contains("slide_layout"))
            && (name_lower.ends_with(".xml") || name_lower.ends_with(".rels"));
        if is_slide_master_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_powerpoint_slide_master_or_layout_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "PowerPoint slide master or layout anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "PowerPointSlideMasterOrLayout".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "PowerPointSlideMasterOrLayoutPartAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Word Document Template or Attached Template Anomaly (VBA-CELL-090)
        let is_word_template_candidate = (name_lower.contains("template")
            || (name_lower.ends_with("settings.xml") && name_lower.contains("word")))
            && (name_lower.ends_with(".xml") || name_lower.ends_with(".rels"))
            && !name_lower.ends_with("settings.xml.rels");
        if is_word_template_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_word_document_template_or_attached_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Word document template or attached template anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "WordAttachedTemplate".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "WordDocumentTemplateOrAttachedTemplateAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Excel XML Spreadsheet or Data Binding Anomaly (VBA-CELL-091)
        let is_xml_binding_candidate = (name_lower.contains("databinding")
            || name_lower.contains("databindings")
            || name_lower.contains("binding")
            || name_lower.contains("xmlbinding"))
            && !name_lower.contains("xmlmap")
            && (name_lower.ends_with(".xml") || name_lower.ends_with(".rels"));
        if is_xml_binding_candidate && let Ok(ref data) = entry_bytes_res {
            for (sev, target_id, coord_suffix, reason) in
                scan_excel_xml_spreadsheet_or_binding_threats(&entry.name, data)
            {
                let coord = format!("part:{}:{}", entry.name, coord_suffix);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Excel XML spreadsheet or data binding anomaly detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "ExcelXmlDataBinding".into(),
                        cell_ref: target_id,
                        coordinate: coord,
                        threat_kind: "ExcelXmlSpreadsheetOrDataBindingAnomaly".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for embedded OLE / executable packages (e.g. xl/embeddings/oleObject1.bin, word/embeddings/package.bin)
        if name_lower.contains("/embeddings/")
            || name_lower.starts_with("embeddings/")
            || name_lower.contains("\\embeddings\\")
        {
            let coord = format!("part:{}", entry.name);
            if !threats.iter().any(|t| t.coordinate == coord) {
                let desc = format!(
                    "Embedded OLE object or package detected in container part '{}' (uncompressed size: {} bytes)",
                    entry.name, entry.uncompressed_size
                );
                diagnostics.push(format!("Security warning: {desc}"));
                threats.push(CellThreat {
                    sheet_name: "Package".into(),
                    cell_ref: entry.name.clone(),
                    coordinate: coord,
                    threat_kind: "EmbeddedOlePackage".into(),
                    severity: "High".into(),
                    formula: entry.name.clone(),
                    description: desc,
                });
            }
        }

        // Check for embedded ActiveX controls (e.g. xl/activeX/activeX1.bin)
        if name_lower.contains("/activex/")
            || name_lower.starts_with("activex/")
            || name_lower.contains("\\activex\\")
        {
            let coord = format!("part:{}", entry.name);
            if !threats.iter().any(|t| t.coordinate == coord) {
                let desc = format!(
                    "Embedded ActiveX control detected in container part '{}' (uncompressed size: {} bytes)",
                    entry.name, entry.uncompressed_size
                );
                diagnostics.push(format!("Security warning: {desc}"));
                threats.push(CellThreat {
                    sheet_name: "Package".into(),
                    cell_ref: entry.name.clone(),
                    coordinate: coord,
                    threat_kind: "ActiveXControl".into(),
                    severity: "Medium".into(),
                    formula: entry.name.clone(),
                    description: desc,
                });
            }
        }

        // Check for suspicious printer settings (printerSettings*.bin)
        let is_printer = (name_lower.contains("printersettings")
            || name_lower.contains("printer_settings"))
            && name_lower.ends_with(".bin");
        if is_printer {
            let Ok(data) = zip.read(entry) else { continue };
            if let Some(indicator) = scan_printer_settings_bytes(&data) {
                let coord = format!("part:{}", entry.name);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Suspicious printer settings part '{}' contains dangerous external target or UNC path ({indicator})",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "Package".into(),
                        cell_ref: entry.name.clone(),
                        coordinate: coord,
                        threat_kind: "SuspiciousPrinterSettings".into(),
                        severity: "High".into(),
                        formula: entry.name.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Custom XML payload smuggling (/customXml/*.xml)
        let is_custom_xml = (name_lower.contains("/customxml/")
            || name_lower.starts_with("customxml/")
            || name_lower.contains("\\customxml\\"))
            && name_lower.ends_with(".xml");
        if is_custom_xml {
            let Ok(data) = zip.read(entry) else { continue };
            if let Some((kind, details)) = scan_custom_xml_content(&data) {
                let coord = format!("part:{}", entry.name);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Custom XML payload smuggling detected in part '{}': {kind} ({details})",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "Package".into(),
                        cell_ref: entry.name.clone(),
                        coordinate: coord,
                        threat_kind: "CustomXmlPayloadSmuggling".into(),
                        severity: "High".into(),
                        formula: entry.name.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for suspicious drawings and VML form controls
        let is_drawing = (name_lower.contains("/drawings/drawing")
            || name_lower.starts_with("drawings/drawing")
            || name_lower.contains("\\drawings\\drawing")
            || name_lower.contains("vmldrawing"))
            && (name_lower.ends_with(".xml") || name_lower.ends_with(".vml"));
        if is_drawing {
            let Ok(data) = zip.read(entry) else { continue };
            let s = String::from_utf8_lossy(&data);
            let s_lower = s.to_ascii_lowercase();

            let mut indicator: Option<(&'static str, String)> = None;
            if s_lower.contains("ppaction://program") {
                indicator = Some((
                    "Critical",
                    "Shape action launches external program ('ppaction://program')".into(),
                ));
            } else if s_lower.contains("ppaction://macro") {
                indicator = Some((
                    "High",
                    "Shape action executes macro ('ppaction://macro')".into(),
                ));
            } else if s_lower.contains("<a:hlinkhover") || s_lower.contains("hlinkhover") {
                indicator = Some((
                    "High",
                    "Drawing object configured with mouse-over hover trigger ('<a:hlinkHover>')"
                        .into(),
                ));
            } else if s_lower.contains("<x:fmlamacro>") {
                let macro_name = if let Some(start) = s_lower.find("<x:fmlamacro>") {
                    let rest = &s[start + 13..];
                    if let Some(end) = rest.find("</") {
                        rest[..end].trim().to_string()
                    } else {
                        "Unknown".into()
                    }
                } else {
                    "Unknown".into()
                };
                indicator = Some((
                    "High",
                    format!("VML form control shape links to macro execution ('{macro_name}')"),
                ));
            }

            if let Some((sev, details)) = indicator {
                let coord = format!("part:{}", entry.name);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Suspicious drawing or shape action detected in part '{}': {details}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "Package".into(),
                        cell_ref: entry.name.clone(),
                        coordinate: coord,
                        threat_kind: "SuspiciousDrawingAction".into(),
                        severity: sev.into(),
                        formula: entry.name.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for suspicious PowerPoint slide actions, hover triggers, and executable links
        let is_ppt_slide = (name_lower.starts_with("ppt/slides/")
            || name_lower.contains("/ppt/slides/")
            || name_lower.starts_with("ppt/slidelayouts/")
            || name_lower.contains("/ppt/slidelayouts/")
            || name_lower.starts_with("ppt/slidemasters/")
            || name_lower.contains("/ppt/slidemasters/")
            || name_lower.starts_with("ppt/notesslides/")
            || name_lower.contains("/ppt/notesslides/")
            || name_lower.ends_with("presentation.xml"))
            && name_lower.ends_with(".xml");
        if is_ppt_slide {
            let Ok(data) = zip.read(entry) else { continue };
            let s = String::from_utf8_lossy(&data);
            for (action_type, sev, details) in scan_ppt_slide_actions(&s) {
                let coord = format!("part:{}:action:{}", entry.name, action_type);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Suspicious PowerPoint slide action or trigger detected in part '{}': {details}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "Presentation".into(),
                        cell_ref: action_type.into(),
                        coordinate: coord,
                        threat_kind: "PowerPointSlideAction".into(),
                        severity: sev.into(),
                        formula: details.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Word field codes (DDE, DDEAUTO, INCLUDETEXT, LINK, MACROBUTTON, FILENAME \p)
        let is_word_xml = (name_lower.starts_with("word/")
            || name_lower.contains("/word/")
            || name_lower.starts_with("word\\")
            || name_lower.contains("\\word\\"))
            && (name_lower.ends_with("document.xml")
                || name_lower.contains("/header")
                || name_lower.contains("/footer")
                || name_lower.ends_with("footnotes.xml")
                || name_lower.ends_with("endnotes.xml")
                || name_lower.ends_with("comments.xml"));
        if is_word_xml {
            let Ok(data) = zip.read(entry) else { continue };
            let xml_str = String::from_utf8_lossy(&data);
            for (fld_id, sev, reason) in scan_word_field_codes(&xml_str) {
                let coord = format!("part:{}:field:{}", entry.name, fld_id);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Suspicious Word field code detected in part '{}': {reason}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "Document".into(),
                        cell_ref: fld_id,
                        coordinate: coord,
                        threat_kind: "WordFieldCode".into(),
                        severity: sev.into(),
                        formula: reason.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Word Alternative Format Chunks (AltChunk / aFChunk)
        let is_altchunk = (name_lower.contains("/afchunk")
            || name_lower.starts_with("afchunk")
            || name_lower.contains("\\afchunk"))
            && (name_lower.ends_with(".dat")
                || name_lower.ends_with(".htm")
                || name_lower.ends_with(".html")
                || name_lower.ends_with(".rtf")
                || name_lower.ends_with(".mht")
                || name_lower.ends_with(".bin"));
        if is_altchunk {
            let Ok(data) = zip.read(entry) else { continue };
            if let Some((kind, sev, details)) = scan_altchunk_content(&data) {
                let coord = format!("part:{}", entry.name);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Word Alternative Format Chunk (AltChunk) in part '{}' contains suspicious payload: {details}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "Package".into(),
                        cell_ref: entry.name.clone(),
                        coordinate: coord,
                        threat_kind: "SuspiciousAltChunk".into(),
                        severity: sev.into(),
                        formula: kind.into(),
                        description: desc,
                    });
                }
            }
        }

        // Check for external data connections and query tables
        let is_connection = (name_lower.contains("connections.xml")
            || name_lower.contains("querytable")
            || name_lower.ends_with("settings.xml"))
            && name_lower.ends_with(".xml");
        if is_connection {
            let Ok(data) = zip.read(entry) else { continue };
            let s = String::from_utf8_lossy(&data);
            let s_lower = s.to_ascii_lowercase();

            let mut indicator: Option<(&'static str, String)> = None;
            if s_lower.contains("xp_cmdshell")
                || s_lower.contains("powershell")
                || s_lower.contains("cmd.exe")
            {
                indicator = Some((
                    "Critical",
                    "External data connection contains shell command trigger".into(),
                ));
            } else if (s_lower.contains("type=\"4\"")
                && (s_lower.contains("http://") || s_lower.contains("https://")))
                || s_lower.contains("connection=\"url;http")
                || s_lower.contains("connection=\"url;https")
            {
                indicator = Some((
                    "High",
                    "External web query data connection targets remote URL payload".into(),
                ));
            } else if s_lower.contains("data source=\\\\")
                || s_lower.contains("data source=//")
                || (s_lower.contains("connection=")
                    && (s_lower.contains("\\\\") || s_lower.contains("//")))
                || (s_lower.contains("<w:mailmerge")
                    && (s_lower.contains("\\\\")
                        || s_lower.contains("http://")
                        || s_lower.contains("https://")))
            {
                indicator = Some((
                    "High",
                    "External data connection or MailMerge contains remote UNC path (NTLM credential coercion vector)".into(),
                ));
            }

            if let Some((sev, details)) = indicator {
                let coord = format!("part:{}", entry.name);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "External data connection security threat detected in part '{}': {details}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "Package".into(),
                        cell_ref: entry.name.clone(),
                        coordinate: coord,
                        threat_kind: "ExternalDataConnection".into(),
                        severity: sev.into(),
                        formula: entry.name.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for embedded SVG vector graphics (/media/*.svg)
        let is_svg = name_lower.ends_with(".svg");
        if is_svg {
            let Ok(data) = zip.read(entry) else { continue };
            let s = String::from_utf8_lossy(&data);
            let s_lower = s.to_ascii_lowercase();

            let mut svg_indicator: Option<(&'static str, String)> = None;
            if s_lower.contains("<script") {
                svg_indicator = Some((
                    "Critical",
                    "SVG vector graphic contains embedded script element ('<script')".into(),
                ));
            } else if s_lower.contains("onload=")
                || s_lower.contains("onerror=")
                || s_lower.contains("onclick=")
                || s_lower.contains("onmouseover=")
                || s_lower.contains("onfocus=")
                || s_lower.contains("onbegin=")
            {
                svg_indicator = Some((
                    "High",
                    "SVG vector graphic contains inline event handler (onload/onerror/onclick/onmouseover)".into(),
                ));
            } else if s_lower.contains("<!entity")
                && (s_lower.contains("system") || s_lower.contains("public"))
            {
                svg_indicator = Some((
                    "Critical",
                    "SVG vector graphic contains XML External Entity (XXE) definition".into(),
                ));
            } else if s_lower.contains("ms-msdt:")
                || s_lower.contains("search-ms:")
                || s_lower.contains("ms-appinstaller:")
                || s_lower.contains("file:////")
                || s_lower.contains("file://\\\\")
            {
                svg_indicator = Some((
                    "Critical",
                    "SVG vector graphic targets dangerous protocol handler or remote UNC path"
                        .into(),
                ));
            } else if s_lower.contains("<foreignobject") {
                svg_indicator = Some((
                    "High",
                    "SVG vector graphic embeds external HTML/foreignObject elements".into(),
                ));
            }

            if let Some((sev, details)) = svg_indicator {
                let coord = format!("part:{}", entry.name);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Suspicious SVG vector graphic detected in part '{}': {details}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "Package".into(),
                        cell_ref: entry.name.clone(),
                        coordinate: coord,
                        threat_kind: "SuspiciousSvgVector".into(),
                        severity: sev.into(),
                        formula: entry.name.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for VBA project digital signature parts (vbaProjectSignature*.bin)
        let is_vba_sig = (name_lower.contains("vbaprojectsignature")
            || name_lower.starts_with("vbaprojectsignature"))
            && name_lower.ends_with(".bin");
        if is_vba_sig {
            let Ok(data) = zip.read(entry) else { continue };
            let mut sig_indicator: Option<(&'static str, String)> = None;
            if data.is_empty() || data.len() < 16 {
                sig_indicator = Some((
                    "High",
                    format!(
                        "VBA project digital signature is truncated or empty ({} bytes)",
                        data.len()
                    ),
                ));
            } else if data[0] != 0x30 && data[0] != 0x06 && data[0] != 0x04 {
                sig_indicator = Some((
                    "High",
                    format!(
                        "VBA project signature does not have a valid ASN.1/PKCS#7 header (first byte: 0x{:02X})",
                        data[0]
                    ),
                ));
            } else if data.iter().all(|&b| b == 0x00) || data.iter().all(|&b| b == 0xFF) {
                sig_indicator = Some((
                    "High",
                    "VBA project signature contains hollowed or repetitive dummy padding".into(),
                ));
            }

            if let Some((sev, details)) = sig_indicator {
                let coord = format!("part:{}", entry.name);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    let desc = format!(
                        "Tampered or malformed VBA project digital signature in part '{}': {details}",
                        entry.name
                    );
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "Package".into(),
                        cell_ref: entry.name.clone(),
                        coordinate: coord,
                        threat_kind: "TamperedVbaProjectSignature".into(),
                        severity: sev.into(),
                        formula: entry.name.clone(),
                        description: desc,
                    });
                }
            }
        }

        // Check for Custom UI Ribbon XML (customUI/customUI*.xml)
        let is_custom_ui = (name_lower.contains("customui/")
            || name_lower.starts_with("customui/")
            || name_lower.contains("\\customui\\"))
            && name_lower.ends_with(".xml");
        if is_custom_ui {
            let Ok(data) = zip.read(entry) else { continue };
            let xml_str = String::from_utf8_lossy(&data);
            for (sub_type, sev, trigger, desc) in scan_customui_content(&xml_str) {
                let coord = format!("part:{}:{}:{}", entry.name, sub_type, trigger);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "Ribbon".into(),
                        cell_ref: trigger.clone(),
                        coordinate: coord,
                        threat_kind: "CustomUiRibbon".into(),
                        severity: sev.into(),
                        formula: trigger,
                        description: desc,
                    });
                }
            }
        }

        // Check for legacy Excel 5.0/95 Dialog Sheets (xl/dialogsheets/sheet*.xml)
        let is_dialog_sheet = (name_lower.contains("dialogsheet")
            || name_lower.contains("/dialogsheets/"))
            && name_lower.ends_with(".xml");
        if is_dialog_sheet {
            let Ok(data) = zip.read(entry) else { continue };
            let xml_str = String::from_utf8_lossy(&data);
            for (sev, macro_name, desc) in scan_legacy_dialogsheet_content(&xml_str) {
                let coord = if macro_name.is_empty() {
                    format!("part:{}", entry.name)
                } else {
                    format!("part:{}:macro:{}", entry.name, macro_name)
                };
                if !threats.iter().any(|t| t.coordinate == coord) {
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "DialogSheet".into(),
                        cell_ref: if macro_name.is_empty() {
                            entry.name.clone()
                        } else {
                            macro_name.clone()
                        },
                        coordinate: coord,
                        threat_kind: "LegacyDialogSheet".into(),
                        severity: sev.into(),
                        formula: macro_name,
                        description: desc,
                    });
                }
            }
        }

        // Check for Content Types anomalies, path traversal, and MIME spoofing ([Content_Types].xml)
        let is_content_types = name_lower.trim_start_matches('/') == "[content_types].xml";
        if is_content_types {
            let Ok(data) = zip.read(entry) else { continue };
            let xml_str = String::from_utf8_lossy(&data);
            for (sev, cell_ref, coord_key, desc) in scan_content_types_content(&xml_str) {
                let coord = format!("part:[Content_Types].xml:{}", coord_key);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "Package".into(),
                        cell_ref: cell_ref.clone(),
                        coordinate: coord,
                        threat_kind: "ContentTypeAnomaly".into(),
                        severity: sev.into(),
                        formula: cell_ref,
                        description: desc,
                    });
                }
            }
        }

        // Check for Excel External Links (xl/externalLinks/externalLink*.xml)
        let is_external_link = (name_lower.contains("externallinks/externallink")
            || name_lower.contains("\\externallinks\\externallink")
            || name_lower.starts_with("xl/externallinks/"))
            && name_lower.ends_with(".xml");
        if is_external_link {
            let Ok(data) = zip.read(entry) else { continue };
            let xml_str = String::from_utf8_lossy(&data);
            for (sev, cell_ref, coord_key, desc) in scan_external_link_content(&xml_str) {
                let coord = format!("part:{}:{}", entry.name, coord_key);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "ExternalLink".into(),
                        cell_ref: cell_ref.clone(),
                        coordinate: coord,
                        threat_kind: "ExternalLinkTarget".into(),
                        severity: sev.into(),
                        formula: cell_ref,
                        description: desc,
                    });
                }
            }
        }

        // Check for Word Web Settings (word/webSettings.xml)
        let is_web_settings = (name_lower.ends_with("websettings.xml")
            || name_lower.contains("/websettings")
            || name_lower.contains("\\websettings"))
            && name_lower.ends_with(".xml");
        if is_web_settings {
            let Ok(data) = zip.read(entry) else { continue };
            let xml_str = String::from_utf8_lossy(&data);
            for (sev, cell_ref, coord_key, desc) in scan_websettings_content(&xml_str) {
                let coord = format!("part:{}:{}", entry.name, coord_key);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "WebSettings".into(),
                        cell_ref: cell_ref.clone(),
                        coordinate: coord,
                        threat_kind: "WebSettingsScriptOrReload".into(),
                        severity: sev.into(),
                        formula: cell_ref,
                        description: desc,
                    });
                }
            }
        }

        // Check for Workbook Protection and Evasion (xl/workbook.xml)
        let is_workbook = (name_lower.ends_with("workbook.xml")
            || name_lower.contains("/workbook.xml")
            || name_lower.contains("\\workbook.xml"))
            && name_lower.ends_with(".xml");
        if is_workbook {
            let Ok(data) = zip.read(entry) else { continue };
            let xml_str = String::from_utf8_lossy(&data);
            for (sev, cell_ref, coord_key, desc) in scan_workbook_protection_and_evasion(&xml_str) {
                let coord = format!("part:{}:{}", entry.name, coord_key);
                if !threats.iter().any(|t| t.coordinate == coord) {
                    diagnostics.push(format!("Security warning: {desc}"));
                    threats.push(CellThreat {
                        sheet_name: "Workbook".into(),
                        cell_ref: cell_ref.clone(),
                        coordinate: coord,
                        threat_kind: "WorkbookProtectionEvasion".into(),
                        severity: sev.into(),
                        formula: cell_ref,
                        description: desc,
                    });
                }
            }
        }
    }

    // 2. Inspect all OPC relationship parts (.rels) for external references
    let rels_entries: Vec<String> = zip
        .entries
        .iter()
        .take(max_entries)
        .filter(|e| e.name.to_ascii_lowercase().ends_with(".rels"))
        .map(|e| e.name.clone())
        .collect();

    for rels_part in rels_entries {
        if let Ok(relationships) = crate::opc::read_relationships(zip, &rels_part, max_entries) {
            for rel in relationships {
                let rel_type = rel.relationship_type.to_ascii_lowercase();
                let is_ext = is_external_target(&rel.target, rel.target_mode);

                // Check for Remote Template Injection (attachedTemplate)
                if rel_type.contains("attachedtemplate") && is_ext {
                    let coord = format!("rel:{}->{}", rels_part, rel.id);
                    if !threats.iter().any(|t| t.coordinate == coord) {
                        let desc = format!(
                            "Remote Template Injection detected: relationship '{}' in '{}' targets external template '{}'",
                            rel.id, rels_part, rel.target
                        );
                        diagnostics.push(format!("Security warning: {desc}"));
                        threats.push(CellThreat {
                            sheet_name: "Package".into(),
                            cell_ref: rel.id.clone(),
                            coordinate: coord,
                            threat_kind: "RemoteTemplateInjection".into(),
                            severity: "Critical".into(),
                            formula: rel.target.clone(),
                            description: desc,
                        });
                    }
                }

                // Check for External OLE Object links
                if rel_type.contains("oleobject") && is_ext {
                    let coord = format!("rel:{}->{}", rels_part, rel.id);
                    if !threats.iter().any(|t| t.coordinate == coord) {
                        let desc = format!(
                            "External OLE object link detected: relationship '{}' in '{}' targets external object '{}'",
                            rel.id, rels_part, rel.target
                        );
                        diagnostics.push(format!("Security warning: {desc}"));
                        threats.push(CellThreat {
                            sheet_name: "Package".into(),
                            cell_ref: rel.id.clone(),
                            coordinate: coord,
                            threat_kind: "ExternalOleObject".into(),
                            severity: "High".into(),
                            formula: rel.target.clone(),
                            description: desc,
                        });
                    }
                }

                // Check for External Subdocument / Frame references
                if (rel_type.contains("subdocument") || rel_type.contains("frame"))
                    && !rels_part.to_ascii_lowercase().contains("websettings")
                    && is_ext
                {
                    let coord = format!("rel:{}->{}", rels_part, rel.id);
                    if !threats.iter().any(|t| t.coordinate == coord) {
                        let desc = format!(
                            "External subdocument / frame reference detected: relationship '{}' in '{}' targets external resource '{}'",
                            rel.id, rels_part, rel.target
                        );
                        diagnostics.push(format!("Security warning: {desc}"));
                        threats.push(CellThreat {
                            sheet_name: "Package".into(),
                            cell_ref: rel.id.clone(),
                            coordinate: coord,
                            threat_kind: "ExternalSubdocument".into(),
                            severity: "High".into(),
                            formula: rel.target.clone(),
                            description: desc,
                        });
                    }
                }

                // Check for External Printer Settings
                if rel_type.contains("printersettings") && is_ext {
                    let coord = format!("rel:{}->{}", rels_part, rel.id);
                    if !threats.iter().any(|t| t.coordinate == coord) {
                        let desc = format!(
                            "Suspicious external printer settings relationship '{}' in '{}' targets external resource '{}'",
                            rel.id, rels_part, rel.target
                        );
                        diagnostics.push(format!("Security warning: {desc}"));
                        threats.push(CellThreat {
                            sheet_name: "Package".into(),
                            cell_ref: rel.id.clone(),
                            coordinate: coord,
                            threat_kind: "SuspiciousPrinterSettings".into(),
                            severity: "High".into(),
                            formula: rel.target.clone(),
                            description: desc,
                        });
                    }
                }

                let target_lower = rel.target.to_ascii_lowercase();

                // Check for External AltChunk relationship (aFChunk)
                if (rel_type.contains("afchunk") || rel_type.contains("altchunk")) && is_ext {
                    let coord = format!("rel:{}->{}", rels_part, rel.id);
                    if !threats.iter().any(|t| t.coordinate == coord) {
                        let is_dangerous = target_lower.starts_with("ms-msdt:")
                            || target_lower.starts_with("search-ms:")
                            || target_lower.starts_with("mhtml:")
                            || target_lower.starts_with("\\\\")
                            || target_lower.starts_with("//");
                        let sev = if is_dangerous { "Critical" } else { "High" };
                        let desc = format!(
                            "External Alternative Format Chunk (AltChunk) reference detected: relationship '{}' in '{}' targets external resource '{}'",
                            rel.id, rels_part, rel.target
                        );
                        diagnostics.push(format!("Security warning: {desc}"));
                        threats.push(CellThreat {
                            sheet_name: "Package".into(),
                            cell_ref: rel.id.clone(),
                            coordinate: coord,
                            threat_kind: "SuspiciousAltChunk".into(),
                            severity: sev.into(),
                            formula: rel.target.clone(),
                            description: desc,
                        });
                    }
                }

                // Check for External Custom UI Ribbon relationship
                if (rel_type.contains("ui/extensibility") || rel_type.contains("customui"))
                    && is_ext
                {
                    let coord = format!("rel:{}->{}", rels_part, rel.id);
                    if !threats.iter().any(|t| t.coordinate == coord) {
                        let desc = format!(
                            "External Custom UI Ribbon relationship '{}' in '{}' targets external specification '{}'",
                            rel.id, rels_part, rel.target
                        );
                        diagnostics.push(format!("Security warning: {desc}"));
                        threats.push(CellThreat {
                            sheet_name: "Package".into(),
                            cell_ref: rel.id.clone(),
                            coordinate: coord,
                            threat_kind: "CustomUiRibbon".into(),
                            severity: "Critical".into(),
                            formula: rel.target.clone(),
                            description: desc,
                        });
                    }
                }

                // Check for External Link Target relationships (xl/externalLinks/_rels/externalLink*.xml.rels)
                let is_external_link_rel = rels_part.to_ascii_lowercase().contains("externallink")
                    || rel_type.contains("externallinkpath")
                    || rel_type.contains("externallink");
                if is_external_link_rel && is_ext {
                    let coord = format!("rel:{}->{}", rels_part, rel.id);
                    if !threats.iter().any(|t| t.coordinate == coord) {
                        let is_critical = target_lower.starts_with("ms-msdt:")
                            || target_lower.starts_with("search-ms:")
                            || target_lower.starts_with("mhtml:")
                            || target_lower.starts_with("\\\\")
                            || target_lower.starts_with("//")
                            || target_lower.starts_with("file:////")
                            || target_lower.starts_with("file://\\\\")
                            || [
                                ".exe", ".dll", ".bat", ".ps1", ".cmd", ".vbs", ".hta", ".cpl",
                                ".msi", ".iso", ".scr", ".vbe", ".wsf",
                            ]
                            .iter()
                            .any(|ext| {
                                target_lower.ends_with(ext)
                                    || target_lower.contains(&format!("{ext}?"))
                            });
                        let sev = if is_critical { "Critical" } else { "High" };
                        let desc = format!(
                            "External link target anomaly detected: relationship '{}' in '{}' targets external resource '{}'",
                            rel.id, rels_part, rel.target
                        );
                        diagnostics.push(format!("Security warning: {desc}"));
                        threats.push(CellThreat {
                            sheet_name: "Package".into(),
                            cell_ref: rel.id.clone(),
                            coordinate: coord,
                            threat_kind: "ExternalLinkTarget".into(),
                            severity: sev.into(),
                            formula: rel.target.clone(),
                            description: desc,
                        });
                    }
                }

                // Check for Web Settings relationships (word/_rels/webSettings.xml.rels)
                let is_websettings_rel = rels_part.to_ascii_lowercase().contains("websettings");
                if is_websettings_rel && is_ext {
                    let coord = format!("rel:{}->{}", rels_part, rel.id);
                    if !threats.iter().any(|t| t.coordinate == coord) {
                        let is_critical = target_lower.starts_with("ms-msdt:")
                            || target_lower.starts_with("search-ms:")
                            || target_lower.starts_with("mhtml:")
                            || target_lower.starts_with("\\\\")
                            || target_lower.starts_with("//");
                        let sev = if is_critical { "Critical" } else { "High" };
                        let desc = format!(
                            "Web settings remote frameset or external link detected: relationship '{}' in '{}' targets external resource '{}'",
                            rel.id, rels_part, rel.target
                        );
                        diagnostics.push(format!("Security warning: {desc}"));
                        threats.push(CellThreat {
                            sheet_name: "Package".into(),
                            cell_ref: rel.id.clone(),
                            coordinate: coord,
                            threat_kind: "WebSettingsScriptOrReload".into(),
                            severity: sev.into(),
                            formula: rel.target.clone(),
                            description: desc,
                        });
                    }
                }

                // Check for Suspicious Protocol Handler (ms-msdt, search-ms, ms-appinstaller, mhtml, javascript, vbscript, remote file://)
                let is_suspicious_proto = target_lower.starts_with("ms-msdt:")
                    || target_lower.starts_with("search-ms:")
                    || target_lower.starts_with("ms-appinstaller:")
                    || target_lower.starts_with("mhtml:")
                    || target_lower.starts_with("javascript:")
                    || target_lower.starts_with("vbscript:")
                    || target_lower.starts_with("file:////")
                    || target_lower.starts_with("file://\\\\");

                if is_suspicious_proto
                    && !rel_type.contains("attachedtemplate")
                    && !rel_type.contains("oleobject")
                    && !rel_type.contains("subdocument")
                    && !rel_type.contains("frame")
                    && !rel_type.contains("afchunk")
                    && !rel_type.contains("altchunk")
                    && !rel_type.contains("ui/extensibility")
                    && !rel_type.contains("customui")
                    && !is_external_link_rel
                    && !is_websettings_rel
                {
                    let coord = format!("rel:{}->{}", rels_part, rel.id);
                    if !threats.iter().any(|t| t.coordinate == coord) {
                        let desc = format!(
                            "Suspicious protocol handler / URI exploit target detected: relationship '{}' in '{}' targets '{}'",
                            rel.id, rels_part, rel.target
                        );
                        diagnostics.push(format!("Security warning: {desc}"));
                        threats.push(CellThreat {
                            sheet_name: "Package".into(),
                            cell_ref: rel.id.clone(),
                            coordinate: coord,
                            threat_kind: "SuspiciousProtocolHandler".into(),
                            severity: "Critical".into(),
                            formula: rel.target.clone(),
                            description: desc,
                        });
                    }
                }

                // Check for Suspicious Drawing / Slide Relationships
                let is_drawing_rels = rels_part.to_ascii_lowercase().contains("drawing")
                    || rels_part.to_ascii_lowercase().contains("slide");
                if is_drawing_rels && is_ext {
                    let t_lower = rel.target.to_ascii_lowercase();
                    let is_dangerous_target = t_lower.ends_with(".exe")
                        || t_lower.ends_with(".scr")
                        || t_lower.ends_with(".bat")
                        || t_lower.ends_with(".vbs")
                        || t_lower.ends_with(".ps1")
                        || t_lower.ends_with(".cmd")
                        || t_lower.ends_with(".hta")
                        || t_lower.ends_with(".cpl")
                        || t_lower.ends_with(".msi")
                        || t_lower.ends_with(".jar")
                        || t_lower.ends_with(".iso")
                        || t_lower.ends_with(".img")
                        || t_lower.ends_with(".vhd")
                        || t_lower.ends_with(".lnk")
                        || t_lower.starts_with("ms-msdt:")
                        || t_lower.starts_with("search-ms:")
                        || t_lower.starts_with("ms-appinstaller:")
                        || t_lower.starts_with("mhtml:")
                        || t_lower.starts_with("javascript:")
                        || t_lower.starts_with("vbscript:")
                        || t_lower.starts_with("file:////")
                        || t_lower.starts_with("\\\\");
                    if is_dangerous_target {
                        let coord = format!("rel:{}->{}", rels_part, rel.id);
                        if !threats.iter().any(|t| t.coordinate == coord) {
                            let desc = format!(
                                "Suspicious drawing or slide relationship '{}' in '{}' targets dangerous resource '{}'",
                                rel.id, rels_part, rel.target
                            );
                            diagnostics.push(format!("Security warning: {desc}"));
                            threats.push(CellThreat {
                                sheet_name: "Package".into(),
                                cell_ref: rel.id.clone(),
                                coordinate: coord,
                                threat_kind: "SuspiciousDrawingAction".into(),
                                severity: "Critical".into(),
                                formula: rel.target.clone(),
                                description: desc,
                            });
                        }
                    }
                }

                // Check for External Data Connection / MailMerge relationships
                if (rel_type.contains("connection") || rel_type.contains("mailmerge")) && is_ext {
                    let coord = format!("rel:{}->{}", rels_part, rel.id);
                    if !threats.iter().any(|t| t.coordinate == coord) {
                        let desc = format!(
                            "External data connection relationship '{}' in '{}' targets external resource '{}'",
                            rel.id, rels_part, rel.target
                        );
                        diagnostics.push(format!("Security warning: {desc}"));
                        threats.push(CellThreat {
                            sheet_name: "Package".into(),
                            cell_ref: rel.id.clone(),
                            coordinate: coord,
                            threat_kind: "ExternalDataConnection".into(),
                            severity: "High".into(),
                            formula: rel.target.clone(),
                            description: desc,
                        });
                    }
                }

                // Check for Dangling / Stripped VBA Project Signature relationship
                if rel_type.contains("relationships/vbaprojectsignature")
                    || rel_type.contains("vbaprojectsignature")
                {
                    let target_clean = rel.target.trim_start_matches('/').trim_start_matches("./");
                    let target_lower = target_clean.to_ascii_lowercase();
                    let target_found = zip.entries.iter().any(|e| {
                        let e_name = e.name.trim_start_matches('/').to_ascii_lowercase();
                        e_name == target_lower || e_name.ends_with(&target_lower)
                    });
                    if !target_found {
                        let coord = format!("rel:{}->{}", rels_part, rel.id);
                        if !threats.iter().any(|t| t.coordinate == coord) {
                            let desc = format!(
                                "Dangling VBA project signature relationship '{}' in '{}': target '{}' is missing from package (signature stripping evasion)",
                                rel.id, rels_part, rel.target
                            );
                            diagnostics.push(format!("Security warning: {desc}"));
                            threats.push(CellThreat {
                                sheet_name: "Package".into(),
                                cell_ref: rel.id.clone(),
                                coordinate: coord,
                                threat_kind: "TamperedVbaProjectSignature".into(),
                                severity: "High".into(),
                                formula: rel.target.clone(),
                                description: desc,
                            });
                        }
                    }
                }
            }
        }
    }
}

/// Disassemble P-code for an extracted module using the standard built-in opcode tables.
pub fn disassemble_extracted_module(
    module: &ExtractedModule,
    identifiers: &[String],
    is_64bit: bool,
    vba_ver: u16,
) -> Result<crate::pcode::DisassembledPCodeModule, String> {
    crate::pcode::disassemble_pcode_module(
        &module.name,
        &module.performance_cache,
        module.text_offset,
        identifiers,
        is_64bit,
        vba_ver,
    )
}

/// Disassemble P-code for all modules in an extracted project using built-in standard tables.
pub fn disassemble_extracted_project(
    project: &ExtractedProject,
) -> Result<Vec<crate::pcode::DisassembledPCodeModule>, String> {
    let is_64bit = project.system_kind == Some(3);
    let vba_ver = if let Some(tag) = project.project_version_tag {
        if tag >= 0x97 {
            7
        } else if tag >= 0x6B {
            6
        } else {
            5
        }
    } else {
        7
    };

    let mut results = Vec::new();
    for module in &project.modules {
        if !module.performance_cache.is_empty() {
            let Ok(disasm) =
                disassemble_extracted_module(module, &project.identifiers, is_64bit, vba_ver)
            else {
                continue;
            };
            results.push(disasm);
        }
    }
    Ok(results)
}

/// Check the entire extracted project for VBA Stomping and tampering indicators.
pub fn detect_project_stomping(
    project: &ExtractedProject,
) -> Result<crate::stomping::ProjectStompingReport, String> {
    let disasms = disassemble_extracted_project(project)?;
    let mut module_reports = Vec::new();
    let mut project_findings = Vec::new();
    let mut max_severity = crate::stomping::StompingSeverity::Clean;

    if project.is_locked_or_unviewable {
        project_findings.push(crate::stomping::StompingFinding {
            severity: crate::stomping::StompingSeverity::Medium,
            kind: crate::stomping::StompingFindingKind::ProjectLockedOrUnviewable,
            description: "VBA project contains protection/lock attributes (CMG/DPB/GC); project may appear locked or unviewable in VBA IDE".to_string(),
        });
        if crate::stomping::StompingSeverity::Medium > max_severity {
            max_severity = crate::stomping::StompingSeverity::Medium;
        }
    }

    for module in &project.modules {
        let matching_disasm = disasms.iter().find(|d| d.module_name == module.name);
        let mut report = crate::stomping::detect_vba_stomping_with_error(
            &module.name,
            module.source_text.as_deref(),
            module.diagnostic.as_deref(),
            matching_disasm,
        );

        if matching_disasm.map(|d| d.lines.is_empty()).unwrap_or(true)
            && !module.performance_cache.is_empty()
        {
            let has_source = module
                .source_text
                .as_deref()
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false);
            if !has_source
                && module.diagnostic.is_none()
                && !report
                    .findings
                    .iter()
                    .any(|f| matches!(f.kind, crate::stomping::StompingFindingKind::SourcePurged))
            {
                report.findings.push(crate::stomping::StompingFinding {
                    severity: crate::stomping::StompingSeverity::Critical,
                    kind: crate::stomping::StompingFindingKind::SourcePurged,
                    description: format!(
                        "Module '{}' contains {} bytes of compiled performance cache but source code is completely purged/empty (VBA Stomping pattern)",
                        module.name,
                        module.performance_cache.len()
                    ),
                });
                report.confidence_score = report.confidence_score.max(95);
                report.is_stomped = true;
                if crate::stomping::StompingSeverity::Critical > report.severity {
                    report.severity = crate::stomping::StompingSeverity::Critical;
                }
            } else if let Some(err) = &module.diagnostic
                && !report.findings.iter().any(|f| {
                    matches!(
                        f.kind,
                        crate::stomping::StompingFindingKind::SourceCorruptedWithValidPCode(_)
                    )
                })
            {
                report.findings.push(crate::stomping::StompingFinding {
                    severity: crate::stomping::StompingSeverity::Critical,
                    kind: crate::stomping::StompingFindingKind::SourceCorruptedWithValidPCode(
                        err.clone(),
                    ),
                    description: format!(
                        "Module '{}' contains {} bytes of compiled performance cache but source extraction failed: {err}",
                        module.name,
                        module.performance_cache.len()
                    ),
                });
                report.confidence_score = report.confidence_score.max(95);
                report.is_stomped = true;
                if crate::stomping::StompingSeverity::Critical > report.severity {
                    report.severity = crate::stomping::StompingSeverity::Critical;
                }
            }
        }

        if project
            .hidden_gui_modules
            .iter()
            .any(|h| h.eq_ignore_ascii_case(&module.name))
        {
            let is_auto = crate::stomping::is_auto_exec_hook(&module.name)
                || module
                    .source_text
                    .as_deref()
                    .map(|s| {
                        let norm = s.replace("\r\n", "\n").replace('\r', "\n");
                        norm.lines().any(|l| {
                            let trim = l.trim();
                            let upper = trim.to_ascii_uppercase();
                            for kw in &[
                                "SUB ",
                                "FUNCTION ",
                                "PROPERTY GET ",
                                "PROPERTY LET ",
                                "PROPERTY SET ",
                            ] {
                                if let Some(idx) = upper.find(kw) {
                                    let after = trim[idx + kw.len()..].trim_start();
                                    let name: String = after
                                        .chars()
                                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                                        .collect();
                                    if !name.is_empty() && crate::stomping::is_auto_exec_hook(&name)
                                    {
                                        return true;
                                    }
                                }
                            }
                            false
                        })
                    })
                    .unwrap_or(false);
            let sev = if is_auto {
                crate::stomping::StompingSeverity::Critical
            } else {
                crate::stomping::StompingSeverity::High
            };
            report.findings.push(crate::stomping::StompingFinding {
                severity: sev,
                kind: crate::stomping::StompingFindingKind::HiddenGuiModule(module.name.clone()),
                description: format!(
                    "Module '{}' is compiled in dir stream but omitted from PROJECT stream manifest; invisible in Office VBA IDE (Evil Clippy GUI hiding)",
                    module.name
                ),
            });
            report.confidence_score = report.confidence_score.max(80);
            if sev > report.severity {
                report.severity = sev;
            }
            report.is_stomped = true;
        }

        if report.severity > max_severity {
            max_severity = report.severity;
        }
        module_reports.push(report);
    }

    let has_stomping = module_reports.iter().any(|r| r.is_stomped);

    Ok(crate::stomping::ProjectStompingReport {
        overall_severity: max_severity,
        has_stomping,
        project_findings,
        modules: module_reports,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zip::crc32;
    #[test]
    fn rejects_plain_text() {
        assert!(
            extract_xlsm(b"not a workbook", &Limits::default())
                .unwrap_err()
                .contains("ZIP")
        );
    }

    #[test]
    fn pcode_analysis_defaults_are_bounded_and_profile_explicit() {
        let options = PCodeAnalysisOptions::default();
        assert_eq!(
            options.profile,
            crate::compiled::PCodeLayoutProfile::Vba7Observed
        );
        assert!(options.max_lines > 0);
        assert!(options.max_modules > 0);
        assert!(options.max_instructions > 0);
        assert!(options.max_paths > 0);
        assert!(options.max_steps > 0);
        assert_eq!(
            options.branch_base,
            crate::compiled::PCodeBranchBase::InstructionStart
        );
    }

    #[test]
    fn runs_caller_supplied_pcode_semantics_from_an_extracted_module() {
        let module = ExtractedModule {
            name: "Mod1".into(),
            pcode_layout: Some(crate::compiled::PCodeLineMap {
                profile: crate::compiled::PCodeLayoutProfile::Vba7Observed,
                cafe_offset: 0,
                profile_header_raw: [0, 0],
                line_count: 1,
                directory_offset: 6,
                code_table_offset: 28,
                code_bytes_total: 8,
                lines: vec![crate::compiled::PCodeLineSegment {
                    source_line: 0,
                    line_length: 8,
                    record_prefix_raw: [0; 4],
                    record_middle_raw: [0; 2],
                    relative_code_offset_raw: 0,
                    cache_offset: Some(100),
                    raw_bytes: vec![0x01, 0x00, 0x06, 0x00, 0x02, 0x00, 0x03, 0x00],
                    raw_word_count: 4,
                    has_partial_word: false,
                }],
                mnemonics_decoded: false,
            }),
            ..ExtractedModule::default()
        };
        let instruction_schema = crate::compiled::PCodeInstructionSchema {
            id: "extracted-branch".into(),
            opcode_mask: 0xffff,
            opcode_shift: 0,
            operation_type_mask: 0,
            operation_type_shift: 0,
            definitions: vec![
                crate::compiled::PCodeOpcodeDefinition {
                    opcode: 1,
                    operation_type: None,
                    mnemonic: "Branch".into(),
                    operands: vec![crate::compiled::PCodeOperandEncoding::SignedWord16],
                },
                crate::compiled::PCodeOpcodeDefinition {
                    opcode: 2,
                    operation_type: None,
                    mnemonic: "ReturnFallthrough".into(),
                    operands: Vec::new(),
                },
                crate::compiled::PCodeOpcodeDefinition {
                    opcode: 3,
                    operation_type: None,
                    mnemonic: "ReturnTarget".into(),
                    operands: Vec::new(),
                },
            ],
        };
        let semantic_schema = crate::compiled::PCodeSemanticSchema {
            id: "extracted-branch".into(),
            max_stack: 4,
            definitions: vec![
                crate::compiled::PCodeSemanticDefinition {
                    opcode: 1,
                    operation_type: None,
                    actions: vec![crate::compiled::PCodeSemanticAction::BranchRelative {
                        operand_index: 0,
                    }],
                },
                crate::compiled::PCodeSemanticDefinition {
                    opcode: 2,
                    operation_type: None,
                    actions: vec![crate::compiled::PCodeSemanticAction::Return {
                        has_value: false,
                    }],
                },
                crate::compiled::PCodeSemanticDefinition {
                    opcode: 3,
                    operation_type: None,
                    actions: vec![crate::compiled::PCodeSemanticAction::Return {
                        has_value: false,
                    }],
                },
            ],
        };
        let (_, semantic) = analyze_extracted_module_pcode(
            &module,
            &instruction_schema,
            &semantic_schema,
            16,
            4,
            8,
            crate::compiled::PCodeBranchBase::InstructionStart,
        )
        .unwrap()
        .unwrap();
        assert_eq!(semantic.paths.len(), 2);
        assert!(semantic.paths.iter().all(|path| path.complete));
        let project_analysis = analyze_extracted_project_pcode(
            &ExtractedProject {
                modules: vec![module.clone(), ExtractedModule::default()],
                ..ExtractedProject::default()
            },
            &instruction_schema,
            &semantic_schema,
            4,
            16,
            4,
            8,
            crate::compiled::PCodeBranchBase::InstructionStart,
        )
        .unwrap();
        assert_eq!(project_analysis.modules.len(), 1);
        assert_eq!(project_analysis.modules[0].module_name, "Mod1");
        assert!(!project_analysis.truncated);
        assert!(
            analyze_extracted_module_pcode(
                &ExtractedModule::default(),
                &instruction_schema,
                &semantic_schema,
                16,
                4,
                8,
                crate::compiled::PCodeBranchBase::InstructionStart,
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn extracts_module_from_synthetic_xlsm_package() {
        let bin = fixture_cfb();
        let raw_profiled = extract_vba_project_with_pcode_profile(
            &bin,
            &Limits::default(),
            crate::compiled::PCodeLayoutProfile::Vba7Observed,
            65_535,
        )
        .unwrap();
        assert_eq!(raw_profiled.modules.len(), 1);
        assert_eq!(
            raw_profiled.modules[0].pcode_layout_status,
            "no_valid_line_map_found_for_selected_profile"
        );
        let x = extract_xlsm(&fixture_zip(&bin), &Limits::default()).unwrap();
        let profiled = extract_xlsm_with_pcode_profile(
            &fixture_zip(&bin),
            &Limits::default(),
            crate::compiled::PCodeLayoutProfile::Vba7Observed,
            65_535,
        )
        .unwrap();
        assert!(
            profiled
                .compiled_representation_status
                .contains("line_map_only")
        );
        assert_eq!(
            profiled.modules[0].pcode_layout_status,
            "no_valid_line_map_found_for_selected_profile"
        );
        assert_eq!(x.name.as_deref(), Some("TestProject"));
        assert_eq!(x.code_page, Some(1252));
        assert_eq!(x.system_kind, Some(1));
        assert_eq!(x.project_version_tag, Some(0x3164));
        assert_eq!(x.workbook_code_name.as_deref(), Some("MainBookCode"));
        assert_eq!(
            x.conditional_constants.get("Win64").map(String::as_str),
            Some("1")
        );
        assert_eq!(x.modules.len(), 1);
        assert_eq!(x.modules[0].name, "Mod1");
        assert_eq!(x.workbook_sheets.len(), 2);
        assert_eq!(x.workbook_sheets[0].name, "Orders");
        assert_eq!(
            x.workbook_sheets[0].code_name.as_deref(),
            Some("OrdersCode")
        );
        assert_eq!(x.workbook_sheets[0].sheet_id, Some(1));
        assert_eq!(x.workbook_sheets[0].kind, "worksheet");
        assert_eq!(
            x.workbook_sheets[0].part_name.as_deref(),
            Some("xl/worksheets/sheet1.xml")
        );
        assert_eq!(x.workbook_sheets[0].resolution, "resolved_internal");
        assert_eq!(x.workbook_sheets[1].state.as_deref(), Some("veryHidden"));
        assert_eq!(
            x.workbook_sheets[1].part_name.as_deref(),
            Some("xl/worksheets/sheet2.xml")
        );
        assert_eq!(x.workbook_defined_names.len(), 4);
        assert_eq!(x.workbook_defined_names[0].name, "TaxRate");
        assert_eq!(x.workbook_defined_names[0].formula, "0.075");
        assert_eq!(
            x.workbook_defined_names[0].scope_resolution,
            "workbook_scope"
        );
        assert_eq!(x.workbook_defined_names[1].name, "OrdersData");
        assert_eq!(x.workbook_defined_names[1].formula, "'Orders'!$A$1:$B$10");
        assert_eq!(x.workbook_defined_names[1].local_sheet_id, Some(0));
        assert_eq!(
            x.workbook_defined_names[1].local_sheet_name.as_deref(),
            Some("Orders")
        );
        assert_eq!(
            x.workbook_defined_names[1].scope_resolution,
            "sheet_scope_candidate"
        );
        assert_eq!(
            x.workbook_defined_names[1].formula_reference_resolution,
            "partial_formula_reference_scan"
        );
        assert_eq!(
            x.workbook_defined_names[1]
                .formula_reference_candidates
                .len(),
            1
        );
        assert_eq!(
            x.workbook_defined_names[1].formula_reference_candidates[0].reference,
            "'Orders'!$A$1:$B$10"
        );
        assert_eq!(
            x.workbook_defined_names[1].formula_reference_candidates[0].workbook_cell_indices,
            vec![0, 1, 6, 7]
        );
        assert_eq!(x.workbook_defined_names[2].hidden, Some(true));
        assert!(x.workbook_defined_names[2].built_in);
        assert_eq!(x.workbook_defined_names[3].formula, "=\"A\"&\"B\"");
        assert_eq!(x.workbook_cells.len(), 9);
        assert_eq!(x.workbook_cells[0].cell_ref, "A1");
        assert_eq!(x.workbook_cells[0].row, Some(1));
        assert_eq!(x.workbook_cells[0].column, Some(1));
        assert_eq!(x.workbook_cells[0].value.as_deref(), Some("10"));
        assert_eq!(x.workbook_cells[1].value.as_deref(), Some("Shared & Text"));
        assert_eq!(x.workbook_cells[1].resolution, "shared_string");
        assert_eq!(x.workbook_cells[2].value.as_deref(), Some(" Inline Text "));
        assert_eq!(x.workbook_cells[2].resolution, "inline_string");
        assert_eq!(
            x.workbook_cells[3].formula.as_deref(),
            Some("A1+TaxRate+OrdersTable[Shared & Text]")
        );
        assert_eq!(x.workbook_cells[3].stored_value.as_deref(), Some("11"));
        assert_eq!(x.workbook_cells[3].resolution, "formula_cached_value");
        assert_eq!(x.workbook_cells[3].formula_reference_candidates.len(), 3);
        assert_eq!(
            x.workbook_cells[3].formula_reference_candidates[0].reference,
            "A1"
        );
        assert_eq!(
            x.workbook_cells[3].formula_reference_candidates[0].workbook_cell_indices,
            vec![0]
        );
        assert_eq!(
            x.workbook_cells[3].formula_reference_candidates[1].reference,
            "TaxRate"
        );
        assert_eq!(
            x.workbook_cells[3].formula_reference_candidates[1].defined_name_index_candidate,
            Some(0)
        );
        assert_eq!(
            x.workbook_cells[3].formula_reference_candidates[1]
                .defined_name_resolution
                .as_deref(),
            Some("workbook_defined_name_candidate")
        );
        let table_reference = &x.workbook_cells[3].formula_reference_candidates[2];
        assert_eq!(
            table_reference.reference_kind,
            "structured_table_reference_candidate"
        );
        assert_eq!(table_reference.table_index_candidate, Some(0));
        assert_eq!(table_reference.table_column_index_candidate, Some(1));
        assert_eq!(table_reference.workbook_cell_indices, vec![7]);
        assert_eq!(x.workbook_cells[4].value.as_deref(), Some("true"));
        assert_eq!(x.workbook_cells[5].value.as_deref(), Some("Rich Text"));
        assert_eq!(x.workbook_cells[8].sheet_name, "Archive");
        assert_eq!(x.workbook_tables.len(), 1);
        assert_eq!(x.workbook_tables[0].display_name, "OrdersTable");
        assert_eq!(x.workbook_tables[0].sheet_name, "Orders");
        assert_eq!(
            x.workbook_tables[0].cell_range_bounds,
            Some(crate::model::CellRangeBounds {
                first_row: 1,
                first_column: 1,
                last_row: 2,
                last_column: 2,
            })
        );
        assert_eq!(x.workbook_tables[0].columns, vec!["10", "Shared & Text"]);
        assert_eq!(x.workbook_tables[0].resolution, "resolved_internal");
        assert!(!x.workbook_cells_truncated);
        let bounded = extract_xlsm(
            &fixture_zip(&bin),
            &Limits {
                max_workbook_cells: 3,
                ..Limits::default()
            },
        )
        .unwrap();
        assert_eq!(bounded.workbook_cells.len(), 3);
        assert!(bounded.workbook_cells_truncated);
        let tables_bounded = extract_xlsm(
            &fixture_zip(&bin),
            &Limits {
                max_workbook_tables: 0,
                ..Limits::default()
            },
        )
        .unwrap();
        assert!(tables_bounded.workbook_tables.is_empty());
        assert!(tables_bounded.workbook_tables_truncated);
        assert_eq!(
            x.modules[0].source_text.as_deref(),
            Some(
                "Public Sub S()\r\nx=ThisWorkbook.Worksheets(\"Orders\").Range(\"A1\").Value\r\nEnd Sub\r\n"
            )
        );
        assert_eq!(x.modules[0].cache.byte_length, 2);
        assert!(x.compiled_representation_status.contains("opaque"));
        assert_eq!(x.srp_caches.len(), 1);
        assert_eq!(x.srp_caches[0].stream_name, "__SRP_A1B2");
        assert_eq!(x.srp_caches[0].byte_length, 3);
        assert_eq!(
            x.srp_caches[0].fingerprint,
            fingerprint_fnv1a64(&[0x53, 0x52, 0x50])
        );
        assert_eq!(x.references[0], "stdole");
        assert_eq!(x.project_references.len(), 1);
        assert_eq!(x.project_references[0].kind, "registered_type_library");
        assert_eq!(x.project_references[0].name.as_deref(), Some("stdole"));
        assert_eq!(sources_from_extracted(&x)[0].name, "Mod1.bas");
        let (analysis, full_extract) = crate::analyze_xlsm(
            &fixture_zip(&bin),
            &crate::AnalysisOptions {
                host_profile: crate::host::HostProfile::Excel,
                ..crate::AnalysisOptions::default()
            },
        )
        .unwrap();
        assert_eq!(full_extract.modules[0].name, "Mod1");
        assert_eq!(analysis.project.input_kind, "xlsm_vba_project");
        assert_eq!(analysis.host_profile, crate::host::HostProfile::Excel);
        assert_eq!(analysis.project.name.as_deref(), Some("TestProject"));
        assert_eq!(
            analysis
                .project
                .conditional_constants
                .get("Win64")
                .map(String::as_str),
            Some("1")
        );
        assert_eq!(
            analysis.project.modules[0]
                .conditional_constants
                .get("win64")
                .map(String::as_str),
            Some("1")
        );
        assert_eq!(
            analysis.project.modules[0].module_kind.as_deref(),
            Some("standard")
        );
        assert_eq!(analysis.project.modules[0].procedures[0].name, "S");
        assert_eq!(analysis.excel_worksheet_accesses.len(), 1);
        assert_eq!(
            analysis.excel_worksheet_accesses[0].workbook_cell_indices,
            vec![0]
        );
        assert!(analysis.data_access_value_flows.iter().any(|flow| {
            flow.excel_worksheet_access_index == Some(0)
                && flow.role == "excel_read_to_variable_candidate"
        }));
        let structure_json = crate::export::to_json(
            &analysis,
            Some(&full_extract),
            crate::export::Disclosure::StructureOnly,
        );
        assert!(structure_json.contains("\"srp_cache_count\": 1"));
        assert!(structure_json.contains("\"stream_name\":null"));
        assert!(!structure_json.contains("__SRP_A1B2"));
        assert!(structure_json.contains("\"table_count\":1"));
        assert!(structure_json.contains("\"tables\":null"));
        assert!(!structure_json.contains("OrdersTable"));
        let source_json = crate::export::to_json(
            &analysis,
            Some(&full_extract),
            crate::export::Disclosure::IncludeSource,
        );
        assert!(source_json.contains("__SRP_A1B2"));
        assert!(source_json.contains("opaque version-dependent SRP cache; ignored on read"));
        assert!(source_json.contains("\"table_count\":1"));
        assert!(source_json.contains("structured_table_reference_candidate"));
        assert!(source_json.contains("\"table_id_candidate\":0"));
        assert!(source_json.contains("\"workbook_cell_ids\":[7]"));
        assert!(source_json.contains("OrdersTable"));
    }

    #[test]
    fn follows_workbook_relationship_to_a_nonconventional_vba_part_path() {
        let bin = fixture_cfb();
        let package =
            fixture_zip_with_vba_part(&bin, "custom/vba-project.bin", "../custom/vba-project.bin");
        let extracted = extract_xlsm(&package, &Limits::default()).unwrap();
        assert_eq!(extracted.modules.len(), 1);
        assert_eq!(extracted.modules[0].name, "Mod1");
        assert_eq!(
            extracted.modules[0].source_text.as_deref(),
            Some(
                "Public Sub S()\r\nx=ThisWorkbook.Worksheets(\"Orders\").Range(\"A1\").Value\r\nEnd Sub\r\n"
            )
        );
    }

    #[test]
    fn rejects_an_external_vba_project_relationship_without_fetching_it() {
        let package = fixture_zip_with_vba_part_mode(
            b"not fetched",
            "custom/vba-project.bin",
            "https://example.invalid/vba-project.bin",
            Some("External"),
        );
        let error = extract_xlsm(&package, &Limits::default()).unwrap_err();
        assert!(error.contains("VBA project relationship must target a package part"));
    }

    #[test]
    fn recognizes_only_spec_shaped_srp_stream_names_in_the_vba_storage() {
        assert!(is_srp_stream_name("__SRP_A"));
        assert!(is_srp_stream_name("__srp_0123456789abcdef012345678"));
        assert!(!is_srp_stream_name("__SRP_"));
        assert!(!is_srp_stream_name("__SRP_G"));
        assert!(!is_srp_stream_name("__SRP_0123456789abcdef0123456789"));
        assert!(is_srp_stream_path("VBA/__SRP_A1B2"));
        assert!(is_srp_stream_path("vba/__srp_a1b2"));
        assert!(!is_srp_stream_path("VBA/Sub/__SRP_A1B2"));
        assert!(!is_srp_stream_path("Other/__SRP_A1B2"));
    }
    fn record(id: u16, payload: &[u8], out: &mut Vec<u8>) {
        out.extend_from_slice(&id.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
    }
    fn comp(data: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        for chunk in data.chunks(8) {
            body.push(0);
            body.extend_from_slice(chunk);
        }
        let total = body.len() + 2;
        let h = 0xb000u16 | ((total - 3) as u16);
        let mut out = vec![1];
        out.extend_from_slice(&h.to_le_bytes());
        out.extend_from_slice(&body);
        out
    }
    fn fixture_cfb() -> Vec<u8> {
        let mut dir = Vec::new();
        record(0x0001, &1u32.to_le_bytes(), &mut dir);
        record(0x0002, &0x0409u32.to_le_bytes(), &mut dir);
        record(0x0014, &0x0409u32.to_le_bytes(), &mut dir);
        record(0x0003, &1252u16.to_le_bytes(), &mut dir);
        record(0x0004, b"TestProject", &mut dir);
        dir.extend_from_slice(&0x0005u16.to_le_bytes());
        dir.extend_from_slice(&0u32.to_le_bytes());
        dir.extend_from_slice(&0x0040u16.to_le_bytes());
        dir.extend_from_slice(&0u32.to_le_bytes());
        dir.extend_from_slice(&0x0006u16.to_le_bytes());
        dir.extend_from_slice(&0u32.to_le_bytes());
        dir.extend_from_slice(&0x003du16.to_le_bytes());
        dir.extend_from_slice(&0u32.to_le_bytes());
        record(0x0007, &0u32.to_le_bytes(), &mut dir);
        record(0x0008, &0u32.to_le_bytes(), &mut dir);
        dir.extend_from_slice(&0x0009u16.to_le_bytes());
        dir.extend_from_slice(&4u32.to_le_bytes());
        dir.extend_from_slice(&1u32.to_le_bytes());
        dir.extend_from_slice(&1u16.to_le_bytes());
        let constants = b"Win64 = 1";
        dir.extend_from_slice(&0x000cu16.to_le_bytes());
        dir.extend_from_slice(&(constants.len() as u32).to_le_bytes());
        dir.extend_from_slice(constants);
        dir.extend_from_slice(&0x003cu16.to_le_bytes());
        let constants_u = "Win64 = 1"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        dir.extend_from_slice(&(constants_u.len() as u32).to_le_bytes());
        dir.extend_from_slice(&constants_u);
        // One optional REFERENCENAME followed by a registered-library reference.
        dir.extend_from_slice(&0x0016u16.to_le_bytes());
        dir.extend_from_slice(&6u32.to_le_bytes());
        dir.extend_from_slice(b"stdole");
        dir.extend_from_slice(&0x003eu16.to_le_bytes());
        let ref_name_u = "stdole"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        dir.extend_from_slice(&(ref_name_u.len() as u32).to_le_bytes());
        dir.extend_from_slice(&ref_name_u);
        let libid = b"stdole";
        dir.extend_from_slice(&0x000du16.to_le_bytes());
        dir.extend_from_slice(&((4 + libid.len() + 4 + 2) as u32).to_le_bytes());
        dir.extend_from_slice(&(libid.len() as u32).to_le_bytes());
        dir.extend_from_slice(libid);
        dir.extend_from_slice(&0u32.to_le_bytes());
        dir.extend_from_slice(&0u16.to_le_bytes());
        dir.extend_from_slice(&0x000fu16.to_le_bytes());
        dir.extend_from_slice(&2u32.to_le_bytes());
        dir.extend_from_slice(&1u16.to_le_bytes());
        dir.extend_from_slice(&0x0013u16.to_le_bytes());
        dir.extend_from_slice(&2u32.to_le_bytes());
        dir.extend_from_slice(&0xffffu16.to_le_bytes());
        record(0x0019, b"Mod1", &mut dir);
        let name16 = "Mod1"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        record(0x0047, &name16, &mut dir);
        record(0x001a, b"Mod1", &mut dir);
        dir.extend_from_slice(&0x0032u16.to_le_bytes());
        dir.extend_from_slice(&(name16.len() as u32).to_le_bytes());
        dir.extend_from_slice(&name16);
        record(0x001c, b"", &mut dir);
        dir.extend_from_slice(&0x0048u16.to_le_bytes());
        dir.extend_from_slice(&0u32.to_le_bytes());
        record(0x0031, &2u32.to_le_bytes(), &mut dir); // replace payload size below with a 4-byte offset value
        let off_record = dir.len() - 10;
        dir[off_record + 2..off_record + 6].copy_from_slice(&4u32.to_le_bytes());
        dir[off_record + 6..off_record + 10].copy_from_slice(&2u32.to_le_bytes());
        record(0x001e, &0u32.to_le_bytes(), &mut dir);
        record(0x002c, &0xffffu16.to_le_bytes(), &mut dir);
        record(0x0021, &0u32.to_le_bytes(), &mut dir);
        dir.extend_from_slice(&0x002bu16.to_le_bytes());
        dir.extend_from_slice(&0u32.to_le_bytes());
        let dir = comp(&dir);
        let project = b"Name=TestProject\r\nReference=stdole\r\n".to_vec();
        let vcache = vec![0xcc, 0x61, 0xff, 0xff, 0, 0, 0];
        let source = comp(
            b"Public Sub S()\r\nx=ThisWorkbook.Worksheets(\"Orders\").Range(\"A1\").Value\r\nEnd Sub\r\n",
        );
        let mut module = vec![0xde, 0xad];
        module.extend_from_slice(&source);
        let mut mini = vec![0u8; 704];
        let mut at = 0;
        mini[at..at + dir.len()].copy_from_slice(&dir);
        at = 384;
        mini[at..at + project.len()].copy_from_slice(&project);
        at = 448;
        mini[at..at + vcache.len()].copy_from_slice(&vcache);
        at = 512;
        mini[at..at + module.len()].copy_from_slice(&module);
        at = 640;
        mini[at..at + 3].copy_from_slice(&[0x53, 0x52, 0x50]);
        // The directory occupies mini-sectors 0..5; the other streams occupy 6..10.
        let mut dir_entries = vec![0u8; 1024];
        entry(
            &mut dir_entries,
            0,
            "Root Entry",
            5,
            0xffff_ffff,
            0xffff_ffff,
            1,
            4,
            704,
        );
        entry(
            &mut dir_entries,
            1,
            "VBA",
            1,
            0xffff_ffff,
            5,
            2,
            0xffff_ffff,
            0,
        );
        entry(
            &mut dir_entries,
            2,
            "dir",
            2,
            0xffff_ffff,
            3,
            0xffff_ffff,
            0,
            dir.len() as u64,
        );
        entry(
            &mut dir_entries,
            3,
            "Mod1",
            2,
            0xffff_ffff,
            4,
            0xffff_ffff,
            8,
            module.len() as u64,
        );
        entry(
            &mut dir_entries,
            4,
            "_VBA_PROJECT",
            2,
            0xffff_ffff,
            6,
            0xffff_ffff,
            4,
            7,
        );
        entry(
            &mut dir_entries,
            5,
            "PROJECT",
            2,
            0xffff_ffff,
            0xffff_ffff,
            0xffff_ffff,
            6,
            project.len() as u64,
        );
        entry(
            &mut dir_entries,
            6,
            "__SRP_A1B2",
            2,
            0xffff_ffff,
            0xffff_ffff,
            0xffff_ffff,
            10,
            3,
        );
        let mut file = vec![0u8; 512 + 6 * 512];
        file[..8].copy_from_slice(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
        put16(&mut file, 24, 0x003e);
        put16(&mut file, 26, 3);
        put16(&mut file, 28, 0xfffe);
        put16(&mut file, 30, 9);
        put16(&mut file, 32, 6);
        put32(&mut file, 44, 1);
        put32(&mut file, 48, 1);
        put32(&mut file, 56, 4096);
        put32(&mut file, 60, 3);
        put32(&mut file, 64, 1);
        put32(&mut file, 68, 0xffff_fffe);
        put32(&mut file, 72, 0);
        put32(&mut file, 76, 0);
        for i in 1..109 {
            put32(&mut file, 76 + i * 4, 0xffff_ffff);
        }
        let fat = 512;
        put32(&mut file, fat, 0xffff_fffd);
        put32(&mut file, fat + 4, 2);
        put32(&mut file, fat + 8, 0xffff_fffe);
        put32(&mut file, fat + 12, 0xffff_fffe);
        put32(&mut file, fat + 16, 5);
        put32(&mut file, fat + 20, 0xffff_fffe);
        put32(&mut file, fat + 24, 0xffff_ffff);
        file[1024..1536].copy_from_slice(&dir_entries[..512]);
        file[1536..2048].copy_from_slice(&dir_entries[512..]);
        put32(&mut file, 2048, 1);
        put32(&mut file, 2052, 2);
        put32(&mut file, 2056, 3);
        put32(&mut file, 2060, 4);
        put32(&mut file, 2064, 5);
        put32(&mut file, 2068, 0xffff_fffe);
        for i in 5..10 {
            put32(&mut file, 2048 + i * 4, 0xffff_fffe);
        }
        put32(&mut file, 2048 + 8 * 4, 9);
        put32(&mut file, 2048 + 9 * 4, 0xffff_fffe);
        put32(&mut file, 2048 + 10 * 4, 0xffff_fffe);
        for i in 11..128 {
            put32(&mut file, 2048 + i * 4, 0xffff_ffff);
        }
        file[2560..2560 + mini.len()].copy_from_slice(&mini);
        file
    }
    #[allow(clippy::too_many_arguments)]
    fn entry(
        buf: &mut [u8],
        id: usize,
        name: &str,
        kind: u8,
        left: u32,
        right: u32,
        child: u32,
        start: u32,
        size: u64,
    ) {
        let off = id * 128;
        for (i, u) in name.encode_utf16().chain(std::iter::once(0)).enumerate() {
            buf[off + i * 2..off + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        put16(
            buf,
            off + 64,
            ((name.encode_utf16().count() + 1) * 2) as u16,
        );
        buf[off + 66] = kind;
        put32(buf, off + 68, left);
        put32(buf, off + 72, right);
        put32(buf, off + 76, child);
        put32(buf, off + 116, start);
        buf[off + 120..off + 128].copy_from_slice(&size.to_le_bytes());
    }
    fn put16(b: &mut [u8], i: usize, v: u16) {
        b[i..i + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn put32(b: &mut [u8], i: usize, v: u32) {
        b[i..i + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn fixture_zip(payload: &[u8]) -> Vec<u8> {
        fixture_zip_with_vba_part_mode(payload, "xl/vbaProject.bin", "vbaProject.bin", None)
    }

    fn fixture_zip_with_vba_part(payload: &[u8], part_name: &str, target: &str) -> Vec<u8> {
        fixture_zip_with_vba_part_mode(payload, part_name, target, None)
    }

    fn fixture_zip_with_vba_part_mode(
        payload: &[u8],
        part_name: &str,
        target: &str,
        target_mode: Option<&str>,
    ) -> Vec<u8> {
        let package_relationships = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/></Relationships>";
        let target_mode = target_mode
            .map(|mode| format!(" TargetMode=\"{mode}\""))
            .unwrap_or_default();
        let workbook_relationships = format!(
            "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.microsoft.com/office/2006/relationships/vbaProject\" Target=\"{target}\"{target_mode}/><Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet1.xml\"/><Relationship Id=\"rId3\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet2.xml\"/><Relationship Id=\"rId4\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings\" Target=\"sharedStrings.xml\"/></Relationships>"
        );
        let content_types = format!(
            "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.ms-excel.sheet.macroEnabled.main+xml\"/><Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/><Override PartName=\"/xl/worksheets/sheet2.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/><Override PartName=\"/xl/sharedStrings.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml\"/><Override PartName=\"/xl/tables/table1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.table+xml\"/><Override PartName=\"/{part_name}\" ContentType=\"application/vnd.ms-office.vbaProject\"/></Types>"
        );
        let workbook = "<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><workbookPr codeName=\"MainBookCode\"/><sheets><sheet name=\"Orders\" sheetId=\"1\" r:id=\"rId2\"/><sheet name=\"Archive\" sheetId=\"2\" state=\"veryHidden\" r:id=\"rId3\"/></sheets><definedNames><definedName name=\"TaxRate\">0.075</definedName><definedName name=\"OrdersData\" localSheetId=\"0\">'Orders'!$A$1:$B$10</definedName><definedName name=\"_xlnm.Print_Area\" localSheetId=\"0\" hidden=\"1\">'Orders'!$A$1:$B$10</definedName><definedName name=\"FormulaJoin\">=&quot;A&quot;&amp;&quot;B&quot;</definedName></definedNames></workbook>";
        let sheet1 = "<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><sheetPr codeName=\"OrdersCode\"/><sheetData><row r=\"1\"><c r=\"A1\"><v>10</v></c><c r=\"B1\" t=\"s\"><v>0</v></c><c r=\"C1\" t=\"inlineStr\"><is><t xml:space=\"preserve\"> Inline Text </t></is></c><c r=\"D1\"><f>A1+TaxRate+OrdersTable[Shared &amp; Text]</f><v>11</v></c><c r=\"E1\" t=\"b\"><v>1</v></c><c r=\"F1\" t=\"s\"><v>1</v></c></row><row r=\"2\"><c r=\"A2\"><v>20</v></c><c r=\"B2\" t=\"inlineStr\"><is><t>OK</t></is></c></row></sheetData><tableParts count=\"1\"><tablePart r:id=\"rId1\"/></tableParts></worksheet>";
        let sheet2 = "<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData><row r=\"1\"><c r=\"A1\"><v>3</v></c></row></sheetData></worksheet>";
        let sheet1_relationships = "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/table\" Target=\"../tables/table1.xml\"/></Relationships>";
        let table1 = "<table xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" id=\"1\" name=\"OrdersTable\" displayName=\"OrdersTable\" ref=\"A1:B2\" headerRowCount=\"1\" totalsRowCount=\"0\"><autoFilter ref=\"A1:B2\"/><tableColumns count=\"2\"><tableColumn id=\"1\" name=\"10\"/><tableColumn id=\"2\" name=\"Shared &amp; Text\"/></tableColumns></table>";
        let shared_strings = "<sst xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" count=\"2\" uniqueCount=\"2\"><si><t>Shared &amp; Text</t></si><si><r><t>Rich</t></r><r><t xml:space=\"preserve\"> Text</t></r></si></sst>";
        let entries = [
            ("[Content_Types].xml", content_types.as_bytes()),
            ("_rels/.rels", package_relationships.as_bytes()),
            ("xl/workbook.xml", workbook.as_bytes()),
            (
                "xl/_rels/workbook.xml.rels",
                workbook_relationships.as_bytes(),
            ),
            ("xl/worksheets/sheet1.xml", sheet1.as_bytes()),
            (
                "xl/worksheets/_rels/sheet1.xml.rels",
                sheet1_relationships.as_bytes(),
            ),
            ("xl/worksheets/sheet2.xml", sheet2.as_bytes()),
            ("xl/sharedStrings.xml", shared_strings.as_bytes()),
            ("xl/tables/table1.xml", table1.as_bytes()),
            (part_name, payload),
        ];
        let mut z = Vec::new();
        let mut records = Vec::new();
        for (name, payload) in &entries {
            let name = name.as_bytes();
            let crc = crc32(payload);
            let local_offset = z.len() as u32;
            z.extend_from_slice(&0x04034b50u32.to_le_bytes());
            z.extend_from_slice(&20u16.to_le_bytes());
            z.extend_from_slice(&0u16.to_le_bytes());
            z.extend_from_slice(&0u16.to_le_bytes());
            z.extend_from_slice(&[0; 4]);
            z.extend_from_slice(&crc.to_le_bytes());
            z.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            z.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            z.extend_from_slice(&(name.len() as u16).to_le_bytes());
            z.extend_from_slice(&0u16.to_le_bytes());
            z.extend_from_slice(name);
            z.extend_from_slice(payload);
            records.push((name, crc, payload.len() as u32, local_offset));
        }
        let cd = z.len();
        for (name, crc, size, local_offset) in &records {
            z.extend_from_slice(&0x02014b50u32.to_le_bytes());
            z.extend_from_slice(&[20, 0, 20, 0, 0, 0]);
            z.extend_from_slice(&0u16.to_le_bytes());
            z.extend_from_slice(&[0; 4]);
            z.extend_from_slice(&crc.to_le_bytes());
            z.extend_from_slice(&size.to_le_bytes());
            z.extend_from_slice(&size.to_le_bytes());
            z.extend_from_slice(&(name.len() as u16).to_le_bytes());
            z.extend_from_slice(&[0; 6]);
            z.extend_from_slice(&[0; 6]);
            z.extend_from_slice(&local_offset.to_le_bytes());
            z.extend_from_slice(name);
        }
        let cdsize = z.len() - cd;
        z.extend_from_slice(&0x06054b50u32.to_le_bytes());
        z.extend_from_slice(&[0; 4]);
        z.extend_from_slice(&(records.len() as u16).to_le_bytes());
        z.extend_from_slice(&(records.len() as u16).to_le_bytes());
        z.extend_from_slice(&(cdsize as u32).to_le_bytes());
        z.extend_from_slice(&(cd as u32).to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes());
        z
    }

    #[test]
    fn extract_macro_container_rejects_random_data() {
        let err = extract_macro_container(b"Not an office file", &Limits::default()).unwrap_err();
        assert!(err.contains("unrecognized macro container format"));
    }
}
