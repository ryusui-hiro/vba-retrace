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

    // 1. Inspect package parts / entry names for embedded binaries and controls
    for entry in zip.entries.iter().take(max_entries) {
        let name_lower = entry.name.to_ascii_lowercase();
        let is_dir = entry.name.ends_with('/') || entry.name.ends_with('\\');
        if is_dir {
            continue;
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

        // Check for suspicious drawings, slides, and VML form controls
        let is_drawing_or_slide = (name_lower.contains("/drawings/drawing")
            || name_lower.starts_with("drawings/drawing")
            || name_lower.contains("\\drawings\\drawing")
            || name_lower.contains("vmldrawing")
            || name_lower.contains("/slides/slide")
            || name_lower.starts_with("slides/slide")
            || name_lower.contains("/notesslides/notesslide"))
            && (name_lower.ends_with(".xml") || name_lower.ends_with(".vml"));
        if is_drawing_or_slide {
            let Ok(data) = zip.read(entry) else { continue };
            let s = String::from_utf8_lossy(&data);
            let s_lower = s.to_ascii_lowercase();

            let mut indicator: Option<(&'static str, String)> = None;
            if s_lower.contains("ppaction://program") {
                indicator = Some((
                    "Critical",
                    "Shape or slide action launches external program ('ppaction://program')".into(),
                ));
            } else if s_lower.contains("ppaction://macro") {
                indicator = Some((
                    "High",
                    "Shape or slide action executes macro ('ppaction://macro')".into(),
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
                if (rel_type.contains("subdocument") || rel_type.contains("frame")) && is_ext {
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

                // Check for Suspicious Protocol Handler (ms-msdt, search-ms, ms-appinstaller, mhtml, javascript, vbscript, remote file://)
                let target_lower = rel.target.to_ascii_lowercase();
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
