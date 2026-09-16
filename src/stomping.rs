//! VBA Stomping and source-tampering detection engine.
//!
//! "VBA Stomping" refers to the technique where the source code in a VBA module
//! is altered, emptied, or purged to evade static text scanners, while the compiled
//! P-code execution cache is retained and executed by Microsoft Office.
//!
//! This module compares extracted VBA source code with disassembled P-code representations
//! to detect discrepancies in declared procedures, called APIs, string literals, and code size.

use crate::pcode::DisassembledPCodeModule;

/// Severity classification for VBA Stomping findings.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum StompingSeverity {
    Clean,
    Low,
    Medium,
    High,
    Critical,
}

impl StompingSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// Category of discrepancy detected between source code and compiled P-code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StompingFindingKind {
    /// The source code is absent, emptied, or purged while compiled P-code instructions exist.
    SourcePurged,
    /// The source code container could not be decompressed or is damaged while compiled P-code instructions exist.
    SourceCorruptedWithValidPCode(String),
    /// A procedure is present in the P-code execution stream but absent from the source code.
    ProcedureHiddenInPCode(String),
    /// A procedure declared in the source code does not exist in the P-code stream.
    ProcedureMissingInPCode(String),
    /// A sensitive or suspicious string literal (e.g., URL, executable, command) is found in P-code but not in source code.
    SuspiciousLiteralInPCode(String),
    /// Sensitive calls or dangerous APIs found in P-code are missing from the source text.
    SensitiveCallInPCode(String),
    /// Extreme discrepancy between source line count and P-code line count.
    LineCountDiscrepancy {
        source_lines: usize,
        pcode_lines: usize,
    },
    /// Compiled P-code performance cache has been purged (text offset 0, empty cache) to evade compiled cache scanners.
    PerformanceCachePurged { source_lines: usize },
    /// The module exists in the dir stream but is omitted from the PROJECT manifest (Evil Clippy GUI hiding).
    HiddenGuiModule(String),
    /// The VBA project contains protection/lock attributes (CMG/DPB/GC) making it unviewable in the VBA IDE.
    ProjectLockedOrUnviewable,
}

/// Detailed finding describing a specific discrepancy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StompingFinding {
    pub severity: StompingSeverity,
    pub kind: StompingFindingKind,
    pub description: String,
}

/// Result of evaluating a module for VBA Stomping / tampering.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleStompingReport {
    pub module_name: String,
    pub severity: StompingSeverity,
    pub confidence_score: u8, // 0 to 100
    pub is_stomped: bool,
    pub findings: Vec<StompingFinding>,
    pub source_procedure_count: usize,
    pub pcode_procedure_count: usize,
    pub source_line_count: usize,
    pub pcode_line_count: usize,
}

/// Comprehensive project-level stomping evaluation report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectStompingReport {
    pub overall_severity: StompingSeverity,
    pub has_stomping: bool,
    pub project_findings: Vec<StompingFinding>,
    pub modules: Vec<ModuleStompingReport>,
}

/// Known high-risk or suspicious keywords commonly associated with macro malware payloads.
static SUSPICIOUS_PATTERNS: &[&str] = &[
    "http://",
    "https://",
    "ftp://",
    "powershell",
    "pwsh",
    "cmd.exe",
    "wscript",
    "cscript",
    "certutil",
    "bitsadmin",
    "rundll32",
    "regsvr32",
    "mshta",
    "wmic",
    "curl",
    "msiexec",
    "schtasks",
    "invoke-expression",
    "invoke-webrequest",
    "downloadfile",
    "downloadstring",
    "createtextfile",
    "urldownloadtofile",
    "winexec",
    "shellexecute",
    "-encodedcommand",
    "-enc ",
    "-executionpolicy bypass",
    "-ep bypass",
    "-windowstyle hidden",
    "-w hidden",
    ".exe",
    ".dll",
    ".vbs",
    ".bat",
    ".ps1",
    ".vbe",
    ".hta",
    ".scr",
    ".pif",
];

/// Known sensitive APIs or procedure names.
static SENSITIVE_CALLS: &[&str] = &[
    "Shell",
    "CreateObject",
    "GetObject",
    "URLDownloadToFile",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "URLDownloadToCacheFileA",
    "WinExec",
    "ShellExecute",
    "ShellExecuteA",
    "ShellExecuteW",
    "CreateProcess",
    "CreateProcessA",
    "CreateProcessW",
    "CreateThread",
    "OpenProcess",
    "TerminateProcess",
    "InternetOpen",
    "InternetOpenA",
    "InternetOpenW",
    "InternetOpenUrl",
    "InternetOpenUrlA",
    "InternetOpenUrlW",
    "HttpOpenRequest",
    "HttpSendRequest",
    "HttpSendRequestA",
    "HttpSendRequestW",
    "WinHttpOpen",
    "WinHttpConnect",
    "WinHttpSendRequest",
    "VirtualAlloc",
    "VirtualAllocEx",
    "VirtualProtect",
    "VirtualProtectEx",
    "RtlMoveMemory",
    "WriteProcessMemory",
    "ReadProcessMemory",
    "CreateRemoteThread",
    "QueueUserAPC",
    "NtTestAlert",
    "MapViewOfFile",
    "CreateFileMappingA",
    "CreateFileMappingW",
    "WScript.Shell",
    "Shell.Application",
    "Scripting.FileSystemObject",
    "ADODB.Stream",
    "MSXML2.XMLHTTP",
    "MSXML2.ServerXMLHTTP",
    "Microsoft.XMLHTTP",
    "Schedule.Service",
    "WbemScripting.SWbemLocator",
    "System.Diagnostics.Process",
    "ExecuteExcel4Macro",
    "MacScript",
    "CallByName",
    "Application.Run",
    "ShellExecuteEx",
    "NtCreateSection",
    "ZwMapViewOfSection",
    "NtMapViewOfSection",
    "SetTimer",
    "KillTimer",
    "VirtualAllocEx",
    "OpenProcess",
    "GetProcAddress",
    "LoadLibrary",
    "LoadLibraryA",
    "LoadLibraryW",
    "LdrLoadDll",
    "CreateRemoteThread",
    "HeapAlloc",
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "Sleep",
];

/// Common auto-execution hook procedures frequently targeted in macro attacks.
static AUTO_EXEC_HOOKS: &[&str] = &[
    "autoopen",
    "autoclose",
    "autonew",
    "autoexec",
    "autoexit",
    "auto_open",
    "auto_close",
    "auto_activate",
    "auto_deactivate",
    "document_open",
    "document_close",
    "document_new",
    "documentopen",
    "documentnew",
    "workbook_open",
    "workbook_beforeclose",
    "workbook_activate",
    "workbook_deactivate",
    "userform_initialize",
    "userform_activate",
];

/// Check if a procedure name matches a known auto-execution hook.
pub fn is_auto_exec_hook(name: &str) -> bool {
    AUTO_EXEC_HOOKS.iter().any(|h| name.eq_ignore_ascii_case(h))
}

/// Inspect a module for evidence of VBA Stomping by contrasting source text and P-code disassembly.
pub fn detect_vba_stomping(
    module_name: &str,
    source_text: Option<&str>,
    pcode: Option<&DisassembledPCodeModule>,
) -> ModuleStompingReport {
    detect_vba_stomping_with_error(module_name, source_text, None, pcode)
}

/// Inspect a module for evidence of VBA Stomping, taking into account any source decompression or stream corruption errors.
pub fn detect_vba_stomping_with_error(
    module_name: &str,
    source_text: Option<&str>,
    source_error: Option<&str>,
    pcode: Option<&DisassembledPCodeModule>,
) -> ModuleStompingReport {
    // Analyze source text first
    let (source_lines, source_procs, source_effective_code) = match source_text {
        Some(src) => {
            let lines: Vec<&str> = src.lines().collect();
            let mut procs = Vec::new();
            let mut effective_lines = 0;
            for line in &lines {
                let trimmed = line.trim();
                if trimmed.is_empty()
                    || trimmed.starts_with('\'')
                    || trimmed.to_ascii_uppercase().starts_with("REM")
                    || trimmed.to_ascii_uppercase().starts_with("ATTRIBUTE")
                {
                    continue;
                }
                effective_lines += 1;
                let upper = trimmed.to_ascii_uppercase();
                for kw in &[
                    "SUB ",
                    "FUNCTION ",
                    "PROPERTY GET ",
                    "PROPERTY LET ",
                    "PROPERTY SET ",
                ] {
                    if let Some(idx) = upper.find(kw) {
                        let after = trimmed[idx + kw.len()..].trim_start();
                        let name: String = after
                            .chars()
                            .take_while(|c| c.is_alphanumeric() || *c == '_')
                            .collect();
                        if !name.is_empty() && !procs.contains(&name) {
                            procs.push(name);
                        }
                    }
                }
            }
            (lines.len(), procs, effective_lines)
        }
        None => (0, Vec::new(), 0),
    };

    let pcode_module = match pcode {
        Some(p) => p,
        None => {
            let mut findings = Vec::new();
            let mut score = 0u8;
            if !source_procs.is_empty() && source_effective_code > 0 {
                findings.push(StompingFinding {
                    severity: StompingSeverity::Medium,
                    kind: StompingFindingKind::PerformanceCachePurged { source_lines },
                    description: format!(
                        "Module '{}' contains declared VBA procedures ({}) but lacks compiled P-code performance cache (VBA Purging pattern).",
                        module_name,
                        source_procs.join(", ")
                    ),
                });
                score = 35;
            }
            let severity = if score >= 25 {
                StompingSeverity::Medium
            } else {
                StompingSeverity::Clean
            };
            return ModuleStompingReport {
                module_name: module_name.to_string(),
                severity,
                confidence_score: score,
                is_stomped: false,
                findings,
                source_procedure_count: source_procs.len(),
                pcode_procedure_count: 0,
                source_line_count: source_lines,
                pcode_line_count: 0,
            };
        }
    };

    let mut findings = Vec::new();
    let mut score = 0u8;

    let pcode_line_count = pcode_module.lines.len();
    let pcode_instruction_count: usize = pcode_module
        .lines
        .iter()
        .map(|l| l.instructions.len())
        .sum();
    let pcode_proc_count = pcode_module.declared_procedures.len();
    let normalized_source = source_text.unwrap_or("").to_ascii_lowercase();

    // 1. Performance Cache Purged Check: Source has real code, but compiled P-code instructions are 0 (VBA Purging)
    if pcode_instruction_count == 0 && !source_procs.is_empty() && source_effective_code > 0 {
        findings.push(StompingFinding {
            severity: StompingSeverity::Medium,
            kind: StompingFindingKind::PerformanceCachePurged { source_lines },
            description: format!(
                "Module '{}' contains declared VBA procedures ({}) but has 0 compiled P-code instructions (VBA Purging pattern).",
                module_name,
                source_procs.join(", ")
            ),
        });
        score = score.saturating_add(35);
    }

    // 1. Source Corrupted or Purged Check: P-code exists with executable instructions
    if let Some(err) = source_error {
        if pcode_instruction_count > 0 {
            findings.push(StompingFinding {
                severity: StompingSeverity::Critical,
                kind: StompingFindingKind::SourceCorruptedWithValidPCode(err.to_string()),
                description: format!(
                    "Module '{}' has {} P-code instructions across {} lines, but its source code container is corrupted or malformed ('{}') (anti-analysis stomping evasion).",
                    module_name, pcode_instruction_count, pcode_line_count, err
                ),
            });
            score = score.saturating_add(95);
        }
    } else if pcode_instruction_count > 0 && (source_lines == 0 || source_effective_code == 0) {
        findings.push(StompingFinding {
            severity: StompingSeverity::Critical,
            kind: StompingFindingKind::SourcePurged,
            description: format!(
                "Module '{}' has {} P-code instructions across {} lines, but source code is completely purged or empty.",
                module_name, pcode_instruction_count, pcode_line_count
            ),
        });
        score = score.saturating_add(95);
    }

    // 2. Procedure Mismatch: Procedures found in P-code that are NOT in source text
    for pcode_proc in &pcode_module.declared_procedures {
        let found = source_procs
            .iter()
            .any(|sp| sp.eq_ignore_ascii_case(pcode_proc));
        if !found {
            let is_auto_hook = AUTO_EXEC_HOOKS
                .iter()
                .any(|h| pcode_proc.eq_ignore_ascii_case(h));
            let (severity, add_score, description) = if is_auto_hook {
                (
                    StompingSeverity::Critical,
                    60u8,
                    format!(
                        "Auto-executing procedure hook '{}' is compiled into P-code but completely hidden from readable VBA source.",
                        pcode_proc
                    ),
                )
            } else {
                (
                    StompingSeverity::High,
                    40u8,
                    format!(
                        "Procedure '{}' is compiled into P-code but does not exist in the readable VBA source.",
                        pcode_proc
                    ),
                )
            };
            findings.push(StompingFinding {
                severity,
                kind: StompingFindingKind::ProcedureHiddenInPCode(pcode_proc.clone()),
                description,
            });
            score = score.saturating_add(add_score);
        }
    }

    // Check procedures in source but missing in P-code
    for src_proc in &source_procs {
        let found = pcode_module
            .declared_procedures
            .iter()
            .any(|pp| pp.eq_ignore_ascii_case(src_proc));
        if !found && pcode_proc_count > 0 {
            findings.push(StompingFinding {
                severity: StompingSeverity::Medium,
                kind: StompingFindingKind::ProcedureMissingInPCode(src_proc.clone()),
                description: format!(
                    "Procedure '{}' declared in source text is missing in the compiled P-code stream.",
                    src_proc
                ),
            });
            score = score.saturating_add(20);
        }
    }

    // 3. String Literal Discrepancies (especially suspicious ones)
    for lit in &pcode_module.string_literals {
        let lit_lower = lit.to_ascii_lowercase();
        // Check if literal is in source
        if !normalized_source.contains(&lit_lower) {
            // Is it a suspicious pattern?
            let is_suspicious = SUSPICIOUS_PATTERNS
                .iter()
                .any(|&pat| lit_lower.contains(pat));
            if is_suspicious {
                findings.push(StompingFinding {
                    severity: StompingSeverity::Critical,
                    kind: StompingFindingKind::SuspiciousLiteralInPCode(lit.clone()),
                    description: format!(
                        "Suspicious literal \"{}\" is embedded in compiled P-code but entirely missing from VBA source text.",
                        lit
                    ),
                });
                score = score.saturating_add(50);
            } else if lit.len() > 10 {
                // Non-trivial mismatch
                findings.push(StompingFinding {
                    severity: StompingSeverity::Low,
                    kind: StompingFindingKind::SuspiciousLiteralInPCode(lit.clone()),
                    description: format!(
                        "String literal \"{}\" in P-code is not found in source text.",
                        lit
                    ),
                });
                score = score.saturating_add(5);
            }
        }
    }

    // 4. Sensitive API Call Discrepancies
    for call in &pcode_module.called_procedures {
        let is_sensitive = SENSITIVE_CALLS
            .iter()
            .any(|&s| s.eq_ignore_ascii_case(call));
        if is_sensitive {
            let in_source = normalized_source.contains(&call.to_ascii_lowercase());
            if !in_source {
                findings.push(StompingFinding {
                    severity: StompingSeverity::High,
                    kind: StompingFindingKind::SensitiveCallInPCode(call.clone()),
                    description: format!(
                        "Potentially hazardous call to '{}' found in P-code is not visible in source text.",
                        call
                    ),
                });
                score = score.saturating_add(45);
            }
        }
    }

    // 5. Line Count Discrepancies (if ratio is extreme)
    if source_lines > 0
        && pcode_line_count > 0
        && pcode_line_count > source_lines * 4
        && pcode_line_count > 20
    {
        findings.push(StompingFinding {
            severity: StompingSeverity::Medium,
            kind: StompingFindingKind::LineCountDiscrepancy {
                source_lines,
                pcode_lines: pcode_line_count,
            },
            description: format!(
                "P-code has {} lines while source text has only {} lines (large divergence).",
                pcode_line_count, source_lines
            ),
        });
        score = score.saturating_add(25);
    }

    let final_score = score.min(100);
    let score_severity = if final_score >= 80 {
        StompingSeverity::Critical
    } else if final_score >= 50 {
        StompingSeverity::High
    } else if final_score >= 25 {
        StompingSeverity::Medium
    } else if final_score > 0 {
        StompingSeverity::Low
    } else {
        StompingSeverity::Clean
    };
    let max_finding_severity = findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(StompingSeverity::Clean);
    let severity = score_severity.max(max_finding_severity);

    ModuleStompingReport {
        module_name: module_name.to_string(),
        severity,
        confidence_score: final_score,
        is_stomped: final_score >= 50,
        findings,
        source_procedure_count: source_procs.len(),
        pcode_procedure_count: pcode_proc_count,
        source_line_count: source_lines,
        pcode_line_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::{DisassembledInstruction, DisassembledPCodeLine};

    fn make_synthetic_pcode(
        declared_procs: &[&str],
        calls: &[&str],
        literals: &[&str],
        line_count: usize,
    ) -> DisassembledPCodeModule {
        let mut lines = Vec::new();
        for i in 0..line_count {
            lines.push(DisassembledPCodeLine {
                line_number: i + 1,
                instructions: vec![DisassembledInstruction::simple(0, 0, 0, "Nop", "Nop")],
                formatted_text: format!("Line #{}:\n\tNop\n", i + 1),
            });
        }
        DisassembledPCodeModule {
            module_name: "Module1".into(),
            lines,
            declared_procedures: declared_procs.iter().map(|s| s.to_string()).collect(),
            string_literals: literals.iter().map(|s| s.to_string()).collect(),
            called_procedures: calls.iter().map(|s| s.to_string()).collect(),
            is_stomped_suspect: false,
        }
    }

    #[test]
    fn clean_module_reports_clean() {
        let source = "Attribute VB_Name = \"Module1\"\nSub Main()\n    MsgBox \"Hello\"\nEnd Sub\n";
        let pcode = make_synthetic_pcode(&["Main"], &["MsgBox"], &["Hello"], 4);
        let report = detect_vba_stomping("Module1", Some(source), Some(&pcode));

        assert_eq!(report.severity, StompingSeverity::Clean);
        assert!(!report.is_stomped);
        assert_eq!(report.confidence_score, 0);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn detects_source_purged_stomping() {
        let source = "Attribute VB_Name = \"Module1\"\n";
        let pcode = make_synthetic_pcode(&["ExecutePayload"], &["Shell"], &["calc.exe"], 10);
        let report = detect_vba_stomping("Module1", Some(source), Some(&pcode));

        assert!(report.is_stomped);
        assert_eq!(report.severity, StompingSeverity::Critical);
        assert!(report.confidence_score >= 80);
        assert!(
            report
                .findings
                .iter()
                .any(|f| matches!(f.kind, StompingFindingKind::SourcePurged))
        );
    }

    #[test]
    fn detects_hidden_procedure_in_pcode() {
        let source = "Sub Harmless()\n    Dim x As Integer\nEnd Sub\n";
        let pcode = make_synthetic_pcode(&["Harmless", "SecretBackdoor"], &[], &[], 6);
        let report = detect_vba_stomping("Module1", Some(source), Some(&pcode));

        assert!(report.findings.iter().any(|f| matches!(
            &f.kind,
            StompingFindingKind::ProcedureHiddenInPCode(name) if name == "SecretBackdoor"
        )));
    }

    #[test]
    fn detects_suspicious_literal_in_pcode() {
        let source = "Sub Test()\n    MsgBox \"Everything is fine\"\nEnd Sub\n";
        let pcode = make_synthetic_pcode(
            &["Test"],
            &["MsgBox"],
            &["Everything is fine", "http://evil.example.com/malware.exe"],
            5,
        );
        let report = detect_vba_stomping("Module1", Some(source), Some(&pcode));

        assert!(report.is_stomped);
        assert!(report.confidence_score >= 50);
        assert!(report.findings.iter().any(|f| matches!(
            &f.kind,
            StompingFindingKind::SuspiciousLiteralInPCode(lit) if lit.contains("evil.example.com")
        )));
    }

    #[test]
    fn detects_sensitive_api_call_discrepancy() {
        let source = "Sub RunWork()\n    Dim a As Integer\nEnd Sub\n";
        let pcode = make_synthetic_pcode(&["RunWork"], &["Shell", "URLDownloadToFile"], &[], 5);
        let report = detect_vba_stomping("Module1", Some(source), Some(&pcode));

        assert!(report.is_stomped);
        assert!(report.findings.iter().any(|f| matches!(
            &f.kind,
            StompingFindingKind::SensitiveCallInPCode(call) if call == "Shell"
        )));
        assert!(report.findings.iter().any(|f| matches!(
            &f.kind,
            StompingFindingKind::SensitiveCallInPCode(call) if call == "URLDownloadToFile"
        )));
    }

    #[test]
    fn detects_hidden_auto_exec_procedure_in_pcode() {
        let source = "Sub Harmless()\n    Dim x As Integer\nEnd Sub\n";
        let pcode = make_synthetic_pcode(&["Harmless", "AutoOpen"], &[], &[], 6);
        let report = detect_vba_stomping("Module1", Some(source), Some(&pcode));

        assert!(report.is_stomped);
        assert_eq!(report.severity, StompingSeverity::Critical);
        assert_eq!(report.confidence_score, 60);
        assert!(report.findings.iter().any(|f| {
            f.severity == StompingSeverity::Critical
                && matches!(&f.kind, StompingFindingKind::ProcedureHiddenInPCode(name) if name == "AutoOpen")
                && f.description.contains("Auto-executing procedure hook")
        }));
    }
}
