use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;
use vba_insight::compiled::PCodeLayoutProfile;
use vba_insight::export::{
    Disclosure, disasm_to_json, disasm_to_markdown, inspect_to_json, inspect_to_markdown,
    stomping_to_json, stomping_to_markdown, stomping_to_sarif, to_dot_with_disclosure, to_json,
};
use vba_insight::extract::{extract_macro_container, extract_xlsm_with_pcode_profile};
use vba_insight::host::HostProfile;
use vba_insight::model::{Analysis, SourceUnit};
use vba_insight::{
    AnalysisOptions, Limits, analyze, analyze_extracted_project, detect_entry_points,
    detect_project_stomping, disassemble_extracted_project, inspect_macro_file,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vba-insight: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let command = args.next().ok_or_else(usage)?;
    if command == "--help" || command == "-h" {
        println!("{}", usage());
        return Ok(());
    }
    if command != "analyze"
        && command != "extract"
        && command != "disasm"
        && command != "stomping"
        && command != "inspect"
    {
        return Err(usage());
    }

    let mut paths = Vec::new();
    let mut user_format: Option<String> = None;
    let mut include_source = false;
    let mut source_code_page = None;
    let mut conditional_constants = BTreeMap::new();
    let mut pcode_profile = None;
    let mut host_profile = HostProfile::Unknown;
    let mut host_overridden = false;

    while let Some(a) = args.next() {
        match a.as_str() {
            "--include-source" => include_source = true,
            "--format" => user_format = Some(args.next().ok_or("--format requires an argument")?),
            "--code-page" => {
                source_code_page = Some(
                    args.next()
                        .ok_or("--code-page needs a number")?
                        .parse::<u16>()
                        .map_err(|_| "invalid --code-page value")?,
                )
            }
            "--define" => {
                let pair = args.next().ok_or("--define needs NAME=VALUE")?;
                let (name, value) = pair.split_once('=').ok_or("--define needs NAME=VALUE")?;
                conditional_constants.insert(name.trim().into(), value.trim().into());
            }
            "--pcode-profile" => {
                let profile = args.next().ok_or("--pcode-profile needs vba7-observed")?;
                if profile != "vba7-observed" {
                    return Err("supported p-code layout profile: vba7-observed".into());
                }
                pcode_profile = Some(PCodeLayoutProfile::Vba7Observed);
            }
            "--host" => {
                host_profile = match args.next().as_deref() {
                    Some("excel") => HostProfile::Excel,
                    Some("word") => HostProfile::Word,
                    Some("powerpoint") => HostProfile::PowerPoint,
                    Some("access") => HostProfile::Access,
                    Some("generic") | Some("unknown") => HostProfile::Unknown,
                    _ => {
                        return Err(
                            "--host must be excel, word, powerpoint, access, or generic".into()
                        );
                    }
                };
                host_overridden = true;
            }
            "--help" | "-h" => {
                println!("{}", usage());
                return Ok(());
            }
            _ if a.starts_with('-') => return Err(format!("unknown option {a}\n{}", usage())),
            _ => paths.push(a),
        }
    }

    if paths.is_empty() {
        return Err(usage());
    }

    let default_format = match command.as_str() {
        "analyze" | "extract" => "json",
        "disasm" | "stomping" | "inspect" => "text",
        _ => "text",
    };
    let format = user_format.unwrap_or_else(|| default_format.to_string());

    // Validate format per command
    match command.as_str() {
        "analyze" => {
            if format != "json" && format != "dot" {
                return Err("format for analyze must be json or dot".into());
            }
        }
        "extract" => {
            if format != "json" {
                return Err("format for extract must be json".into());
            }
        }
        "disasm" => {
            if format != "json" && format != "markdown" && format != "text" {
                return Err("format for disasm must be json, markdown, or text".into());
            }
        }
        "stomping" => {
            if format != "json" && format != "sarif" && format != "markdown" && format != "text" {
                return Err("format for stomping must be json, sarif, markdown, or text".into());
            }
        }
        "inspect" => {
            if format != "json" && format != "markdown" && format != "text" {
                return Err("format for inspect must be json, markdown, or text".into());
            }
        }
        _ => {}
    }

    let limits = Limits::default();
    let mut sources = Vec::new();
    let mut extracted = None;
    let mut kind = None;
    let mut primary_bytes: Option<Vec<u8>> = None;

    for p in &paths {
        let bytes = fs::read(p).map_err(|e| format!("cannot read {p}: {e}"))?;
        if bytes.len() > limits.max_input_bytes {
            return Err(format!("input file exceeds configured limit: {p}"));
        }

        let is_container = bytes.starts_with(b"PK\x03\x04")
            || bytes.starts_with(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])
            || Path::new(p).extension().is_some_and(|e| {
                let s = e.to_string_lossy();
                s.eq_ignore_ascii_case("xlsm")
                    || s.eq_ignore_ascii_case("xltm")
                    || s.eq_ignore_ascii_case("xlam")
                    || s.eq_ignore_ascii_case("xlsb")
                    || s.eq_ignore_ascii_case("docm")
                    || s.eq_ignore_ascii_case("dotm")
                    || s.eq_ignore_ascii_case("pptm")
                    || s.eq_ignore_ascii_case("ppam")
                    || s.eq_ignore_ascii_case("xls")
                    || s.eq_ignore_ascii_case("bin")
            });

        if is_container {
            if paths.len() != 1 {
                return Err("a macro container must be analyzed as a single input".into());
            }
            let x = if let Some(profile) = pcode_profile {
                extract_xlsm_with_pcode_profile(&bytes, &limits, profile, 65_535)?
            } else {
                extract_macro_container(&bytes, &limits)?
            };
            if !host_overridden {
                host_profile = HostProfile::Excel;
            }
            kind = Some("macro_container");
            extracted = Some(x);
            primary_bytes = Some(bytes);
        } else {
            if pcode_profile.is_some() {
                return Err("--pcode-profile requires a macro container input".into());
            }
            let text = vba_insight::source::decode_text(&bytes, source_code_page)
                .map_err(|e| format!("{p}: {e}"))?;
            sources.push(SourceUnit {
                name: p.clone(),
                text,
            });
            kind = Some("exported_vba_text");
        }
    }

    let analysis_options = AnalysisOptions {
        limits,
        conditional_constants,
        project_references: Vec::new(),
        host_profile,
    };

    let disclosure = if include_source {
        Disclosure::IncludeSource
    } else {
        Disclosure::StructureOnly
    };

    if command == "disasm" {
        let Some(x) = &extracted else {
            return Err("disasm command requires a macro container input".into());
        };
        let disasms = disassemble_extracted_project(x)?;
        match format.as_str() {
            "json" => println!("{}", disasm_to_json(&disasms)),
            "markdown" => print!("{}", disasm_to_markdown(&disasms)),
            _ => {
                for mod_disasm in disasms {
                    println!("=== Module: {} ===", mod_disasm.module_name);
                    println!("Procedures: {:?}", mod_disasm.declared_procedures);
                    println!("Calls: {:?}", mod_disasm.called_procedures);
                    println!("Strings: {:?}", mod_disasm.string_literals);
                    for line in &mod_disasm.lines {
                        print!("{}", line.formatted_text);
                    }
                    println!();
                }
            }
        }
        return Ok(());
    }

    if command == "stomping" {
        let Some(x) = &extracted else {
            return Err("stomping command requires a macro container input".into());
        };
        let report = detect_project_stomping(x)?;
        match format.as_str() {
            "json" => println!("{}", stomping_to_json(&report)),
            "sarif" => println!("{}", stomping_to_sarif(&report, &paths[0])),
            "markdown" => print!("{}", stomping_to_markdown(&report)),
            _ => {
                println!(
                    "Overall Stomping Severity: {}",
                    report.overall_severity.as_str()
                );
                println!("Has Stomping: {}", report.has_stomping);
                for m in &report.modules {
                    println!("--- Module: {} ---", m.module_name);
                    println!(
                        "  Severity: {} (Confidence: {}%)",
                        m.severity.as_str(),
                        m.confidence_score
                    );
                    println!(
                        "  Source lines: {}, P-code lines: {}",
                        m.source_line_count, m.pcode_line_count
                    );
                    println!(
                        "  Source procs: {}, P-code procs: {}",
                        m.source_procedure_count, m.pcode_procedure_count
                    );
                    for finding in &m.findings {
                        println!(
                            "  * [{}] {}",
                            finding.severity.as_str(),
                            finding.description
                        );
                    }
                }
            }
        }
        return Ok(());
    }

    if command == "inspect" {
        let Some(data) = &primary_bytes else {
            return Err("inspect command requires a macro container input".into());
        };
        let inspection = inspect_macro_file(data, &analysis_options)?;
        match format.as_str() {
            "json" => println!("{}", inspect_to_json(&inspection, disclosure)),
            "markdown" => print!("{}", inspect_to_markdown(&inspection)),
            _ => {
                println!("=======================================================");
                println!("           VBA MACRO CONTAINER INSPECTION REPORT        ");
                println!("=======================================================");
                println!(
                    "Project Name      : {}",
                    inspection.extracted.name.as_deref().unwrap_or("<unnamed>")
                );
                println!("Modules Count     : {}", inspection.extracted.modules.len());
                println!(
                    "Overall Severity  : {}",
                    inspection
                        .stomping_report
                        .overall_severity
                        .as_str()
                        .to_ascii_uppercase()
                );
                println!(
                    "Stomping Detected : {}",
                    inspection.stomping_report.has_stomping
                );
                println!("-------------------------------------------------------");
                println!("Modules Summary:");
                for m in &inspection.stomping_report.modules {
                    println!(
                        "  - {:<20} | Severity: {:<8} | Score: {:>3}% | Src Lines: {:>3} | PCode Lines: {:>3}",
                        m.module_name,
                        m.severity.as_str(),
                        m.confidence_score,
                        m.source_line_count,
                        m.pcode_line_count
                    );
                    for f in &m.findings {
                        println!("      * [{}] {}", f.severity.as_str(), f.description);
                    }
                }
                println!("=======================================================");
            }
        }
        return Ok(());
    }

    let mut report = if let Some(x) = &extracted {
        analyze_extracted_project(x, &analysis_options)?
    } else if sources.is_empty() {
        Analysis::default()
    } else {
        analyze(&sources, &analysis_options)?
    };
    report.host_profile = host_profile;
    report.entry_points = detect_entry_points(&report.project, host_profile);
    report.project.input_kind = kind.unwrap_or("exported_vba_text").into();

    if format == "dot" {
        print!("{}", to_dot_with_disclosure(&report, disclosure));
    } else {
        print!("{}", to_json(&report, extracted.as_ref(), disclosure));
    }
    if let Some(x) = &extracted {
        for d in &x.diagnostics {
            eprintln!("warning: {d}");
        }
    }
    Ok(())
}

fn usage() -> String {
    "usage: vba-insight analyze FILE... [--format json|dot] [--include-source] [--define NAME=VALUE] [--code-page N] [--host excel|generic] [--pcode-profile vba7-observed]
       vba-insight extract FILE.xlsm [--format json] [--include-source] [--pcode-profile vba7-observed]
       vba-insight disasm FILE.xlsm [--format json|markdown|text]
       vba-insight stomping FILE.xlsm [--format json|sarif|markdown|text]
       vba-insight inspect FILE.xlsm [--format json|markdown|text]".into()
}
