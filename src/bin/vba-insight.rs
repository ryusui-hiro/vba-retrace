use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;
use vba_insight::compiled::{PCodeLayoutProfile, inspect_vba7_line_map};
use vba_insight::export::{Disclosure, to_dot_with_disclosure, to_json};
use vba_insight::extract::{extract_xlsm, sources_from_extracted};
use vba_insight::host::HostProfile;
use vba_insight::model::{Analysis, SourceUnit};
use vba_insight::{AnalysisOptions, Limits, analyze};

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
    if command != "analyze" && command != "extract" {
        return Err(usage());
    }
    let mut paths = Vec::new();
    let mut format = "json".to_string();
    let mut include_source = false;
    let mut source_code_page = None;
    let mut conditional_constants = BTreeMap::new();
    let mut pcode_profile = None;
    let mut host_profile = HostProfile::Unknown;
    let mut host_overridden = false;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--include-source" => include_source = true,
            "--format" => format = args.next().ok_or("--format needs json or dot")?,
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
                    Some("generic") | Some("unknown") => HostProfile::Unknown,
                    _ => return Err("--host must be excel or generic".into()),
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
    if format != "json" && format != "dot" {
        return Err("format must be json or dot".into());
    }
    let limits = Limits::default();
    let mut sources = Vec::new();
    let mut extracted = None;
    let mut kind = None;
    for p in &paths {
        let bytes = fs::read(p).map_err(|e| format!("cannot read {p}: {e}"))?;
        if bytes.len() > limits.max_input_bytes {
            return Err(format!("input file exceeds configured limit: {p}"));
        }
        if Path::new(p)
            .extension()
            .is_some_and(|e| e.to_string_lossy().eq_ignore_ascii_case("xlsm"))
            || bytes.starts_with(b"PK\x03\x04")
        {
            if paths.len() != 1 {
                return Err("an .xlsm workbook must be analyzed as a single input".into());
            }
            let mut x = extract_xlsm(&bytes, &limits)?;
            if !host_overridden {
                host_profile = HostProfile::Excel;
            }
            if let Some(profile) = pcode_profile {
                x.compiled_representation_status =
                    "vba7_observed_line_map_only; opcode semantics are not decoded".into();
                for module in &mut x.modules {
                    match inspect_vba7_line_map(&module.performance_cache, profile, 65_535) {
                        Ok(Some(map)) => {
                            module.pcode_layout_status = "line_map_parsed_raw_bytes_only".into();
                            module.pcode_layout = Some(map);
                        }
                        Ok(None) => {
                            module.pcode_layout_status =
                                "no_valid_line_map_found_for_selected_profile".into()
                        }
                        Err(e) => {
                            module.pcode_layout_status = "malformed_line_map".into();
                            x.diagnostics
                                .push(format!("{} p-code layout: {e}", module.name));
                        }
                    }
                }
            }
            sources = sources_from_extracted(&x);
            kind = Some("xlsm_vba_project");
            extracted = Some(x);
        } else {
            if pcode_profile.is_some() {
                return Err("--pcode-profile requires an .xlsm/VBA project input".into());
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
    if let Some(x) = &extracted {
        for (k, v) in &x.conditional_constants {
            conditional_constants.entry(k.clone()).or_insert(v.clone());
        }
    }
    let mut report = if sources.is_empty() {
        Analysis::default()
    } else {
        analyze(
            &sources,
            &AnalysisOptions {
                limits,
                conditional_constants,
                host_profile,
            },
        )?
    };
    if let Some(x) = &extracted {
        report.project.name = x.name.clone();
        report.project.code_page = x.code_page;
        report.project.system_kind = x.system_kind;
        report.project.references = x.references.clone();
        report.project.conditional_constants = x.conditional_constants.clone();
        for (k, v) in &x.metadata {
            report.project.metadata.insert(k.clone(), v.clone());
        }
    }
    report.project.input_kind = kind.unwrap_or("exported_vba_text").into();
    let disclosure = if include_source {
        Disclosure::IncludeSource
    } else {
        Disclosure::StructureOnly
    };
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
    let _ = command;
    Ok(())
}
fn usage() -> String {
    "usage: vba-insight analyze FILE... [--format json|dot] [--include-source] [--define NAME=VALUE] [--code-page N] [--host excel|generic] [--pcode-profile vba7-observed]\n       vba-insight extract FILE.xlsm [--format json] [--include-source] [--pcode-profile vba7-observed]".into()
}
