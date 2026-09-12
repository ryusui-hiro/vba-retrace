use crate::extract::ExtractedProject;
use crate::model::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disclosure {
    StructureOnly,
    IncludeSource,
}

pub fn to_json(a: &Analysis, x: Option<&ExtractedProject>, d: Disclosure) -> String {
    let reveal = d == Disclosure::IncludeSource;
    let mut o = String::from("{\n");
    o.push_str(&format!("  \"schema_version\": \"0.1\",\n  \"input_kind\": {},\n  \"host_profile\": {},\n  \"code_executed\": false,\n  \"external_network_used\": false,\n  \"semantic_analysis_complete\": {},\n",q(&a.project.input_kind),q(match a.host_profile{crate::host::HostProfile::Unknown=>"unknown",crate::host::HostProfile::Excel=>"excel"}),a.semantic_analysis_complete));
    o.push_str("  \"compiled_representation\": {");
    if let Some(x) = x {
        let project_constants = if reveal {
            format!(
                "[{}]",
                x.conditional_constants
                    .iter()
                    .map(|(k, v)| format!("{{\"name\":{},\"value\":{}}}", q(k), q(v)))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        } else {
            "null".into()
        };
        o.push_str(&format!("\n    \"status\": {},\n    \"project_name\": {},\n    \"system_kind\": {},\n    \"pcode_disassembled\": false,\n    \"pcode_verified\": false,\n    \"code_page\": {},\n    \"reference_count\": {},\n    \"project_constants\": {},\n    \"project_cache\": {{\"length\": {}, \"fingerprint_fnv1a64\": {}}},\n    \"module_caches\": [",q(&x.compiled_representation_status),if reveal{opt_q(&x.name)}else{"null".into()},x.system_kind.map(|v|v.to_string()).unwrap_or_else(||"null".into()),x.code_page.map(|v|v.to_string()).unwrap_or_else(||"null".into()),x.references.len(),project_constants,x.project_cache.byte_length,q(&format!("{:016x}",x.project_cache.fingerprint))));
        for (i, m) in x.modules.iter().enumerate() {
            if i > 0 {
                o.push(',');
            }
            o.push_str(&format!(
                "{{\"module\":{},\"length\":{},\"fingerprint_fnv1a64\":{},\"pcode_layout_status\":{}",
                if reveal {
                    q(&m.name)
                } else {
                    q(&format!("module_{i}"))
                },
                m.cache.byte_length,
                q(&format!("{:016x}", m.cache.fingerprint)),
                q(&m.pcode_layout_status)
            ));
            if let Some(layout) = &m.pcode_layout {
                o.push_str(&format!(",\"pcode_layout\":{{\"profile\":\"vba7_observed\",\"cafe_offset\":{},\"line_count\":{},\"code_bytes_total\":{},\"mnemonics_decoded\":false,\"lines\":[",layout.cafe_offset,layout.line_count,layout.code_bytes_total));
                for (j, line) in layout.lines.iter().enumerate() {
                    if j > 0 {
                        o.push(',');
                    }
                    o.push_str(&format!("{{\"source_line\":{},\"length\":{},\"cache_offset\":{},\"raw_word_count\":{},\"has_partial_word\":{},\"raw_hex\":{}}}",line.source_line,line.line_length,line.cache_offset.map(|x|x.to_string()).unwrap_or_else(||"null".into()),line.raw_word_count,line.has_partial_word,if reveal{q(&line.raw_bytes.iter().map(|b|format!("{b:02x}")).collect::<String>())}else{"null".into()}));
                }
                o.push_str("]}");
            }
            o.push('}');
        }
        o.push_str("]\n  }");
    } else {
        o.push_str("\n    \"status\": \"not_present_in_source_input\",\n    \"pcode_disassembled\": false,\n    \"pcode_verified\": false\n  }");
    }
    o.push_str(",\n  \"modules\": [");
    for (i, m) in a.project.modules.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        o.push_str("\n    {");
        o.push_str(&format!(
            "\n      \"name\": {},\n      \"source_name\": {},\n      \"procedures\": [",
            if reveal {
                q(&m.name)
            } else {
                q(&format!("module_{i}"))
            },
            if reveal {
                q(&m.source_name)
            } else {
                "null".into()
            }
        ));
        for (j, p) in m.procedures.iter().enumerate() {
            if j > 0 {
                o.push(',');
            }
            o.push_str(&format!("{{\"name\":{},\"kind\":{},\"visibility\":{},\"return_type\":{},\"line\":{},\"parameters\":[",if reveal{q(&p.name)}else{q(&format!("procedure_{j}"))},q(&p.kind),q(&p.visibility),if reveal{opt_q(&p.return_type)}else{"null".into()},p.span.line));
            for (k, arg) in p.parameters.iter().enumerate() {
                if k > 0 {
                    o.push(',');
                }
                o.push_str(&format!(
                    "{{\"name\":{},\"type\":{},\"passing\":{},\"optional\":{},\"param_array\":{}}}",
                    if reveal {
                        q(&arg.name)
                    } else {
                        q(&format!("argument_{k}"))
                    },
                    if reveal {
                        opt_q(&arg.type_name)
                    } else {
                        "null".into()
                    },
                    q(&arg.passing),
                    arg.optional,
                    arg.is_param_array
                ));
            }
            o.push_str("],\"statements\":[");
            write_statements(&mut o, &p.statements, reveal);
            o.push_str("]}");
        }
        o.push_str("],\n      \"declarations\": [");
        for (j, var) in m.declarations.iter().enumerate() {
            if j > 0 {
                o.push(',');
            }
            o.push_str(&format!(
                "{{\"name\":{},\"kind\":{},\"visibility\":{},\"type\":{},\"line\":{}}}",
                if reveal {
                    q(&var.name)
                } else {
                    q(&format!("declaration_{j}"))
                },
                q(&var.kind),
                q(&var.visibility),
                if reveal {
                    opt_q(&var.type_name)
                } else {
                    "null".into()
                },
                var.span.line
            ));
        }
        o.push(']');
        if reveal {
            o.push_str(&format!(",\n      \"source\": {}", q(&m.text)));
        }
        o.push_str("\n    }");
    }
    o.push_str("\n  ],\n  \"calls\": [");
    for (i, c) in a.calls.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        let arguments = if reveal {
            format!(
                "[{}]",
                c.arguments
                    .iter()
                    .map(|arg| q(arg))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        } else {
            "null".into()
        };
        o.push_str(&format!("{{\"module\":{},\"procedure\":{},\"target\":{},\"resolution\":{},\"argument_count\":{},\"arguments\":{},\"line\":{}}}",module_label(a,&c.module,reveal),procedure_label(a,&c.module,c.procedure.as_deref(),reveal),if reveal{q(&c.target)}else{q(&format!("call_{i}"))},q(&c.resolution),c.argument_count.map(|n|n.to_string()).unwrap_or_else(||"null".into()),arguments,c.span.line));
    }
    o.push_str("],\n  \"references\": [");
    for (i, r) in a.references.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        o.push_str(&format!(
            "{{\"module\":{},\"procedure\":{},\"name\":{},\"resolution\":{},\"line\":{}}}",
            module_label(a, &r.module, reveal),
            procedure_label(a, &r.module, r.procedure.as_deref(), reveal),
            if reveal {
                q(&r.name)
            } else {
                q(&format!("symbol_{i}"))
            },
            q(&r.resolution),
            r.span.line
        ));
    }
    o.push_str("],\n  \"data_access_candidates\": [");
    for (i, v) in a.data_accesses.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        o.push_str(&format!("{{\"module\":{},\"procedure\":{},\"operation\":{},\"target\":{},\"host_dependent\":{},\"line\":{}}}",module_label(a,&v.module,reveal),procedure_label(a,&v.module,v.procedure.as_deref(),reveal),q(&v.operation),if reveal{q(&v.target)}else{"null".into()},v.host_dependent,v.span.line));
    }
    o.push_str("],\n  \"data_flow_candidates\": [");
    for (i, v) in a.data_flow.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        o.push_str(&format!("{{\"module\":{},\"procedure\":{},\"target\":{},\"inputs\":{},\"transfer\":{},\"line\":{}}}",module_label(a,&v.module,reveal),procedure_label(a,&v.module,v.procedure.as_deref(),reveal),if reveal{q(&v.target)}else{"null".into()},if reveal{format!("[{}]",v.inputs.iter().map(|z|q(z)).collect::<Vec<_>>().join(","))}else{v.inputs.len().to_string()},q(&v.transfer),v.span.line));
    }
    o.push_str("],\n  \"type_facts\": [");
    for (i, f) in a.type_facts.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        o.push_str(&format!("{{\"module\":{},\"procedure\":{},\"target\":{},\"target_type\":{},\"value_type\":{},\"status\":{},\"line\":{}}}",module_label(a,&f.module,reveal),procedure_label(a,&f.module,f.procedure.as_deref(),reveal),if reveal{q(&f.target)}else{"null".into()},if reveal{opt_q(&f.target_type)}else{"null".into()},if reveal{q(&f.value_type)}else{"null".into()},q(&f.status),f.span.line));
    }
    o.push_str("],\n  \"error_handling\": [");
    for (i, f) in a.error_handling.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        o.push_str(&format!("{{\"module\":{},\"procedure\":{},\"operation\":{},\"target\":{},\"target_resolved\":{},\"path_state_verified\":{},\"line\":{}}}",module_label(a,&f.module,reveal),procedure_label(a,&f.module,Some(&f.procedure),reveal),q(&f.operation),if reveal{opt_q(&f.target)}else{"null".into()},f.target_resolved.map(|v|v.to_string()).unwrap_or_else(||"null".into()),f.path_state_verified,f.span.line));
    }
    o.push_str("],\n  \"control_flow\": [");
    for (i, g) in a.control_flow.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        o.push_str(&format!(
            "{{\"module\":{},\"procedure\":{},\"complete\":{},\"entry\":{},\"exit\":{},\"nodes\":[",
            module_label(a, &g.module, reveal),
            procedure_label(a, &g.module, Some(&g.procedure), reveal),
            g.complete,
            g.entry,
            g.exit
        ));
        for (j, n) in g.nodes.iter().enumerate() {
            if j > 0 {
                o.push(',');
            }
            o.push_str(&format!(
                "{{\"id\":{},\"kind\":{},\"label\":{},\"line\":{}}}",
                n.id,
                q(&n.kind),
                if reveal { q(&n.label) } else { q(&n.kind) },
                n.span.line
            ));
        }
        o.push_str("],\"edges\":[");
        for (j, e) in g.edges.iter().enumerate() {
            if j > 0 {
                o.push(',');
            }
            o.push_str(&format!(
                "{{\"from\":{},\"to\":{},\"condition\":{}}}",
                e.from,
                e.to,
                if reveal {
                    opt_q(&e.condition)
                } else {
                    redacted_condition(&e.condition)
                        .as_deref()
                        .map(q)
                        .unwrap_or_else(|| "null".into())
                }
            ));
        }
        o.push_str("]}");
    }
    o.push_str("],\n  \"diagnostics\": [");
    let mut first = true;
    for dgn in &a.diagnostics {
        if !first {
            o.push(',');
        }
        first = false;
        o.push_str(&format!("{{\"code\":{},\"severity\":{},\"message\":{},\"source\":{},\"line\":{},\"column\":{}}}",q(dgn.code),q(severity(dgn.severity)),if reveal{q(&dgn.message)}else{"null".into()},if reveal{q(&dgn.source)}else{"null".into()},dgn.span.line,dgn.span.column));
    }
    if let Some(x) = x {
        for _ in &x.diagnostics {
            if !first {
                o.push(',');
            }
            first = false;
            o.push_str("{\"code\":\"EXTRACT\",\"severity\":\"warning\",\"message\":null,\"source\":null,\"line\":0,\"column\":0}");
        }
    }
    o.push_str("]\n}\n");
    o
}

pub fn to_dot(a: &Analysis) -> String {
    to_dot_with_disclosure(a, Disclosure::StructureOnly)
}
pub fn to_dot_with_disclosure(a: &Analysis, d: Disclosure) -> String {
    let reveal = d == Disclosure::IncludeSource;
    let mut s = String::from("digraph vba_control_flow {\n  rankdir=TB;\n");
    for (gi, g) in a.control_flow.iter().enumerate() {
        s.push_str(&format!(
            "  subgraph cluster_{gi} {{ label=\"{}\";\n",
            if reveal {
                dot_escape(&format!("{}::{}", g.module, g.procedure))
            } else {
                format!("module_{}::procedure_{}", module_index(a, &g.module), gi)
            }
        ));
        for n in &g.nodes {
            let node_label = if reveal {
                format!("{}: {}", n.kind, n.label)
            } else {
                n.kind.clone()
            };
            s.push_str(&format!(
                "    g{gi}_n{} [label=\"{}\"];\n",
                n.id,
                dot_escape(&node_label)
            ));
        }
        for e in &g.edges {
            let label = if reveal {
                e.condition
                    .as_deref()
                    .map(|x| format!(" [label=\"{}\"]", dot_escape(x)))
                    .unwrap_or_default()
            } else {
                redacted_condition(&e.condition)
                    .map(|x| format!(" [label=\"{}\"]", dot_escape(&x)))
                    .unwrap_or_default()
            };
            s.push_str(&format!(
                "    g{gi}_n{} -> g{gi}_n{}{};\n",
                e.from, e.to, label
            ));
        }
        s.push_str("  }\n");
    }
    s.push_str("}\n");
    s
}

fn write_statements(o: &mut String, ss: &[Statement], reveal: bool) {
    for (i, s) in ss.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        o.push('{');
        o.push_str(&format!("\"kind\":{},\"line\":{}", q(&s.kind), s.span.line));
        if reveal && let Some(e) = &s.expression {
            o.push_str(&format!(",\"expression\":{}", q(e)));
        }
        if !s.children.is_empty() {
            o.push_str(",\"children\":[");
            write_statements(o, &s.children, reveal);
            o.push(']');
        }
        o.push('}');
    }
}
fn module_index(a: &Analysis, m: &str) -> usize {
    a.project
        .modules
        .iter()
        .position(|x| x.name.eq_ignore_ascii_case(m))
        .unwrap_or(0)
}
fn module_label(a: &Analysis, m: &str, reveal: bool) -> String {
    if reveal {
        q(m)
    } else {
        q(&format!("module_{}", module_index(a, m)))
    }
}
fn procedure_label(a: &Analysis, m: &str, p: Option<&str>, reveal: bool) -> String {
    match p {
        None => "null".into(),
        Some(n) if reveal => q(n),
        Some(n) => {
            let mi = module_index(a, m);
            let pi = a
                .project
                .modules
                .get(mi)
                .and_then(|x| {
                    x.procedures
                        .iter()
                        .position(|z| z.name.eq_ignore_ascii_case(n))
                })
                .unwrap_or(0);
            q(&format!("procedure_{pi}"))
        }
    }
}
fn redacted_condition(c: &Option<String>) -> Option<String> {
    match c.as_deref() {
        None => None,
        Some(x) if x.contains("= True") => Some("condition true".into()),
        Some(x) if x.contains("= False") => Some("condition false".into()),
        Some(x) if x.contains("iteration") => Some("next iteration".into()),
        Some(x) if x.contains("case") => Some("case selection".into()),
        Some(_) => Some("branch condition".into()),
    }
}
fn severity(s: Severity) -> &'static str {
    match s {
        Severity::Note => "note",
        Severity::Warning => "warning",
        Severity::Error => "error",
    }
}
fn opt_q(x: &Option<String>) -> String {
    x.as_ref().map(|x| q(x)).unwrap_or_else(|| "null".into())
}
fn q(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if c < ' ' => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}
fn dot_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_json_hides_source_and_names() {
        let a = Analysis {
            project: Project {
                input_kind: "test".into(),
                modules: vec![Module {
                    name: "SecretModule".into(),
                    source_name: "private/path.bas".into(),
                    text: "x=\"secret\"".into(),
                    ..Module::default()
                }],
                ..Project::default()
            },
            ..Analysis::default()
        };
        let j = to_json(&a, None, Disclosure::StructureOnly);
        assert!(!j.contains("SecretModule"));
        assert!(!j.contains("private/path.bas"));
        assert!(!j.contains("secret"));
        let full = to_json(&a, None, Disclosure::IncludeSource);
        assert!(full.contains("SecretModule"));
        assert!(full.contains("secret"));
        assert!(j.ends_with("}\n"));
    }
}
