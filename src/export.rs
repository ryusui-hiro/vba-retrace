use crate::extract::ExtractedProject;
use crate::model::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disclosure {
    StructureOnly,
    IncludeSource,
}

/// Export a caller-schema p-code decode report as JSON.
///
/// Opcode names and raw operands are emitted only with `IncludeSource`; the
/// report always remains explicitly marked as caller-supplied and unverified.
pub fn pcode_decode_to_json(
    report: &crate::compiled::PCodeDecodeReport,
    disclosure: Disclosure,
) -> String {
    let reveal = disclosure == Disclosure::IncludeSource;
    let mut out = String::from("{\"schema_version\":\"0.1\",\"pcode_verified\":false,");
    out.push_str(&format!(
        "\"schema_id\":{},\"schema_status\":\"caller_supplied_unverified\",\"complete\":{},\"truncated\":{},\"instruction_count\":{},\"lines\":[",
        if reveal { q(&report.schema_id) } else { "null".into() },
        report.complete,
        report.truncated,
        report.instruction_count
    ));
    for (line_index, line) in report.lines.iter().enumerate() {
        if line_index > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"source_line\":{},\"complete\":{},\"instruction_count\":{},\"issues\":[",
            line.source_line,
            line.complete,
            line.instructions.len()
        ));
        for (issue_index, issue) in line.issues.iter().enumerate() {
            if issue_index > 0 {
                out.push(',');
            }
            let kind = match issue.kind {
                crate::compiled::PCodeDecodeIssueKind::UnknownOpcode => "unknown_opcode",
                crate::compiled::PCodeDecodeIssueKind::UnknownOperationType => {
                    "unknown_operation_type"
                }
                crate::compiled::PCodeDecodeIssueKind::TruncatedHeader => "truncated_header",
                crate::compiled::PCodeDecodeIssueKind::TruncatedOperand => "truncated_operand",
                crate::compiled::PCodeDecodeIssueKind::TruncatedPayloadPadding => {
                    "truncated_payload_padding"
                }
                crate::compiled::PCodeDecodeIssueKind::InstructionLimit => "instruction_limit",
            };
            out.push_str(&format!(
                "{{\"kind\":{},\"line_offset\":{},\"cache_offset\":{},\"raw_header_word\":{}}}",
                q(kind),
                issue.line_offset,
                issue
                    .cache_offset
                    .map(|offset| offset.to_string())
                    .unwrap_or_else(|| "null".into()),
                if reveal {
                    issue
                        .raw_header_word
                        .map(|word| word.to_string())
                        .unwrap_or_else(|| "null".into())
                } else {
                    "null".into()
                }
            ));
        }
        out.push_str("],\"instructions\":[");
        for (instruction_index, instruction) in line.instructions.iter().enumerate() {
            if instruction_index > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "{{\"line_offset\":{},\"cache_offset\":{},\"complete\":{},\"raw_header_word\":{},\"opcode\":{},\"operation_type\":{},\"mnemonic\":{},\"operand_count\":{}",
                instruction.line_offset,
                instruction
                    .cache_offset
                    .map(|offset| offset.to_string())
                    .unwrap_or_else(|| "null".into()),
                instruction.complete,
                if reveal {
                    instruction.header_word.to_string()
                } else {
                    "null".into()
                },
                if reveal {
                    instruction.opcode.to_string()
                } else {
                    "null".into()
                },
                if reveal {
                    instruction.operation_type.to_string()
                } else {
                    "null".into()
                },
                if reveal {
                    instruction
                        .mnemonic
                        .as_deref()
                        .map(q)
                        .unwrap_or_else(|| "null".into())
                } else {
                    "null".into()
                },
                instruction.operands.len()
            ));
            if reveal {
                out.push_str(",\"operands\":[");
                for (operand_index, operand) in instruction.operands.iter().enumerate() {
                    if operand_index > 0 {
                        out.push(',');
                    }
                    match operand {
                        crate::compiled::DecodedPCodeOperand::Byte8(value) => {
                            out.push_str(&format!("{{\"kind\":\"byte8\",\"value\":{value}}}"));
                        }
                        crate::compiled::DecodedPCodeOperand::Word16(value) => {
                            out.push_str(&format!("{{\"kind\":\"word16\",\"value\":{value}}}"));
                        }
                        crate::compiled::DecodedPCodeOperand::SignedWord16(value) => {
                            out.push_str(&format!(
                                "{{\"kind\":\"signed_word16\",\"value\":{value}}}"
                            ));
                        }
                        crate::compiled::DecodedPCodeOperand::DoubleWord32(value) => {
                            out.push_str(&format!(
                                "{{\"kind\":\"double_word32\",\"value\":{value}}}"
                            ));
                        }
                        crate::compiled::DecodedPCodeOperand::SignedDoubleWord32(value) => {
                            out.push_str(&format!(
                                "{{\"kind\":\"signed_double_word32\",\"value\":{value}}}"
                            ));
                        }
                        crate::compiled::DecodedPCodeOperand::QuadWord64(value) => {
                            out.push_str(&format!(
                                "{{\"kind\":\"quad_word64\",\"value\":{value}}}"
                            ));
                        }
                        crate::compiled::DecodedPCodeOperand::Float64Bits(value) => {
                            out.push_str(&format!(
                                "{{\"kind\":\"float64_bits\",\"bits_hex\":{}}}",
                                q(&format!("0x{value:016x}"))
                            ));
                        }
                        crate::compiled::DecodedPCodeOperand::Bytes(bytes) => {
                            let hex = bytes
                                .iter()
                                .map(|byte| format!("{byte:02x}"))
                                .collect::<String>();
                            out.push_str(&format!("{{\"kind\":\"bytes\",\"hex\":{}}}", q(&hex)));
                        }
                    }
                }
                out.push(']');
            } else {
                out.push_str(",\"operands\":null");
            }
            out.push('}');
        }
        out.push_str("]}");
    }
    out.push_str("]}");
    out
}

/// Export abstract p-code stack semantics using the same disclosure policy as
/// the structural decoder. The report is always marked caller-supplied and
/// unverified because both the opcode table and meaning specification are
/// version-specific.
pub fn pcode_semantics_to_json(
    report: &crate::compiled::PCodeSemanticReport,
    disclosure: Disclosure,
) -> String {
    let reveal = disclosure == Disclosure::IncludeSource;
    let mut out = format!(
        "{{\"schema_version\":\"0.1\",\"pcode_verified\":false,\"schema_id\":{},\"schema_status\":\"caller_supplied_unverified\",\"complete\":{},\"truncated\":{},\"step_count\":{},\"unknown_value_count\":{},\"unknown_instruction_count\":{},\"stack_underflow_count\":{},\"steps\":[",
        if reveal {
            q(&report.schema_id)
        } else {
            "null".into()
        },
        report.complete,
        report.truncated,
        report.steps.len(),
        report.unknown_value_count,
        report.unknown_instruction_count,
        report.stack_underflow_count
    );
    for (index, step) in report.steps.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        let status = match step.status {
            crate::compiled::PCodeSemanticStepStatus::Applied => "applied",
            crate::compiled::PCodeSemanticStepStatus::UnknownInstruction => "unknown_instruction",
            crate::compiled::PCodeSemanticStepStatus::UnknownValue => "unknown_value",
            crate::compiled::PCodeSemanticStepStatus::StackUnderflow => "stack_underflow",
        };
        let control = semantic_control_transfer_json(&step.control_transfer, reveal);
        out.push_str(&format!(
            "{{\"source_line\":{},\"line_offset\":{},\"opcode\":{},\"operation_type\":{},\"mnemonic\":{},\"status\":{},\"stack_before_depth\":{},\"stack_after_depth\":{},\"stack_before\":{},\"stack_after\":{},\"locals_before_count\":{},\"locals_after_count\":{},\"locals_before\":{},\"locals_after\":{},\"control_transfer\":{}}}",
            step.source_line,
            step.line_offset,
            if reveal { step.opcode.to_string() } else { "null".into() },
            if reveal { step.operation_type.to_string() } else { "null".into() },
            if reveal {
                step.mnemonic.as_deref().map(q).unwrap_or_else(|| "null".into())
            } else {
                "null".into()
            },
            q(status),
            step.stack_before.len(),
            step.stack_after.len(),
            semantic_values_json(&step.stack_before, reveal),
            semantic_values_json(&step.stack_after, reveal),
            step.locals_before.len(),
            step.locals_after.len(),
            semantic_locals_json(&step.locals_before, reveal),
            semantic_locals_json(&step.locals_after, reveal),
            control
        ));
    }
    out.push_str("]}");
    out
}

/// Export bounded p-code semantic paths. Source disclosure controls opcode,
/// mnemonic, stack values, local-slot values, and branch operands; structural
/// path counts and termination kinds remain visible in both modes.
pub fn pcode_semantic_paths_to_json(
    report: &crate::compiled::PCodeSemanticPathReport,
    disclosure: Disclosure,
) -> String {
    let reveal = disclosure == Disclosure::IncludeSource;
    let mut out = format!(
        "{{\"schema_version\":\"0.1\",\"pcode_verified\":false,\"schema_id\":{},\"schema_status\":\"caller_supplied_unverified\",\"complete\":{},\"truncated\":{},\"path_count\":{},\"unknown_value_count\":{},\"unknown_instruction_count\":{},\"stack_underflow_count\":{},\"paths\":[",
        if reveal {
            q(&report.schema_id)
        } else {
            "null".into()
        },
        report.complete,
        report.truncated,
        report.paths.len(),
        report.unknown_value_count,
        report.unknown_instruction_count,
        report.stack_underflow_count
    );
    for (path_index, path) in report.paths.iter().enumerate() {
        if path_index > 0 {
            out.push(',');
        }
        let termination = match path.termination {
            crate::compiled::PCodeSemanticPathTermination::EndOfStream => "end_of_stream",
            crate::compiled::PCodeSemanticPathTermination::Return => "return",
            crate::compiled::PCodeSemanticPathTermination::UnknownInstruction => {
                "unknown_instruction"
            }
            crate::compiled::PCodeSemanticPathTermination::LoopBound => "loop_bound",
            crate::compiled::PCodeSemanticPathTermination::StepLimit => "step_limit",
        };
        out.push_str(&format!(
            "{{\"path_index\":{},\"complete\":{},\"truncated\":{},\"termination\":{},\"step_count\":{},\"steps\":[",
            path.path_index,
            path.complete,
            path.truncated,
            q(termination),
            path.steps.len()
        ));
        for (step_index, step) in path.steps.iter().enumerate() {
            if step_index > 0 {
                out.push(',');
            }
            let status = match step.status {
                crate::compiled::PCodeSemanticStepStatus::Applied => "applied",
                crate::compiled::PCodeSemanticStepStatus::UnknownInstruction => {
                    "unknown_instruction"
                }
                crate::compiled::PCodeSemanticStepStatus::UnknownValue => "unknown_value",
                crate::compiled::PCodeSemanticStepStatus::StackUnderflow => "stack_underflow",
            };
            out.push_str(&format!(
                "{{\"source_line\":{},\"line_offset\":{},\"opcode\":{},\"operation_type\":{},\"mnemonic\":{},\"status\":{},\"stack_before_depth\":{},\"stack_after_depth\":{},\"stack_before\":{},\"stack_after\":{},\"locals_before_count\":{},\"locals_after_count\":{},\"locals_before\":{},\"locals_after\":{},\"control_transfer\":{}}}",
                step.source_line,
                step.line_offset,
                if reveal { step.opcode.to_string() } else { "null".into() },
                if reveal { step.operation_type.to_string() } else { "null".into() },
                if reveal {
                    step.mnemonic.as_deref().map(q).unwrap_or_else(|| "null".into())
                } else {
                    "null".into()
                },
                q(status),
                step.stack_before.len(),
                step.stack_after.len(),
                semantic_values_json(&step.stack_before, reveal),
                semantic_values_json(&step.stack_after, reveal),
                step.locals_before.len(),
                step.locals_after.len(),
                semantic_locals_json(&step.locals_before, reveal),
                semantic_locals_json(&step.locals_after, reveal),
                semantic_control_transfer_json(&step.control_transfer, reveal)
            ));
        }
        out.push_str("]}");
    }
    out.push_str("]}");
    out
}

/// Export all module-level p-code reports from an extracted project analysis.
/// The nested reports retain their caller-supplied/unverified status and the
/// module name follows the normal source-disclosure policy.
pub fn pcode_project_semantics_to_json(
    report: &crate::extract::ExtractedProjectPCodeAnalysis,
    disclosure: Disclosure,
) -> String {
    let reveal = disclosure == Disclosure::IncludeSource;
    let mut out = format!(
        "{{\"schema_version\":\"0.1\",\"pcode_verified\":false,\"module_count\":{},\"truncated\":{},\"modules\":[",
        report.modules.len(),
        report.truncated
    );
    for (index, module) in report.modules.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"module\":{},\"decoded\":{},\"semantic_paths\":{}}}",
            if reveal {
                q(&module.module_name)
            } else {
                q(&format!("module_{index}"))
            },
            pcode_decode_to_json(&module.decoded, disclosure),
            pcode_semantic_paths_to_json(&module.semantic_paths, disclosure)
        ));
    }
    out.push_str("]}");
    out
}

fn semantic_values_json(values: &[crate::compiled::PCodeSemanticValue], reveal: bool) -> String {
    if !reveal {
        return "null".into();
    }
    let mut out = String::from("[");
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&semantic_value_json(value));
    }
    out.push(']');
    out
}

fn semantic_locals_json(
    locals: &[(u64, crate::compiled::PCodeSemanticValue)],
    reveal: bool,
) -> String {
    if !reveal {
        return "null".into();
    }
    let mut out = String::from("[");
    for (index, (slot, value)) in locals.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"slot\":{},\"value\":{}}}",
            slot,
            semantic_value_json(value)
        ));
    }
    out.push(']');
    out
}

fn semantic_value_json(value: &crate::compiled::PCodeSemanticValue) -> String {
    match value {
        crate::compiled::PCodeSemanticValue::Unknown => "{\"kind\":\"unknown\"}".into(),
        crate::compiled::PCodeSemanticValue::Null => "{\"kind\":\"null\"}".into(),
        crate::compiled::PCodeSemanticValue::Empty => "{\"kind\":\"empty\"}".into(),
        crate::compiled::PCodeSemanticValue::Error(value) => {
            format!("{{\"kind\":\"error\",\"code\":{value}}}")
        }
        crate::compiled::PCodeSemanticValue::Integer(value) => {
            format!("{{\"kind\":\"integer\",\"value\":{value}}}")
        }
        crate::compiled::PCodeSemanticValue::Boolean(value) => {
            format!("{{\"kind\":\"boolean\",\"value\":{value}}}")
        }
        crate::compiled::PCodeSemanticValue::String(value) => {
            format!("{{\"kind\":\"string\",\"value\":{}}}", q(value))
        }
        crate::compiled::PCodeSemanticValue::Float64Bits(value) => format!(
            "{{\"kind\":\"float64_bits\",\"bits_hex\":{}}}",
            q(&format!("0x{value:016x}"))
        ),
        crate::compiled::PCodeSemanticValue::Bytes(bytes) => {
            let hex = bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            format!("{{\"kind\":\"bytes\",\"hex\":{}}}", q(&hex))
        }
        crate::compiled::PCodeSemanticValue::Object(identity) => {
            format!("{{\"kind\":\"object\",\"identity\":{identity}}}")
        }
        crate::compiled::PCodeSemanticValue::Array(values) => format!(
            "{{\"kind\":\"array\",\"length\":{},\"values\":{}}}",
            values.len(),
            semantic_values_json(values, true)
        ),
    }
}

fn semantic_control_transfer_json(
    transfer: &crate::compiled::PCodeSemanticControlTransfer,
    reveal: bool,
) -> String {
    match transfer {
        crate::compiled::PCodeSemanticControlTransfer::None => "{\"kind\":\"none\"}".into(),
        crate::compiled::PCodeSemanticControlTransfer::BranchRelative(value) => format!(
            "{{\"kind\":\"branch_relative\",\"value\":{}}}",
            if reveal {
                semantic_value_json(value)
            } else {
                "null".into()
            }
        ),
        crate::compiled::PCodeSemanticControlTransfer::ConditionalBranchRelative {
            target,
            condition,
        } => format!(
            "{{\"kind\":\"conditional_branch_relative\",\"target\":{},\"condition\":{}}}",
            if reveal {
                semantic_value_json(target)
            } else {
                "null".into()
            },
            if reveal {
                semantic_value_json(condition)
            } else {
                "null".into()
            }
        ),
        crate::compiled::PCodeSemanticControlTransfer::Call {
            target,
            returns_value,
        } => format!(
            "{{\"kind\":\"call\",\"target\":{},\"returns_value\":{returns_value}}}",
            if reveal {
                target
                    .as_ref()
                    .map(semantic_value_json)
                    .unwrap_or_else(|| "null".into())
            } else {
                "null".into()
            }
        ),
        crate::compiled::PCodeSemanticControlTransfer::Return(value) => format!(
            "{{\"kind\":\"return\",\"value\":{}}}",
            if reveal {
                value
                    .as_ref()
                    .map(semantic_value_json)
                    .unwrap_or_else(|| "null".into())
            } else {
                "null".into()
            }
        ),
    }
}

pub fn to_json(a: &Analysis, x: Option<&ExtractedProject>, d: Disclosure) -> String {
    let reveal = d == Disclosure::IncludeSource;
    let mut o = String::from("{\n");
    o.push_str(&format!("  \"schema_version\": \"0.1\",\n  \"input_kind\": {},\n  \"host_profile\": {},\n  \"code_executed\": false,\n  \"external_network_used\": false,\n  \"semantic_analysis_complete\": {},\n  \"path_enumeration_truncated\": {},\n  \"data_flow_paths_truncated\": {},\n  \"data_flow_path_unassociated_count\": {},\n  \"interprocedural_data_flow_paths_truncated\": {},\n  \"interprocedural_argument_value_paths_truncated\": {},\n  \"interprocedural_argument_composition_paths_truncated\": {},\n  \"interprocedural_return_paths_truncated\": {},\n  \"interprocedural_return_compositions_truncated\": {},\n  \"interprocedural_byref_write_paths_truncated\": {},\n  \"interprocedural_byref_value_paths_truncated\": {},\n  \"interprocedural_error_paths_truncated\": {},\n  \"data_access_paths_truncated\": {},\n  \"data_access_path_unassociated_count\": {},\n  \"path_value_flows_truncated\": {},\n  \"path_aliases_truncated\": {},\n  \"path_alias_dispatches_truncated\": {},\n  \"data_access_value_flows_truncated\": {},\n  \"data_access_predicate_unassociated_count\": {},\n",q(&a.project.input_kind),q(match a.host_profile{crate::host::HostProfile::Unknown=>"unknown",crate::host::HostProfile::Excel=>"excel",crate::host::HostProfile::Word=>"word",crate::host::HostProfile::PowerPoint=>"powerpoint",crate::host::HostProfile::Access=>"access"}),a.semantic_analysis_complete,a.path_enumeration_truncated,a.data_flow_paths_truncated,a.data_flow_path_unassociated_count,a.interprocedural_data_flow_paths_truncated,a.interprocedural_argument_value_paths_truncated,a.interprocedural_argument_composition_paths_truncated,a.interprocedural_return_paths_truncated,a.interprocedural_return_compositions_truncated,a.interprocedural_byref_write_paths_truncated,a.interprocedural_byref_value_paths_truncated,a.interprocedural_error_paths_truncated,a.data_access_paths_truncated,a.data_access_path_unassociated_count,a.path_value_flows_truncated,a.path_aliases_truncated,a.path_alias_dispatches_truncated,a.data_access_value_flows_truncated,a.data_access_predicate_unassociated_count));
    o.push_str("  \"workbook_structure\": ");
    if let Some(extracted) = x {
        o.push_str(&format!(
            "{{\"workbook_code_name\":{},\"sheet_count\":{},\"sheets\":[",
            if reveal {
                opt_q(&extracted.workbook_code_name)
            } else {
                "null".into()
            },
            extracted.workbook_sheets.len()
        ));
        for (index, sheet) in extracted.workbook_sheets.iter().enumerate() {
            if index > 0 {
                o.push(',');
            }
            o.push_str(&format!(
                "{{\"index\":{},\"name\":{},\"code_name\":{},\"sheet_id\":{},\"state\":{},\"kind\":{},\"relationship_id\":{},\"part_name\":{},\"resolution\":{}}}",
                index,
                if reveal { q(&sheet.name) } else { "null".into() },
                if reveal { opt_q(&sheet.code_name) } else { "null".into() },
                sheet.sheet_id.map(|id| id.to_string()).unwrap_or_else(|| "null".into()),
                if reveal { opt_q(&sheet.state) } else { "null".into() },
                q(&sheet.kind),
                if reveal { opt_q(&sheet.relationship_id) } else { "null".into() },
                if reveal { opt_q(&sheet.part_name) } else { "null".into() },
                q(&sheet.resolution)
            ));
        }
        o.push_str(&format!(
            "],\"defined_name_count\":{},\"defined_names\":[",
            extracted.workbook_defined_names.len()
        ));
        for (index, name) in extracted.workbook_defined_names.iter().enumerate() {
            if index > 0 {
                o.push(',');
            }
            let formula_references = if reveal {
                workbook_formula_references_json(&name.formula_reference_candidates)
            } else {
                "null".into()
            };
            o.push_str(&format!(
                "{{\"index\":{},\"name\":{},\"formula\":{},\"local_sheet_id\":{},\"local_sheet_name\":{},\"hidden\":{},\"built_in\":{},\"scope_resolution\":{},\"formula_reference_resolution\":{},\"formula_reference_count\":{},\"formula_references_truncated\":{},\"formula_reference_candidates\":{}}}",
                index,
                if reveal { q(&name.name) } else { "null".into() },
                if reveal { q(&name.formula) } else { "null".into() },
                name.local_sheet_id.map(|id| id.to_string()).unwrap_or_else(|| "null".into()),
                if reveal { opt_q(&name.local_sheet_name) } else { "null".into() },
                if reveal {
                    name.hidden.map(|hidden| hidden.to_string()).unwrap_or_else(|| "null".into())
                } else {
                    "null".into()
                },
                name.built_in,
                q(&name.scope_resolution),
                if reveal { q(&name.formula_reference_resolution) } else { "null".into() },
                if reveal { name.formula_reference_candidates.len().to_string() } else { "null".into() },
                if reveal { name.formula_references_truncated.to_string() } else { "null".into() },
                formula_references
            ));
        }
        o.push_str(&format!(
            "],\"table_count\":{},\"tables_truncated\":{},\"tables\":",
            extracted.workbook_tables.len(),
            extracted.workbook_tables_truncated
        ));
        if reveal {
            o.push('[');
            for (index, table) in extracted.workbook_tables.iter().enumerate() {
                if index > 0 {
                    o.push(',');
                }
                let range = table
                    .cell_range_bounds
                    .map(|bounds| {
                        format!(
                            "{{\"first_row\":{},\"first_column\":{},\"last_row\":{},\"last_column\":{}}}",
                            bounds.first_row,
                            bounds.first_column,
                            bounds.last_row,
                            bounds.last_column
                        )
                    })
                    .unwrap_or_else(|| "null".into());
                let columns = format!(
                    "[{}]",
                    table
                        .columns
                        .iter()
                        .map(|column| q(column))
                        .collect::<Vec<_>>()
                        .join(",")
                );
                o.push_str(&format!(
                    "{{\"index\":{},\"name\":{},\"display_name\":{},\"sheet_index\":{},\"sheet_name\":{},\"part_name\":{},\"cell_range_bounds\":{},\"header_row_count\":{},\"totals_row_count\":{},\"columns\":{},\"resolution\":{}}}",
                    index,
                    q(&table.name),
                    q(&table.display_name),
                    table.sheet_index,
                    q(&table.sheet_name),
                    opt_q(&table.part_name),
                    range,
                    table.header_row_count,
                    table.totals_row_count,
                    columns,
                    q(&table.resolution)
                ));
            }
            o.push(']');
        } else {
            o.push_str("null");
        }
        o.push_str(&format!(
            ",\"workbook_cell_count\":{},\"workbook_cells_truncated\":{},\"cells\":",
            extracted.workbook_cells.len(),
            extracted.workbook_cells_truncated
        ));
        if reveal {
            o.push('[');
            for (index, cell) in extracted.workbook_cells.iter().enumerate() {
                if index > 0 {
                    o.push(',');
                }
                let formula_references =
                    workbook_formula_references_json(&cell.formula_reference_candidates);
                o.push_str(&format!(
                    "{{\"index\":{},\"sheet_index\":{},\"sheet_name\":{},\"cell_ref\":{},\"row\":{},\"column\":{},\"cell_type\":{},\"formula\":{},\"formula_type\":{},\"formula_ref\":{},\"formula_shared_index\":{},\"stored_value\":{},\"value\":{},\"resolution\":{},\"formula_reference_resolution\":{},\"formula_reference_source_cell_id\":{},\"formula_reference_count\":{},\"formula_references_truncated\":{},\"formula_reference_candidates\":{}}}",
                    index,
                    cell.sheet_index,
                    q(&cell.sheet_name),
                    q(&cell.cell_ref),
                    cell.row.map(|row| row.to_string()).unwrap_or_else(|| "null".into()),
                    cell.column.map(|column| column.to_string()).unwrap_or_else(|| "null".into()),
                    q(&cell.cell_type),
                    opt_q(&cell.formula),
                    opt_q(&cell.formula_type),
                    opt_q(&cell.formula_ref),
                    cell.formula_shared_index.map(|value| value.to_string()).unwrap_or_else(|| "null".into()),
                    opt_q(&cell.stored_value),
                    opt_q(&cell.value),
                    q(&cell.resolution),
                    q(&cell.formula_reference_resolution),
                    cell.formula_reference_source_cell_index
                        .map_or_else(|| "null".into(), |value| value.to_string()),
                    cell.formula_reference_candidates.len(),
                    cell.formula_references_truncated,
                    formula_references
                ));
            }
            o.push(']');
        } else {
            o.push_str("null");
        }
        o.push_str(&format!(
            ",\"cell_threat_count\":{},\"cell_threats\":[",
            extracted.cell_threats.len()
        ));
        for (index, threat) in extracted.cell_threats.iter().enumerate() {
            if index > 0 {
                o.push(',');
            }
            let (rule_id, _) = cell_threat_to_sarif_rule(threat);
            o.push_str(&format!(
                "{{\"sheet_name\":{},\"cell_ref\":{},\"coordinate\":{},\"threat_kind\":{},\"rule_id\":{},\"severity\":{},\"formula\":{},\"description\":{}}}",
                if reveal { q(&threat.sheet_name) } else { "null".into() },
                if reveal { q(&threat.cell_ref) } else { "null".into() },
                if reveal { q(&threat.coordinate) } else { "null".into() },
                q(&threat.threat_kind),
                q(rule_id),
                q(&threat.severity),
                if reveal { q(&threat.formula) } else { "null".into() },
                if reveal { q(&threat.description) } else { "null".into() }
            ));
        }
        o.push(']');
        o.push('}');
    } else {
        o.push_str("null");
    }
    o.push_str(",\n  \"compiled_representation\": {");
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
        let project_version_tag = x
            .project_version_tag
            .map(|value| q(&format!("0x{value:04X}")))
            .unwrap_or_else(|| "null".into());
        let project_references = x
            .project_references
            .iter()
            .map(|reference| {
                format!(
                    "{{\"kind\":{},\"name\":{},\"extended_name\":{},\"libid\":{},\"libid_info\":{},\"libid_absolute\":{},\"libid_absolute_info\":{},\"libid_relative\":{},\"libid_relative_info\":{},\"major_version\":{},\"minor_version\":{},\"original_libid\":{},\"libid_twiddled\":{},\"libid_twiddled_info\":{},\"libid_extended\":{},\"libid_extended_info\":{},\"original_type_lib_guid_bytes\":{},\"cookie\":{}}}",
                    q(&reference.kind),
                    if reveal { opt_q(&reference.name) } else { "null".into() },
                    if reveal { opt_q(&reference.extended_name) } else { "null".into() },
                    if reveal { opt_q(&reference.libid) } else { "null".into() },
                    libid_info_json(reference.parsed_libid.as_ref(), reveal),
                    if reveal { opt_q(&reference.libid_absolute) } else { "null".into() },
                    project_reference_info_json(reference.parsed_libid_absolute.as_ref(), reveal),
                    if reveal { opt_q(&reference.libid_relative) } else { "null".into() },
                    project_reference_info_json(reference.parsed_libid_relative.as_ref(), reveal),
                    reference.major_version.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
                    reference.minor_version.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
                    if reveal { opt_q(&reference.original_libid) } else { "null".into() },
                    if reveal { opt_q(&reference.libid_twiddled) } else { "null".into() },
                    libid_info_json(reference.parsed_libid_twiddled.as_ref(), reveal),
                    if reveal { opt_q(&reference.libid_extended) } else { "null".into() },
                    libid_info_json(reference.parsed_libid_extended.as_ref(), reveal),
                    if reveal { opt_q(&reference.original_type_lib_guid_bytes) } else { "null".into() },
                    reference.cookie.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        o.push_str(&format!("\n    \"status\": {},\n    \"project_name\": {},\n    \"system_kind\": {},\n    \"project_version_tag\": {},\n    \"pcode_disassembled\": false,\n    \"pcode_verified\": false,\n    \"code_page\": {},\n    \"reference_count\": {},\n    \"references\": [{}],\n    \"project_constants\": {},\n    \"project_cache\": {{\"length\": {}, \"fingerprint_fnv1a64\": {}}},\n    \"srp_cache_count\": {},\n    \"srp_caches\": [",q(&x.compiled_representation_status),if reveal{opt_q(&x.name)}else{"null".into()},x.system_kind.map(|v|v.to_string()).unwrap_or_else(||"null".into()),project_version_tag,x.code_page.map(|v|v.to_string()).unwrap_or_else(||"null".into()),x.project_references.len(),project_references,project_constants,x.project_cache.byte_length,q(&format!("{:016x}",x.project_cache.fingerprint)),x.srp_caches.len()));
        for (i, cache) in x.srp_caches.iter().enumerate() {
            if i > 0 {
                o.push(',');
            }
            o.push_str(&format!(
                "{{\"stream_name\":{},\"length\":{},\"fingerprint_fnv1a64\":{},\"interpretation\":\"opaque version-dependent SRP cache; ignored on read\"}}",
                if reveal { q(&cache.stream_name) } else { "null".into() },
                cache.byte_length,
                q(&format!("{:016x}", cache.fingerprint))
            ));
        }
        o.push_str("],\n    \"module_caches\": [");
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
                o.push_str(&format!(
                    ",\"pcode_layout\":{{\"profile\":\"vba7_observed\",\"cafe_offset\":{},\"profile_header_raw\":{},\"line_count\":{},\"code_bytes_total\":{},\"mnemonics_decoded\":false,\"lines\":[",
                    layout.cafe_offset,
                    if reveal {
                        q(&layout
                            .profile_header_raw
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<String>())
                    } else {
                        "null".into()
                    },
                    layout.line_count,
                    layout.code_bytes_total
                ));
                for (j, line) in layout.lines.iter().enumerate() {
                    if j > 0 {
                        o.push(',');
                    }
                    let record_prefix_raw = if reveal {
                        q(&line
                            .record_prefix_raw
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<String>())
                    } else {
                        "null".into()
                    };
                    let record_middle_raw = if reveal {
                        q(&line
                            .record_middle_raw
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<String>())
                    } else {
                        "null".into()
                    };
                    let raw_bytes = if reveal {
                        q(&line
                            .raw_bytes
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<String>())
                    } else {
                        "null".into()
                    };
                    o.push_str(&format!(
                        "{{\"source_line\":{},\"record_prefix_raw\":{},\"length\":{},\"record_middle_raw\":{},\"relative_code_offset_raw\":{},\"cache_offset\":{},\"raw_word_count\":{},\"has_partial_word\":{},\"raw_hex\":{}}}",
                        line.source_line,
                        record_prefix_raw,
                        line.line_length,
                        record_middle_raw,
                        line.relative_code_offset_raw,
                        line.cache_offset
                            .map(|offset| offset.to_string())
                            .unwrap_or_else(|| "null".into()),
                        line.raw_word_count,
                        line.has_partial_word,
                        raw_bytes
                    ));
                }
                o.push_str("]}");
            }
            o.push('}');
        }
        o.push_str("]\n  }");
    } else {
        o.push_str("\n    \"status\": \"not_present_in_source_input\",\n    \"pcode_disassembled\": false,\n    \"pcode_verified\": false\n  }");
    }
    o.push_str(",\n  \"selected_compile_constants\": [");
    for (i, (name, value)) in a.project.conditional_constants.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        o.push_str(&format!(
            "{{\"name\":{},\"value\":{}}}",
            if reveal {
                q(name)
            } else {
                q(&format!("constant_{i}"))
            },
            if reveal { q(value) } else { "null".into() }
        ));
    }
    o.push(']');
    o.push_str(",\n  \"modules\": [");
    for (i, m) in a.project.modules.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        o.push_str("\n    {");
        let module_options = format!(
            "{{\"explicit\":{},\"compare_mode\":{},\"compare_explicit\":{},\"compare_valid\":{},\"array_base\":{},\"array_base_explicit\":{},\"array_base_valid\":{},\"private_module\":{}}}",
            m.options.explicit,
            q(&m.options.compare_mode),
            m.options.compare_explicit,
            m.options.compare_valid,
            m.options.array_base,
            m.options.array_base_explicit,
            m.options.array_base_valid,
            m.options.private_module
        );
        let implicit_type_rules = format!(
            "{{\"valid\":{},\"universal\":{},\"letter_count\":{},\"by_initial\":{}}}",
            m.implicit_types.valid,
            m.implicit_types.universal_type.is_some(),
            m.implicit_types.by_initial.len(),
            if reveal {
                format!(
                    "{{{}}}",
                    m.implicit_types
                        .by_initial
                        .iter()
                        .map(|(letter, type_name)| {
                            format!("{}:{}", q(&letter.to_string()), q(type_name))
                        })
                        .collect::<Vec<_>>()
                        .join(",")
                )
            } else {
                "null".into()
            }
        );
        o.push_str(&format!(
            "\n      \"name\": {},\n      \"source_name\": {},\n      \"predeclared_id\": {},\n      \"global_namespace\": {},\n      \"options\": {},\n      \"implicit_type_rules\": {},\n      \"implemented_interfaces\": [{}],\n      \"module_compile_constants\": [{}],\n      \"procedures\": [",
            if reveal {
                q(&m.name)
            } else {
                q(&format!("module_{i}"))
            },
            if reveal {
                q(&m.source_name)
            } else {
                "null".into()
            },
            m.predeclared_id
                .map(|value| value.to_string())
                .unwrap_or_else(|| "null".into()),
            m.global_namespace
                .map(|value| value.to_string())
                .unwrap_or_else(|| "null".into()),
            module_options,
            implicit_type_rules,
            m.implemented_interfaces.iter().enumerate().map(|(interface_index, interface)| {
                if reveal { q(interface) } else { q(&format!("interface_{interface_index}")) }
            }).collect::<Vec<_>>().join(","),
            m.conditional_constants
                .iter()
                .enumerate()
                .map(|(constant_index, (name, value))| {
                    format!(
                        "{{\"name\":{},\"value\":{}}}",
                        if reveal {
                            q(name)
                        } else {
                            q(&format!("constant_{constant_index}"))
                        },
                        if reveal { q(value) } else { "null".into() }
                    )
                })
                .collect::<Vec<_>>()
                .join(",")
        ));
        for (j, p) in m.procedures.iter().enumerate() {
            if j > 0 {
                o.push(',');
            }
            let effective_return_type = effective_procedure_return_type(&a.project, i, m, p);
            o.push_str(&format!("{{\"name\":{},\"kind\":{},\"visibility\":{},\"return_type\":{},\"effective_return_type\":{},\"automation_member_id\":{},\"default_member_candidate\":{},\"line\":{},\"parameters\":[",if reveal{q(&p.name)}else{q(&format!("procedure_{j}"))},q(&p.kind),q(&p.visibility),if reveal{opt_q(&p.return_type)}else{"null".into()},if reveal{opt_q(&effective_return_type)}else{"null".into()},if reveal{p.automation_member_id.map(|id|id.to_string()).unwrap_or_else(||"null".into())}else{"null".into()},p.automation_member_id == Some(0),p.span.line));
            for (k, arg) in p.parameters.iter().enumerate() {
                if k > 0 {
                    o.push(',');
                }
                o.push_str(&format!(
                    "{{\"name\":{},\"type\":{},\"effective_type\":{},\"default_value\":{},\"passing\":{},\"passing_explicit\":{},\"array\":{},\"optional\":{},\"param_array\":{}}}",
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
                    if reveal {
                        opt_q(&effective_parameter_type(&a.project, i, m, arg))
                    } else {
                        "null".into()
                    },
                    if reveal {
                        opt_q(&arg.default_value)
                    } else {
                        "null".into()
                    },
                    q(&arg.passing),
                    arg.passing_explicit,
                    arg.is_array,
                    arg.optional,
                    arg.is_param_array
                ));
            }
            o.push_str("],\"statements\":[");
            write_statements(&mut o, &p.statements, &a.project, i, m, reveal);
            o.push_str("]}");
        }
        o.push_str("],\n      \"declarations\": [");
        for (j, var) in m.declarations.iter().enumerate() {
            if j > 0 {
                o.push(',');
            }
            let dimensions = var
                .array_dimensions
                .iter()
                .map(|dimension| {
                    array_dimension_json(
                        dimension,
                        m.options.array_base,
                        m.options.array_base_valid,
                        reveal,
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            o.push_str(&format!(
                "{{\"name\":{},\"kind\":{},\"visibility\":{},\"type\":{},\"effective_type\":{},\"enum_value_status\":{},\"enum_value\":{},\"array\":{},\"array_dimensions_status\":{},\"array_dimensions\":[{}],\"ptr_safe\":{},\"external_library\":{},\"external_alias\":{},\"line\":{},\"parameters\":[{}]}}",
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
                if reveal {
                    opt_q(&effective_declaration_type(&a.project, i, m, var))
                } else {
                    "null".into()
                },
                q(if var.kind != "enum_member" {
                    "not_applicable"
                } else if var.enum_value.is_some() {
                    "computed"
                } else {
                    "unresolved"
                }),
                if reveal {
                    var.enum_value
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "null".into())
                } else {
                    "null".into()
                },
                var.is_array,
                q(array_dimension_status(var)),
                dimensions,
                var.is_ptr_safe,
                if reveal { opt_q(&var.external_library) } else { "null".into() },
                if reveal { opt_q(&var.external_alias) } else { "null".into() },
                var.span.line,
                var.parameters.iter().enumerate().map(|(k, arg)| format!(
                    "{{\"name\":{},\"type\":{},\"effective_type\":{},\"default_value\":{},\"passing\":{},\"passing_explicit\":{},\"array\":{},\"optional\":{},\"param_array\":{}}}",
                    if reveal { q(&arg.name) } else { q(&format!("argument_{k}")) },
                    if reveal { opt_q(&arg.type_name) } else { "null".into() },
                    if reveal { opt_q(&effective_parameter_type(&a.project, i, m, arg)) } else { "null".into() },
                    if reveal { opt_q(&arg.default_value) } else { "null".into() },
                    q(&arg.passing), arg.passing_explicit, arg.is_array, arg.optional, arg.is_param_array
                )).collect::<Vec<_>>().join(",")
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
        let dispatch_candidates = if reveal {
            format!(
                "[{}]",
                c.dispatch_candidates
                    .iter()
                    .map(|candidate| q(candidate))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        } else {
            "null".into()
        };
        o.push_str(&format!("{{\"module\":{},\"procedure\":{},\"target\":{},\"resolution\":{},\"argument_count\":{},\"arguments\":{},\"external_library\":{},\"external_alias\":{},\"dispatch_candidate_count\":{},\"dispatch_candidates\":{},\"line\":{}}}",module_label(a,&c.module,reveal),procedure_label(a,&c.module,c.procedure.as_deref(),reveal),if reveal{q(&c.target)}else{q(&format!("call_{i}"))},q(&c.resolution),c.argument_count.map(|n|n.to_string()).unwrap_or_else(||"null".into()),arguments,if reveal{opt_q(&c.external_library)}else{"null".into()},if reveal{opt_q(&c.external_alias)}else{"null".into()},c.dispatch_candidates.len(),dispatch_candidates,c.span.line));
    }
    o.push_str("],\n  \"references\": [");
    for (i, r) in a.references.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        o.push_str(&format!(
            "{{\"module\":{},\"procedure\":{},\"name\":{},\"resolution\":{},\"implicit_type\":{},\"line\":{}}}",
            module_label(a, &r.module, reveal),
            procedure_label(a, &r.module, r.procedure.as_deref(), reveal),
            if reveal {
                q(&r.name)
            } else {
                q(&format!("symbol_{i}"))
            },
            q(&r.resolution),
            if reveal {
                opt_q(&r.implicit_type)
            } else {
                "null".into()
            },
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
    o.push_str("],\n  \"excel_worksheet_access_candidates\": [");
    for (i, access) in a.excel_worksheet_accesses.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        let data_access_ids = format!(
            "[{}]",
            access
                .data_access_indices
                .iter()
                .map(|index| index.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        let cell_range_bounds = if reveal {
            access
                .cell_range_bounds
                .map(|bounds| {
                    format!(
                        "{{\"first_row\":{},\"first_column\":{},\"last_row\":{},\"last_column\":{}}}",
                        bounds.first_row,
                        bounds.first_column,
                        bounds.last_row,
                        bounds.last_column
                    )
                })
                .unwrap_or_else(|| "null".into())
        } else {
            "null".into()
        };
        let workbook_cell_ids = if reveal {
            format!(
                "[{}]",
                access
                    .workbook_cell_indices
                    .iter()
                    .map(|index| index.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            )
        } else {
            "null".into()
        };
        o.push_str(&format!(
            "{{\"module\":{},\"procedure\":{},\"sheet_selector_kind\":{},\"sheet_selector\":{},\"sheet_index_candidate\":{},\"sheet_candidate\":{},\"sheet_resolution\":{},\"access_kind\":{},\"member_selector_candidate\":{},\"cell_range_bounds\":{},\"defined_name_candidate\":{},\"defined_name_resolution\":{},\"table_id_candidate\":{},\"table_candidate\":{},\"table_column_id_candidate\":{},\"table_column_candidate\":{},\"table_row_index_candidate\":{},\"table_resolution\":{},\"table_section\":{},\"data_access_ids\":{},\"workbook_cell_ids\":{},\"workbook_cell_match_count\":{},\"workbook_cell_matches_truncated\":{},\"start_byte\":{},\"end_byte\":{},\"line\":{},\"column\":{}}}",
            module_label(a, &access.module, reveal),
            procedure_label(a, &access.module, access.procedure.as_deref(), reveal),
            q(&access.sheet_selector_kind),
            if reveal { opt_q(&access.sheet_selector) } else { "null".into() },
            access
                .sheet_index_candidate
                .map(|index| index.to_string())
                .unwrap_or_else(|| "null".into()),
            if reveal { opt_q(&access.sheet_candidate) } else { "null".into() },
            q(&access.sheet_resolution),
            q(&access.access_kind),
            if reveal { opt_q(&access.member_selector_candidate) } else { "null".into() },
            cell_range_bounds,
            if reveal { opt_q(&access.defined_name_candidate) } else { "null".into() },
            opt_q(&access.defined_name_resolution),
            if reveal { access.table_index_candidate.map_or_else(|| "null".into(), |index| index.to_string()) } else { "null".into() },
            if reveal { opt_q(&access.table_candidate) } else { "null".into() },
            if reveal { access.table_column_index_candidate.map_or_else(|| "null".into(), |index| index.to_string()) } else { "null".into() },
            if reveal { opt_q(&access.table_column_candidate) } else { "null".into() },
            if reveal { access.table_row_index_candidate.map_or_else(|| "null".into(), |index| index.to_string()) } else { "null".into() },
            opt_q(&access.table_resolution),
            opt_q(&access.table_section),
            data_access_ids,
            workbook_cell_ids,
            if reveal {
                access.workbook_cell_indices.len().to_string()
            } else {
                "null".into()
            },
            access.workbook_cell_matches_truncated,
            access.span.start,
            access.span.end,
            access.span.line,
            access.span.column
        ));
    }
    o.push_str("],\n  \"data_flow_candidates\": [");
    for (i, v) in a.data_flow.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        let call_callee_module = if reveal {
            v.call_callee_module
                .as_deref()
                .map(q)
                .unwrap_or_else(|| "null".into())
        } else {
            "null".into()
        };
        let call_callee_procedure = if reveal {
            v.call_callee_procedure
                .as_deref()
                .map(q)
                .unwrap_or_else(|| "null".into())
        } else {
            "null".into()
        };
        o.push_str(&format!("{{\"module\":{},\"procedure\":{},\"target\":{},\"inputs\":{},\"argument_slot_index\":{},\"value_expression\":{},\"transfer\":{},\"call_callee_module\":{},\"call_callee_procedure\":{},\"line\":{}}}",module_label(a,&v.module,reveal),procedure_label(a,&v.module,v.procedure.as_deref(),reveal),if reveal{q(&v.target)}else{"null".into()},if reveal{format!("[{}]",v.inputs.iter().map(|z|q(z)).collect::<Vec<_>>().join(","))}else{v.inputs.len().to_string()},v.argument_slot_index.map(|slot| slot.to_string()).unwrap_or_else(|| "null".into()),if reveal{opt_q(&v.value_expression)}else{"null".into()},q(&v.transfer),call_callee_module,call_callee_procedure,v.span.line));
    }
    o.push_str("],\n  \"data_flow_paths\": [");
    for (i, fact) in a.data_flow_paths.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        let conditions = if reveal {
            format!(
                "[{}]",
                fact.conditions
                    .iter()
                    .map(|condition| q(condition))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        } else if fact.conditions.is_empty() {
            "[]".into()
        } else {
            format!(
                "[{}]",
                (0..fact.conditions.len())
                    .map(|index| q(&format!("condition_{index}")))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        o.push_str(&format!(
            "{{\"data_flow_id\":{},\"path_id\":{},\"path_position\":{},\"flow_node_id\":{},\"module\":{},\"procedure\":{},\"conditions\":{},\"condition_count\":{},\"feasibility\":{},\"path_complete\":{},\"line\":{}}}",
            fact.data_flow_index,
            fact.path_index,
            fact.path_position,
            fact.flow_node_id,
            module_label(a, &fact.module, reveal),
            procedure_label(a, &fact.module, Some(&fact.procedure), reveal),
            conditions,
            fact.conditions.len(),
            q(&fact.feasibility),
            fact.path_complete,
            fact.span.line
        ));
    }
    o.push_str("],\n  \"interprocedural_data_flow_paths\": [");
    for (i, fact) in a.interprocedural_data_flow_paths.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        let caller_conditions = disclosure_conditions(&fact.caller_conditions, reveal, "caller", i);
        let callee_conditions = disclosure_conditions(&fact.callee_conditions, reveal, "callee", i);
        let relation = a
            .data_flow
            .get(fact.argument_data_flow_index)
            .filter(|argument| argument.transfer.starts_with("optional_"))
            .map(|_| "optional_default_to_parameter_use_candidate")
            .unwrap_or("procedure_argument_to_parameter_use_candidate");
        o.push_str(&format!(
            "{{\"argument_data_flow_id\":{},\"callee_use_data_flow_id\":{},\"caller_path_id\":{},\"caller_path_position\":{},\"callee_path_id\":{},\"callee_path_position\":{},\"caller_module\":{},\"caller_procedure\":{},\"callee_module\":{},\"callee_procedure\":{},\"parameter\":{},\"relation\":{},\"caller_conditions\":{},\"callee_conditions\":{},\"caller_condition_count\":{},\"callee_condition_count\":{},\"feasibility\":{},\"caller_path_complete\":{},\"callee_path_complete\":{}}}",
            fact.argument_data_flow_index,
            fact.callee_use_data_flow_index,
            fact.caller_path_index,
            fact.caller_path_position,
            fact.callee_path_index,
            fact.callee_path_position,
            module_label(a, &fact.caller_module, reveal),
            procedure_label(a, &fact.caller_module, Some(&fact.caller_procedure), reveal),
            module_label(a, &fact.callee_module, reveal),
            procedure_label(a, &fact.callee_module, Some(&fact.callee_procedure), reveal),
            if reveal { q(&fact.parameter) } else { q(&format!("parameter_{i}")) },
            q(relation),
            caller_conditions,
            callee_conditions,
            fact.caller_conditions.len(),
            fact.callee_conditions.len(),
            q(&fact.feasibility),
            fact.caller_path_complete,
            fact.callee_path_complete
        ));
    }
    o.push_str("],\n  \"interprocedural_argument_value_paths\": [");
    for (i, fact) in a.interprocedural_argument_value_paths.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        let conditions = disclosure_conditions(&fact.conditions, reveal, "argument_value", i);
        o.push_str(&format!(
            "{{\"argument_data_flow_id\":{},\"argument_slot_index\":{},\"caller_call_id\":{},\"caller_path_id\":{},\"caller_path_position\":{},\"caller_module\":{},\"caller_procedure\":{},\"callee_module\":{},\"callee_procedure\":{},\"parameter\":{},\"actual_expression\":{},\"resolved_value\":{},\"resolution\":{},\"conditions\":{},\"condition_count\":{},\"feasibility\":{},\"path_complete\":{}}}",
            fact.argument_data_flow_index,
            fact.argument_slot_index.map(|slot| slot.to_string()).unwrap_or_else(|| "null".into()),
            fact.caller_call_index.map(|index| index.to_string()).unwrap_or_else(|| "null".into()),
            fact.caller_path_index,
            fact.caller_path_position,
            module_label(a, &fact.caller_module, reveal),
            procedure_label(a, &fact.caller_module, Some(&fact.caller_procedure), reveal),
            module_label(a, &fact.callee_module, reveal),
            procedure_label(a, &fact.callee_module, Some(&fact.callee_procedure), reveal),
            if reveal { q(&fact.parameter) } else { q(&format!("parameter_{i}")) },
            if reveal { opt_q(&fact.actual_expression) } else { "null".into() },
            if reveal { opt_q(&fact.resolved_value) } else { "null".into() },
            q(&fact.resolution),
            conditions,
            fact.conditions.len(),
            q(&fact.feasibility),
            fact.path_complete
        ));
    }
    o.push_str("],\n  \"interprocedural_argument_composition_paths\": [");
    for (i, fact) in a
        .interprocedural_argument_composition_paths
        .iter()
        .enumerate()
    {
        if i > 0 {
            o.push(',');
        }
        let caller_conditions =
            disclosure_conditions(&fact.caller_conditions, reveal, "argument_caller", i);
        let callee_conditions =
            disclosure_conditions(&fact.callee_conditions, reveal, "argument_callee", i);
        o.push_str(&format!(
            "{{\"argument_data_flow_id\":{},\"argument_slot_index\":{},\"caller_call_id\":{},\"caller_path_id\":{},\"caller_path_position\":{},\"callee_path_id\":{},\"callee_path_position\":{},\"caller_module\":{},\"caller_procedure\":{},\"callee_module\":{},\"callee_procedure\":{},\"parameter\":{},\"actual_expression\":{},\"resolved_value\":{},\"caller_conditions\":{},\"callee_conditions\":{},\"caller_condition_count\":{},\"callee_condition_count\":{},\"caller_feasibility\":{},\"callee_feasibility\":{},\"feasibility\":{},\"caller_path_complete\":{},\"callee_path_complete\":{}}}",
            fact.argument_data_flow_index,
            fact.argument_slot_index.map(|slot| slot.to_string()).unwrap_or_else(|| "null".into()),
            fact.caller_call_index.map(|index| index.to_string()).unwrap_or_else(|| "null".into()),
            fact.caller_path_index,
            fact.caller_path_position,
            fact.callee_path_index,
            fact.callee_path_position,
            module_label(a, &fact.caller_module, reveal),
            procedure_label(a, &fact.caller_module, Some(&fact.caller_procedure), reveal),
            module_label(a, &fact.callee_module, reveal),
            procedure_label(a, &fact.callee_module, Some(&fact.callee_procedure), reveal),
            if reveal { q(&fact.parameter) } else { q(&format!("parameter_{i}")) },
            if reveal { opt_q(&fact.actual_expression) } else { "null".into() },
            if reveal { opt_q(&fact.resolved_value) } else { "null".into() },
            caller_conditions,
            callee_conditions,
            fact.caller_conditions.len(),
            fact.callee_conditions.len(),
            q(&fact.caller_feasibility),
            q(&fact.callee_feasibility),
            q(&fact.feasibility),
            fact.caller_path_complete,
            fact.callee_path_complete
        ));
    }
    o.push_str("],\n  \"interprocedural_return_paths\": [");
    for (i, fact) in a.interprocedural_return_paths.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        let caller_conditions =
            disclosure_conditions(&fact.caller_conditions, reveal, "return_caller", i);
        let callee_conditions =
            disclosure_conditions(&fact.callee_conditions, reveal, "return_callee", i);
        o.push_str(&format!(
            "{{\"caller_return_data_flow_id\":{},\"callee_return_data_flow_id\":{},\"caller_path_id\":{},\"caller_path_position\":{},\"callee_path_id\":{},\"callee_path_position\":{},\"caller_module\":{},\"caller_procedure\":{},\"callee_module\":{},\"callee_procedure\":{},\"relation\":\"function_return_to_caller_assignment_candidate\",\"caller_conditions\":{},\"callee_conditions\":{},\"callee_return_expression\":{},\"resolved_return_value\":{},\"caller_post_return_conditions\":{},\"post_return_feasibility\":{},\"caller_condition_count\":{},\"callee_condition_count\":{},\"feasibility\":{},\"caller_path_complete\":{},\"callee_path_complete\":{}}}",
            fact.caller_return_data_flow_index,
            fact.callee_return_data_flow_index,
            fact.caller_path_index,
            fact.caller_path_position,
            fact.callee_path_index,
            fact.callee_path_position,
            module_label(a, &fact.caller_module, reveal),
            procedure_label(a, &fact.caller_module, Some(&fact.caller_procedure), reveal),
            module_label(a, &fact.callee_module, reveal),
            procedure_label(a, &fact.callee_module, Some(&fact.callee_procedure), reveal),
            caller_conditions,
            callee_conditions,
            if reveal { opt_q(&fact.callee_return_expression) } else { "null".into() },
            if reveal { opt_q(&fact.resolved_return_value) } else { "null".into() },
            if reveal { disclosure_conditions(&fact.caller_post_return_conditions, true, "return_post", i) } else { "null".into() },
            q(&fact.post_return_feasibility),
            fact.caller_conditions.len(),
            fact.callee_conditions.len(),
            q(&fact.feasibility),
            fact.caller_path_complete,
            fact.callee_path_complete
        ));
    }
    o.push_str("],\n  \"interprocedural_return_compositions\": [");
    for (i, fact) in a.interprocedural_return_compositions.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        let outer_conditions =
            disclosure_conditions(&fact.outer_conditions, reveal, "return_comp_outer", i);
        let intermediate_conditions = disclosure_conditions(
            &fact.intermediate_conditions,
            reveal,
            "return_comp_intermediate",
            i,
        );
        let inner_conditions =
            disclosure_conditions(&fact.inner_conditions, reveal, "return_comp_inner", i);
        let outer_post_return_conditions = disclosure_conditions(
            &fact.outer_post_return_conditions,
            reveal,
            "return_comp_post",
            i,
        );
        let chain_modules = if reveal {
            format!(
                "[{}]",
                fact.chain_modules
                    .iter()
                    .map(|module| module_label(a, module, true))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        } else {
            format!(
                "[{}]",
                fact.chain_modules
                    .iter()
                    .map(|_| "null".to_owned())
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        let chain_procedures = if reveal {
            format!(
                "[{}]",
                fact.chain_procedures
                    .iter()
                    .zip(fact.chain_modules.iter())
                    .map(|(procedure, module)| procedure_label(a, module, Some(procedure), true))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        } else {
            format!(
                "[{}]",
                fact.chain_procedures
                    .iter()
                    .map(|procedure| procedure_label(a, "", Some(procedure), false))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        let chain_conditions = format!(
            "[{}]",
            fact.chain_conditions
                .iter()
                .enumerate()
                .map(|(index, conditions)| {
                    disclosure_conditions(conditions, reveal, "return_comp_chain", i * 1000 + index)
                })
                .collect::<Vec<_>>()
                .join(",")
        );
        let chain_return_data_flow_indices = usize_array_json(&fact.chain_return_data_flow_indices);
        let chain_path_indices = usize_array_json(&fact.chain_path_indices);
        let chain_path_positions = usize_array_json(&fact.chain_path_positions);
        let chain_path_complete = bool_array_json(&fact.chain_path_complete);
        o.push_str(&format!(
            "{{\"outer_return_data_flow_id\":{},\"inner_return_data_flow_id\":{},\"composition_depth\":{},\"outer_path_id\":{},\"outer_path_position\":{},\"intermediate_path_id\":{},\"intermediate_path_position\":{},\"inner_path_id\":{},\"inner_path_position\":{},\"outer_module\":{},\"outer_procedure\":{},\"intermediate_module\":{},\"intermediate_procedure\":{},\"inner_module\":{},\"inner_procedure\":{},\"outer_conditions\":{},\"intermediate_conditions\":{},\"inner_conditions\":{},\"inner_return_expression\":{},\"resolved_return_value\":{},\"outer_post_return_conditions\":{},\"post_return_feasibility\":{},\"outer_condition_count\":{},\"intermediate_condition_count\":{},\"inner_condition_count\":{},\"outer_post_return_condition_count\":{},\"feasibility\":{},\"outer_path_complete\":{},\"intermediate_path_complete\":{},\"inner_path_complete\":{},\"chain_return_data_flow_ids\":{},\"chain_modules\":{},\"chain_procedures\":{},\"chain_path_ids\":{},\"chain_path_positions\":{},\"chain_conditions\":{},\"chain_path_complete\":{}}}",
            fact.outer_return_data_flow_index,
            fact.inner_return_data_flow_index,
            fact.composition_depth,
            fact.outer_path_index,
            fact.outer_path_position,
            fact.intermediate_path_index,
            fact.intermediate_path_position,
            fact.inner_path_index,
            fact.inner_path_position,
            module_label(a, &fact.outer_module, reveal),
            procedure_label(a, &fact.outer_module, Some(&fact.outer_procedure), reveal),
            module_label(a, &fact.intermediate_module, reveal),
            procedure_label(
                a,
                &fact.intermediate_module,
                Some(&fact.intermediate_procedure),
                reveal,
            ),
            module_label(a, &fact.inner_module, reveal),
            procedure_label(a, &fact.inner_module, Some(&fact.inner_procedure), reveal),
            outer_conditions,
            intermediate_conditions,
            inner_conditions,
            if reveal {
                opt_q(&fact.inner_return_expression)
            } else {
                "null".into()
            },
            if reveal {
                opt_q(&fact.resolved_return_value)
            } else {
                "null".into()
            },
            outer_post_return_conditions,
            q(&fact.post_return_feasibility),
            fact.outer_conditions.len(),
            fact.intermediate_conditions.len(),
            fact.inner_conditions.len(),
            fact.outer_post_return_conditions.len(),
            q(&fact.feasibility),
            fact.outer_path_complete,
            fact.intermediate_path_complete,
            fact.inner_path_complete,
            chain_return_data_flow_indices,
            chain_modules,
            chain_procedures,
            chain_path_indices,
            chain_path_positions,
            chain_conditions,
            chain_path_complete
        ));
    }
    o.push_str("],\n  \"interprocedural_byref_write_paths\": [");
    for (i, fact) in a.interprocedural_byref_write_paths.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        let caller_conditions =
            disclosure_conditions(&fact.caller_conditions, reveal, "byref_caller", i);
        let callee_conditions =
            disclosure_conditions(&fact.callee_conditions, reveal, "byref_callee", i);
        o.push_str(&format!(
            "{{\"caller_write_data_flow_id\":{},\"argument_data_flow_id\":{},\"callee_write_data_flow_id\":{},\"caller_path_id\":{},\"caller_path_position\":{},\"callee_path_id\":{},\"callee_path_position\":{},\"caller_module\":{},\"caller_procedure\":{},\"callee_module\":{},\"callee_procedure\":{},\"parameter\":{},\"relation\":\"byref_call_to_callee_write_candidate\",\"caller_conditions\":{},\"callee_conditions\":{},\"caller_condition_count\":{},\"callee_condition_count\":{},\"feasibility\":{},\"caller_path_complete\":{},\"callee_path_complete\":{}}}",
            fact.caller_write_data_flow_index,
            fact.argument_data_flow_index,
            fact.callee_write_data_flow_index,
            fact.caller_path_index,
            fact.caller_path_position,
            fact.callee_path_index,
            fact.callee_path_position,
            module_label(a, &fact.caller_module, reveal),
            procedure_label(a, &fact.caller_module, Some(&fact.caller_procedure), reveal),
            module_label(a, &fact.callee_module, reveal),
            procedure_label(a, &fact.callee_module, Some(&fact.callee_procedure), reveal),
            if reveal { q(&fact.parameter) } else { q(&format!("parameter_{i}")) },
            caller_conditions,
            callee_conditions,
            fact.caller_conditions.len(),
            fact.callee_conditions.len(),
            q(&fact.feasibility),
            fact.caller_path_complete,
            fact.callee_path_complete
        ));
    }
    o.push_str("],\n  \"interprocedural_byref_value_paths\": [");
    for (i, fact) in a.interprocedural_byref_value_paths.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        let caller_conditions =
            disclosure_conditions(&fact.caller_conditions, reveal, "byref_value_caller", i);
        let callee_conditions =
            disclosure_conditions(&fact.callee_conditions, reveal, "byref_value_callee", i);
        o.push_str(&format!(
            "{{\"composition_depth\":{},\"caller_write_data_flow_id\":{},\"argument_data_flow_id\":{},\"callee_write_data_flow_id\":{},\"caller_path_id\":{},\"caller_path_position\":{},\"callee_path_id\":{},\"callee_path_position\":{},\"caller_module\":{},\"caller_procedure\":{},\"callee_module\":{},\"callee_procedure\":{},\"parameter\":{},\"caller_value\":{},\"callee_write_expression\":{},\"resolved_value\":{},\"resolution\":{},\"caller_conditions\":{},\"callee_conditions\":{},\"caller_condition_count\":{},\"callee_condition_count\":{},\"feasibility\":{},\"caller_path_complete\":{},\"callee_path_complete\":{}}}",
            fact.composition_depth,
            fact.caller_write_data_flow_index,
            fact.argument_data_flow_index,
            fact.callee_write_data_flow_index,
            fact.caller_path_index,
            fact.caller_path_position,
            fact.callee_path_index,
            fact.callee_path_position,
            module_label(a, &fact.caller_module, reveal),
            procedure_label(a, &fact.caller_module, Some(&fact.caller_procedure), reveal),
            module_label(a, &fact.callee_module, reveal),
            procedure_label(a, &fact.callee_module, Some(&fact.callee_procedure), reveal),
            if reveal { q(&fact.parameter) } else { q(&format!("parameter_{i}")) },
            if reveal { opt_q(&fact.caller_value) } else { "null".into() },
            if reveal { opt_q(&fact.callee_write_expression) } else { "null".into() },
            if reveal { opt_q(&fact.resolved_value) } else { "null".into() },
            q(&fact.resolution),
            caller_conditions,
            callee_conditions,
            fact.caller_conditions.len(),
            fact.callee_conditions.len(),
            q(&fact.feasibility),
            fact.caller_path_complete,
            fact.callee_path_complete
        ));
    }
    o.push_str("],\n  \"interprocedural_error_paths\": [");
    for (i, fact) in a.interprocedural_error_paths.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        let caller_conditions =
            disclosure_conditions(&fact.caller_conditions, reveal, "error_caller", i);
        let callee_conditions =
            disclosure_conditions(&fact.callee_conditions, reveal, "error_callee", i);
        o.push_str(&format!(
            "{{\"caller_call_id\":{},\"caller_path_id\":{},\"caller_path_position\":{},\"callee_path_id\":{},\"callee_fault_path_position\":{},\"callee_fault_node_id\":{},\"caller_module\":{},\"caller_procedure\":{},\"callee_module\":{},\"callee_procedure\":{},\"caller_host_entry_candidate\":{},\"caller_error_response\":{},\"caller_recovery_path_position\":{},\"caller_recovery_node_id\":{},\"relation\":{},\"caller_conditions\":{},\"callee_conditions\":{},\"caller_condition_count\":{},\"callee_condition_count\":{},\"feasibility\":{},\"caller_path_complete\":{},\"callee_path_complete\":{}}}",
            fact.caller_call_index,
            fact.caller_path_index,
            fact.caller_path_position,
            fact.callee_path_index,
            fact.callee_fault_path_position,
            fact.callee_fault_node_id,
            module_label(a, &fact.caller_module, reveal),
            procedure_label(a, &fact.caller_module, Some(&fact.caller_procedure), reveal),
            module_label(a, &fact.callee_module, reveal),
            procedure_label(a, &fact.callee_module, Some(&fact.callee_procedure), reveal),
            fact.caller_host_entry_candidate,
            q(&fact.caller_error_response),
            fact.caller_recovery_path_position
                .map(|position| position.to_string())
                .unwrap_or_else(|| "null".into()),
            fact.caller_recovery_node_id
                .map(|node| node.to_string())
                .unwrap_or_else(|| "null".into()),
            q(&fact.propagation),
            caller_conditions,
            callee_conditions,
            fact.caller_conditions.len(),
            fact.callee_conditions.len(),
            q(&fact.feasibility),
            fact.caller_path_complete,
            fact.callee_path_complete
        ));
    }
    o.push_str("],\n  \"path_value_flows\": [");
    for (i, fact) in a.path_value_flows.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        let conditions = if reveal {
            format!(
                "[{}]",
                fact.conditions
                    .iter()
                    .map(|condition| q(condition))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        } else if fact.conditions.is_empty() {
            "[]".into()
        } else {
            format!(
                "[{}]",
                (0..fact.conditions.len())
                    .map(|index| q(&format!("condition_{index}")))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        o.push_str(&format!(
            "{{\"path_id\":{},\"source_data_flow_id\":{},\"target_data_flow_id\":{},\"variable\":{},\"variable_present\":true,\"resolution\":{},\"conditions\":{},\"feasibility\":{},\"path_complete\":{}}}",
            fact.path_index,
            fact.source_data_flow_index
                .map(|index| index.to_string())
                .unwrap_or_else(|| "null".into()),
            fact.target_data_flow_index,
            if reveal { q(&fact.variable) } else { q(&format!("variable_{i}")) },
            q(&fact.resolution),
            conditions,
            q(&fact.feasibility),
            fact.path_complete,
        ));
    }
    o.push_str("],\n  \"path_aliases\": [");
    for (i, fact) in a.path_aliases.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        let conditions = disclosure_conditions(&fact.conditions, reveal, "alias", i);
        o.push_str(&format!(
            "{{\"data_flow_id\":{},\"path_id\":{},\"path_position\":{},\"module\":{},\"procedure\":{},\"target\":{},\"source\":{},\"conditions\":{},\"condition_count\":{},\"feasibility\":{},\"path_complete\":{}}}",
            fact.data_flow_index,
            fact.path_index,
            fact.path_position,
            module_label(a, &fact.module, reveal),
            procedure_label(a, &fact.module, Some(&fact.procedure), reveal),
            if reveal { q(&fact.target) } else { q(&format!("alias_target_{i}")) },
            if reveal { q(&fact.source) } else { q(&format!("alias_source_{i}")) },
            conditions,
            fact.conditions.len(),
            q(&fact.feasibility),
            fact.path_complete
        ));
    }
    o.push_str("],\n  \"path_alias_dispatches\": [");
    for (i, fact) in a.path_alias_dispatches.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        let conditions = disclosure_conditions(&fact.conditions, reveal, "alias_dispatch", i);
        let candidates = if reveal {
            format!(
                "[{}]",
                fact.dispatch_candidates
                    .iter()
                    .map(|candidate| q(candidate))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        } else {
            format!(
                "[{}]",
                (0..fact.dispatch_candidates.len())
                    .map(|index| q(&format!("dispatch_candidate_{index}")))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        o.push_str(&format!(
            "{{\"call_id\":{},\"alias_data_flow_id\":{},\"path_id\":{},\"path_position\":{},\"module\":{},\"procedure\":{},\"receiver\":{},\"alias_source\":{},\"member\":{},\"dispatch_candidates\":{},\"resolution\":{},\"conditions\":{},\"condition_count\":{},\"feasibility\":{},\"path_complete\":{}}}",
            fact.call_index,
            fact.alias_data_flow_index,
            fact.path_index,
            fact.path_position,
            module_label(a, &fact.module, reveal),
            procedure_label(a, &fact.module, Some(&fact.procedure), reveal),
            if reveal { q(&fact.receiver) } else { q(&format!("receiver_{i}")) },
            if reveal { q(&fact.alias_source) } else { q(&format!("alias_source_{i}")) },
            if reveal { q(&fact.member) } else { q(&format!("member_{i}")) },
            candidates,
            q(&fact.resolution),
            conditions,
            fact.conditions.len(),
            q(&fact.feasibility),
            fact.path_complete
        ));
    }
    o.push_str("],\n  \"data_access_paths\": [");
    for (i, fact) in a.data_access_paths.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        let conditions = if reveal {
            format!(
                "[{}]",
                fact.conditions
                    .iter()
                    .map(|condition| q(condition))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        } else if fact.conditions.is_empty() {
            "[]".into()
        } else {
            format!(
                "[{}]",
                (0..fact.conditions.len())
                    .map(|index| q(&format!("condition_{index}")))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        let operation = a
            .data_accesses
            .get(fact.data_access_index)
            .map(|access| q(&access.operation))
            .unwrap_or_else(|| "null".into());
        o.push_str(&format!(
            "{{\"data_access_id\":{},\"excel_worksheet_access_id\":{},\"path_id\":{},\"path_position\":{},\"flow_node_id\":{},\"module\":{},\"procedure\":{},\"operation\":{},\"conditions\":{},\"condition_count\":{},\"feasibility\":{},\"path_complete\":{},\"line\":{}}}",
            fact.data_access_index,
            fact
                .excel_worksheet_access_index
                .map(|index| index.to_string())
                .unwrap_or_else(|| "null".into()),
            fact.path_index,
            fact.path_position,
            fact.flow_node_id,
            module_label(a, &fact.module, reveal),
            procedure_label(a, &fact.module, Some(&fact.procedure), reveal),
            operation,
            conditions,
            fact.conditions.len(),
            q(&fact.feasibility),
            fact.path_complete,
            fact.span.line
        ));
    }
    o.push_str("],\n  \"data_access_value_flows\": [");
    for (i, fact) in a.data_access_value_flows.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        let conditions = if reveal {
            format!(
                "[{}]",
                fact.conditions
                    .iter()
                    .map(|condition| q(condition))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        } else if fact.conditions.is_empty() {
            "[]".into()
        } else {
            format!(
                "[{}]",
                (0..fact.conditions.len())
                    .map(|index| q(&format!("condition_{index}")))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        o.push_str(&format!(
            "{{\"path_id\":{},\"data_access_id\":{},\"excel_worksheet_access_id\":{},\"data_flow_id\":{},\"role\":{},\"variable\":{},\"conditions\":{},\"feasibility\":{},\"path_complete\":{}}}",
            fact.path_index,
            fact.data_access_index,
            fact
                .excel_worksheet_access_index
                .map(|index| index.to_string())
                .unwrap_or_else(|| "null".into()),
            fact.data_flow_index,
            q(&fact.role),
            if reveal { q(&fact.variable) } else { q(&format!("variable_{i}")) },
            conditions,
            q(&fact.feasibility),
            fact.path_complete,
        ));
    }
    o.push_str("],\n  \"data_access_predicates\": [");
    for (i, fact) in a.data_access_predicates.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        let conditions_before = if reveal {
            format!(
                "[{}]",
                fact.conditions_before
                    .iter()
                    .map(|condition| q(condition))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        } else if fact.conditions_before.is_empty() {
            "[]".into()
        } else {
            format!(
                "[{}]",
                (0..fact.conditions_before.len())
                    .map(|index| q(&format!("condition_{index}")))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        let outcome_condition = if reveal {
            q(&fact.outcome_condition)
        } else {
            redacted_condition(&Some(fact.outcome_condition.clone()))
                .as_deref()
                .map(q)
                .unwrap_or_else(|| q("branch condition"))
        };
        o.push_str(&format!(
            "{{\"path_id\":{},\"data_access_id\":{},\"excel_worksheet_access_id\":{},\"flow_node_id\":{},\"module\":{},\"procedure\":{},\"conditions_before\":{},\"condition_count\":{},\"outcome_condition\":{},\"feasibility\":{},\"path_complete\":{},\"line\":{}}}",
            fact.path_index,
            fact.data_access_index,
            fact
                .excel_worksheet_access_index
                .map(|index| index.to_string())
                .unwrap_or_else(|| "null".into()),
            fact.flow_node_id,
            module_label(a, &fact.module, reveal),
            procedure_label(a, &fact.module, Some(&fact.procedure), reveal),
            conditions_before,
            fact.conditions_before.len(),
            outcome_condition,
            q(&fact.feasibility),
            fact.path_complete,
            fact.span.line
        ));
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
    o.push_str("],\n  \"entry_points\": [");
    for (i, f) in a.entry_points.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        o.push_str(&format!(
            "{{\"module\":{},\"procedure\":{},\"trigger\":{},\"reason\":{},\"line\":{}}}",
            module_label(a, &f.module, reveal),
            procedure_label(a, &f.module, Some(&f.procedure), reveal),
            q(&f.trigger),
            if reveal { q(&f.reason) } else { "null".into() },
            f.span.line
        ));
    }
    o.push_str("],\n  \"paths\": [");
    for (i, p) in a.paths.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        let conditions = if reveal {
            format!(
                "[{}]",
                p.conditions
                    .iter()
                    .map(|c| q(c))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        } else {
            format!(
                "[{}]",
                p.conditions
                    .iter()
                    .map(|c| q(redacted_condition(&Some(c.clone()))
                        .as_deref()
                        .unwrap_or("condition")))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        o.push_str(&format!("{{\"module\":{},\"procedure\":{},\"nodes\":[{}],\"conditions\":{},\"stop_reason\":{},\"feasibility\":{},\"complete\":{}}}",module_label(a,&p.module,reveal),procedure_label(a,&p.module,Some(&p.procedure),reveal),p.nodes.iter().map(|n|n.to_string()).collect::<Vec<_>>().join(","),conditions,q(&p.stop_reason),q(&p.feasibility),p.complete));
    }
    o.push_str("],\n  \"decision_table\": [");
    for (i, row) in a.decision_table.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        let conditions = if reveal {
            format!(
                "[{}]",
                row.conditions
                    .iter()
                    .map(|c| q(c))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        } else {
            format!(
                "[{}]",
                row.conditions
                    .iter()
                    .map(|c| q(redacted_condition(&Some(c.clone()))
                        .as_deref()
                        .unwrap_or("condition")))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        o.push_str(&format!("{{\"module\":{},\"procedure\":{},\"conditions\":{},\"actions\":{},\"action_count\":{},\"outcome\":{},\"feasibility\":{}}}",module_label(a,&row.module,reveal),procedure_label(a,&row.module,Some(&row.procedure),reveal),conditions,if reveal{format!("[{}]",row.actions.iter().map(|v|q(v)).collect::<Vec<_>>().join(","))}else{"null".into()},row.actions.len(),q(&row.outcome),q(&row.feasibility)));
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

fn write_statements(
    o: &mut String,
    ss: &[Statement],
    project: &Project,
    module_index: usize,
    module: &Module,
    reveal: bool,
) {
    for (i, s) in ss.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        o.push('{');
        o.push_str(&format!("\"kind\":{},\"line\":{}", q(&s.kind), s.span.line));
        if reveal && let Some(e) = &s.expression {
            o.push_str(&format!(",\"expression\":{}", q(e)));
        }
        if let Some(declaration) = &s.declaration {
            o.push_str(&format!(
                ",\"declaration\":{}",
                declaration_json(declaration, project, module_index, module, reveal)
            ));
        }
        if s.kind == "case" {
            o.push_str(",\"case_ranges\":[");
            for (range_index, range) in s.case_ranges.iter().enumerate() {
                if range_index > 0 {
                    o.push(',');
                }
                o.push_str(&format!(
                    "{{\"kind\":{},\"valid\":{},\"line\":{},\"expression\":{},\"start_value\":{},\"end_value\":{},\"comparison_operator\":{}}}",
                    q(&range.kind),
                    range.valid,
                    range.span.line,
                    if reveal { opt_q(&range.expression) } else { "null".into() },
                    if reveal { opt_q(&range.start_value) } else { "null".into() },
                    if reveal { opt_q(&range.end_value) } else { "null".into() },
                    opt_q(&range.comparison_operator),
                ));
            }
            o.push(']');
        }
        if matches!(s.kind.as_str(), "for" | "for_each") {
            o.push_str(&format!(
                ",\"loop_control_variable_present\":{},\"loop_control_variable\":{},\"next_control_variable_present\":{},\"next_control_variable\":{}",
                s.loop_control_variable.is_some(),
                if reveal { opt_q(&s.loop_control_variable) } else { "null".into() },
                s.next_control_variable.is_some(),
                if reveal { opt_q(&s.next_control_variable) } else { "null".into() },
            ));
        }
        if s.kind == "for" {
            let header_valid =
                s.loop_control_variable.is_some() && s.loop_start.is_some() && s.loop_end.is_some();
            o.push_str(&format!(
                ",\"loop_header_valid\":{},\"loop_start_present\":{},\"loop_start\":{},\"loop_end_present\":{},\"loop_end\":{},\"loop_step_present\":{},\"loop_step\":{},\"loop_step_omitted\":{}",
                header_valid,
                s.loop_start.is_some(),
                if reveal { opt_q(&s.loop_start) } else { "null".into() },
                s.loop_end.is_some(),
                if reveal { opt_q(&s.loop_end) } else { "null".into() },
                s.loop_step.is_some(),
                if reveal { opt_q(&s.loop_step) } else { "null".into() },
                header_valid && s.loop_step.is_none(),
            ));
        }
        if !s.children.is_empty() {
            o.push_str(",\"children\":[");
            write_statements(o, &s.children, project, module_index, module, reveal);
            o.push(']');
        }
        o.push('}');
    }
}

fn effective_declaration_type(
    project: &Project,
    module_index: usize,
    module: &Module,
    declaration: &Declaration,
) -> Option<String> {
    if declaration.kind == "field" && declaration.type_name.is_none() {
        return None;
    }
    declaration
        .type_name
        .clone()
        .map(|type_name| {
            crate::typecheck::effective_project_type_name(project, module_index, module, &type_name)
        })
        .or_else(|| type_suffix(&declaration.name))
        .or_else(|| {
            (declaration.kind != "constant")
                .then(|| effective_implicit_type(module, &declaration.name))
                .flatten()
        })
}

fn effective_parameter_type(
    project: &Project,
    module_index: usize,
    module: &Module,
    parameter: &Parameter,
) -> Option<String> {
    if parameter.is_param_array {
        return Some("Variant".into());
    }
    parameter
        .type_name
        .clone()
        .map(|type_name| {
            crate::typecheck::effective_project_type_name(project, module_index, module, &type_name)
        })
        .or_else(|| effective_implicit_type(module, &parameter.name))
}

fn effective_procedure_return_type(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
) -> Option<String> {
    procedure
        .return_type
        .clone()
        .map(|type_name| {
            crate::typecheck::effective_project_type_name(project, module_index, module, &type_name)
        })
        .or_else(|| {
            matches!(
                procedure.kind.to_ascii_lowercase().as_str(),
                "function" | "property get"
            )
            .then(|| effective_implicit_type(module, &procedure.name))
            .flatten()
        })
}

fn effective_implicit_type(module: &Module, name: &str) -> Option<String> {
    type_suffix(name).or_else(|| {
        module.implicit_types.valid.then(|| {
            module
                .implicit_types
                .type_for_identifier(name)
                .unwrap_or_else(|| "Variant".into())
        })
    })
}

fn type_suffix(name: &str) -> Option<String> {
    Some(
        match name.chars().last()? {
            '%' => "Integer",
            '&' => "Long",
            '^' => "LongLong",
            '@' => "Currency",
            '!' => "Single",
            '#' => "Double",
            '$' => "String",
            _ => return None,
        }
        .into(),
    )
}

fn declaration_json(
    declaration: &Declaration,
    project: &Project,
    module_index: usize,
    module: &Module,
    reveal: bool,
) -> String {
    let dimensions = declaration
        .array_dimensions
        .iter()
        .map(|dimension| {
            array_dimension_json(
                dimension,
                module.options.array_base,
                module.options.array_base_valid,
                reveal,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"name\":{},\"kind\":{},\"type\":{},\"effective_type\":{},\"array\":{},\"array_dimensions_status\":{},\"array_dimensions\":[{}]}}",
        if reveal {
            q(&declaration.name)
        } else {
            "null".into()
        },
        q(&declaration.kind),
        if reveal {
            opt_q(&declaration.type_name)
        } else {
            "null".into()
        },
        if reveal {
            opt_q(&effective_declaration_type(
                project,
                module_index,
                module,
                declaration,
            ))
        } else {
            "null".into()
        },
        declaration.is_array,
        q(array_dimension_status(declaration)),
        dimensions,
    )
}

fn array_dimension_status(declaration: &Declaration) -> &'static str {
    if !declaration.is_array {
        "not_array"
    } else if declaration.array_dimensions.is_empty() {
        "array_bounds_not_declared"
    } else {
        "dimension_bounds_parsed"
    }
}

fn array_dimension_json(
    dimension: &ArrayDimension,
    array_base: u8,
    array_base_valid: bool,
    reveal: bool,
) -> String {
    let explicit_lower_bound = dimension.lower_bound.is_some();
    let lower_bound_source = match (explicit_lower_bound, array_base_valid) {
        (true, _) => "explicit_expression",
        (false, true) => "module_option_base",
        (false, false) => "invalid_module_option",
    };
    let effective_lower_bound = if explicit_lower_bound {
        if reveal {
            opt_q(&dimension.lower_bound)
        } else {
            "null".into()
        }
    } else if array_base_valid {
        q(&array_base.to_string())
    } else {
        "null".into()
    };
    format!(
        "{{\"lower_bound\":{},\"upper_bound\":{},\"lower_bound_present\":{},\"upper_bound_present\":{},\"lower_bound_source\":{},\"effective_lower_bound_expression\":{}}}",
        if reveal {
            opt_q(&dimension.lower_bound)
        } else {
            "null".into()
        },
        if reveal {
            opt_q(&dimension.upper_bound)
        } else {
            "null".into()
        },
        explicit_lower_bound,
        dimension.upper_bound.is_some(),
        q(lower_bound_source),
        effective_lower_bound,
    )
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
fn disclosure_conditions(
    conditions: &[String],
    reveal: bool,
    side: &str,
    fact_index: usize,
) -> String {
    if reveal {
        format!(
            "[{}]",
            conditions
                .iter()
                .map(|condition| q(condition))
                .collect::<Vec<_>>()
                .join(",")
        )
    } else if conditions.is_empty() {
        "[]".into()
    } else {
        format!(
            "[{}]",
            (0..conditions.len())
                .map(|index| q(&format!("{side}_condition_{fact_index}_{index}")))
                .collect::<Vec<_>>()
                .join(",")
        )
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
fn libid_info_json(info: Option<&crate::ovba::ParsedLibidReference>, reveal: bool) -> String {
    let Some(info) = info else {
        return "null".into();
    };
    format!(
        "{{\"path_kind\":{},\"guid\":{},\"major_version\":{},\"minor_version\":{},\"lcid\":{},\"path\":{},\"display_name\":{}}}",
        q(&info.path_kind),
        q(&info.guid),
        info.major_version,
        info.minor_version,
        info.lcid,
        if reveal { q(&info.path) } else { "null".into() },
        if reveal {
            q(&info.display_name)
        } else {
            "null".into()
        },
    )
}
fn project_reference_info_json(
    info: Option<&crate::ovba::ParsedProjectReference>,
    reveal: bool,
) -> String {
    let Some(info) = info else {
        return "null".into();
    };
    format!(
        "{{\"project_kind\":{},\"path\":{}}}",
        q(&info.project_kind),
        if reveal { q(&info.path) } else { "null".into() },
    )
}
fn workbook_formula_references_json(references: &[WorkbookFormulaReferenceInfo]) -> String {
    let mut output = String::from("[");
    for (index, reference) in references.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        let bounds = reference
            .cell_range_bounds
            .map(|bounds| {
                format!(
                    "{{\"first_row\":{},\"first_column\":{},\"last_row\":{},\"last_column\":{}}}",
                    bounds.first_row, bounds.first_column, bounds.last_row, bounds.last_column
                )
            })
            .unwrap_or_else(|| "null".into());
        let cell_ids = format!(
            "[{}]",
            reference
                .workbook_cell_indices
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(",")
        );
        output.push_str(&format!(
            "{{\"start_byte\":{},\"end_byte\":{},\"reference\":{},\"reference_kind\":{},\"defined_name_id_candidate\":{},\"defined_name_resolution\":{},\"table_id_candidate\":{},\"table_column_id_candidate\":{},\"table_resolution\":{},\"table_section\":{},\"sheet_selector\":{},\"sheet_index_candidate\":{},\"sheet_name_candidate\":{},\"sheet_resolution\":{},\"cell_range_bounds\":{},\"workbook_cell_ids\":{},\"workbook_cell_match_count\":{},\"workbook_cell_matches_truncated\":{}}}",
            reference.start_byte,
            reference.end_byte,
            q(&reference.reference),
            q(&reference.reference_kind),
            reference
                .defined_name_index_candidate
                .map_or_else(|| "null".into(), |value| value.to_string()),
            opt_q(&reference.defined_name_resolution),
            reference
                .table_index_candidate
                .map_or_else(|| "null".into(), |value| value.to_string()),
            reference
                .table_column_index_candidate
                .map_or_else(|| "null".into(), |value| value.to_string()),
            opt_q(&reference.table_resolution),
            opt_q(&reference.table_section),
            opt_q(&reference.sheet_selector),
            reference.sheet_index_candidate.map_or_else(|| "null".into(), |value| value.to_string()),
            opt_q(&reference.sheet_name_candidate),
            q(&reference.sheet_resolution),
            bounds,
            cell_ids,
            reference.workbook_cell_indices.len(),
            reference.workbook_cell_matches_truncated
        ));
    }
    output.push(']');
    output
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

fn usize_array_json(values: &[usize]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn bool_array_json(values: &[bool]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn dot_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

use crate::pcode::{DisassembledPCodeModule, PCodeOperandValue};
use crate::stomping::{
    ProjectStompingReport, StompingFinding, StompingFindingKind, StompingSeverity,
};

/// Export disassembled P-code modules as a structured JSON string.
pub fn disasm_to_json(modules: &[DisassembledPCodeModule]) -> String {
    let mut out = String::from("{\"schema_version\":\"0.1\",\"module_count\":");
    out.push_str(&modules.len().to_string());
    out.push_str(",\"modules\":[");
    for (m_idx, m) in modules.iter().enumerate() {
        if m_idx > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"module_name\":{},\"line_count\":{},\"declared_procedures\":[",
            q(&m.module_name),
            m.lines.len()
        ));
        for (i, p) in m.declared_procedures.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&q(p));
        }
        out.push_str("],\"called_procedures\":[");
        for (i, c) in m.called_procedures.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&q(c));
        }
        out.push_str("],\"string_literals\":[");
        for (i, s) in m.string_literals.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&q(s));
        }
        out.push_str("],\"lines\":[");
        for (l_idx, line) in m.lines.iter().enumerate() {
            if l_idx > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "{{\"source_line\":{},\"instruction_count\":{},\"instructions\":[",
                line.line_number,
                line.instructions.len()
            ));
            for (i_idx, inst) in line.instructions.iter().enumerate() {
                if i_idx > 0 {
                    out.push(',');
                }
                out.push_str(&format!(
                    "{{\"offset\":{},\"opcode\":{},\"op_type\":{},\"mnemonic\":{},\"formatted\":{},\"target_name\":{},\"string_literal\":{},\"is_call\":{},\"is_branch\":{},\"jump_target\":{},\"operands\":[",
                    inst.offset,
                    inst.opcode,
                    inst.op_type,
                    q(&inst.mnemonic),
                    q(&inst.formatted),
                    opt_q(&inst.target_name),
                    opt_q(&inst.string_literal),
                    inst.is_call,
                    inst.is_branch,
                    inst.jump_target.map(|t| t.to_string()).unwrap_or_else(|| "null".into())
                ));
                for (op_idx, op) in inst.detailed_operands.iter().enumerate() {
                    if op_idx > 0 {
                        out.push(',');
                    }
                    match op {
                        PCodeOperandValue::Integer(v) => {
                            out.push_str(&format!("{{\"kind\":\"integer\",\"value\":{v}}}"));
                        }
                        PCodeOperandValue::Float(v) => {
                            out.push_str(&format!("{{\"kind\":\"float\",\"value\":{}}}", q(v)));
                        }
                        PCodeOperandValue::Date(v) => {
                            out.push_str(&format!("{{\"kind\":\"date\",\"value\":{}}}", q(v)));
                        }
                        PCodeOperandValue::Currency(v) => {
                            out.push_str(&format!("{{\"kind\":\"currency\",\"value\":{}}}", q(v)));
                        }
                        PCodeOperandValue::SpecialVariant(v) => {
                            out.push_str(&format!(
                                "{{\"kind\":\"special_variant\",\"value\":{}}}",
                                q(v)
                            ));
                        }
                        PCodeOperandValue::StringLit(v) => {
                            out.push_str(&format!(
                                "{{\"kind\":\"string_lit\",\"value\":{}}}",
                                q(v)
                            ));
                        }
                        PCodeOperandValue::NameRef(v) => {
                            out.push_str(&format!("{{\"kind\":\"name_ref\",\"value\":{}}}", q(v)));
                        }
                        PCodeOperandValue::RawWord(v) => {
                            out.push_str(&format!("{{\"kind\":\"raw_word\",\"value\":{v}}}"));
                        }
                        PCodeOperandValue::RawDword(v) => {
                            out.push_str(&format!("{{\"kind\":\"raw_dword\",\"value\":{v}}}"));
                        }
                        PCodeOperandValue::TargetAddress(v) => {
                            out.push_str(&format!("{{\"kind\":\"target_address\",\"value\":{v}}}"));
                        }
                    }
                }
                out.push_str("]}");
            }
            out.push_str("]}");
        }
        out.push_str("]}");
    }
    out.push_str("]}");
    out
}

/// Export disassembled P-code modules as a formatted Markdown report.
pub fn disasm_to_markdown(modules: &[DisassembledPCodeModule]) -> String {
    let mut out = String::from("# VBA P-Code Disassembly Report\n\n");
    for m in modules {
        out.push_str(&format!("## Module: `{}`\n\n", m.module_name));
        out.push_str(&format!(
            "- **Declared Procedures ({}):** {}\n",
            m.declared_procedures.len(),
            if m.declared_procedures.is_empty() {
                "none".into()
            } else {
                m.declared_procedures.join(", ")
            }
        ));
        out.push_str(&format!(
            "- **Called Procedures ({}):** {}\n",
            m.called_procedures.len(),
            if m.called_procedures.is_empty() {
                "none".into()
            } else {
                m.called_procedures.join(", ")
            }
        ));
        out.push_str(&format!(
            "- **String Literals ({}):** {}\n\n",
            m.string_literals.len(),
            if m.string_literals.is_empty() {
                "none".into()
            } else {
                m.string_literals
                    .iter()
                    .map(|s| format!("`\"{}\"`", s.replace('`', "'")))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        ));
        out.push_str("```vba-pcode\n");
        for line in &m.lines {
            out.push_str(&line.formatted_text);
        }
        out.push_str("```\n\n");
    }
    out
}

/// Export a VBA Stomping evaluation report as JSON.
pub fn stomping_to_json(report: &ProjectStompingReport) -> String {
    let mut out = format!(
        "{{\"schema_version\":\"0.1\",\"overall_severity\":{},\"has_stomping\":{},\"project_findings\":[",
        q(report.overall_severity.as_str()),
        report.has_stomping
    );
    for (f_idx, f) in report.project_findings.iter().enumerate() {
        if f_idx > 0 {
            out.push(',');
        }
        let kind_str = match &f.kind {
            StompingFindingKind::SourcePurged => "source_purged",
            StompingFindingKind::SourceCorruptedWithValidPCode(_) => {
                "source_corrupted_with_valid_pcode"
            }
            StompingFindingKind::ProcedureHiddenInPCode(_) => "procedure_hidden_in_pcode",
            StompingFindingKind::ProcedureMissingInPCode(_) => "procedure_missing_in_pcode",
            StompingFindingKind::SuspiciousLiteralInPCode(_) => "suspicious_literal_in_pcode",
            StompingFindingKind::SensitiveCallInPCode(_) => "sensitive_call_in_pcode",
            StompingFindingKind::LineCountDiscrepancy { .. } => "line_count_discrepancy",
            StompingFindingKind::PerformanceCachePurged { .. } => "performance_cache_purged",
            StompingFindingKind::HiddenGuiModule(_) => "hidden_gui_module",
            StompingFindingKind::ProjectLockedOrUnviewable => "project_locked_or_unviewable",
        };
        let (rule_id, _) = finding_to_sarif_rule(f);
        out.push_str(&format!(
            "{{\"severity\":{},\"kind\":{},\"rule_id\":{},\"description\":{}}}",
            q(f.severity.as_str()),
            q(kind_str),
            q(rule_id),
            q(&f.description)
        ));
    }
    out.push_str(&format!(
        "],\"module_count\":{},\"modules\":[",
        report.modules.len()
    ));
    for (m_idx, m) in report.modules.iter().enumerate() {
        if m_idx > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"module_name\":{},\"severity\":{},\"confidence_score\":{},\"is_stomped\":{},\"source_lines\":{},\"pcode_lines\":{},\"source_procedures\":{},\"pcode_procedures\":{},\"findings\":[",
            q(&m.module_name),
            q(m.severity.as_str()),
            m.confidence_score,
            m.is_stomped,
            m.source_line_count,
            m.pcode_line_count,
            m.source_procedure_count,
            m.pcode_procedure_count
        ));
        for (f_idx, f) in m.findings.iter().enumerate() {
            if f_idx > 0 {
                out.push(',');
            }
            let kind_str = match &f.kind {
                StompingFindingKind::SourcePurged => "source_purged",
                StompingFindingKind::SourceCorruptedWithValidPCode(_) => {
                    "source_corrupted_with_valid_pcode"
                }
                StompingFindingKind::ProcedureHiddenInPCode(_) => "procedure_hidden_in_pcode",
                StompingFindingKind::ProcedureMissingInPCode(_) => "procedure_missing_in_pcode",
                StompingFindingKind::SuspiciousLiteralInPCode(_) => "suspicious_literal_in_pcode",
                StompingFindingKind::SensitiveCallInPCode(_) => "sensitive_call_in_pcode",
                StompingFindingKind::LineCountDiscrepancy { .. } => "line_count_discrepancy",
                StompingFindingKind::PerformanceCachePurged { .. } => "performance_cache_purged",
                StompingFindingKind::HiddenGuiModule(_) => "hidden_gui_module",
                StompingFindingKind::ProjectLockedOrUnviewable => "project_locked_or_unviewable",
            };
            let (rule_id, _) = finding_to_sarif_rule(f);
            out.push_str(&format!(
                "{{\"severity\":{},\"kind\":{},\"rule_id\":{},\"description\":{}}}",
                q(f.severity.as_str()),
                q(kind_str),
                q(rule_id),
                q(&f.description)
            ));
        }
        out.push_str("]}");
    }
    out.push_str("]}");
    out
}

/// Helper mapping StompingFinding to SARIF rule ID and level.
fn finding_to_sarif_rule(f: &StompingFinding) -> (&'static str, &'static str) {
    let (rule_id, default_level) = match f.kind {
        StompingFindingKind::SourcePurged => ("VBA-STOMP-001", "error"),
        StompingFindingKind::ProcedureHiddenInPCode(_) => ("VBA-STOMP-002", "error"),
        StompingFindingKind::SuspiciousLiteralInPCode(_) => ("VBA-STOMP-003", "error"),
        StompingFindingKind::SensitiveCallInPCode(_) => ("VBA-STOMP-004", "error"),
        StompingFindingKind::LineCountDiscrepancy { .. } => ("VBA-STOMP-005", "warning"),
        StompingFindingKind::ProcedureMissingInPCode(_) => ("VBA-STOMP-006", "note"),
        StompingFindingKind::PerformanceCachePurged { .. } => ("VBA-STOMP-007", "warning"),
        StompingFindingKind::HiddenGuiModule(_) => ("VBA-STOMP-008", "error"),
        StompingFindingKind::ProjectLockedOrUnviewable => ("VBA-STOMP-009", "note"),
        StompingFindingKind::SourceCorruptedWithValidPCode(_) => ("VBA-STOMP-010", "error"),
    };
    let level = match f.severity {
        StompingSeverity::Critical | StompingSeverity::High => "error",
        StompingSeverity::Medium => "warning",
        StompingSeverity::Low => "note",
        StompingSeverity::Clean => default_level,
    };
    (rule_id, level)
}

/// Export a VBA Stomping evaluation report as SARIF v2.1.0 for GitHub Code Scanning and VS Code integration.
pub fn stomping_to_sarif(report: &ProjectStompingReport, file_uri: &str) -> String {
    let mut out = String::from(
        "{\"$schema\":\"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json\",\"version\":\"2.1.0\",\"runs\":[{\"tool\":{\"driver\":{\"name\":\"vba-insight\",\"version\":\"",
    );
    out.push_str(env!("CARGO_PKG_VERSION"));
    out.push_str(
        "\",\"informationUri\":\"https://github.com/ryusui-hiro/vba-retrace\",\"rules\":[",
    );
    out.push_str(
        "{\"id\":\"VBA-STOMP-001\",\"name\":\"SourcePurged\",\"shortDescription\":{\"text\":\"VBA Source Code Purged\"},\"fullDescription\":{\"text\":\"VBA source code has been completely stripped or purged while compiled P-code instructions remain executable.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-STOMP-002\",\"name\":\"ProcedureHiddenInPCode\",\"shortDescription\":{\"text\":\"Hidden Procedure in P-Code\"},\"fullDescription\":{\"text\":\"A procedure exists in the compiled P-code stream but does not appear in the VBA source text.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-STOMP-003\",\"name\":\"SuspiciousLiteralInPCode\",\"shortDescription\":{\"text\":\"Suspicious Literal in P-Code\"},\"fullDescription\":{\"text\":\"Suspicious string literal (such as URL, executable name, or command) is present in compiled P-code but absent from source code.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-STOMP-004\",\"name\":\"SensitiveCallInPCode\",\"shortDescription\":{\"text\":\"Sensitive API Call in P-Code\"},\"fullDescription\":{\"text\":\"Dangerous system API or shell execution call is found in compiled P-code but hidden from source text.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-STOMP-005\",\"name\":\"LineCountDiscrepancy\",\"shortDescription\":{\"text\":\"Line Count Discrepancy\"},\"fullDescription\":{\"text\":\"Large divergence between source code line count and compiled P-code line count.\"},\"defaultConfiguration\":{\"level\":\"warning\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-STOMP-006\",\"name\":\"ProcedureMissingInPCode\",\"shortDescription\":{\"text\":\"Procedure Missing in P-Code\"},\"fullDescription\":{\"text\":\"A procedure declared in source text is missing from the compiled P-code stream.\"},\"defaultConfiguration\":{\"level\":\"note\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-STOMP-007\",\"name\":\"PerformanceCachePurged\",\"shortDescription\":{\"text\":\"VBA Performance Cache Purged\"},\"fullDescription\":{\"text\":\"Compiled P-code performance cache has been wiped or omitted while source code procedures remain, indicating potential VBA Purging evasion.\"},\"defaultConfiguration\":{\"level\":\"warning\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-STOMP-008\",\"name\":\"HiddenGuiModule\",\"shortDescription\":{\"text\":\"Module Hidden from VBA GUI\"},\"fullDescription\":{\"text\":\"Module is present in dir stream and compiled for execution but omitted from PROJECT stream manifest, making it invisible in the Office VBA GUI (Evil Clippy technique).\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-STOMP-009\",\"name\":\"ProjectLockedOrUnviewable\",\"shortDescription\":{\"text\":\"Project Locked or Unviewable\"},\"fullDescription\":{\"text\":\"VBA project contains protection/lock attributes (CMG/DPB/GC) making the macro unviewable or password-protected in the VBA IDE.\"},\"defaultConfiguration\":{\"level\":\"note\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-STOMP-010\",\"name\":\"SourceCorruptedWithValidPCode\",\"shortDescription\":{\"text\":\"Corrupted Source Container with Executable P-Code\"},\"fullDescription\":{\"text\":\"Module source code container failed decompression or is malformed while executable compiled P-code remains, indicating anti-analysis stomping evasion.\"},\"defaultConfiguration\":{\"level\":\"error\"}}"
    );
    out.push_str("]}},\"artifacts\":[{\"location\":{\"uri\":");
    out.push_str(&q(file_uri));
    out.push_str("}}],\"results\":[");

    let mut first_result = true;
    for f in &report.project_findings {
        if !first_result {
            out.push(',');
        }
        first_result = false;
        let (rule_id, level) = finding_to_sarif_rule(f);
        out.push_str(&format!(
            "{{\"ruleId\":{},\"level\":{},\"message\":{{\"text\":{}}},\"locations\":[{{\"physicalLocation\":{{\"artifactLocation\":{{\"uri\":{}}}}},\"logicalLocations\":[{{\"name\":\"PROJECT\",\"kind\":\"project\"}}]}}]}}",
            q(rule_id),
            q(level),
            q(&f.description),
            q(file_uri)
        ));
    }
    for m in &report.modules {
        for f in &m.findings {
            if !first_result {
                out.push(',');
            }
            first_result = false;
            let (rule_id, level) = finding_to_sarif_rule(f);
            out.push_str(&format!(
                "{{\"ruleId\":{},\"level\":{},\"message\":{{\"text\":{}}},\"locations\":[{{\"physicalLocation\":{{\"artifactLocation\":{{\"uri\":{}}}}},\"logicalLocations\":[{{\"name\":{},\"kind\":\"module\"}}]}}]}}",
                q(rule_id),
                q(level),
                q(&f.description),
                q(file_uri),
                q(&m.module_name)
            ));
        }
    }

    out.push_str("]}]}");
    out
}

/// Export a VBA Stomping evaluation report as a GitHub-flavored Markdown document.
pub fn stomping_to_markdown(report: &ProjectStompingReport) -> String {
    let mut out = String::from("# VBA Stomping & Tampering Inspection Report\n\n");
    let badge = match report.overall_severity {
        StompingSeverity::Clean => "🟢 **CLEAN**",
        StompingSeverity::Low => "🔵 **LOW RISK**",
        StompingSeverity::Medium => "🟡 **MEDIUM RISK**",
        StompingSeverity::High => "🟠 **HIGH RISK (LIKELY STOMPED)**",
        StompingSeverity::Critical => "🔴 **CRITICAL (STOMPED / TAMPERED)**",
    };
    out.push_str(&format!("- **Overall Assessment:** {}\n", badge));
    out.push_str(&format!(
        "- **Tampering Detected:** {}\n",
        if report.has_stomping { "YES" } else { "NO" }
    ));
    out.push_str(&format!(
        "- **Total Modules Inspected:** {}\n\n",
        report.modules.len()
    ));

    if !report.project_findings.is_empty() {
        out.push_str("### Project-Level Indicators\n\n");
        for f in &report.project_findings {
            let icon = match f.severity {
                StompingSeverity::Critical => "🔴",
                StompingSeverity::High => "🟠",
                StompingSeverity::Medium => "🟡",
                _ => "ℹ️",
            };
            out.push_str(&format!(
                "- {} **[{}]** {}\n",
                icon,
                f.severity.as_str().to_ascii_uppercase(),
                f.description
            ));
        }
        out.push('\n');
    }

    out.push_str("| Module Name | Severity | Score | Source Lines | P-Code Lines | Findings |\n");
    out.push_str("| :--- | :--- | :--- | :--- | :--- | :--- |\n");
    for m in &report.modules {
        let m_badge = match m.severity {
            StompingSeverity::Clean => "🟢 Clean",
            StompingSeverity::Low => "🔵 Low",
            StompingSeverity::Medium => "🟡 Medium",
            StompingSeverity::High => "🟠 High",
            StompingSeverity::Critical => "🔴 Critical",
        };
        out.push_str(&format!(
            "| `{}` | {} | {}% | {} | {} | {} |\n",
            m.module_name,
            m_badge,
            m.confidence_score,
            m.source_line_count,
            m.pcode_line_count,
            m.findings.len()
        ));
    }
    out.push('\n');

    let all_findings: Vec<(&str, &StompingFinding)> = report
        .modules
        .iter()
        .flat_map(|m| m.findings.iter().map(move |f| (m.module_name.as_str(), f)))
        .collect();

    if !all_findings.is_empty() {
        out.push_str("### Detailed Findings\n\n");
        for (m_name, f) in all_findings {
            let icon = match f.severity {
                StompingSeverity::Critical => "🔴",
                StompingSeverity::High => "🟠",
                StompingSeverity::Medium => "🟡",
                _ => "ℹ️",
            };
            out.push_str(&format!(
                "- {} **[{}]** [`{}`] {}\n",
                icon,
                f.severity.as_str().to_ascii_uppercase(),
                m_name,
                f.description
            ));
        }
        out.push('\n');
    }

    out
}

/// Export a ComprehensiveInspection as a consolidated JSON string.
pub fn inspect_to_json(
    inspection: &crate::ComprehensiveInspection,
    disclosure: Disclosure,
) -> String {
    let mut out = format!(
        "{{\"schema_version\":\"0.1\",\"project_name\":{},\"analysis\":",
        q(inspection.extracted.name.as_deref().unwrap_or(""))
    );
    out.push_str(&to_json(
        &inspection.analysis,
        Some(&inspection.extracted),
        disclosure,
    ));
    out.push_str(",\"stomping\":");
    out.push_str(&stomping_to_json(&inspection.stomping_report));
    out.push_str(",\"pcode\":");
    out.push_str(&disasm_to_json(&inspection.pcode_disassembly));
    out.push('}');
    out
}

/// Export a ComprehensiveInspection as a comprehensive Markdown report.
pub fn inspect_to_markdown(inspection: &crate::ComprehensiveInspection) -> String {
    let mut out = String::from("# Comprehensive Macro Container Inspection\n\n");
    out.push_str(&format!(
        "- **Project Name:** `{}`\n",
        inspection.extracted.name.as_deref().unwrap_or("unnamed")
    ));
    out.push_str(&format!(
        "- **Input Kind:** `{}`\n",
        inspection.analysis.project.input_kind
    ));
    out.push_str(&format!(
        "- **Modules:** {}\n",
        inspection.extracted.modules.len()
    ));
    out.push_str(&format!(
        "- **Cell Threats:** {}\n",
        inspection.extracted.cell_threats.len()
    ));
    out.push_str(&format!(
        "- **Stomping Severity:** `{}`\n\n",
        inspection.stomping_report.overall_severity.as_str()
    ));

    if !inspection.extracted.cell_threats.is_empty() {
        out.push_str("## Worksheet & Cell Threats\n\n");
        out.push_str("| Coordinate | Threat Kind | Severity | Description |\n");
        out.push_str("|---|---|---|---|\n");
        for threat in &inspection.extracted.cell_threats {
            out.push_str(&format!(
                "| `{}` | `{}` | `{}` | {} |\n",
                threat.coordinate, threat.threat_kind, threat.severity, threat.description
            ));
        }
        out.push('\n');
    }

    out.push_str(&stomping_to_markdown(&inspection.stomping_report));
    out.push_str(&disasm_to_markdown(&inspection.pcode_disassembly));
    out
}

fn cell_threat_to_sarif_rule(threat: &crate::extract::CellThreat) -> (&'static str, &'static str) {
    let (rule_id, default_level) = match threat.threat_kind.as_str() {
        "DDE" => ("VBA-CELL-001", "error"),
        "XLM" => ("VBA-CELL-002", "error"),
        "RemoteLink" => ("VBA-CELL-003", "warning"),
        "WebService" => ("VBA-CELL-004", "warning"),
        "SuspiciousHyperlink" => ("VBA-CELL-005", "warning"),
        "AutoExecDefinedName" => ("VBA-CELL-006", "warning"),
        "VeryHiddenSheet" => ("VBA-CELL-007", "note"),
        "XlmMacroSheet" => ("VBA-CELL-008", "error"),
        "DeobfuscatedThreat" => ("VBA-CELL-009", "error"),
        "RemoteTemplateInjection" => ("VBA-CELL-010", "error"),
        "EmbeddedOlePackage" => ("VBA-CELL-011", "error"),
        "ExternalOleObject" => ("VBA-CELL-012", "error"),
        "ActiveXControl" => ("VBA-CELL-013", "warning"),
        "ExternalSubdocument" => ("VBA-CELL-014", "error"),
        "SuspiciousPrinterSettings" => ("VBA-CELL-015", "error"),
        "CustomXmlPayloadSmuggling" => ("VBA-CELL-016", "error"),
        "SuspiciousProtocolHandler" => ("VBA-CELL-017", "error"),
        "SuspiciousDrawingAction" => ("VBA-CELL-018", "error"),
        "ExternalDataConnection" => ("VBA-CELL-019", "error"),
        "RealTimeData" => ("VBA-CELL-020", "error"),
        "SuspiciousSvgVector" => ("VBA-CELL-021", "error"),
        "TamperedVbaProjectSignature" => ("VBA-CELL-022", "error"),
        "WordFieldCode" => ("VBA-CELL-023", "error"),
        "PowerPointSlideAction" => ("VBA-CELL-024", "error"),
        "SuspiciousAltChunk" => ("VBA-CELL-025", "error"),
        "CustomUiRibbon" => ("VBA-CELL-026", "error"),
        "LegacyDialogSheet" => ("VBA-CELL-027", "error"),
        "ContentTypeAnomaly" => ("VBA-CELL-028", "error"),
        "ExternalLinkTarget" => ("VBA-CELL-029", "error"),
        "WebSettingsScriptOrReload" => ("VBA-CELL-030", "error"),
        "WorkbookProtectionEvasion" => ("VBA-CELL-031", "error"),
        "SmuggledContainerPayload" => ("VBA-CELL-032", "error"),
        "WorksheetViewEvasion" => ("VBA-CELL-033", "warning"),
        "ActiveXObjectDeclaration" => ("VBA-CELL-034", "error"),
        "GlossaryDocumentAnomaly" => ("VBA-CELL-035", "error"),
        "EmbeddedFontObfuscation" | "EmbeddedFontSmuggling" => ("VBA-CELL-036", "error"),
        "DigitalInkDefinitionAnomaly" | "DigitalInkActionAnomaly" => ("VBA-CELL-037", "error"),
        "DocumentPropertyPayloadSmuggling" | "DocumentPropertyAnomaly" => ("VBA-CELL-038", "error"),
        "WebExtensionOrTaskpaneAnomaly" | "WebExtensionAnomaly" | "TaskpaneAnomaly" => {
            ("VBA-CELL-039", "error")
        }
        "PivotCacheDataConnectionAnomaly" | "PivotCacheAnomaly" => ("VBA-CELL-040", "error"),
        "MetafileExploitOrPayloadSmuggling" | "MetafileExploit" => ("VBA-CELL-041", "error"),
        "XsltTransformOrScriptInjection" | "XsltTransformAnomaly" => ("VBA-CELL-042", "error"),
        "RelationshipTargetCloakingOrEvasion" | "RelationshipCloakingAnomaly" => {
            ("VBA-CELL-043", "error")
        }
        "SmartArtOrDiagramPayloadAnomaly" | "SmartArtAnomaly" | "DiagramPayloadAnomaly" => {
            ("VBA-CELL-044", "error")
        }
        "MailMergeDataSourceOrCoercionAnomaly" | "MailMergeAnomaly" => ("VBA-CELL-045", "error"),
        "QueryTableOrExternalQueryAnomaly" | "QueryTableAnomaly" => ("VBA-CELL-046", "error"),
        "PowerQueryFormulaOrMashupAnomaly" | "PowerQueryAnomaly" | "MashupAnomaly" => {
            ("VBA-CELL-047", "error")
        }
        "PackageMonikerOrActivationAnomaly" | "PackageMonikerAnomaly" | "MonikerAnomaly" => {
            ("VBA-CELL-048", "error")
        }
        "NamespaceCloakingOrSchemaSpoofingAnomaly"
        | "NamespaceCloakingAnomaly"
        | "SchemaSpoofingAnomaly" => ("VBA-CELL-049", "error"),
        "SlicerOrTimelineCacheAnomaly" | "SlicerAnomaly" | "TimelineAnomaly" => {
            ("VBA-CELL-050", "error")
        }
        "BibliographyOrCitationAnomaly" | "BibliographyAnomaly" | "CitationAnomaly" => {
            ("VBA-CELL-051", "error")
        }
        "CustomXmlDataBindingOrXPathAnomaly" | "CustomXmlDataBindingAnomaly" | "XPathAnomaly" => {
            ("VBA-CELL-052", "error")
        }
        "XmlMapsOrSchemaDefinitionAnomaly" | "XmlMapAnomaly" | "XmlMapsAnomaly" => {
            ("VBA-CELL-053", "error")
        }
        "CommentAnnotationOrAuthorAnomaly" | "CommentAnomaly" | "ThreadedCommentAnomaly" => {
            ("VBA-CELL-054", "error")
        }
        "ThemeFontOrEffectCoercionAnomaly" | "ThemeAnomaly" | "ThemeFontAnomaly" => {
            ("VBA-CELL-055", "error")
        }
        "CustomXmlPropertiesOrItemSchemaAnomaly"
        | "CustomXmlPropertyAnomaly"
        | "CustomXmlPropAnomaly" => ("VBA-CELL-056", "error"),
        "VbaDataStreamOrProjectRelsAnomaly" | "VbaProjectRelsAnomaly" | "VbaDataAnomaly" => {
            ("VBA-CELL-057", "error")
        }
        "WordGlossaryOrBuildingBlocksRelsAnomaly"
        | "GlossaryRelsAnomaly"
        | "BuildingBlocksAnomaly" => ("VBA-CELL-058", "error"),
        "WordDocVariablesOrNotesAnomaly"
        | "WordDocVarsAnomaly"
        | "DocVariablesAnomaly"
        | "FootnotesEndnotesAnomaly" => ("VBA-CELL-059", "error"),
        "PowerPointTagsOrMastersAnomaly"
        | "PowerPointTagsAnomaly"
        | "PptTagsAnomaly"
        | "PptMastersAnomaly" => ("VBA-CELL-060", "error"),
        "ScenarioManagerOrConsolidationAnomaly"
        | "ScenarioManagerAnomaly"
        | "DataConsolidationAnomaly" => ("VBA-CELL-061", "error"),
        "PowerPointAnimationOrTimeNodeAnomaly"
        | "PowerPointAnimationAnomaly"
        | "PptAnimationAnomaly"
        | "TimeNodeAnomaly" => ("VBA-CELL-062", "error"),
        "WordHeaderFooterOrWatermarkAnomaly"
        | "WordHeaderFooterAnomaly"
        | "HeaderFooterAnomaly"
        | "WatermarkAnomaly" => ("VBA-CELL-063", "error"),
        "ExcelDataModelOrFormulaCacheAnomaly"
        | "ExcelDataModelAnomaly"
        | "DataModelAnomaly"
        | "FormulaCacheAnomaly" => ("VBA-CELL-064", "error"),
        "ExcelPivotCacheOrDefinitionAnomaly"
        | "ExcelPivotCacheDefinitionAnomaly"
        | "PivotCacheDefinitionAnomaly"
        | "PivotTableDefinitionAnomaly" => ("VBA-CELL-065", "error"),
        "WordOrPowerPointEmbeddedPackageAnomaly"
        | "WordEmbeddedPackageAnomaly"
        | "PowerPointEmbeddedPackageAnomaly"
        | "EmbeddedPackageAnomaly" => ("VBA-CELL-066", "error"),
        "ExcelExternalBookOrSheetPathAnomaly"
        | "ExcelExternalBookAnomaly"
        | "ExternalBookAnomaly"
        | "SheetPathAnomaly" => ("VBA-CELL-067", "error"),
        _ => ("VBA-CELL-001", "warning"),
    };
    let level = match threat.severity.as_str() {
        "Critical" | "High" => "error",
        "Medium" => "warning",
        "Low" => "note",
        _ => default_level,
    };
    (rule_id, level)
}

/// Export a ComprehensiveInspection as SARIF v2.1.0 for GitHub Code Scanning and VS Code integration,
/// containing both VBA Stomping and Worksheet Cell Threat findings.
pub fn inspection_to_sarif(inspection: &crate::ComprehensiveInspection, file_uri: &str) -> String {
    let mut out = String::from(
        "{\"$schema\":\"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json\",\"version\":\"2.1.0\",\"runs\":[{\"tool\":{\"driver\":{\"name\":\"vba-insight\",\"version\":\"",
    );
    out.push_str(env!("CARGO_PKG_VERSION"));
    out.push_str(
        "\",\"informationUri\":\"https://github.com/ryusui-hiro/vba-retrace\",\"rules\":[",
    );
    out.push_str(
        "{\"id\":\"VBA-STOMP-001\",\"name\":\"SourcePurged\",\"shortDescription\":{\"text\":\"VBA Source Code Purged\"},\"fullDescription\":{\"text\":\"VBA source code has been completely stripped or purged while compiled P-code instructions remain executable.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-STOMP-002\",\"name\":\"ProcedureHiddenInPCode\",\"shortDescription\":{\"text\":\"Hidden Procedure in P-Code\"},\"fullDescription\":{\"text\":\"A procedure exists in the compiled P-code stream but does not appear in the VBA source text.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-STOMP-003\",\"name\":\"SuspiciousLiteralInPCode\",\"shortDescription\":{\"text\":\"Suspicious Literal in P-Code\"},\"fullDescription\":{\"text\":\"Suspicious string literal (such as URL, executable name, or command) is present in compiled P-code but absent from source code.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-STOMP-004\",\"name\":\"SensitiveCallInPCode\",\"shortDescription\":{\"text\":\"Sensitive API Call in P-Code\"},\"fullDescription\":{\"text\":\"Dangerous system API or shell execution call is found in compiled P-code but hidden from source text.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-STOMP-005\",\"name\":\"LineCountDiscrepancy\",\"shortDescription\":{\"text\":\"Line Count Discrepancy\"},\"fullDescription\":{\"text\":\"Large divergence between source code line count and compiled P-code line count.\"},\"defaultConfiguration\":{\"level\":\"warning\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-STOMP-006\",\"name\":\"ProcedureMissingInPCode\",\"shortDescription\":{\"text\":\"Procedure Missing in P-Code\"},\"fullDescription\":{\"text\":\"A procedure declared in source text is missing from the compiled P-code stream.\"},\"defaultConfiguration\":{\"level\":\"note\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-STOMP-007\",\"name\":\"PerformanceCachePurged\",\"shortDescription\":{\"text\":\"VBA Performance Cache Purged\"},\"fullDescription\":{\"text\":\"Compiled P-code performance cache has been wiped or omitted while source code procedures remain, indicating potential VBA Purging evasion.\"},\"defaultConfiguration\":{\"level\":\"warning\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-STOMP-008\",\"name\":\"HiddenGuiModule\",\"shortDescription\":{\"text\":\"Module Hidden from VBA GUI\"},\"fullDescription\":{\"text\":\"Module is present in dir stream and compiled for execution but omitted from PROJECT stream manifest, making it invisible in the Office VBA GUI (Evil Clippy technique).\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-STOMP-009\",\"name\":\"ProjectLockedOrUnviewable\",\"shortDescription\":{\"text\":\"Project Locked or Unviewable\"},\"fullDescription\":{\"text\":\"VBA project contains protection/lock attributes (CMG/DPB/GC) making the macro unviewable or password-protected in the VBA IDE.\"},\"defaultConfiguration\":{\"level\":\"note\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-STOMP-010\",\"name\":\"SourceCorruptedWithValidPCode\",\"shortDescription\":{\"text\":\"Corrupted Source Container with Executable P-Code\"},\"fullDescription\":{\"text\":\"Module source code container failed decompression or is malformed while executable compiled P-code remains, indicating anti-analysis stomping evasion.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-001\",\"name\":\"DDEExecutionFormula\",\"shortDescription\":{\"text\":\"Dynamic Data Exchange (DDE) Formula Execution\"},\"fullDescription\":{\"text\":\"Worksheet cell or defined name contains a formula executing commands via Dynamic Data Exchange (DDE).\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-002\",\"name\":\"XlmMacroExecutionFormula\",\"shortDescription\":{\"text\":\"Excel 4.0 (XLM) Macro Formula Execution\"},\"fullDescription\":{\"text\":\"Worksheet cell or defined name contains an Excel 4.0 macro expression executing code or launching processes.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-003\",\"name\":\"RemoteWorkbookLink\",\"shortDescription\":{\"text\":\"Remote Workbook Link Injection\"},\"fullDescription\":{\"text\":\"Worksheet cell formula references remote external workbook paths over UNC or HTTP/HTTPS.\"},\"defaultConfiguration\":{\"level\":\"warning\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-004\",\"name\":\"DataExfiltrationFormula\",\"shortDescription\":{\"text\":\"External Web Service / Exfiltration Formula\"},\"fullDescription\":{\"text\":\"Worksheet cell uses WEBSERVICE or FILTERXML to transmit or fetch data externally.\"},\"defaultConfiguration\":{\"level\":\"warning\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-005\",\"name\":\"SuspiciousDownloadHyperlink\",\"shortDescription\":{\"text\":\"Suspicious Download Hyperlink or Protocol Handler\"},\"fullDescription\":{\"text\":\"Worksheet HYPERLINK points to an executable, script, archive, or custom protocol handler.\"},\"defaultConfiguration\":{\"level\":\"warning\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-006\",\"name\":\"AutoExecDefinedName\",\"shortDescription\":{\"text\":\"Auto-Execution Defined Name\"},\"fullDescription\":{\"text\":\"Workbook defined name (such as Auto_Open or Auto_Close) triggers automatic macro execution.\"},\"defaultConfiguration\":{\"level\":\"warning\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-007\",\"name\":\"VeryHiddenWorksheet\",\"shortDescription\":{\"text\":\"VeryHidden Worksheet Cloaking\"},\"fullDescription\":{\"text\":\"Worksheet visibility is set to veryHidden to cloak malicious content from standard Excel UI.\"},\"defaultConfiguration\":{\"level\":\"note\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-008\",\"name\":\"XlmMacroSheetPresent\",\"shortDescription\":{\"text\":\"Excel 4.0 (XLM) Macro Sheet Present\"},\"fullDescription\":{\"text\":\"Workbook contains legacy Excel 4.0 macro sheet, frequently used in malware payloads.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-009\",\"name\":\"DeobfuscatedThreatFormula\",\"shortDescription\":{\"text\":\"De-obfuscated Threat Formula\"},\"fullDescription\":{\"text\":\"Formula obfuscation (CHAR, CONCATENATE, string substitution) resolves dynamically to an executable, command, or DDE payload.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-010\",\"name\":\"RemoteTemplateInjection\",\"shortDescription\":{\"text\":\"Remote Template Injection\"},\"fullDescription\":{\"text\":\"Relationship links to an external template over HTTP/HTTPS/SMB, allowing remote malicious template execution.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-011\",\"name\":\"EmbeddedOlePackage\",\"shortDescription\":{\"text\":\"Embedded OLE Object or Package\"},\"fullDescription\":{\"text\":\"Container package contains embedded OLE binary or packager payload in embeddings/.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-012\",\"name\":\"ExternalOleObject\",\"shortDescription\":{\"text\":\"External OLE Object Link\"},\"fullDescription\":{\"text\":\"Relationship links to an external OLE object over HTTP/HTTPS/SMB, enabling remote Moniker or exploit execution.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-013\",\"name\":\"ActiveXControlPresent\",\"shortDescription\":{\"text\":\"Embedded ActiveX Control Present\"},\"fullDescription\":{\"text\":\"Container package contains embedded ActiveX control binary in activex/.\"},\"defaultConfiguration\":{\"level\":\"warning\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-014\",\"name\":\"ExternalSubdocumentReference\",\"shortDescription\":{\"text\":\"External Subdocument or Frame Reference\"},\"fullDescription\":{\"text\":\"Relationship links to an external subdocument or frame over HTTP/HTTPS/SMB.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-015\",\"name\":\"SuspiciousPrinterSettings\",\"shortDescription\":{\"text\":\"Suspicious Printer Settings (NTLM Coercion / UNC Injection)\"},\"fullDescription\":{\"text\":\"Printer settings binary or relationship contains remote UNC paths, external URLs, or executable commands (NTLM relay / CVE-2023-36884 vector).\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-016\",\"name\":\"CustomXmlPayloadSmuggling\",\"shortDescription\":{\"text\":\"Custom XML Part Payload Smuggling\"},\"fullDescription\":{\"text\":\"Container custom XML part contains smuggled base64 executables, script tags, XXE external entities, or exploit protocol handlers.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-017\",\"name\":\"SuspiciousProtocolHandler\",\"shortDescription\":{\"text\":\"Suspicious Protocol Handler / URI Exploit Target\"},\"fullDescription\":{\"text\":\"Package relationship links to dangerous protocol handlers such as ms-msdt (Follina), search-ms, ms-appinstaller, or mhtml.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-018\",\"name\":\"SuspiciousDrawingAction\",\"shortDescription\":{\"text\":\"Suspicious Drawing or Shape Action / Macro Trigger\"},\"fullDescription\":{\"text\":\"Drawing shape, slide action, or VML form control is configured with mouse-over hover triggers, executable program launches, or auto-macro execution.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-019\",\"name\":\"ExternalDataConnection\",\"shortDescription\":{\"text\":\"External Data Connection / NTLM Coercion / Web Query\"},\"fullDescription\":{\"text\":\"Container connections, query tables, or MailMerge settings contain remote UNC paths (NTLM credential coercion), web queries, or command injection.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-020\",\"name\":\"RealTimeDataExecution\",\"shortDescription\":{\"text\":\"Real-Time Data (RTD) COM Automation Formula\"},\"fullDescription\":{\"text\":\"Worksheet cell or defined name contains an RTD formula to invoke COM automation servers or execute commands via external ProgIDs or remote DCOM servers.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-021\",\"name\":\"SuspiciousSvgVector\",\"shortDescription\":{\"text\":\"Suspicious SVG Vector Graphic (Embedded Script / XXE / Protocol Exploit)\"},\"fullDescription\":{\"text\":\"Container SVG vector graphic part contains embedded script tags, inline event handlers, XML external entity injection, or dangerous protocol handlers.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-022\",\"name\":\"TamperedVbaProjectSignature\",\"shortDescription\":{\"text\":\"Tampered, Corrupted, or Stripped VBA Project Digital Signature\"},\"fullDescription\":{\"text\":\"VBA project digital signature binary is truncated, missing valid PKCS#7 structures, hollowed with dummy padding, or referenced by dangling relationships.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-023\",\"name\":\"WordFieldCodeExecution\",\"shortDescription\":{\"text\":\"Suspicious Word Field Code (DDE / INCLUDETEXT / Remote Injection)\"},\"fullDescription\":{\"text\":\"Word document part contains suspicious field codes executing commands via DDE/DDEAUTO, downloading remote documents via INCLUDETEXT/LINK, or coercing credentials via UNC paths.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-024\",\"name\":\"PowerPointSlideAction\",\"shortDescription\":{\"text\":\"Suspicious PowerPoint Slide Action or Hover Trigger\"},\"fullDescription\":{\"text\":\"PowerPoint slide or layout contains clickable or mouse-over hover action triggers executing programs, macros, or linking to executable files.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-025\",\"name\":\"SuspiciousAltChunkPayload\",\"shortDescription\":{\"text\":\"Suspicious Alternative Format Chunk (AltChunk / HTML Smuggling)\"},\"fullDescription\":{\"text\":\"Word alternative format import chunk (AltChunk) references external remote templates or contains smuggled HTML, scripts, RTF exploits, or PE headers.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-026\",\"name\":\"CustomUiRibbonCallback\",\"shortDescription\":{\"text\":\"Custom UI Ribbon Callback Auto-Execution\"},\"fullDescription\":{\"text\":\"Office Custom UI Ribbon XML (customUI.xml) contains onLoad automatic execution callback or onAction macro controls triggered upon document open or UI interaction.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-027\",\"name\":\"LegacyDialogSheetMacro\",\"shortDescription\":{\"text\":\"Legacy Excel 5.0/95 Dialog Sheet Macro\"},\"fullDescription\":{\"text\":\"Workbook contains legacy Excel 5.0/95 dialog sheet (xl/dialogsheets/sheet*.xml) with embedded macro bindings (<x:FmlaMacro>) or dialog controls.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-028\",\"name\":\"ContentTypeAnomaly\",\"shortDescription\":{\"text\":\"Content Types Package Anomaly or MIME Spoofing\"},\"fullDescription\":{\"text\":\"[Content_Types].xml contains dangerous executable MIME types, path traversal part names, or extension spoofing (cloaking vbaProject or macrosheets under image/innocuous extensions).\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-029\",\"name\":\"ExternalLinkTargetAnomaly\",\"shortDescription\":{\"text\":\"External Link Target Anomaly or Remote Payload\"},\"fullDescription\":{\"text\":\"Workbook external link cache or relationship (xl/externalLinks/) references remote UNC paths, dangerous executable files, exploit protocols, or hidden DDE/OLE server links.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-030\",\"name\":\"WebSettingsScriptOrReload\",\"shortDescription\":{\"text\":\"Web Settings Remote Frameset or Script Injection\"},\"fullDescription\":{\"text\":\"Document web settings (word/webSettings.xml) contains suspicious remote framesets, frame injections, or script/exploit protocol targets triggered during web layout rendering.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-031\",\"name\":\"WorkbookProtectionEvasion\",\"shortDescription\":{\"text\":\"Workbook Protection Evasion or VeryHidden Sheet Cloaking\"},\"fullDescription\":{\"text\":\"Workbook contains cloaked worksheets (state=\\\"veryHidden\\\"), workbook structure lock evasion, or anomalous password protection hashes designed to impede analysis.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-032\",\"name\":\"SmuggledContainerPayload\",\"shortDescription\":{\"text\":\"Smuggled Container Payload or Executable Binary\"},\"fullDescription\":{\"text\":\"OOXML container package contains standalone executable files (.exe, .dll, .bat, .ps1, .lnk, .iso, etc.), raw Windows PE binaries, or smuggled staging scripts.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-033\",\"name\":\"WorksheetViewEvasion\",\"shortDescription\":{\"text\":\"Worksheet View Evasion or Hidden Formula Cloaking\"},\"fullDescription\":{\"text\":\"Worksheet contains formulas cloaked in hidden rows or columns, extreme viewport scrolling (topLeftCell), or display header suppression to evade visual inspection.\"},\"defaultConfiguration\":{\"level\":\"warning\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-034\",\"name\":\"ActiveXObjectDeclarationAnomaly\",\"shortDescription\":{\"text\":\"ActiveX Object Declaration Anomaly or Weaponized CLSID\"},\"fullDescription\":{\"text\":\"ActiveX definition XML part (activeX*.xml) registers weaponized ActiveX CLSIDs (WScript.Shell, Equation Editor, Shell.Explorer, ADODB.Stream, Scriptlet.TypeLib) or properties with remote UNC/URL targets.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-035\",\"name\":\"GlossaryDocumentAnomaly\",\"shortDescription\":{\"text\":\"Glossary Document Payload or External Relationship Anomaly\"},\"fullDescription\":{\"text\":\"Word glossary document tree (word/glossary/) contains external template injection, DDE/command field codes, dangerous URI protocols, or smuggled AltChunk payloads.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-036\",\"name\":\"EmbeddedFontObfuscationOrSmuggling\",\"shortDescription\":{\"text\":\"Embedded Font Obfuscation or Payload Smuggling\"},\"fullDescription\":{\"text\":\"Package font table or embedded font streams contain external UNC/HTTP links for credential coercion, or smuggled executable PE/script binaries cloaked within obfuscated font streams.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-037\",\"name\":\"DigitalInkDefinitionAnomaly\",\"shortDescription\":{\"text\":\"Digital Ink Definition Anomaly or Action Trigger\"},\"fullDescription\":{\"text\":\"Digital Ink annotations (ink*.xml, ink*.bin) contain hidden click/hover action triggers, external UNC/web targets, or embedded OLE/COM binary payloads.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-038\",\"name\":\"DocumentPropertyPayloadSmuggling\",\"shortDescription\":{\"text\":\"Document Property Payload Smuggling or Staged Script\"},\"fullDescription\":{\"text\":\"Document properties (docProps/core.xml, custom.xml, app.xml) contain smuggled Base64 Windows PE binaries, shell execution commands, dangerous protocol schemes, or remote UNC paths.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-039\",\"name\":\"WebExtensionOrTaskpaneAnomaly\",\"shortDescription\":{\"text\":\"Web Extension or Taskpane Auto-Show Anomaly\"},\"fullDescription\":{\"text\":\"Office Web Add-in or Taskpane (webextensions/, taskpanes/) defines auto-show triggers (canAutoShow/visible), remote external web targets, dangerous URI schemes, or embedded script code.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-040\",\"name\":\"PivotCacheDataConnectionAnomaly\",\"shortDescription\":{\"text\":\"PivotCache Data Connection Anomaly or Command Injection\"},\"fullDescription\":{\"text\":\"Workbook PivotCache definition (xl/pivotCache/) contains external UNC connection paths for NTLM credential coercion, database shell execution commands (xp_cmdshell), or dangerous URI schemes.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-041\",\"name\":\"MetafileExploitOrPayloadSmuggling\",\"shortDescription\":{\"text\":\"Metafile Exploit or Payload Smuggling\"},\"fullDescription\":{\"text\":\"Windows Metafile (WMF/EMF) contains CVE-2005-4560 META_SETABORTPROC exploit records, embedded Windows PE executables, Windows Shell Links (.lnk), or embedded shell commands.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-042\",\"name\":\"XsltTransformOrScriptInjection\",\"shortDescription\":{\"text\":\"XSLT Transform or Script Injection\"},\"fullDescription\":{\"text\":\"XML part or stylesheet contains executable MSXSL script elements, external saveThroughXslt transform targets, dangerous document() SSRF/NTLM coercion functions, or Windows Shell automation objects.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-043\",\"name\":\"RelationshipTargetCloakingOrEvasion\",\"shortDescription\":{\"text\":\"Relationship Target Cloaking or Evasion\"},\"fullDescription\":{\"text\":\"Relationship Target contains evasion characters (null bytes or Unicode bidirectional overrides), percent-encoded dangerous URI schemes, or local IPC named pipe / loopback coercion targets.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-044\",\"name\":\"SmartArtOrDiagramPayloadAnomaly\",\"shortDescription\":{\"text\":\"SmartArt or Diagram Payload or Action Anomaly\"},\"fullDescription\":{\"text\":\"SmartArt diagram parts or relationships contain interactive click/hover actions, dangerous URI protocol handlers, remote UNC paths, or embedded executable/command payloads.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-045\",\"name\":\"MailMergeDataSourceOrCoercionAnomaly\",\"shortDescription\":{\"text\":\"Word MailMerge Data Source or Coercion Anomaly\"},\"fullDescription\":{\"text\":\"Word MailMerge settings (word/settings.xml) or relationships contain remote UNC paths for NTLM credential coercion, database command injection queries, or dangerous external data source targets.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-046\",\"name\":\"QueryTableOrExternalQueryAnomaly\",\"shortDescription\":{\"text\":\"Excel QueryTable or External Query Anomaly\"},\"fullDescription\":{\"text\":\"Excel QueryTable definition or relationships contain automatic refresh to remote Web Queries (.iqy), UNC credential coercion paths, or database command execution.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-047\",\"name\":\"PowerQueryFormulaOrMashupAnomaly\",\"shortDescription\":{\"text\":\"Excel Power Query Formula or Mashup Anomaly\"},\"fullDescription\":{\"text\":\"Excel Power Query M formulas or Data Mashup parts contain Web.Page arbitrary HTML/script execution, Web.Contents exfiltration, remote UNC paths, database command execution, or smuggled Base64 executable binaries.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-048\",\"name\":\"PackageMonikerOrActivationAnomaly\",\"shortDescription\":{\"text\":\"OLE Package Moniker or Activation Anomaly\"},\"fullDescription\":{\"text\":\"OLE object or package relationship specifies dangerous Moniker protocol handlers, automatic silent activation, deceptive icon aspect cloaking, or weaponized Packager CLSIDs.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-049\",\"name\":\"NamespaceCloakingOrSchemaSpoofingAnomaly\",\"shortDescription\":{\"text\":\"XML Namespace Cloaking or Schema Spoofing Anomaly\"},\"fullDescription\":{\"text\":\"XML package parts declare remote UNC namespaces for NTLM credential coercion, DTD/XXE entity declarations, or Unicode homoglyph/zero-width character cloaking spoofing standard Office schemas.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-050\",\"name\":\"SlicerOrTimelineCacheAnomaly\",\"shortDescription\":{\"text\":\"Excel Slicer or Timeline Cache Anomaly\"},\"fullDescription\":{\"text\":\"Excel Slicer or Timeline definitions or relationships configure remote UNC connection targets, database command execution, or dangerous exploit URI protocols.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-051\",\"name\":\"BibliographyOrCitationAnomaly\",\"shortDescription\":{\"text\":\"Word Bibliography or Citation Anomaly\"},\"fullDescription\":{\"text\":\"Word Bibliography definitions or citation fields contain remote UNC paths for NTLM credential coercion, exploit protocol handlers, shell execution commands, or smuggled PE binaries.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-052\",\"name\":\"CustomXmlDataBindingOrXPathAnomaly\",\"shortDescription\":{\"text\":\"Custom XML Data Binding or XPath Anomaly\"},\"fullDescription\":{\"text\":\"Custom XML data binding or Structured Document Tag (SDT) XPath queries contain external document resolution (SSRF/NTLM coercion), command injection, or remote UNC namespace mappings.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-053\",\"name\":\"XmlMapsOrSchemaDefinitionAnomaly\",\"shortDescription\":{\"text\":\"Excel XML Map or Schema Definition Anomaly\"},\"fullDescription\":{\"text\":\"Excel XML Map definitions or table XML column bindings configure remote UNC schema locations, XXE DTD entity declarations, exploit protocol handlers, or smuggled executable payloads.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-054\",\"name\":\"CommentAnnotationOrAuthorAnomaly\",\"shortDescription\":{\"text\":\"Comment, Modern Annotation, or Author Anomaly\"},\"fullDescription\":{\"text\":\"Document comment parts or relationships contain remote UNC paths for NTLM credential coercion, exploit protocol handlers, shell execution commands, or smuggled PE binaries.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-055\",\"name\":\"ThemeFontOrEffectCoercionAnomaly\",\"shortDescription\":{\"text\":\"Theme Font or Effect Coercion Anomaly\"},\"fullDescription\":{\"text\":\"Theme definitions configure remote UNC font typeface paths enabling NTLM credential coercion or font engine exploits, external theme relationships, or smuggled payloads.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-056\",\"name\":\"CustomXmlPropertiesOrItemSchemaAnomaly\",\"shortDescription\":{\"text\":\"Custom XML Properties or Item Schema Anomaly\"},\"fullDescription\":{\"text\":\"Custom XML item properties or schema references configure remote UNC schema paths enabling NTLM credential coercion, dangerous exploit URI schemes, external relationships to executables, or smuggled PE binaries.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-057\",\"name\":\"VbaDataStreamOrProjectRelsAnomaly\",\"shortDescription\":{\"text\":\"VBA Data Stream or Project Relationship Anomaly\"},\"fullDescription\":{\"text\":\"VBA project relationship parts or vbaData streams configure external relationships to remote UNC paths or binaries, exploit protocol handlers, shell execution commands, or smuggled PE binaries.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-058\",\"name\":\"WordGlossaryOrBuildingBlocksRelsAnomaly\",\"shortDescription\":{\"text\":\"Word Glossary or Building Blocks Relationship Anomaly\"},\"fullDescription\":{\"text\":\"Word glossary definitions or building blocks relationships configure remote template injection, remote UNC paths enabling NTLM credential coercion, exploit protocol handlers, or smuggled PE binaries.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-059\",\"name\":\"WordDocVariablesOrNotesAnomaly\",\"shortDescription\":{\"text\":\"Word Document Variables and Notes Anomaly\"},\"fullDescription\":{\"text\":\"Word document variable definitions (docVars) or footnotes and endnotes parts contain smuggled Windows PE binaries, shell execution commands, remote UNC paths, or dangerous exploit URI schemes.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-060\",\"name\":\"PowerPointTagsOrMastersAnomaly\",\"shortDescription\":{\"text\":\"PowerPoint Tags, Masters, and Font Table Anomaly\"},\"fullDescription\":{\"text\":\"PowerPoint programmable tags, presentation relationships, masters, or font tables contain smuggled Windows PE binaries, shell execution commands, remote template injection, or remote UNC paths.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-061\",\"name\":\"ScenarioManagerOrConsolidationAnomaly\",\"shortDescription\":{\"text\":\"Excel Scenario Manager and Data Consolidation Anomaly\"},\"fullDescription\":{\"text\":\"Excel Scenario Manager replacement cells or Data Consolidation definitions contain cloaked DDE execution formulas, Excel 4.0 macros, shell commands, or remote UNC workbook paths enabling NTLM credential coercion.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-062\",\"name\":\"PowerPointAnimationOrTimeNodeAnomaly\",\"shortDescription\":{\"text\":\"PowerPoint Animation and TimeNode Anomaly\"},\"fullDescription\":{\"text\":\"PowerPoint slide animation timing nodes, media nodes, or slide relationships contain shell command execution triggers, remote UNC media streams, dangerous exploit URI schemes, or smuggled PE binaries.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-063\",\"name\":\"WordHeaderFooterOrWatermarkAnomaly\",\"shortDescription\":{\"text\":\"Word Header, Footer, and Watermark Anomaly\"},\"fullDescription\":{\"text\":\"Word headers, footers, watermarks, or their relationships configure remote UNC paths enabling NTLM credential coercion, dangerous exploit URI schemes, executable or script targets, shell commands, or smuggled PE binaries.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-064\",\"name\":\"ExcelDataModelOrFormulaCacheAnomaly\",\"shortDescription\":{\"text\":\"Excel DataModel and Shared Formula Cache Anomaly\"},\"fullDescription\":{\"text\":\"Excel DataModel definitions or worksheet shared formula caches contain remote UNC connections enabling NTLM credential coercion, database command execution strings, XXE declarations, cloaked DDE execution, or smuggled PE binaries.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-065\",\"name\":\"ExcelPivotCacheOrDefinitionAnomaly\",\"shortDescription\":{\"text\":\"Excel PivotCache and Definition Anomaly\"},\"fullDescription\":{\"text\":\"Excel PivotCache definitions, records, or relationships configure remote UNC connection targets enabling NTLM credential coercion, database command execution strings, dangerous exploit URI schemes, cloaked DDE execution, or smuggled PE binaries.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-066\",\"name\":\"WordOrPowerPointEmbeddedPackageAnomaly\",\"shortDescription\":{\"text\":\"Word and PowerPoint Embedded Package Anomaly\"},\"fullDescription\":{\"text\":\"Word or PowerPoint embedded packages, OLE binary streams, or auto-activation directives disguise Windows PE executables, staged shell scripts, remote UNC paths, dangerous exploit URI schemes, or auto-activating OLE handlers.\"},\"defaultConfiguration\":{\"level\":\"error\"}},"
    );
    out.push_str(
        "{\"id\":\"VBA-CELL-067\",\"name\":\"ExcelExternalBookOrSheetPathAnomaly\",\"shortDescription\":{\"text\":\"Excel External Workbook and Sheet Path Anomaly\"},\"fullDescription\":{\"text\":\"Excel external workbook links, relationships, or cached datasets configure remote UNC workbook paths enabling NTLM credential coercion, dangerous exploit URI schemes, cloaked DDE execution in defined names, or smuggled PE binaries.\"},\"defaultConfiguration\":{\"level\":\"error\"}}"
    );
    out.push_str("]}},\"artifacts\":[{\"location\":{\"uri\":");
    out.push_str(&q(file_uri));
    out.push_str("}}],\"results\":[");

    let mut first_result = true;
    for f in &inspection.stomping_report.project_findings {
        if !first_result {
            out.push(',');
        }
        first_result = false;
        let (rule_id, level) = finding_to_sarif_rule(f);
        out.push_str(&format!(
            "{{\"ruleId\":{},\"level\":{},\"message\":{{\"text\":{}}},\"locations\":[{{\"physicalLocation\":{{\"artifactLocation\":{{\"uri\":{}}}}},\"logicalLocations\":[{{\"name\":\"PROJECT\",\"kind\":\"project\"}}]}}]}}",
            q(rule_id),
            q(level),
            q(&f.description),
            q(file_uri)
        ));
    }
    for m in &inspection.stomping_report.modules {
        for f in &m.findings {
            if !first_result {
                out.push(',');
            }
            first_result = false;
            let (rule_id, level) = finding_to_sarif_rule(f);
            out.push_str(&format!(
                "{{\"ruleId\":{},\"level\":{},\"message\":{{\"text\":{}}},\"locations\":[{{\"physicalLocation\":{{\"artifactLocation\":{{\"uri\":{}}}}},\"logicalLocations\":[{{\"name\":{},\"kind\":\"module\"}}]}}]}}",
                q(rule_id),
                q(level),
                q(&f.description),
                q(file_uri),
                q(&m.module_name)
            ));
        }
    }
    for t in &inspection.extracted.cell_threats {
        if !first_result {
            out.push(',');
        }
        first_result = false;
        let (rule_id, level) = cell_threat_to_sarif_rule(t);
        let logical_kind = if t.coordinate.starts_with("sheet:") {
            "sheet"
        } else if t.coordinate.starts_with("definedName:") {
            "definedName"
        } else if t.coordinate.starts_with("part:") {
            "part"
        } else if t.coordinate.starts_with("rel:") {
            "relationship"
        } else {
            "cell"
        };
        out.push_str(&format!(
            "{{\"ruleId\":{},\"level\":{},\"message\":{{\"text\":{}}},\"locations\":[{{\"physicalLocation\":{{\"artifactLocation\":{{\"uri\":{}}}}},\"logicalLocations\":[{{\"name\":{},\"kind\":{}}}]}}]}}",
            q(rule_id),
            q(level),
            q(&t.description),
            q(file_uri),
            q(&t.coordinate),
            q(logical_kind)
        ));
    }

    out.push_str("]}]}");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compiled_report_exposes_the_raw_project_version_tag() {
        let extraction = ExtractedProject {
            project_version_tag: Some(0x3164),
            compiled_representation_status:
                "opaque_version_dependent_performance_cache; not disassembled or verified".into(),
            ..ExtractedProject::default()
        };
        let report = to_json(
            &Analysis::default(),
            Some(&extraction),
            Disclosure::StructureOnly,
        );
        assert!(report.contains("\"project_version_tag\": \"0x3164\""));
        assert!(report.contains("\"pcode_disassembled\": false"));
        assert!(!report.contains("\"pcode_verified\": true"));
    }

    #[test]
    fn pcode_decode_json_obeys_source_disclosure() {
        let report = crate::compiled::PCodeDecodeReport {
            schema_id: "private_profile".into(),
            schema_status: crate::compiled::PCodeSchemaStatus::CallerSuppliedUnverified,
            lines: vec![crate::compiled::DecodedPCodeLine {
                source_line: 0,
                instructions: vec![crate::compiled::DecodedPCodeInstruction {
                    source_line: 0,
                    line_offset: 0,
                    cache_offset: Some(128),
                    header_word: 0x0401,
                    opcode: 1,
                    operation_type: 1,
                    mnemonic: Some("PrivateMnemonic".into()),
                    operands: vec![
                        crate::compiled::DecodedPCodeOperand::Bytes(b"hidden-payload".to_vec()),
                        crate::compiled::DecodedPCodeOperand::Float64Bits(0x3ff0_0000_0000_0000),
                    ],
                    complete: true,
                }],
                issues: Vec::new(),
                complete: true,
            }],
            instruction_count: 1,
            complete: true,
            truncated: false,
        };
        let structure = pcode_decode_to_json(&report, Disclosure::StructureOnly);
        assert!(structure.contains("\"schema_id\":null"));
        assert!(structure.contains("\"mnemonic\":null"));
        assert!(structure.contains("\"operands\":null"));
        assert!(!structure.contains("private_profile"));
        assert!(!structure.contains("PrivateMnemonic"));
        assert!(!structure.contains("hidden-payload"));

        let full = pcode_decode_to_json(&report, Disclosure::IncludeSource);
        assert!(full.contains("\"schema_id\":\"private_profile\""));
        assert!(full.contains("\"mnemonic\":\"PrivateMnemonic\""));
        assert!(full.contains("68696464656e2d7061796c6f6164"));
        assert!(full.contains("\"kind\":\"float64_bits\""));
        assert!(full.contains("0x3ff0000000000000"));
        assert!(full.contains("\"schema_status\":\"caller_supplied_unverified\""));
        assert!(full.contains("\"pcode_verified\":false"));
    }

    #[test]
    fn pcode_semantic_json_obeys_source_disclosure() {
        let report = crate::compiled::PCodeSemanticReport {
            schema_id: "private_semantics".into(),
            schema_status: crate::compiled::PCodeSchemaStatus::CallerSuppliedUnverified,
            steps: vec![crate::compiled::PCodeSemanticStep {
                source_line: 2,
                line_offset: 4,
                opcode: 7,
                operation_type: 1,
                mnemonic: Some("PrivateAdd".into()),
                stack_before: vec![crate::compiled::PCodeSemanticValue::Integer(3)],
                stack_after: vec![crate::compiled::PCodeSemanticValue::Integer(5)],
                locals_before: Vec::new(),
                locals_after: Vec::new(),
                control_transfer: crate::compiled::PCodeSemanticControlTransfer::None,
                status: crate::compiled::PCodeSemanticStepStatus::Applied,
            }],
            unknown_value_count: 0,
            unknown_instruction_count: 0,
            stack_underflow_count: 0,
            complete: true,
            truncated: false,
        };
        let structure = pcode_semantics_to_json(&report, Disclosure::StructureOnly);
        assert!(structure.contains("\"schema_id\":null"));
        assert!(structure.contains("\"mnemonic\":null"));
        assert!(structure.contains("\"stack_before_depth\":1"));
        assert!(structure.contains("\"stack_before\":null"));
        assert!(structure.contains("\"locals_after_count\":0"));
        assert!(!structure.contains("private_semantics"));
        assert!(!structure.contains("PrivateAdd"));
        let full = pcode_semantics_to_json(&report, Disclosure::IncludeSource);
        assert!(full.contains("\"schema_id\":\"private_semantics\""));
        assert!(full.contains("PrivateAdd"));
        assert!(full.contains("\"kind\":\"integer\",\"value\":5"));
        assert!(full.contains("\"pcode_verified\":false"));
    }

    #[test]
    fn pcode_semantic_path_json_keeps_path_structure_and_disclosure() {
        let report = crate::compiled::PCodeSemanticPathReport {
            schema_id: "private_path_semantics".into(),
            schema_status: crate::compiled::PCodeSchemaStatus::CallerSuppliedUnverified,
            paths: vec![crate::compiled::PCodeSemanticPath {
                path_index: 0,
                steps: vec![crate::compiled::PCodeSemanticStep {
                    source_line: 1,
                    line_offset: 2,
                    opcode: 8,
                    operation_type: 0,
                    mnemonic: Some("PrivateBranch".into()),
                    stack_before: Vec::new(),
                    stack_after: Vec::new(),
                    locals_before: Vec::new(),
                    locals_after: Vec::new(),
                    control_transfer: crate::compiled::PCodeSemanticControlTransfer::BranchRelative(
                        crate::compiled::PCodeSemanticValue::Integer(4),
                    ),
                    status: crate::compiled::PCodeSemanticStepStatus::Applied,
                }],
                complete: true,
                truncated: false,
                termination: crate::compiled::PCodeSemanticPathTermination::Return,
            }],
            unknown_value_count: 0,
            unknown_instruction_count: 0,
            stack_underflow_count: 0,
            complete: true,
            truncated: false,
        };
        let structure = pcode_semantic_paths_to_json(&report, Disclosure::StructureOnly);
        assert!(structure.contains("\"path_count\":1"));
        assert!(structure.contains("\"unknown_value_count\":0"));
        assert!(structure.contains("\"termination\":\"return\""));
        assert!(structure.contains("\"mnemonic\":null"));
        assert!(structure.contains("\"value\":null"));
        assert!(!structure.contains("private_path_semantics"));
        assert!(!structure.contains("PrivateBranch"));
        let full = pcode_semantic_paths_to_json(&report, Disclosure::IncludeSource);
        assert!(full.contains("private_path_semantics"));
        assert!(full.contains("PrivateBranch"));
        assert!(full.contains("\"value\":4"));
    }

    #[test]
    fn pcode_project_semantic_json_obeys_module_disclosure() {
        let report = crate::extract::ExtractedProjectPCodeAnalysis {
            modules: vec![crate::extract::ExtractedModulePCodeAnalysis {
                module_name: "SecretModule".into(),
                decoded: crate::compiled::PCodeDecodeReport {
                    schema_id: "decode".into(),
                    schema_status: crate::compiled::PCodeSchemaStatus::CallerSuppliedUnverified,
                    lines: Vec::new(),
                    instruction_count: 0,
                    complete: true,
                    truncated: false,
                },
                semantic_paths: crate::compiled::PCodeSemanticPathReport {
                    schema_id: "semantic".into(),
                    schema_status: crate::compiled::PCodeSchemaStatus::CallerSuppliedUnverified,
                    paths: Vec::new(),
                    unknown_value_count: 0,
                    unknown_instruction_count: 0,
                    stack_underflow_count: 0,
                    complete: true,
                    truncated: false,
                },
            }],
            truncated: false,
        };
        let structure = pcode_project_semantics_to_json(&report, Disclosure::StructureOnly);
        assert!(structure.contains("\"module_count\":1"));
        assert!(structure.contains("\"module\":\"module_0\""));
        assert!(!structure.contains("SecretModule"));
        let full = pcode_project_semantics_to_json(&report, Disclosure::IncludeSource);
        assert!(full.contains("SecretModule"));
        assert!(full.contains("\"schema_id\":\"decode\""));
        assert!(full.contains("\"schema_id\":\"semantic\""));
    }

    #[test]
    fn observed_pcode_record_bytes_follow_source_disclosure() {
        let extraction = ExtractedProject {
            modules: vec![crate::extract::ExtractedModule {
                pcode_layout: Some(crate::compiled::PCodeLineMap {
                    profile: crate::compiled::PCodeLayoutProfile::Vba7Observed,
                    cafe_offset: 10,
                    profile_header_raw: [0x12, 0x34],
                    line_count: 1,
                    directory_offset: 16,
                    code_table_offset: 38,
                    code_bytes_total: 2,
                    lines: vec![crate::compiled::PCodeLineSegment {
                        source_line: 0,
                        line_length: 2,
                        record_prefix_raw: [0x11, 0x22, 0x33, 0x44],
                        record_middle_raw: [0x55, 0x66],
                        relative_code_offset_raw: 0,
                        cache_offset: Some(38),
                        raw_bytes: vec![0x77, 0x88],
                        raw_word_count: 1,
                        has_partial_word: false,
                    }],
                    mnemonics_decoded: false,
                }),
                ..crate::extract::ExtractedModule::default()
            }],
            ..ExtractedProject::default()
        };
        let structure = to_json(
            &Analysis::default(),
            Some(&extraction),
            Disclosure::StructureOnly,
        );
        assert!(structure.contains("\"profile_header_raw\":null"));
        assert!(structure.contains("\"record_prefix_raw\":null"));
        assert!(structure.contains("\"record_middle_raw\":null"));
        assert!(structure.contains("\"relative_code_offset_raw\":0"));
        assert!(structure.contains("\"raw_hex\":null"));

        let full = to_json(
            &Analysis::default(),
            Some(&extraction),
            Disclosure::IncludeSource,
        );
        assert!(full.contains("\"profile_header_raw\":\"1234\""));
        assert!(full.contains("\"record_prefix_raw\":\"11223344\""));
        assert!(full.contains("\"record_middle_raw\":\"5566\""));
        assert!(full.contains("\"relative_code_offset_raw\":0"));
        assert!(full.contains("\"raw_hex\":\"7788\""));
    }

    #[test]
    fn project_reference_metadata_obeys_source_disclosure() {
        let extraction = ExtractedProject {
            references: vec!["WorkbookLibrary".into()],
            project_references: vec![crate::ovba::OvbaReference {
                kind: "vba_project".into(),
                name: Some("WorkbookLibrary".into()),
                libid_absolute: Some("*\\C:\\private\\WorkbookLibrary.xls".into()),
                parsed_libid_absolute: Some(crate::ovba::ParsedProjectReference {
                    project_kind: "embedded_windows".into(),
                    path: "C:\\private\\WorkbookLibrary.xls".into(),
                }),
                libid_relative: Some("*\\CWorkbookLibrary.xls".into()),
                parsed_libid_relative: Some(crate::ovba::ParsedProjectReference {
                    project_kind: "embedded_windows".into(),
                    path: "WorkbookLibrary.xls".into(),
                }),
                major_version: Some(2),
                minor_version: Some(7),
                ..crate::ovba::OvbaReference::default()
            }, crate::ovba::OvbaReference {
                kind: "registered_type_library".into(),
                libid: Some("*\\G{01234567-89AB-CDEF-0123-456789ABCDEF}#2.0#0#C:\\private\\Automation.tlb#OLE Automation".into()),
                parsed_libid: Some(crate::ovba::ParsedLibidReference {
                    path_kind: "windows".into(),
                    guid: "{01234567-89AB-CDEF-0123-456789ABCDEF}".into(),
                    major_version: 2,
                    minor_version: 0,
                    lcid: 0,
                    path: "C:\\private\\Automation.tlb".into(),
                    display_name: "OLE Automation".into(),
                }),
                ..crate::ovba::OvbaReference::default()
            }],
            ..ExtractedProject::default()
        };
        let structure = to_json(
            &Analysis::default(),
            Some(&extraction),
            Disclosure::StructureOnly,
        );
        assert!(structure.contains("\"kind\":\"vba_project\""));
        assert!(structure.contains("\"major_version\":2"));
        assert!(structure.contains("\"guid\":\"{01234567-89AB-CDEF-0123-456789ABCDEF}\""));
        assert!(structure.contains("\"project_kind\":\"embedded_windows\""));
        assert!(!structure.contains("WorkbookLibrary"));
        assert!(!structure.contains("private"));
        assert!(!structure.contains("WorkbookLibrary.xls"));
        assert!(!structure.contains("OLE Automation"));

        let full = to_json(
            &Analysis::default(),
            Some(&extraction),
            Disclosure::IncludeSource,
        );
        assert!(full.contains("WorkbookLibrary"));
        assert!(full.contains("private"));
        assert!(full.contains("WorkbookLibrary.xls"));
        assert!(full.contains("Automation.tlb"));
        assert!(full.contains("OLE Automation"));
        assert!(full.contains("\"minor_version\":7"));
    }

    #[test]
    fn workbook_sheet_identity_obeys_source_disclosure() {
        let extraction = ExtractedProject {
            workbook_code_name: Some("MainBookCode".into()),
            workbook_sheets: vec![crate::model::WorkbookSheetInfo {
                name: "PayrollArchive".into(),
                code_name: Some("ArchiveCode".into()),
                sheet_id: Some(7),
                state: Some("veryHidden".into()),
                kind: "worksheet".into(),
                relationship_id: Some("rId7".into()),
                part_name: Some("xl/worksheets/sheet7.xml".into()),
                resolution: "resolved_internal".into(),
            }],
            ..ExtractedProject::default()
        };
        let structure = to_json(
            &Analysis::default(),
            Some(&extraction),
            Disclosure::StructureOnly,
        );
        assert!(structure.contains("\"sheet_count\":1"));
        assert!(structure.contains("\"workbook_code_name\":null"));
        assert!(structure.contains("\"code_name\":null"));
        assert!(structure.contains("\"kind\":\"worksheet\""));
        assert!(structure.contains("\"resolution\":\"resolved_internal\""));
        assert!(!structure.contains("PayrollArchive"));
        assert!(!structure.contains("MainBookCode"));
        assert!(!structure.contains("ArchiveCode"));
        assert!(!structure.contains("sheet7.xml"));

        let full = to_json(
            &Analysis::default(),
            Some(&extraction),
            Disclosure::IncludeSource,
        );
        assert!(full.contains("PayrollArchive"));
        assert!(full.contains("MainBookCode"));
        assert!(full.contains("ArchiveCode"));
        assert!(full.contains("veryHidden"));
        assert!(full.contains("rId7"));
        assert!(full.contains("xl/worksheets/sheet7.xml"));
    }

    #[test]
    fn workbook_defined_names_obey_source_disclosure() {
        let extraction = ExtractedProject {
            workbook_sheets: vec![crate::model::WorkbookSheetInfo {
                name: "InputSheet".into(),
                kind: "worksheet".into(),
                resolution: "resolved_internal".into(),
                ..crate::model::WorkbookSheetInfo::default()
            }],
            workbook_defined_names: vec![crate::model::WorkbookDefinedNameInfo {
                name: "PrivateThreshold".into(),
                formula: "'InputSheet'!$B$2".into(),
                local_sheet_id: Some(0),
                local_sheet_name: Some("InputSheet".into()),
                hidden: Some(true),
                built_in: false,
                scope_resolution: "sheet_scope_candidate".into(),
                formula_reference_resolution: "partial_formula_reference_scan".into(),
                formula_reference_candidates: vec![WorkbookFormulaReferenceInfo {
                    start_byte: 13,
                    end_byte: 17,
                    reference: "$B$2".into(),
                    reference_kind: "cell_reference".into(),
                    sheet_index_candidate: Some(0),
                    sheet_name_candidate: Some("InputSheet".into()),
                    sheet_resolution: "workbook_worksheet_name_candidate".into(),
                    cell_range_bounds: Some(CellRangeBounds {
                        first_row: 2,
                        first_column: 2,
                        last_row: 2,
                        last_column: 2,
                    }),
                    workbook_cell_indices: vec![0],
                    ..WorkbookFormulaReferenceInfo::default()
                }],
                formula_references_truncated: false,
            }],
            ..ExtractedProject::default()
        };
        let structure = to_json(
            &Analysis::default(),
            Some(&extraction),
            Disclosure::StructureOnly,
        );
        assert!(structure.contains("\"defined_name_count\":1"));
        assert!(structure.contains("\"scope_resolution\":\"sheet_scope_candidate\""));
        assert!(!structure.contains("PrivateThreshold"));
        assert!(!structure.contains("InputSheet"));
        assert!(!structure.contains("$B$2"));
        assert!(structure.contains("\"hidden\":null"));

        let full = to_json(
            &Analysis::default(),
            Some(&extraction),
            Disclosure::IncludeSource,
        );
        assert!(full.contains("PrivateThreshold"));
        assert!(full.contains("'InputSheet'!$B$2"));
        assert!(full.contains("\"hidden\":true"));
        assert!(full.contains("\"formula_reference_candidates\":[{"));
        assert!(full.contains("\"workbook_cell_ids\":[0]"));
    }

    #[test]
    fn workbook_cell_contents_follow_source_disclosure() {
        let extraction = ExtractedProject {
            workbook_sheets: vec![crate::model::WorkbookSheetInfo {
                name: "PrivateInputs".into(),
                kind: "worksheet".into(),
                resolution: "resolved_internal".into(),
                ..crate::model::WorkbookSheetInfo::default()
            }],
            workbook_defined_names: vec![WorkbookDefinedNameInfo {
                name: "PrivateThreshold".into(),
                formula: "0.075".into(),
                scope_resolution: "workbook_scope".into(),
                ..WorkbookDefinedNameInfo::default()
            }],
            workbook_cells: vec![crate::model::WorkbookCellInfo {
                sheet_index: 0,
                sheet_name: "PrivateInputs".into(),
                cell_ref: "B4".into(),
                row: Some(4),
                column: Some(2),
                cell_type: "n".into(),
                formula: Some("A1+1".into()),
                stored_value: Some("12".into()),
                value: Some("12".into()),
                resolution: "formula_cached_value".into(),
                formula_reference_resolution: "partial_formula_reference_scan".into(),
                formula_reference_source_cell_index: Some(0),
                formula_reference_candidates: vec![
                    WorkbookFormulaReferenceInfo {
                        start_byte: 0,
                        end_byte: 2,
                        reference: "A1".into(),
                        reference_kind: "cell_reference".into(),
                        sheet_index_candidate: Some(0),
                        sheet_name_candidate: Some("PrivateInputs".into()),
                        sheet_resolution: "formula_worksheet_candidate".into(),
                        cell_range_bounds: Some(CellRangeBounds {
                            first_row: 1,
                            first_column: 1,
                            last_row: 1,
                            last_column: 1,
                        }),
                        workbook_cell_indices: vec![0],
                        ..WorkbookFormulaReferenceInfo::default()
                    },
                    WorkbookFormulaReferenceInfo {
                        start_byte: 3,
                        end_byte: 18,
                        reference: "PrivateThreshold".into(),
                        reference_kind: "defined_name_candidate".into(),
                        defined_name_index_candidate: Some(0),
                        defined_name_resolution: Some("workbook_defined_name_candidate".into()),
                        sheet_resolution: "workbook_scope_candidate".into(),
                        ..WorkbookFormulaReferenceInfo::default()
                    },
                ],
                ..crate::model::WorkbookCellInfo::default()
            }],
            ..ExtractedProject::default()
        };
        let structure = to_json(
            &Analysis::default(),
            Some(&extraction),
            Disclosure::StructureOnly,
        );
        assert!(structure.contains("\"workbook_cell_count\":1"));
        assert!(structure.contains("\"cells\":null"));
        assert!(!structure.contains("PrivateInputs"));
        assert!(!structure.contains("B4"));
        assert!(!structure.contains("A1+1"));
        assert!(!structure.contains("\"value\":\"12\""));

        let full = to_json(
            &Analysis::default(),
            Some(&extraction),
            Disclosure::IncludeSource,
        );
        assert!(full.contains("PrivateInputs"));
        assert!(full.contains("B4"));
        assert!(full.contains("A1+1"));
        assert!(full.contains("\"value\":\"12\""));
        assert!(full.contains("\"formula_reference_candidates\":[{"));
        assert!(
            full.contains("\"formula_reference_resolution\":\"partial_formula_reference_scan\"")
        );
        assert!(full.contains("\"formula_reference_source_cell_id\":0"));
        assert!(full.contains("\"reference\":\"A1\""));
        assert!(full.contains("\"reference\":\"PrivateThreshold\""));
        assert!(full.contains("\"defined_name_id_candidate\":0"));
        assert!(full.contains("\"workbook_cell_ids\":[0]"));
    }

    #[test]
    fn workbook_table_names_and_columns_follow_source_disclosure() {
        let extraction = ExtractedProject {
            workbook_tables: vec![crate::model::WorkbookTableInfo {
                name: "OrdersTable".into(),
                display_name: "OrdersTable".into(),
                sheet_index: 0,
                sheet_name: "Orders".into(),
                part_name: Some("xl/tables/table1.xml".into()),
                cell_range_bounds: Some(CellRangeBounds {
                    first_row: 1,
                    first_column: 1,
                    last_row: 12,
                    last_column: 3,
                }),
                header_row_count: 1,
                totals_row_count: 1,
                columns: vec!["Account".into(), "Amount".into(), "Status".into()],
                resolution: "resolved_internal".into(),
            }],
            ..ExtractedProject::default()
        };
        let structure = to_json(
            &Analysis::default(),
            Some(&extraction),
            Disclosure::StructureOnly,
        );
        assert!(structure.contains("\"table_count\":1"));
        assert!(structure.contains("\"tables\":null"));
        assert!(!structure.contains("OrdersTable"));
        assert!(!structure.contains("Account"));

        let full = to_json(
            &Analysis::default(),
            Some(&extraction),
            Disclosure::IncludeSource,
        );
        assert!(full.contains("OrdersTable"));
        assert!(full.contains("Account"));
        assert!(full.contains("\"last_row\":12"));
    }

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

    #[test]
    fn guarded_dataflow_keeps_path_links_but_redacts_conditions_by_default() {
        let analysis = crate::analyze::analyze(
            &[SourceUnit {
                name: "Approval.bas".into(),
                text: "Public Sub Decide()\nrawAmount = PayrollAmount\nIf CustomerApproved Then\nresult = rawAmount\nElse\nresult = 0\nEnd If\nEnd Sub\n".into(),
            }],
            &crate::analyze::AnalysisOptions::default(),
        )
        .unwrap();
        assert!(!analysis.data_flow_paths.is_empty());
        assert!(!analysis.path_value_flows.is_empty());
        assert!(analysis.path_value_flows.iter().any(|flow| {
            flow.source_data_flow_index.is_none()
                && flow.resolution == "no_prior_local_definition_on_path"
                && flow.variable == "PayrollAmount"
        }));
        let structure = to_json(&analysis, None, Disclosure::StructureOnly);
        assert!(structure.contains("\"data_flow_paths\": ["));
        assert!(structure.contains("\"path_value_flows\": ["));
        assert!(structure.contains("\"data_flow_path_unassociated_count\":"));
        assert!(structure.contains("condition_0"));
        assert!(!structure.contains("CustomerApproved"));
        assert!(!structure.contains("PayrollAmount"));
        assert!(!structure.contains("rawAmount"));
        let full = to_json(&analysis, None, Disclosure::IncludeSource);
        assert!(full.contains("CustomerApproved"));
        assert!(full.contains("PayrollAmount"));
        assert!(full.contains("rawAmount"));

        let excel_analysis = crate::analyze::analyze(
            &[SourceUnit {
                name: "ExcelApproval.bas".into(),
                text: "Public Sub WriteIfApproved()\nIf ApprovalFlag Then\nWorksheets(\"Orders\").Range(\"A1\").Value = PayrollAmount\nEnd If\nEnd Sub\n".into(),
            }],
            &crate::analyze::AnalysisOptions {
                host_profile: crate::host::HostProfile::Excel,
                ..crate::analyze::AnalysisOptions::default()
            },
        )
        .unwrap();
        assert!(!excel_analysis.data_access_paths.is_empty());
        assert!(!excel_analysis.data_access_value_flows.is_empty());
        let structure = to_json(&excel_analysis, None, Disclosure::StructureOnly);
        assert!(structure.contains("\"data_access_paths\": ["));
        assert!(structure.contains("\"data_access_value_flows\": ["));
        assert!(!structure.contains("ApprovalFlag"));
        assert!(!structure.contains("PayrollAmount"));
        let full = to_json(&excel_analysis, None, Disclosure::IncludeSource);
        assert!(full.contains("ApprovalFlag"));
        assert!(full.contains("PayrollAmount"));
        assert!(full.contains("variable_to_excel_write_candidate"));

        let predicate_analysis = crate::analyze::analyze(
            &[SourceUnit {
                name: "ExcelPredicate.bas".into(),
                text: "Public Sub Guard()\nIf Worksheets(\"Orders\").Range(\"A1\").Value > 0 Then\namount = 1\nEnd If\nEnd Sub\n".into(),
            }],
            &crate::analyze::AnalysisOptions {
                host_profile: crate::host::HostProfile::Excel,
                ..crate::analyze::AnalysisOptions::default()
            },
        )
        .unwrap();
        assert!(!predicate_analysis.data_access_predicates.is_empty());
        let structure = to_json(&predicate_analysis, None, Disclosure::StructureOnly);
        assert!(structure.contains("\"data_access_predicates\": ["));
        assert!(!structure.contains("Orders"));
        assert!(!structure.contains("A1"));
        let full = to_json(&predicate_analysis, None, Disclosure::IncludeSource);
        assert!(full.contains("Orders"));
        assert!(full.contains("= True"));
        assert!(full.contains("= False"));
    }

    #[test]
    fn qualified_return_constant_flow_respects_source_disclosure() {
        let analysis = crate::analyze::analyze(
            &[
                SourceUnit {
                    name: "Provider.bas".into(),
                    text: "Private Const HiddenLimit As Long = 19\nPrivate Function InnerLimit() As Long\nInnerLimit = HiddenLimit\nEnd Function\nPublic Function ReadLimit() As Long\nDim localCopy As Long\nlocalCopy = InnerLimit()\nReadLimit = localCopy\nEnd Function\n".into(),
                },
                SourceUnit {
                    name: "Consumer.bas".into(),
                    text: "Public Sub Read()\nDim result As Long\nresult = Provider.ReadLimit()\nEnd Sub\n".into(),
                },
            ],
            &crate::analyze::AnalysisOptions::default(),
        )
        .unwrap();
        assert!(analysis.path_value_flows.iter().any(|flow| {
            flow.variable == "Provider.HiddenLimit"
                && flow.resolution == "constant_initializer_candidate"
        }));

        let structure = to_json(&analysis, None, Disclosure::StructureOnly);
        assert!(!structure.contains("Provider"));
        assert!(!structure.contains("HiddenLimit"));
        assert!(structure.contains("constant_initializer_candidate"));
        let full = to_json(&analysis, None, Disclosure::IncludeSource);
        assert!(full.contains("Provider.HiddenLimit"));
    }

    #[test]
    fn interprocedural_dataflow_paths_keep_both_procedures_and_redact_names() {
        let analysis = crate::analyze::analyze(
            &[SourceUnit {
                name: "Calls.bas".into(),
                text: "Private Sub Update(ByRef SECRET_PARAMETER As Long)\nDim currentValue As Long\nSECRET_PARAMETER = SECRET_PARAMETER + 1\ncurrentValue = SECRET_PARAMETER\nEnd Sub\nPublic Sub Caller()\nDim amount As Long\namount = 1\nIf SECRET_APPROVAL Then\nUpdate amount\nEnd If\nEnd Sub\n".into(),
            }],
            &crate::analyze::AnalysisOptions::default(),
        )
        .unwrap();
        assert_eq!(analysis.interprocedural_data_flow_paths.len(), 2);
        assert!(!analysis.interprocedural_byref_write_paths.is_empty());
        let structure = to_json(&analysis, None, Disclosure::StructureOnly);
        assert!(structure.contains("\"interprocedural_data_flow_paths\": ["));
        assert!(structure.contains("\"interprocedural_byref_write_paths\": ["));
        assert!(structure.contains("\"interprocedural_byref_value_paths\": ["));
        assert!(structure.contains("procedure_argument_to_parameter_use_candidate"));
        assert!(structure.contains("byref_call_to_callee_write_candidate"));
        assert!(structure.contains("caller_condition_"));
        assert!(!structure.contains("SECRET_PARAMETER"));
        assert!(!structure.contains("SECRET_APPROVAL"));
        let full = to_json(&analysis, None, Disclosure::IncludeSource);
        assert!(full.contains("SECRET_PARAMETER"));
        assert!(full.contains("SECRET_APPROVAL"));
        assert!(full.contains("procedure_argument_to_parameter_use_candidate"));
        assert!(full.contains("byref_call_to_callee_write_candidate"));
        assert!(full.contains("caller_snapshot_to_byref_write_value"));
        assert!(full.contains("SECRET_PARAMETER"));
    }

    #[test]
    fn path_alias_dispatches_follow_source_disclosure() {
        let analysis = crate::analyze::analyze(
            &[
                SourceUnit {
                    name: "Widget.cls".into(),
                    text: "Public Sub Save(ByVal value As Long)\nEnd Sub\n".into(),
                },
                SourceUnit {
                    name: "Caller.bas".into(),
                    text: "Option Explicit\nPublic Sub Run()\nDim source As Widget\nDim target As Object\nSet target = source\ntarget.Save(1)\nEnd Sub\n".into(),
                },
            ],
            &crate::analyze::AnalysisOptions::default(),
        )
        .unwrap();
        assert!(!analysis.path_alias_dispatches.is_empty());
        let structure = to_json(&analysis, None, Disclosure::StructureOnly);
        assert!(structure.contains("\"path_alias_dispatches\": ["));
        assert!(!structure.contains("Widget.Save"));
        let full = to_json(&analysis, None, Disclosure::IncludeSource);
        assert!(full.contains("Widget.Save"));
        assert!(full.contains("path_alias_typed_member_dispatch_candidate"));
    }

    #[test]
    fn interprocedural_return_paths_preserve_wrapper_edges_and_redact_names() {
        let analysis = crate::analyze::analyze(
            &[SourceUnit {
                name: "Returns.bas".into(),
                text: "Private Function Inner(ByVal value As Long) As Long\nInner = value + 1\nEnd Function\nPrivate Function SECRET_WRAPPER(ByVal value As Long) As Long\nSECRET_WRAPPER = Inner(value)\nEnd Function\nPublic Sub Caller()\nDim amount As Long\nDim result As Long\namount = 1\nresult = SECRET_WRAPPER(amount)\nEnd Sub\n".into(),
            }],
            &crate::analyze::AnalysisOptions::default(),
        )
        .unwrap();
        assert!(analysis.interprocedural_return_paths.len() >= 2);
        let structure = to_json(&analysis, None, Disclosure::StructureOnly);
        assert!(structure.contains("\"interprocedural_return_paths\": ["));
        assert!(structure.contains("\"interprocedural_return_compositions\": ["));
        assert!(structure.contains("function_return_to_caller_assignment_candidate"));
        assert!(!structure.contains("SECRET_WRAPPER"));
        let full = to_json(&analysis, None, Disclosure::IncludeSource);
        assert!(full.contains("SECRET_WRAPPER"));
        assert!(full.contains("function_return_to_caller_assignment_candidate"));
        assert!(full.contains("\"composition_depth\":2"));
        assert!(full.contains("\"chain_procedures\":["));
        assert!(structure.contains("\"chain_procedures\":["));
        assert!(!structure.contains("SECRET_WRAPPER"));
    }

    #[test]
    fn interprocedural_error_paths_preserve_separate_conditions_and_redact_names() {
        let analysis = crate::analyze::analyze(
            &[SourceUnit {
                name: "Errors.bas".into(),
                text: "Private Sub SECRET_WORKER(ByVal amount As Long)\nDim result As Long\nresult = 1 / amount\nEnd Sub\nPublic Sub Caller(ByVal SECRET_READY As Boolean, ByVal amount As Long)\nOn Error GoTo Handler\nIf SECRET_READY Then\nSECRET_WORKER amount\nEnd If\nExit Sub\nHandler:\nResume Next\nEnd Sub\nPublic Sub Main()\nSECRET_WORKER 1\nEnd Sub\n".into(),
            }],
            &crate::analyze::AnalysisOptions::default(),
        )
        .unwrap();
        assert!(!analysis.interprocedural_error_paths.is_empty());
        let structure = to_json(&analysis, None, Disclosure::StructureOnly);
        assert!(structure.contains("\"interprocedural_error_paths\": ["));
        assert!(structure.contains("default_error_policy_may_propagate_to_caller"));
        assert!(structure.contains("caller_error_response"));
        assert!(structure.contains("caller_handler_transfer_candidate"));
        assert!(structure.contains("\"caller_host_entry_candidate\":true"));
        assert!(structure.contains("error_caller_condition_"));
        assert!(!structure.contains("SECRET_WORKER"));
        assert!(!structure.contains("SECRET_READY"));
        let full = to_json(&analysis, None, Disclosure::IncludeSource);
        assert!(full.contains("SECRET_WORKER"));
        assert!(full.contains("SECRET_READY"));
    }

    #[test]
    fn automation_member_ids_follow_the_source_disclosure_policy() {
        let analysis = crate::analyze::analyze(
            &[SourceUnit {
                name: "Indexed.cls".into(),
                text: "Public Property Get Item(ByVal index As Long) As String\nEnd Property\nAttribute Item.VB_UserMemId = 0\n".into(),
            }],
            &crate::analyze::AnalysisOptions::default(),
        )
        .unwrap();
        let structure = to_json(&analysis, None, Disclosure::StructureOnly);
        assert!(structure.contains("\"default_member_candidate\":true"));
        assert!(structure.contains("\"automation_member_id\":null"));
        assert!(!structure.contains("VB_UserMemId"));
        let full = to_json(&analysis, None, Disclosure::IncludeSource);
        assert!(full.contains("\"automation_member_id\":0"));
        assert!(full.contains("VB_UserMemId"));
    }
    #[test]
    fn predeclared_class_attributes_are_exported_without_source_text() {
        let analysis = crate::analyze::analyze(
            &[SourceUnit {
                name: "FormLike.cls".into(),
                text: "Attribute VB_PredeclaredId = True\nAttribute VB_GlobalNameSpace = False\nPublic Sub Show()\nEnd Sub\n".into(),
            }],
            &crate::analyze::AnalysisOptions::default(),
        )
        .unwrap();
        let structure = to_json(&analysis, None, Disclosure::StructureOnly);
        assert!(structure.contains("\"predeclared_id\": true"));
        assert!(structure.contains("\"global_namespace\": false"));
        assert!(!structure.contains("Attribute VB_PredeclaredId"));
    }
    #[test]
    fn default_json_redacts_parameter_defaults() {
        let analysis = crate::analyze::analyze(
            &[SourceUnit {
                name: "Module.bas".into(),
                text:
                    "Public Sub S(Optional ByVal token As String = \"hidden-default\")\nEnd Sub\n"
                        .into(),
            }],
            &crate::analyze::AnalysisOptions::default(),
        )
        .unwrap();
        let structure = to_json(&analysis, None, Disclosure::StructureOnly);
        assert!(!structure.contains("hidden-default"));
        assert!(structure.contains("\"default_value\":null"));
        let full = to_json(&analysis, None, Disclosure::IncludeSource);
        assert!(full.contains("hidden-default"));
        assert!(full.contains("\"default_value\":"));
    }

    #[test]
    fn data_flow_callee_metadata_follows_source_disclosure() {
        let analysis = Analysis {
            data_flow: vec![crate::model::DataFlowFact {
                module: "Caller".into(),
                procedure: Some("Run".into()),
                target: "Receiver.Value".into(),
                inputs: vec!["amount".into()],
                transfer: "nested_function_argument_return_candidate".into(),
                call_callee_module: Some("SecretLibrary".into()),
                call_callee_procedure: Some("Calculate".into()),
                ..crate::model::DataFlowFact::default()
            }],
            ..Analysis::default()
        };
        let structure = to_json(&analysis, None, Disclosure::StructureOnly);
        assert!(structure.contains("\"call_callee_module\":null"));
        assert!(structure.contains("\"call_callee_procedure\":null"));
        assert!(!structure.contains("SecretLibrary"));
        assert!(!structure.contains("Calculate"));

        let full = to_json(&analysis, None, Disclosure::IncludeSource);
        assert!(full.contains("\"call_callee_module\":\"SecretLibrary\""));
        assert!(full.contains("\"call_callee_procedure\":\"Calculate\""));
    }

    #[test]
    fn selected_compile_constants_follow_the_disclosure_setting() {
        let mut constants = std::collections::BTreeMap::new();
        constants.insert("VBA7".into(), "True".into());
        let analysis = Analysis {
            project: Project {
                conditional_constants: constants,
                ..Project::default()
            },
            ..Analysis::default()
        };
        let structure = to_json(&analysis, None, Disclosure::StructureOnly);
        assert!(structure.contains("constant_0"));
        assert!(!structure.contains("VBA7"));
        assert!(!structure.contains("True"));
        let full = to_json(&analysis, None, Disclosure::IncludeSource);
        assert!(full.contains("VBA7"));
        assert!(full.contains("True"));
    }
    #[test]
    fn default_json_redacts_external_library_and_alias_names() {
        let analysis = crate::analyze::analyze(
            &[SourceUnit {
                name: "Api.bas".into(),
                text: "Private Declare Function Native Lib \"secretlib\" Alias \"secretalias\" () As Long\nPublic Sub Caller()\nNative()\nEnd Sub\n".into(),
            }],
            &crate::analyze::AnalysisOptions::default(),
        )
        .unwrap();
        let structure = to_json(&analysis, None, Disclosure::StructureOnly);
        assert!(!structure.contains("secretlib"));
        assert!(!structure.contains("secretalias"));
        let full = to_json(&analysis, None, Disclosure::IncludeSource);
        assert!(full.contains("secretlib"));
        assert!(full.contains("secretalias"));
    }

    #[test]
    fn array_bounds_show_option_base_and_follow_disclosure_policy() {
        let analysis = crate::analyze::analyze(
            &[SourceUnit {
                name: "Arrays.bas".into(),
                text: "Option Base 1\nPublic implicit_array(UPPER_BOUND) As Long\nPublic explicit_array(LOWER_BOUND To UPPER_BOUND) As Long\nPublic Sub Run()\nDim local_array(LOCAL_UPPER_BOUND) As Long\nDim dynamic_array() As Long\nEnd Sub\n".into(),
            }],
            &crate::analyze::AnalysisOptions::default(),
        )
        .unwrap();

        let structure = to_json(&analysis, None, Disclosure::StructureOnly);
        assert!(structure.contains("\"effective_lower_bound_expression\":\"1\""));
        assert!(structure.contains("\"lower_bound_source\":\"module_option_base\""));
        assert!(structure.contains("\"lower_bound_source\":\"explicit_expression\""));
        assert!(structure.contains("\"array_dimensions_status\":\"array_bounds_not_declared\""));
        assert!(!structure.contains("UPPER_BOUND"));
        assert!(!structure.contains("LOWER_BOUND"));
        assert!(!structure.contains("LOCAL_UPPER_BOUND"));

        let full = to_json(&analysis, None, Disclosure::IncludeSource);
        assert!(full.contains("UPPER_BOUND"));
        assert!(full.contains("LOWER_BOUND"));
        assert!(full.contains("LOCAL_UPPER_BOUND"));
        assert!(full.contains("\"name\":\"dynamic_array\""));
    }

    #[test]
    fn select_case_range_structure_is_visible_but_values_follow_disclosure_policy() {
        let analysis = crate::analyze::analyze(
            &[SourceUnit {
                name: "Cases.bas".into(),
                text: "Public Sub Choose(ByVal value As Long)\nSelect Case value\nCase 1, 2 To CASE_BOUND_SECRET, Is >= 5\nresult = True\nCase Else\nresult = False\nEnd Select\nEnd Sub\n".into(),
            }],
            &crate::analyze::AnalysisOptions::default(),
        )
        .unwrap();

        let structure = to_json(&analysis, None, Disclosure::StructureOnly);
        assert!(structure.contains("\"case_ranges\":["));
        assert!(structure.contains("\"kind\":\"range\",\"valid\":true"));
        assert!(structure.contains("\"comparison_operator\":\">=\""));
        assert!(structure.contains("\"expression\":null"));
        assert!(!structure.contains("CASE_BOUND_SECRET"));

        let full = to_json(&analysis, None, Disclosure::IncludeSource);
        assert!(full.contains("CASE_BOUND_SECRET"));
        assert!(full.contains("\"start_value\":\"2\""));
        assert!(full.contains("\"end_value\":\"CASE_BOUND_SECRET\""));
    }

    #[test]
    fn for_each_bindings_follow_source_disclosure_policy() {
        let analysis = crate::analyze::analyze(
            &[SourceUnit {
                name: "ForEach.bas".into(),
                text: "Public Sub Walk()\nDim collection As Variant\nDim SECRET_ITEM As Variant\nDim SECRET_COUNTER As Long\nFor Each SECRET_ITEM In collection\nNext SECRET_ITEM\nFor SECRET_COUNTER = 1 To 2\nNext SECRET_COUNTER\nEnd Sub\n".into(),
            }],
            &crate::analyze::AnalysisOptions::default(),
        )
        .unwrap();
        let structure = to_json(&analysis, None, Disclosure::StructureOnly);
        assert!(structure.contains("\"loop_control_variable_present\":true"));
        assert!(structure.contains("\"next_control_variable_present\":true"));
        assert!(structure.contains("\"loop_header_valid\":true"));
        assert!(structure.contains("\"loop_step_omitted\":true"));
        assert!(!structure.contains("SECRET_ITEM"));
        assert!(!structure.contains("SECRET_COUNTER"));

        let full = to_json(&analysis, None, Disclosure::IncludeSource);
        assert!(full.contains("\"loop_control_variable\":\"SECRET_ITEM\""));
        assert!(full.contains("\"next_control_variable\":\"SECRET_ITEM\""));
        assert!(full.contains("\"loop_control_variable\":\"SECRET_COUNTER\""));
        assert!(full.contains("\"next_control_variable\":\"SECRET_COUNTER\""));
        assert!(full.contains("\"loop_start\":\"1\""));
        assert!(full.contains("\"loop_end\":\"2\""));
    }

    #[test]
    fn implicit_type_rules_and_candidates_follow_disclosure_policy() {
        let analysis = crate::analyze::analyze(
            &[SourceUnit {
                name: "Implicit.bas".into(),
                text: "DefInt A-C\nPublic Function AddOne(amount)\nAddOne = amount + 1\nEnd Function\nPublic Sub S()\nDim amount\namount = 1\namountMissing = 2\nEnd Sub\n".into(),
            }],
            &crate::analyze::AnalysisOptions::default(),
        )
        .unwrap();
        let structure = to_json(&analysis, None, Disclosure::StructureOnly);
        assert!(structure.contains("\"letter_count\":3"));
        assert!(structure.contains("\"by_initial\":null"));
        assert!(!structure.contains("Integer"));
        assert!(!structure.contains("amountMissing"));

        let full = to_json(&analysis, None, Disclosure::IncludeSource);
        assert!(full.contains("\"A\":\"Integer\""));
        assert!(full.contains("\"effective_return_type\":\"Integer\""));
        assert!(full.contains("\"effective_type\":\"Integer\""));
        assert!(full.contains("\"implicit_type\":\"Integer\""));
        assert!(full.contains("amountMissing"));
    }

    #[test]
    fn deftype_rules_and_inferred_reference_types_follow_disclosure_policy() {
        let analysis = crate::analyze::analyze(
            &[SourceUnit {
                name: "ImplicitTypes.bas".into(),
                text: "DefInt A-C\nPublic Sub UseNames()\nDim amount\namount = 1\namountMissing = 2\nEnd Sub\n".into(),
            }],
            &crate::analyze::AnalysisOptions::default(),
        )
        .unwrap();

        let structure = to_json(&analysis, None, Disclosure::StructureOnly);
        assert!(
            structure.contains("\"implicit_type_rules\": {\"valid\":true,\"universal\":false,\"letter_count\":3,\"by_initial\":null}"),
            "{structure}"
        );
        assert!(!structure.contains("Integer"));
        assert!(!structure.contains("amountMissing"));

        let full = to_json(&analysis, None, Disclosure::IncludeSource);
        assert!(full.contains("\"A\":\"Integer\""));
        assert!(full.contains("\"implicit_type\":\"Integer\""));
        assert!(full.contains("amountMissing"));
    }

    #[test]
    fn array_lower_bounds_use_the_declaring_modules_option_base() {
        let analysis = crate::analyze::analyze(
            &[
                SourceUnit {
                    name: "OneBased.bas".into(),
                    text: "Option Base 1\nPublic values(UPPER_LIMIT) As Long\n".into(),
                },
                SourceUnit {
                    name: "ZeroBased.bas".into(),
                    text: "Public values(UPPER_LIMIT) As Long\n".into(),
                },
            ],
            &crate::analyze::AnalysisOptions::default(),
        )
        .unwrap();
        assert_eq!(analysis.project.modules[0].options.array_base, 1);
        assert_eq!(analysis.project.modules[1].options.array_base, 0);

        let structure = to_json(&analysis, None, Disclosure::StructureOnly);
        assert!(structure.contains("\"effective_lower_bound_expression\":\"1\""));
        assert!(structure.contains("\"effective_lower_bound_expression\":\"0\""));
    }

    #[test]
    fn invalid_option_base_does_not_claim_an_effective_implicit_bound() {
        let analysis = crate::analyze::analyze(
            &[SourceUnit {
                name: "InvalidBase.bas".into(),
                text: "Option Base 2\nPublic values(UPPER_LIMIT) As Long\n".into(),
            }],
            &crate::analyze::AnalysisOptions::default(),
        )
        .unwrap();
        assert!(!analysis.project.modules[0].options.array_base_valid);
        let report = to_json(&analysis, None, Disclosure::StructureOnly);
        assert!(report.contains("\"array_base_valid\":false"));
        assert!(report.contains("\"lower_bound_source\":\"invalid_module_option\""));
        assert!(report.contains("\"effective_lower_bound_expression\":null"));
    }

    #[test]
    fn redim_shapes_follow_option_base_and_keep_preserve_mode() {
        let analysis = crate::analyze::analyze(
            &[SourceUnit {
                name: "DynamicArrays.bas".into(),
                text: "Option Base 1\nPublic Sub Resize()\nDim values() As Long\nReDim values(UPPER_BOUND)\nReDim Preserve values(LOWER_BOUND To NEW_UPPER_BOUND)\nEnd Sub\n".into(),
            }],
            &crate::analyze::AnalysisOptions::default(),
        )
        .unwrap();
        let structure = to_json(&analysis, None, Disclosure::StructureOnly);
        assert!(structure.contains("\"effective_lower_bound_expression\":\"1\""));
        assert!(structure.contains("\"kind\":\"redim_preserve\""));
        assert!(!structure.contains("UPPER_BOUND"));
        assert!(!structure.contains("LOWER_BOUND"));

        let full = to_json(&analysis, None, Disclosure::IncludeSource);
        assert!(full.contains("NEW_UPPER_BOUND"));
    }

    #[test]
    fn erase_targets_keep_count_without_disclosing_names_by_default() {
        let analysis = crate::analyze::analyze(
            &[SourceUnit {
                name: "EraseArrays.bas".into(),
                text: "Public Sub Clear()\nDim first_array() As Long, second_array() As Long\nErase first_array, second_array\nEnd Sub\n".into(),
            }],
            &crate::analyze::AnalysisOptions::default(),
        )
        .unwrap();

        let structure = to_json(&analysis, None, Disclosure::StructureOnly);
        assert_eq!(structure.matches("\"kind\":\"erase_target\"").count(), 2);
        assert!(!structure.contains("first_array"));
        assert!(!structure.contains("second_array"));

        let full = to_json(&analysis, None, Disclosure::IncludeSource);
        assert!(full.contains("first_array"));
        assert!(full.contains("second_array"));
    }

    #[test]
    fn default_json_redacts_interface_dispatch_candidates() {
        let analysis = Analysis {
            calls: vec![CallFact {
                module: "Reader".into(),
                target: "GetName".into(),
                resolution: "interface_dispatch_candidate".into(),
                dispatch_candidates: vec!["Person.IName_GetName".into()],
                ..CallFact::default()
            }],
            ..Analysis::default()
        };
        let structure = to_json(&analysis, None, Disclosure::StructureOnly);
        assert!(!structure.contains("Person.IName_GetName"));
        assert!(structure.contains("\"dispatch_candidate_count\":1"));
        let full = to_json(&analysis, None, Disclosure::IncludeSource);
        assert!(full.contains("Person.IName_GetName"));
    }

    #[test]
    fn application_run_macro_candidates_follow_source_disclosure() {
        let analysis = crate::analyze::analyze(
            &[
                SourceUnit {
                    name: "Macros.bas".into(),
                    text: "Public Sub SensitiveMacro()\nEnd Sub\n".into(),
                },
                SourceUnit {
                    name: "Caller.bas".into(),
                    text: "Public Sub Run()\nApplication.Run \"SensitiveMacro\"\nEnd Sub\n".into(),
                },
            ],
            &crate::analyze::AnalysisOptions {
                host_profile: crate::host::HostProfile::Excel,
                ..crate::analyze::AnalysisOptions::default()
            },
        )
        .unwrap();

        let structure = to_json(&analysis, None, Disclosure::StructureOnly);
        assert!(structure.contains("\"dispatch_candidate_count\":1"));
        assert!(!structure.contains("SensitiveMacro"));
        assert!(!structure.contains("Macros.SensitiveMacro"));

        let full = to_json(&analysis, None, Disclosure::IncludeSource);
        assert!(full.contains("SensitiveMacro"));
        assert!(full.contains("Macros.SensitiveMacro"));
    }

    #[test]
    fn disasm_and_stomping_export_formats() {
        use crate::pcode::{
            DisassembledInstruction, DisassembledPCodeLine, DisassembledPCodeModule,
        };
        use crate::stomping::{
            ModuleStompingReport, ProjectStompingReport, StompingFinding, StompingFindingKind,
            StompingSeverity,
        };

        let module = DisassembledPCodeModule {
            module_name: "Module1".into(),
            lines: vec![DisassembledPCodeLine {
                line_number: 1,
                instructions: vec![DisassembledInstruction::simple(
                    0,
                    0x20,
                    0,
                    "Ld",
                    "0020 Ld MyVar",
                )],
                formatted_text: "Line #1:\n\t0020 Ld MyVar\n".into(),
            }],
            declared_procedures: vec!["Main".into()],
            called_procedures: vec!["MsgBox".into()],
            string_literals: vec!["Hello".into()],
            is_stomped_suspect: false,
        };

        // Test disasm JSON and Markdown
        let d_json = disasm_to_json(std::slice::from_ref(&module));
        assert!(d_json.contains("\"module_name\":\"Module1\""));
        assert!(d_json.contains("\"mnemonic\":\"Ld\""));

        let d_md = disasm_to_markdown(&[module]);
        assert!(d_md.contains("## Module: `Module1`"));
        assert!(d_md.contains("Main"));
        assert!(d_md.contains("0020 Ld MyVar"));

        // Test stomping JSON, SARIF, and Markdown
        let report = ProjectStompingReport {
            overall_severity: StompingSeverity::Critical,
            has_stomping: true,
            project_findings: vec![StompingFinding {
                severity: StompingSeverity::Medium,
                kind: StompingFindingKind::ProjectLockedOrUnviewable,
                description: "VBA project locked".into(),
            }],
            modules: vec![
                ModuleStompingReport {
                    module_name: "EvilMod".into(),
                    severity: StompingSeverity::Critical,
                    confidence_score: 95,
                    is_stomped: true,
                    findings: vec![
                        StompingFinding {
                            severity: StompingSeverity::Critical,
                            kind: StompingFindingKind::SourcePurged,
                            description: "Source code purged".into(),
                        },
                        StompingFinding {
                            severity: StompingSeverity::Critical,
                            kind: StompingFindingKind::HiddenGuiModule("EvilMod".into()),
                            description: "Module hidden from GUI".into(),
                        },
                    ],
                    source_procedure_count: 0,
                    pcode_procedure_count: 1,
                    source_line_count: 0,
                    pcode_line_count: 10,
                },
                ModuleStompingReport {
                    module_name: "PurgedMod".into(),
                    severity: StompingSeverity::Medium,
                    confidence_score: 35,
                    is_stomped: false,
                    findings: vec![StompingFinding {
                        severity: StompingSeverity::Medium,
                        kind: StompingFindingKind::PerformanceCachePurged { source_lines: 5 },
                        description: "Performance cache purged".into(),
                    }],
                    source_procedure_count: 1,
                    pcode_procedure_count: 0,
                    source_line_count: 5,
                    pcode_line_count: 0,
                },
            ],
        };

        let s_json = stomping_to_json(&report);
        assert!(s_json.contains("\"overall_severity\":\"critical\""));
        assert!(s_json.contains("\"source_purged\""));
        assert!(s_json.contains("\"hidden_gui_module\""));
        assert!(s_json.contains("\"performance_cache_purged\""));
        assert!(s_json.contains("\"project_locked_or_unviewable\""));

        let s_sarif = stomping_to_sarif(&report, "test.xlsm");
        assert!(s_sarif.contains("\"VBA-STOMP-001\""));
        assert!(s_sarif.contains("\"VBA-STOMP-007\""));
        assert!(s_sarif.contains("\"VBA-STOMP-008\""));
        assert!(s_sarif.contains("\"VBA-STOMP-009\""));
        assert!(s_sarif.contains("\"error\""));
        assert!(s_sarif.contains("test.xlsm"));

        let s_md = stomping_to_markdown(&report);
        assert!(s_md.contains("CRITICAL"));
        assert!(s_md.contains("EvilMod"));
        assert!(s_md.contains("PurgedMod"));
        assert!(s_md.contains("Project-Level Indicators"));
    }
}
