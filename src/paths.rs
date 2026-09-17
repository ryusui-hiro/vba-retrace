//! Bounded structural path enumeration and decision-table projection.

use crate::lexer::{TokenKind, lex};
use crate::model::{
    CallFact, ControlFlowGraph, ControlFlowPath, DataAccessFact, DataAccessPathFact,
    DataAccessPredicateFact, DataAccessValueFlowFact, DataFlowFact, DataFlowPathFact, DecisionRow,
    EntryPointFact, Expr, InterproceduralArgumentCompositionPathFact,
    InterproceduralArgumentValuePathFact, InterproceduralByRefValuePathFact,
    InterproceduralByRefWritePathFact, InterproceduralDataFlowPathFact,
    InterproceduralErrorPathFact, InterproceduralReturnCompositionPathFact, Limits, LiteralKind,
    Module, PathAliasDispatchFact, PathAliasFact, PathValueFlowFact, Procedure, Project, Statement,
};
use crate::parser::parse_expression_source;
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Clone, Debug, Default)]
pub struct DataFlowPathAssociations {
    pub facts: Vec<DataFlowPathFact>,
    pub truncated: bool,
    pub unassociated_count: usize,
}

#[derive(Clone, Debug, Default)]
pub struct PathValueFlowAnalysis {
    pub facts: Vec<PathValueFlowFact>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Default)]
pub struct DataAccessValueFlowAnalysis {
    pub facts: Vec<DataAccessValueFlowFact>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Default)]
pub struct DataAccessPredicateAnalysis {
    pub facts: Vec<DataAccessPredicateFact>,
    pub unassociated_count: usize,
}

#[derive(Clone, Debug, Default)]
pub struct InterproceduralDataFlowPathAnalysis {
    pub facts: Vec<InterproceduralDataFlowPathFact>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Default)]
pub struct InterproceduralArgumentValuePathAnalysis {
    pub facts: Vec<InterproceduralArgumentValuePathFact>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Default)]
pub struct InterproceduralArgumentCompositionPathAnalysis {
    pub facts: Vec<InterproceduralArgumentCompositionPathFact>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Default)]
pub struct InterproceduralReturnPathAnalysis {
    pub facts: Vec<crate::model::InterproceduralReturnPathFact>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Default)]
pub struct InterproceduralReturnCompositionPathAnalysis {
    pub facts: Vec<InterproceduralReturnCompositionPathFact>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Default)]
pub struct InterproceduralByRefWritePathAnalysis {
    pub facts: Vec<InterproceduralByRefWritePathFact>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Default)]
pub struct InterproceduralByRefValuePathAnalysis {
    pub facts: Vec<InterproceduralByRefValuePathFact>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Default)]
pub struct PathAliasAnalysis {
    pub facts: Vec<PathAliasFact>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Default)]
pub struct PathAliasDispatchAnalysis {
    pub facts: Vec<PathAliasDispatchFact>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Default)]
pub struct InterproceduralErrorPathAnalysis {
    pub facts: Vec<InterproceduralErrorPathFact>,
    pub truncated: bool,
}

/// Connect source-level transfer candidates to the bounded structural paths
/// that reach their statement. Conditions are collected only through the
/// target node; path feasibility remains explicitly unverified.
pub fn associate_data_flow_paths(
    data_flow: &[DataFlowFact],
    graphs: &[ControlFlowGraph],
    paths: &[ControlFlowPath],
    limit: usize,
    step_limit: usize,
) -> DataFlowPathAssociations {
    associate_path_facts(data_flow, graphs, paths, limit, step_limit, false)
}

fn associate_path_facts(
    data_flow: &[DataFlowFact],
    graphs: &[ControlFlowGraph],
    paths: &[ControlFlowPath],
    limit: usize,
    step_limit: usize,
    include_condition_nodes: bool,
) -> DataFlowPathAssociations {
    let mut flow_by_procedure: HashMap<(String, String), Vec<usize>> = HashMap::new();
    let mut procedure_order = Vec::new();
    for (index, fact) in data_flow.iter().enumerate() {
        let Some(procedure) = &fact.procedure else {
            continue;
        };
        let key = (fact.module.clone(), procedure.clone());
        if !flow_by_procedure.contains_key(&key) {
            procedure_order.push(key.clone());
        }
        flow_by_procedure.entry(key).or_default().push(index);
    }
    let mut paths_by_procedure: HashMap<(String, String), Vec<usize>> = HashMap::new();
    for (index, path) in paths.iter().enumerate() {
        paths_by_procedure
            .entry((path.module.clone(), path.procedure.clone()))
            .or_default()
            .push(index);
    }

    let mut result = DataFlowPathAssociations::default();
    let mut associated = vec![false; data_flow.len()];
    let mut steps = 0usize;
    for (module, procedure) in procedure_order {
        let flow_indices = &flow_by_procedure[&(module.clone(), procedure.clone())];
        let mut matching_graphs = graphs
            .iter()
            .filter(|graph| graph.module == module && graph.procedure == procedure);
        let Some(graph) = matching_graphs.next() else {
            continue;
        };
        if matching_graphs.next().is_some() {
            // Property accessors can share a name; without an identity key,
            // do not attach a transfer to the wrong accessor's graph.
            continue;
        }
        let Some(path_indices) = paths_by_procedure.get(&(module.clone(), procedure.clone()))
        else {
            continue;
        };
        for &data_flow_index in flow_indices {
            let fact = &data_flow[data_flow_index];
            if fact.span.start >= fact.span.end {
                continue;
            }
            let mut nodes = Vec::new();
            for node in &graph.nodes {
                if steps >= step_limit {
                    result.truncated = true;
                    result.unassociated_count = data_flow
                        .iter()
                        .enumerate()
                        .filter(|(index, fact)| fact.procedure.is_some() && !associated[*index])
                        .count();
                    return result;
                }
                steps += 1;
                let included = if fact.transfer == "loop_control_write_candidate" {
                    node.kind == "loop_test"
                } else if include_condition_nodes || fact.transfer == "expression_read_candidate" {
                    is_data_access_node(&node.kind)
                } else {
                    is_transfer_node(&node.kind)
                };
                if included && node.span.start <= fact.span.start && fact.span.end <= node.span.end
                {
                    nodes.push(node);
                }
            }
            let Some(minimum_span) = nodes
                .iter()
                .map(|node| node.span.end - node.span.start)
                .min()
            else {
                continue;
            };
            nodes.retain(|node| node.span.end - node.span.start == minimum_span);
            if nodes.len() != 1 {
                continue;
            }
            let node = nodes[0];
            for &path_index in path_indices {
                let path = &paths[path_index];
                for (path_position, &node_id) in path.nodes.iter().enumerate() {
                    if node_id != node.id {
                        continue;
                    }
                    let Some(conditions) = conditions_before_node(graph, path, path_position)
                    else {
                        continue;
                    };
                    if result.facts.len() >= limit {
                        result.truncated = true;
                        result.unassociated_count = data_flow
                            .iter()
                            .enumerate()
                            .filter(|(index, fact)| fact.procedure.is_some() && !associated[*index])
                            .count();
                        return result;
                    }
                    result.facts.push(DataFlowPathFact {
                        data_flow_index,
                        path_index,
                        path_position,
                        flow_node_id: node.id,
                        module: module.clone(),
                        procedure: procedure.clone(),
                        conditions,
                        feasibility: path.feasibility.clone(),
                        path_complete: path.complete,
                        span: fact.span,
                    });
                    associated[data_flow_index] = true;
                }
            }
        }
    }
    result.unassociated_count = data_flow
        .iter()
        .enumerate()
        .filter(|(index, fact)| fact.procedure.is_some() && !associated[*index])
        .count();
    result
}

pub fn associate_data_access_paths(
    data_accesses: &[DataAccessFact],
    graphs: &[ControlFlowGraph],
    paths: &[ControlFlowPath],
    limit: usize,
    step_limit: usize,
) -> DataFlowPathAssociations {
    let path_locators = data_accesses
        .iter()
        .map(|fact| DataFlowFact {
            module: fact.module.clone(),
            procedure: fact.procedure.clone(),
            span: fact.span,
            ..DataFlowFact::default()
        })
        .collect::<Vec<_>>();
    associate_path_facts(&path_locators, graphs, paths, limit, step_limit, true)
}

/// Connect direct, resolved procedure argument candidates to parameter reads
/// along bounded callee paths. Caller and callee paths remain separate; their
/// feasibility is not composed or proved.
pub fn associate_interprocedural_data_flow_paths(
    project: &Project,
    data_flow: &[DataFlowFact],
    associations: &[DataFlowPathFact],
    limit: usize,
    step_limit: usize,
) -> InterproceduralDataFlowPathAnalysis {
    type ParameterKey = (String, String, String);

    let mut result = InterproceduralDataFlowPathAnalysis::default();
    let mut steps = 0usize;
    let mut parameters = HashSet::<ParameterKey>::new();
    let mut parameter_display_names = HashMap::<ParameterKey, String>::new();
    let mut qualified_parameters: HashMap<String, Vec<ParameterKey>> = HashMap::new();
    for module in &project.modules {
        let module_name = canonical_data_name(&module.name);
        for procedure in &module.procedures {
            let procedure_name = canonical_data_name(&procedure.name);
            for parameter in &procedure.parameters {
                if steps >= step_limit {
                    result.truncated = true;
                    return result;
                }
                steps += 1;
                let parameter_name = canonical_data_name(&parameter.name);
                let key = (
                    module_name.clone(),
                    procedure_name.clone(),
                    parameter_name.clone(),
                );
                parameters.insert(key.clone());
                parameter_display_names
                    .entry(key.clone())
                    .or_insert_with(|| parameter.name.clone());
                qualified_parameters
                    .entry(canonical_data_name(&format!(
                        "{}.{}.{}",
                        module.name, procedure.name, parameter.name
                    )))
                    .or_default()
                    .push(key);
            }
        }
    }

    let mut associations_by_data_flow: HashMap<usize, Vec<&DataFlowPathFact>> = HashMap::new();
    for association in associations {
        if steps >= step_limit {
            result.truncated = true;
            return result;
        }
        steps += 1;
        associations_by_data_flow
            .entry(association.data_flow_index)
            .or_default()
            .push(association);
    }

    let mut parameter_uses: HashMap<ParameterKey, Vec<usize>> = HashMap::new();
    for (data_flow_index, fact) in data_flow.iter().enumerate() {
        let Some(procedure) = fact.procedure.as_deref() else {
            continue;
        };
        let module_name = canonical_data_name(&fact.module);
        let procedure_name = canonical_data_name(procedure);
        for input in &fact.inputs {
            if steps >= step_limit {
                result.truncated = true;
                return result;
            }
            steps += 1;
            let Some(input_name) = simple_variable_name(input) else {
                continue;
            };
            let key = (
                module_name.clone(),
                procedure_name.clone(),
                canonical_data_name(&input_name),
            );
            if parameters.contains(&key) {
                parameter_uses.entry(key).or_default().push(data_flow_index);
            }
        }
    }

    let mut seen = HashSet::new();
    for (argument_data_flow_index, argument_fact) in data_flow.iter().enumerate() {
        if argument_fact.transfer != "procedure_argument_input_candidate"
            && !argument_fact.transfer.starts_with("optional_")
        {
            continue;
        }
        if steps >= step_limit {
            result.truncated = true;
            return result;
        }
        steps += 1;
        let Some(qualified_parameters) =
            qualified_parameters.get(&canonical_data_name(&argument_fact.target))
        else {
            continue;
        };
        if qualified_parameters.len() != 1 {
            continue;
        }
        let parameter_key = &qualified_parameters[0];
        let Some(callee_use_indices) = parameter_uses.get(parameter_key) else {
            continue;
        };
        let Some(caller_path_associations) =
            associations_by_data_flow.get(&argument_data_flow_index)
        else {
            continue;
        };
        let Some(callee_module) = project
            .modules
            .iter()
            .find(|module| canonical_data_name(&module.name) == parameter_key.0)
        else {
            continue;
        };
        let Some(callee_procedure) = callee_module
            .procedures
            .iter()
            .find(|procedure| canonical_data_name(&procedure.name) == parameter_key.1)
        else {
            continue;
        };
        for &callee_use_data_flow_index in callee_use_indices {
            let Some(callee_path_associations) =
                associations_by_data_flow.get(&callee_use_data_flow_index)
            else {
                continue;
            };
            for caller_path in caller_path_associations {
                if caller_path.module != argument_fact.module
                    || caller_path.procedure
                        != argument_fact.procedure.as_deref().unwrap_or_default()
                {
                    continue;
                }
                for callee_path in callee_path_associations {
                    if steps >= step_limit {
                        result.truncated = true;
                        return result;
                    }
                    steps += 1;
                    if callee_path.module != callee_module.name
                        || callee_path.procedure != callee_procedure.name
                    {
                        continue;
                    }
                    let identity = (
                        argument_data_flow_index,
                        callee_use_data_flow_index,
                        caller_path.path_index,
                        callee_path.path_index,
                    );
                    if !seen.insert(identity) {
                        continue;
                    }
                    if result.facts.len() >= limit {
                        result.truncated = true;
                        return result;
                    }
                    result.facts.push(InterproceduralDataFlowPathFact {
                        argument_data_flow_index,
                        callee_use_data_flow_index,
                        caller_path_index: caller_path.path_index,
                        caller_path_position: caller_path.path_position,
                        callee_path_index: callee_path.path_index,
                        callee_path_position: callee_path.path_position,
                        caller_module: argument_fact.module.clone(),
                        caller_procedure: argument_fact.procedure.clone().unwrap_or_default(),
                        callee_module: callee_module.name.clone(),
                        callee_procedure: callee_procedure.name.clone(),
                        parameter: parameter_display_names
                            .get(parameter_key)
                            .cloned()
                            .unwrap_or_else(|| parameter_key.2.clone()),
                        caller_conditions: caller_path.conditions.clone(),
                        callee_conditions: callee_path.conditions.clone(),
                        feasibility: combined_path_feasibility(
                            &caller_path.conditions,
                            &callee_path.conditions,
                            &caller_path.feasibility,
                            &callee_path.feasibility,
                        ),
                        caller_path_complete: caller_path.path_complete,
                        callee_path_complete: callee_path.path_complete,
                    });
                }
            }
        }
    }
    result
}

/// Record caller-path snapshots for resolved procedure arguments. This is a
/// bounded evidence layer: it never invents a value for a mutable or
/// unsupported expression, and it records the caller conditions separately
/// from the callee's later path conditions.
#[allow(clippy::too_many_arguments)]
pub fn associate_interprocedural_argument_value_paths(
    project: &Project,
    calls: &[CallFact],
    data_flow: &[DataFlowFact],
    associations: &[DataFlowPathFact],
    graphs: &[ControlFlowGraph],
    paths: &[ControlFlowPath],
    static_parameter_values: &StaticParameterValues,
    limit: usize,
    step_limit: usize,
) -> InterproceduralArgumentValuePathAnalysis {
    let mut result = InterproceduralArgumentValuePathAnalysis::default();
    let mut associations_by_flow: HashMap<usize, Vec<&DataFlowPathFact>> = HashMap::new();
    let mut steps = 0usize;
    for association in associations {
        if steps >= step_limit {
            result.truncated = true;
            return result;
        }
        steps += 1;
        associations_by_flow
            .entry(association.data_flow_index)
            .or_default()
            .push(association);
    }

    for (argument_index, argument_fact) in data_flow.iter().enumerate() {
        let optional_variant_omission =
            argument_fact.transfer == "optional_variant_omission_error_448_candidate";
        if argument_fact.transfer != "procedure_argument_input_candidate"
            && !optional_variant_omission
        {
            continue;
        }
        let mut target_parts = argument_fact.target.split('.');
        let (Some(callee_module_name), Some(callee_procedure_name), Some(parameter_name)) = (
            target_parts.next(),
            target_parts.next(),
            target_parts.next(),
        ) else {
            continue;
        };
        if target_parts.next().is_some() {
            continue;
        }
        let Some(callee_module) = project.modules.iter().find(|module| {
            canonical_data_name(&module.name) == canonical_data_name(callee_module_name)
        }) else {
            continue;
        };
        let Some(callee_procedure) = callee_module.procedures.iter().find(|procedure| {
            canonical_data_name(&procedure.name) == canonical_data_name(callee_procedure_name)
        }) else {
            continue;
        };
        let Some(parameter_index) = callee_procedure.parameters.iter().position(|parameter| {
            canonical_data_name(&parameter.name) == canonical_data_name(parameter_name)
        }) else {
            continue;
        };
        let Some((caller_call_index, call)) = calls.iter().enumerate().find(|(_, call)| {
            call.module.eq_ignore_ascii_case(&argument_fact.module)
                && call.procedure.as_deref() == argument_fact.procedure.as_deref()
                && call.span == argument_fact.span
                && canonical_data_name(&call.target) == canonical_data_name(callee_procedure_name)
        }) else {
            continue;
        };
        let actual_expressions = if optional_variant_omission {
            // The omission itself has no source expression.  Keep a synthetic
            // slot so the caller path and callsite index can still be carried
            // into the callee; composition will inject IsMissing rather than
            // attempting to seed a value.
            vec![(None, String::new())]
        } else {
            let Some(actual_expressions) = argument_expressions_for_parameter(
                &callee_procedure.parameters,
                &call.arguments,
                parameter_index,
            ) else {
                continue;
            };
            actual_expressions
        };
        let actual_expressions = if callee_procedure.parameters[parameter_index].is_param_array {
            let Some(actual) = argument_fact.value_expression.as_deref() else {
                continue;
            };
            if let Some(slot) = argument_fact.argument_slot_index {
                actual_expressions
                    .into_iter()
                    .filter(|(candidate_slot, _)| *candidate_slot == Some(slot))
                    .collect::<Vec<_>>()
            } else {
                actual_expressions
                    .into_iter()
                    .filter(|(_, expression)| expression.eq_ignore_ascii_case(actual))
                    .collect::<Vec<_>>()
            }
        } else {
            actual_expressions
        };
        if actual_expressions.is_empty() {
            continue;
        }
        for (argument_slot_index, actual_expression) in actual_expressions {
            let Some(caller_procedure_name) = argument_fact.procedure.as_deref() else {
                continue;
            };
            let Some(caller_module) = project
                .modules
                .iter()
                .find(|module| module.name.eq_ignore_ascii_case(&argument_fact.module))
            else {
                continue;
            };
            let Some(caller_procedure) = caller_module
                .procedures
                .iter()
                .find(|procedure| procedure.name.eq_ignore_ascii_case(caller_procedure_name))
            else {
                continue;
            };
            let Some(graph) = graphs.iter().find(|graph| {
                graph.module.eq_ignore_ascii_case(&argument_fact.module)
                    && graph.procedure.eq_ignore_ascii_case(caller_procedure_name)
            }) else {
                continue;
            };
            let Some(path_associations) = associations_by_flow.get(&argument_index) else {
                continue;
            };
            let caller_module_index = unique_project_module_index(project, caller_module);
            for association in path_associations {
                if steps >= step_limit {
                    result.truncated = true;
                    return result;
                }
                steps += 1;
                let Some(path) = paths.get(association.path_index) else {
                    continue;
                };
                if association.path_position > path.nodes.len()
                    || !path_value_tracking_is_supported(graph, &path.nodes)
                {
                    continue;
                }
                let Some(module_index) = caller_module_index else {
                    continue;
                };
                let context = ProcedurePathContext {
                    project: Some(project),
                    module: caller_module,
                    procedure: caller_procedure,
                    call_facts: Some(calls),
                    path_values: None,
                    callsite_parameter_values: Some(static_parameter_values),
                    param_array_lengths: None,
                    array_shapes: None,
                    optional_missing: None,
                };
                let (snapshots, caller_array_shapes) = snapshot_values_before_path_position(
                    graph,
                    path,
                    association.path_position,
                    context,
                );
                if optional_variant_omission {
                    if result.facts.len() >= limit {
                        result.truncated = true;
                        return result;
                    }
                    result.facts.push(InterproceduralArgumentValuePathFact {
                        argument_data_flow_index: argument_index,
                        argument_slot_index,
                        caller_call_index: Some(caller_call_index),
                        caller_path_index: association.path_index,
                        caller_path_position: association.path_position,
                        caller_module: argument_fact.module.clone(),
                        caller_procedure: caller_procedure.name.clone(),
                        callee_module: callee_module.name.clone(),
                        callee_procedure: callee_procedure.name.clone(),
                        parameter: callee_procedure.parameters[parameter_index].name.clone(),
                        actual_expression: None,
                        resolved_value: None,
                        resolution: "caller_path_optional_missing".into(),
                        conditions: association.conditions.clone(),
                        feasibility: association.feasibility.clone(),
                        path_complete: association.path_complete,
                    });
                    continue;
                }
                let Some(expression) = parse_expression_source(&actual_expression) else {
                    continue;
                };
                let mut resolving = HashSet::new();
                let effective_expression = if let Expr::Identifier(name, _) = &expression {
                    snapshots
                        .get(&canon_flow(name))
                        .cloned()
                        .unwrap_or(expression.clone())
                } else {
                    expression.clone()
                };
                let value_context = ProcedurePathContext {
                    path_values: Some(&snapshots),
                    array_shapes: Some(&caller_array_shapes),
                    ..context
                };
                let value = evaluate_literal_branch_value_in_context(
                    &effective_expression,
                    0,
                    Some(value_context),
                    &mut resolving,
                    false,
                );
                let (resolution, resolved_value) = match value {
                    Some(value) => ("caller_path_snapshot", Some(literal_value_display(&value))),
                    None => ("unresolved_caller_path_value", None),
                };
                if result.facts.len() >= limit {
                    result.truncated = true;
                    return result;
                }
                let _ = module_index;
                result.facts.push(InterproceduralArgumentValuePathFact {
                    argument_data_flow_index: argument_index,
                    argument_slot_index,
                    caller_call_index: Some(caller_call_index),
                    caller_path_index: association.path_index,
                    caller_path_position: association.path_position,
                    caller_module: argument_fact.module.clone(),
                    caller_procedure: caller_procedure.name.clone(),
                    callee_module: callee_module.name.clone(),
                    callee_procedure: callee_procedure.name.clone(),
                    parameter: callee_procedure.parameters[parameter_index].name.clone(),
                    actual_expression: Some(actual_expression.clone()),
                    resolved_value,
                    resolution: resolution.into(),
                    conditions: association.conditions.clone(),
                    feasibility: association.feasibility.clone(),
                    path_complete: association.path_complete,
                });
            }
        }
    }
    result
}

/// Compose caller-path argument snapshots with each callee CFG path. The
/// composition is deliberately evidence-oriented: caller and callee paths
/// remain separately visible, while a branch is marked infeasible only when
/// either side has a supported contradiction.
#[allow(clippy::too_many_arguments)]
pub fn compose_interprocedural_argument_value_paths(
    project: &Project,
    value_facts: &[InterproceduralArgumentValuePathFact],
    graphs: &[ControlFlowGraph],
    paths: &[ControlFlowPath],
    calls: &[CallFact],
    static_parameter_values: &StaticParameterValues,
    limit: usize,
    step_limit: usize,
) -> InterproceduralArgumentCompositionPathAnalysis {
    let mut result = InterproceduralArgumentCompositionPathAnalysis::default();
    let mut steps = 0usize;
    for value_fact in value_facts {
        if steps >= step_limit {
            result.truncated = true;
            return result;
        }
        steps += 1;
        let Some(callee_module) = project
            .modules
            .iter()
            .find(|module| module.name.eq_ignore_ascii_case(&value_fact.callee_module))
        else {
            continue;
        };
        let Some(callee_procedure) = callee_module.procedures.iter().find(|procedure| {
            procedure
                .name
                .eq_ignore_ascii_case(&value_fact.callee_procedure)
        }) else {
            continue;
        };
        let Some(parameter) = callee_procedure
            .parameters
            .iter()
            .find(|parameter| parameter.name.eq_ignore_ascii_case(&value_fact.parameter))
        else {
            continue;
        };
        let optional_variant = parameter.optional
            && parameter.default_value.is_none()
            && parameter
                .type_name
                .as_deref()
                .is_some_and(|type_name| type_name.eq_ignore_ascii_case("Variant"));
        if (parameter.is_array
            || (!parameter.passing.eq_ignore_ascii_case("byval") && !optional_variant))
            && !parameter.is_param_array
        {
            continue;
        }
        let Some(graph) = graphs.iter().find(|graph| {
            graph.module.eq_ignore_ascii_case(&callee_module.name)
                && graph.procedure.eq_ignore_ascii_case(&callee_procedure.name)
        }) else {
            continue;
        };
        let mut seed = static_parameter_values.clone();
        let mut param_array_lengths = StaticParamArrayLengths::new();
        if parameter.is_param_array {
            let length = value_facts
                .iter()
                .filter(|candidate| {
                    candidate.caller_path_index == value_fact.caller_path_index
                        && candidate.caller_path_position == value_fact.caller_path_position
                        && candidate
                            .caller_module
                            .eq_ignore_ascii_case(&value_fact.caller_module)
                        && candidate
                            .caller_procedure
                            .eq_ignore_ascii_case(&value_fact.caller_procedure)
                        && candidate
                            .callee_module
                            .eq_ignore_ascii_case(&value_fact.callee_module)
                        && candidate
                            .callee_procedure
                            .eq_ignore_ascii_case(&value_fact.callee_procedure)
                        && candidate
                            .parameter
                            .eq_ignore_ascii_case(&value_fact.parameter)
                })
                .filter_map(|candidate| candidate.argument_slot_index)
                .max()
                .and_then(|slot| slot.checked_add(1))
                .unwrap_or(0);
            param_array_lengths.insert(
                (
                    canonical_data_name(&callee_module.name),
                    canonical_data_name(&callee_procedure.name),
                    canonical_data_name(&value_fact.parameter),
                ),
                length,
            );
        }
        let mut optional_missing = HashSet::new();
        if let Some(call_index) = value_fact.caller_call_index
            && let Some(call) = calls.get(call_index)
        {
            for (parameter_index, candidate) in callee_procedure.parameters.iter().enumerate() {
                if !candidate.optional
                    || candidate.is_param_array
                    || candidate.default_value.is_some()
                    || !candidate
                        .type_name
                        .as_deref()
                        .is_some_and(|type_name| type_name.eq_ignore_ascii_case("Variant"))
                {
                    continue;
                }
                if argument_supplies_parameter(
                    &callee_procedure.parameters,
                    &call.arguments,
                    parameter_index,
                ) == Some(false)
                {
                    optional_missing.insert(canonical_data_name(&candidate.name));
                }
            }
        }
        if !parameter.is_param_array {
            if value_fact.resolution != "caller_path_optional_missing" {
                let Some(value_text) = value_fact.resolved_value.as_deref() else {
                    continue;
                };
                let Some(value_expression) = parse_expression_source(value_text) else {
                    continue;
                };
                seed.entry((
                    canonical_data_name(&callee_module.name),
                    canonical_data_name(&callee_procedure.name),
                ))
                .or_default()
                .insert(canonical_data_name(&value_fact.parameter), value_expression);
            } else if !optional_variant {
                // An omission marker is meaningful only for the exact
                // Optional Variant case.  Other unresolved/default forms must
                // remain uncomposed rather than being treated as missing.
                continue;
            }
        }
        for (callee_path_index, callee_path) in paths.iter().enumerate().filter(|(_, path)| {
            path.module.eq_ignore_ascii_case(&callee_module.name)
                && path.procedure.eq_ignore_ascii_case(&callee_procedure.name)
        }) {
            if steps >= step_limit {
                result.truncated = true;
                return result;
            }
            steps += 1;
            let Some(callee_path_module) = project
                .modules
                .iter()
                .find(|module| module.name.eq_ignore_ascii_case(&callee_path.module))
            else {
                continue;
            };
            let Some(callee_path_procedure) = callee_path_module
                .procedures
                .iter()
                .find(|procedure| procedure.name.eq_ignore_ascii_case(&callee_path.procedure))
            else {
                continue;
            };
            let context = ProcedurePathContext {
                project: Some(project),
                module: callee_path_module,
                procedure: callee_path_procedure,
                call_facts: Some(calls),
                path_values: None,
                callsite_parameter_values: Some(&seed),
                param_array_lengths: Some(&param_array_lengths),
                array_shapes: None,
                optional_missing: Some(&optional_missing),
            };
            let callee_infeasible = path_has_infeasible_condition(
                graph,
                &callee_path.nodes,
                &callee_path.conditions,
                Some(context),
            );
            let feasibility = if value_fact.feasibility == "infeasible_constant_condition"
                || callee_infeasible
                || callee_path.feasibility == "infeasible_constant_condition"
            {
                "infeasible_constant_condition"
            } else {
                "not_checked"
            };
            if result.facts.len() >= limit {
                result.truncated = true;
                return result;
            }
            result
                .facts
                .push(InterproceduralArgumentCompositionPathFact {
                    argument_data_flow_index: value_fact.argument_data_flow_index,
                    argument_slot_index: value_fact.argument_slot_index,
                    caller_call_index: value_fact.caller_call_index,
                    caller_path_index: value_fact.caller_path_index,
                    caller_path_position: value_fact.caller_path_position,
                    callee_path_index,
                    callee_path_position: callee_path.nodes.len().saturating_sub(1),
                    caller_module: value_fact.caller_module.clone(),
                    caller_procedure: value_fact.caller_procedure.clone(),
                    callee_module: value_fact.callee_module.clone(),
                    callee_procedure: value_fact.callee_procedure.clone(),
                    parameter: value_fact.parameter.clone(),
                    actual_expression: value_fact.actual_expression.clone(),
                    resolved_value: value_fact.resolved_value.clone(),
                    caller_conditions: value_fact.conditions.clone(),
                    callee_conditions: callee_path.conditions.clone(),
                    caller_feasibility: value_fact.feasibility.clone(),
                    callee_feasibility: callee_path.feasibility.clone(),
                    feasibility: feasibility.into(),
                    caller_path_complete: value_fact.path_complete,
                    callee_path_complete: callee_path.complete,
                });
        }
    }
    result
}

fn snapshot_values_before_path_position(
    graph: &ControlFlowGraph,
    path: &ControlFlowPath,
    path_position: usize,
    context: ProcedurePathContext<'_>,
) -> (HashMap<String, Expr>, StaticArrayShapes) {
    let key = (
        canonical_data_name(&context.module.name),
        canonical_data_name(&context.procedure.name),
    );
    let mut values = context
        .callsite_parameter_values
        .and_then(|seed| seed.get(&key))
        .cloned()
        .unwrap_or_default();
    let mut array_shapes = StaticArrayShapes::new();
    for node_id in path.nodes.iter().take(path_position) {
        if let Some(node) = graph.nodes.get(*node_id) {
            update_path_value_state(node, context, &mut values, &mut array_shapes);
        }
    }
    (values, array_shapes)
}

fn literal_value_display(value: &LiteralBranchValue) -> String {
    match value {
        LiteralBranchValue::Boolean(value) => value.to_string(),
        LiteralBranchValue::Integer(value) => value.to_string(),
        LiteralBranchValue::Date(value) => format!("CDate({})", branch_date_to_serial(*value)),
        LiteralBranchValue::String(value) => format!("\"{value}\""),
        LiteralBranchValue::Null => "Null".into(),
        LiteralBranchValue::Empty => "Empty".into(),
    }
}

/// Connect a caller's function-return candidate to the callee's return-value
/// definitions. The relation is path-annotated on both sides, but it does not
/// claim that the two paths are jointly feasible.
pub fn associate_interprocedural_return_paths(
    data_flow: &[DataFlowFact],
    associations: &[DataFlowPathFact],
    graphs: &[ControlFlowGraph],
    paths: &[ControlFlowPath],
    project: &Project,
    limit: usize,
    step_limit: usize,
) -> InterproceduralReturnPathAnalysis {
    let mut result = InterproceduralReturnPathAnalysis::default();
    let mut steps = 0usize;
    let mut paths_by_data_flow: HashMap<usize, Vec<&DataFlowPathFact>> = HashMap::new();
    for association in associations {
        if steps >= step_limit {
            result.truncated = true;
            return result;
        }
        steps += 1;
        paths_by_data_flow
            .entry(association.data_flow_index)
            .or_default()
            .push(association);
    }

    let mut return_definitions: HashMap<(String, String), Vec<usize>> = HashMap::new();
    for (index, fact) in data_flow.iter().enumerate() {
        if steps >= step_limit {
            result.truncated = true;
            return result;
        }
        steps += 1;
        let Some(procedure) = fact.procedure.as_deref() else {
            continue;
        };
        if canon_flow(&fact.target) != canon_flow(procedure)
            || !matches!(
                fact.transfer.as_str(),
                "assignment" | "object_assignment" | "function_return_candidate"
            )
        {
            continue;
        }
        return_definitions
            .entry((canon_flow(&fact.module), canon_flow(procedure)))
            .or_default()
            .push(index);
    }

    let mut seen = HashSet::new();
    for (caller_return_index, caller_return) in data_flow.iter().enumerate() {
        if steps >= step_limit {
            result.truncated = true;
            return result;
        }
        steps += 1;
        if caller_return.transfer != "function_return_candidate" {
            continue;
        }
        let (Some(callee_module), Some(callee_procedure)) = (
            caller_return.call_callee_module.as_deref(),
            caller_return.call_callee_procedure.as_deref(),
        ) else {
            continue;
        };
        let key = (canon_flow(callee_module), canon_flow(callee_procedure));
        let Some(callee_return_indices) = return_definitions.get(&key) else {
            continue;
        };
        let Some(caller_path_associations) = paths_by_data_flow.get(&caller_return_index) else {
            continue;
        };
        for &callee_return_index in callee_return_indices {
            let Some(callee_path_associations) = paths_by_data_flow.get(&callee_return_index)
            else {
                continue;
            };
            for caller_path in caller_path_associations {
                if caller_path.module != caller_return.module
                    || caller_path.procedure
                        != caller_return.procedure.as_deref().unwrap_or_default()
                {
                    continue;
                }
                for callee_path in callee_path_associations {
                    if steps >= step_limit {
                        result.truncated = true;
                        return result;
                    }
                    steps += 1;
                    if callee_path.module != callee_module
                        || callee_path.procedure != callee_procedure
                    {
                        continue;
                    }
                    let identity = (
                        caller_return_index,
                        callee_return_index,
                        caller_path.path_index,
                        callee_path.path_index,
                    );
                    if !seen.insert(identity) {
                        continue;
                    }
                    if result.facts.len() >= limit {
                        result.truncated = true;
                        return result;
                    }
                    let (caller_post_return_conditions, post_return_feasibility) =
                        post_return_condition_evidence(
                            project,
                            data_flow,
                            caller_return_index,
                            callee_return_index,
                            caller_path.path_index,
                            caller_path.path_position,
                            graphs,
                            paths,
                        );
                    result
                        .facts
                        .push(crate::model::InterproceduralReturnPathFact {
                            caller_return_data_flow_index: caller_return_index,
                            callee_return_data_flow_index: callee_return_index,
                            caller_path_index: caller_path.path_index,
                            caller_path_position: caller_path.path_position,
                            callee_path_index: callee_path.path_index,
                            callee_path_position: callee_path.path_position,
                            caller_module: caller_return.module.clone(),
                            caller_procedure: caller_return.procedure.clone().unwrap_or_default(),
                            callee_module: callee_module.to_owned(),
                            callee_procedure: callee_procedure.to_owned(),
                            caller_conditions: caller_path.conditions.clone(),
                            callee_conditions: callee_path.conditions.clone(),
                            callee_return_expression: data_flow
                                .get(callee_return_index)
                                .and_then(|fact| fact.value_expression.clone()),
                            resolved_return_value: data_flow
                                .get(callee_return_index)
                                .and_then(|fact| fact.value_expression.as_deref())
                                .and_then(|expression| {
                                    evaluate_static_return_expression(
                                        project,
                                        callee_module,
                                        callee_procedure,
                                        expression,
                                    )
                                }),
                            caller_post_return_conditions,
                            post_return_feasibility,
                            feasibility: combined_path_feasibility(
                                &caller_path.conditions,
                                &callee_path.conditions,
                                &caller_path.feasibility,
                                &callee_path.feasibility,
                            ),
                            caller_path_complete: caller_path.path_complete,
                            callee_path_complete: callee_path.path_complete,
                        });
                }
            }
        }
    }
    result
}

/// Compose two adjacent direct return relations (outer caller -> wrapper and
/// wrapper -> leaf callee). The wrapper path is retained as its own evidence;
/// no claim is made that independently enumerated wrapper paths are the same
/// runtime activation. A bounded two-hop relation is preferable to silently
/// collapsing a longer dynamic call chain.
pub fn compose_interprocedural_return_paths(
    direct: &[crate::model::InterproceduralReturnPathFact],
    data_flow: &[DataFlowFact],
    graphs: &[ControlFlowGraph],
    paths: &[ControlFlowPath],
    project: &Project,
    limit: usize,
    step_limit: usize,
) -> InterproceduralReturnCompositionPathAnalysis {
    let mut result = InterproceduralReturnCompositionPathAnalysis::default();
    let mut by_caller: HashMap<usize, Vec<&crate::model::InterproceduralReturnPathFact>> =
        HashMap::new();
    let mut steps = 0usize;
    for fact in direct {
        if steps >= step_limit {
            result.truncated = true;
            return result;
        }
        steps += 1;
        by_caller
            .entry(fact.caller_return_data_flow_index)
            .or_default()
            .push(fact);
    }
    for outer in direct {
        let Some(inner_candidates) = by_caller.get(&outer.callee_return_data_flow_index) else {
            continue;
        };
        for inner in inner_candidates {
            if steps >= step_limit {
                result.truncated = true;
                return result;
            }
            steps += 1;
            if !outer
                .callee_module
                .eq_ignore_ascii_case(&inner.caller_module)
                || !outer
                    .callee_procedure
                    .eq_ignore_ascii_case(&inner.caller_procedure)
            {
                continue;
            }
            if outer.caller_return_data_flow_index == inner.callee_return_data_flow_index {
                continue;
            }
            if result.facts.len() >= limit {
                result.truncated = true;
                return result;
            }
            let mut all_conditions = outer.caller_conditions.clone();
            all_conditions.extend(outer.callee_conditions.iter().cloned());
            all_conditions.extend(inner.caller_conditions.iter().cloned());
            all_conditions.extend(inner.callee_conditions.iter().cloned());
            let feasibility = if outer.feasibility == "infeasible_constant_condition"
                || inner.feasibility == "infeasible_constant_condition"
                || all_conditions
                    .iter()
                    .any(|condition| evaluate_literal_branch_condition(condition) == Some(false))
            {
                "infeasible_constant_condition"
            } else {
                "not_checked"
            };
            let (outer_post_return_conditions, post_return_feasibility) =
                post_return_condition_evidence(
                    project,
                    data_flow,
                    outer.caller_return_data_flow_index,
                    inner.callee_return_data_flow_index,
                    outer.caller_path_index,
                    outer.caller_path_position,
                    graphs,
                    paths,
                );
            result.facts.push(InterproceduralReturnCompositionPathFact {
                outer_return_data_flow_index: outer.caller_return_data_flow_index,
                inner_return_data_flow_index: inner.callee_return_data_flow_index,
                composition_depth: 2,
                outer_path_index: outer.caller_path_index,
                outer_path_position: outer.caller_path_position,
                intermediate_path_index: outer.callee_path_index,
                intermediate_path_position: outer.callee_path_position,
                inner_path_index: inner.callee_path_index,
                inner_path_position: inner.callee_path_position,
                outer_module: outer.caller_module.clone(),
                outer_procedure: outer.caller_procedure.clone(),
                intermediate_module: outer.callee_module.clone(),
                intermediate_procedure: outer.callee_procedure.clone(),
                inner_module: inner.callee_module.clone(),
                inner_procedure: inner.callee_procedure.clone(),
                outer_conditions: outer.caller_conditions.clone(),
                intermediate_conditions: outer.callee_conditions.clone(),
                inner_conditions: inner.callee_conditions.clone(),
                inner_return_expression: inner.callee_return_expression.clone(),
                resolved_return_value: inner.resolved_return_value.clone().or_else(|| {
                    inner
                        .callee_return_expression
                        .as_deref()
                        .and_then(|expression| {
                            evaluate_static_return_expression(
                                project,
                                &inner.callee_module,
                                &inner.callee_procedure,
                                expression,
                            )
                        })
                }),
                outer_post_return_conditions,
                post_return_feasibility,
                feasibility: feasibility.into(),
                outer_path_complete: outer.caller_path_complete,
                intermediate_path_complete: outer.callee_path_complete
                    && inner.caller_path_complete,
                inner_path_complete: inner.callee_path_complete,
                chain_return_data_flow_indices: vec![
                    outer.caller_return_data_flow_index,
                    outer.callee_return_data_flow_index,
                    inner.callee_return_data_flow_index,
                ],
                chain_modules: vec![
                    outer.caller_module.clone(),
                    outer.callee_module.clone(),
                    inner.callee_module.clone(),
                ],
                chain_procedures: vec![
                    outer.caller_procedure.clone(),
                    outer.callee_procedure.clone(),
                    inner.callee_procedure.clone(),
                ],
                chain_path_indices: vec![
                    outer.caller_path_index,
                    outer.callee_path_index,
                    inner.callee_path_index,
                ],
                chain_path_positions: vec![
                    outer.caller_path_position,
                    outer.callee_path_position,
                    inner.callee_path_position,
                ],
                chain_conditions: vec![
                    outer.caller_conditions.clone(),
                    outer.callee_conditions.clone(),
                    inner.callee_conditions.clone(),
                ],
                chain_path_complete: vec![
                    outer.caller_path_complete,
                    outer.callee_path_complete && inner.caller_path_complete,
                    inner.callee_path_complete,
                ],
            });
        }
    }
    result
}

/// Extend the two-hop return relations with bounded longer wrapper chains.
/// Every direct edge remains available, while a chain fact retains each
/// procedure/path identity in explicit vectors. This never proves that the
/// independently enumerated activations execute together.
#[allow(clippy::too_many_arguments)]
pub fn extend_interprocedural_return_chains(
    direct: &[crate::model::InterproceduralReturnPathFact],
    compositions: &mut Vec<InterproceduralReturnCompositionPathFact>,
    data_flow: &[DataFlowFact],
    graphs: &[ControlFlowGraph],
    paths: &[ControlFlowPath],
    project: &Project,
    limit: usize,
    step_limit: usize,
    max_depth: usize,
) -> bool {
    if max_depth <= 2 || direct.is_empty() {
        return false;
    }
    let mut by_caller = HashMap::<usize, Vec<usize>>::new();
    for (index, fact) in direct.iter().enumerate() {
        by_caller
            .entry(fact.caller_return_data_flow_index)
            .or_default()
            .push(index);
    }
    let mut queue = VecDeque::<Vec<usize>>::new();
    for index in 0..direct.len() {
        queue.push_back(vec![index]);
    }
    let mut steps = 0usize;
    while let Some(chain) = queue.pop_front() {
        if steps >= step_limit {
            return true;
        }
        steps += 1;
        let Some(last_index) = chain.last().copied() else {
            continue;
        };
        let last = &direct[last_index];
        if chain.len() >= max_depth {
            continue;
        }
        let Some(next_indices) = by_caller.get(&last.callee_return_data_flow_index) else {
            continue;
        };
        for &next_index in next_indices {
            if steps >= step_limit {
                return true;
            }
            steps += 1;
            let next = &direct[next_index];
            if !last.callee_module.eq_ignore_ascii_case(&next.caller_module)
                || !last
                    .callee_procedure
                    .eq_ignore_ascii_case(&next.caller_procedure)
            {
                continue;
            }
            if chain.contains(&next_index) {
                continue;
            }
            let mut extended = chain.clone();
            extended.push(next_index);
            if extended.len() >= 3 {
                if compositions.len() >= limit {
                    return true;
                }
                let first = &direct[extended[0]];
                let leaf = &direct[*extended.last().expect("extended chain is non-empty")];
                let mut chain_return_data_flow_indices = vec![first.caller_return_data_flow_index];
                let mut chain_modules = vec![first.caller_module.clone()];
                let mut chain_procedures = vec![first.caller_procedure.clone()];
                let mut chain_path_indices = vec![first.caller_path_index];
                let mut chain_path_positions = vec![first.caller_path_position];
                let mut chain_path_complete = vec![first.caller_path_complete];
                let mut chain_conditions = vec![first.caller_conditions.clone()];
                for &edge_index in &extended {
                    let edge = &direct[edge_index];
                    chain_return_data_flow_indices.push(edge.callee_return_data_flow_index);
                    chain_modules.push(edge.callee_module.clone());
                    chain_procedures.push(edge.callee_procedure.clone());
                    chain_path_indices.push(edge.callee_path_index);
                    chain_path_positions.push(edge.callee_path_position);
                    chain_path_complete.push(edge.callee_path_complete);
                    let mut conditions = edge.caller_conditions.clone();
                    conditions.extend(edge.callee_conditions.iter().cloned());
                    chain_conditions.push(conditions);
                }
                let intermediate_conditions = extended
                    .iter()
                    .take(extended.len().saturating_sub(1))
                    .flat_map(|index| {
                        direct[*index]
                            .caller_conditions
                            .iter()
                            .chain(direct[*index].callee_conditions.iter())
                            .cloned()
                    })
                    .collect::<Vec<_>>();
                let mut feasibility = "not_checked";
                if extended.iter().any(|index| {
                    let edge = &direct[*index];
                    edge.feasibility == "infeasible_constant_condition"
                        || edge
                            .caller_conditions
                            .iter()
                            .chain(edge.callee_conditions.iter())
                            .any(|condition| {
                                evaluate_literal_branch_condition(condition) == Some(false)
                            })
                }) {
                    feasibility = "infeasible_constant_condition";
                }
                let (outer_post_return_conditions, post_return_feasibility) =
                    post_return_condition_evidence(
                        project,
                        data_flow,
                        first.caller_return_data_flow_index,
                        leaf.callee_return_data_flow_index,
                        first.caller_path_index,
                        first.caller_path_position,
                        graphs,
                        paths,
                    );
                let mut inner_post_feasibility = post_return_feasibility;
                if feasibility == "infeasible_constant_condition" {
                    inner_post_feasibility = feasibility.to_owned();
                }
                let resolved_return_value = leaf.resolved_return_value.clone().or_else(|| {
                    leaf.callee_return_expression
                        .as_deref()
                        .and_then(|expression| {
                            evaluate_static_return_expression(
                                project,
                                &leaf.callee_module,
                                &leaf.callee_procedure,
                                expression,
                            )
                        })
                });
                compositions.push(InterproceduralReturnCompositionPathFact {
                    outer_return_data_flow_index: first.caller_return_data_flow_index,
                    inner_return_data_flow_index: leaf.callee_return_data_flow_index,
                    composition_depth: extended.len(),
                    outer_path_index: first.caller_path_index,
                    outer_path_position: first.caller_path_position,
                    intermediate_path_index: direct[extended[0]].callee_path_index,
                    intermediate_path_position: direct[extended[0]].callee_path_position,
                    inner_path_index: leaf.callee_path_index,
                    inner_path_position: leaf.callee_path_position,
                    outer_module: first.caller_module.clone(),
                    outer_procedure: first.caller_procedure.clone(),
                    intermediate_module: direct[extended[0]].callee_module.clone(),
                    intermediate_procedure: direct[extended[0]].callee_procedure.clone(),
                    inner_module: leaf.callee_module.clone(),
                    inner_procedure: leaf.callee_procedure.clone(),
                    outer_conditions: first.caller_conditions.clone(),
                    intermediate_conditions,
                    inner_conditions: leaf.callee_conditions.clone(),
                    inner_return_expression: leaf.callee_return_expression.clone(),
                    resolved_return_value,
                    outer_post_return_conditions,
                    post_return_feasibility: inner_post_feasibility,
                    feasibility: feasibility.into(),
                    outer_path_complete: first.caller_path_complete,
                    intermediate_path_complete: chain_path_complete
                        .iter()
                        .skip(1)
                        .take(chain_path_complete.len().saturating_sub(2))
                        .all(|complete| *complete),
                    inner_path_complete: leaf.callee_path_complete,
                    chain_return_data_flow_indices,
                    chain_modules,
                    chain_procedures,
                    chain_path_indices,
                    chain_path_positions,
                    chain_conditions,
                    chain_path_complete,
                });
            }
            if extended.len() < max_depth {
                queue.push_back(extended);
            }
        }
    }
    false
}

/// Evaluate a return assignment only when the expression is made entirely of
/// the bounded literal/constant subset already used for path predicates. A
/// user procedure call, host member, Variant runtime value, or locale
/// dependent conversion remains unresolved and is represented by the source
/// expression instead.
fn evaluate_static_return_expression(
    project: &Project,
    module_name: &str,
    procedure_name: &str,
    expression: &str,
) -> Option<String> {
    let module = project
        .modules
        .iter()
        .find(|module| module.name.eq_ignore_ascii_case(module_name))?;
    let procedure = module
        .procedures
        .iter()
        .find(|procedure| procedure.name.eq_ignore_ascii_case(procedure_name))?;
    let expression = parse_expression_source(expression)?;
    let context = ProcedurePathContext {
        project: Some(project),
        module,
        procedure,
        call_facts: None,
        path_values: None,
        callsite_parameter_values: None,
        param_array_lengths: None,
        array_shapes: None,
        optional_missing: None,
    };
    let value = evaluate_literal_branch_value_in_context(
        &expression,
        0,
        Some(context),
        &mut HashSet::new(),
        false,
    )?;
    Some(literal_value_display(&value))
}

/// Refine return-path facts with caller-path argument snapshots. This is a
/// separate pass because a leaf call may receive a wrapper parameter whose
/// value is known only on the outer caller path. It substitutes only bounded
/// literal expressions and leaves dynamic calls, aliases, and Variant runtime
/// payloads unresolved.
#[allow(clippy::too_many_arguments)]
pub fn enrich_interprocedural_return_values(
    direct: &mut [crate::model::InterproceduralReturnPathFact],
    compositions: &mut [crate::model::InterproceduralReturnCompositionPathFact],
    data_flow: &[DataFlowFact],
    argument_values: &[InterproceduralArgumentValuePathFact],
    project: &Project,
    step_limit: usize,
) -> bool {
    if step_limit == 0 {
        return !direct.is_empty() || !compositions.is_empty();
    }
    let mut steps = 0usize;
    let mut argument_index: HashMap<ReturnArgumentKey, Vec<&InterproceduralArgumentValuePathFact>> =
        HashMap::new();
    for fact in argument_values {
        if steps >= step_limit {
            return true;
        }
        steps += 1;
        argument_index
            .entry(ReturnArgumentKey::from_fact(fact))
            .or_default()
            .push(fact);
    }

    for fact in direct.iter_mut() {
        if steps >= step_limit {
            return true;
        }
        steps += 1;
        if fact.resolved_return_value.is_none() {
            fact.resolved_return_value =
                resolve_direct_return_value(fact, &argument_index, project, &mut steps, step_limit);
        }
        if let Some(value) = fact.resolved_return_value.as_deref() {
            update_return_post_return_feasibility(
                fact.caller_return_data_flow_index,
                &mut fact.post_return_feasibility,
                &fact.caller_post_return_conditions,
                value,
                data_flow,
                project,
            );
        }
    }

    for composition in compositions.iter_mut() {
        if steps >= step_limit {
            return true;
        }
        steps += 1;
        if composition.resolved_return_value.is_some() {
            continue;
        }
        let Some(outer) = direct.iter().find(|fact| {
            fact.caller_return_data_flow_index == composition.outer_return_data_flow_index
                && fact.caller_path_index == composition.outer_path_index
                && fact.caller_path_position == composition.outer_path_position
                && fact
                    .callee_module
                    .eq_ignore_ascii_case(&composition.intermediate_module)
                && fact
                    .callee_procedure
                    .eq_ignore_ascii_case(&composition.intermediate_procedure)
                && fact.callee_path_index == composition.intermediate_path_index
        }) else {
            continue;
        };
        let Some(inner) = direct.iter().find(|fact| {
            fact.caller_module
                .eq_ignore_ascii_case(&composition.intermediate_module)
                && fact
                    .caller_procedure
                    .eq_ignore_ascii_case(&composition.intermediate_procedure)
                && fact.caller_path_index == composition.intermediate_path_index
                && fact
                    .callee_module
                    .eq_ignore_ascii_case(&composition.inner_module)
                && fact
                    .callee_procedure
                    .eq_ignore_ascii_case(&composition.inner_procedure)
                && fact.callee_path_index == composition.inner_path_index
        }) else {
            continue;
        };
        composition.resolved_return_value = resolve_composed_return_value(
            outer,
            inner,
            &argument_index,
            project,
            &mut steps,
            step_limit,
        );
        if let Some(value) = composition.resolved_return_value.clone() {
            update_composed_post_return_feasibility(composition, &value, data_flow, project);
        }
    }
    false
}

fn update_return_post_return_feasibility(
    caller_return_index: usize,
    feasibility: &mut String,
    conditions: &[String],
    resolved_value: &str,
    data_flow: &[DataFlowFact],
    project: &Project,
) {
    let Some(caller_return) = data_flow.get(caller_return_index) else {
        return;
    };
    let Some(module) = project
        .modules
        .iter()
        .find(|module| module.name.eq_ignore_ascii_case(&caller_return.module))
    else {
        return;
    };
    let Some(procedure_name) = caller_return.procedure.as_deref() else {
        return;
    };
    let Some(procedure) = module
        .procedures
        .iter()
        .find(|procedure| procedure.name.eq_ignore_ascii_case(procedure_name))
    else {
        return;
    };
    let Some(value) = parse_expression_source(resolved_value) else {
        return;
    };
    let mut path_values = HashMap::new();
    path_values.insert(canon_flow(&caller_return.target), value);
    let context = ProcedurePathContext {
        project: Some(project),
        module,
        procedure,
        call_facts: None,
        path_values: Some(&path_values),
        callsite_parameter_values: None,
        param_array_lengths: None,
        array_shapes: None,
        optional_missing: None,
    };
    if conditions.iter().any(|condition| {
        evaluate_literal_branch_condition_in_context(condition, Some(context)) == Some(false)
    }) {
        *feasibility = "infeasible_constant_condition".into();
    }
}

fn update_composed_post_return_feasibility(
    composition: &mut crate::model::InterproceduralReturnCompositionPathFact,
    resolved_value: &str,
    data_flow: &[DataFlowFact],
    project: &Project,
) {
    update_return_post_return_feasibility(
        composition.outer_return_data_flow_index,
        &mut composition.post_return_feasibility,
        &composition.outer_post_return_conditions,
        resolved_value,
        data_flow,
        project,
    );
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ReturnArgumentKey {
    caller_module: String,
    caller_procedure: String,
    caller_path_index: usize,
    caller_path_position: usize,
    callee_module: String,
    callee_procedure: String,
}

impl ReturnArgumentKey {
    fn from_fact(fact: &InterproceduralArgumentValuePathFact) -> Self {
        Self {
            caller_module: canon_flow(&fact.caller_module),
            caller_procedure: canon_flow(&fact.caller_procedure),
            caller_path_index: fact.caller_path_index,
            caller_path_position: fact.caller_path_position,
            callee_module: canon_flow(&fact.callee_module),
            callee_procedure: canon_flow(&fact.callee_procedure),
        }
    }
}

fn return_argument_facts<'a>(
    fact: &crate::model::InterproceduralReturnPathFact,
    index: &'a HashMap<ReturnArgumentKey, Vec<&'a InterproceduralArgumentValuePathFact>>,
) -> impl Iterator<Item = &'a InterproceduralArgumentValuePathFact> {
    index
        .get(&ReturnArgumentKey {
            caller_module: canon_flow(&fact.caller_module),
            caller_procedure: canon_flow(fact.caller_procedure.as_str()),
            caller_path_index: fact.caller_path_index,
            caller_path_position: fact.caller_path_position,
            callee_module: canon_flow(&fact.callee_module),
            callee_procedure: canon_flow(&fact.callee_procedure),
        })
        .into_iter()
        .flat_map(|facts| facts.iter().copied())
}

fn resolve_direct_return_value(
    fact: &crate::model::InterproceduralReturnPathFact,
    argument_index: &HashMap<ReturnArgumentKey, Vec<&InterproceduralArgumentValuePathFact>>,
    project: &Project,
    steps: &mut usize,
    step_limit: usize,
) -> Option<String> {
    let expression = fact.callee_return_expression.as_deref()?;
    let mut values = HashMap::new();
    for argument in return_argument_facts(fact, argument_index) {
        if *steps >= step_limit {
            return None;
        }
        *steps += 1;
        let Some(value) = argument.resolved_value.as_deref() else {
            continue;
        };
        let Some(value) = parse_expression_source(value) else {
            continue;
        };
        values.insert(canon_flow(&argument.parameter), value);
    }
    evaluate_return_expression_with_values(
        project,
        &fact.callee_module,
        &fact.callee_procedure,
        expression,
        &values,
    )
}

fn resolve_composed_return_value(
    outer: &crate::model::InterproceduralReturnPathFact,
    inner: &crate::model::InterproceduralReturnPathFact,
    argument_index: &HashMap<ReturnArgumentKey, Vec<&InterproceduralArgumentValuePathFact>>,
    project: &Project,
    steps: &mut usize,
    step_limit: usize,
) -> Option<String> {
    let mut outer_values = HashMap::new();
    for argument in return_argument_facts(outer, argument_index) {
        if *steps >= step_limit {
            return None;
        }
        *steps += 1;
        let Some(value) = argument.resolved_value.as_deref() else {
            continue;
        };
        let Some(value) = parse_expression_source(value) else {
            continue;
        };
        outer_values.insert(canon_flow(&argument.parameter), value);
    }

    let mut inner_values = HashMap::new();
    for argument in return_argument_facts(inner, argument_index) {
        if *steps >= step_limit {
            return None;
        }
        *steps += 1;
        let expression = argument
            .resolved_value
            .as_deref()
            .or(argument.actual_expression.as_deref())?;
        let expression = evaluate_return_expression_with_values(
            project,
            &inner.caller_module,
            &inner.caller_procedure,
            expression,
            &outer_values,
        )?;
        let expression = parse_expression_source(&expression)?;
        inner_values.insert(canon_flow(&argument.parameter), expression);
    }
    inner
        .callee_return_expression
        .as_deref()
        .and_then(|expression| {
            evaluate_return_expression_with_values(
                project,
                &inner.callee_module,
                &inner.callee_procedure,
                expression,
                &inner_values,
            )
        })
}

fn evaluate_return_expression_with_values(
    project: &Project,
    module_name: &str,
    procedure_name: &str,
    expression: &str,
    values: &HashMap<String, Expr>,
) -> Option<String> {
    let module = project
        .modules
        .iter()
        .find(|module| module.name.eq_ignore_ascii_case(module_name))?;
    let procedure = module
        .procedures
        .iter()
        .find(|procedure| procedure.name.eq_ignore_ascii_case(procedure_name))?;
    let expression = parse_expression_source(expression)?;
    let context = ProcedurePathContext {
        project: Some(project),
        module,
        procedure,
        call_facts: None,
        path_values: Some(values),
        callsite_parameter_values: None,
        param_array_lengths: None,
        array_shapes: None,
        optional_missing: None,
    };
    evaluate_literal_branch_value_in_context(
        &expression,
        0,
        Some(context),
        &mut HashSet::new(),
        false,
    )
    .map(|value| literal_value_display(&value))
}

#[allow(clippy::too_many_arguments)]
fn post_return_condition_evidence(
    project: &Project,
    data_flow: &[DataFlowFact],
    caller_return_index: usize,
    callee_return_index: usize,
    caller_path_index: usize,
    caller_path_position: usize,
    graphs: &[ControlFlowGraph],
    paths: &[ControlFlowPath],
) -> (Vec<String>, String) {
    let Some(caller_return) = data_flow.get(caller_return_index) else {
        return (Vec::new(), "not_checked".into());
    };
    let Some(callee_return_expression) = data_flow
        .get(callee_return_index)
        .and_then(|fact| fact.value_expression.as_deref())
    else {
        return (Vec::new(), "not_checked".into());
    };
    let Some(path) = paths.get(caller_path_index) else {
        return (Vec::new(), "not_checked".into());
    };
    let Some(graph) = graphs
        .iter()
        .find(|graph| graph.module == path.module && graph.procedure == path.procedure)
    else {
        return (Vec::new(), "not_checked".into());
    };
    let Some(prefix) = conditions_before_node_from_path(graph, path, caller_path_position) else {
        return (Vec::new(), "not_checked".into());
    };
    let post_conditions = path
        .conditions
        .get(prefix.len()..)
        .unwrap_or_default()
        .to_vec();
    if post_conditions.is_empty() {
        return (post_conditions, "not_checked".into());
    }
    let Some(caller_module) = project
        .modules
        .iter()
        .find(|module| module.name.eq_ignore_ascii_case(&caller_return.module))
    else {
        return (post_conditions, "not_checked".into());
    };
    let Some(caller_procedure_name) = caller_return.procedure.as_deref() else {
        return (post_conditions, "not_checked".into());
    };
    let Some(caller_procedure) = caller_module
        .procedures
        .iter()
        .find(|procedure| procedure.name.eq_ignore_ascii_case(caller_procedure_name))
    else {
        return (post_conditions, "not_checked".into());
    };
    let Some(expression) = parse_expression_source(callee_return_expression) else {
        return (post_conditions, "not_checked".into());
    };
    let mut path_values = HashMap::new();
    path_values.insert(canon_flow(&caller_return.target), expression);
    let context = ProcedurePathContext {
        project: Some(project),
        module: caller_module,
        procedure: caller_procedure,
        call_facts: None,
        path_values: Some(&path_values),
        callsite_parameter_values: None,
        param_array_lengths: None,
        array_shapes: None,
        optional_missing: None,
    };
    let contradiction = post_conditions.iter().any(|condition| {
        evaluate_literal_branch_condition_in_context(condition, Some(context)) == Some(false)
    });
    (
        post_conditions,
        if contradiction {
            "infeasible_constant_condition".into()
        } else {
            "not_checked".into()
        },
    )
}

/// Link each caller-side ByRef write candidate to writes of the matching
/// formal in the callee on independently enumerated caller and callee paths.
/// The paths are not combined into a feasibility proof.
pub fn associate_interprocedural_byref_write_paths(
    project: &Project,
    data_flow: &[DataFlowFact],
    associations: &[DataFlowPathFact],
    limit: usize,
    step_limit: usize,
) -> InterproceduralByRefWritePathAnalysis {
    type CallParameterKey = (String, String, usize, usize, String, String, String);
    type ProcedureParameterKey = (String, String, String);

    let mut result = InterproceduralByRefWritePathAnalysis::default();
    let mut steps = 0usize;
    let mut argument_facts: HashMap<CallParameterKey, Vec<usize>> = HashMap::new();
    for (index, fact) in data_flow.iter().enumerate() {
        if !matches!(
            fact.transfer.as_str(),
            "procedure_argument_input_candidate"
                | "default_member_argument_input_candidate"
                | "property_set_argument_candidate"
        ) {
            continue;
        }
        if steps >= step_limit {
            result.truncated = true;
            return result;
        }
        steps += 1;
        let mut target = fact.target.split('.');
        let (Some(callee_module), Some(callee_procedure), Some(parameter)) =
            (target.next(), target.next(), target.next())
        else {
            continue;
        };
        if target.next().is_some() {
            continue;
        }
        let Some(caller_procedure) = fact.procedure.as_deref() else {
            continue;
        };
        argument_facts
            .entry((
                canon_flow(&fact.module),
                canon_flow(caller_procedure),
                fact.span.start,
                fact.span.end,
                canon_flow(callee_module),
                canon_flow(callee_procedure),
                canon_flow(parameter),
            ))
            .or_default()
            .push(index);
    }

    let mut associations_by_flow: HashMap<usize, Vec<&DataFlowPathFact>> = HashMap::new();
    for association in associations {
        if steps >= step_limit {
            result.truncated = true;
            return result;
        }
        steps += 1;
        associations_by_flow
            .entry(association.data_flow_index)
            .or_default()
            .push(association);
    }

    let mut callee_writes: HashMap<ProcedureParameterKey, Vec<usize>> = HashMap::new();
    for (index, fact) in data_flow.iter().enumerate() {
        if !matches!(
            fact.transfer.as_str(),
            "assignment"
                | "object_assignment"
                | "file_read_candidate"
                | "redim_array_write_candidate"
                | "redim_preserve_array_write_candidate"
                | "erase_array_write_candidate"
                | "loop_control_write_candidate"
                | "byref_argument_write"
                | "event_handler_byref_write_candidate"
                | "default_member_byref_write_candidate"
        ) {
            continue;
        }
        if steps >= step_limit {
            result.truncated = true;
            return result;
        }
        steps += 1;
        let (Some(procedure), Some(target)) = (
            fact.procedure.as_deref(),
            write_target_base_identifier(&fact.target),
        ) else {
            continue;
        };
        callee_writes
            .entry((
                canon_flow(&fact.module),
                canon_flow(procedure),
                canon_flow(&target),
            ))
            .or_default()
            .push(index);
    }

    let mut seen = HashSet::new();
    for (caller_write_index, caller_write) in data_flow.iter().enumerate() {
        if !matches!(
            caller_write.transfer.as_str(),
            "byref_argument_write" | "default_member_byref_write_candidate"
        ) {
            continue;
        }
        if steps >= step_limit {
            result.truncated = true;
            return result;
        }
        steps += 1;
        let (Some(caller_procedure), Some(callee_module), Some(callee_procedure), Some(parameter)) = (
            caller_write.procedure.as_deref(),
            caller_write.call_callee_module.as_deref(),
            caller_write.call_callee_procedure.as_deref(),
            caller_write.inputs.get(1).map(String::as_str),
        ) else {
            continue;
        };
        let Some((resolved_module, resolved_procedure)) =
            unique_path_procedure(project, callee_module, callee_procedure)
        else {
            continue;
        };
        let matching_parameters = resolved_procedure
            .parameters
            .iter()
            .filter(|candidate| canon_flow(&candidate.name) == canon_flow(parameter))
            .collect::<Vec<_>>();
        if matching_parameters.len() != 1 {
            continue;
        }
        let argument_key = (
            canon_flow(&caller_write.module),
            canon_flow(caller_procedure),
            caller_write.span.start,
            caller_write.span.end,
            canon_flow(&resolved_module.name),
            canon_flow(&resolved_procedure.name),
            canon_flow(parameter),
        );
        let Some(argument_indices) = argument_facts.get(&argument_key) else {
            continue;
        };
        if argument_indices.len() != 1 {
            continue;
        }
        let Some(caller_path_associations) = associations_by_flow.get(&caller_write_index) else {
            continue;
        };
        let argument_data_flow_index = argument_indices[0];
        let Some(argument_path_associations) = associations_by_flow.get(&argument_data_flow_index)
        else {
            continue;
        };
        let write_key = (
            canon_flow(&resolved_module.name),
            canon_flow(&resolved_procedure.name),
            canon_flow(parameter),
        );
        let Some(callee_write_indices) = callee_writes.get(&write_key) else {
            continue;
        };
        for caller_path in caller_path_associations {
            let argument_path_matches = argument_path_associations.iter().any(|argument_path| {
                argument_path.path_index == caller_path.path_index
                    && argument_path.path_position == caller_path.path_position
                    && argument_path.module == caller_path.module
                    && argument_path.procedure == caller_path.procedure
            });
            if !argument_path_matches {
                continue;
            }
            for &callee_write_index in callee_write_indices {
                let Some(callee_path_associations) = associations_by_flow.get(&callee_write_index)
                else {
                    continue;
                };
                for callee_path in callee_path_associations {
                    if steps >= step_limit {
                        result.truncated = true;
                        return result;
                    }
                    steps += 1;
                    if callee_path.module != resolved_module.name
                        || callee_path.procedure != resolved_procedure.name
                    {
                        continue;
                    }
                    let identity = (
                        caller_write_index,
                        argument_data_flow_index,
                        callee_write_index,
                        caller_path.path_index,
                        caller_path.path_position,
                        callee_path.path_index,
                        callee_path.path_position,
                    );
                    if !seen.insert(identity) {
                        continue;
                    }
                    if result.facts.len() >= limit {
                        result.truncated = true;
                        return result;
                    }
                    result.facts.push(InterproceduralByRefWritePathFact {
                        caller_write_data_flow_index: caller_write_index,
                        argument_data_flow_index,
                        callee_write_data_flow_index: callee_write_index,
                        caller_path_index: caller_path.path_index,
                        caller_path_position: caller_path.path_position,
                        callee_path_index: callee_path.path_index,
                        callee_path_position: callee_path.path_position,
                        caller_module: caller_write.module.clone(),
                        caller_procedure: caller_procedure.to_owned(),
                        callee_module: resolved_module.name.clone(),
                        callee_procedure: resolved_procedure.name.clone(),
                        parameter: matching_parameters[0].name.clone(),
                        caller_conditions: caller_path.conditions.clone(),
                        callee_conditions: callee_path.conditions.clone(),
                        feasibility: combined_path_feasibility(
                            &caller_path.conditions,
                            &callee_path.conditions,
                            &caller_path.feasibility,
                            &callee_path.feasibility,
                        ),
                        caller_path_complete: caller_path.path_complete,
                        callee_path_complete: callee_path.path_complete,
                    });
                }
            }
        }
    }
    result
}

/// Compose caller-side scalar snapshots with a matching callee ByRef write.
/// This preserves the alias boundary: the result is a value candidate for the
/// write expression, not a claim that the caller variable has a proven final
/// runtime value after every possible call effect.
#[allow(clippy::too_many_arguments)]
pub fn compose_interprocedural_byref_value_paths(
    project: &Project,
    data_flow: &[DataFlowFact],
    value_facts: &[InterproceduralArgumentValuePathFact],
    write_facts: &[InterproceduralByRefWritePathFact],
    limit: usize,
    step_limit: usize,
) -> InterproceduralByRefValuePathAnalysis {
    let mut result = InterproceduralByRefValuePathAnalysis::default();
    let mut steps = 0usize;
    for write_fact in write_facts {
        if steps >= step_limit {
            result.truncated = true;
            return result;
        }
        steps += 1;
        let write_expression = data_flow
            .get(write_fact.callee_write_data_flow_index)
            .and_then(|fact| fact.value_expression.clone());
        let matching_values = value_facts.iter().filter(|value_fact| {
            value_fact.argument_data_flow_index == write_fact.argument_data_flow_index
                && value_fact.caller_path_index == write_fact.caller_path_index
                && value_fact.caller_path_position == write_fact.caller_path_position
                && value_fact
                    .callee_module
                    .eq_ignore_ascii_case(&write_fact.callee_module)
                && value_fact
                    .callee_procedure
                    .eq_ignore_ascii_case(&write_fact.callee_procedure)
                && value_fact
                    .parameter
                    .eq_ignore_ascii_case(&write_fact.parameter)
        });
        for value_fact in matching_values {
            if steps >= step_limit {
                result.truncated = true;
                return result;
            }
            steps += 1;
            if result.facts.len() >= limit {
                result.truncated = true;
                return result;
            }
            let resolved_value = if let (Some(write_expression), Some(caller_value)) = (
                write_expression.as_deref(),
                value_fact.resolved_value.as_deref(),
            ) {
                let caller_expression = parse_expression_source(caller_value);
                let write_expression_ast = parse_expression_source(write_expression);
                let callee_module = project
                    .modules
                    .iter()
                    .find(|module| module.name.eq_ignore_ascii_case(&write_fact.callee_module));
                let callee_procedure = callee_module.and_then(|module| {
                    module.procedures.iter().find(|procedure| {
                        procedure
                            .name
                            .eq_ignore_ascii_case(&write_fact.callee_procedure)
                    })
                });
                match (
                    caller_expression,
                    write_expression_ast,
                    callee_module,
                    callee_procedure,
                ) {
                    (
                        Some(caller_expression),
                        Some(write_expression),
                        Some(module),
                        Some(procedure),
                    ) => {
                        let mut path_values = HashMap::new();
                        path_values.insert(canon_flow(&write_fact.parameter), caller_expression);
                        let context = ProcedurePathContext {
                            project: Some(project),
                            module,
                            procedure,
                            call_facts: None,
                            path_values: Some(&path_values),
                            callsite_parameter_values: None,
                            param_array_lengths: None,
                            array_shapes: None,
                            optional_missing: None,
                        };
                        evaluate_literal_branch_value_in_context(
                            &write_expression,
                            0,
                            Some(context),
                            &mut HashSet::new(),
                            false,
                        )
                        .map(|value| literal_value_display(&value))
                    }
                    _ => None,
                }
            } else if write_expression.is_none() {
                value_fact.resolved_value.clone()
            } else {
                None
            };
            let resolution = if write_expression.is_none() && value_fact.resolved_value.is_some() {
                "caller_snapshot_to_byref_forward_candidate"
            } else if resolved_value.is_some() {
                "caller_snapshot_to_byref_write_value"
            } else if value_fact.resolved_value.is_some() {
                "callee_write_value_unresolved"
            } else {
                "caller_value_unresolved"
            };
            result.facts.push(InterproceduralByRefValuePathFact {
                composition_depth: 1,
                caller_write_data_flow_index: write_fact.caller_write_data_flow_index,
                argument_data_flow_index: write_fact.argument_data_flow_index,
                callee_write_data_flow_index: write_fact.callee_write_data_flow_index,
                caller_path_index: write_fact.caller_path_index,
                caller_path_position: write_fact.caller_path_position,
                callee_path_index: write_fact.callee_path_index,
                callee_path_position: write_fact.callee_path_position,
                caller_module: write_fact.caller_module.clone(),
                caller_procedure: write_fact.caller_procedure.clone(),
                callee_module: write_fact.callee_module.clone(),
                callee_procedure: write_fact.callee_procedure.clone(),
                parameter: write_fact.parameter.clone(),
                caller_value: value_fact.resolved_value.clone(),
                callee_write_expression: write_expression.clone(),
                resolved_value,
                resolution: resolution.into(),
                caller_conditions: write_fact.caller_conditions.clone(),
                callee_conditions: write_fact.callee_conditions.clone(),
                feasibility: write_fact.feasibility.clone(),
                caller_path_complete: write_fact.caller_path_complete,
                callee_path_complete: write_fact.callee_path_complete,
            });
        }
    }
    let mut frontier = result.facts.clone();
    while frontier.iter().any(|fact| fact.composition_depth < 4) {
        let mut next_frontier = Vec::new();
        for value_fact in frontier {
            if value_fact.composition_depth >= 4 {
                continue;
            }
            for write_fact in write_facts.iter().filter(|write_fact| {
                write_fact.caller_write_data_flow_index == value_fact.callee_write_data_flow_index
                    && write_fact
                        .caller_module
                        .eq_ignore_ascii_case(&value_fact.callee_module)
                    && write_fact
                        .caller_procedure
                        .eq_ignore_ascii_case(&value_fact.callee_procedure)
            }) {
                if steps >= step_limit {
                    result.truncated = true;
                    return result;
                }
                steps += 1;
                let Some(write_expression) = data_flow
                    .get(write_fact.callee_write_data_flow_index)
                    .and_then(|fact| fact.value_expression.clone())
                else {
                    continue;
                };
                let resolved_value = value_fact.resolved_value.as_deref().and_then(|value| {
                    resolve_byref_write_value(
                        project,
                        &write_expression,
                        &write_fact.parameter,
                        &write_fact.callee_module,
                        &write_fact.callee_procedure,
                        value,
                    )
                });
                let resolution = if resolved_value.is_some() {
                    "nested_byref_snapshot_to_write_value"
                } else if value_fact.resolved_value.is_some() {
                    "nested_byref_write_value_unresolved"
                } else {
                    "caller_value_unresolved"
                };
                let mut callee_conditions = value_fact.callee_conditions.clone();
                callee_conditions.extend(write_fact.callee_conditions.iter().cloned());
                let fact = InterproceduralByRefValuePathFact {
                    composition_depth: value_fact.composition_depth + 1,
                    caller_write_data_flow_index: value_fact.caller_write_data_flow_index,
                    argument_data_flow_index: value_fact.argument_data_flow_index,
                    callee_write_data_flow_index: write_fact.callee_write_data_flow_index,
                    caller_path_index: value_fact.caller_path_index,
                    caller_path_position: value_fact.caller_path_position,
                    callee_path_index: write_fact.callee_path_index,
                    callee_path_position: write_fact.callee_path_position,
                    caller_module: value_fact.caller_module.clone(),
                    caller_procedure: value_fact.caller_procedure.clone(),
                    callee_module: write_fact.callee_module.clone(),
                    callee_procedure: write_fact.callee_procedure.clone(),
                    parameter: write_fact.parameter.clone(),
                    caller_value: value_fact.caller_value.clone(),
                    callee_write_expression: Some(write_expression),
                    resolved_value,
                    resolution: resolution.into(),
                    caller_conditions: value_fact.caller_conditions.clone(),
                    callee_conditions,
                    feasibility: combined_path_feasibility(
                        &value_fact.caller_conditions,
                        &value_fact.callee_conditions,
                        &value_fact.feasibility,
                        &write_fact.feasibility,
                    ),
                    caller_path_complete: value_fact.caller_path_complete,
                    callee_path_complete: write_fact.callee_path_complete,
                };
                if result.facts.len() >= limit {
                    result.truncated = true;
                    return result;
                }
                next_frontier.push(fact.clone());
                result.facts.push(fact);
            }
        }
        if next_frontier.is_empty() {
            break;
        }
        frontier = next_frontier;
    }
    result
}

fn resolve_byref_write_value(
    project: &Project,
    write_expression: &str,
    parameter: &str,
    callee_module_name: &str,
    callee_procedure_name: &str,
    caller_value: &str,
) -> Option<String> {
    let caller_expression = parse_expression_source(caller_value)?;
    let write_expression_ast = parse_expression_source(write_expression)?;
    let module = project
        .modules
        .iter()
        .find(|module| module.name.eq_ignore_ascii_case(callee_module_name))?;
    let procedure = module
        .procedures
        .iter()
        .find(|procedure| procedure.name.eq_ignore_ascii_case(callee_procedure_name))?;
    let mut path_values = HashMap::new();
    path_values.insert(canon_flow(parameter), caller_expression);
    let context = ProcedurePathContext {
        project: Some(project),
        module,
        procedure,
        call_facts: None,
        path_values: Some(&path_values),
        callsite_parameter_values: None,
        param_array_lengths: None,
        array_shapes: None,
        optional_missing: None,
    };
    evaluate_literal_branch_value_in_context(
        &write_expression_ast,
        0,
        Some(context),
        &mut HashSet::new(),
        false,
    )
    .map(|value| literal_value_display(&value))
}

/// Pair a statically resolved in-project call path with a callee path that can
/// expose an unhandled error to that call site. Caller recovery and callee
/// fault paths remain separate candidates, not a composed execution proof.
pub fn associate_interprocedural_error_paths(
    project: &Project,
    calls: &[CallFact],
    entry_points: &[EntryPointFact],
    graphs: &[ControlFlowGraph],
    paths: &[ControlFlowPath],
    limit: usize,
    step_limit: usize,
) -> InterproceduralErrorPathAnalysis {
    type ProcedureKey = (String, String);

    let mut result = InterproceduralErrorPathAnalysis::default();
    let mut steps = 0usize;
    let mut graphs_by_procedure: HashMap<ProcedureKey, Vec<&ControlFlowGraph>> = HashMap::new();
    for graph in graphs {
        graphs_by_procedure
            .entry((canon_flow(&graph.module), canon_flow(&graph.procedure)))
            .or_default()
            .push(graph);
    }
    let mut paths_by_procedure: HashMap<ProcedureKey, Vec<usize>> = HashMap::new();
    for (index, path) in paths.iter().enumerate() {
        paths_by_procedure
            .entry((canon_flow(&path.module), canon_flow(&path.procedure)))
            .or_default()
            .push(index);
    }

    let mut error_sites: HashMap<ProcedureKey, Vec<InterproceduralErrorSite>> = HashMap::new();
    for ((module_name, procedure_name), matching_graphs) in &graphs_by_procedure {
        if matching_graphs.len() != 1 {
            continue;
        }
        let graph = matching_graphs[0];
        let Some(path_indices) =
            paths_by_procedure.get(&(module_name.clone(), procedure_name.clone()))
        else {
            continue;
        };
        let has_error_policy = graph
            .nodes
            .iter()
            .any(|node| matches!(node.kind.as_str(), "on_error" | "resume"));
        if has_error_policy {
            let unhandled_edges = graph
                .edges
                .iter()
                .filter_map(|edge| {
                    edge.condition
                        .as_deref()
                        .filter(|condition| {
                            condition.contains("possible unhandled error leaves this procedure")
                        })
                        .map(|condition| (edge.from, edge.to, condition.to_owned()))
                })
                .collect::<Vec<_>>();
            for &path_index in path_indices {
                let path = &paths[path_index];
                for position in 0..path.nodes.len().saturating_sub(1) {
                    let from = path.nodes[position];
                    let to = path.nodes[position + 1];
                    let Some((_, _, condition)) = unhandled_edges
                        .iter()
                        .find(|(edge_from, edge_to, _)| *edge_from == from && *edge_to == to)
                    else {
                        continue;
                    };
                    if steps >= step_limit {
                        result.truncated = true;
                        return result;
                    }
                    steps += 1;
                    let Some(mut conditions) =
                        conditions_before_node_from_path(graph, path, position)
                    else {
                        continue;
                    };
                    conditions.push(condition.clone());
                    error_sites
                        .entry((module_name.clone(), procedure_name.clone()))
                        .or_default()
                        .push(InterproceduralErrorSite {
                            path_index,
                            path_position: position,
                            fault_node_id: from,
                            conditions,
                            feasibility: path.feasibility.clone(),
                            path_complete: path.complete,
                            propagation: "callee_unhandled_error_candidate".into(),
                        });
                }
            }
        } else {
            for &path_index in path_indices {
                let path = &paths[path_index];
                for (position, &node_id) in path.nodes.iter().enumerate() {
                    if steps >= step_limit {
                        result.truncated = true;
                        return result;
                    }
                    steps += 1;
                    let Some(node) = graph.nodes.get(node_id) else {
                        continue;
                    };
                    if !crate::error_handling::may_raise_error(&node.kind) {
                        continue;
                    }
                    let Some(conditions) = conditions_before_node_from_path(graph, path, position)
                    else {
                        continue;
                    };
                    error_sites
                        .entry((module_name.clone(), procedure_name.clone()))
                        .or_default()
                        .push(InterproceduralErrorSite {
                            path_index,
                            path_position: position,
                            fault_node_id: node_id,
                            conditions,
                            feasibility: path.feasibility.clone(),
                            path_complete: path.complete,
                            propagation: "default_error_policy_may_propagate_to_caller".into(),
                        });
                }
            }
        }
    }

    let mut seen = HashSet::new();
    for (caller_call_index, call) in calls.iter().enumerate() {
        if steps >= step_limit {
            result.truncated = true;
            return result;
        }
        steps += 1;
        let callee_targets = resolve_error_call_targets(project, call);
        if callee_targets.is_empty() {
            continue;
        }
        let Some(caller_procedure) = call.procedure.as_deref() else {
            continue;
        };
        let caller_key = (canon_flow(&call.module), canon_flow(caller_procedure));
        let Some(caller_graphs) = graphs_by_procedure.get(&caller_key) else {
            continue;
        };
        if caller_graphs.len() != 1 {
            continue;
        }
        let caller_graph = caller_graphs[0];
        let Some(caller_node) = call_node_for_span(caller_graph, call.span) else {
            continue;
        };
        let Some(caller_path_indices) = paths_by_procedure.get(&caller_key) else {
            continue;
        };
        for (callee_module, callee, event_dispatch) in callee_targets {
            let callee_key = (canon_flow(&callee_module.name), canon_flow(&callee.name));
            let Some(callee_sites) = error_sites.get(&callee_key) else {
                continue;
            };
            for &caller_path_index in caller_path_indices {
                let caller_path = &paths[caller_path_index];
                for (caller_position, &node_id) in caller_path.nodes.iter().enumerate() {
                    if node_id != caller_node {
                        continue;
                    }
                    let Some(caller_conditions) = conditions_before_node_from_path(
                        caller_graph,
                        caller_path,
                        caller_position,
                    ) else {
                        continue;
                    };
                    let (
                        caller_error_response,
                        caller_recovery_path_position,
                        caller_recovery_node_id,
                    ) = if event_dispatch {
                        (
                            "event_handler_error_not_caught_by_raiseevent_caller".into(),
                            None,
                            None,
                        )
                    } else {
                        classify_caller_error_response(caller_graph, caller_path, caller_position)
                    };
                    for callee_site in callee_sites {
                        if steps >= step_limit {
                            result.truncated = true;
                            return result;
                        }
                        steps += 1;
                        let identity = (
                            caller_call_index,
                            caller_path_index,
                            caller_position,
                            canon_flow(&callee_module.name),
                            canon_flow(&callee.name),
                            callee_site.path_index,
                            callee_site.path_position,
                            callee_site.fault_node_id,
                        );
                        if !seen.insert(identity) {
                            continue;
                        }
                        if result.facts.len() >= limit {
                            result.truncated = true;
                            return result;
                        }
                        result.facts.push(InterproceduralErrorPathFact {
                            caller_call_index,
                            caller_path_index,
                            caller_path_position: caller_position,
                            callee_path_index: callee_site.path_index,
                            callee_fault_path_position: callee_site.path_position,
                            callee_fault_node_id: callee_site.fault_node_id,
                            caller_module: call.module.clone(),
                            caller_procedure: call.procedure.clone().unwrap_or_default(),
                            callee_module: callee_module.name.clone(),
                            callee_procedure: callee.name.clone(),
                            caller_host_entry_candidate: is_direct_host_entry_candidate(
                                entry_points,
                                &call.module,
                                caller_procedure,
                            ),
                            caller_error_response: caller_error_response.clone(),
                            caller_recovery_path_position,
                            caller_recovery_node_id,
                            caller_conditions: caller_conditions.clone(),
                            callee_conditions: callee_site.conditions.clone(),
                            propagation: if event_dispatch {
                                "event_handler_unhandled_error_stops_remaining_dispatch".into()
                            } else {
                                callee_site.propagation.clone()
                            },
                            feasibility: combined_path_feasibility(
                                &caller_conditions,
                                &callee_site.conditions,
                                &caller_path.feasibility,
                                &callee_site.feasibility,
                            ),
                            caller_path_complete: caller_path.complete,
                            callee_path_complete: callee_site.path_complete,
                        });
                    }
                }
            }
        }
    }
    result
}

fn classify_caller_error_response(
    graph: &ControlFlowGraph,
    path: &ControlFlowPath,
    call_position: usize,
) -> (String, Option<usize>, Option<usize>) {
    let has_error_policy = graph
        .nodes
        .iter()
        .any(|node| matches!(node.kind.as_str(), "on_error" | "resume"));
    if !has_error_policy {
        return ("caller_default_policy_context_dependent".into(), None, None);
    }
    let Some(next_position) = call_position.checked_add(1) else {
        return ("caller_error_response_not_identified".into(), None, None);
    };
    let Some(next_node) = path.nodes.get(next_position).copied() else {
        return ("caller_error_response_not_identified".into(), None, None);
    };
    match selected_edge_condition_on_path(graph, path, call_position) {
        Some(Some(condition)) if condition.starts_with("possible fault; transfer to handler") => (
            "caller_handler_transfer_candidate".into(),
            Some(next_position),
            Some(next_node),
        ),
        Some(Some(condition)) if condition.starts_with("possible fault; On Error Resume Next") => (
            "caller_resume_next_after_call_candidate".into(),
            Some(next_position),
            Some(next_node),
        ),
        Some(Some(condition))
            if condition.contains("possible unhandled error leaves this procedure") =>
        {
            (
                "caller_unhandled_error_propagation_candidate".into(),
                Some(next_position),
                Some(next_node),
            )
        }
        Some(_) => (
            "caller_error_edge_not_selected_on_this_path".into(),
            None,
            None,
        ),
        None => ("caller_error_response_not_identified".into(), None, None),
    }
}

fn is_direct_host_entry_candidate(
    entry_points: &[EntryPointFact],
    module: &str,
    procedure: &str,
) -> bool {
    entry_points.iter().any(|entry| {
        entry.module.eq_ignore_ascii_case(module)
            && entry.procedure.eq_ignore_ascii_case(procedure)
            && crate::host::direct_host_entry_candidate(&entry.trigger)
    })
}

fn selected_edge_condition_on_path(
    graph: &ControlFlowGraph,
    path: &ControlFlowPath,
    target_position: usize,
) -> Option<Option<String>> {
    type State = (usize, Option<String>);
    const MAX_CONDITION_EDGE_STATES: usize = 100_000;
    if target_position + 1 >= path.nodes.len() {
        return None;
    }
    let mut states = HashSet::<State>::from([(0, None)]);
    for (position, pair) in path.nodes.windows(2).enumerate() {
        let edges = graph
            .edges
            .iter()
            .filter(|edge| edge.from == pair[0] && edge.to == pair[1])
            .collect::<Vec<_>>();
        if edges.is_empty() {
            return None;
        }
        let mut next = HashSet::new();
        for (condition_offset, selected_condition) in &states {
            for edge in &edges {
                let next_offset = match edge.condition.as_deref() {
                    None => *condition_offset,
                    Some(condition)
                        if path
                            .conditions
                            .get(*condition_offset)
                            .is_some_and(|actual| actual == condition) =>
                    {
                        condition_offset + 1
                    }
                    Some(_) => continue,
                };
                let selected = if position == target_position {
                    edge.condition.clone()
                } else {
                    selected_condition.clone()
                };
                next.insert((next_offset, selected));
                if next.len() > MAX_CONDITION_EDGE_STATES {
                    return None;
                }
            }
        }
        if next.is_empty() {
            return None;
        }
        states = next;
    }
    let mut selected = states
        .into_iter()
        .filter(|(condition_offset, _)| *condition_offset == path.conditions.len())
        .map(|(_, condition)| condition);
    let first = selected.next()?;
    selected
        .all(|condition| condition == first)
        .then_some(first)
}

#[derive(Clone, Debug)]
struct InterproceduralErrorSite {
    path_index: usize,
    path_position: usize,
    fault_node_id: usize,
    conditions: Vec<String>,
    feasibility: String,
    path_complete: bool,
    propagation: String,
}

fn resolve_error_call_targets<'a>(
    project: &'a Project,
    call: &CallFact,
) -> Vec<(&'a Module, &'a Procedure, bool)> {
    if call.resolution == "event_dispatch_candidate" {
        let mut targets = Vec::new();
        let mut seen = HashSet::new();
        for candidate in &call.dispatch_candidates {
            let mut parts = candidate.split('.');
            let (Some(module), Some(procedure), None) = (parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            let Some(target) = unique_path_procedure(project, module, procedure) else {
                continue;
            };
            if seen.insert((canon_flow(&target.0.name), canon_flow(&target.1.name))) {
                targets.push((target.0, target.1, true));
            }
        }
        return targets;
    }
    resolve_error_call_target(project, call)
        .map(|(module, procedure)| vec![(module, procedure, false)])
        .unwrap_or_default()
}

fn resolve_error_call_target<'a>(
    project: &'a Project,
    call: &CallFact,
) -> Option<(&'a Module, &'a Procedure)> {
    if call.dispatch_candidates.len() == 1 {
        let mut parts = call.dispatch_candidates[0].split('.');
        if let (Some(module), Some(procedure), None) = (parts.next(), parts.next(), parts.next())
            && let Some(target) = unique_path_procedure(project, module, procedure)
        {
            return Some(target);
        }
    }
    match call.resolution.as_str() {
        "resolved_self_procedure" | "resolved_project_procedure" => {
            unique_path_procedure(project, &call.module, &call.target)
        }
        "resolved_cross_module_procedure" => {
            unique_named_error_procedure(project, &call.target, call.module.as_str(), true, false)
        }
        "resolved_qualified_module_procedure" => {
            let module = explicit_standard_module_qualifier(project, call)?;
            unique_path_procedure(project, &module.name, &call.target)
        }
        "resolved_self_property_setter" => {
            unique_named_property_setter(project, &call.module, &call.target)
        }
        "resolved_qualified_module_property_setter" => {
            let module = explicit_standard_module_qualifier(project, call)?;
            unique_named_property_setter(project, &module.name, &call.target)
        }
        "resolved_typed_object_member" => {
            unique_named_error_procedure(project, &call.target, &call.module, false, false)
        }
        _ => None,
    }
}

fn explicit_standard_module_qualifier<'a>(
    project: &'a Project,
    call: &CallFact,
) -> Option<&'a Module> {
    let mut caller_modules = project
        .modules
        .iter()
        .filter(|module| canon_flow(&module.name) == canon_flow(&call.module));
    let caller_module = caller_modules.next()?;
    if caller_modules.next().is_some()
        || call.span.start > call.span.end
        || call.span.end > caller_module.analysis_text.len()
        || !caller_module
            .analysis_text
            .is_char_boundary(call.span.start)
        || !caller_module.analysis_text.is_char_boundary(call.span.end)
    {
        return None;
    }
    let line_start = caller_module.analysis_text[..call.span.start]
        .rfind('\n')
        .map(|position| position + 1)
        .unwrap_or(0);
    let line_end = caller_module.analysis_text[call.span.end..]
        .find('\n')
        .map(|offset| call.span.end + offset)
        .unwrap_or(caller_module.analysis_text.len());
    let line = &caller_module.analysis_text[line_start..line_end];
    let (tokens, _) = lex(line, 4096);
    let significant = tokens
        .iter()
        .filter(|token| !matches!(token.kind, TokenKind::Newline | TokenKind::Eof))
        .collect::<Vec<_>>();
    let call_offset = call.span.start - line_start;
    let position = significant.iter().position(|token| {
        token.span.start == call_offset && canon_flow(&token.text) == canon_flow(&call.target)
    })?;
    if position < 2 || significant[position - 1].text != "." {
        return None;
    }
    let qualifier = significant[position - 2];
    if qualifier.kind != TokenKind::Identifier {
        return None;
    }
    let mut modules = project.modules.iter().filter(|module| {
        canon_flow(&module.name) == canon_flow(&qualifier.text)
            && matches!(module.module_kind.as_deref(), Some("standard") | None)
    });
    let module = modules.next()?;
    modules.next().is_none().then_some(module)
}

fn unique_named_error_procedure<'a>(
    project: &'a Project,
    name: &str,
    caller_module: &str,
    standard_only: bool,
    setter_only: bool,
) -> Option<(&'a Module, &'a Procedure)> {
    let mut candidates = project.modules.iter().flat_map(|module| {
        module.procedures.iter().filter_map(move |procedure| {
            if canon_flow(&procedure.name) != canon_flow(name) {
                return None;
            }
            if standard_only
                && (!matches!(module.module_kind.as_deref(), Some("standard") | None)
                    || module.name.eq_ignore_ascii_case(caller_module))
            {
                return None;
            }
            if !standard_only
                && !setter_only
                && !matches!(
                    module.module_kind.as_deref(),
                    Some(
                        "class"
                            | "form"
                            | "workbook_document"
                            | "worksheet_document"
                            | "class_or_document"
                    )
                )
            {
                return None;
            }
            if !standard_only
                && !module.name.eq_ignore_ascii_case(caller_module)
                && !procedure.visibility.eq_ignore_ascii_case("public")
                && !procedure.visibility.eq_ignore_ascii_case("global")
            {
                return None;
            }
            if setter_only
                && !matches!(
                    procedure.kind.to_ascii_lowercase().as_str(),
                    "property let" | "property set"
                )
            {
                return None;
            }
            Some((module, procedure))
        })
    });
    let first = candidates.next()?;
    candidates.next().is_none().then_some(first)
}

fn unique_named_property_setter<'a>(
    project: &'a Project,
    module_name: &str,
    name: &str,
) -> Option<(&'a Module, &'a Procedure)> {
    let module = project
        .modules
        .iter()
        .find(|module| canon_flow(&module.name) == canon_flow(module_name))?;
    let mut candidates = module.procedures.iter().filter(|procedure| {
        canon_flow(&procedure.name) == canon_flow(name)
            && matches!(
                procedure.kind.to_ascii_lowercase().as_str(),
                "property let" | "property set"
            )
    });
    let procedure = candidates.next()?;
    candidates.next().is_none().then_some((module, procedure))
}

fn call_node_for_span(graph: &ControlFlowGraph, span: crate::model::Span) -> Option<usize> {
    let mut matches = graph
        .nodes
        .iter()
        .filter(|node| {
            is_data_access_node(&node.kind)
                && node.span.start <= span.start
                && span.end <= node.span.end
        })
        .collect::<Vec<_>>();
    let smallest = matches
        .iter()
        .map(|node| node.span.end.saturating_sub(node.span.start))
        .min()?;
    matches.retain(|node| node.span.end.saturating_sub(node.span.start) == smallest);
    (matches.len() == 1).then_some(matches[0].id)
}

fn write_target_base_identifier(target: &str) -> Option<String> {
    let (tokens, _) = lex(target.trim(), 128);
    let mut significant = tokens
        .iter()
        .filter(|token| !matches!(token.kind, TokenKind::Newline | TokenKind::Eof));
    let first = significant.next()?;
    (first.kind == TokenKind::Identifier).then(|| first.text.clone())
}

pub(crate) fn unique_path_procedure<'a>(
    project: &'a Project,
    module_name: &str,
    procedure_name: &str,
) -> Option<(&'a Module, &'a Procedure)> {
    let mut modules = project
        .modules
        .iter()
        .filter(|module| canonical_data_name(&module.name) == canonical_data_name(module_name));
    let module = modules.next()?;
    if modules.next().is_some() {
        return None;
    }
    let mut procedures = module.procedures.iter().filter(|procedure| {
        canonical_data_name(&procedure.name) == canonical_data_name(procedure_name)
    });
    let procedure = procedures.next()?;
    procedures.next().is_none().then_some((module, procedure))
}

fn canon_flow(name: &str) -> String {
    name.trim_end_matches(['%', '&', '^', '@', '!', '#', '$'])
        .to_ascii_lowercase()
}

/// Trace simple variable definitions and uniquely visible Const initializers
/// to later reads along each bounded path. This is a candidate flow: it does
/// not prove the path feasible or resolve member, array, Variant, or
/// host-object state.
#[allow(clippy::explicit_counter_loop)]
pub fn derive_path_aliases(
    data_flow: &[DataFlowFact],
    associations: &[DataFlowPathFact],
    limit: usize,
    step_limit: usize,
) -> PathAliasAnalysis {
    let mut result = PathAliasAnalysis::default();
    let mut steps = 0usize;
    let mut seen = HashSet::new();
    for association in associations {
        if steps >= step_limit {
            result.truncated = true;
            return result;
        }
        steps += 1;
        let Some(fact) = data_flow.get(association.data_flow_index) else {
            continue;
        };
        if fact.transfer != "object_assignment" {
            continue;
        }
        let Some(source) = fact
            .inputs
            .iter()
            .find_map(|input| simple_variable_name(input))
        else {
            continue;
        };
        let Some(target) = simple_variable_name(&fact.target) else {
            continue;
        };
        let identity = (
            association.data_flow_index,
            association.path_index,
            association.path_position,
        );
        if !seen.insert(identity) {
            continue;
        }
        if result.facts.len() >= limit {
            result.truncated = true;
            return result;
        }
        result.facts.push(PathAliasFact {
            data_flow_index: association.data_flow_index,
            path_index: association.path_index,
            path_position: association.path_position,
            module: fact.module.clone(),
            procedure: fact.procedure.clone().unwrap_or_default(),
            target,
            source,
            conditions: association.conditions.clone(),
            feasibility: association.feasibility.clone(),
            path_complete: association.path_complete,
        });
    }
    result
}

/// Connect a path-local object alias to a later member call when the alias
/// source has one statically resolvable in-project member owner. The original
/// `CallFact` is preserved; this is a separate path-conditioned dispatch
/// candidate and does not claim runtime object identity.
#[allow(clippy::too_many_arguments)]
pub fn derive_path_alias_dispatches(
    project: &Project,
    calls: &[CallFact],
    data_flow: &[DataFlowFact],
    associations: &[DataFlowPathFact],
    aliases: &[PathAliasFact],
    limit: usize,
    step_limit: usize,
) -> PathAliasDispatchAnalysis {
    let mut result = PathAliasDispatchAnalysis::default();
    let mut steps = 0usize;
    let mut seen = HashSet::new();
    for (call_index, call) in calls.iter().enumerate() {
        if steps >= step_limit {
            result.truncated = true;
            return result;
        }
        steps += 1;
        let Some(caller_procedure_name) = call.procedure.as_deref() else {
            continue;
        };
        let Some(caller_module) = project
            .modules
            .iter()
            .find(|module| module.name.eq_ignore_ascii_case(&call.module))
        else {
            continue;
        };
        let Some(caller_procedure) = caller_module
            .procedures
            .iter()
            .find(|procedure| procedure.name.eq_ignore_ascii_case(caller_procedure_name))
        else {
            continue;
        };
        let Some(receiver) = receiver_identifier_before_call(caller_module, call.span) else {
            continue;
        };
        let call_data_flow_indices = data_flow
            .iter()
            .enumerate()
            .filter(|(_, fact)| {
                fact.module.eq_ignore_ascii_case(&call.module)
                    && fact
                        .procedure
                        .as_deref()
                        .is_some_and(|name| name.eq_ignore_ascii_case(caller_procedure_name))
                    && fact.span == call.span
                    && (fact.transfer == "procedure_argument_input_candidate"
                        || fact.transfer == "function_return_candidate"
                        || fact.transfer == "property_set_argument_candidate")
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        for alias in aliases.iter().filter(|alias| {
            alias.module.eq_ignore_ascii_case(&call.module)
                && alias.procedure.eq_ignore_ascii_case(caller_procedure_name)
                && alias.target.eq_ignore_ascii_case(&receiver)
        }) {
            let Some(module_index) = unique_project_module_index(project, caller_module) else {
                continue;
            };
            let source_expr = Expr::Identifier(alias.source.clone(), call.span);
            let Some((owner_index, self_access)) = crate::typecheck::member_owner(
                project,
                module_index,
                caller_module,
                caller_procedure,
                &source_expr,
            ) else {
                continue;
            };
            let owner = &project.modules[owner_index];
            let candidates = owner
                .procedures
                .iter()
                .filter(|procedure| {
                    procedure.name.eq_ignore_ascii_case(&call.target)
                        && (self_access || !procedure.visibility.eq_ignore_ascii_case("private"))
                })
                .map(|procedure| format!("{}.{}", owner.name, procedure.name))
                .collect::<Vec<_>>();
            if candidates.is_empty() {
                continue;
            }
            if call_data_flow_indices.is_empty() {
                let alias_line = data_flow
                    .get(alias.data_flow_index)
                    .map(|fact| fact.span.line)
                    .unwrap_or_default();
                if call.span.line <= alias_line {
                    continue;
                }
                if steps >= step_limit {
                    result.truncated = true;
                    return result;
                }
                steps += 1;
                let identity = (call_index, alias.data_flow_index, alias.path_index);
                if !seen.insert(identity) {
                    continue;
                }
                if result.facts.len() >= limit {
                    result.truncated = true;
                    return result;
                }
                let resolution = if candidates.len() == 1 {
                    "path_alias_typed_member_dispatch_candidate"
                } else {
                    "ambiguous_path_alias_typed_member_dispatch_candidates"
                };
                result.facts.push(PathAliasDispatchFact {
                    call_index,
                    alias_data_flow_index: alias.data_flow_index,
                    path_index: alias.path_index,
                    path_position: alias.path_position.saturating_add(1),
                    module: call.module.clone(),
                    procedure: caller_procedure_name.to_owned(),
                    receiver: receiver.clone(),
                    alias_source: alias.source.clone(),
                    member: call.target.clone(),
                    dispatch_candidates: candidates.clone(),
                    resolution: resolution.into(),
                    conditions: alias.conditions.clone(),
                    feasibility: alias.feasibility.clone(),
                    path_complete: alias.path_complete,
                });
                continue;
            }
            for association in associations.iter().filter(|association| {
                call_data_flow_indices.contains(&association.data_flow_index)
                    && association.path_index == alias.path_index
                    && association.path_position > alias.path_position
            }) {
                if steps >= step_limit {
                    result.truncated = true;
                    return result;
                }
                steps += 1;
                let identity = (call_index, alias.data_flow_index, association.path_index);
                if !seen.insert(identity) {
                    continue;
                }
                if result.facts.len() >= limit {
                    result.truncated = true;
                    return result;
                }
                let mut conditions = alias.conditions.clone();
                conditions.extend(association.conditions.iter().cloned());
                let resolution = if candidates.len() == 1 {
                    "path_alias_typed_member_dispatch_candidate"
                } else {
                    "ambiguous_path_alias_typed_member_dispatch_candidates"
                };
                result.facts.push(PathAliasDispatchFact {
                    call_index,
                    alias_data_flow_index: alias.data_flow_index,
                    path_index: association.path_index,
                    path_position: association.path_position,
                    module: call.module.clone(),
                    procedure: caller_procedure_name.to_owned(),
                    receiver: receiver.clone(),
                    alias_source: alias.source.clone(),
                    member: call.target.clone(),
                    dispatch_candidates: candidates.clone(),
                    resolution: resolution.into(),
                    conditions,
                    feasibility: combined_path_feasibility(
                        &alias.conditions,
                        &association.conditions,
                        &alias.feasibility,
                        &association.feasibility,
                    ),
                    path_complete: alias.path_complete && association.path_complete,
                });
            }
        }
    }
    result
}

fn receiver_identifier_before_call(module: &Module, span: crate::model::Span) -> Option<String> {
    let prefix = module.analysis_text.get(..span.start)?.trim_end();
    let prefix = prefix.strip_suffix('.')?.trim_end();
    let receiver = prefix
        .rsplit(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .next()?;
    simple_variable_name(receiver)
}

pub fn derive_path_value_flows(
    project: &Project,
    data_flow: &[DataFlowFact],
    associations: &[DataFlowPathFact],
    limit: usize,
    step_limit: usize,
) -> PathValueFlowAnalysis {
    let constant_sources = ConstantSourceIndex::new(project, data_flow);

    let mut by_path: HashMap<usize, Vec<&DataFlowPathFact>> = HashMap::new();
    let mut path_order = Vec::new();
    for association in associations {
        if !by_path.contains_key(&association.path_index) {
            path_order.push(association.path_index);
        }
        by_path
            .entry(association.path_index)
            .or_default()
            .push(association);
    }

    let mut result = PathValueFlowAnalysis::default();
    let mut seen = HashSet::new();
    let mut steps = 0usize;
    for path_index in path_order {
        let Some(path_facts) = by_path.get_mut(&path_index) else {
            continue;
        };
        path_facts.sort_by_key(|fact| (fact.path_position, fact.data_flow_index));
        let Some(path_context) = path_facts.first() else {
            continue;
        };
        let path_module = &path_context.module;
        let path_procedure = &path_context.procedure;
        let mut reaching: HashMap<String, Vec<usize>> = HashMap::new();
        let mut start = 0usize;
        while start < path_facts.len() {
            let path_position = path_facts[start].path_position;
            let mut end = start + 1;
            while end < path_facts.len() && path_facts[end].path_position == path_position {
                end += 1;
            }

            // Reads at one statement all see definitions that reach the
            // statement's entry; writes become visible only at the next node.
            for association in &path_facts[start..end] {
                let Some(fact) = data_flow.get(association.data_flow_index) else {
                    continue;
                };
                for input in &fact.inputs {
                    if steps >= step_limit {
                        result.truncated = true;
                        return result;
                    }
                    steps += 1;
                    let (variable, key, qualified_constant) =
                        if let Some(variable) = simple_variable_name(input) {
                            let key = canonical_data_name(&variable);
                            (variable, key.clone(), None)
                        } else if let Some(source) = constant_sources.resolve_qualified(input) {
                            // Qualified module names here are provenance copied
                            // from a callee's return summary. Resolve only a
                            // unique module-level Const; never treat arbitrary
                            // member expressions as caller-local variables.
                            (input.clone(), canonical_data_name(input), Some(source))
                        } else {
                            continue;
                        };
                    let definitions = if qualified_constant.is_some() {
                        None
                    } else {
                        reaching.get(&key)
                    };
                    let source_data_flow_indices: Vec<Option<usize>> = definitions
                        .map(|definitions| definitions.iter().copied().map(Some).collect())
                        .unwrap_or_else(|| {
                            vec![qualified_constant.or_else(|| {
                                constant_sources.resolve(path_module, path_procedure, &key)
                            })]
                        });
                    for source_data_flow_index in source_data_flow_indices {
                        let identity = (
                            path_index,
                            source_data_flow_index,
                            association.data_flow_index,
                            key.clone(),
                        );
                        if !seen.insert(identity) {
                            continue;
                        }
                        if result.facts.len() >= limit {
                            result.truncated = true;
                            return result;
                        }
                        result.facts.push(PathValueFlowFact {
                            path_index,
                            source_data_flow_index,
                            target_data_flow_index: association.data_flow_index,
                            variable: variable.clone(),
                            resolution: source_data_flow_index
                                .and_then(|index| data_flow.get(index))
                                .filter(|source| source.transfer == "constant_initializer")
                                .map(|_| "constant_initializer_candidate")
                                .unwrap_or_else(|| {
                                    if source_data_flow_index.is_some() {
                                        "reaching_definition_candidate"
                                    } else {
                                        "no_prior_local_definition_on_path"
                                    }
                                })
                                .into(),
                            conditions: association.conditions.clone(),
                            feasibility: association.feasibility.clone(),
                            path_complete: association.path_complete,
                        });
                    }
                }
            }

            let mut writes: HashMap<String, Vec<usize>> = HashMap::new();
            for association in &path_facts[start..end] {
                let Some(fact) = data_flow.get(association.data_flow_index) else {
                    continue;
                };
                if !defines_simple_target(&fact.transfer) {
                    continue;
                }
                if let Some(variable) = simple_variable_name(&fact.target) {
                    writes
                        .entry(canonical_data_name(&variable))
                        .or_default()
                        .push(association.data_flow_index);
                }
            }
            for (variable, definitions) in writes {
                reaching.insert(variable, definitions);
            }
            start = end;
        }
    }
    result
}

fn canonical_data_name(name: &str) -> String {
    name.trim_end_matches(['%', '&', '^', '@', '!', '#', '$'])
        .to_ascii_lowercase()
}

#[derive(Clone, Copy, Debug, Default)]
struct SymbolCounts {
    declarations: usize,
    constants: usize,
}

#[derive(Default)]
struct ConstantSourceIndex {
    module_name_counts: HashMap<String, usize>,
    module_symbols: HashMap<(String, String), SymbolCounts>,
    procedure_symbols: HashMap<(String, String, String), SymbolCounts>,
    module_procedures: HashSet<(String, String)>,
    module_constants: HashMap<(String, String), usize>,
    procedure_constants: HashMap<(String, String, String), usize>,
    public_constants: HashMap<String, Vec<usize>>,
}

impl ConstantSourceIndex {
    fn new(project: &Project, data_flow: &[DataFlowFact]) -> Self {
        let mut index = Self::default();
        for module in &project.modules {
            let module_name = canonical_data_name(&module.name);
            *index
                .module_name_counts
                .entry(module_name.clone())
                .or_default() += 1;
            for declaration in &module.declarations {
                let counts = index
                    .module_symbols
                    .entry((module_name.clone(), canonical_data_name(&declaration.name)))
                    .or_default();
                counts.declarations += 1;
                counts.constants += usize::from(declaration.kind == "constant");
            }
            for procedure in &module.procedures {
                let procedure_name = canonical_data_name(&procedure.name);
                index
                    .module_procedures
                    .insert((module_name.clone(), procedure_name.clone()));
                for parameter in &procedure.parameters {
                    index
                        .procedure_symbols
                        .entry((
                            module_name.clone(),
                            procedure_name.clone(),
                            canonical_data_name(&parameter.name),
                        ))
                        .or_default()
                        .declarations += 1;
                }
                collect_procedure_symbol_counts(
                    &mut index.procedure_symbols,
                    &module_name,
                    &procedure_name,
                    &procedure.statements,
                );
            }
        }

        let mut module_constant_facts: HashMap<(String, String), Vec<usize>> = HashMap::new();
        let mut procedure_constant_facts: HashMap<(String, String, String), Vec<usize>> =
            HashMap::new();
        for (fact_index, fact) in data_flow.iter().enumerate() {
            if fact.transfer != "constant_initializer" {
                continue;
            }
            let module_name = canonical_data_name(&fact.module);
            let name = canonical_data_name(&fact.target);
            if let Some(procedure) = &fact.procedure {
                procedure_constant_facts
                    .entry((module_name, canonical_data_name(procedure), name))
                    .or_default()
                    .push(fact_index);
            } else {
                module_constant_facts
                    .entry((module_name, name))
                    .or_default()
                    .push(fact_index);
            }
        }

        for (scope, counts) in &index.module_symbols {
            if counts.declarations != 1
                || counts.constants != 1
                || index.module_procedures.contains(scope)
            {
                continue;
            }
            if let Some(sources) = module_constant_facts.get(scope)
                && sources.len() == 1
            {
                index.module_constants.insert(scope.clone(), sources[0]);
            }
        }
        for (scope, counts) in &index.procedure_symbols {
            if counts.declarations != 1 || counts.constants != 1 {
                continue;
            }
            if let Some(sources) = procedure_constant_facts.get(scope)
                && sources.len() == 1
            {
                index.procedure_constants.insert(scope.clone(), sources[0]);
            }
        }

        for module in &project.modules {
            if !matches!(module.module_kind.as_deref(), Some("standard") | None) {
                continue;
            }
            let module_name = canonical_data_name(&module.name);
            for declaration in &module.declarations {
                if declaration.kind != "constant"
                    || !(declaration.visibility.eq_ignore_ascii_case("public")
                        || declaration.visibility.eq_ignore_ascii_case("global"))
                {
                    continue;
                }
                let name = canonical_data_name(&declaration.name);
                if let Some(source) = index
                    .module_constants
                    .get(&(module_name.clone(), name.clone()))
                {
                    index
                        .public_constants
                        .entry(name)
                        .or_default()
                        .push(*source);
                }
            }
        }
        index
    }

    fn resolve(&self, module_name: &str, procedure_name: &str, variable: &str) -> Option<usize> {
        let module_name = canonical_data_name(module_name);
        let procedure_name = canonical_data_name(procedure_name);
        let local_scope = (module_name.clone(), procedure_name, variable.to_owned());
        if let Some(counts) = self.procedure_symbols.get(&local_scope)
            && counts.declarations > 0
        {
            if counts.declarations == 1 && counts.constants == 1 {
                return self.procedure_constants.get(&local_scope).copied();
            }
            return None;
        }

        let module_scope = (module_name.clone(), variable.to_owned());
        if let Some(counts) = self.module_symbols.get(&module_scope)
            && counts.declarations > 0
        {
            if counts.declarations == 1
                && counts.constants == 1
                && !self.module_procedures.contains(&module_scope)
            {
                return self.module_constants.get(&module_scope).copied();
            }
            return None;
        }
        if self.module_procedures.contains(&module_scope) {
            return None;
        }
        self.public_constants
            .get(variable)
            .filter(|sources| sources.len() == 1)
            .and_then(|sources| sources.first().copied())
    }

    fn resolve_qualified(&self, value: &str) -> Option<usize> {
        let (tokens, _) = lex(value.trim(), 8);
        let significant = tokens
            .iter()
            .filter(|token| !matches!(token.kind, TokenKind::Newline | TokenKind::Eof))
            .collect::<Vec<_>>();
        let [module, separator, member] = significant.as_slice() else {
            return None;
        };
        if module.kind != TokenKind::Identifier
            || separator.text != "."
            || member.kind != TokenKind::Identifier
        {
            return None;
        }
        let module_name = canonical_data_name(&module.text);
        if self.module_name_counts.get(&module_name) != Some(&1) {
            return None;
        }
        self.module_constants
            .get(&(module_name, canonical_data_name(&member.text)))
            .copied()
    }
}

fn collect_procedure_symbol_counts(
    symbols: &mut HashMap<(String, String, String), SymbolCounts>,
    module_name: &str,
    procedure_name: &str,
    statements: &[Statement],
) {
    for statement in statements {
        if let Some(declaration) = &statement.declaration
            && matches!(
                declaration.kind.as_str(),
                "variable" | "global" | "static" | "constant" | "with_events" | "redim_array"
            )
        {
            let counts = symbols
                .entry((
                    module_name.to_owned(),
                    procedure_name.to_owned(),
                    canonical_data_name(&declaration.name),
                ))
                .or_default();
            counts.declarations += 1;
            counts.constants += usize::from(declaration.kind == "constant");
        }
        collect_procedure_symbol_counts(symbols, module_name, procedure_name, &statement.children);
    }
}

/// Connect Excel read/write candidates in a statement to its simple assignment
/// candidates on the same structural path. This records a possible relation;
/// it does not establish a concrete workbook, cell, or runtime value.
pub fn derive_data_access_value_flows(
    data_accesses: &[DataAccessFact],
    data_flow: &[DataFlowFact],
    access_paths: &[DataAccessPathFact],
    flow_paths: &[DataFlowPathFact],
    limit: usize,
    step_limit: usize,
) -> DataAccessValueFlowAnalysis {
    type StatementPathKey = (usize, usize, usize);
    let mut accesses_by_statement: HashMap<StatementPathKey, Vec<&DataAccessPathFact>> =
        HashMap::new();
    let mut statement_order = Vec::new();
    for association in access_paths {
        let key = (
            association.path_index,
            association.flow_node_id,
            association.path_position,
        );
        if !accesses_by_statement.contains_key(&key) {
            statement_order.push(key);
        }
        accesses_by_statement
            .entry(key)
            .or_default()
            .push(association);
    }
    let mut flows_by_statement: HashMap<StatementPathKey, Vec<&DataFlowPathFact>> = HashMap::new();
    for association in flow_paths {
        flows_by_statement
            .entry((
                association.path_index,
                association.flow_node_id,
                association.path_position,
            ))
            .or_default()
            .push(association);
    }

    let mut result = DataAccessValueFlowAnalysis::default();
    let mut seen = HashSet::new();
    let mut steps = 0usize;
    for key in statement_order {
        let Some(access_associations) = accesses_by_statement.get(&key) else {
            continue;
        };
        let Some(flow_associations) = flows_by_statement.get(&key) else {
            continue;
        };
        for access_association in access_associations {
            let Some(access) = data_accesses.get(access_association.data_access_index) else {
                continue;
            };
            for flow_association in flow_associations {
                if steps >= step_limit {
                    result.truncated = true;
                    return result;
                }
                steps += 1;
                let Some(flow) = data_flow.get(flow_association.data_flow_index) else {
                    continue;
                };
                if !matches!(
                    flow.transfer.as_str(),
                    "assignment" | "object_assignment" | "function_return_candidate"
                ) {
                    continue;
                }
                let mut links = Vec::new();
                match access.operation.as_str() {
                    "read_candidate" => {
                        if let Some(variable) = simple_variable_name(&flow.target) {
                            links.push(("excel_read_to_variable_candidate", variable));
                        }
                    }
                    "write_candidate" => {
                        links.extend(flow.inputs.iter().filter_map(|input| {
                            simple_variable_name(input)
                                .map(|variable| ("variable_to_excel_write_candidate", variable))
                        }));
                    }
                    _ => {}
                }
                for (role, variable) in links {
                    let identity = (
                        access_association.path_index,
                        access_association.data_access_index,
                        flow_association.data_flow_index,
                        role,
                        variable.to_ascii_lowercase(),
                    );
                    if !seen.insert(identity) {
                        continue;
                    }
                    if result.facts.len() >= limit {
                        result.truncated = true;
                        return result;
                    }
                    result.facts.push(DataAccessValueFlowFact {
                        path_index: access_association.path_index,
                        data_access_index: access_association.data_access_index,
                        excel_worksheet_access_index: None,
                        data_flow_index: flow_association.data_flow_index,
                        role: role.into(),
                        variable,
                        conditions: access_association.conditions.clone(),
                        feasibility: access_association.feasibility.clone(),
                        path_complete: access_association.path_complete
                            && flow_association.path_complete,
                    });
                }
            }
        }
    }
    result
}

/// Connect Excel reads in condition nodes to each traversed decision outcome.
/// The result describes structural source-to-branch links only.
pub fn associate_data_access_predicates(
    data_accesses: &[DataAccessFact],
    graphs: &[ControlFlowGraph],
    paths: &[ControlFlowPath],
    access_paths: &[DataAccessPathFact],
) -> DataAccessPredicateAnalysis {
    let mut by_procedure: HashMap<(String, String), Vec<&DataAccessPathFact>> = HashMap::new();
    let mut procedure_order = Vec::new();
    for association in access_paths {
        let key = (association.module.clone(), association.procedure.clone());
        if !by_procedure.contains_key(&key) {
            procedure_order.push(key.clone());
        }
        by_procedure.entry(key).or_default().push(association);
    }

    let mut result = DataAccessPredicateAnalysis::default();
    for (module, procedure) in procedure_order {
        let mut matching_graphs = graphs
            .iter()
            .filter(|graph| graph.module == module && graph.procedure == procedure);
        let Some(graph) = matching_graphs.next() else {
            continue;
        };
        if matching_graphs.next().is_some() {
            continue;
        }
        let mut edge_conditions: HashMap<(usize, usize), Vec<Option<&str>>> = HashMap::new();
        for edge in &graph.edges {
            edge_conditions
                .entry((edge.from, edge.to))
                .or_default()
                .push(edge.condition.as_deref());
        }
        let Some(access_associations) = by_procedure.get(&(module.clone(), procedure.clone()))
        else {
            continue;
        };
        for association in access_associations {
            if data_accesses
                .get(association.data_access_index)
                .is_none_or(|access| access.operation != "read_candidate")
            {
                continue;
            }
            let Some(node) = graph.nodes.get(association.flow_node_id) else {
                continue;
            };
            let Some(path) = paths.get(association.path_index) else {
                result.unassociated_count += 1;
                continue;
            };
            if path.nodes.get(association.path_position) != Some(&node.id) {
                result.unassociated_count += 1;
                continue;
            }
            let (edge_key, conditions_before) = match node.kind.as_str() {
                "decision" | "case_test" | "loop_test" => {
                    let Some(&next_node) = path.nodes.get(association.path_position + 1) else {
                        result.unassociated_count += 1;
                        continue;
                    };
                    ((node.id, next_node), association.conditions.clone())
                }
                "case" => {
                    if association.path_position == 0 {
                        result.unassociated_count += 1;
                        continue;
                    }
                    let previous_node = path.nodes[association.path_position - 1];
                    let conditions_before = association
                        .conditions
                        .get(..association.conditions.len().saturating_sub(1))
                        .unwrap_or(&[])
                        .to_vec();
                    ((previous_node, node.id), conditions_before)
                }
                _ => continue,
            };
            let Some(conditions) = edge_conditions.get(&edge_key) else {
                result.unassociated_count += 1;
                continue;
            };
            let Some(outcome_condition) = conditions.first().copied().flatten() else {
                result.unassociated_count += 1;
                continue;
            };
            if conditions
                .iter()
                .any(|condition| condition.as_deref() != Some(outcome_condition))
            {
                result.unassociated_count += 1;
                continue;
            }
            result.facts.push(DataAccessPredicateFact {
                path_index: association.path_index,
                data_access_index: association.data_access_index,
                excel_worksheet_access_index: None,
                flow_node_id: node.id,
                module: module.clone(),
                procedure: procedure.clone(),
                conditions_before,
                outcome_condition: outcome_condition.to_owned(),
                feasibility: path.feasibility.clone(),
                path_complete: path.complete,
                span: association.span,
            });
        }
    }
    result
}

fn defines_simple_target(transfer: &str) -> bool {
    matches!(
        transfer,
        "assignment"
            | "object_assignment"
            | "constant_initializer"
            | "function_return_candidate"
            | "file_read_candidate"
            | "byref_argument_write"
            | "event_handler_byref_write_candidate"
            | "default_member_byref_write_candidate"
    )
}

fn simple_variable_name(value: &str) -> Option<String> {
    let (tokens, _) = lex(value.trim(), 16);
    let mut significant = tokens
        .iter()
        .filter(|token| !matches!(token.kind, TokenKind::Newline | TokenKind::Eof));
    let token = significant.next()?;
    if token.kind == TokenKind::Identifier && significant.next().is_none() {
        Some(token.text.clone())
    } else {
        None
    }
}

fn is_transfer_node(kind: &str) -> bool {
    !matches!(
        kind,
        "entry"
            | "exit"
            | "decision"
            | "case_test"
            | "select_expression"
            | "branch"
            | "implicit_else"
            | "loop_test"
            | "for_repeat_test"
            | "loop_body"
            | "loop_exit"
            | "case"
            | "no_case_match"
            | "label"
            | "with"
    )
}

fn is_data_access_node(kind: &str) -> bool {
    !matches!(
        kind,
        "entry"
            | "exit"
            | "branch"
            | "implicit_else"
            | "loop_body"
            | "loop_exit"
            | "no_case_match"
            | "label"
            | "goto"
            | "termination"
    )
}

fn conditions_before_node(
    graph: &ControlFlowGraph,
    path: &ControlFlowPath,
    position: usize,
) -> Option<Vec<String>> {
    if position >= path.nodes.len() {
        return None;
    }
    let mut conditions = Vec::new();
    for pair in path.nodes[..=position].windows(2) {
        let mut matching_edges = graph
            .edges
            .iter()
            .filter(|edge| edge.from == pair[0] && edge.to == pair[1]);
        let edge = matching_edges.next()?;
        let first_condition = edge.condition.as_deref();
        if matching_edges.any(|candidate| candidate.condition.as_deref() != first_condition) {
            return None;
        }
        if let Some(condition) = first_condition {
            conditions.push(condition.to_owned());
        }
    }
    Some(conditions)
}

/// Recover condition prefixes even when multiple error-state edges share the
/// same node pair. The path's condition sequence disambiguates those edges.
fn conditions_before_node_from_path(
    graph: &ControlFlowGraph,
    path: &ControlFlowPath,
    position: usize,
) -> Option<Vec<String>> {
    if position >= path.nodes.len() {
        return None;
    }
    let mut condition_offsets = HashSet::from([0usize]);
    for pair in path.nodes[..=position].windows(2) {
        let edges = graph
            .edges
            .iter()
            .filter(|edge| edge.from == pair[0] && edge.to == pair[1])
            .collect::<Vec<_>>();
        if edges.is_empty() {
            return None;
        }
        let mut next_offsets = HashSet::new();
        for offset in &condition_offsets {
            for edge in &edges {
                match edge.condition.as_deref() {
                    None => {
                        next_offsets.insert(*offset);
                    }
                    Some(condition)
                        if path
                            .conditions
                            .get(*offset)
                            .is_some_and(|path_condition| path_condition == condition) =>
                    {
                        next_offsets.insert(*offset + 1);
                    }
                    Some(_) => {}
                }
            }
        }
        if next_offsets.is_empty() {
            return None;
        }
        condition_offsets = next_offsets;
    }
    let mut prefixes = condition_offsets
        .into_iter()
        .filter_map(|offset| path.conditions.get(..offset).map(<[String]>::to_vec));
    let first = prefixes.next()?;
    prefixes.all(|prefix| prefix == first).then_some(first)
}

pub fn enumerate_control_flow_paths(
    graph: &ControlFlowGraph,
    limits: &Limits,
) -> Vec<ControlFlowPath> {
    enumerate_graph_paths(graph, limits).paths
}

#[derive(Clone, Debug, Default)]
pub struct PathEnumeration {
    pub paths: Vec<ControlFlowPath>,
    pub truncated: bool,
}

#[derive(Clone, Copy)]
struct ProcedurePathContext<'a> {
    project: Option<&'a Project>,
    module: &'a Module,
    procedure: &'a Procedure,
    call_facts: Option<&'a [CallFact]>,
    path_values: Option<&'a HashMap<String, Expr>>,
    callsite_parameter_values: Option<&'a StaticParameterValues>,
    param_array_lengths: Option<&'a StaticParamArrayLengths>,
    /// Path-local dynamic array shapes after bounded `ReDim`/`Erase` steps.
    /// Keys are canonical procedure-local/module-visible names. A missing key
    /// means the shape is unknown (including after an unsupported mutation).
    array_shapes: Option<&'a StaticArrayShapes>,
    optional_missing: Option<&'a HashSet<String>>,
}

pub(crate) type StaticParameterValues = HashMap<(String, String), HashMap<String, Expr>>;
pub(crate) type StaticParamArrayLengths = HashMap<(String, String, String), usize>;
type StaticArrayShapes = HashMap<String, Vec<crate::model::ArrayDimension>>;

pub fn enumerate_graph_paths(graph: &ControlFlowGraph, limits: &Limits) -> PathEnumeration {
    enumerate_graph_paths_with_constants(graph, limits, None)
}

/// Enumerate paths and classify branches made impossible by supported literal
/// and uniquely scoped Const values. This remains a partial value evaluator;
/// unsupported values and ambiguously resolved names stay `not_checked`.
pub fn enumerate_graph_paths_for_procedure(
    graph: &ControlFlowGraph,
    module: &Module,
    procedure: &Procedure,
    limits: &Limits,
) -> PathEnumeration {
    enumerate_graph_paths_with_constants(
        graph,
        limits,
        Some(ProcedurePathContext {
            project: None,
            module,
            procedure,
            call_facts: None,
            path_values: None,
            callsite_parameter_values: None,
            param_array_lengths: None,
            array_shapes: None,
            optional_missing: None,
        }),
    )
}

/// Enumerate paths with project context so a small set of VBA intrinsic values
/// can be folded only when no project symbol shadows the intrinsic name.
pub fn enumerate_graph_paths_for_project_procedure(
    graph: &ControlFlowGraph,
    project: &Project,
    module: &Module,
    procedure: &Procedure,
    limits: &Limits,
) -> PathEnumeration {
    enumerate_graph_paths_with_constants(
        graph,
        limits,
        Some(ProcedurePathContext {
            project: Some(project),
            module,
            procedure,
            call_facts: None,
            path_values: None,
            callsite_parameter_values: None,
            param_array_lengths: None,
            array_shapes: None,
            optional_missing: None,
        }),
    )
}

pub(crate) fn enumerate_graph_paths_for_project_procedure_with_calls(
    graph: &ControlFlowGraph,
    project: &Project,
    call_facts: &[CallFact],
    callsite_parameter_values: &StaticParameterValues,
    module: &Module,
    procedure: &Procedure,
    limits: &Limits,
) -> PathEnumeration {
    enumerate_graph_paths_with_constants(
        graph,
        limits,
        Some(ProcedurePathContext {
            project: Some(project),
            module,
            procedure,
            call_facts: Some(call_facts),
            path_values: None,
            callsite_parameter_values: Some(callsite_parameter_values),
            param_array_lengths: None,
            array_shapes: None,
            optional_missing: None,
        }),
    )
}

fn enumerate_graph_paths_with_constants(
    graph: &ControlFlowGraph,
    limits: &Limits,
    context: Option<ProcedurePathContext<'_>>,
) -> PathEnumeration {
    if graph.nodes.is_empty() || limits.max_paths == 0 {
        return PathEnumeration {
            paths: Vec::new(),
            truncated: !graph.nodes.is_empty(),
        };
    }
    let mut output = PathEnumeration::default();
    let mut nodes = vec![graph.entry];
    let mut conditions = Vec::new();
    walk(
        graph,
        graph.entry,
        limits,
        &mut nodes,
        &mut conditions,
        &mut output,
        context,
    );
    output
}

fn walk(
    graph: &ControlFlowGraph,
    current: usize,
    limits: &Limits,
    nodes: &mut Vec<usize>,
    conditions: &mut Vec<String>,
    out: &mut PathEnumeration,
    context: Option<ProcedurePathContext<'_>>,
) {
    if out.paths.len() >= limits.max_paths {
        out.truncated = true;
        return;
    }
    if current == graph.exit {
        push_path(graph, nodes, conditions, "exit", out, context);
        return;
    }
    if nodes.len() >= limits.max_path_depth {
        out.truncated = true;
        push_path(graph, nodes, conditions, "depth_limit", out, context);
        return;
    }
    let edges = graph
        .edges
        .iter()
        .filter(|e| e.from == current)
        .collect::<Vec<_>>();
    if edges.is_empty() {
        push_path(graph, nodes, conditions, "dead_end", out, context);
        return;
    }
    for edge in edges {
        if out.paths.len() >= limits.max_paths {
            out.truncated = true;
            return;
        }
        if let Some(c) = &edge.condition {
            conditions.push(c.clone());
        }
        if nodes.contains(&edge.to) {
            out.truncated = true;
            nodes.push(edge.to);
            push_path(graph, nodes, conditions, "cycle_pruned", out, context);
            nodes.pop();
        } else {
            nodes.push(edge.to);
            walk(graph, edge.to, limits, nodes, conditions, out, context);
            nodes.pop();
        }
        if edge.condition.is_some() {
            conditions.pop();
        }
    }
}

fn push_path(
    graph: &ControlFlowGraph,
    nodes: &[usize],
    conditions: &[String],
    reason: &str,
    out: &mut PathEnumeration,
    context: Option<ProcedurePathContext<'_>>,
) {
    let feasibility = if path_has_infeasible_condition(graph, nodes, conditions, context) {
        "infeasible_constant_condition"
    } else {
        "not_checked"
    };
    out.paths.push(ControlFlowPath {
        module: graph.module.clone(),
        procedure: graph.procedure.clone(),
        nodes: nodes.to_vec(),
        conditions: conditions.to_vec(),
        stop_reason: reason.into(),
        feasibility: feasibility.into(),
        complete: graph.complete && reason == "exit",
    });
}

fn path_has_infeasible_condition(
    graph: &ControlFlowGraph,
    nodes: &[usize],
    conditions: &[String],
    context: Option<ProcedurePathContext<'_>>,
) -> bool {
    let Some(context) = context else {
        return conditions.iter().any(|condition| {
            evaluate_literal_branch_condition_in_context(condition, None) == Some(false)
        });
    };
    if conditions.is_empty() || !path_value_tracking_is_supported(graph, nodes) {
        return conditions.iter().any(|condition| {
            evaluate_literal_branch_condition_in_context(condition, Some(context)) == Some(false)
        });
    }

    let procedure_key = (
        canonical_data_name(&context.module.name),
        canonical_data_name(&context.procedure.name),
    );
    let mut path_values = context
        .callsite_parameter_values
        .and_then(|values| values.get(&procedure_key))
        .cloned()
        .unwrap_or_default();
    let mut array_shapes = StaticArrayShapes::new();
    let mut condition_index = 0usize;
    for (index, node_id) in nodes.iter().enumerate() {
        let Some(node) = graph.nodes.get(*node_id) else {
            return conditions.iter().any(|condition| {
                evaluate_literal_branch_condition_in_context(condition, Some(context))
                    == Some(false)
            });
        };
        update_path_value_state(node, context, &mut path_values, &mut array_shapes);

        let Some(next_node) = nodes.get(index + 1) else {
            continue;
        };
        let Some(condition) = conditions.get(condition_index) else {
            continue;
        };
        if graph.edges.iter().any(|edge| {
            edge.from == *node_id
                && edge.to == *next_node
                && edge.condition.as_deref() == Some(condition.as_str())
        }) {
            let path_context = ProcedurePathContext {
                path_values: Some(&path_values),
                array_shapes: Some(&array_shapes),
                ..context
            };
            if evaluate_literal_branch_condition_in_context(condition, Some(path_context))
                == Some(false)
            {
                return true;
            }
            condition_index += 1;
        }
    }

    conditions[condition_index..].iter().any(|condition| {
        evaluate_literal_branch_condition_in_context(condition, Some(context)) == Some(false)
    })
}

fn path_value_tracking_is_supported(graph: &ControlFlowGraph, nodes: &[usize]) -> bool {
    if !graph.complete {
        return false;
    }
    let mut visited = HashSet::new();
    if nodes.iter().any(|node_id| {
        let Some(node) = graph.nodes.get(*node_id) else {
            return true;
        };
        !visited.insert(*node_id)
            || node.kind.contains("loop")
            || node.kind.starts_with("for_")
            || node.kind.starts_with("do_")
            || node.kind.starts_with("gosub")
            || node.kind == "on_goto"
            || node.kind == "on_gosub"
    }) {
        return false;
    }
    nodes.windows(2).all(|pair| {
        graph
            .edges
            .iter()
            .filter(|edge| edge.from == pair[0] && edge.to == pair[1])
            .count()
            == 1
    })
}

fn update_path_value_state(
    node: &crate::model::FlowNode,
    context: ProcedurePathContext<'_>,
    values: &mut HashMap<String, Expr>,
    array_shapes: &mut StaticArrayShapes,
) {
    match node.kind.as_str() {
        "redim" => {
            let Some(statement) = find_statement_by_span(&context.procedure.statements, node.span)
            else {
                array_shapes.clear();
                values.clear();
                return;
            };
            for child in &statement.children {
                let Some(declaration) = child.declaration.as_ref() else {
                    array_shapes.clear();
                    continue;
                };
                let Some(name) = path_array_target_name(&declaration.name) else {
                    array_shapes.clear();
                    continue;
                };
                let key = canon_flow(&name);
                if declaration.array_dimensions.is_empty()
                    || declaration.array_dimensions.iter().any(|dimension| {
                        dimension
                            .upper_bound
                            .as_deref()
                            .is_none_or(|bound| bound.trim().is_empty())
                    })
                {
                    array_shapes.remove(&key);
                } else if declaration.kind == "redim_preserve"
                    && !array_shapes.get(&key).is_some_and(|previous| {
                        preserve_path_shape_compatible(
                            previous,
                            &declaration.array_dimensions,
                            context.module,
                        )
                    })
                {
                    // A failed or ambiguous Preserve raises Error 9 before
                    // the following statements. Do not retain a shape when
                    // the existing dynamic array cannot be proven compatible.
                    array_shapes.remove(&key);
                } else {
                    array_shapes.insert(key, declaration.array_dimensions.clone());
                }
            }
            values.clear();
        }
        "erase" => {
            let Some(statement) = find_statement_by_span(&context.procedure.statements, node.span)
            else {
                array_shapes.clear();
                values.clear();
                return;
            };
            if statement.children.is_empty() {
                array_shapes.clear();
            }
            for child in &statement.children {
                if let Some(expression) = child.expression.as_deref()
                    && let Some(name) = path_array_target_name(expression)
                {
                    array_shapes.remove(&canon_flow(&name));
                } else {
                    array_shapes.clear();
                }
            }
            values.clear();
        }
        "assignment" => {
            let Some(statement) =
                find_assignment_statement(&context.procedure.statements, node.span)
            else {
                values.clear();
                return;
            };
            let Some(Expr::Identifier(target, _)) = statement.parsed_target.as_ref() else {
                values.clear();
                array_shapes.clear();
                return;
            };
            let key = canon_flow(target);
            let Some(expression) = statement.parsed_expression.as_ref() else {
                values.remove(&key);
                return;
            };
            let explicit_set = statement
                .expression
                .as_deref()
                .is_some_and(|source| source.trim_start().to_ascii_lowercase().starts_with("set "));
            let assigns_nothing = matches!(
                expression,
                Expr::Identifier(name, _) if name.eq_ignore_ascii_case("Nothing")
            );
            if explicit_set != assigns_nothing {
                values.remove(&key);
                return;
            }
            if expression_has_unsafe_call(expression, context) {
                values.clear();
                array_shapes.clear();
                return;
            }
            let Some(project) = context.project else {
                values.remove(&key);
                return;
            };
            let Some(module_index) = unique_project_module_index(project, context.module) else {
                values.remove(&key);
                return;
            };
            let Some(target_type) = crate::typecheck::declared_symbol_type(
                project,
                module_index,
                context.module,
                Some(&context.procedure.name),
                target,
            ) else {
                values.clear();
                return;
            };
            let target_type = crate::typecheck::normalized_type(&target_type);
            let value_type = crate::typecheck::normalized_type(&crate::typecheck::infer_expr(
                project,
                module_index,
                context.module,
                context.procedure,
                expression,
                crate::host::HostProfile::Unknown,
            ));
            if explicit_set {
                let target_expression = Expr::Identifier(
                    target.to_owned(),
                    statement
                        .parsed_target
                        .as_ref()
                        .map(Expr::span)
                        .unwrap_or_default(),
                );
                let target_is_object = target_type == "variant"
                    || crate::typecheck::known_is_object_value(
                        project,
                        module_index,
                        context.module,
                        context.procedure,
                        &target_expression,
                    ) == Some(true);
                let source_is_object = crate::typecheck::known_is_object_value(
                    project,
                    module_index,
                    context.module,
                    context.procedure,
                    expression,
                ) == Some(true);
                if target_is_object && source_is_object {
                    values.insert(key, expression.clone());
                    return;
                }
                values.remove(&key);
                return;
            }
            let target_is_variant = target_type == "variant";
            let same_supported_scalar_type = target_type == value_type
                && matches!(
                    target_type.as_str(),
                    "boolean"
                        | "byte"
                        | "integer"
                        | "long"
                        | "single"
                        | "double"
                        | "currency"
                        | "date"
                        | "string"
                );
            let value_context = ProcedurePathContext {
                path_values: Some(values),
                ..context
            };
            let known_integer_literal = evaluate_literal_branch_value_in_context(
                expression,
                0,
                Some(value_context),
                &mut HashSet::new(),
                false,
            )
            .and_then(|value| match value {
                LiteralBranchValue::Integer(value) => Some(value),
                _ => None,
            });
            let numeric_literal_coercion = known_integer_literal
                .is_some_and(|value| integer_fits_path_scalar_type(value, &target_type));
            if !target_is_variant && !same_supported_scalar_type && !numeric_literal_coercion {
                values.remove(&key);
                return;
            }

            let expression = if let Expr::Identifier(source, _) = expression {
                values
                    .get(&canon_flow(source))
                    .cloned()
                    .unwrap_or_else(|| expression.clone())
            } else {
                expression.clone()
            };
            let value_context = ProcedurePathContext {
                path_values: Some(values),
                ..context
            };
            if path_value_expression_is_known(&expression, value_context, &mut HashSet::new(), 0) {
                values.insert(key, expression);
            } else {
                values.remove(&key);
            }
        }
        "entry" | "exit" | "declaration" | "decision" | "branch" | "implicit_else"
        | "select_expression" | "case_test" | "case" | "no_case_match" | "label" | "goto" => {
            if matches!(
                node.kind.as_str(),
                "decision" | "select_expression" | "case_test"
            ) && let Some(expression) = node
                .label
                .strip_prefix("Case test: ")
                .or(Some(node.label.as_str()))
                .and_then(crate::parser::parse_expression_source)
                && expression_has_unsafe_call(&expression, context)
            {
                values.clear();
            }
        }
        _ => {
            values.clear();
            array_shapes.clear();
        }
    }
}

fn integer_fits_path_scalar_type(value: i64, target_type: &str) -> bool {
    match target_type {
        "byte" => (0..=255).contains(&value),
        "integer" => (i16::MIN as i64..=i16::MAX as i64).contains(&value),
        "long" => (i32::MIN as i64..=i32::MAX as i64).contains(&value),
        "single" | "double" | "currency" => true,
        _ => false,
    }
}

fn find_assignment_statement(
    statements: &[Statement],
    span: crate::model::Span,
) -> Option<&Statement> {
    for statement in statements {
        if statement.kind == "assignment"
            && statement.span.start == span.start
            && statement.span.end == span.end
        {
            return Some(statement);
        }
        if let Some(found) = find_assignment_statement(&statement.children, span) {
            return Some(found);
        }
    }
    None
}

fn find_statement_by_span(
    statements: &[Statement],
    span: crate::model::Span,
) -> Option<&Statement> {
    for statement in statements {
        if statement.span.start == span.start && statement.span.end == span.end {
            return Some(statement);
        }
        if let Some(found) = find_statement_by_span(&statement.children, span) {
            return Some(found);
        }
    }
    None
}

fn path_array_target_name(expression: &str) -> Option<String> {
    let expression = expression.trim();
    let parsed = parse_expression_source(expression)?;
    match parsed {
        Expr::Identifier(name, _) if !name.trim().is_empty() => Some(name),
        _ => None,
    }
}

fn preserve_path_shape_compatible(
    previous: &[crate::model::ArrayDimension],
    next: &[crate::model::ArrayDimension],
    module: &Module,
) -> bool {
    if previous.len() != next.len() {
        return false;
    }
    previous
        .iter()
        .zip(next)
        .enumerate()
        .all(|(index, (old, new))| {
            let old_lower = old.lower_bound.as_deref().or_else(|| {
                module
                    .options
                    .array_base_valid
                    .then_some(if module.options.array_base == 0 {
                        "0"
                    } else {
                        "1"
                    })
            });
            let new_lower = new.lower_bound.as_deref().or_else(|| {
                module
                    .options
                    .array_base_valid
                    .then_some(if module.options.array_base == 0 {
                        "0"
                    } else {
                        "1"
                    })
            });
            canonical_path_bound(old_lower) == canonical_path_bound(new_lower)
                && (index + 1 == previous.len()
                    || canonical_path_bound(old.upper_bound.as_deref())
                        == canonical_path_bound(new.upper_bound.as_deref()))
        })
}

fn canonical_path_bound(bound: Option<&str>) -> Option<String> {
    let bound = bound?.trim();
    (!bound.is_empty()).then(|| {
        bound
            .split_whitespace()
            .collect::<String>()
            .to_ascii_lowercase()
    })
}

fn path_value_expression_is_known(
    expression: &Expr,
    context: ProcedurePathContext<'_>,
    resolving: &mut HashSet<String>,
    depth: usize,
) -> bool {
    if depth >= 64 || expression_has_unsafe_call(expression, context) {
        return false;
    }
    if let Some(project) = context.project
        && let Some(module_index) = unique_project_module_index(project, context.module)
        && crate::typecheck::known_is_array_value(
            project,
            module_index,
            context.module,
            context.procedure,
            expression,
        ) == Some(true)
    {
        return true;
    }
    if !path_expression_has_only_stable_identifiers(expression, context, resolving, depth + 1) {
        return false;
    }
    if evaluate_literal_branch_value_in_context(expression, depth, Some(context), resolving, false)
        .is_some()
    {
        return true;
    }
    let Some(project) = context.project else {
        return false;
    };
    let Some(module_index) = unique_project_module_index(project, context.module) else {
        return false;
    };
    crate::typecheck::known_vartype_value(
        project,
        module_index,
        context.module,
        context.procedure,
        expression,
    )
    .is_some()
        || crate::typecheck::known_is_date_value(
            project,
            module_index,
            context.module,
            context.procedure,
            expression,
        ) == Some(true)
        || crate::typecheck::known_is_array_value(
            project,
            module_index,
            context.module,
            context.procedure,
            expression,
        )
        .is_some()
        || crate::typecheck::known_is_object_value(
            project,
            module_index,
            context.module,
            context.procedure,
            expression,
        )
        .is_some()
        || crate::typecheck::known_is_error_value(
            project,
            module_index,
            context.module,
            context.procedure,
            expression,
        )
        .is_some()
        || statically_known_numeric_input(
            project,
            module_index,
            context.module,
            context.procedure,
            expression,
        )
        .is_some()
}

fn path_expression_has_only_stable_identifiers(
    expression: &Expr,
    context: ProcedurePathContext<'_>,
    resolving: &mut HashSet<String>,
    depth: usize,
) -> bool {
    if depth >= 64 {
        return false;
    }
    match expression {
        Expr::Identifier(name, _) => path_identifier_is_stable(name, context, resolving, depth),
        Expr::Call { callee, args, .. } => {
            let Expr::Identifier(name, _) = callee.as_ref() else {
                return false;
            };
            let name = canon_flow(name);
            let Some(project) = context.project else {
                return false;
            };
            let Some(module_index) = unique_project_module_index(project, context.module) else {
                return false;
            };
            let pure_intrinsic = matches!(
                name.as_str(),
                "array"
                    | "cbool"
                    | "cbyte"
                    | "ccur"
                    | "cdate"
                    | "cdec"
                    | "cverr"
                    | "cdbl"
                    | "cint"
                    | "clng"
                    | "clnglng"
                    | "clngptr"
                    | "csng"
                    | "cstr"
                    | "cvar"
                    | "cvdate"
                    | "val"
                    | "chr"
                    | "chrw"
                    | "asc"
                    | "ascw"
                    | "space"
                    | "string"
                    | "hex"
                    | "oct"
                    | "choose"
                    | "iif"
                    | "switch"
                    | "date"
                    | "dateadd"
                    | "dateserial"
                    | "datevalue"
                    | "datediff"
                    | "datepart"
                    | "now"
                    | "time"
                    | "timeserial"
                    | "timevalue"
                    | "isarray"
                    | "isdate"
                    | "isempty"
                    | "iserror"
                    | "ismissing"
                    | "isnull"
                    | "isnumeric"
                    | "isobject"
                    | "typename"
                    | "vartype"
                    | "len"
                    | "lenb"
                    | "instr"
                    | "instrrev"
                    | "left"
                    | "right"
                    | "mid"
                    | "ltrim"
                    | "rtrim"
                    | "trim"
                    | "replace"
            ) && !crate::typecheck::project_may_shadow_type_intrinsic(
                project,
                module_index,
                context.module,
                context.procedure,
                &name,
            );
            pure_intrinsic
                && args.iter().all(|argument| {
                    path_expression_has_only_stable_identifiers(
                        argument,
                        context,
                        resolving,
                        depth + 1,
                    )
                })
        }
        Expr::Group(value, _) | Expr::Unary { value, .. } => {
            path_expression_has_only_stable_identifiers(value, context, resolving, depth + 1)
        }
        Expr::Binary { left, right, .. } => {
            path_expression_has_only_stable_identifiers(left, context, resolving, depth + 1)
                && path_expression_has_only_stable_identifiers(right, context, resolving, depth + 1)
        }
        Expr::NamedArgument { value, .. } => {
            path_expression_has_only_stable_identifiers(value, context, resolving, depth + 1)
        }
        Expr::TypeOfIs { expression, .. } => {
            path_expression_has_only_stable_identifiers(expression, context, resolving, depth + 1)
        }
        Expr::Literal(..) => true,
        Expr::Member { .. } | Expr::Unknown(..) => false,
    }
}

fn path_identifier_is_stable(
    name: &str,
    context: ProcedurePathContext<'_>,
    resolving: &mut HashSet<String>,
    depth: usize,
) -> bool {
    let key = canon_flow(name);
    if matches!(
        key.as_str(),
        "true" | "false" | "null" | "empty" | "nothing"
    ) || known_intrinsic_constant_value(name, context).is_some()
    {
        return true;
    }
    if context
        .path_values
        .is_some_and(|values| values.contains_key(&key))
    {
        // A path-variable alias is not immutable unless its snapshot is folded first.
        return false;
    }
    if let Some(project) = context.project
        && let Some(module_index) = unique_project_module_index(project, context.module)
        && matches!(key.as_str(), "date" | "now" | "time")
        && !crate::typecheck::project_may_shadow_type_intrinsic(
            project,
            module_index,
            context.module,
            context.procedure,
            &key,
        )
    {
        return true;
    }

    if !resolving.insert(key.clone()) {
        return false;
    }
    let result = path_identifier_names_constant(&key, context)
        || evaluate_literal_branch_value_in_context(
            &Expr::Identifier(name.to_owned(), crate::model::Span::default()),
            depth + 1,
            Some(context),
            resolving,
            false,
        )
        .is_some();
    resolving.remove(&key);
    result
}

fn path_identifier_names_constant(name: &str, context: ProcedurePathContext<'_>) -> bool {
    let procedure = context.procedure;
    if procedure
        .parameters
        .iter()
        .any(|parameter| canon_flow(&parameter.name) == name)
        || canon_flow(&procedure.name) == name
    {
        return false;
    }
    let mut locals = Vec::new();
    collect_procedure_declarations(&procedure.statements, name, &mut locals);
    if !locals.is_empty() {
        return locals.len() == 1 && locals[0].kind == "constant";
    }
    let module_declarations = context
        .module
        .declarations
        .iter()
        .filter(|declaration| canon_flow(&declaration.name) == name)
        .collect::<Vec<_>>();
    if !module_declarations.is_empty() {
        return module_declarations.len() == 1 && module_declarations[0].kind == "constant";
    }
    let Some(project) = context.project else {
        return false;
    };
    let matches = project
        .modules
        .iter()
        .filter(|candidate| {
            matches!(candidate.module_kind.as_deref(), Some("standard") | None)
                && candidate.declarations.iter().any(|declaration| {
                    canon_flow(&declaration.name) == name
                        && declaration.kind == "constant"
                        && (declaration.visibility.eq_ignore_ascii_case("public")
                            || declaration.visibility.eq_ignore_ascii_case("global"))
                })
        })
        .count();
    matches == 1
}

fn expression_has_unsafe_call(expression: &Expr, context: ProcedurePathContext<'_>) -> bool {
    match expression {
        Expr::Call { callee, args, .. } => {
            let array_access = context.project.is_some_and(|project| {
                unique_project_module_index(project, context.module).is_some_and(|module_index| {
                    crate::typecheck::known_vartype_value(
                        project,
                        module_index,
                        context.module,
                        context.procedure,
                        callee,
                    )
                    .is_some_and(|type_code| type_code >= 8192)
                })
            });
            let pure_intrinsic = match callee.as_ref() {
                Expr::Identifier(name, _) => {
                    let name = canon_flow(name);
                    let known_pure = matches!(
                        name.as_str(),
                        "array"
                            | "cbool"
                            | "cbyte"
                            | "ccur"
                            | "cdate"
                            | "cdec"
                            | "cverr"
                            | "cdbl"
                            | "cint"
                            | "clng"
                            | "clnglng"
                            | "clngptr"
                            | "csng"
                            | "cstr"
                            | "cvar"
                            | "cvdate"
                            | "val"
                            | "chr"
                            | "chrw"
                            | "asc"
                            | "ascw"
                            | "space"
                            | "string"
                            | "hex"
                            | "oct"
                            | "choose"
                            | "iif"
                            | "switch"
                            | "date"
                            | "dateadd"
                            | "dateserial"
                            | "datevalue"
                            | "datediff"
                            | "datepart"
                            | "now"
                            | "time"
                            | "timeserial"
                            | "timevalue"
                            | "isarray"
                            | "isdate"
                            | "isempty"
                            | "iserror"
                            | "ismissing"
                            | "isnull"
                            | "isnumeric"
                            | "isobject"
                            | "typename"
                            | "vartype"
                            | "len"
                            | "lenb"
                            | "instr"
                            | "instrrev"
                            | "left"
                            | "right"
                            | "mid"
                            | "ltrim"
                            | "rtrim"
                            | "trim"
                            | "replace"
                    );
                    known_pure
                        && context.project.is_some_and(|project| {
                            unique_project_module_index(project, context.module).is_some_and(
                                |module_index| {
                                    !crate::typecheck::project_may_shadow_type_intrinsic(
                                        project,
                                        module_index,
                                        context.module,
                                        context.procedure,
                                        &name,
                                    )
                                },
                            )
                        })
                }
                _ => false,
            };
            !(array_access || pure_intrinsic)
                || args
                    .iter()
                    .any(|argument| expression_has_unsafe_call(argument, context))
        }
        Expr::Member { .. } => true,
        Expr::Unary { value, .. } | Expr::Group(value, _) => {
            expression_has_unsafe_call(value, context)
        }
        Expr::Binary { left, right, .. } => {
            expression_has_unsafe_call(left, context) || expression_has_unsafe_call(right, context)
        }
        Expr::NamedArgument { value, .. } => expression_has_unsafe_call(value, context),
        Expr::TypeOfIs { expression, .. } => expression_has_unsafe_call(expression, context),
        Expr::Identifier(..) | Expr::Literal(..) | Expr::Unknown(..) => false,
    }
}

fn combined_path_feasibility(
    caller_conditions: &[String],
    callee_conditions: &[String],
    caller_feasibility: &str,
    callee_feasibility: &str,
) -> String {
    if caller_feasibility == "infeasible_constant_condition"
        || callee_feasibility == "infeasible_constant_condition"
        || caller_conditions
            .iter()
            .chain(callee_conditions)
            .any(|condition| evaluate_literal_branch_condition(condition) == Some(false))
    {
        "infeasible_constant_condition".into()
    } else {
        "not_checked".into()
    }
}

#[derive(Clone, Debug, PartialEq)]
enum LiteralBranchValue {
    Boolean(bool),
    Integer(i64),
    /// Date serial represented in whole seconds from VBA's 1899-12-30 epoch.
    /// Keeping the tag separate from Integer preserves Date subtype semantics
    /// while allowing bounded comparisons and day/time arithmetic.
    Date(i64),
    String(String),
    Null,
    Empty,
}

const MAX_BRANCH_STRING_BYTES: usize = 16 * 1024;
const DATE_SECONDS_PER_DAY: i64 = 86_400;

fn date_serial_to_branch_value(serial: f64) -> Option<LiteralBranchValue> {
    if !serial.is_finite() {
        return None;
    }
    let seconds = (serial * DATE_SECONDS_PER_DAY as f64).round();
    if seconds < i64::MIN as f64 || seconds > i64::MAX as f64 {
        return None;
    }
    Some(LiteralBranchValue::Date(seconds as i64))
}

fn branch_date_to_serial(value: i64) -> f64 {
    value as f64 / DATE_SECONDS_PER_DAY as f64
}

fn branch_date_from_integer(value: i64) -> Option<LiteralBranchValue> {
    date_serial_to_branch_value(value as f64)
}

fn evaluate_literal_branch_condition(condition: &str) -> Option<bool> {
    evaluate_literal_branch_condition_in_context(condition, None)
}

fn evaluate_literal_branch_condition_in_context(
    condition: &str,
    context: Option<ProcedurePathContext<'_>>,
) -> Option<bool> {
    let expression_text = condition
        .split_once("[predicate:")
        .and_then(|(_, predicate)| predicate.strip_suffix(']'))
        .map(str::trim)
        .unwrap_or(condition);
    let expression = parse_expression_source(expression_text)?;
    let mut resolving = HashSet::new();
    if let Some(value) = evaluate_if_numeric_truth_wrapper(&expression, context, &mut resolving) {
        return Some(value);
    }
    match evaluate_literal_branch_value_in_context(&expression, 0, context, &mut resolving, false)?
    {
        LiteralBranchValue::Boolean(value) => Some(value),
        LiteralBranchValue::Integer(_)
        | LiteralBranchValue::Date(_)
        | LiteralBranchValue::String(_)
        | LiteralBranchValue::Null
        | LiteralBranchValue::Empty => None,
    }
}

/// `If` and loop predicates accept numeric expressions. CFG edges render their
/// branch condition as `(source-expression) = True/False`; preserve the outer
/// group check so a source comparison such as `If 1 = True Then` is not
/// confused with an `If 1 Then` truth conversion.
fn evaluate_if_numeric_truth_wrapper(
    expression: &Expr,
    context: Option<ProcedurePathContext<'_>>,
    resolving: &mut HashSet<String>,
) -> Option<bool> {
    let Expr::Binary {
        left, op, right, ..
    } = expression
    else {
        return None;
    };
    if !matches!(op.as_str(), "=" | "<>") {
        return None;
    }

    let (value_expression, expected_expression) = if matches!(left.as_ref(), Expr::Group(..)) {
        (left.as_ref(), right.as_ref())
    } else if matches!(right.as_ref(), Expr::Group(..)) {
        (right.as_ref(), left.as_ref())
    } else {
        return None;
    };
    let expected = match expected_expression {
        Expr::Identifier(name, _) if name.eq_ignore_ascii_case("True") => true,
        Expr::Identifier(name, _) if name.eq_ignore_ascii_case("False") => false,
        // Select Case predicates parenthesize their comparison operands. Only
        // CFG's direct If/loop wrapper leaves the generated Boolean bare.
        _ => return None,
    };
    let actual = match evaluate_literal_branch_value_in_context(
        value_expression,
        1,
        context,
        resolving,
        false,
    )? {
        LiteralBranchValue::Integer(value) => value != 0,
        LiteralBranchValue::Date(value) => value != 0,
        LiteralBranchValue::Boolean(_) => return None,
        LiteralBranchValue::String(value) if value.eq_ignore_ascii_case("true") => true,
        LiteralBranchValue::String(value) if value.eq_ignore_ascii_case("false") => false,
        LiteralBranchValue::String(_) => return None,
        LiteralBranchValue::Null => false,
        LiteralBranchValue::Empty => false,
    };
    let equal = actual == expected;
    Some(if op == "=" { equal } else { !equal })
}

fn evaluate_literal_branch_value_in_context(
    expression: &Expr,
    depth: usize,
    context: Option<ProcedurePathContext<'_>>,
    resolving: &mut HashSet<String>,
    module_scope_only: bool,
) -> Option<LiteralBranchValue> {
    if depth >= 64 {
        return None;
    }
    match expression {
        Expr::Identifier(name, _) if name.eq_ignore_ascii_case("True") => {
            Some(LiteralBranchValue::Boolean(true))
        }
        Expr::Identifier(name, _) if name.eq_ignore_ascii_case("False") => {
            Some(LiteralBranchValue::Boolean(false))
        }
        Expr::Identifier(name, _) if name.eq_ignore_ascii_case("Null") => {
            Some(LiteralBranchValue::Null)
        }
        Expr::Identifier(name, _) if name.eq_ignore_ascii_case("Empty") => {
            Some(LiteralBranchValue::Empty)
        }
        Expr::Identifier(name, _) => {
            let context = context?;
            if !module_scope_only
                && let Some(value) = context
                    .path_values
                    .and_then(|values| values.get(&canon_flow(name)))
            {
                evaluate_literal_branch_value_in_context(
                    value,
                    depth + 1,
                    Some(context),
                    resolving,
                    module_scope_only,
                )
            } else {
                known_intrinsic_constant_value(name, context)
                    .map(LiteralBranchValue::Integer)
                    .or_else(|| {
                        evaluate_constant_identifier(
                            name,
                            context,
                            depth + 1,
                            resolving,
                            module_scope_only,
                        )
                    })
            }
        }
        Expr::Literal(text, LiteralKind::Number, _) => {
            parse_small_integer_literal(text).map(LiteralBranchValue::Integer)
        }
        Expr::Literal(text, LiteralKind::String, _) => {
            parse_branch_string_literal(text).map(LiteralBranchValue::String)
        }
        Expr::Literal(text, LiteralKind::Date, _) => {
            crate::preprocessor::date_text_serial(text).and_then(date_serial_to_branch_value)
        }
        Expr::Group(value, _) => evaluate_literal_branch_value_in_context(
            value,
            depth + 1,
            context,
            resolving,
            module_scope_only,
        ),
        Expr::Unary { op, value, .. } => {
            let value = evaluate_literal_branch_value_in_context(
                value,
                depth + 1,
                context,
                resolving,
                module_scope_only,
            )?;
            match (op.to_ascii_lowercase().as_str(), value) {
                ("not", LiteralBranchValue::Boolean(value)) => {
                    Some(LiteralBranchValue::Boolean(!value))
                }
                ("not", LiteralBranchValue::Integer(value)) => small_integer_value(!value),
                ("not", LiteralBranchValue::Date(_)) => None,
                ("not", LiteralBranchValue::Null) => Some(LiteralBranchValue::Null),
                ("not", LiteralBranchValue::Empty) => small_integer_value(!0),
                ("+", LiteralBranchValue::Integer(value)) => {
                    Some(LiteralBranchValue::Integer(value))
                }
                ("-", LiteralBranchValue::Integer(value)) => {
                    value.checked_neg().and_then(small_integer_value)
                }
                ("+", value @ LiteralBranchValue::Date(_)) => Some(value),
                ("-", LiteralBranchValue::Date(value)) => {
                    Some(LiteralBranchValue::Date(value.checked_neg()?))
                }
                _ => None,
            }
        }
        Expr::Binary {
            left, op, right, ..
        } => {
            let left = evaluate_literal_branch_value_in_context(
                left,
                depth + 1,
                context,
                resolving,
                module_scope_only,
            )?;
            let right = evaluate_literal_branch_value_in_context(
                right,
                depth + 1,
                context,
                resolving,
                module_scope_only,
            )?;
            evaluate_literal_branch_operator(op, left, right, context)
        }
        Expr::Call { callee, args, .. } => {
            let context = context?;
            evaluate_variant_test_intrinsic(
                callee,
                args,
                depth + 1,
                context,
                resolving,
                module_scope_only,
            )
            .or_else(|| {
                evaluate_string_conversion_intrinsic(
                    callee,
                    args,
                    depth + 1,
                    context,
                    resolving,
                    module_scope_only,
                )
            })
            .or_else(|| {
                evaluate_array_bound_intrinsic(
                    callee,
                    args,
                    depth + 1,
                    context,
                    resolving,
                    module_scope_only,
                )
            })
            .or_else(|| {
                evaluate_character_intrinsic(
                    callee,
                    args,
                    depth + 1,
                    context,
                    resolving,
                    module_scope_only,
                )
            })
            .or_else(|| {
                evaluate_radix_string_intrinsic(
                    callee,
                    args,
                    depth + 1,
                    context,
                    resolving,
                    module_scope_only,
                )
            })
            .or_else(|| {
                evaluate_date_intrinsic(
                    callee,
                    args,
                    depth + 1,
                    context,
                    resolving,
                    module_scope_only,
                )
            })
            .or_else(|| {
                evaluate_selection_intrinsic(
                    callee,
                    args,
                    depth + 1,
                    context,
                    resolving,
                    module_scope_only,
                )
            })
            .or_else(|| {
                evaluate_integer_intrinsic(
                    callee,
                    args,
                    depth + 1,
                    context,
                    resolving,
                    module_scope_only,
                )
            })
            .or_else(|| {
                evaluate_string_length_intrinsic(
                    callee,
                    args,
                    depth + 1,
                    context,
                    resolving,
                    module_scope_only,
                )
            })
            .or_else(|| {
                evaluate_instr_intrinsic(
                    callee,
                    args,
                    depth + 1,
                    context,
                    resolving,
                    module_scope_only,
                )
            })
            .or_else(|| {
                evaluate_instrrev_intrinsic(
                    callee,
                    args,
                    depth + 1,
                    context,
                    resolving,
                    module_scope_only,
                )
            })
            .or_else(|| {
                evaluate_string_slice_intrinsic(
                    callee,
                    args,
                    depth + 1,
                    context,
                    resolving,
                    module_scope_only,
                )
            })
            .or_else(|| {
                evaluate_string_trim_intrinsic(
                    callee,
                    args,
                    depth + 1,
                    context,
                    resolving,
                    module_scope_only,
                )
            })
            .or_else(|| {
                evaluate_replace_intrinsic(
                    callee,
                    args,
                    depth + 1,
                    context,
                    resolving,
                    module_scope_only,
                )
            })
        }
        _ => None,
    }
}

fn evaluate_selection_intrinsic(
    callee: &Expr,
    arguments: &[Expr],
    depth: usize,
    context: ProcedurePathContext<'_>,
    resolving: &mut HashSet<String>,
    module_scope_only: bool,
) -> Option<LiteralBranchValue> {
    let Expr::Identifier(name, _) = callee else {
        return None;
    };
    let intrinsic = canon_flow(name);
    if !matches!(intrinsic.as_str(), "iif" | "choose" | "switch") {
        return None;
    }
    let project = context.project?;
    let module_index = unique_project_module_index(project, context.module)?;
    if crate::typecheck::project_may_shadow_intrinsic(
        project,
        module_index,
        context.module,
        context.procedure,
        &intrinsic,
    ) {
        return None;
    }
    let mut evaluate = |argument: &Expr| {
        evaluate_literal_branch_value_in_context(
            path_value_expression(argument, context, module_scope_only),
            depth + 1,
            Some(context),
            resolving,
            module_scope_only,
        )
    };
    match intrinsic.as_str() {
        "iif" if arguments.len() == 3 => {
            // IIf evaluates both result expressions. Require both values to be
            // statically safe before selecting one; this avoids hiding a
            // possible error in the unselected branch.
            let condition = evaluate(&arguments[0]);
            let true_value = evaluate(&arguments[1]);
            let false_value = evaluate(&arguments[2]);
            let condition = match condition? {
                LiteralBranchValue::Boolean(value) => value,
                LiteralBranchValue::Integer(value) => value != 0,
                LiteralBranchValue::Empty => false,
                LiteralBranchValue::Null
                | LiteralBranchValue::Date(_)
                | LiteralBranchValue::String(_) => {
                    return None;
                }
            };
            if condition { true_value } else { false_value }
        }
        "choose" if arguments.len() >= 2 => {
            let LiteralBranchValue::Integer(index) = evaluate(&arguments[0])? else {
                return None;
            };
            if index < 1 || usize::try_from(index).ok()? >= arguments.len() {
                return Some(LiteralBranchValue::Null);
            }
            evaluate(&arguments[usize::try_from(index).ok()?])
        }
        "switch" if arguments.len() >= 2 && arguments.len().is_multiple_of(2) => {
            let mut selected = None;
            for pair in arguments.chunks_exact(2) {
                let condition = evaluate(&pair[0]);
                let value = evaluate(&pair[1]);
                let condition = match condition? {
                    LiteralBranchValue::Boolean(value) => value,
                    LiteralBranchValue::Integer(value) => value != 0,
                    LiteralBranchValue::Empty => false,
                    LiteralBranchValue::Null
                    | LiteralBranchValue::Date(_)
                    | LiteralBranchValue::String(_) => return None,
                };
                if condition && selected.is_none() {
                    selected = value;
                }
            }
            selected.or(Some(LiteralBranchValue::Null))
        }
        _ => None,
    }
}

fn evaluate_date_intrinsic(
    callee: &Expr,
    arguments: &[Expr],
    depth: usize,
    context: ProcedurePathContext<'_>,
    resolving: &mut HashSet<String>,
    module_scope_only: bool,
) -> Option<LiteralBranchValue> {
    let Expr::Identifier(name, _) = callee else {
        return None;
    };
    let intrinsic = canon_flow(name);
    if !matches!(
        intrinsic.as_str(),
        "cdate"
            | "cvdate"
            | "dateserial"
            | "timeserial"
            | "datevalue"
            | "timevalue"
            | "dateadd"
            | "datediff"
            | "datepart"
    ) {
        return None;
    }
    let valid_arity = match intrinsic.as_str() {
        "dateserial" | "timeserial" | "dateadd" | "datediff" => arguments.len() == 3,
        "datepart" => matches!(arguments.len(), 2 | 3),
        _ => arguments.len() == 1,
    };
    if !valid_arity
        || arguments
            .iter()
            .any(|argument| matches!(argument, Expr::NamedArgument { .. }))
    {
        return None;
    }
    let project = context.project?;
    let module_index = unique_project_module_index(project, context.module)?;
    if crate::typecheck::project_may_shadow_intrinsic(
        project,
        module_index,
        context.module,
        context.procedure,
        &intrinsic,
    ) {
        return None;
    }
    let mut evaluate = |argument: &Expr| {
        evaluate_literal_branch_value_in_context(
            path_value_expression(argument, context, module_scope_only),
            depth + 1,
            Some(context),
            resolving,
            module_scope_only,
        )
    };
    match intrinsic.as_str() {
        "cdate" | "cvdate" => match evaluate(&arguments[0])? {
            value @ LiteralBranchValue::Date(_) => Some(value),
            LiteralBranchValue::Integer(value) => branch_date_from_integer(value),
            LiteralBranchValue::Null => Some(LiteralBranchValue::Null),
            _ => None,
        },
        "dateserial" => {
            let LiteralBranchValue::Integer(year) = evaluate(&arguments[0])? else {
                return None;
            };
            let LiteralBranchValue::Integer(month) = evaluate(&arguments[1])? else {
                return None;
            };
            let LiteralBranchValue::Integer(day) = evaluate(&arguments[2])? else {
                return None;
            };
            crate::preprocessor::date_serial_from_components(
                i32::try_from(year).ok()?,
                i32::try_from(month).ok()?,
                i32::try_from(day).ok()?,
            )
            .and_then(date_serial_to_branch_value)
        }
        "timeserial" => {
            let LiteralBranchValue::Integer(hour) = evaluate(&arguments[0])? else {
                return None;
            };
            let LiteralBranchValue::Integer(minute) = evaluate(&arguments[1])? else {
                return None;
            };
            let LiteralBranchValue::Integer(second) = evaluate(&arguments[2])? else {
                return None;
            };
            let seconds = hour
                .checked_mul(3_600)?
                .checked_add(minute.checked_mul(60)?)?
                .checked_add(second)?;
            Some(LiteralBranchValue::Date(seconds))
        }
        "datevalue" | "timevalue" => {
            let LiteralBranchValue::String(value) = evaluate(&arguments[0])? else {
                return None;
            };
            if !value.is_ascii() {
                return None;
            }
            crate::preprocessor::date_text_serial(&value).and_then(date_serial_to_branch_value)
        }
        "dateadd" => {
            let LiteralBranchValue::String(interval) = evaluate(&arguments[0])? else {
                return None;
            };
            let LiteralBranchValue::Integer(number) = evaluate(&arguments[1])? else {
                return None;
            };
            let date = match evaluate(&arguments[2])? {
                LiteralBranchValue::Date(value) => value,
                LiteralBranchValue::Integer(value) => match branch_date_from_integer(value)? {
                    LiteralBranchValue::Date(value) => value,
                    _ => return None,
                },
                _ => return None,
            };
            let interval = interval.to_ascii_lowercase();
            let unit_seconds = match interval.as_str() {
                "s" | "ss" | "second" | "seconds" => 1,
                "n" | "minute" | "minutes" => 60,
                "h" | "hour" | "hours" => 3_600,
                "d" | "day" | "days" | "y" | "dayofyear" => DATE_SECONDS_PER_DAY,
                "ww" | "week" | "weeks" => 7 * DATE_SECONDS_PER_DAY,
                "m" | "month" | "months" | "q" | "quarter" | "quarters" | "yyyy" | "year"
                | "years" => 0,
                _ => return None,
            };
            if unit_seconds == 0 {
                let months_per_unit = match interval.as_str() {
                    "m" | "month" | "months" => 1,
                    "q" | "quarter" | "quarters" => 3,
                    "yyyy" | "year" | "years" => 12,
                    _ => return None,
                };
                return crate::preprocessor::date_serial_add_months(
                    branch_date_to_serial(date),
                    number.checked_mul(months_per_unit)?,
                )
                .and_then(date_serial_to_branch_value);
            }
            let delta = number.checked_mul(unit_seconds)?;
            Some(LiteralBranchValue::Date(date.checked_add(delta)?))
        }
        "datediff" => {
            let LiteralBranchValue::String(interval) = evaluate(&arguments[0])? else {
                return None;
            };
            let start = branch_date_argument(evaluate(&arguments[1])?)?;
            let end = branch_date_argument(evaluate(&arguments[2])?)?;
            evaluate_date_difference(&interval, start, end)
        }
        "datepart" => {
            let LiteralBranchValue::String(interval) = evaluate(&arguments[0])? else {
                return None;
            };
            if arguments.len() == 3 {
                let LiteralBranchValue::Integer(first_day) = evaluate(&arguments[2])? else {
                    return None;
                };
                if !(0..=7).contains(&first_day) {
                    return None;
                }
            }
            let date = branch_date_argument(evaluate(&arguments[1])?)?;
            let components =
                crate::preprocessor::date_components_from_serial(branch_date_to_serial(date))?;
            let value = match interval.to_ascii_lowercase().as_str() {
                "d" | "day" | "dayofmonth" => components.2,
                "m" | "month" => components.1,
                "yyyy" | "year" => components.0,
                "h" | "hour" => components.3,
                "n" | "minute" => components.4,
                "s" | "second" => components.5,
                "q" | "quarter" => (components.1 - 1) / 3 + 1,
                "y" | "dayofyear" => {
                    let start =
                        crate::preprocessor::date_serial_from_components(components.0, 1, 1)?;
                    (branch_date_to_serial(date) - start).floor() as i32 + 1
                }
                _ => return None,
            };
            Some(LiteralBranchValue::Integer(i64::from(value)))
        }
        _ => None,
    }
}

fn branch_date_argument(value: LiteralBranchValue) -> Option<i64> {
    match value {
        LiteralBranchValue::Date(value) => Some(value),
        LiteralBranchValue::Integer(value) => match branch_date_from_integer(value)? {
            LiteralBranchValue::Date(value) => Some(value),
            _ => None,
        },
        _ => None,
    }
}

fn evaluate_date_difference(interval: &str, start: i64, end: i64) -> Option<LiteralBranchValue> {
    let interval = interval.to_ascii_lowercase();
    let result = match interval.as_str() {
        "s" | "ss" | "second" | "seconds" => end.checked_sub(start)?,
        "n" | "minute" | "minutes" => end.checked_sub(start)?.div_euclid(60),
        "h" | "hour" | "hours" => end.checked_sub(start)?.div_euclid(3_600),
        "d" | "day" | "days" => {
            end.div_euclid(DATE_SECONDS_PER_DAY) - start.div_euclid(DATE_SECONDS_PER_DAY)
        }
        "ww" | "week" | "weeks" => {
            let start_day = start.div_euclid(DATE_SECONDS_PER_DAY);
            let end_day = end.div_euclid(DATE_SECONDS_PER_DAY);
            (end_day + 1).div_euclid(7) - (start_day + 1).div_euclid(7)
        }
        "m" | "month" | "months" | "q" | "quarter" | "quarters" | "yyyy" | "year" | "years" => {
            let start_components =
                crate::preprocessor::date_components_from_serial(branch_date_to_serial(start))?;
            let end_components =
                crate::preprocessor::date_components_from_serial(branch_date_to_serial(end))?;
            let months = i64::from(end_components.0 - start_components.0) * 12
                + i64::from(end_components.1 - start_components.1);
            match interval.as_str() {
                "q" | "quarter" | "quarters" => months.div_euclid(3),
                "yyyy" | "year" | "years" => months.div_euclid(12),
                _ => months,
            }
        }
        _ => return None,
    };
    Some(LiteralBranchValue::Integer(result))
}

fn evaluate_variant_test_intrinsic(
    callee: &Expr,
    arguments: &[Expr],
    depth: usize,
    context: ProcedurePathContext<'_>,
    resolving: &mut HashSet<String>,
    module_scope_only: bool,
) -> Option<LiteralBranchValue> {
    let Expr::Identifier(name, _) = callee else {
        return None;
    };
    let intrinsic = canon_flow(name);
    if !matches!(
        intrinsic.as_str(),
        "isnull"
            | "iserror"
            | "isempty"
            | "ismissing"
            | "isarray"
            | "isnumeric"
            | "isobject"
            | "isdate"
            | "vartype"
            | "typename"
    ) || arguments.len() != 1
        || matches!(arguments.first(), Some(Expr::NamedArgument { .. }))
    {
        return None;
    }
    let project = context.project?;
    let module_index = unique_project_module_index(project, context.module)?;
    if project
        .modules
        .iter()
        .any(|candidate| canonical_data_name(&candidate.name) == intrinsic)
        || project
            .name
            .as_deref()
            .is_some_and(|project_name| canonical_data_name(project_name) == intrinsic)
        || crate::typecheck::project_may_shadow_intrinsic(
            project,
            module_index,
            context.module,
            context.procedure,
            &intrinsic,
        )
    {
        return None;
    }
    let original_argument = &arguments[0];
    let argument = path_value_expression(original_argument, context, module_scope_only);
    let value = evaluate_literal_branch_value_in_context(
        argument,
        depth + 1,
        Some(context),
        resolving,
        module_scope_only,
    );
    if intrinsic == "vartype" {
        if let Some(value) = crate::typecheck::known_vartype_value(
            project,
            module_index,
            context.module,
            context.procedure,
            argument,
        ) {
            return Some(LiteralBranchValue::Integer(value));
        }
        return match value? {
            LiteralBranchValue::Boolean(_) => Some(LiteralBranchValue::Integer(11)),
            LiteralBranchValue::Date(_) => Some(LiteralBranchValue::Integer(7)),
            LiteralBranchValue::String(_) => Some(LiteralBranchValue::Integer(8)),
            LiteralBranchValue::Null => Some(LiteralBranchValue::Integer(1)),
            LiteralBranchValue::Empty => Some(LiteralBranchValue::Integer(0)),
            LiteralBranchValue::Integer(_) => None,
        };
    }
    if intrinsic == "typename" {
        if let Some(value) = crate::typecheck::known_typename_value(
            project,
            module_index,
            context.module,
            context.procedure,
            argument,
        ) {
            return Some(LiteralBranchValue::String(value));
        }
        return match value? {
            LiteralBranchValue::Boolean(_) => Some(LiteralBranchValue::String("Boolean".into())),
            LiteralBranchValue::Date(_) => Some(LiteralBranchValue::String("Date".into())),
            LiteralBranchValue::String(_) => Some(LiteralBranchValue::String("String".into())),
            LiteralBranchValue::Null => Some(LiteralBranchValue::String("Null".into())),
            LiteralBranchValue::Empty => Some(LiteralBranchValue::String("Empty".into())),
            LiteralBranchValue::Integer(_) => None,
        };
    }
    let result = match intrinsic.as_str() {
        "isarray" => {
            let path_shape_known = if let Expr::Identifier(name, _) = argument {
                context
                    .array_shapes
                    .is_some_and(|shapes| shapes.contains_key(&canon_flow(name)))
            } else {
                false
            };
            if path_shape_known {
                true
            } else {
                crate::typecheck::known_is_array_value(
                    project,
                    module_index,
                    context.module,
                    context.procedure,
                    argument,
                )?
            }
        }
        "isobject" => crate::typecheck::known_is_object_value(
            project,
            module_index,
            context.module,
            context.procedure,
            argument,
        )?,
        "isdate" => crate::typecheck::known_is_date_value(
            project,
            module_index,
            context.module,
            context.procedure,
            argument,
        )?,
        "isnumeric" => {
            if let Some(is_numeric) = statically_known_numeric_input(
                project,
                module_index,
                context.module,
                context.procedure,
                argument,
            ) {
                is_numeric
            } else {
                match value? {
                    LiteralBranchValue::Boolean(_) | LiteralBranchValue::Integer(_) => true,
                    LiteralBranchValue::Date(_) => false,
                    LiteralBranchValue::Null | LiteralBranchValue::Empty => false,
                    LiteralBranchValue::String(value) => ascii_numeric_string(&value)?,
                }
            }
        }
        "isnull" => {
            let value = value?;
            matches!(value, LiteralBranchValue::Null)
        }
        "iserror" => {
            if let Some(result) = crate::typecheck::known_is_error_value(
                project,
                module_index,
                context.module,
                context.procedure,
                argument,
            ) {
                result
            } else {
                match value? {
                    LiteralBranchValue::Boolean(_)
                    | LiteralBranchValue::Integer(_)
                    | LiteralBranchValue::Date(_)
                    | LiteralBranchValue::String(_)
                    | LiteralBranchValue::Null
                    | LiteralBranchValue::Empty => false,
                }
            }
        }
        "isempty" => {
            let value = value?;
            matches!(value, LiteralBranchValue::Empty)
        }
        "ismissing" => {
            if let Expr::Identifier(argument_name, _) = &arguments[0]
                && let Some(parameter) = context
                    .procedure
                    .parameters
                    .iter()
                    .find(|parameter| canon_flow(&parameter.name) == canon_flow(argument_name))
            {
                if parameter.is_param_array {
                    false
                } else {
                    let parameter_type = crate::typecheck::declared_parameter_type(
                        project,
                        module_index,
                        context.module,
                        parameter,
                    )?;
                    if parameter_type.eq_ignore_ascii_case("Variant")
                        && parameter.optional
                        && parameter.default_value.is_none()
                    {
                        if let Some(missing) = context.optional_missing {
                            missing.contains(&canonical_data_name(&parameter.name))
                        } else {
                            known_is_missing_for_private_call_sites(context, &parameter.name)?
                        }
                    } else {
                        false
                    }
                }
            } else if value.is_some() {
                false
            } else {
                return None;
            }
        }
        _ => return None,
    };
    Some(LiteralBranchValue::Boolean(result))
}

fn evaluate_radix_string_intrinsic(
    callee: &Expr,
    arguments: &[Expr],
    depth: usize,
    context: ProcedurePathContext<'_>,
    resolving: &mut HashSet<String>,
    module_scope_only: bool,
) -> Option<LiteralBranchValue> {
    let Expr::Identifier(name, _) = callee else {
        return None;
    };
    let intrinsic = canon_flow(name);
    if !matches!(intrinsic.as_str(), "hex" | "oct")
        || arguments.len() != 1
        || matches!(arguments.first(), Some(Expr::NamedArgument { .. }))
    {
        return None;
    }
    let project = context.project?;
    let module_index = unique_project_module_index(project, context.module)?;
    if crate::typecheck::project_may_shadow_intrinsic(
        project,
        module_index,
        context.module,
        context.procedure,
        &intrinsic,
    ) {
        return None;
    }
    let value = evaluate_literal_branch_value_in_context(
        path_value_expression(&arguments[0], context, module_scope_only),
        depth + 1,
        Some(context),
        resolving,
        module_scope_only,
    )?;
    let LiteralBranchValue::Integer(value) = value else {
        return None;
    };
    if value < 0 {
        return None;
    }
    let rendered = if intrinsic == "hex" {
        format!("{value:X}")
    } else {
        format!("{value:o}")
    };
    Some(LiteralBranchValue::String(rendered))
}

fn evaluate_character_intrinsic(
    callee: &Expr,
    arguments: &[Expr],
    depth: usize,
    context: ProcedurePathContext<'_>,
    resolving: &mut HashSet<String>,
    module_scope_only: bool,
) -> Option<LiteralBranchValue> {
    let Expr::Identifier(name, _) = callee else {
        return None;
    };
    let intrinsic = canon_flow(name);
    if !matches!(
        intrinsic.as_str(),
        "chr" | "chrw" | "asc" | "ascw" | "space" | "string"
    ) {
        return None;
    }
    let valid_arity = match intrinsic.as_str() {
        "string" => arguments.len() == 2,
        _ => arguments.len() == 1,
    };
    if !valid_arity
        || arguments
            .iter()
            .any(|argument| matches!(argument, Expr::NamedArgument { .. }))
    {
        return None;
    }
    let project = context.project?;
    let module_index = unique_project_module_index(project, context.module)?;
    if crate::typecheck::project_may_shadow_intrinsic(
        project,
        module_index,
        context.module,
        context.procedure,
        &intrinsic,
    ) {
        return None;
    }
    let mut evaluate = |argument: &Expr| {
        evaluate_literal_branch_value_in_context(
            path_value_expression(argument, context, module_scope_only),
            depth + 1,
            Some(context),
            resolving,
            module_scope_only,
        )
    };
    match intrinsic.as_str() {
        "chr" | "chrw" => {
            let LiteralBranchValue::Integer(value) = evaluate(&arguments[0])? else {
                return None;
            };
            if !(0..=127).contains(&value) {
                return None;
            }
            Some(LiteralBranchValue::String(
                char::from_u32(value as u32)?.to_string(),
            ))
        }
        "asc" | "ascw" => {
            let LiteralBranchValue::String(value) = evaluate(&arguments[0])? else {
                return None;
            };
            let byte = value.as_bytes().first().copied()?;
            value
                .is_ascii()
                .then_some(LiteralBranchValue::Integer(i64::from(byte)))
        }
        "space" => {
            let LiteralBranchValue::Integer(value) = evaluate(&arguments[0])? else {
                return None;
            };
            let length = usize::try_from(value).ok()?;
            (length <= MAX_BRANCH_STRING_BYTES)
                .then(|| LiteralBranchValue::String(" ".repeat(length)))
        }
        "string" => {
            let LiteralBranchValue::Integer(count) = evaluate(&arguments[0])? else {
                return None;
            };
            let count = usize::try_from(count).ok()?;
            if count > MAX_BRANCH_STRING_BYTES {
                return None;
            }
            let character = match evaluate(&arguments[1])? {
                LiteralBranchValue::String(value) if value.is_ascii() => value.chars().next()?,
                LiteralBranchValue::Integer(value) if (0..=127).contains(&value) => {
                    char::from_u32(value as u32)?
                }
                _ => return None,
            };
            Some(LiteralBranchValue::String(
                character.to_string().repeat(count),
            ))
        }
        _ => None,
    }
}

fn evaluate_array_bound_intrinsic(
    callee: &Expr,
    arguments: &[Expr],
    depth: usize,
    context: ProcedurePathContext<'_>,
    resolving: &mut HashSet<String>,
    module_scope_only: bool,
) -> Option<LiteralBranchValue> {
    let Expr::Identifier(name, _) = callee else {
        return None;
    };
    let intrinsic = canon_flow(name);
    if !matches!(intrinsic.as_str(), "lbound" | "ubound")
        || !matches!(arguments.len(), 1 | 2)
        || arguments
            .iter()
            .any(|argument| matches!(argument, Expr::NamedArgument { .. }))
    {
        return None;
    }
    let project = context.project?;
    let module_index = unique_project_module_index(project, context.module)?;
    if crate::typecheck::project_may_shadow_intrinsic(
        project,
        module_index,
        context.module,
        context.procedure,
        &intrinsic,
    ) {
        return None;
    }
    if let Expr::Call { callee, args, .. } = &arguments[0]
        && let Expr::Identifier(array_intrinsic, _) = callee.as_ref()
        && array_intrinsic.eq_ignore_ascii_case("Array")
        && !args.is_empty()
        && args
            .iter()
            .all(|argument| !expression_has_unsafe_call(argument, context))
    {
        if arguments.len() == 2 {
            let LiteralBranchValue::Integer(dimension) = evaluate_literal_branch_value_in_context(
                &arguments[1],
                depth + 1,
                Some(context),
                resolving,
                module_scope_only,
            )?
            else {
                return None;
            };
            if dimension != 1 {
                return None;
            }
        }
        return if intrinsic == "lbound" {
            Some(LiteralBranchValue::Integer(0))
        } else {
            i64::try_from(args.len().checked_sub(1)?)
                .ok()
                .map(LiteralBranchValue::Integer)
        };
    }
    let Expr::Identifier(array_name, _) =
        path_value_expression(&arguments[0], context, module_scope_only)
    else {
        return None;
    };
    if intrinsic == "lbound"
        && context.procedure.parameters.iter().any(|parameter| {
            parameter.is_param_array && canon_flow(&parameter.name) == canon_flow(array_name)
        })
    {
        if arguments.len() == 1 {
            return Some(LiteralBranchValue::Integer(0));
        }
        let LiteralBranchValue::Integer(dimension) = evaluate_literal_branch_value_in_context(
            &arguments[1],
            depth + 1,
            Some(context),
            resolving,
            module_scope_only,
        )?
        else {
            return None;
        };
        return (dimension == 1).then_some(LiteralBranchValue::Integer(0));
    }
    if intrinsic == "ubound"
        && context.procedure.parameters.iter().any(|parameter| {
            parameter.is_param_array && canon_flow(&parameter.name) == canon_flow(array_name)
        })
    {
        if arguments.len() == 2 {
            let LiteralBranchValue::Integer(dimension) = evaluate_literal_branch_value_in_context(
                &arguments[1],
                depth + 1,
                Some(context),
                resolving,
                module_scope_only,
            )?
            else {
                return None;
            };
            if dimension != 1 {
                return None;
            }
        }
        let key = (
            canonical_data_name(&context.module.name),
            canonical_data_name(&context.procedure.name),
            canon_flow(array_name),
        );
        let length = context.param_array_lengths?.get(&key).copied()?;
        return i64::try_from(length.checked_sub(1)?)
            .ok()
            .map(LiteralBranchValue::Integer);
    }
    if let Some(shapes) = context.array_shapes
        && let Some(shape) = shapes.get(&canon_flow(array_name))
    {
        let dimension = if arguments.len() == 2 {
            let value = evaluate_literal_branch_value_in_context(
                &arguments[1],
                depth + 1,
                Some(context),
                resolving,
                module_scope_only,
            )?;
            let LiteralBranchValue::Integer(value) = value else {
                return None;
            };
            usize::try_from(value.checked_sub(1)?).ok()?
        } else {
            0
        };
        let array_dimension = shape.get(dimension)?;
        let bound_text = if intrinsic == "lbound" {
            array_dimension.lower_bound.clone().or_else(|| {
                context
                    .module
                    .options
                    .array_base_valid
                    .then(|| context.module.options.array_base.to_string())
            })?
        } else {
            array_dimension.upper_bound.clone()?
        };
        let expression = parse_expression_source(&bound_text)?;
        return evaluate_literal_branch_value_in_context(
            &expression,
            depth + 1,
            Some(context),
            resolving,
            module_scope_only,
        );
    }
    let mut candidates = Vec::new();
    let mut locals = Vec::new();
    collect_procedure_declarations(
        &context.procedure.statements,
        &canon_flow(array_name),
        &mut locals,
    );
    candidates.extend(locals);
    candidates.extend(
        context
            .module
            .declarations
            .iter()
            .filter(|declaration| canon_flow(&declaration.name) == canon_flow(array_name)),
    );
    if candidates.len() != 1 || !candidates[0].is_array || candidates[0].array_dimensions.is_empty()
    {
        return None;
    }
    let dimension = if arguments.len() == 2 {
        let value = evaluate_literal_branch_value_in_context(
            &arguments[1],
            depth + 1,
            Some(context),
            resolving,
            module_scope_only,
        )?;
        let LiteralBranchValue::Integer(value) = value else {
            return None;
        };
        usize::try_from(value.checked_sub(1)?).ok()?
    } else {
        0
    };
    let array_dimension = candidates[0].array_dimensions.get(dimension)?;
    let bound_text = if intrinsic == "lbound" {
        array_dimension.lower_bound.clone().or_else(|| {
            context
                .module
                .options
                .array_base_valid
                .then(|| context.module.options.array_base.to_string())
        })?
    } else {
        array_dimension.upper_bound.clone()?
    };
    let expression = parse_expression_source(&bound_text)?;
    evaluate_literal_branch_value_in_context(
        &expression,
        depth + 1,
        Some(context),
        resolving,
        module_scope_only,
    )
}

fn evaluate_string_conversion_intrinsic(
    callee: &Expr,
    arguments: &[Expr],
    depth: usize,
    context: ProcedurePathContext<'_>,
    resolving: &mut HashSet<String>,
    module_scope_only: bool,
) -> Option<LiteralBranchValue> {
    let Expr::Identifier(name, _) = callee else {
        return None;
    };
    let intrinsic = canon_flow(name);
    if !matches!(intrinsic.as_str(), "cstr" | "val")
        || arguments.len() != 1
        || matches!(arguments.first(), Some(Expr::NamedArgument { .. }))
    {
        return None;
    }
    let project = context.project?;
    let module_index = unique_project_module_index(project, context.module)?;
    if crate::typecheck::project_may_shadow_intrinsic(
        project,
        module_index,
        context.module,
        context.procedure,
        &intrinsic,
    ) {
        return None;
    }
    let value = evaluate_literal_branch_value_in_context(
        path_value_expression(&arguments[0], context, module_scope_only),
        depth + 1,
        Some(context),
        resolving,
        module_scope_only,
    )?;
    if intrinsic == "cstr" {
        return match value {
            LiteralBranchValue::String(value) => Some(LiteralBranchValue::String(value)),
            LiteralBranchValue::Boolean(value) => Some(LiteralBranchValue::String(
                if value { "True" } else { "False" }.into(),
            )),
            LiteralBranchValue::Integer(value) => {
                Some(LiteralBranchValue::String(value.to_string()))
            }
            LiteralBranchValue::Empty => Some(LiteralBranchValue::String(String::new())),
            LiteralBranchValue::Date(_) | LiteralBranchValue::Null => None,
        };
    }
    let LiteralBranchValue::String(value) = value else {
        return None;
    };
    parse_ascii_val_integer(&value).map(LiteralBranchValue::Integer)
}

fn parse_ascii_integer_text(value: &str) -> Option<i64> {
    let value = value.trim();
    if value.is_empty() || value.contains('.') || value.contains('e') || value.contains('E') {
        return None;
    }
    let (sign, digits) = match value.as_bytes().first() {
        Some(b'-') => (-1i64, &value[1..]),
        Some(b'+') => (1i64, &value[1..]),
        _ => (1i64, value),
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse::<i64>().ok()?.checked_mul(sign)
}

fn parse_ascii_val_integer(value: &str) -> Option<i64> {
    let value = value.trim_start();
    let mut end = 0usize;
    for (index, byte) in value.bytes().enumerate() {
        if index == 0 && matches!(byte, b'+' | b'-') {
            end = 1;
            continue;
        }
        if byte.is_ascii_digit() {
            end = index + 1;
            continue;
        }
        break;
    }
    if end == 0 {
        None
    } else {
        parse_ascii_integer_text(&value[..end])
    }
}

fn evaluate_integer_intrinsic(
    callee: &Expr,
    arguments: &[Expr],
    depth: usize,
    context: ProcedurePathContext<'_>,
    resolving: &mut HashSet<String>,
    module_scope_only: bool,
) -> Option<LiteralBranchValue> {
    let Expr::Identifier(name, _) = callee else {
        return None;
    };
    let intrinsic = canon_flow(name);
    if !matches!(
        intrinsic.as_str(),
        "abs" | "fix" | "int" | "sgn" | "cbyte" | "cint" | "clng" | "sqr" | "round"
    ) || (intrinsic != "round" && arguments.len() != 1)
        || (intrinsic == "round" && !matches!(arguments.len(), 1 | 2))
        || matches!(arguments.first(), Some(Expr::NamedArgument { .. }))
    {
        return None;
    }
    let project = context.project?;
    let module_index = unique_project_module_index(project, context.module)?;
    if crate::typecheck::project_may_shadow_intrinsic(
        project,
        module_index,
        context.module,
        context.procedure,
        &intrinsic,
    ) {
        return None;
    }
    let argument = path_value_expression(&arguments[0], context, module_scope_only);
    let value = evaluate_literal_branch_value_in_context(
        argument,
        depth + 1,
        Some(context),
        resolving,
        module_scope_only,
    )?;
    let value = match value {
        LiteralBranchValue::Integer(value) => value,
        LiteralBranchValue::String(value)
            if matches!(intrinsic.as_str(), "cbyte" | "cint" | "clng") =>
        {
            parse_ascii_integer_text(&value)?
        }
        _ => return None,
    };
    if intrinsic == "round" && arguments.len() == 2 {
        let digits = evaluate_literal_branch_value_in_context(
            &arguments[1],
            depth + 1,
            Some(context),
            resolving,
            module_scope_only,
        )?;
        if digits != LiteralBranchValue::Integer(0) {
            return None;
        }
    }
    let result = match intrinsic.as_str() {
        "abs" => value.checked_abs()?,
        "fix" | "int" => value,
        "sgn" => value.signum(),
        "cbyte" if (0..=255).contains(&value) => value,
        "cint" if (i16::MIN as i64..=i16::MAX as i64).contains(&value) => value,
        "clng" if (i32::MIN as i64..=i32::MAX as i64).contains(&value) => value,
        "sqr" if value >= 0 => {
            let root = (value as f64).sqrt() as i64;
            if root.checked_mul(root) == Some(value) {
                root
            } else {
                return None;
            }
        }
        "round" => value,
        _ => return None,
    };
    small_integer_value(result)
}

fn evaluate_string_length_intrinsic(
    callee: &Expr,
    arguments: &[Expr],
    depth: usize,
    context: ProcedurePathContext<'_>,
    resolving: &mut HashSet<String>,
    module_scope_only: bool,
) -> Option<LiteralBranchValue> {
    let Expr::Identifier(name, _) = callee else {
        return None;
    };
    let intrinsic = canon_flow(name);
    if !matches!(intrinsic.as_str(), "len" | "lenb")
        || arguments.len() != 1
        || matches!(arguments.first(), Some(Expr::NamedArgument { .. }))
    {
        return None;
    }
    let project = context.project?;
    let module_index = unique_project_module_index(project, context.module)?;
    if project
        .modules
        .iter()
        .any(|candidate| canonical_data_name(&candidate.name) == intrinsic)
        || project
            .name
            .as_deref()
            .is_some_and(|project_name| canonical_data_name(project_name) == intrinsic)
        || crate::typecheck::project_may_shadow_intrinsic(
            project,
            module_index,
            context.module,
            context.procedure,
            &intrinsic,
        )
    {
        return None;
    }
    let original_argument = &arguments[0];
    let argument = path_value_expression(original_argument, context, module_scope_only);
    match evaluate_literal_branch_value_in_context(
        argument,
        depth + 1,
        Some(context),
        resolving,
        module_scope_only,
    ) {
        Some(LiteralBranchValue::String(value)) => {
            let units = i64::try_from(value.encode_utf16().count()).ok()?;
            let length = if intrinsic == "lenb" {
                units.checked_mul(2)?
            } else {
                units
            };
            return small_integer_value(length);
        }
        Some(LiteralBranchValue::Null) => return Some(LiteralBranchValue::Null),
        _ => {}
    }

    if let Expr::Identifier(name, _) = original_argument {
        let type_name = crate::typecheck::declared_symbol_type(
            project,
            module_index,
            context.module,
            Some(&context.procedure.name),
            name,
        )?;
        let normalized = crate::typecheck::normalized_type(&type_name);
        if let Some(length) = normalized.strip_prefix("string*")
            && !length.is_empty()
            && length.chars().all(|character| character.is_ascii_digit())
        {
            let characters = length.parse::<i64>().ok()?;
            let bytes = if intrinsic == "lenb" {
                characters.checked_mul(2)?
            } else {
                characters
            };
            return small_integer_value(bytes);
        }
        let storage_bytes = match crate::typecheck::known_vartype_value(
            project,
            module_index,
            context.module,
            context.procedure,
            original_argument,
        )? {
            2 => 2,           // Integer
            3 => 4,           // Long
            4 => 4,           // Single
            5..=7 => 8,       // Double, Currency, Date
            11 => 2,          // Boolean
            17 => 1,          // Byte
            _ => return None, // Variant, String, Object, UDT, and target-dependent types
        };
        return small_integer_value(storage_bytes);
    }
    None
}

fn evaluate_instr_intrinsic(
    callee: &Expr,
    arguments: &[Expr],
    depth: usize,
    context: ProcedurePathContext<'_>,
    resolving: &mut HashSet<String>,
    module_scope_only: bool,
) -> Option<LiteralBranchValue> {
    let Expr::Identifier(name, _) = callee else {
        return None;
    };
    if canon_flow(name) != "instr"
        || !(2..=4).contains(&arguments.len())
        || arguments
            .iter()
            .any(|argument| matches!(argument, Expr::NamedArgument { .. }))
    {
        return None;
    }
    let project = context.project?;
    let module_index = unique_project_module_index(project, context.module)?;
    if project
        .modules
        .iter()
        .any(|candidate| canonical_data_name(&candidate.name) == "instr")
        || project
            .name
            .as_deref()
            .is_some_and(|project_name| canonical_data_name(project_name) == "instr")
        || crate::typecheck::project_may_shadow_intrinsic(
            project,
            module_index,
            context.module,
            context.procedure,
            "instr",
        )
    {
        return None;
    }

    let (start, search_expression, match_expression, explicit_binary_compare) =
        if arguments.len() == 2 {
            (1, &arguments[0], &arguments[1], None)
        } else {
            let start = match evaluate_literal_branch_value_in_context(
                path_value_expression(&arguments[0], context, module_scope_only),
                depth + 1,
                Some(context),
                resolving,
                module_scope_only,
            )? {
                LiteralBranchValue::Integer(value) if value >= 1 => value,
                _ => return None,
            };
            let explicit_binary_compare = if arguments.len() == 4 {
                Some(evaluate_instr_binary_compare(
                    &arguments[3],
                    depth + 1,
                    context,
                    resolving,
                    module_scope_only,
                )?)
            } else {
                None
            };
            (start, &arguments[1], &arguments[2], explicit_binary_compare)
        };
    let binary_compare = explicit_binary_compare.unwrap_or_else(|| {
        context.module.options.compare_valid && context.module.options.compare_mode == "Binary"
    });
    if !binary_compare {
        return None;
    }

    let search = evaluate_literal_branch_value_in_context(
        path_value_expression(search_expression, context, module_scope_only),
        depth + 1,
        Some(context),
        resolving,
        module_scope_only,
    );
    let sought = evaluate_literal_branch_value_in_context(
        path_value_expression(match_expression, context, module_scope_only),
        depth + 1,
        Some(context),
        resolving,
        module_scope_only,
    );
    let (search, sought) = match (search, sought) {
        (Some(LiteralBranchValue::Null), _) | (_, Some(LiteralBranchValue::Null)) => {
            return Some(LiteralBranchValue::Null);
        }
        (Some(LiteralBranchValue::String(search)), Some(LiteralBranchValue::String(sought))) => {
            (search, sought)
        }
        _ => return None,
    };
    if !search.is_ascii() || !sought.is_ascii() {
        return None;
    }

    let position = if search.is_empty() {
        0
    } else if sought.is_empty() {
        let start = usize::try_from(start).ok()?;
        if start > search.len() {
            return None;
        }
        i64::try_from(start).ok()?
    } else {
        let start_index = usize::try_from(start.checked_sub(1)?).ok()?;
        if start_index >= search.len() {
            0
        } else {
            search[start_index..]
                .find(&sought)
                .and_then(|offset| i64::try_from(start_index + offset + 1).ok())
                .unwrap_or(0)
        }
    };
    small_integer_value(position)
}

fn evaluate_instrrev_intrinsic(
    callee: &Expr,
    arguments: &[Expr],
    depth: usize,
    context: ProcedurePathContext<'_>,
    resolving: &mut HashSet<String>,
    module_scope_only: bool,
) -> Option<LiteralBranchValue> {
    let Expr::Identifier(name, _) = callee else {
        return None;
    };
    if canon_flow(name) != "instrrev"
        || !(2..=4).contains(&arguments.len())
        || arguments
            .iter()
            .any(|argument| matches!(argument, Expr::NamedArgument { .. }))
    {
        return None;
    }
    let project = context.project?;
    let module_index = unique_project_module_index(project, context.module)?;
    if project
        .modules
        .iter()
        .any(|candidate| canonical_data_name(&candidate.name) == "instrrev")
        || project
            .name
            .as_deref()
            .is_some_and(|project_name| canonical_data_name(project_name) == "instrrev")
        || crate::typecheck::project_may_shadow_intrinsic(
            project,
            module_index,
            context.module,
            context.procedure,
            "instrrev",
        )
    {
        return None;
    }

    let explicit_start = if arguments.len() >= 3 {
        match evaluate_literal_branch_value_in_context(
            path_value_expression(&arguments[2], context, module_scope_only),
            depth + 1,
            Some(context),
            resolving,
            module_scope_only,
        )? {
            LiteralBranchValue::Integer(-1) => Some(-1),
            LiteralBranchValue::Integer(value) if value > 0 => Some(value),
            _ => return None,
        }
    } else {
        None
    };
    let binary_compare = if arguments.len() == 4 {
        evaluate_instr_binary_compare(
            &arguments[3],
            depth + 1,
            context,
            resolving,
            module_scope_only,
        )?
    } else {
        context.module.options.compare_valid && context.module.options.compare_mode == "Binary"
    };
    if !binary_compare {
        return None;
    }

    let search = evaluate_literal_branch_value_in_context(
        path_value_expression(&arguments[0], context, module_scope_only),
        depth + 1,
        Some(context),
        resolving,
        module_scope_only,
    );
    let sought = evaluate_literal_branch_value_in_context(
        path_value_expression(&arguments[1], context, module_scope_only),
        depth + 1,
        Some(context),
        resolving,
        module_scope_only,
    );
    let (search, sought) = match (search, sought) {
        (Some(LiteralBranchValue::Null), _) | (_, Some(LiteralBranchValue::Null)) => {
            return Some(LiteralBranchValue::Null);
        }
        (Some(LiteralBranchValue::String(search)), Some(LiteralBranchValue::String(sought))) => {
            (search, sought)
        }
        _ => return None,
    };
    if !search.is_ascii() || !sought.is_ascii() {
        return None;
    }
    if search.is_empty() {
        return small_integer_value(0);
    }

    let start = match explicit_start {
        Some(-1) | None => i64::try_from(search.len()).ok()?,
        Some(value) => value,
    };
    let search_length = i64::try_from(search.len()).ok()?;
    if start > search_length {
        return small_integer_value(0);
    }
    if sought.is_empty() {
        if explicit_start.is_none() || explicit_start == Some(-1) {
            return None;
        }
        return small_integer_value(start);
    }
    if start < 1 {
        return None;
    }
    let end = usize::try_from(start).ok()?;
    let position = search[..end]
        .rfind(&sought)
        .and_then(|index| i64::try_from(index + 1).ok())
        .unwrap_or(0);
    small_integer_value(position)
}

fn evaluate_string_slice_intrinsic(
    callee: &Expr,
    arguments: &[Expr],
    depth: usize,
    context: ProcedurePathContext<'_>,
    resolving: &mut HashSet<String>,
    module_scope_only: bool,
) -> Option<LiteralBranchValue> {
    let Expr::Identifier(name, _) = callee else {
        return None;
    };
    let intrinsic = canon_flow(name);
    if !matches!(intrinsic.as_str(), "left" | "right" | "mid")
        || arguments
            .iter()
            .any(|argument| matches!(argument, Expr::NamedArgument { .. }))
        || match intrinsic.as_str() {
            "left" | "right" => arguments.len() != 2,
            "mid" => !(2..=3).contains(&arguments.len()),
            _ => true,
        }
    {
        return None;
    }
    let project = context.project?;
    let module_index = unique_project_module_index(project, context.module)?;
    if project
        .modules
        .iter()
        .any(|candidate| canonical_data_name(&candidate.name) == intrinsic)
        || project
            .name
            .as_deref()
            .is_some_and(|project_name| canonical_data_name(project_name) == intrinsic)
        || crate::typecheck::project_may_shadow_intrinsic(
            project,
            module_index,
            context.module,
            context.procedure,
            &intrinsic,
        )
    {
        return None;
    }

    let source = evaluate_literal_branch_value_in_context(
        path_value_expression(&arguments[0], context, module_scope_only),
        depth + 1,
        Some(context),
        resolving,
        module_scope_only,
    );
    let source = match source {
        Some(LiteralBranchValue::Null) => return Some(LiteralBranchValue::Null),
        Some(LiteralBranchValue::String(value)) if value.is_ascii() => value,
        _ => return None,
    };

    let (start, length) = match intrinsic.as_str() {
        "left" | "right" => {
            let length = evaluate_literal_branch_value_in_context(
                path_value_expression(&arguments[1], context, module_scope_only),
                depth + 1,
                Some(context),
                resolving,
                module_scope_only,
            )?;
            let LiteralBranchValue::Integer(length) = length else {
                return None;
            };
            if length < 0 {
                return None;
            }
            (0, usize::try_from(length).ok()?)
        }
        "mid" => {
            let start = evaluate_literal_branch_value_in_context(
                path_value_expression(&arguments[1], context, module_scope_only),
                depth + 1,
                Some(context),
                resolving,
                module_scope_only,
            )?;
            let LiteralBranchValue::Integer(start) = start else {
                return None;
            };
            if start < 1 {
                return None;
            }
            let length = if arguments.len() == 3 {
                let length = evaluate_literal_branch_value_in_context(
                    path_value_expression(&arguments[2], context, module_scope_only),
                    depth + 1,
                    Some(context),
                    resolving,
                    module_scope_only,
                )?;
                let LiteralBranchValue::Integer(length) = length else {
                    return None;
                };
                if length < 0 {
                    return None;
                }
                usize::try_from(length).ok()?
            } else {
                source.len()
            };
            (usize::try_from(start.checked_sub(1)?).ok()?, length)
        }
        _ => return None,
    };

    if intrinsic == "left" {
        let end = length.min(source.len());
        return Some(LiteralBranchValue::String(source[..end].to_owned()));
    }
    if intrinsic == "right" {
        let start = source.len().saturating_sub(length);
        return Some(LiteralBranchValue::String(source[start..].to_owned()));
    }
    if start >= source.len() {
        return Some(LiteralBranchValue::String(String::new()));
    }
    let end = start.saturating_add(length).min(source.len());
    Some(LiteralBranchValue::String(source[start..end].to_owned()))
}

fn evaluate_string_trim_intrinsic(
    callee: &Expr,
    arguments: &[Expr],
    depth: usize,
    context: ProcedurePathContext<'_>,
    resolving: &mut HashSet<String>,
    module_scope_only: bool,
) -> Option<LiteralBranchValue> {
    let Expr::Identifier(name, _) = callee else {
        return None;
    };
    let intrinsic = canon_flow(name);
    if !matches!(intrinsic.as_str(), "trim" | "ltrim" | "rtrim")
        || arguments.len() != 1
        || matches!(arguments.first(), Some(Expr::NamedArgument { .. }))
    {
        return None;
    }
    let project = context.project?;
    let module_index = unique_project_module_index(project, context.module)?;
    if project
        .modules
        .iter()
        .any(|candidate| canonical_data_name(&candidate.name) == intrinsic)
        || project
            .name
            .as_deref()
            .is_some_and(|project_name| canonical_data_name(project_name) == intrinsic)
        || crate::typecheck::project_may_shadow_intrinsic(
            project,
            module_index,
            context.module,
            context.procedure,
            &intrinsic,
        )
    {
        return None;
    }
    let source = evaluate_literal_branch_value_in_context(
        path_value_expression(&arguments[0], context, module_scope_only),
        depth + 1,
        Some(context),
        resolving,
        module_scope_only,
    );
    match source {
        Some(LiteralBranchValue::Null) => Some(LiteralBranchValue::Null),
        Some(LiteralBranchValue::String(value)) if value.is_ascii() => {
            let trimmed = match intrinsic.as_str() {
                "ltrim" => value.trim_start_matches(' '),
                "rtrim" => value.trim_end_matches(' '),
                _ => value.trim_matches(' '),
            };
            Some(LiteralBranchValue::String(trimmed.to_owned()))
        }
        _ => None,
    }
}

fn evaluate_replace_intrinsic(
    callee: &Expr,
    arguments: &[Expr],
    depth: usize,
    context: ProcedurePathContext<'_>,
    resolving: &mut HashSet<String>,
    module_scope_only: bool,
) -> Option<LiteralBranchValue> {
    let Expr::Identifier(name, _) = callee else {
        return None;
    };
    if canon_flow(name) != "replace"
        || arguments.len() != 3
        || arguments
            .iter()
            .any(|argument| matches!(argument, Expr::NamedArgument { .. }))
    {
        return None;
    }
    let project = context.project?;
    let module_index = unique_project_module_index(project, context.module)?;
    if project
        .modules
        .iter()
        .any(|candidate| canonical_data_name(&candidate.name) == "replace")
        || project
            .name
            .as_deref()
            .is_some_and(|project_name| canonical_data_name(project_name) == "replace")
        || crate::typecheck::project_may_shadow_intrinsic(
            project,
            module_index,
            context.module,
            context.procedure,
            "replace",
        )
        || !context.module.options.compare_valid
        || context.module.options.compare_mode != "Binary"
    {
        return None;
    }

    let mut values = Vec::with_capacity(3);
    for argument in arguments {
        match evaluate_literal_branch_value_in_context(
            path_value_expression(argument, context, module_scope_only),
            depth + 1,
            Some(context),
            resolving,
            module_scope_only,
        ) {
            Some(LiteralBranchValue::String(value)) if value.is_ascii() => values.push(value),
            // VBA's Replace raises a runtime error when expression is Null.
            // Leave every Null/string-coercion case unresolved rather than
            // treating it like an ordinary Null-propagating string intrinsic.
            _ => return None,
        }
    }
    let mut values = values.into_iter();
    let expression = values.next()?;
    let find = values.next()?;
    let replacement = values.next()?;
    if find.is_empty() {
        return Some(LiteralBranchValue::String(expression));
    }
    let replacement_count = expression.matches(&find).count();
    let removed = replacement_count.checked_mul(find.len())?;
    let inserted = replacement_count.checked_mul(replacement.len())?;
    let result_length = expression
        .len()
        .checked_sub(removed)?
        .checked_add(inserted)?;
    if result_length > MAX_BRANCH_STRING_BYTES {
        return None;
    }
    Some(LiteralBranchValue::String(
        expression.replace(&find, &replacement),
    ))
}

fn evaluate_instr_binary_compare(
    expression: &Expr,
    depth: usize,
    context: ProcedurePathContext<'_>,
    resolving: &mut HashSet<String>,
    module_scope_only: bool,
) -> Option<bool> {
    let expression = path_value_expression(expression, context, module_scope_only);
    if let Some(value) = evaluate_literal_branch_value_in_context(
        expression,
        depth + 1,
        Some(context),
        resolving,
        module_scope_only,
    ) {
        return Some(match value {
            LiteralBranchValue::Integer(0) => true,
            LiteralBranchValue::Integer(-1) => {
                context.module.options.compare_valid
                    && context.module.options.compare_mode == "Binary"
            }
            LiteralBranchValue::Integer(_) => false,
            _ => return None,
        });
    }
    let Expr::Identifier(name, _) = expression else {
        return None;
    };
    let name = canon_flow(name);
    if crate::typecheck::project_may_shadow_type_intrinsic(
        context.project?,
        unique_project_module_index(context.project?, context.module)?,
        context.module,
        context.procedure,
        &name,
    ) {
        return None;
    }
    match name.as_str() {
        "vbbinarycompare" => Some(true),
        "vbusecompareoption" => Some(
            context.module.options.compare_valid && context.module.options.compare_mode == "Binary",
        ),
        "vbtextcompare" => Some(false),
        _ => None,
    }
}

fn path_value_expression<'a>(
    expression: &'a Expr,
    context: ProcedurePathContext<'a>,
    module_scope_only: bool,
) -> &'a Expr {
    if module_scope_only {
        return expression;
    }
    let mut current = expression;
    let mut seen = HashSet::new();
    for _ in 0..64 {
        match current {
            Expr::Group(value, _) => current = value,
            Expr::Identifier(name, _) => {
                let key = canon_flow(name);
                if !seen.insert(key.clone()) {
                    break;
                }
                let Some(next) = context.path_values.and_then(|values| values.get(&key)) else {
                    break;
                };
                current = next;
            }
            _ => break,
        }
    }
    current
}

fn known_intrinsic_constant_value(name: &str, context: ProcedurePathContext<'_>) -> Option<i64> {
    let name = canon_flow(name);
    let value = match name.as_str() {
        "vbempty" => 0,
        "vbnull" => 1,
        "vbinteger" => 2,
        "vblong" => 3,
        "vbsingle" => 4,
        "vbdouble" => 5,
        "vbcurrency" => 6,
        "vbdate" => 7,
        "vbstring" => 8,
        "vbobject" => 9,
        "vberror" => 10,
        "vbboolean" => 11,
        "vbvariant" => 12,
        "vbdataobject" => 13,
        "vbdecimal" => 14,
        "vbbyte" => 17,
        "vbuserdefinedtype" => 36,
        "vbarray" => 8192,
        "vbbinarycompare" => 0,
        "vbtextcompare" => 1,
        "vbusecompareoption" => -1,
        _ => return None,
    };
    let project = context.project?;
    let module_index = unique_project_module_index(project, context.module)?;
    if crate::typecheck::project_may_shadow_type_intrinsic(
        project,
        module_index,
        context.module,
        context.procedure,
        &name,
    ) {
        None
    } else {
        Some(value)
    }
}

fn known_is_missing_for_private_call_sites(
    context: ProcedurePathContext<'_>,
    parameter_name: &str,
) -> Option<bool> {
    let project = context.project?;
    let call_facts = context.call_facts?;
    let procedure = context.procedure;
    let module = context.module;
    if !procedure.visibility.eq_ignore_ascii_case("private")
        || !matches!(module.module_kind.as_deref(), Some("standard") | None)
        || !matches!(
            procedure.kind.to_ascii_lowercase().as_str(),
            "sub" | "function"
        )
        || project
            .metadata
            .get(&format!(
                "module:{}:conditional_compile_unknown",
                module.name
            ))
            .is_some_and(|value| value == "true")
        || call_facts.iter().any(|call| {
            matches!(canon_flow(&call.target).as_str(), "run" | "ontime")
                || call.arguments.iter().any(|argument| {
                    let argument = argument.to_ascii_lowercase();
                    argument.contains("addressof")
                        && argument.contains(&procedure.name.to_ascii_lowercase())
                })
        })
    {
        return None;
    }

    let target_name = canon_flow(&procedure.name);
    let mut matching_calls = call_facts.iter().filter(|call| {
        call.module.eq_ignore_ascii_case(&module.name)
            && canon_flow(&call.target) == target_name
            && call.procedure.is_some()
    });
    let first = matching_calls.next()?;
    let parameter_index = procedure
        .parameters
        .iter()
        .position(|parameter| canon_flow(&parameter.name) == canon_flow(parameter_name))?;
    let is_missing = |call: &CallFact| {
        if call.resolution != "resolved_project_procedure"
            || call.argument_count != Some(call.arguments.len())
        {
            return None;
        }
        let supplied =
            argument_supplies_parameter(&procedure.parameters, &call.arguments, parameter_index)?;
        Some(!supplied)
    };
    let expected = is_missing(first)?;
    for call in matching_calls {
        if is_missing(call)? != expected {
            return None;
        }
    }
    Some(expected)
}

fn argument_supplies_parameter(
    parameters: &[crate::model::Parameter],
    arguments: &[String],
    target_index: usize,
) -> Option<bool> {
    let mut assigned = vec![None; parameters.len()];
    let param_array_index = parameters
        .iter()
        .position(|parameter| parameter.is_param_array);
    let mut next_positional = 0usize;
    let mut named_seen = false;

    for argument in arguments {
        if let Some((name, value)) = split_named_call_argument(argument) {
            named_seen = true;
            if param_array_index.is_some() {
                return None;
            }
            let index = parameters
                .iter()
                .position(|parameter| canon_flow(&parameter.name) == canon_flow(name.trim()))?;
            if assigned[index].is_some() || value.trim().is_empty() {
                return None;
            }
            assigned[index] = Some(true);
            continue;
        }

        if named_seen {
            return None;
        }
        while next_positional < parameters.len() && assigned[next_positional].is_some() {
            next_positional += 1;
        }
        if next_positional >= parameters.len() {
            if param_array_index.is_some() {
                continue;
            }
            return None;
        }
        let index = next_positional;
        next_positional += 1;
        let supplied = !argument.trim().is_empty();
        if !supplied && !parameters[index].optional && !parameters[index].is_param_array {
            return None;
        }
        if assigned[index].is_some() && Some(index) != param_array_index {
            return None;
        }
        assigned[index] = Some(supplied);
    }

    for (index, parameter) in parameters.iter().enumerate() {
        if !parameter.optional && !parameter.is_param_array && assigned[index].is_none() {
            return None;
        }
    }
    Some(
        assigned
            .get(target_index)
            .copied()
            .flatten()
            .unwrap_or(false),
    )
}

fn argument_expressions_for_parameter(
    parameters: &[crate::model::Parameter],
    arguments: &[String],
    target_index: usize,
) -> Option<Vec<(Option<usize>, String)>> {
    let param_array_index = parameters
        .iter()
        .position(|parameter| parameter.is_param_array);
    if Some(target_index) == param_array_index {
        let mut fixed_seen = 0usize;
        let mut slots = Vec::new();
        for argument in arguments {
            if split_named_call_argument(argument).is_some() {
                return None;
            }
            if fixed_seen < target_index {
                fixed_seen += 1;
                continue;
            }
            let value = argument.trim();
            if value.is_empty() {
                return None;
            }
            slots.push((Some(slots.len()), value.to_owned()));
        }
        return Some(slots);
    }
    argument_expression_for_parameter(parameters, arguments, target_index)
        .map(|expression| vec![(None, expression)])
}

fn argument_expression_for_parameter(
    parameters: &[crate::model::Parameter],
    arguments: &[String],
    target_index: usize,
) -> Option<String> {
    if target_index >= parameters.len()
        || parameters.iter().any(|parameter| parameter.is_param_array)
    {
        return None;
    }
    let mut assigned = vec![false; parameters.len()];
    let mut values = vec![None; parameters.len()];
    let mut next_positional = 0usize;
    let mut named_seen = false;
    for argument in arguments {
        if let Some((name, value)) = split_named_call_argument(argument) {
            named_seen = true;
            let index = parameters
                .iter()
                .position(|parameter| canon_flow(&parameter.name) == canon_flow(name.trim()))?;
            if assigned[index] || value.trim().is_empty() {
                return None;
            }
            assigned[index] = true;
            values[index] = Some(value.trim().to_owned());
            continue;
        }
        if named_seen {
            return None;
        }
        while next_positional < parameters.len() && assigned[next_positional] {
            next_positional += 1;
        }
        if next_positional >= parameters.len() {
            return None;
        }
        let index = next_positional;
        next_positional += 1;
        let value = argument.trim();
        if value.is_empty() {
            if !parameters[index].optional {
                return None;
            }
            assigned[index] = true;
        } else {
            assigned[index] = true;
            values[index] = Some(value.to_owned());
        }
    }
    for (index, parameter) in parameters.iter().enumerate() {
        if !parameter.optional && !assigned[index] {
            return None;
        }
    }
    values.get(target_index).cloned().flatten()
}

fn split_named_call_argument(argument: &str) -> Option<(&str, &str)> {
    let (name, value) = argument.split_once('=')?;
    let name = name.trim().strip_suffix(':')?.trim();
    if name.is_empty() || name.starts_with('"') || name.starts_with('#') {
        return None;
    }
    Some((name, value.trim()))
}

fn literal_branch_value_expression(value: LiteralBranchValue) -> Expr {
    let span = crate::model::Span::default();
    match value {
        LiteralBranchValue::Boolean(value) => {
            Expr::Identifier(if value { "True" } else { "False" }.into(), span)
        }
        LiteralBranchValue::Integer(value) => {
            Expr::Literal(value.to_string(), crate::model::LiteralKind::Number, span)
        }
        LiteralBranchValue::Date(value) => Expr::Call {
            callee: Box::new(Expr::Identifier("CDate".into(), span)),
            args: vec![Expr::Literal(
                branch_date_to_serial(value).to_string(),
                crate::model::LiteralKind::Number,
                span,
            )],
            span,
        },
        LiteralBranchValue::String(value) => {
            Expr::Literal(value, crate::model::LiteralKind::String, span)
        }
        LiteralBranchValue::Null => Expr::Identifier("Null".into(), span),
        LiteralBranchValue::Empty => Expr::Identifier("Empty".into(), span),
    }
}

/// Collect only callsite-consensus values for private standard-module ByVal
/// parameters. Every known direct project call must supply the same statically
/// evaluable literal/constant; dynamic entry points, conditional compilation,
/// mutable caller variables, and ByRef aliases keep the callee value unknown.
pub(crate) fn build_static_private_parameter_values(
    project: &Project,
    call_facts: &[CallFact],
    step_limit: usize,
) -> StaticParameterValues {
    let mut output = StaticParameterValues::new();
    if step_limit == 0 {
        return output;
    }

    let mut steps = 0usize;
    let mut calls_by_module_target: HashMap<(String, String), Vec<&CallFact>> = HashMap::new();
    for call in call_facts {
        if steps >= step_limit {
            return StaticParameterValues::new();
        }
        steps += 1;
        if matches!(canon_flow(&call.target).as_str(), "run" | "ontime") {
            return StaticParameterValues::new();
        }
        for argument in &call.arguments {
            if steps >= step_limit {
                return StaticParameterValues::new();
            }
            steps += 1;
            if argument.to_ascii_lowercase().contains("addressof") {
                return StaticParameterValues::new();
            }
        }
        if call.procedure.is_none() {
            continue;
        }
        calls_by_module_target
            .entry((
                canonical_data_name(&call.module),
                canonical_data_name(&call.target),
            ))
            .or_default()
            .push(call);
    }

    let mut module_indices = HashMap::<String, Option<usize>>::new();
    for (index, module) in project.modules.iter().enumerate() {
        if steps >= step_limit {
            return StaticParameterValues::new();
        }
        steps += 1;
        module_indices
            .entry(canonical_data_name(&module.name))
            .and_modify(|index| *index = None)
            .or_insert(Some(index));
    }

    for (module_index, module) in project.modules.iter().enumerate() {
        let module_key = canonical_data_name(&module.name);
        if !matches!(module.module_kind.as_deref(), Some("standard") | None)
            || project
                .metadata
                .get(&format!(
                    "module:{}:conditional_compile_unknown",
                    module.name
                ))
                .is_some_and(|value| value == "true")
            || module_indices.get(&module_key) != Some(&Some(module_index))
        {
            continue;
        }
        let mut procedure_counts = HashMap::<String, usize>::new();
        for candidate in &module.procedures {
            if steps >= step_limit {
                return StaticParameterValues::new();
            }
            steps += 1;
            *procedure_counts
                .entry(canonical_data_name(&candidate.name))
                .or_default() += 1;
        }
        for procedure in &module.procedures {
            if steps >= step_limit {
                return StaticParameterValues::new();
            }
            steps += 1;
            if !procedure.visibility.eq_ignore_ascii_case("private")
                || !matches!(
                    procedure.kind.to_ascii_lowercase().as_str(),
                    "sub" | "function"
                )
                || procedure_counts.get(&canonical_data_name(&procedure.name)) != Some(&1)
            {
                continue;
            }
            let procedure_key = canonical_data_name(&procedure.name);
            let Some(calls) =
                calls_by_module_target.get(&(module_key.clone(), procedure_key.clone()))
            else {
                continue;
            };
            let mut valid_call_sites = true;
            for call in calls {
                if steps >= step_limit {
                    return StaticParameterValues::new();
                }
                steps += 1;
                if call.resolution != "resolved_project_procedure"
                    || call.argument_count != Some(call.arguments.len())
                {
                    valid_call_sites = false;
                    break;
                }
            }
            if !valid_call_sites {
                continue;
            }

            let mut known_parameters = HashMap::new();
            for (parameter_index, parameter) in procedure.parameters.iter().enumerate() {
                if steps >= step_limit {
                    return StaticParameterValues::new();
                }
                steps += 1;
                if !parameter.passing.eq_ignore_ascii_case("byval")
                    || parameter.is_array
                    || parameter.is_param_array
                {
                    continue;
                }
                let Some(formal_type) = crate::typecheck::declared_parameter_type(
                    project,
                    module_index,
                    module,
                    parameter,
                ) else {
                    continue;
                };
                let formal_type = crate::typecheck::normalized_type(&formal_type);
                if !matches!(
                    formal_type.as_str(),
                    "variant" | "boolean" | "byte" | "integer" | "long" | "string"
                ) {
                    continue;
                }

                let parameter_value = (|| {
                    let mut agreed_value: Option<LiteralBranchValue> = None;
                    for call in calls {
                        if steps >= step_limit || call.arguments.len() > step_limit - steps - 1 {
                            return None;
                        }
                        steps += 1 + call.arguments.len();
                        let caller_module_index = module_indices
                            .get(&canonical_data_name(&call.module))
                            .copied()
                            .flatten()?;
                        let caller_module = &project.modules[caller_module_index];
                        if project
                            .metadata
                            .get(&format!(
                                "module:{}:conditional_compile_unknown",
                                caller_module.name
                            ))
                            .is_some_and(|value| value == "true")
                        {
                            return None;
                        }
                        let caller_procedure_name = call.procedure.as_deref()?;
                        let caller_procedure_key = canonical_data_name(caller_procedure_name);
                        let mut matching_caller = None;
                        for candidate in &caller_module.procedures {
                            if steps >= step_limit {
                                return None;
                            }
                            steps += 1;
                            if canonical_data_name(&candidate.name) == caller_procedure_key {
                                if matching_caller.is_some() {
                                    return None;
                                }
                                matching_caller = Some(candidate);
                            }
                        }
                        let caller_procedure = matching_caller?;
                        let actual = argument_expression_for_parameter(
                            &procedure.parameters,
                            &call.arguments,
                            parameter_index,
                        )?;
                        let expression = crate::parser::parse_expression_source(&actual)?;
                        let caller_context = ProcedurePathContext {
                            project: Some(project),
                            module: caller_module,
                            procedure: caller_procedure,
                            call_facts: None,
                            path_values: None,
                            callsite_parameter_values: None,
                            param_array_lengths: None,
                            array_shapes: None,
                            optional_missing: None,
                        };
                        let mut resolving = HashSet::new();
                        if expression_has_unsafe_call(&expression, caller_context)
                            || !path_expression_has_only_stable_identifiers(
                                &expression,
                                caller_context,
                                &mut resolving,
                                0,
                            )
                        {
                            return None;
                        }
                        let actual_type =
                            crate::typecheck::normalized_type(&crate::typecheck::infer_expr(
                                project,
                                caller_module_index,
                                caller_module,
                                caller_procedure,
                                &expression,
                                crate::host::HostProfile::Unknown,
                            ));
                        if formal_type != "variant" && actual_type != formal_type {
                            return None;
                        }
                        let value = evaluate_literal_branch_value_in_context(
                            &expression,
                            0,
                            Some(caller_context),
                            &mut resolving,
                            false,
                        )?;
                        if !matches!(formal_type.as_str(), "variant")
                            && matches!(value, LiteralBranchValue::Null | LiteralBranchValue::Empty)
                        {
                            return None;
                        }
                        if agreed_value
                            .as_ref()
                            .is_some_and(|existing| existing != &value)
                        {
                            return None;
                        }
                        agreed_value = Some(value);
                    }
                    agreed_value
                })();
                if let Some(value) = parameter_value {
                    known_parameters.insert(
                        canonical_data_name(&parameter.name),
                        literal_branch_value_expression(value),
                    );
                }
            }
            if !known_parameters.is_empty() {
                output.insert((module_key.clone(), procedure_key), known_parameters);
            }
        }
    }
    output
}

fn unique_project_module_index(project: &Project, module: &Module) -> Option<usize> {
    let mut candidates = project
        .modules
        .iter()
        .enumerate()
        .filter(|(_, candidate)| {
            canonical_data_name(&candidate.name) == canonical_data_name(&module.name)
        })
        .map(|(index, _)| index);
    let index = candidates.next()?;
    candidates.next().is_none().then_some(index)
}

fn statically_known_numeric_input(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    expression: &Expr,
) -> Option<bool> {
    if let Some(type_code) =
        crate::typecheck::known_vartype_value(project, module_index, module, procedure, expression)
    {
        return match type_code {
            0 | 1 | 7 | 10 => Some(false),
            2 | 3 | 4 | 5 | 6 | 11 | 14 | 17 | 20 => Some(true),
            _ => None,
        };
    }
    match expression {
        Expr::Literal(_, LiteralKind::Number, _) => Some(true),
        Expr::Identifier(name, _)
            if name.eq_ignore_ascii_case("True") || name.eq_ignore_ascii_case("False") =>
        {
            Some(true)
        }
        Expr::Identifier(name, _)
            if name.eq_ignore_ascii_case("Null") || name.eq_ignore_ascii_case("Empty") =>
        {
            Some(false)
        }
        Expr::Group(value, _) => {
            statically_known_numeric_input(project, module_index, module, procedure, value)
        }
        Expr::Identifier(name, _) => {
            let type_name = crate::typecheck::declared_symbol_type(
                project,
                module_index,
                module,
                Some(&procedure.name),
                name,
            )?;
            match crate::typecheck::normalized_type(&type_name).as_str() {
                "boolean" | "byte" | "integer" | "long" | "longlong" | "longptr" | "single"
                | "double" | "currency" | "decimal" => Some(true),
                "date" => Some(false),
                _ => None,
            }
        }
        _ => None,
    }
}

fn evaluate_constant_identifier(
    name: &str,
    context: ProcedurePathContext<'_>,
    depth: usize,
    resolving: &mut HashSet<String>,
    module_scope_only: bool,
) -> Option<LiteralBranchValue> {
    let module = context.module;
    let procedure = context.procedure;
    let key = canon_flow(name);
    if key.is_empty() || depth >= 64 {
        return None;
    }

    let mut locals = Vec::new();
    if !module_scope_only {
        collect_procedure_declarations(&procedure.statements, &key, &mut locals);
    }
    let parameter_shadows = !module_scope_only
        && procedure
            .parameters
            .iter()
            .any(|parameter| canon_flow(&parameter.name) == key);
    let function_result_shadows = !module_scope_only && canon_flow(&procedure.name) == key;
    if parameter_shadows || function_result_shadows || !locals.is_empty() {
        if parameter_shadows || function_result_shadows || locals.len() != 1 {
            return None;
        }
        let declaration = locals[0];
        if declaration.kind != "constant" {
            return None;
        }
        return evaluate_constant_declaration(
            declaration,
            &format!("local:{}:{key}", canon_flow(&procedure.name)),
            context,
            depth + 1,
            resolving,
        );
    }

    let matches = module
        .declarations
        .iter()
        .filter(|declaration| canon_flow(&declaration.name) == key)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return None;
    }
    let declaration = matches[0];
    if declaration.kind == "enum_member" {
        return declaration
            .enum_value
            .and_then(|value| small_integer_value(i64::from(value)));
    }
    if declaration.kind != "constant" {
        return None;
    }
    evaluate_constant_declaration(
        declaration,
        &format!("module:{key}"),
        context,
        depth + 1,
        resolving,
    )
}

fn evaluate_constant_declaration(
    declaration: &crate::model::Declaration,
    key: &str,
    context: ProcedurePathContext<'_>,
    depth: usize,
    resolving: &mut HashSet<String>,
) -> Option<LiteralBranchValue> {
    if !resolving.insert(key.to_owned()) {
        return None;
    }
    let result = declaration
        .initializer
        .as_deref()
        .and_then(parse_expression_source)
        .and_then(|expression| {
            if expression_contains_call(&expression) {
                return None;
            }
            evaluate_literal_branch_value_in_context(
                &expression,
                depth + 1,
                Some(context),
                resolving,
                key.starts_with("module:"),
            )
        });
    resolving.remove(key);

    let declared_type = declaration
        .type_name
        .as_deref()
        .map(|type_name| type_name.trim().to_ascii_lowercase());
    match declared_type.as_deref() {
        Some("boolean") => {
            return match result? {
                LiteralBranchValue::Boolean(value) => Some(LiteralBranchValue::Boolean(value)),
                LiteralBranchValue::Integer(value) => Some(LiteralBranchValue::Boolean(value != 0)),
                LiteralBranchValue::String(value) if value.eq_ignore_ascii_case("true") => {
                    Some(LiteralBranchValue::Boolean(true))
                }
                LiteralBranchValue::String(value) if value.eq_ignore_ascii_case("false") => {
                    Some(LiteralBranchValue::Boolean(false))
                }
                LiteralBranchValue::Empty => Some(LiteralBranchValue::Boolean(false)),
                LiteralBranchValue::String(_)
                | LiteralBranchValue::Null
                | LiteralBranchValue::Date(_) => None,
            };
        }
        Some("string") => {
            return match result? {
                value @ LiteralBranchValue::String(_) => Some(value),
                _ => None,
            };
        }
        Some("variant") | None => {}
        Some(_)
            if matches!(
                result.as_ref(),
                Some(LiteralBranchValue::String(_) | LiteralBranchValue::Null)
            ) =>
        {
            return None;
        }
        Some(_) => {}
    }
    result
}

fn expression_contains_call(expression: &Expr) -> bool {
    match expression {
        Expr::Call { .. } => true,
        Expr::Unary { value, .. } | Expr::Group(value, _) => expression_contains_call(value),
        Expr::Binary { left, right, .. } => {
            expression_contains_call(left) || expression_contains_call(right)
        }
        Expr::Member { object, .. } => expression_contains_call(object),
        Expr::NamedArgument { value, .. } => expression_contains_call(value),
        Expr::TypeOfIs { expression, .. } => expression_contains_call(expression),
        Expr::Identifier(..) | Expr::Literal(..) | Expr::Unknown(..) => false,
    }
}

fn collect_procedure_declarations<'a>(
    statements: &'a [Statement],
    name: &str,
    out: &mut Vec<&'a crate::model::Declaration>,
) {
    for statement in statements {
        if let Some(declaration) = statement.declaration.as_ref()
            && canon_flow(&declaration.name) == name
        {
            out.push(declaration);
        }
        collect_procedure_declarations(&statement.children, name, out);
    }
}

fn evaluate_literal_branch_operator(
    operator: &str,
    left: LiteralBranchValue,
    right: LiteralBranchValue,
    context: Option<ProcedurePathContext<'_>>,
) -> Option<LiteralBranchValue> {
    let operator = operator.to_ascii_lowercase();
    if matches!(&left, LiteralBranchValue::Null) || matches!(&right, LiteralBranchValue::Null) {
        return match (operator.as_str(), &left, &right) {
            ("=", _, _)
            | ("<>", _, _)
            | ("<", _, _)
            | (">", _, _)
            | ("<=", _, _)
            | (">=", _, _)
            | ("like", _, _) => Some(LiteralBranchValue::Null),
            ("and", LiteralBranchValue::Boolean(false), LiteralBranchValue::Null)
            | ("and", LiteralBranchValue::Null, LiteralBranchValue::Boolean(false)) => {
                Some(LiteralBranchValue::Boolean(false))
            }
            ("and", LiteralBranchValue::Boolean(true), LiteralBranchValue::Null)
            | ("and", LiteralBranchValue::Null, LiteralBranchValue::Boolean(true))
            | ("and", LiteralBranchValue::Null, LiteralBranchValue::Null) => {
                Some(LiteralBranchValue::Null)
            }
            ("or", LiteralBranchValue::Boolean(value), LiteralBranchValue::Null)
            | ("or", LiteralBranchValue::Null, LiteralBranchValue::Boolean(value)) => {
                Some(LiteralBranchValue::Boolean(*value))
            }
            ("or", LiteralBranchValue::Null, LiteralBranchValue::Null)
            | ("xor", _, _)
            | ("eqv", _, _) => Some(LiteralBranchValue::Null),
            ("imp", LiteralBranchValue::Boolean(false), LiteralBranchValue::Null)
            | ("imp", LiteralBranchValue::Null, LiteralBranchValue::Boolean(true)) => {
                Some(LiteralBranchValue::Boolean(true))
            }
            ("imp", LiteralBranchValue::Boolean(true), LiteralBranchValue::Null)
            | ("imp", LiteralBranchValue::Null, LiteralBranchValue::Boolean(false))
            | ("imp", LiteralBranchValue::Null, LiteralBranchValue::Null) => {
                Some(LiteralBranchValue::Null)
            }
            _ => None,
        };
    }
    if let (LiteralBranchValue::String(left), LiteralBranchValue::String(right)) = (&left, &right) {
        if matches!(operator.as_str(), "&" | "+") {
            let length = left.len().checked_add(right.len())?;
            if length > MAX_BRANCH_STRING_BYTES {
                return None;
            }
            let mut result = String::with_capacity(length);
            result.push_str(left);
            result.push_str(right);
            return Some(LiteralBranchValue::String(result));
        }
        if operator == "like" {
            let module = context?.module;
            if !module.options.compare_valid || module.options.compare_mode != "Binary" {
                return None;
            }
            return crate::preprocessor::like_match_ascii(left, right)
                .map(LiteralBranchValue::Boolean);
        }
        let ordering = compare_branch_strings(left, right, context)?;
        let result = match operator.as_str() {
            "=" => ordering.is_eq(),
            "<>" => !ordering.is_eq(),
            "<" => ordering.is_lt(),
            ">" => ordering.is_gt(),
            "<=" => !ordering.is_gt(),
            ">=" => !ordering.is_lt(),
            _ => return None,
        };
        return Some(LiteralBranchValue::Boolean(result));
    }
    let date_ticks = |value: &LiteralBranchValue| match value {
        LiteralBranchValue::Date(value) => Some(*value),
        LiteralBranchValue::Integer(value) => value.checked_mul(DATE_SECONDS_PER_DAY),
        _ => None,
    };
    if matches!(&left, LiteralBranchValue::Date(_)) || matches!(&right, LiteralBranchValue::Date(_))
    {
        let left_ticks = date_ticks(&left)?;
        let right_ticks = date_ticks(&right)?;
        return match operator.as_str() {
            "=" => Some(LiteralBranchValue::Boolean(left_ticks == right_ticks)),
            "<>" => Some(LiteralBranchValue::Boolean(left_ticks != right_ticks)),
            "<" => Some(LiteralBranchValue::Boolean(left_ticks < right_ticks)),
            ">" => Some(LiteralBranchValue::Boolean(left_ticks > right_ticks)),
            "<=" => Some(LiteralBranchValue::Boolean(left_ticks <= right_ticks)),
            ">=" => Some(LiteralBranchValue::Boolean(left_ticks >= right_ticks)),
            "+" if matches!(&left, LiteralBranchValue::Date(_)) => {
                let days = match right {
                    LiteralBranchValue::Integer(value) => {
                        value.checked_mul(DATE_SECONDS_PER_DAY)?
                    }
                    _ => return None,
                };
                Some(LiteralBranchValue::Date(left_ticks.checked_add(days)?))
            }
            "+" if matches!(&right, LiteralBranchValue::Date(_)) => {
                let days = match left {
                    LiteralBranchValue::Integer(value) => {
                        value.checked_mul(DATE_SECONDS_PER_DAY)?
                    }
                    _ => return None,
                };
                Some(LiteralBranchValue::Date(right_ticks.checked_add(days)?))
            }
            "-" if matches!(&left, LiteralBranchValue::Date(_))
                && matches!(&right, LiteralBranchValue::Date(_)) =>
            {
                let difference = left_ticks.checked_sub(right_ticks)?;
                (difference % DATE_SECONDS_PER_DAY == 0).then_some(LiteralBranchValue::Integer(
                    difference / DATE_SECONDS_PER_DAY,
                ))
            }
            "-" if matches!(&left, LiteralBranchValue::Date(_)) => {
                let days = match right {
                    LiteralBranchValue::Integer(value) => {
                        value.checked_mul(DATE_SECONDS_PER_DAY)?
                    }
                    _ => return None,
                };
                Some(LiteralBranchValue::Date(left_ticks.checked_sub(days)?))
            }
            _ => None,
        };
    }
    let numeric = |value: LiteralBranchValue| match value {
        LiteralBranchValue::Boolean(value) => Some(if value { -1 } else { 0 }),
        LiteralBranchValue::Integer(value) => Some(value),
        LiteralBranchValue::String(_) | LiteralBranchValue::Null | LiteralBranchValue::Date(_) => {
            None
        }
        LiteralBranchValue::Empty => Some(0),
    };
    if let (LiteralBranchValue::Boolean(left), LiteralBranchValue::Boolean(right)) = (&left, &right)
        && matches!(
            operator.as_str(),
            "=" | "<>" | "<" | ">" | "<=" | ">=" | "and" | "or" | "xor" | "eqv" | "imp"
        )
    {
        let result = match operator.as_str() {
            "=" => left == right,
            "<>" => left != right,
            "<" => *left && !*right,
            ">" => !*left && *right,
            "<=" => !*left || *right,
            ">=" => *left || !*right,
            "and" => *left && *right,
            "or" => *left || *right,
            "xor" => *left ^ *right,
            "eqv" => left == right,
            "imp" => !*left || *right,
            _ => unreachable!(),
        };
        return Some(LiteralBranchValue::Boolean(result));
    }
    let left = numeric(left)?;
    let right = numeric(right)?;
    let result = match operator.as_str() {
        "=" => LiteralBranchValue::Boolean(left == right),
        "<>" => LiteralBranchValue::Boolean(left != right),
        "<" => LiteralBranchValue::Boolean(left < right),
        ">" => LiteralBranchValue::Boolean(left > right),
        "<=" => LiteralBranchValue::Boolean(left <= right),
        ">=" => LiteralBranchValue::Boolean(left >= right),
        "+" => small_integer_value(left.checked_add(right)?)?,
        "-" => small_integer_value(left.checked_sub(right)?)?,
        "*" => small_integer_value(left.checked_mul(right)?)?,
        "\\" if right != 0 && left % right == 0 => small_integer_value(left.checked_div(right)?)?,
        "mod" if left >= 0 && right > 0 => small_integer_value(left.checked_rem(right)?)?,
        "^" => {
            let exponent = u32::try_from(right).ok()?;
            small_integer_value(left.checked_pow(exponent)?)?
        }
        "and" => small_integer_value(left & right)?,
        "or" => small_integer_value(left | right)?,
        "xor" => small_integer_value(left ^ right)?,
        "eqv" => small_integer_value(!(left ^ right))?,
        "imp" => small_integer_value(!left | right)?,
        _ => return None,
    };
    Some(result)
}

fn compare_branch_strings(
    left: &str,
    right: &str,
    context: Option<ProcedurePathContext<'_>>,
) -> Option<std::cmp::Ordering> {
    if left == right {
        return Some(std::cmp::Ordering::Equal);
    }
    let module = context?.module;
    if !module.options.compare_valid || module.options.compare_mode != "Binary" {
        return None;
    }
    if !left.is_ascii() || !right.is_ascii() {
        return None;
    }
    Some(left.as_bytes().cmp(right.as_bytes()))
}

fn parse_branch_string_literal(text: &str) -> Option<String> {
    // The lexer stores string token contents without their surrounding quotes
    // and has already collapsed VBA's doubled-quote escape.
    if text.len() > MAX_BRANCH_STRING_BYTES {
        return None;
    }
    Some(text.to_owned())
}

fn ascii_numeric_string(value: &str) -> Option<bool> {
    if value.is_empty() {
        return Some(false);
    }
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit())
        .then_some(true)
}

fn parse_small_integer_literal(text: &str) -> Option<i64> {
    let value = text.trim().trim_end_matches(['%', '&', '^', '@', '!', '#']);
    if value.contains(['.', 'e', 'E', 'd', 'D'])
        || value.starts_with('&')
        || value.starts_with('+')
        || value.starts_with('-')
    {
        return None;
    }
    let value = value.parse().ok()?;
    (-32_768..=32_767).contains(&value).then_some(value)
}

fn small_integer_value(value: i64) -> Option<LiteralBranchValue> {
    (-32_768..=32_767)
        .contains(&value)
        .then_some(LiteralBranchValue::Integer(value))
}

pub fn decision_rows(graph: &ControlFlowGraph, paths: &[ControlFlowPath]) -> Vec<DecisionRow> {
    paths
        .iter()
        .map(|path| {
            let actions = path
                .nodes
                .iter()
                .filter_map(|id| graph.nodes.get(*id))
                .filter(|n| {
                    !matches!(
                        n.kind.as_str(),
                        "entry"
                            | "exit"
                            | "decision"
                            | "branch"
                            | "implicit_else"
                            | "loop_test"
                            | "for_repeat_test"
                            | "loop_body"
                            | "loop_exit"
                            | "case"
                            | "no_case_match"
                            | "label"
                    )
                })
                .map(|n| n.label.clone())
                .collect();
            DecisionRow {
                module: path.module.clone(),
                procedure: path.procedure.clone(),
                conditions: path.conditions.clone(),
                actions,
                outcome: path.stop_reason.clone(),
                feasibility: path.feasibility.clone(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        flow::build_graph,
        model::{Declaration, Limits, Module, Project},
        parser::parse_module,
    };

    #[test]
    fn qualified_constant_lookup_requires_one_module_and_one_constant() {
        let module = Module {
            name: "Provider".into(),
            declarations: vec![Declaration {
                name: "PrivateLimit".into(),
                kind: "constant".into(),
                visibility: "private".into(),
                ..Declaration::default()
            }],
            ..Module::default()
        };
        let project = Project {
            modules: vec![module.clone()],
            ..Project::default()
        };
        let fact = DataFlowFact {
            module: "Provider".into(),
            target: "PrivateLimit".into(),
            transfer: "constant_initializer".into(),
            ..DataFlowFact::default()
        };
        let sources = ConstantSourceIndex::new(&project, std::slice::from_ref(&fact));
        assert_eq!(sources.resolve_qualified("Provider.PrivateLimit"), Some(0));
        assert_eq!(sources.resolve_qualified("Provider.Missing"), None);
        assert_eq!(
            sources.resolve_qualified("Provider.PrivateLimit.Member"),
            None
        );

        let ambiguous_project = Project {
            modules: vec![module.clone(), module],
            ..Project::default()
        };
        let ambiguous = ConstantSourceIndex::new(&ambiguous_project, std::slice::from_ref(&fact));
        assert_eq!(ambiguous.resolve_qualified("Provider.PrivateLimit"), None);
    }

    #[test]
    fn enumerates_both_if_paths_and_marks_them_unproven() {
        let m = parse_module(
            "M",
            "M.bas",
            "Public Sub S()\nIf ready Then\nx = 1\nElse\nx = 0\nEnd If\nEnd Sub\n",
            1000,
            32,
        );
        let g = build_graph(&m, &m.procedures[0]);
        let paths = enumerate_control_flow_paths(&g, &Limits::default());
        assert_eq!(paths.len(), 2);
        assert!(
            paths
                .iter()
                .all(|p| p.feasibility == "not_checked" && p.stop_reason == "exit")
        );
        assert_eq!(decision_rows(&g, &paths).len(), 2);
    }

    #[test]
    fn marks_literal_false_condition_paths_infeasible_without_claiming_other_paths_feasible() {
        assert_eq!(
            evaluate_literal_branch_condition("(False) = True"),
            Some(false)
        );
        assert_eq!(
            evaluate_literal_branch_condition("(1 + 1 = 2) = True"),
            Some(true)
        );
        assert_eq!(
            evaluate_literal_branch_condition("(True < False) = True"),
            Some(true)
        );
        assert_eq!(
            evaluate_literal_branch_condition("(\"True\") = True"),
            Some(true)
        );
        assert_eq!(
            evaluate_literal_branch_condition("(\"False\") = True"),
            Some(false)
        );
        assert_eq!(
            evaluate_literal_branch_condition("(\"same\" = \"same\") = True"),
            Some(true)
        );
        assert_eq!(
            evaluate_literal_branch_condition("(\"A\" = \"a\") = True"),
            None
        );
        assert_eq!(
            evaluate_literal_branch_condition("(Null) = True"),
            Some(false)
        );
        assert_eq!(
            evaluate_literal_branch_condition("(Null) = False"),
            Some(true)
        );
        assert_eq!(
            evaluate_literal_branch_condition("(Null = True) = True"),
            Some(false)
        );
        for (predicate, expected) in [
            ("(Not Null) = True", Some(false)),
            ("(False And Null) = True", Some(false)),
            ("(True And Null) = True", Some(false)),
            ("(Null And False) = True", Some(false)),
            ("(Null Or True) = True", Some(true)),
            ("(Null Or False) = True", Some(false)),
            ("(False Xor Null) = True", Some(false)),
            ("(True Eqv Null) = True", Some(false)),
            ("(False Imp Null) = True", Some(true)),
            ("(Null Imp True) = True", Some(true)),
            ("(Null Imp False) = True", Some(false)),
        ] {
            assert_eq!(
                evaluate_literal_branch_condition(predicate),
                expected,
                "{predicate}"
            );
        }
        assert_eq!(evaluate_literal_branch_condition("ready = True"), None);

        let m = parse_module(
            "M",
            "M.bas",
            "Public Sub S()\nIf False Then\nx = 1\nElse\nx = 0\nEnd If\nIf 1 = 1 Then\ny = 1\nElse\ny = 0\nEnd If\nEnd Sub\n",
            1000,
            32,
        );
        let graph = build_graph(&m, &m.procedures[0]);
        let paths = enumerate_control_flow_paths(&graph, &Limits::default());
        assert_eq!(paths.len(), 4);
        assert_eq!(
            paths
                .iter()
                .filter(|path| path.feasibility == "infeasible_constant_condition")
                .count(),
            3
        );
        assert_eq!(
            paths
                .iter()
                .filter(|path| path.feasibility == "not_checked")
                .count(),
            1
        );
        assert!(paths.iter().all(|path| path.stop_reason == "exit"));
    }

    #[test]
    fn resolves_scoped_const_values_and_numeric_if_truth_without_resolving_shadowed_names() {
        assert_eq!(evaluate_literal_branch_condition("(1) = True"), Some(true));
        assert_eq!(evaluate_literal_branch_condition("(0) = False"), Some(true));
        assert_eq!(evaluate_literal_branch_condition("(0) = True"), Some(false));
        assert_eq!(
            evaluate_literal_branch_condition("Select Case 1 [predicate: (1) = (True)]"),
            Some(false)
        );
        assert_eq!(
            evaluate_literal_branch_condition("(1 = True) = True"),
            Some(false)
        );
        assert_eq!(
            evaluate_literal_branch_condition("(Not 0) = True"),
            Some(true)
        );
        assert_eq!(
            evaluate_literal_branch_condition("(3 And 1) = True"),
            Some(true)
        );
        assert_eq!(
            evaluate_literal_branch_condition("(2 And 4) = True"),
            Some(false)
        );

        let module = parse_module(
            "ConstPaths",
            "ConstPaths.bas",
            "Private Const DISABLED As Boolean = False\nPrivate Const ENABLED As Boolean = True\nPrivate Const MODULE_TARGET As Boolean = True\nPrivate Const FLAG_FROM_MODULE_SCOPE As Boolean = MODULE_TARGET\nPublic Sub ModuleConstant()\nIf DISABLED Then\nx = 1\nElse\nx = 0\nEnd If\nIf ENABLED Then\ny = 1\nElse\ny = 0\nEnd If\nEnd Sub\nPublic Sub LocalConstant()\nIf localDisabled Then\nx = 1\nElse\nx = 0\nEnd If\nConst localDisabled As Boolean = DISABLED\nEnd Sub\nPublic Sub ShadowedByVariable()\nDim DISABLED As Boolean\nIf DISABLED Then\nx = 1\nElse\nx = 0\nEnd If\nEnd Sub\nPublic Sub LocalCannotShadowInModuleInitializer()\nConst MODULE_TARGET As Boolean = False\nIf FLAG_FROM_MODULE_SCOPE Then\nx = 1\nElse\nx = 0\nEnd If\nEnd Sub\n",
            10_000,
            64,
        );

        let mut infeasible_by_procedure = HashMap::<String, usize>::new();
        let mut unchecked_by_procedure = HashMap::<String, usize>::new();
        for procedure in &module.procedures {
            let graph = build_graph(&module, procedure);
            let paths =
                enumerate_graph_paths_for_procedure(&graph, &module, procedure, &Limits::default());
            infeasible_by_procedure.insert(
                procedure.name.clone(),
                paths
                    .paths
                    .iter()
                    .filter(|path| path.feasibility == "infeasible_constant_condition")
                    .count(),
            );
            unchecked_by_procedure.insert(
                procedure.name.clone(),
                paths
                    .paths
                    .iter()
                    .filter(|path| path.feasibility == "not_checked")
                    .count(),
            );
        }
        assert_eq!(infeasible_by_procedure["ModuleConstant"], 3);
        assert_eq!(unchecked_by_procedure["ModuleConstant"], 1);
        assert_eq!(infeasible_by_procedure["LocalConstant"], 1);
        assert_eq!(unchecked_by_procedure["LocalConstant"], 1);
        assert_eq!(infeasible_by_procedure["ShadowedByVariable"], 0);
        assert_eq!(unchecked_by_procedure["ShadowedByVariable"], 2);
        assert_eq!(
            infeasible_by_procedure["LocalCannotShadowInModuleInitializer"],
            1
        );
        assert_eq!(
            unchecked_by_procedure["LocalCannotShadowInModuleInitializer"],
            1
        );
    }

    #[test]
    fn constant_cycles_and_ambiguous_module_constants_remain_unchecked() {
        let module = parse_module(
            "UnresolvedConstants",
            "UnresolvedConstants.bas",
            "Private Const FirstValue As Boolean = SecondValue\nPrivate Const SecondValue As Boolean = FirstValue\nPrivate Const DuplicateValue As Boolean = False\nPrivate Const DuplicateValue As Boolean = True\nPublic Sub S()\nIf FirstValue Then\nx = 1\nElse\nx = 0\nEnd If\nIf DuplicateValue Then\ny = 1\nElse\ny = 0\nEnd If\nEnd Sub\n",
            10_000,
            64,
        );
        let procedure = &module.procedures[0];
        let graph = build_graph(&module, procedure);
        let paths =
            enumerate_graph_paths_for_procedure(&graph, &module, procedure, &Limits::default());
        assert_eq!(paths.paths.len(), 4);
        assert!(
            paths
                .paths
                .iter()
                .all(|path| path.feasibility == "not_checked")
        );
    }

    #[test]
    fn marks_literal_and_variant_null_if_conditions_as_false() {
        let module = parse_module(
            "NullCondition",
            "NullCondition.bas",
            "Private Const NULL_FLAG As Variant = Null\nPublic Sub Check()\nIf Null Then\na = 1\nElse\na = 0\nEnd If\nIf NULL_FLAG Then\nb = 1\nElse\nb = 0\nEnd If\nIf Null = True Then\nc = 1\nElse\nc = 0\nEnd If\nIf 1 = Null Then\nd = 1\nElse\nd = 0\nEnd If\nIf False And Null Then\ne = 1\nElse\ne = 0\nEnd If\nIf Null Or True Then\nf = 1\nElse\nf = 0\nEnd If\nEnd Sub\n",
            10_000,
            64,
        );
        let procedure = &module.procedures[0];
        let graph = build_graph(&module, procedure);
        let paths =
            enumerate_graph_paths_for_procedure(&graph, &module, procedure, &Limits::default());
        assert_eq!(paths.paths.len(), 64);
        assert_eq!(
            paths
                .paths
                .iter()
                .filter(|path| path.feasibility == "infeasible_constant_condition")
                .count(),
            63
        );
        assert_eq!(
            paths
                .paths
                .iter()
                .filter(|path| path.feasibility == "not_checked")
                .count(),
            1
        );
    }

    #[test]
    fn marks_literal_select_case_alternatives_infeasible_when_the_selector_cannot_match() {
        let module = parse_module(
            "M",
            "M.bas",
            "Public Sub Choose()\nDim result As Long\nSelect Case 1\nCase 2\nresult = 2\nCase 1\nresult = 1\nCase Else\nresult = 0\nEnd Select\nEnd Sub\n",
            1000,
            32,
        );
        let graph = build_graph(&module, &module.procedures[0]);
        let paths = enumerate_control_flow_paths(&graph, &Limits::default());
        assert!(paths.iter().any(|path| {
            path.feasibility == "infeasible_constant_condition"
                && path
                    .conditions
                    .iter()
                    .any(|condition| condition.contains("matches Case 2"))
        }));
        assert!(paths.iter().any(|path| {
            path.feasibility == "not_checked"
                && path
                    .conditions
                    .iter()
                    .any(|condition| condition.contains("matches Case 1"))
        }));
        assert!(paths.iter().any(|path| {
            path.feasibility == "infeasible_constant_condition"
                && path
                    .conditions
                    .iter()
                    .any(|condition| condition.contains("does not match Case 1"))
        }));
    }

    #[test]
    fn marks_literal_while_and_do_loop_edges_infeasible() {
        let module = parse_module(
            "M",
            "M.bas",
            "Public Sub WhileTest()\nDim result As Long\nWhile False\nresult = 0\nWend\nEnd Sub\nPublic Sub PreTest()\nDim result As Long\nDo While False\nresult = 1\nLoop\nEnd Sub\nPublic Sub PostTest()\nDim result As Long\nDo\nresult = 2\nLoop Until True\nEnd Sub\n",
            1000,
            32,
        );
        let while_graph = build_graph(
            &module,
            module
                .procedures
                .iter()
                .find(|procedure| procedure.name == "WhileTest")
                .unwrap(),
        );
        let while_paths = enumerate_control_flow_paths(&while_graph, &Limits::default());
        assert!(
            while_paths.iter().any(|path| {
                path.feasibility == "infeasible_constant_condition"
                    && path
                        .conditions
                        .iter()
                        .any(|condition| condition.contains("(False) = True"))
            }),
            "{while_paths:#?}"
        );

        let pre_graph = build_graph(
            &module,
            module
                .procedures
                .iter()
                .find(|procedure| procedure.name == "PreTest")
                .unwrap(),
        );
        let pre_paths = enumerate_control_flow_paths(&pre_graph, &Limits::default());
        let pre_infeasible = pre_paths
            .iter()
            .filter(|path| path.feasibility == "infeasible_constant_condition")
            .collect::<Vec<_>>();
        assert!(!pre_infeasible.is_empty(), "{pre_paths:#?}");
        assert!(pre_infeasible.iter().all(|path| {
            path.conditions
                .iter()
                .any(|condition| condition.contains("[predicate:"))
        }));
        assert!(
            pre_paths
                .iter()
                .any(|path| path.feasibility == "not_checked")
        );

        let post_graph = build_graph(
            &module,
            module
                .procedures
                .iter()
                .find(|procedure| procedure.name == "PostTest")
                .unwrap(),
        );
        let post_paths = enumerate_control_flow_paths(&post_graph, &Limits::default());
        assert!(
            post_paths.iter().any(|path| {
                path.feasibility == "infeasible_constant_condition"
                    && path.conditions.iter().any(|condition| {
                        condition.contains("condition false")
                            && condition.contains("(True) = False")
                    })
            }),
            "{post_paths:#?}"
        );
        assert!(
            post_paths
                .iter()
                .any(|path| path.feasibility == "not_checked")
        );
    }

    #[test]
    fn marks_empty_literal_for_ranges_without_guessing_nonempty_loop_paths() {
        let module = parse_module(
            "M",
            "M.bas",
            "Public Sub EmptyForward()\nDim value As Long\nFor value = 5 To 1\nvalue = value + 1\nNext\nEnd Sub\nPublic Sub Descending()\nDim value As Long\nFor value = 5 To 1 Step -1\nvalue = value - 1\nNext\nEnd Sub\n",
            1000,
            32,
        );
        let empty_graph = build_graph(
            &module,
            module
                .procedures
                .iter()
                .find(|procedure| procedure.name == "EmptyForward")
                .unwrap(),
        );
        let empty_paths = enumerate_control_flow_paths(&empty_graph, &Limits::default());
        assert!(
            empty_paths.iter().any(|path| {
                path.feasibility == "infeasible_constant_condition"
                    && path
                        .conditions
                        .iter()
                        .any(|condition| condition.contains("For initial bounds enter body"))
            }),
            "{empty_paths:#?}"
        );
        assert!(
            empty_paths
                .iter()
                .any(|path| path.feasibility == "not_checked")
        );

        let descending_graph = build_graph(
            &module,
            module
                .procedures
                .iter()
                .find(|procedure| procedure.name == "Descending")
                .unwrap(),
        );
        let descending_paths = enumerate_control_flow_paths(&descending_graph, &Limits::default());
        assert!(
            descending_paths.iter().any(|path| {
                path.feasibility == "not_checked"
                    && path.nodes.iter().any(|node_id| {
                        descending_graph
                            .nodes
                            .get(*node_id)
                            .is_some_and(|node| node.kind == "loop_body")
                    })
            }),
            "{descending_paths:#?}"
        );
        assert!(
            descending_paths.iter().any(|path| {
                path.feasibility == "infeasible_constant_condition"
                    && path
                        .conditions
                        .iter()
                        .any(|condition| condition.contains("For initial bounds skip body"))
            }),
            "{descending_paths:#?}"
        );
    }

    #[test]
    fn bounds_loop_exploration() {
        let m = parse_module(
            "M",
            "M.bas",
            "Public Sub S()\nDo While x\nx = x + 1\nLoop\nEnd Sub\n",
            1000,
            32,
        );
        let g = build_graph(&m, &m.procedures[0]);
        let l = Limits {
            max_paths: 8,
            max_path_depth: 8,
            ..Limits::default()
        };
        let result = enumerate_graph_paths(&g, &l);
        assert!(result.paths.len() <= 8);
        assert!(result.paths.iter().any(|p| p.stop_reason == "cycle_pruned"));
        assert!(result.truncated);
    }
}
