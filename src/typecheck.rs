//! Conservative expression and assignment type propagation.

use crate::host::{HostProfile, excel};
use crate::lexer::{TokenKind, lex};
use crate::model::{
    Declaration, Diagnostic, Expr, LiteralKind, MemberAccessKind, Module, Parameter, Procedure,
    Project, Severity, Statement, TypeFact,
};

pub fn infer_assignment_types(project: &Project, host_profile: HostProfile) -> Vec<TypeFact> {
    let mut out = Vec::new();
    for (module_index, module) in project.modules.iter().enumerate() {
        for procedure in &module.procedures {
            visit_statements(
                project,
                module_index,
                module,
                procedure,
                &procedure.statements,
                host_profile,
                &mut out,
            );
        }
    }
    out
}

pub(crate) fn set_assignment_diagnostics(
    project: &Project,
    host_profile: HostProfile,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    for (module_index, module) in project.modules.iter().enumerate() {
        for procedure in &module.procedures {
            visit_set_assignment_diagnostics(
                project,
                module_index,
                module,
                procedure,
                &procedure.statements,
                host_profile,
                &mut diagnostics,
            );
        }
    }
    diagnostics
}

fn visit_set_assignment_diagnostics(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    statements: &[Statement],
    host_profile: HostProfile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for statement in statements {
        if statement.kind == "assignment"
            && let (Some(source), Some(target_expression), Some(value_expression)) = (
                statement.expression.as_deref(),
                statement.parsed_target.as_ref(),
                statement.parsed_expression.as_ref(),
            )
            && source
                .trim_start()
                .get(..3)
                .is_some_and(|keyword| keyword.eq_ignore_ascii_case("Set"))
            && source
                .trim_start()
                .get(3..)
                .and_then(|remainder| remainder.chars().next())
                .is_some_and(char::is_whitespace)
        {
            let target_source = source
                .split_once('=')
                .map(|(target, _)| target.trim().get(3..).unwrap_or("").trim().to_owned())
                .unwrap_or_default();
            let target_array = whole_array_info_for_expression(
                project,
                module_index,
                module,
                procedure,
                target_expression,
            );
            let target_type = infer_expr(
                project,
                module_index,
                module,
                procedure,
                target_expression,
                host_profile,
            );
            let value_array = whole_array_info_for_expression(
                project,
                module_index,
                module,
                procedure,
                value_expression,
            );
            let value_type = infer_expr(
                project,
                module_index,
                module,
                procedure,
                value_expression,
                host_profile,
            );
            let target_is_variant = canon(&target_type) == "variant";
            let target_is_object = is_object_declared_type(project, &target_type, host_profile);
            let target_is_known_non_object =
                user_type_owner_index(project, module_index, &target_type).is_some()
                    || known_non_udt_type(
                        project,
                        module_index,
                        module,
                        &target_type,
                        host_profile,
                    );

            let invalid_target = target_array.is_some()
                || (!target_is_variant && !target_is_object && target_is_known_non_object);
            let value_may_be_an_object =
                crate::typecheck::is_explicit_nothing_expression(value_expression)
                    || canon(&value_type) == "variant"
                    || value_type.starts_with("host-dependent")
                    || is_object_declared_type(project, &value_type, host_profile);
            let value_is_known_non_object = value_array.is_some()
                || user_type_owner_index(project, module_index, &value_type).is_some()
                || known_non_udt_type(project, module_index, module, &value_type, host_profile);
            let invalid_value =
                !invalid_target && !value_may_be_an_object && value_is_known_non_object;

            if invalid_target || invalid_value {
                diagnostics.push(Diagnostic {
                    code: "VBA2134",
                    severity: Severity::Error,
                    message: if invalid_target {
                        format!(
                            "Set assignment target '{}' has known non-object declared type {}; the target must be an object, class, or Variant",
                            target_source, target_type
                        )
                    } else {
                        format!(
                            "Set assignment value has known non-object type {} for object target '{}'",
                            value_type, target_source
                        )
                    },
                    source: module.source_name.clone(),
                    span: statement.span,
                });
            }
        }
        visit_set_assignment_diagnostics(
            project,
            module_index,
            module,
            procedure,
            &statement.children,
            host_profile,
            diagnostics,
        );
    }
}

pub(crate) fn array_index_diagnostics(project: &Project) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    for (module_index, module) in project.modules.iter().enumerate() {
        for procedure in &module.procedures {
            visit_array_index_diagnostics(
                project,
                module_index,
                module,
                procedure,
                &procedure.statements,
                &mut diagnostics,
            );
        }
    }
    diagnostics
}

pub(crate) fn with_expression_diagnostics(
    project: &Project,
    host_profile: HostProfile,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    for (module_index, module) in project.modules.iter().enumerate() {
        for procedure in &module.procedures {
            visit_with_expression_diagnostics(
                project,
                module_index,
                module,
                procedure,
                &procedure.statements,
                host_profile,
                &mut diagnostics,
            );
        }
    }
    diagnostics
}

fn visit_with_expression_diagnostics(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    statements: &[Statement],
    host_profile: HostProfile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for statement in statements {
        if statement.kind == "with"
            && let Some(expression) = &statement.parsed_expression
        {
            let type_name = infer_expr(
                project,
                module_index,
                module,
                procedure,
                expression,
                host_profile,
            );
            if with_type_validity(project, module_index, &type_name) == Some(false) {
                diagnostics.push(Diagnostic {
                    code: "VBA1039",
                    severity: Severity::Error,
                    message: format!(
                        "With expression has declared type '{}'; it must be a UDT, class, Object, or Variant",
                        type_name
                    ),
                    source: module.source_name.clone(),
                    span: statement.span,
                });
            }
        }
        visit_with_expression_diagnostics(
            project,
            module_index,
            module,
            procedure,
            &statement.children,
            host_profile,
            diagnostics,
        );
    }
}

fn with_type_validity(project: &Project, module_index: usize, type_name: &str) -> Option<bool> {
    let key = canon(
        type_name
            .trim()
            .trim_start_matches("New ")
            .trim_end_matches("()"),
    );
    if key == "object" || key == "variant" {
        return Some(true);
    }
    if key.starts_with("host-dependent") || key.starts_with("array<") {
        return None;
    }
    if is_string_type(&key)
        || matches!(
            key.as_str(),
            "boolean"
                | "byte"
                | "integer"
                | "long"
                | "longlong"
                | "longptr"
                | "single"
                | "double"
                | "currency"
                | "decimal"
                | "date"
                | "error"
        )
    {
        return Some(false);
    }
    if user_type_owner_index(project, module_index, &key).is_some() {
        return Some(true);
    }
    if project.modules.iter().any(|candidate| {
        canon(&candidate.name) == key
            && matches!(
                candidate.module_kind.as_deref(),
                Some(
                    "class"
                        | "form"
                        | "workbook_document"
                        | "worksheet_document"
                        | "class_or_document"
                        | "document_or_class"
                )
            )
    }) {
        return Some(true);
    }
    None
}

fn visit_array_index_diagnostics(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    statements: &[Statement],
    diagnostics: &mut Vec<Diagnostic>,
) {
    for statement in statements {
        if matches!(statement.kind.as_str(), "for" | "for_each") {
            validate_loop_statement(
                project,
                module_index,
                module,
                procedure,
                statement,
                diagnostics,
            );
        }
        if let Some(target) = &statement.parsed_target {
            inspect_array_index_expression(
                project,
                module_index,
                module,
                procedure,
                target,
                diagnostics,
            );
        }
        if let Some(expression) = &statement.parsed_expression {
            inspect_array_index_expression(
                project,
                module_index,
                module,
                procedure,
                expression,
                diagnostics,
            );
        }
        visit_array_index_diagnostics(
            project,
            module_index,
            module,
            procedure,
            &statement.children,
            diagnostics,
        );
    }
}

fn validate_loop_statement(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    statement: &Statement,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if let (Some(control), Some(next)) = (
        statement.loop_control_variable.as_deref(),
        statement.next_control_variable.as_deref(),
    ) && let (Some(control_key), Some(next_key)) = (
        canonical_loop_variable(control),
        canonical_loop_variable(next),
    ) && control_key != next_key
    {
        diagnostics.push(Diagnostic {
            code: "VBA2091",
            severity: Severity::Error,
            message: format!(
                "loop control variable '{}' does not match Next variable '{}'",
                control, next
            ),
            source: module.source_name.clone(),
            span: statement.span,
        });
    }

    if statement.kind == "for" {
        let Some(control) = statement.loop_control_variable.as_deref() else {
            return;
        };
        let Some(control_expression) = crate::parser::parse_expression_source(control) else {
            return;
        };
        let control_type = infer_expr(
            project,
            module_index,
            module,
            procedure,
            &control_expression,
            HostProfile::Unknown,
        );
        let array_element = is_array_element_expression(
            project,
            module_index,
            module,
            procedure,
            &control_expression,
        );
        if array_element
            || for_counter_type_validity(project, module_index, &control_type) == Some(false)
        {
            diagnostics.push(Diagnostic {
                code: "VBA2094",
                severity: Severity::Error,
                message: if array_element {
                    format!("For counter '{}' cannot be an array element", control)
                } else {
                    format!(
                        "For counter '{}' has declared type '{}'; a For counter must be numeric or Variant",
                        control, control_type
                    )
                },
                source: module.source_name.clone(),
                span: statement.span,
            });
        }
        for (label, expression) in [
            ("start", statement.parsed_loop_start.as_ref()),
            ("end", statement.parsed_loop_end.as_ref()),
            ("Step", statement.parsed_loop_step.as_ref()),
        ] {
            let Some(expression) = expression else {
                continue;
            };
            if string_literal_let_coercion_error_13(expression, "Double") {
                diagnostics.push(Diagnostic {
                    code: "VBA2135",
                    severity: Severity::Warning,
                    message: format!(
                        "For {label} string literal can raise runtime error 13 when converted to Double"
                    ),
                    source: module.source_name.clone(),
                    span: expression.span(),
                });
                continue;
            }
            if for_bound_coercion_validity(project, module_index, module, procedure, expression)
                == Some(false)
            {
                diagnostics.push(Diagnostic {
                    code: "VBA2095",
                    severity: Severity::Error,
                    message: format!(
                        "For {label} value has declared type '{}' that cannot be Let-coerced to Double",
                        infer_expr(
                            project,
                            module_index,
                            module,
                            procedure,
                            expression,
                            HostProfile::Unknown,
                        )
                    ),
                    source: module.source_name.clone(),
                    span: expression.span(),
                });
            }
        }
        return;
    }

    let (Some(control), Some(collection)) = (
        statement.loop_control_variable.as_deref(),
        statement.parsed_expression.as_ref(),
    ) else {
        return;
    };
    let Some(control_expression) = crate::parser::parse_expression_source(control) else {
        return;
    };
    let Some(array) =
        array_info_for_expression(project, module_index, module, procedure, collection)
    else {
        return;
    };
    let control_type = infer_expr(
        project,
        module_index,
        module,
        procedure,
        &control_expression,
        HostProfile::Unknown,
    );
    if !control_type.eq_ignore_ascii_case("Variant") && !control_type.starts_with("host-dependent")
    {
        diagnostics.push(Diagnostic {
            code: "VBA2092",
            severity: Severity::Error,
            message: format!(
                "For Each control variable '{}' has declared type '{}'; iterating a declared array requires Variant",
                control, control_type
            ),
            source: module.source_name.clone(),
            span: statement.span,
        });
    }
    if user_type_owner_index(project, module_index, &array.element_type).is_some() {
        diagnostics.push(Diagnostic {
            code: "VBA2093",
            severity: Severity::Error,
            message: format!(
                "For Each cannot iterate array '{}' with user-defined type elements",
                statement.expression.as_deref().unwrap_or("<expression>")
            ),
            source: module.source_name.clone(),
            span: statement.span,
        });
    }
}

fn is_array_element_expression(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    expression: &Expr,
) -> bool {
    match expression {
        Expr::Call { callee, args, .. } if !args.is_empty() => match callee.as_ref() {
            Expr::Identifier(name, _) => {
                array_symbol_info(project, module_index, module, procedure, name).is_some()
            }
            Expr::Member {
                object,
                member,
                access: MemberAccessKind::Dot,
                ..
            } => member_array_symbol_info(project, module_index, module, procedure, object, member)
                .is_some(),
            _ => false,
        },
        Expr::Group(value, _) => {
            is_array_element_expression(project, module_index, module, procedure, value)
        }
        _ => false,
    }
}

fn for_counter_type_validity(
    project: &Project,
    module_index: usize,
    type_name: &str,
) -> Option<bool> {
    let key = canon(type_name.trim());
    if key == "variant" {
        return Some(true);
    }
    if matches!(
        key.as_str(),
        "byte" | "integer" | "long" | "longlong" | "longptr" | "single" | "double" | "currency"
    ) {
        return Some(true);
    }
    if matches!(key.as_str(), "boolean" | "date" | "object")
        || key == "string"
        || key.starts_with("string *")
        || key.starts_with("array<")
        || user_type_owner_index(project, module_index, &key).is_some()
        || project.modules.iter().any(|module| {
            canon(&module.name) == key
                && matches!(
                    module.module_kind.as_deref(),
                    Some(
                        "class"
                            | "form"
                            | "workbook_document"
                            | "worksheet_document"
                            | "class_or_document"
                            | "document_or_class"
                    )
                )
        })
    {
        return Some(false);
    }
    None
}

fn for_bound_coercion_validity(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    expression: &Expr,
) -> Option<bool> {
    if is_explicit_nothing_expression(expression) {
        return Some(false);
    }
    let type_name = infer_expr(
        project,
        module_index,
        module,
        procedure,
        expression,
        HostProfile::Unknown,
    );
    let key = canon(type_name.trim());
    if key == "variant"
        || matches!(
            key.as_str(),
            "byte"
                | "integer"
                | "long"
                | "single"
                | "double"
                | "currency"
                | "boolean"
                | "date"
                | "string"
        )
        || key.starts_with("string *")
    {
        return Some(true);
    }
    if key == "longlong" {
        return Some(false);
    }
    if key.starts_with("array<") || user_type_owner_index(project, module_index, &key).is_some() {
        return Some(false);
    }
    None
}

pub(crate) fn is_explicit_nothing_expression(expression: &Expr) -> bool {
    match expression {
        Expr::Identifier(name, _) => name.eq_ignore_ascii_case("Nothing"),
        Expr::Group(inner, _) => is_explicit_nothing_expression(inner),
        _ => false,
    }
}

pub(crate) fn is_explicit_null_expression(expression: &Expr) -> bool {
    match expression {
        Expr::Identifier(name, _) => name.eq_ignore_ascii_case("Null"),
        Expr::Group(inner, _) => is_explicit_null_expression(inner),
        _ => false,
    }
}

/// Whether a direct ASCII String literal has no digits and therefore cannot
/// supply the numeric or currency component of a documented numeric
/// Let-coercion. Locale and punctuation-sensitive cases remain unresolved.
pub(crate) fn string_literal_let_coercion_error_13(expression: &Expr, target_type: &str) -> bool {
    let target = normalized_type(target_type);
    let target_is_boolean = target == "boolean";
    if !target_is_boolean
        && !matches!(
            target.as_str(),
            "byte" | "integer" | "long" | "longlong" | "longptr" | "single" | "double" | "currency"
        )
    {
        return false;
    }
    let Some(value) = string_literal_contents(expression) else {
        return false;
    };
    if target_is_boolean
        && (value.eq_ignore_ascii_case("True")
            || value.eq_ignore_ascii_case("False")
            || value == "#TRUE#"
            || value == "#FALSE#")
    {
        return false;
    }
    if !value.is_ascii() {
        return false;
    }
    !value.bytes().any(|byte| byte.is_ascii_digit())
}

fn string_literal_contents(expression: &Expr) -> Option<String> {
    match expression {
        Expr::Group(value, _) => string_literal_contents(value),
        // The lexer stores decoded string contents without the delimiters.
        Expr::Literal(value, LiteralKind::String, _) => Some(value.clone()),
        _ => None,
    }
}

fn canonical_loop_variable(source: &str) -> Option<String> {
    let (tokens, _) = lex(source, 32);
    let tokens = tokens
        .into_iter()
        .filter(|token| !matches!(token.kind, TokenKind::Newline | TokenKind::Eof))
        .collect::<Vec<_>>();
    let mut output = String::new();
    let mut expect_identifier = true;
    for token in tokens {
        if expect_identifier && token.kind == TokenKind::Identifier {
            output.push_str(&canon(&token.text));
            expect_identifier = false;
        } else if !expect_identifier && token.kind == TokenKind::Symbol && token.text == "." {
            output.push('.');
            expect_identifier = true;
        } else {
            return None;
        }
    }
    (!output.is_empty() && !expect_identifier).then_some(output)
}

fn inspect_array_index_expression(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    expression: &Expr,
    diagnostics: &mut Vec<Diagnostic>,
) {
    match expression {
        Expr::Call { callee, args, span } => {
            validate_variant_query_intrinsic_call(
                project,
                module_index,
                module,
                procedure,
                expression,
                diagnostics,
            );
            validate_array_bound_intrinsic_call(
                project,
                module_index,
                module,
                procedure,
                expression,
                diagnostics,
            );
            let array_target = match callee.as_ref() {
                Expr::Identifier(name, _) => {
                    array_symbol_info(project, module_index, module, procedure, name)
                        .map(|info| (name.clone(), info))
                }
                Expr::Member {
                    object,
                    member,
                    access: MemberAccessKind::Dot,
                    ..
                } => member_array_symbol_info(
                    project,
                    module_index,
                    module,
                    procedure,
                    object,
                    member,
                )
                .map(|info| (member.clone(), info)),
                _ => None,
            };
            if let Some((name, info)) = array_target
                && !args.is_empty()
            {
                let has_named_argument = args
                    .iter()
                    .any(|argument| matches!(argument, Expr::NamedArgument { .. }));
                let rank_mismatch = info.rank.is_some_and(|rank| rank != args.len());
                if has_named_argument || rank_mismatch {
                    let reason = if has_named_argument {
                        "array indices cannot use named arguments".to_string()
                    } else {
                        format!(
                            "array '{}' has rank {} but this index expression supplies {} arguments",
                            name,
                            info.rank.unwrap_or_default(),
                            args.len()
                        )
                    };
                    diagnostics.push(Diagnostic {
                        code: "VBA2087",
                        severity: Severity::Error,
                        message: reason,
                        source: module.source_name.clone(),
                        span: *span,
                    });
                }
            }
            inspect_array_index_expression(
                project,
                module_index,
                module,
                procedure,
                callee,
                diagnostics,
            );
            for argument in args {
                inspect_array_index_expression(
                    project,
                    module_index,
                    module,
                    procedure,
                    argument,
                    diagnostics,
                );
            }
        }
        Expr::Unary { value, .. } | Expr::Group(value, _) => inspect_array_index_expression(
            project,
            module_index,
            module,
            procedure,
            value,
            diagnostics,
        ),
        Expr::TypeOfIs { expression, .. } => inspect_array_index_expression(
            project,
            module_index,
            module,
            procedure,
            expression,
            diagnostics,
        ),
        Expr::Binary { left, right, .. } => {
            inspect_array_index_expression(
                project,
                module_index,
                module,
                procedure,
                left,
                diagnostics,
            );
            inspect_array_index_expression(
                project,
                module_index,
                module,
                procedure,
                right,
                diagnostics,
            );
        }
        Expr::Member { object, .. } | Expr::NamedArgument { value: object, .. } => {
            inspect_array_index_expression(
                project,
                module_index,
                module,
                procedure,
                object,
                diagnostics,
            );
        }
        Expr::Identifier(..) | Expr::Literal(..) | Expr::Unknown(..) => {}
    }
}

fn validate_variant_query_intrinsic_call(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    expression: &Expr,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Expr::Call { callee, args, span } = expression else {
        return;
    };
    let Expr::Identifier(name, _) = callee.as_ref() else {
        return;
    };
    let name = canon(name);
    if name == "replace" {
        if project_may_shadow_type_intrinsic(project, module_index, module, procedure, &name)
            || (3..=6).contains(&args.len())
        {
            return;
        }
        diagnostics.push(Diagnostic {
            code: "VBA2148",
            severity: Severity::Error,
            message: "Replace expects three to six arguments".into(),
            source: module.source_name.clone(),
            span: *span,
        });
        return;
    }
    if matches!(name.as_str(), "trim" | "ltrim" | "rtrim") {
        if project_may_shadow_type_intrinsic(project, module_index, module, procedure, &name)
            || args.len() == 1
        {
            return;
        }
        let display_name = match name.as_str() {
            "trim" => "Trim",
            "ltrim" => "LTrim",
            "rtrim" => "RTrim",
            _ => unreachable!(),
        };
        diagnostics.push(Diagnostic {
            code: "VBA2148",
            severity: Severity::Error,
            message: format!("{display_name} expects exactly one argument"),
            source: module.source_name.clone(),
            span: *span,
        });
        return;
    }
    if matches!(name.as_str(), "left" | "right" | "mid") {
        let valid_arity = match name.as_str() {
            "left" | "right" => args.len() == 2,
            "mid" => (2..=3).contains(&args.len()),
            _ => unreachable!(),
        };
        if project_may_shadow_type_intrinsic(project, module_index, module, procedure, &name)
            || valid_arity
        {
            return;
        }
        let display_name = match name.as_str() {
            "left" => "Left",
            "right" => "Right",
            "mid" => "Mid",
            _ => unreachable!(),
        };
        let expected = if name == "mid" {
            "two or three arguments"
        } else {
            "exactly two arguments"
        };
        diagnostics.push(Diagnostic {
            code: "VBA2148",
            severity: Severity::Error,
            message: format!("{display_name} expects {expected}"),
            source: module.source_name.clone(),
            span: *span,
        });
        return;
    }
    if matches!(name.as_str(), "instr" | "instrrev") {
        if project_may_shadow_type_intrinsic(project, module_index, module, procedure, &name)
            || (2..=4).contains(&args.len())
        {
            return;
        }
        let display_name = if name == "instr" { "InStr" } else { "InStrRev" };
        diagnostics.push(Diagnostic {
            code: "VBA2148",
            severity: Severity::Error,
            message: format!("{display_name} expects two to four arguments"),
            source: module.source_name.clone(),
            span: *span,
        });
        return;
    }
    if !matches!(
        name.as_str(),
        "isempty"
            | "isnull"
            | "iserror"
            | "ismissing"
            | "isarray"
            | "isnumeric"
            | "isobject"
            | "isdate"
            | "vartype"
            | "typename"
            | "cdec"
            | "cverr"
            | "len"
            | "lenb"
    ) || project_may_shadow_intrinsic(project, module_index, module, procedure, &name)
        || args.len() == 1
    {
        return;
    }
    let display_name = match name.as_str() {
        "isempty" => "IsEmpty",
        "isnull" => "IsNull",
        "iserror" => "IsError",
        "ismissing" => "IsMissing",
        "isarray" => "IsArray",
        "isobject" => "IsObject",
        "isdate" => "IsDate",
        "vartype" => "VarType",
        "typename" => "TypeName",
        "cdec" => "CDec",
        "cverr" => "CVErr",
        "len" => "Len",
        "lenb" => "LenB",
        _ => "IsNumeric",
    };
    diagnostics.push(Diagnostic {
        code: "VBA2148",
        severity: Severity::Error,
        message: format!("{display_name} expects exactly one argument"),
        source: module.source_name.clone(),
        span: *span,
    });
}

fn validate_array_bound_intrinsic_call(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    expression: &Expr,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Expr::Call { callee, args, span } = expression else {
        return;
    };
    let Expr::Identifier(intrinsic, _) = callee.as_ref() else {
        return;
    };
    let intrinsic = canon(intrinsic);
    if !matches!(intrinsic.as_str(), "lbound" | "ubound") {
        return;
    }
    if project_may_shadow_intrinsic(project, module_index, module, procedure, &intrinsic) {
        return;
    }
    let intrinsic_name = if intrinsic == "lbound" {
        "LBound"
    } else {
        "UBound"
    };
    if !(1..=2).contains(&args.len()) {
        diagnostics.push(Diagnostic {
            code: "VBA2088",
            severity: Severity::Error,
            message: format!(
                "{intrinsic_name} expects an array and an optional dimension argument"
            ),
            source: module.source_name.clone(),
            span: *span,
        });
        return;
    }
    if args
        .iter()
        .any(|argument| matches!(argument, Expr::NamedArgument { .. }))
    {
        return;
    }
    let array_argument = &args[0];
    if let Some(info) =
        array_info_for_expression(project, module_index, module, procedure, array_argument)
    {
        let dimension = args.get(1).map(known_integer_argument).unwrap_or(Some(1));
        if let (Some(rank), Some(dimension)) = (info.rank, dimension)
            && !(1..=rank as i64).contains(&dimension)
        {
            let name = simple_array_expression_name(array_argument)
                .unwrap_or_else(|| "array expression".into());
            diagnostics.push(Diagnostic {
                code: "VBA2089",
                severity: Severity::Warning,
                message: format!(
                    "{intrinsic_name} dimension {dimension} is outside the statically known rank {rank} of '{name}'; this call would raise run-time error 9 if reached"
                ),
                source: module.source_name.clone(),
                span: *span,
            });
        }
        return;
    }

    let argument_type = infer_expr(
        project,
        module_index,
        module,
        procedure,
        array_argument,
        HostProfile::Unknown,
    );
    let possibly_array = argument_type.eq_ignore_ascii_case("Variant")
        || argument_type.eq_ignore_ascii_case("Object")
        || argument_type.starts_with("host-dependent")
        || argument_type.starts_with("Array<");
    if !possibly_array {
        diagnostics.push(Diagnostic {
            code: "VBA2090",
            severity: Severity::Warning,
            message: format!(
                "{intrinsic_name} argument has statically known non-array type '{argument_type}'; this call would fail at run time if reached"
            ),
            source: module.source_name.clone(),
            span: array_argument.span(),
        });
    }
}

pub(crate) fn project_may_shadow_intrinsic(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    name: &str,
) -> bool {
    procedure.name.eq_ignore_ascii_case(name)
        || procedure
            .parameters
            .iter()
            .any(|parameter| canon(&parameter.name) == name)
        || find_local(&procedure.statements, name).is_some()
        || module
            .procedures
            .iter()
            .any(|candidate| canon(&candidate.name) == name)
        || module
            .declarations
            .iter()
            .any(|declaration| canon(&declaration.name) == name)
        || project
            .modules
            .iter()
            .enumerate()
            .filter(|(index, candidate)| {
                *index != module_index
                    && matches!(candidate.module_kind.as_deref(), Some("standard") | None)
            })
            .any(|(_, candidate)| {
                candidate.procedures.iter().any(|procedure| {
                    canon(&procedure.name) == name
                        && (procedure.visibility.eq_ignore_ascii_case("public")
                            || procedure.visibility.eq_ignore_ascii_case("global"))
                }) || candidate.declarations.iter().any(|declaration| {
                    canon(&declaration.name) == name
                        && (declaration.visibility.eq_ignore_ascii_case("public")
                            || declaration.visibility.eq_ignore_ascii_case("global"))
                })
            })
}

fn array_info_for_expression(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    expression: &Expr,
) -> Option<ArraySymbolInfo> {
    match expression {
        Expr::Identifier(name, _) => {
            array_symbol_info(project, module_index, module, procedure, name)
        }
        Expr::Member {
            object,
            member,
            access: MemberAccessKind::Dot,
            ..
        } => member_array_symbol_info(project, module_index, module, procedure, object, member),
        Expr::Member { .. } => None,
        Expr::Group(value, _) => {
            array_info_for_expression(project, module_index, module, procedure, value)
        }
        _ => None,
    }
}

/// Return a Boolean only when the declaration proves the expression's array
/// shape. Variant/object payloads and unresolved members retain runtime state.
pub(crate) fn known_is_array_value(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    expression: &Expr,
) -> Option<bool> {
    if array_info_for_expression(project, module_index, module, procedure, expression).is_some() {
        return Some(true);
    }
    if let Expr::Call { callee, args, .. } = expression
        && let Expr::Identifier(name, _) = callee.as_ref()
        && canon(name) == "array"
        && !args
            .iter()
            .any(|argument| matches!(argument, Expr::NamedArgument { .. }))
        && !project_may_shadow_type_intrinsic(project, module_index, module, procedure, "array")
    {
        return Some(true);
    }
    let Expr::Identifier(name, _) = expression else {
        return None;
    };
    let type_name =
        declared_symbol_type(project, module_index, module, Some(&procedure.name), name)?;
    let effective_type = effective_project_type_name(project, module_index, module, &type_name);
    let key = normalized_type(&effective_type);
    if matches!(key.as_str(), "variant" | "object")
        || key.starts_with("host-dependent")
        || class_type_owner_index(project, &effective_type).is_some()
    {
        return None;
    }
    matches!(
        key.as_str(),
        "boolean"
            | "byte"
            | "integer"
            | "long"
            | "longlong"
            | "longptr"
            | "single"
            | "double"
            | "currency"
            | "date"
            | "string"
            | "error"
    )
    .then_some(false)
}

/// Return a Boolean only for statically known object or scalar expressions;
/// Variant values and external/default-member behavior remain unresolved.
pub(crate) fn known_is_object_value(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    expression: &Expr,
) -> Option<bool> {
    match expression {
        Expr::Group(value, _) => {
            return known_is_object_value(project, module_index, module, procedure, value);
        }
        Expr::Identifier(name, _) if name.eq_ignore_ascii_case("Nothing") => return Some(true),
        Expr::Identifier(name, _)
            if name.eq_ignore_ascii_case("Null")
                || name.eq_ignore_ascii_case("Empty")
                || name.eq_ignore_ascii_case("True")
                || name.eq_ignore_ascii_case("False") =>
        {
            return Some(false);
        }
        Expr::Literal(_, LiteralKind::Number | LiteralKind::String | LiteralKind::Date, _) => {
            return Some(false);
        }
        Expr::Identifier(..) => {}
        _ => return None,
    }

    if array_info_for_expression(project, module_index, module, procedure, expression).is_some() {
        return None;
    }
    let Expr::Identifier(name, _) = expression else {
        return None;
    };
    let type_name =
        declared_symbol_type(project, module_index, module, Some(&procedure.name), name)?;
    let effective_type = effective_project_type_name(project, module_index, module, &type_name);
    if is_object_declared_type(project, &effective_type, HostProfile::Unknown) {
        return Some(true);
    }
    let key = normalized_type(&effective_type);
    if key == "variant" || key.starts_with("host-dependent") {
        return None;
    }
    matches!(
        key.as_str(),
        "boolean"
            | "byte"
            | "integer"
            | "long"
            | "longlong"
            | "longptr"
            | "single"
            | "double"
            | "currency"
            | "date"
            | "string"
            | "error"
    )
    .then_some(false)
}

/// Return true only when the argument is statically known to contain a Date
/// value. String recognition and Variant coercion depend on runtime context
/// and are deliberately left unresolved.
pub(crate) fn known_is_date_value(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    expression: &Expr,
) -> Option<bool> {
    match expression {
        Expr::Group(value, _) => {
            return known_is_date_value(project, module_index, module, procedure, value);
        }
        Expr::Literal(_, LiteralKind::Date, _) => return Some(true),
        Expr::Identifier(name, _) => {
            let intrinsic = name.to_ascii_lowercase();
            if matches!(intrinsic.as_str(), "date" | "now" | "time")
                && !project_may_shadow_date_intrinsic(
                    project,
                    module_index,
                    module,
                    procedure,
                    &intrinsic,
                )
            {
                return Some(true);
            }
        }
        _ => {}
    }

    let inferred_type = infer_expr(
        project,
        module_index,
        module,
        procedure,
        expression,
        HostProfile::Unknown,
    );
    if normalized_type(&inferred_type) == "date" {
        return Some(true);
    }

    let Expr::Call { callee, args, .. } = expression else {
        return None;
    };
    let Expr::Identifier(name, _) = callee.as_ref() else {
        return None;
    };
    let intrinsic = name.to_ascii_lowercase();
    if project_may_shadow_date_intrinsic(project, module_index, module, procedure, &intrinsic)
        || args
            .iter()
            .any(|argument| matches!(argument, Expr::NamedArgument { .. }))
    {
        return None;
    }
    let argument_type = |index: usize| {
        args.get(index).map(|argument| {
            normalized_type(&infer_expr(
                project,
                module_index,
                module,
                procedure,
                argument,
                HostProfile::Unknown,
            ))
        })
    };
    let returns_date = match intrinsic.as_str() {
        "date" | "now" | "time" => args.is_empty(),
        "dateserial" | "timeserial" => {
            args.len() == 3
                && (0..3).all(|index| {
                    argument_type(index)
                        .is_some_and(|type_name| is_known_date_numeric_type(&type_name))
                })
        }
        "datevalue" | "timevalue" => {
            args.len() == 1
                && argument_type(0)
                    .is_some_and(|type_name| is_known_date_or_string_type(&type_name))
        }
        "dateadd" => {
            args.len() == 3
                && argument_type(0).is_some_and(|type_name| is_known_string_type(&type_name))
                && argument_type(1).is_some_and(|type_name| is_known_date_numeric_type(&type_name))
                && argument_type(2)
                    .is_some_and(|type_name| is_known_date_or_string_type(&type_name))
        }
        "cvdate" => {
            args.len() == 1
                && argument_type(0)
                    .is_some_and(|type_name| is_known_date_conversion_type(&type_name))
        }
        _ => false,
    };
    returns_date.then_some(true)
}

fn is_known_string_type(type_name: &str) -> bool {
    type_name == "string" || type_name.starts_with("string*")
}

fn is_known_date_or_string_type(type_name: &str) -> bool {
    type_name == "date" || is_known_string_type(type_name)
}

fn is_known_date_numeric_type(type_name: &str) -> bool {
    matches!(
        type_name,
        "boolean"
            | "byte"
            | "integer"
            | "long"
            | "longlong"
            | "longptr"
            | "single"
            | "double"
            | "currency"
    )
}

fn is_known_date_conversion_type(type_name: &str) -> bool {
    is_known_date_or_string_type(type_name) || is_known_date_numeric_type(type_name)
}

/// Return the VBA `VarType` code only when the expression's value subtype is
/// fixed by syntax or a resolved declaration. Variant payloads and object
/// default-property results remain unknown.
pub(crate) fn known_vartype_value(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    expression: &Expr,
) -> Option<i64> {
    match expression {
        Expr::Group(value, _) => {
            return known_vartype_value(project, module_index, module, procedure, value);
        }
        Expr::Identifier(name, _) if name.eq_ignore_ascii_case("Empty") => return Some(0),
        Expr::Identifier(name, _) if name.eq_ignore_ascii_case("Null") => return Some(1),
        Expr::Identifier(name, _)
            if name.eq_ignore_ascii_case("True") || name.eq_ignore_ascii_case("False") =>
        {
            return Some(11);
        }
        Expr::Literal(_, LiteralKind::String, _) => return Some(8),
        Expr::Literal(_, LiteralKind::Date, _) => return Some(7),
        _ => {}
    }

    if known_is_date_value(project, module_index, module, procedure, expression) == Some(true) {
        return Some(7);
    }

    if let Some(info) =
        array_info_for_expression(project, module_index, module, procedure, expression)
    {
        let element_code =
            vartype_code_for_array_element(project, module_index, module, &info.element_type)?;
        return Some(8192 + element_code);
    }

    if let Expr::Call { callee, args, .. } = expression
        && let Expr::Identifier(name, _) = callee.as_ref()
        && canon(name) == "array"
        && !args
            .iter()
            .any(|argument| matches!(argument, Expr::NamedArgument { .. }))
        && !project_may_shadow_type_intrinsic(project, module_index, module, procedure, "array")
    {
        return Some(8204);
    }

    if let Expr::Call { callee, args, .. } = expression
        && let Expr::Identifier(name, _) = callee.as_ref()
        && canon(name) == "cverr"
        && args.len() == 1
        && !project_may_shadow_type_intrinsic(project, module_index, module, procedure, "cverr")
    {
        return Some(10);
    }

    if let Expr::Call { callee, args, .. } = expression
        && let Expr::Identifier(name, _) = callee.as_ref()
        && canon(name) == "cdec"
        && args.len() == 1
        && !project_may_shadow_type_intrinsic(project, module_index, module, procedure, "cdec")
    {
        return Some(14);
    }

    let inferred_type = infer_expr(
        project,
        module_index,
        module,
        procedure,
        expression,
        HostProfile::Unknown,
    );
    vartype_code_for_scalar_type(project, module_index, &inferred_type)
}

pub(crate) fn known_is_error_value(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    expression: &Expr,
) -> Option<bool> {
    known_vartype_value(project, module_index, module, procedure, expression)
        .map(|type_code| type_code == 10)
}

fn vartype_code_for_array_element(
    project: &Project,
    module_index: usize,
    module: &Module,
    type_name: &str,
) -> Option<i64> {
    let effective_type = effective_project_type_name(project, module_index, module, type_name);
    let key = normalized_type(&effective_type);
    if key == "variant" {
        return Some(12);
    }
    if key == "object" || class_type_owner_index(project, &effective_type).is_some() {
        return Some(9);
    }
    vartype_code_for_scalar_type(project, module_index, &effective_type)
}

fn vartype_code_for_scalar_type(
    project: &Project,
    module_index: usize,
    type_name: &str,
) -> Option<i64> {
    let key = normalized_type(type_name);
    Some(match key.as_str() {
        "integer" => 2,
        "long" => 3,
        "single" => 4,
        "double" => 5,
        "currency" => 6,
        "date" => 7,
        "string" => 8,
        "error" => 10,
        "boolean" => 11,
        "decimal" => 14,
        "byte" => 17,
        // VarType's LongLong subtype is valid only for 64-bit VBA. The
        // analyzed source alone does not always prove the target bitness.
        _ if key.starts_with("string*") => 8,
        _ if user_type_owner_index(project, module_index, type_name).is_some() => return None,
        _ => return None,
    })
}

/// Return TypeName's stable text for known scalar subtypes and supported
/// array subtypes. Object values, UDTs, and dynamic Variant contents may
/// report a run-time or default-property type and remain unresolved.
pub(crate) fn known_typename_value(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    expression: &Expr,
) -> Option<String> {
    if let Expr::Group(value, _) = expression {
        return known_typename_value(project, module_index, module, procedure, value);
    }
    let code = known_vartype_value(project, module_index, module, procedure, expression)?;
    let (code, is_array) = if code >= 8192 {
        (code - 8192, true)
    } else {
        (code, false)
    };
    let type_name = match code {
        0 => "Empty",
        1 => "Null",
        2 => "Integer",
        3 => "Long",
        4 => "Single",
        5 => "Double",
        6 => "Currency",
        7 => "Date",
        8 => "String",
        10 => "Error",
        11 => "Boolean",
        12 => "Variant",
        14 => "Decimal",
        17 => "Byte",
        20 => "LongLong",
        // TypeName(object) reports the run-time object type or its default
        // property's type, neither of which is proved by a static Object code.
        9 | 13 | 36 | 8192.. => return None,
        _ => return None,
    };
    Some(if is_array {
        format!("{type_name}()")
    } else {
        type_name.into()
    })
}

pub(crate) fn project_may_shadow_type_intrinsic(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    name: &str,
) -> bool {
    project_may_shadow_intrinsic(project, module_index, module, procedure, name)
        || project
            .modules
            .iter()
            .any(|candidate| canon(&candidate.name) == name)
        || project
            .name
            .as_deref()
            .is_some_and(|project_name| canon(project_name) == name)
}

fn project_may_shadow_date_intrinsic(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    name: &str,
) -> bool {
    project_may_shadow_intrinsic(project, module_index, module, procedure, name)
        || project
            .modules
            .iter()
            .any(|candidate| canon(&candidate.name) == name)
        || project
            .name
            .as_deref()
            .is_some_and(|project_name| canon(project_name) == name)
}

fn whole_array_info_for_expression(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    expression: &Expr,
) -> Option<ArraySymbolInfo> {
    if let Some(info) =
        array_info_for_expression(project, module_index, module, procedure, expression)
    {
        return Some(info);
    }
    match expression {
        Expr::Call { callee, args, .. } if args.is_empty() => {
            array_info_for_expression(project, module_index, module, procedure, callee)
        }
        _ => None,
    }
}

fn simple_array_expression_name(expression: &Expr) -> Option<String> {
    match expression {
        Expr::Identifier(name, _) => Some(name.clone()),
        Expr::Member {
            object,
            member,
            access: MemberAccessKind::Dot,
            ..
        } => Some(format!(
            "{}.{}",
            simple_array_expression_name(object)?,
            member
        )),
        Expr::Member { .. } => None,
        Expr::Group(value, _) => simple_array_expression_name(value),
        _ => None,
    }
}

fn known_integer_argument(expression: &Expr) -> Option<i64> {
    match expression {
        Expr::Literal(text, LiteralKind::Number, _) => {
            let value = text.trim_end_matches(['%', '&', '^', '@', '!', '#']);
            if let Some(hex) = value
                .strip_prefix("&H")
                .or_else(|| value.strip_prefix("&h"))
            {
                i64::from_str_radix(hex, 16).ok()
            } else if let Some(octal) = value
                .strip_prefix("&O")
                .or_else(|| value.strip_prefix("&o"))
            {
                i64::from_str_radix(octal, 8).ok()
            } else {
                value.parse().ok()
            }
        }
        Expr::Group(value, _) => known_integer_argument(value),
        Expr::Unary { op, value, .. } if op == "-" => known_integer_argument(value)?.checked_neg(),
        Expr::Unary { op, value, .. } if op == "+" => known_integer_argument(value),
        _ => None,
    }
}

pub(crate) fn infer_expression_type(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure_name: &str,
    expression: &str,
    host_profile: HostProfile,
) -> Option<String> {
    let procedure = module
        .procedures
        .iter()
        .find(|procedure| procedure.name.eq_ignore_ascii_case(procedure_name))?;
    let parsed = crate::parser::parse_expression_source(expression)?;
    Some(infer_expr(
        project,
        module_index,
        module,
        procedure,
        &parsed,
        host_profile,
    ))
}

pub(crate) fn infer_expression_type_in_module(
    project: &Project,
    module_index: usize,
    module: &Module,
    expression: &Expr,
    host_profile: HostProfile,
) -> String {
    let procedure = Procedure::default();
    infer_expr(
        project,
        module_index,
        module,
        &procedure,
        expression,
        host_profile,
    )
}

fn visit_statements(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    statements: &[Statement],
    host_profile: HostProfile,
    out: &mut Vec<TypeFact>,
) {
    for statement in statements {
        if statement.kind == "assignment"
            && let (Some(source), Some(value)) =
                (&statement.expression, &statement.parsed_expression)
        {
            let target = assignment_target(source);
            let target_name = target
                .rsplit(['.', '!'])
                .next()
                .unwrap_or(&target)
                .split('(')
                .next()
                .unwrap_or("")
                .trim();
            let target_type = statement
                .parsed_target
                .as_ref()
                .and_then(|target_expression| {
                    matches!(
                        target_expression,
                        Expr::Member { .. } | Expr::Call { .. } | Expr::Group(..)
                    )
                    .then(|| {
                        infer_expr(
                            project,
                            module_index,
                            module,
                            procedure,
                            target_expression,
                            host_profile,
                        )
                    })
                    .filter(|type_name| !type_name.eq_ignore_ascii_case("host-dependent Variant"))
                })
                .or_else(|| symbol_type(project, module_index, module, procedure, target_name));
            let is_set_assignment = source
                .split_whitespace()
                .next()
                .is_some_and(|keyword| keyword.eq_ignore_ascii_case("set"));
            let declared_value_type = infer_expr(
                project,
                module_index,
                module,
                procedure,
                value,
                host_profile,
            );
            let simple_value_target = target_type.as_deref().is_some_and(|type_name| {
                is_variant_type(type_name)
                    || with_type_validity(project, module_index, type_name) == Some(false)
            });
            let value_type = if !is_set_assignment && simple_value_target {
                infer_simple_expression_type(
                    project,
                    module_index,
                    module,
                    procedure,
                    value,
                    host_profile,
                    0,
                )
                .unwrap_or_else(|| {
                    infer_expr(
                        project,
                        module_index,
                        module,
                        procedure,
                        value,
                        host_profile,
                    )
                })
            } else {
                infer_expr(
                    project,
                    module_index,
                    module,
                    procedure,
                    value,
                    host_profile,
                )
            };
            let target_array = statement.parsed_target.as_ref().and_then(|target| {
                whole_array_info_for_expression(project, module_index, module, procedure, target)
            });
            let value_array =
                whole_array_info_for_expression(project, module_index, module, procedure, value);
            let class_default_status =
                if is_set_assignment || target_array.is_some() || value_array.is_some() {
                    None
                } else {
                    target_type
                        .as_deref()
                        .and_then(|target_type| {
                            class_default_member_let_coercion_invalid(
                                project,
                                module_index,
                                module,
                                &declared_value_type,
                                module_index,
                                module,
                                target_type,
                                host_profile,
                            )
                        })
                        .filter(|invalid| *invalid)
                        .map(|_| "invalid_class_default_let_coercion")
                };
            let nothing_status = (!is_set_assignment && is_explicit_nothing_expression(value))
                .then_some("nothing_let_coercion_runtime_error");
            let null_status = (!is_set_assignment && is_explicit_null_expression(value))
                .then(|| {
                    null_let_coercion_status(
                        project,
                        module_index,
                        module,
                        target_array.as_ref(),
                        target_type.as_deref(),
                        host_profile,
                    )
                })
                .flatten();
            let string_status = (!is_set_assignment
                && target_type.as_deref().is_some_and(|target_type| {
                    string_literal_let_coercion_error_13(value, target_type)
                }))
            .then_some("string_literal_numeric_coercion_runtime_error_13");
            let udt_status = if is_set_assignment || target_array.is_some() || value_array.is_some()
            {
                None
            } else {
                udt_let_coercion_status(
                    project,
                    module_index,
                    module,
                    target_type.as_deref(),
                    &value_type,
                    host_profile,
                )
            };
            let object_status = if is_set_assignment || target_array.is_some() {
                None
            } else {
                object_let_coercion_status(
                    project,
                    AssignmentContext {
                        module_index,
                        module,
                        procedure,
                    },
                    target_type.as_deref(),
                    value,
                    &value_type,
                    host_profile,
                )
            };
            let array_status = if is_set_assignment {
                None
            } else {
                array_let_coercion_status(
                    project,
                    ArrayAssignmentContext {
                        assignment: AssignmentContext {
                            module_index,
                            module,
                            procedure,
                        },
                        target: target_array.as_ref(),
                        value: value_array.as_ref(),
                    },
                    target_type.as_deref(),
                    &value_type,
                    value,
                    host_profile,
                )
            };
            let status = nothing_status
                .or(null_status)
                .or(string_status)
                .or(class_default_status)
                .or(udt_status)
                .or(object_status)
                .or(array_status)
                .unwrap_or_else(|| assignment_status(target_type.as_deref(), &value_type));
            out.push(TypeFact {
                module: module.name.clone(),
                procedure: Some(procedure.name.clone()),
                target,
                target_type,
                value_type,
                status: status.into(),
                span: statement.span,
            });
        }
        visit_statements(
            project,
            module_index,
            module,
            procedure,
            &statement.children,
            host_profile,
            out,
        );
    }
}

fn infer_simple_expression_type(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    expression: &Expr,
    host_profile: HostProfile,
    depth: usize,
) -> Option<String> {
    if depth >= 8 {
        return Some("host-dependent Variant".into());
    }
    match expression {
        Expr::Group(value, _) => infer_simple_expression_type(
            project,
            module_index,
            module,
            procedure,
            value,
            host_profile,
            depth + 1,
        ),
        Expr::Binary {
            left, op, right, ..
        } => {
            let left = infer_simple_expression_type(
                project,
                module_index,
                module,
                procedure,
                left,
                host_profile,
                depth + 1,
            )?;
            let right = infer_simple_expression_type(
                project,
                module_index,
                module,
                procedure,
                right,
                host_profile,
                depth + 1,
            )?;
            Some(binary_type(op, &left, &right))
        }
        Expr::Unary { op, value, .. } => {
            let operand = infer_simple_expression_type(
                project,
                module_index,
                module,
                procedure,
                value,
                host_profile,
                depth + 1,
            )?;
            Some(if op.eq_ignore_ascii_case("not") {
                logical_not_type(&operand)
            } else if op == "-" {
                unary_minus_type(&operand)
            } else if op == "+" {
                unary_plus_type(&operand)
            } else {
                operand
            })
        }
        Expr::NamedArgument { value, .. } => infer_simple_expression_type(
            project,
            module_index,
            module,
            procedure,
            value,
            host_profile,
            depth + 1,
        ),
        _ => {
            let value_type = infer_expr(
                project,
                module_index,
                module,
                procedure,
                expression,
                host_profile,
            );
            infer_simple_value_from_declared_type(
                project,
                module_index,
                &value_type,
                host_profile,
                depth + 1,
            )
        }
    }
}

fn infer_simple_value_from_declared_type(
    project: &Project,
    module_index: usize,
    type_name: &str,
    host_profile: HostProfile,
    depth: usize,
) -> Option<String> {
    if depth >= 8 {
        return Some("host-dependent Variant".into());
    }
    let normalized = type_name
        .trim()
        .trim_start_matches("New ")
        .trim_end_matches("()");
    if type_name.starts_with("host-dependent") {
        return Some(type_name.to_owned());
    }
    if normalized.eq_ignore_ascii_case("Object") || normalized.eq_ignore_ascii_case("Variant") {
        return Some("Variant".into());
    }
    if with_type_validity(project, module_index, normalized) == Some(false) {
        return Some(effective_project_type_name(
            project,
            module_index,
            &project.modules[module_index],
            normalized,
        ));
    }
    let class_modules = project
        .modules
        .iter()
        .enumerate()
        .filter(|(_, candidate)| {
            canon(&candidate.name) == canon(normalized)
                && matches!(
                    candidate.module_kind.as_deref(),
                    Some(
                        "class"
                            | "form"
                            | "workbook_document"
                            | "worksheet_document"
                            | "class_or_document"
                            | "document_or_class"
                    )
                )
        })
        .collect::<Vec<_>>();
    if class_modules.len() == 1 {
        let (owner, class_module) = class_modules[0];
        let getters = class_module
            .procedures
            .iter()
            .filter(|candidate| {
                candidate.automation_member_id == Some(0)
                    && candidate.visibility.eq_ignore_ascii_case("public")
                    && (candidate.kind.eq_ignore_ascii_case("Property Get")
                        || candidate.kind.eq_ignore_ascii_case("Function"))
                    && procedure_parameters_accept_arguments(&candidate.parameters, &[])
            })
            .collect::<Vec<_>>();
        if getters.len() != 1 {
            return Some("host-dependent Variant".into());
        }
        let getter = getters[0];
        let return_type = getter
            .return_type
            .as_deref()
            .map(|value| effective_project_type_name(project, owner, class_module, value))
            .or_else(|| implicit_type_name(class_module, &getter.name))
            .unwrap_or_else(|| "Variant".into());
        return infer_simple_value_from_declared_type(
            project,
            owner,
            &return_type,
            host_profile,
            depth + 1,
        );
    }
    if user_type_owner_index(project, module_index, normalized).is_some() {
        return Some(normalized.to_owned());
    }
    if host_profile == HostProfile::Excel && excel::is_known_type(normalized) {
        return Some("host-dependent Variant".into());
    }
    None
}

fn assignment_target(source: &str) -> String {
    let mut target = source
        .split_once('=')
        .map(|x| x.0.trim().to_owned())
        .unwrap_or_default();
    if target.to_ascii_lowercase().starts_with("set ")
        || target.to_ascii_lowercase().starts_with("let ")
    {
        target = target[4..].trim().to_owned();
    }
    target
}

pub(crate) fn effective_project_type_name(
    project: &Project,
    module_index: usize,
    module: &Module,
    type_name: &str,
) -> String {
    let key = canon(type_name);
    let local_enum = module
        .declarations
        .iter()
        .any(|declaration| declaration.kind == "enum" && canon(&declaration.name) == key);
    let public_project_enum = project
        .modules
        .iter()
        .enumerate()
        .any(|(index, candidate)| {
            index != module_index
                && candidate.declarations.iter().any(|declaration| {
                    declaration.kind == "enum"
                        && (declaration.visibility.eq_ignore_ascii_case("public")
                            || declaration.visibility.eq_ignore_ascii_case("global"))
                        && canon(&declaration.name) == key
                })
        });
    if local_enum || public_project_enum {
        "Long".into()
    } else {
        type_name.to_string()
    }
}

fn symbol_type(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    name: &str,
) -> Option<String> {
    if let Some(p) = module
        .procedures
        .iter()
        .find(|p| p.name.eq_ignore_ascii_case(name))
    {
        return p
            .return_type
            .clone()
            .map(|type_name| effective_project_type_name(project, module_index, module, &type_name))
            .or_else(|| implicit_type_name(module, &p.name));
    }
    if let Some(parameter) = procedure
        .parameters
        .iter()
        .find(|p| p.name.eq_ignore_ascii_case(name))
    {
        return parameter
            .type_name
            .clone()
            .map(|type_name| effective_project_type_name(project, module_index, module, &type_name))
            .or_else(|| implicit_type_name(module, &parameter.name));
    }
    if let Some(decl) = find_local(&procedure.statements, name) {
        return declaration_type(project, module_index, decl, module);
    }
    module
        .declarations
        .iter()
        .find(|d| {
            d.name.eq_ignore_ascii_case(name)
                && !matches!(d.kind.as_str(), "user_type" | "enum" | "field")
        })
        .and_then(|declaration| declaration_type(project, module_index, declaration, module))
        .or_else(|| {
            let target = canon(name);
            let mut matches = Vec::new();
            for (index, other) in project.modules.iter().enumerate() {
                if index == module_index {
                    continue;
                }
                let standard_module =
                    matches!(other.module_kind.as_deref(), Some("standard") | None);
                for declaration in &other.declarations {
                    let enum_member_public = declaration.kind == "enum_member"
                        && declaration.type_name.as_deref().is_some_and(|enum_name| {
                            other.declarations.iter().any(|enum_declaration| {
                                enum_declaration.kind == "enum"
                                    && (enum_declaration.visibility.eq_ignore_ascii_case("public")
                                        || enum_declaration
                                            .visibility
                                            .eq_ignore_ascii_case("global"))
                                    && canon(&enum_declaration.name) == canon(enum_name)
                            })
                        });
                    if (matches!(
                        declaration.kind.as_str(),
                        "variable" | "global" | "static" | "constant" | "with_events"
                    ) && standard_module
                        && (declaration.visibility.eq_ignore_ascii_case("public")
                            || declaration.visibility.eq_ignore_ascii_case("global"))
                        || enum_member_public)
                        && canon(&declaration.name) == target
                    {
                        matches.push((index, other, declaration));
                    }
                }
            }
            if matches.len() == 1 {
                declaration_type(project, matches[0].0, matches[0].2, matches[0].1)
            } else {
                None
            }
        })
        .or_else(|| {
            let target = canon(name);
            let modules = project
                .modules
                .iter()
                .enumerate()
                .filter(|(_, candidate)| {
                    canon(&candidate.name) == target
                        && candidate.predeclared_id == Some(true)
                        && matches!(
                            candidate.module_kind.as_deref(),
                            Some(
                                "class"
                                    | "form"
                                    | "workbook_document"
                                    | "worksheet_document"
                                    | "class_or_document"
                                    | "document_or_class"
                            )
                        )
                })
                .collect::<Vec<_>>();
            (modules.len() == 1).then(|| modules[0].1.name.clone())
        })
}

fn find_local<'a>(statements: &'a [Statement], name: &str) -> Option<&'a Declaration> {
    for s in statements {
        if let Some(d) = &s.declaration
            && d.name.eq_ignore_ascii_case(name)
        {
            return Some(d);
        }
        if let Some(found) = find_local(&s.children, name) {
            return Some(found);
        }
    }
    None
}

#[derive(Clone, Copy)]
struct AssignmentContext<'a> {
    module_index: usize,
    module: &'a Module,
    procedure: &'a Procedure,
}

#[derive(Clone, Debug)]
struct ArraySymbolInfo {
    element_type: String,
    rank: Option<usize>,
    is_fixed_size: bool,
}

#[derive(Clone, Copy)]
struct ArrayAssignmentContext<'a> {
    assignment: AssignmentContext<'a>,
    target: Option<&'a ArraySymbolInfo>,
    value: Option<&'a ArraySymbolInfo>,
}

fn array_symbol_info(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    name: &str,
) -> Option<ArraySymbolInfo> {
    let key = canon(name);
    if let Some(parameter) = procedure
        .parameters
        .iter()
        .find(|parameter| canon(&parameter.name) == key)
    {
        if parameter.is_array || parameter.is_param_array {
            return Some(ArraySymbolInfo {
                element_type: declared_parameter_type(project, module_index, module, parameter)
                    .unwrap_or_else(|| "Variant".into()),
                rank: parameter.is_param_array.then_some(1),
                is_fixed_size: false,
            });
        }
        return None;
    }
    if let Some(declaration) = find_local(&procedure.statements, name) {
        return array_info_from_declaration(project, module_index, module, declaration);
    }
    if let Some(declaration) = module
        .declarations
        .iter()
        .find(|declaration| canon(&declaration.name) == key)
    {
        return array_info_from_declaration(project, module_index, module, declaration);
    }

    let mut candidates = Vec::new();
    for (candidate_index, candidate_module) in project.modules.iter().enumerate() {
        if candidate_index == module_index
            || !matches!(
                candidate_module.module_kind.as_deref(),
                Some("standard") | None
            )
        {
            continue;
        }
        candidates.extend(
            candidate_module
                .declarations
                .iter()
                .filter_map(|declaration| {
                    let visible = declaration.visibility.eq_ignore_ascii_case("public")
                        || declaration.visibility.eq_ignore_ascii_case("global");
                    let value = matches!(
                        declaration.kind.as_str(),
                        "variable" | "global" | "static" | "with_events"
                    );
                    (visible && value && canon(&declaration.name) == key).then_some((
                        candidate_index,
                        candidate_module,
                        declaration,
                    ))
                }),
        );
    }
    if candidates.len() == 1 {
        array_info_from_declaration(project, candidates[0].0, candidates[0].1, candidates[0].2)
    } else {
        None
    }
}

fn member_array_symbol_info(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    object: &Expr,
    member: &str,
) -> Option<ArraySymbolInfo> {
    if let Some((owner, target, field)) =
        resolve_udt_field(project, module_index, module, procedure, object, member)
    {
        return array_info_from_declaration(project, owner, target, field);
    }
    let (owner, self_access) = member_owner(project, module_index, module, procedure, object)?;
    let target_module = &project.modules[owner];
    let candidates = target_module
        .declarations
        .iter()
        .filter(|declaration| {
            declaration.is_array
                && canon(&declaration.name) == canon(member)
                && matches!(
                    declaration.kind.as_str(),
                    "variable" | "global" | "static" | "with_events"
                )
                && member_accessible(owner, module_index, declaration, self_access)
        })
        .collect::<Vec<_>>();
    if candidates.len() == 1 {
        array_info_from_declaration(project, owner, target_module, candidates[0])
    } else {
        None
    }
}

fn array_info_from_declaration(
    project: &Project,
    module_index: usize,
    module: &Module,
    declaration: &Declaration,
) -> Option<ArraySymbolInfo> {
    if !declaration.is_array {
        return None;
    }
    Some(ArraySymbolInfo {
        element_type: declaration_type(project, module_index, declaration, module)?,
        rank: (!declaration.array_dimensions.is_empty())
            .then_some(declaration.array_dimensions.len()),
        is_fixed_size: !declaration.array_dimensions.is_empty()
            && !matches!(declaration.kind.as_str(), "redim" | "redim_preserve"),
    })
}

fn array_reference_type(info: &ArraySymbolInfo) -> String {
    format!("Array<{}>", info.element_type)
}

fn array_index_type(info: &ArraySymbolInfo, arguments: &[Expr]) -> String {
    if arguments.is_empty() {
        return array_reference_type(info);
    }
    if arguments
        .iter()
        .any(|argument| matches!(argument, Expr::NamedArgument { .. }))
    {
        return "Variant".into();
    }
    if info.rank.is_some_and(|rank| rank != arguments.len()) {
        return "Variant".into();
    }
    info.element_type.clone()
}

fn declaration_type(
    project: &Project,
    module_index: usize,
    d: &Declaration,
    module: &Module,
) -> Option<String> {
    if d.kind == "field" && d.type_name.is_none() {
        return None;
    }
    d.type_name
        .clone()
        .map(|type_name| effective_project_type_name(project, module_index, module, &type_name))
        .or_else(|| suffix_type(&d.name))
        .or_else(|| {
            (d.kind != "constant")
                .then(|| implicit_type_name(module, &d.name))
                .flatten()
        })
}

fn implicit_type_name(module: &Module, name: &str) -> Option<String> {
    suffix_type(name).or_else(|| {
        module.implicit_types.valid.then(|| {
            module
                .implicit_types
                .type_for_identifier(name)
                .unwrap_or_else(|| "Variant".into())
        })
    })
}

pub(crate) fn declared_parameter_type(
    project: &Project,
    module_index: usize,
    module: &Module,
    parameter: &crate::model::Parameter,
) -> Option<String> {
    parameter
        .type_name
        .clone()
        .map(|type_name| effective_project_type_name(project, module_index, module, &type_name))
        .or_else(|| implicit_type_name(module, &parameter.name))
}

pub(crate) fn declared_symbol_type(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure_name: Option<&str>,
    name: &str,
) -> Option<String> {
    let procedure = procedure_name.and_then(|procedure_name| {
        module
            .procedures
            .iter()
            .find(|procedure| procedure.name.eq_ignore_ascii_case(procedure_name))
    })?;
    symbol_type(project, module_index, module, procedure, name)
}

fn suffix_type(name: &str) -> Option<String> {
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

pub(crate) fn infer_expr(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    expr: &Expr,
    host_profile: HostProfile,
) -> String {
    match expr {
        Expr::TypeOfIs { .. } => "Boolean".into(),
        Expr::Literal(text, kind, _) => match kind {
            LiteralKind::Number => numeric_literal_type(text),
            LiteralKind::String => "String".into(),
            LiteralKind::Date => "Date".into(),
        },
        Expr::Identifier(name, _) => {
            let low = canon(name);
            if host_profile == HostProfile::Excel && excel::is_constant(name) {
                return "Long".into();
            }
            if matches!(low.as_str(), "true" | "false") {
                return "Boolean".into();
            }
            if matches!(low.as_str(), "vbget" | "vblet" | "vbmethod" | "vbset") {
                return "Long".into();
            }
            if matches!(low.as_str(), "nothing" | "me") {
                return "Object".into();
            }
            if let Some(info) = array_symbol_info(project, module_index, module, procedure, name) {
                return array_reference_type(&info);
            }
            symbol_type(project, module_index, module, procedure, name)
                .unwrap_or_else(|| "Variant".into())
        }
        Expr::Group(value, _) => infer_expr(
            project,
            module_index,
            module,
            procedure,
            value,
            host_profile,
        ),
        Expr::Unary { op, value, .. } => {
            if op.eq_ignore_ascii_case("not") {
                let operand = infer_expr(
                    project,
                    module_index,
                    module,
                    procedure,
                    value,
                    host_profile,
                );
                logical_not_type(&operand)
            } else if op.eq_ignore_ascii_case("new") {
                if let Expr::Identifier(type_name, _) = value.as_ref() {
                    format!("New {type_name}")
                } else {
                    "host-dependent Object".into()
                }
            } else if op.eq_ignore_ascii_case("addressof") {
                "LongPtr".into()
            } else if op == "-" {
                let operand = infer_expr(
                    project,
                    module_index,
                    module,
                    procedure,
                    value,
                    host_profile,
                );
                unary_minus_type(&operand)
            } else if op == "+" {
                let operand = infer_expr(
                    project,
                    module_index,
                    module,
                    procedure,
                    value,
                    host_profile,
                );
                unary_plus_type(&operand)
            } else {
                infer_expr(
                    project,
                    module_index,
                    module,
                    procedure,
                    value,
                    host_profile,
                )
            }
        }
        Expr::Member {
            object,
            member,
            access: MemberAccessKind::Bang,
            span,
        } => {
            let key = Expr::Literal(member.clone(), LiteralKind::String, *span);
            resolve_default_member_call_type(
                project,
                module_index,
                module,
                procedure,
                object,
                &[key],
            )
            .unwrap_or_else(|| "host-dependent Variant".into())
        }
        Expr::Member {
            object,
            member,
            access: MemberAccessKind::Dot,
            ..
        } => {
            if let Some(info) =
                member_array_symbol_info(project, module_index, module, procedure, object, member)
            {
                return array_reference_type(&info);
            }
            resolve_member_value_type(project, module_index, module, procedure, object, member)
                .or_else(|| {
                    resolve_member_procedure_type(
                        project,
                        module_index,
                        module,
                        procedure,
                        object,
                        member,
                        true,
                    )
                })
                .unwrap_or_else(|| "host-dependent Variant".into())
        }
        Expr::NamedArgument { value, .. } => infer_expr(
            project,
            module_index,
            module,
            procedure,
            value,
            host_profile,
        ),
        Expr::Unknown(..) => "Variant".into(),
        Expr::Binary {
            left, op, right, ..
        } => {
            let a = infer_expr(project, module_index, module, procedure, left, host_profile);
            let b = infer_expr(
                project,
                module_index,
                module,
                procedure,
                right,
                host_profile,
            );
            binary_type(op, &a, &b)
        }
        Expr::Call { callee, args, .. } => {
            let name = match callee.as_ref() {
                Expr::Identifier(n, _) => canon(n),
                Expr::Member {
                    member,
                    access: MemberAccessKind::Dot,
                    ..
                } => canon(member),
                _ => String::new(),
            };
            let indexed_array = match callee.as_ref() {
                Expr::Identifier(callee_name, _) => {
                    array_symbol_info(project, module_index, module, procedure, callee_name)
                }
                Expr::Member {
                    object,
                    member,
                    access: MemberAccessKind::Dot,
                    ..
                } => member_array_symbol_info(
                    project,
                    module_index,
                    module,
                    procedure,
                    object,
                    member,
                ),
                _ => None,
            };
            if let Some(info) = indexed_array {
                return array_index_type(&info, args);
            }
            if name == "callbyname"
                && let Some(return_type) =
                    infer_callbyname_return_type(project, module_index, module, procedure, args)
            {
                return return_type;
            }
            if matches!(callee.as_ref(), Expr::Identifier(..))
                && !project_may_shadow_intrinsic(project, module_index, module, procedure, &name)
                && let Some(ty) = intrinsic_return_type(&name)
            {
                return ty.into();
            }
            if name == "iif" && args.len() >= 3 {
                let a = infer_expr(
                    project,
                    module_index,
                    module,
                    procedure,
                    &args[1],
                    host_profile,
                );
                let b = infer_expr(
                    project,
                    module_index,
                    module,
                    procedure,
                    &args[2],
                    host_profile,
                );
                return if a.eq_ignore_ascii_case(&b) {
                    a
                } else {
                    "Variant".into()
                };
            }
            if let Some(p) = module.procedures.iter().find(|p| canon(&p.name) == name) {
                return p
                    .return_type
                    .clone()
                    .map(|type_name| {
                        effective_project_type_name(project, module_index, module, &type_name)
                    })
                    .or_else(|| implicit_type_name(module, &p.name))
                    .unwrap_or_else(|| "host-dependent Variant".into());
            }
            if let Expr::Member {
                object,
                member,
                access: MemberAccessKind::Dot,
                ..
            } = callee.as_ref()
                && let Some(value_type) = resolve_member_procedure_type(
                    project,
                    module_index,
                    module,
                    procedure,
                    object,
                    member,
                    false,
                )
            {
                return value_type;
            }
            let mut candidates = Vec::new();
            for (index, other) in project.modules.iter().enumerate() {
                if index == module_index
                    || !matches!(other.module_kind.as_deref(), Some("standard") | None)
                {
                    continue;
                }
                candidates.extend(
                    other
                        .procedures
                        .iter()
                        .filter(|candidate| {
                            canon(&candidate.name) == name
                                && candidate.visibility.eq_ignore_ascii_case("public")
                                && (candidate.kind.eq_ignore_ascii_case("function")
                                    || candidate
                                        .kind
                                        .to_ascii_lowercase()
                                        .starts_with("property get"))
                        })
                        .map(|candidate| (index, other, candidate)),
                );
            }
            if candidates.len() == 1 {
                let (candidate_module_index, candidate_module, candidate) = candidates[0];
                return candidate
                    .return_type
                    .clone()
                    .map(|type_name| {
                        effective_project_type_name(
                            project,
                            candidate_module_index,
                            candidate_module,
                            &type_name,
                        )
                    })
                    .or_else(|| implicit_type_name(candidate_module, &candidate.name))
                    .unwrap_or_else(|| "host-dependent Variant".into());
            }
            if let Expr::Identifier(_, _) = callee.as_ref()
                && let Some(default_type) = resolve_default_member_call_type(
                    project,
                    module_index,
                    module,
                    procedure,
                    callee,
                    args,
                )
            {
                return default_type;
            }
            "host-dependent Variant".into()
        }
    }
}

fn infer_callbyname_return_type(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    arguments: &[Expr],
) -> Option<String> {
    if arguments.len() < 3
        || arguments[..3]
            .iter()
            .any(|argument| matches!(argument, Expr::NamedArgument { .. }))
    {
        return None;
    }
    let Expr::Literal(member, LiteralKind::String, _) = &arguments[1] else {
        return None;
    };
    let call_type = match &arguments[2] {
        Expr::Identifier(name, _) => match canon(name).as_str() {
            "vbmethod" => 1,
            "vbget" => 2,
            "vblet" => 4,
            "vbset" => 8,
            _ => return None,
        },
        Expr::Literal(value, LiteralKind::Number, _) => value.parse::<i64>().ok()? as i32,
        _ => return None,
    };
    let (owner, _) = member_owner(project, module_index, module, procedure, &arguments[0])?;
    let target = &project.modules[owner];
    if matches!(call_type, 1 | 2 | 4 | 8) {
        let candidates = target
            .procedures
            .iter()
            .filter(|candidate| {
                canon(&candidate.name) == canon(member)
                    && candidate.visibility.eq_ignore_ascii_case("public")
                    && match call_type {
                        1 => {
                            candidate.kind.eq_ignore_ascii_case("Sub")
                                || candidate.kind.eq_ignore_ascii_case("Function")
                        }
                        2 => candidate.kind.eq_ignore_ascii_case("Property Get"),
                        4 => candidate.kind.eq_ignore_ascii_case("Property Let"),
                        8 => candidate.kind.eq_ignore_ascii_case("Property Set"),
                        _ => false,
                    }
                    && procedure_parameters_accept_arguments(&candidate.parameters, &arguments[3..])
            })
            .collect::<Vec<_>>();
        if candidates.len() == 1 {
            let candidate = candidates[0];
            if matches!(call_type, 4 | 8) || candidate.kind.eq_ignore_ascii_case("Sub") {
                return Some("Variant".into());
            }
            return candidate
                .return_type
                .as_deref()
                .map(|type_name| effective_project_type_name(project, owner, target, type_name))
                .or_else(|| implicit_type_name(target, &candidate.name));
        }
    }
    if call_type == 2 && arguments.len() == 3 {
        let fields = target
            .declarations
            .iter()
            .filter(|declaration| {
                canon(&declaration.name) == canon(member)
                    && matches!(
                        declaration.kind.as_str(),
                        "variable" | "global" | "static" | "with_events"
                    )
                    && declaration.visibility.eq_ignore_ascii_case("public")
                    && !declaration.is_array
            })
            .collect::<Vec<_>>();
        if fields.len() == 1 {
            return declaration_type(project, owner, fields[0], target);
        }
    }
    Some("Variant".into())
}

fn resolve_default_member_call_type(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    receiver: &Expr,
    arguments: &[Expr],
) -> Option<String> {
    let (owner, self_access) = member_owner(project, module_index, module, procedure, receiver)?;
    let target = &project.modules[owner];
    let candidates = target
        .procedures
        .iter()
        .filter(|candidate| {
            candidate.automation_member_id == Some(0)
                && (candidate.kind.eq_ignore_ascii_case("Function")
                    || candidate.kind.eq_ignore_ascii_case("Property Get"))
                && (self_access
                    || owner == module_index
                    || !candidate.visibility.eq_ignore_ascii_case("Private"))
                && procedure_parameters_accept_arguments(&candidate.parameters, arguments)
        })
        .collect::<Vec<_>>();
    if candidates.len() != 1 {
        return None;
    }
    let candidate = candidates[0];
    candidate
        .return_type
        .as_deref()
        .map(|type_name| effective_project_type_name(project, owner, target, type_name))
        .or_else(|| implicit_type_name(target, &candidate.name))
}

fn procedure_parameters_accept_arguments(parameters: &[Parameter], arguments: &[Expr]) -> bool {
    let mut assigned = vec![false; parameters.len()];
    let param_array = parameters
        .iter()
        .position(|parameter| parameter.is_param_array);
    let mut next_positional = 0usize;
    for argument in arguments {
        if let Expr::NamedArgument { name, .. } = argument {
            if param_array.is_some() {
                return false;
            }
            let Some(index) = parameters
                .iter()
                .position(|parameter| canon(&parameter.name) == canon(name))
            else {
                return false;
            };
            if assigned[index] {
                return false;
            }
            assigned[index] = true;
            continue;
        }
        while next_positional < parameters.len() && assigned[next_positional] {
            next_positional += 1;
        }
        if next_positional < parameters.len() {
            assigned[next_positional] = true;
            next_positional += 1;
        } else if param_array.is_none() {
            return false;
        }
    }
    parameters
        .iter()
        .enumerate()
        .all(|(index, parameter)| parameter.optional || parameter.is_param_array || assigned[index])
}

pub(crate) fn member_owner(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    object: &Expr,
) -> Option<(usize, bool)> {
    if let Expr::Identifier(object_name, _) = object {
        if object_name.eq_ignore_ascii_case("Me") {
            return Some((module_index, true));
        }
        let object_key = canon(object_name);
        if let Some((owner, _)) = project.modules.iter().enumerate().find(|(_, candidate)| {
            canon(&candidate.name) == object_key
                && candidate.predeclared_id == Some(true)
                && matches!(
                    candidate.module_kind.as_deref(),
                    Some(
                        "class"
                            | "form"
                            | "workbook_document"
                            | "worksheet_document"
                            | "class_or_document"
                            | "document_or_class"
                    )
                )
        }) {
            return Some((owner, owner == module_index));
        }
        if let Some((owner, _)) = project.modules.iter().enumerate().find(|(_, candidate)| {
            canon(&candidate.name) == object_key
                && matches!(candidate.module_kind.as_deref(), Some("standard") | None)
        }) {
            return Some((owner, owner == module_index));
        }
    }
    let object_type =
        expression_type_for_member_resolution(project, module_index, module, procedure, object)?;
    let type_key = canon(
        object_type
            .trim()
            .trim_start_matches("New ")
            .trim_end_matches("()"),
    );
    project
        .modules
        .iter()
        .enumerate()
        .find(|(_, candidate)| {
            canon(&candidate.name) == type_key
                && matches!(
                    candidate.module_kind.as_deref(),
                    Some(
                        "class"
                            | "form"
                            | "workbook_document"
                            | "worksheet_document"
                            | "class_or_document"
                            | "document_or_class"
                    )
                )
        })
        .map(|(owner, _)| (owner, false))
}

fn expression_type_for_member_resolution(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    expression: &Expr,
) -> Option<String> {
    match expression {
        Expr::Identifier(name, _) => symbol_type(project, module_index, module, procedure, name),
        Expr::Member {
            object,
            member,
            access: MemberAccessKind::Dot,
            ..
        } => resolve_member_value_type(project, module_index, module, procedure, object, member)
            .or_else(|| {
                resolve_member_procedure_type(
                    project,
                    module_index,
                    module,
                    procedure,
                    object,
                    member,
                    true,
                )
            }),
        Expr::Member { .. } => None,
        Expr::Call { .. } => Some(infer_expr(
            project,
            module_index,
            module,
            procedure,
            expression,
            HostProfile::Unknown,
        )),
        Expr::Group(value, _) => {
            expression_type_for_member_resolution(project, module_index, module, procedure, value)
        }
        Expr::Unary { op, value, .. } if op.eq_ignore_ascii_case("new") => {
            if let Expr::Identifier(type_name, _) = value.as_ref() {
                Some(type_name.clone())
            } else {
                None
            }
        }
        _ => None,
    }
}

pub(crate) fn user_type_owner_index(
    project: &Project,
    module_index: usize,
    type_name: &str,
) -> Option<usize> {
    let type_name = canon(
        type_name
            .trim()
            .trim_start_matches("New ")
            .trim_end_matches("()"),
    );
    if project.modules[module_index]
        .declarations
        .iter()
        .any(|declaration| declaration.kind == "user_type" && canon(&declaration.name) == type_name)
    {
        return Some(module_index);
    }
    let candidates = project
        .modules
        .iter()
        .enumerate()
        .filter(|(index, module)| {
            *index != module_index
                && matches!(module.module_kind.as_deref(), Some("standard") | None)
                && module.declarations.iter().any(|declaration| {
                    declaration.kind == "user_type"
                        && (declaration.visibility.eq_ignore_ascii_case("public")
                            || declaration.visibility.eq_ignore_ascii_case("global"))
                        && canon(&declaration.name) == type_name
                })
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    (candidates.len() == 1).then(|| candidates[0])
}

pub(crate) fn class_type_owner_index(project: &Project, type_name: &str) -> Option<usize> {
    let type_name = canon(
        type_name
            .trim()
            .trim_start_matches("New ")
            .trim_end_matches("()"),
    );
    let candidates = project
        .modules
        .iter()
        .enumerate()
        .filter(|(_, module)| {
            canon(&module.name) == type_name
                && matches!(
                    module.module_kind.as_deref(),
                    Some(
                        "class"
                            | "form"
                            | "workbook_document"
                            | "worksheet_document"
                            | "class_or_document"
                            | "document_or_class"
                    )
                )
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    (candidates.len() == 1).then(|| candidates[0])
}

fn resolve_udt_field<'a>(
    project: &'a Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    object: &Expr,
    member: &str,
) -> Option<(usize, &'a Module, &'a Declaration)> {
    let object_type =
        expression_type_for_member_resolution(project, module_index, module, procedure, object)?;
    let owner = user_type_owner_index(project, module_index, &object_type)?;
    let target = &project.modules[owner];
    let user_type = target.declarations.iter().find(|declaration| {
        declaration.kind == "user_type" && canon(&declaration.name) == canon(&object_type)
    })?;
    if owner != module_index
        && !user_type.visibility.eq_ignore_ascii_case("public")
        && !user_type.visibility.eq_ignore_ascii_case("global")
    {
        return None;
    }
    let fields = target
        .declarations
        .iter()
        .filter(|declaration| {
            declaration.kind == "field"
                && canon(&declaration.visibility) == canon(&user_type.name)
                && canon(&declaration.name) == canon(member)
        })
        .collect::<Vec<_>>();
    (fields.len() == 1).then(|| (owner, target, fields[0]))
}

fn member_accessible(
    owner: usize,
    current: usize,
    declaration: &Declaration,
    self_access: bool,
) -> bool {
    self_access
        || owner == current
        || declaration.visibility.eq_ignore_ascii_case("public")
        || declaration.visibility.eq_ignore_ascii_case("global")
}

fn resolve_member_value_type(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    object: &Expr,
    member: &str,
) -> Option<String> {
    if let Expr::Identifier(qualifier, _) = object
        && let Some(enum_member_type) =
            resolve_qualified_enum_member_type(project, module_index, qualifier, member)
    {
        return Some(enum_member_type);
    }
    if let Some((owner, target, field)) =
        resolve_udt_field(project, module_index, module, procedure, object, member)
    {
        let field_type = declaration_type(project, owner, field, target)?;
        return Some(if field.is_array {
            format!("Array<{field_type}>")
        } else {
            field_type
        });
    }
    let (owner, self_access) = member_owner(project, module_index, module, procedure, object)?;
    let target = &project.modules[owner];
    target
        .declarations
        .iter()
        .find(|declaration| {
            canon(&declaration.name) == canon(member)
                && matches!(
                    declaration.kind.as_str(),
                    "variable" | "global" | "static" | "constant" | "with_events" | "enum_member"
                )
                && (owner == module_index
                    || (declaration_is_public_value(target, declaration)
                        && member_accessible(owner, module_index, declaration, self_access)))
        })
        .and_then(|declaration| {
            let member_type = declaration_type(project, owner, declaration, target)?;
            Some(if declaration.is_array {
                format!("Array<{member_type}>")
            } else {
                member_type
            })
        })
}

fn resolve_member_procedure_type(
    project: &Project,
    module_index: usize,
    module: &Module,
    procedure: &Procedure,
    object: &Expr,
    member: &str,
    no_arguments: bool,
) -> Option<String> {
    let (owner, self_access) = member_owner(project, module_index, module, procedure, object)?;
    let target = &project.modules[owner];
    let candidates = target
        .procedures
        .iter()
        .filter(|candidate| {
            canon(&candidate.name) == canon(member)
                && (candidate.kind.eq_ignore_ascii_case("function")
                    || candidate.kind.eq_ignore_ascii_case("property get"))
                && (self_access
                    || owner == module_index
                    || !candidate.visibility.eq_ignore_ascii_case("private"))
                && (!no_arguments
                    || candidate
                        .parameters
                        .iter()
                        .all(|parameter| parameter.optional || parameter.is_param_array))
        })
        .collect::<Vec<_>>();
    if candidates.len() != 1 {
        return None;
    }
    let candidate = candidates[0];
    candidate
        .return_type
        .clone()
        .map(|type_name| effective_project_type_name(project, owner, target, &type_name))
        .or_else(|| implicit_type_name(target, &candidate.name))
}

fn declaration_is_public_value(module: &Module, declaration: &Declaration) -> bool {
    let public = declaration.visibility.eq_ignore_ascii_case("public")
        || declaration.visibility.eq_ignore_ascii_case("global");
    public
        && (declaration.kind != "enum_member"
            || declaration.type_name.as_deref().is_some_and(|enum_name| {
                module.declarations.iter().any(|enum_declaration| {
                    enum_declaration.kind == "enum"
                        && (enum_declaration.visibility.eq_ignore_ascii_case("public")
                            || enum_declaration.visibility.eq_ignore_ascii_case("global"))
                        && canon(&enum_declaration.name) == canon(enum_name)
                })
            }))
}

fn binary_type(op: &str, a: &str, b: &str) -> String {
    let op = op.trim().to_ascii_lowercase();
    if op == "is" {
        return "Boolean".into();
    }
    if matches!(op.as_str(), "=" | "<>" | "<" | ">" | "<=" | ">=" | "like") {
        return if is_variant_type(a) || is_variant_type(b) {
            "Variant".into()
        } else {
            "Boolean".into()
        };
    }
    if op == "&" {
        return if is_variant_type(a) || is_variant_type(b) {
            "Variant".into()
        } else if is_concatenable_type(a) && is_concatenable_type(b) {
            "String".into()
        } else {
            "Variant".into()
        };
    }
    if matches!(op.as_str(), "and" | "or" | "xor" | "eqv" | "imp") {
        return logical_binary_type(a, b);
    }
    if matches!(op.as_str(), "+" | "-" | "*" | "/" | "\\" | "mod" | "^") {
        return arithmetic_binary_type(&op, a, b);
    }
    "Variant".into()
}

fn arithmetic_binary_type(op: &str, a: &str, b: &str) -> String {
    if is_variant_type(a) || is_variant_type(b) {
        return "Variant".into();
    }
    if !is_arithmetic_operand_type(a) || !is_arithmetic_operand_type(b) {
        return "Variant".into();
    }

    if op == "^" || op == "/" {
        return "Double".into();
    }
    if matches!(op, "\\" | "mod") {
        if is_floating_or_fixed_type(a)
            || is_floating_or_fixed_type(b)
            || is_string_type(a)
            || is_string_type(b)
            || is_date_type(a)
            || is_date_type(b)
        {
            return "Long".into();
        }
        return integral_binary_type(a, b).unwrap_or_else(|| "Variant".into());
    }

    if op == "+" && is_string_type(a) && is_string_type(b) {
        return "String".into();
    }
    if op == "-" && is_date_type(a) && is_date_type(b) {
        return "Double".into();
    }
    if is_date_type(a) || is_date_type(b) {
        if op == "*" {
            return "Double".into();
        }
        return "Date".into();
    }
    if op == "*"
        && ((is_currency_type(a) && (is_single_or_double_type(b) || is_string_type(b)))
            || (is_currency_type(b) && (is_single_or_double_type(a) || is_string_type(a))))
    {
        return "Double".into();
    }
    if is_currency_type(a) || is_currency_type(b) {
        return "Currency".into();
    }
    if is_double_or_string_type(a) || is_double_or_string_type(b) {
        return "Double".into();
    }
    if (is_single_type(a) && is_long_or_longlong_type(b))
        || (is_single_type(b) && is_long_or_longlong_type(a))
    {
        return "Double".into();
    }
    if (is_single_type(a) && is_small_integral_type(b))
        || (is_single_type(b) && is_small_integral_type(a))
    {
        return "Single".into();
    }
    integral_binary_type(a, b).unwrap_or_else(|| "Variant".into())
}

fn integral_binary_type(a: &str, b: &str) -> Option<String> {
    if !is_integral_type(a) || !is_integral_type(b) {
        return None;
    }
    if is_byte_type(a) && is_byte_type(b) {
        Some("Byte".into())
    } else if is_longlong_type(a) || is_longlong_type(b) {
        Some("LongLong".into())
    } else if is_long_type(a) || is_long_type(b) {
        Some("Long".into())
    } else {
        Some("Integer".into())
    }
}

fn resolve_qualified_enum_member_type(
    project: &Project,
    module_index: usize,
    qualifier: &str,
    member: &str,
) -> Option<String> {
    let module_candidates = project
        .modules
        .iter()
        .enumerate()
        .filter(|(_, candidate)| canon(&candidate.name) == canon(qualifier))
        .collect::<Vec<_>>();
    if !module_candidates.is_empty() {
        if module_candidates.len() != 1 {
            return None;
        }
        let (owner_index, owner) = module_candidates[0];
        let candidates = owner
            .declarations
            .iter()
            .filter(|declaration| {
                if declaration.kind != "enum_member" || canon(&declaration.name) != canon(member) {
                    return false;
                }
                owner.declarations.iter().any(|enum_declaration| {
                    enum_declaration.kind == "enum"
                        && (owner_index == module_index
                            || enum_declaration.visibility.eq_ignore_ascii_case("public")
                            || enum_declaration.visibility.eq_ignore_ascii_case("global"))
                        && declaration.span.start >= enum_declaration.span.start
                        && declaration.span.end <= enum_declaration.span.end
                })
            })
            .count();
        return (candidates == 1).then(|| "Long".into());
    }

    let enum_candidates = project
        .modules
        .iter()
        .enumerate()
        .flat_map(|(owner_index, owner)| {
            owner.declarations.iter().filter_map(move |declaration| {
                (declaration.kind == "enum"
                    && canon(&declaration.name) == canon(qualifier)
                    && (owner_index == module_index
                        || declaration.visibility.eq_ignore_ascii_case("public")
                        || declaration.visibility.eq_ignore_ascii_case("global")))
                .then_some((owner_index, owner, declaration))
            })
        })
        .collect::<Vec<_>>();
    if enum_candidates.len() != 1 {
        return None;
    }
    let (owner_index, owner, enum_declaration) = enum_candidates[0];
    let member_candidates = owner
        .declarations
        .iter()
        .filter(|declaration| {
            declaration.kind == "enum_member"
                && canon(&declaration.name) == canon(member)
                && declaration.span.start >= enum_declaration.span.start
                && declaration.span.end <= enum_declaration.span.end
                && (owner_index == module_index
                    || enum_declaration.visibility.eq_ignore_ascii_case("public")
                    || enum_declaration.visibility.eq_ignore_ascii_case("global"))
        })
        .count();
    (member_candidates == 1).then(|| "Long".into())
}

fn logical_binary_type(a: &str, b: &str) -> String {
    if is_variant_type(a) || is_variant_type(b) {
        return "Variant".into();
    }
    if is_boolean_type(a) && is_boolean_type(b) {
        return "Boolean".into();
    }
    if is_byte_type(a) && is_byte_type(b) {
        return "Byte".into();
    }
    if is_small_integral_type(a) && is_small_integral_type(b) {
        return "Integer".into();
    }
    if is_longlong_type(a) || is_longlong_type(b) {
        if is_logical_operand_type(a) && is_logical_operand_type(b) {
            return "LongLong".into();
        }
        return "Variant".into();
    }
    if is_logical_operand_type(a) && is_logical_operand_type(b) {
        "Long".into()
    } else {
        "Variant".into()
    }
}

fn logical_not_type(operand: &str) -> String {
    if is_variant_type(operand) {
        return "Variant".into();
    }
    if is_byte_type(operand) || is_boolean_type(operand) || is_integer_type(operand) {
        return if is_boolean_type(operand) {
            "Boolean".into()
        } else if is_byte_type(operand) {
            "Byte".into()
        } else {
            "Integer".into()
        };
    }
    if is_longlong_type(operand) {
        return "LongLong".into();
    }
    if is_logical_operand_type(operand) {
        "Long".into()
    } else {
        "Variant".into()
    }
}

fn unary_minus_type(operand: &str) -> String {
    if is_variant_type(operand) {
        return "Variant".into();
    }
    if is_byte_type(operand) || is_boolean_type(operand) || is_integer_type(operand) {
        return "Integer".into();
    }
    if is_longlong_type(operand) {
        return "LongLong".into();
    }
    if is_long_type(operand) {
        return "Long".into();
    }
    if is_single_type(operand) {
        return "Single".into();
    }
    if is_currency_type(operand) {
        return "Currency".into();
    }
    if is_date_type(operand) {
        return "Date".into();
    }
    if is_double_or_string_type(operand) {
        return "Double".into();
    }
    "Variant".into()
}

fn unary_plus_type(operand: &str) -> String {
    if is_variant_type(operand) {
        return "Variant".into();
    }
    if is_boolean_type(operand) || is_integer_type(operand) {
        return "Integer".into();
    }
    if is_byte_type(operand) {
        return "Byte".into();
    }
    unary_minus_type(operand)
}

fn is_variant_type(value: &str) -> bool {
    let normalized = normalized_type(value);
    normalized == "variant" || normalized.starts_with("host-dependentvariant")
}

fn is_arithmetic_operand_type(value: &str) -> bool {
    is_integral_type(value)
        || is_single_or_double_type(value)
        || is_currency_type(value)
        || is_string_type(value)
        || is_date_type(value)
}

fn is_logical_operand_type(value: &str) -> bool {
    is_arithmetic_operand_type(value)
}

fn is_integral_type(value: &str) -> bool {
    is_byte_type(value)
        || is_boolean_type(value)
        || is_integer_type(value)
        || is_long_type(value)
        || is_longlong_type(value)
}

fn is_small_integral_type(value: &str) -> bool {
    is_byte_type(value) || is_boolean_type(value) || is_integer_type(value)
}

fn is_floating_or_fixed_type(value: &str) -> bool {
    is_single_or_double_type(value) || is_currency_type(value)
}

fn is_concatenable_type(value: &str) -> bool {
    is_arithmetic_operand_type(value)
}

fn is_double_or_string_type(value: &str) -> bool {
    is_double_type(value) || is_string_type(value)
}

fn is_single_or_double_type(value: &str) -> bool {
    is_single_type(value) || is_double_type(value)
}

fn is_long_or_longlong_type(value: &str) -> bool {
    is_long_type(value) || is_longlong_type(value)
}

fn is_date_type(value: &str) -> bool {
    normalized_type(value) == "date"
}

fn is_currency_type(value: &str) -> bool {
    normalized_type(value) == "currency"
}

fn is_byte_type(value: &str) -> bool {
    normalized_type(value) == "byte"
}

fn is_boolean_type(value: &str) -> bool {
    normalized_type(value) == "boolean"
}

fn is_integer_type(value: &str) -> bool {
    normalized_type(value) == "integer"
}

fn is_long_type(value: &str) -> bool {
    normalized_type(value) == "long"
}

fn is_longlong_type(value: &str) -> bool {
    normalized_type(value) == "longlong"
}

fn is_single_type(value: &str) -> bool {
    normalized_type(value) == "single"
}

fn is_double_type(value: &str) -> bool {
    normalized_type(value) == "double"
}

fn is_string_type(value: &str) -> bool {
    let normalized = normalized_type(value);
    normalized == "string" || normalized.starts_with("string*")
}

pub(crate) fn normalized_type(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace([' ', '\t'], "")
}
fn numeric_widen(a: &str, b: &str) -> Option<String> {
    let order = [
        "Byte", "Integer", "Long", "LongLong", "Single", "Double", "Currency", "Decimal",
    ];
    let ai = order.iter().position(|x| x.eq_ignore_ascii_case(a))?;
    let bi = order.iter().position(|x| x.eq_ignore_ascii_case(b))?;
    Some(order[ai.max(bi)].into())
}
pub(crate) fn numeric_literal_type(text: &str) -> String {
    if let Some(ty) = suffix_type(text) {
        return ty;
    }
    let number = text.trim_end_matches(['%', '&', '^', '@', '!', '#']);
    if number.contains('.')
        || number.contains('e')
        || number.contains('E')
        || number.contains('d')
        || number.contains('D')
    {
        "Double".into()
    } else if number.parse::<i16>().is_ok() {
        "Integer".into()
    } else {
        "Long".into()
    }
}
fn assignment_status(target: Option<&str>, value: &str) -> &'static str {
    let Some(t) = target else {
        return "target_type_unresolved";
    };
    if value.eq_ignore_ascii_case("LongLong")
        && !matches!(canon(t).as_str(), "longlong" | "longptr" | "variant")
    {
        return "invalid_longlong_implicit_coercion";
    }
    if value == "Variant" || value == "host-dependent Variant" {
        return "variant_or_host_dependent";
    }
    if t.eq_ignore_ascii_case(value) {
        return "compatible";
    }
    if numeric_widen(t, value).is_some() {
        return "numeric_conversion_possible";
    }
    if t.eq_ignore_ascii_case("String")
        || t.eq_ignore_ascii_case("Variant")
        || t.eq_ignore_ascii_case("Object")
    {
        return "implicit_or_host_conversion_possible";
    }
    if value == "Object" {
        return "host_conversion_unresolved";
    }
    "possible_type_mismatch"
}

/// Determine whether a known in-project class value is statically invalid in
/// a Let-coercion context because of its accessible zero-argument default
/// getter, following additional local class-valued getters conservatively.
/// `Some(false)` means the declared type chain has no statically forbidden
/// coercion; runtime conversion can still fail. `None` means the type chain is
/// ambiguous, external, dynamic, or recursive.
#[allow(clippy::too_many_arguments)]
pub(crate) fn class_default_member_let_coercion_invalid(
    project: &Project,
    source_module_index: usize,
    source_module: &Module,
    source_type: &str,
    target_module_index: usize,
    target_module: &Module,
    target_type: &str,
    host_profile: HostProfile,
) -> Option<bool> {
    class_type_owner_index(project, source_type)?;
    let mut seen_classes = std::collections::HashSet::new();
    class_default_member_let_coercion_invalid_inner(
        project,
        source_module_index,
        source_module,
        source_type,
        target_module_index,
        target_module,
        target_type,
        host_profile,
        &mut seen_classes,
        0,
    )
}

#[allow(clippy::too_many_arguments)]
fn class_default_member_let_coercion_invalid_inner(
    project: &Project,
    source_module_index: usize,
    source_module: &Module,
    source_type: &str,
    target_module_index: usize,
    target_module: &Module,
    target_type: &str,
    host_profile: HostProfile,
    seen_classes: &mut std::collections::HashSet<usize>,
    depth: usize,
) -> Option<bool> {
    if depth >= 16
        || is_variant_type(source_type)
        || source_type.starts_with("host-dependent")
        || matches!(normalized_type(source_type).as_str(), "nothing" | "null")
    {
        return None;
    }

    if let Some(owner) = class_type_owner_index(project, source_type) {
        if !seen_classes.insert(owner) {
            return None;
        }
        let class_module = &project.modules[owner];
        let getters = class_module
            .procedures
            .iter()
            .filter(|candidate| {
                candidate.automation_member_id == Some(0)
                    && candidate.visibility.eq_ignore_ascii_case("public")
                    && (candidate.kind.eq_ignore_ascii_case("Property Get")
                        || candidate.kind.eq_ignore_ascii_case("Function"))
                    && procedure_parameters_accept_arguments(&candidate.parameters, &[])
            })
            .collect::<Vec<_>>();
        if getters.is_empty() {
            // A confirmed local class with no accessible default getter cannot
            // supply a value for implicit Let-coercion to any declared type.
            return Some(true);
        }
        if getters.len() != 1 {
            return None;
        }
        let getter = getters[0];
        let returned_type = getter
            .return_type
            .as_deref()
            .map(|type_name| effective_project_type_name(project, owner, class_module, type_name))
            .or_else(|| implicit_type_name(class_module, &getter.name))?;
        return class_default_member_let_coercion_invalid_inner(
            project,
            owner,
            class_module,
            &returned_type,
            target_module_index,
            target_module,
            target_type,
            host_profile,
            seen_classes,
            depth + 1,
        );
    }

    let source_udt = user_type_owner_index(project, source_module_index, source_type);
    let target_udt = user_type_owner_index(project, target_module_index, target_type);
    if let (Some(source_owner), Some(target_owner)) = (source_udt, target_udt) {
        return Some(source_owner != target_owner || canon(source_type) != canon(target_type));
    }

    if source_udt.is_some() {
        if is_variant_type(target_type) {
            return Some(true);
        }
        return known_non_udt_type(
            project,
            target_module_index,
            target_module,
            target_type,
            host_profile,
        )
        .then_some(true);
    }
    if target_udt.is_some() {
        if is_variant_type(source_type) {
            return None;
        }
        return known_non_udt_type(
            project,
            source_module_index,
            source_module,
            source_type,
            host_profile,
        )
        .then_some(true);
    }

    if is_variant_type(target_type) {
        return known_non_udt_type(
            project,
            source_module_index,
            source_module,
            source_type,
            host_profile,
        )
        .then_some(false);
    }
    if is_object_declared_type(project, target_type, host_profile) {
        if normalized_type(source_type) == "object" {
            return None;
        }
        return known_non_udt_type(
            project,
            source_module_index,
            source_module,
            source_type,
            host_profile,
        )
        .then_some(true);
    }
    if normalized_type(source_type) == "longlong"
        && !matches!(
            normalized_type(target_type).as_str(),
            "longlong" | "variant"
        )
    {
        if normalized_type(target_type) == "longptr" {
            return None;
        }
        return Some(true);
    }

    let source_known = known_non_udt_type(
        project,
        source_module_index,
        source_module,
        source_type,
        host_profile,
    );
    let target_known = known_non_udt_type(
        project,
        target_module_index,
        target_module,
        target_type,
        host_profile,
    );
    (source_known && target_known).then_some(false)
}

fn udt_let_coercion_status(
    project: &Project,
    module_index: usize,
    module: &Module,
    target_type: Option<&str>,
    value_type: &str,
    host_profile: HostProfile,
) -> Option<&'static str> {
    let target_type = target_type?;
    let target_udt = user_type_owner_index(project, module_index, target_type);
    let value_udt = user_type_owner_index(project, module_index, value_type);
    match (target_udt, value_udt) {
        (Some(target_owner), Some(value_owner)) => {
            let same_type = target_owner == value_owner && canon(target_type) == canon(value_type);
            Some(if same_type {
                "compatible"
            } else {
                "invalid_udt_let_coercion"
            })
        }
        (Some(_), None) => {
            if is_variant_type(value_type) {
                Some("variant_or_host_dependent")
            } else if known_non_udt_type(project, module_index, module, value_type, host_profile) {
                Some("invalid_udt_let_coercion")
            } else {
                None
            }
        }
        (None, Some(_)) => {
            if known_non_udt_type(project, module_index, module, target_type, host_profile) {
                Some("invalid_udt_let_coercion")
            } else {
                None
            }
        }
        (None, None) => None,
    }
}

fn null_let_coercion_status(
    project: &Project,
    module_index: usize,
    module: &Module,
    target_array: Option<&ArraySymbolInfo>,
    target_type: Option<&str>,
    host_profile: HostProfile,
) -> Option<&'static str> {
    if let Some(target_array) = target_array {
        return (!target_array.is_fixed_size).then_some("null_let_coercion_runtime_error_13");
    }
    let target_type = target_type?;
    if normalized_type(target_type) == "variant" {
        return None;
    }
    if user_type_owner_index(project, module_index, target_type).is_some() {
        return Some("null_let_coercion_runtime_error_13");
    }
    known_non_udt_type(project, module_index, module, target_type, host_profile)
        .then_some("null_let_coercion_runtime_error_94")
}

fn object_let_coercion_status(
    project: &Project,
    context: AssignmentContext<'_>,
    target_type: Option<&str>,
    value_expression: &Expr,
    value_type: &str,
    host_profile: HostProfile,
) -> Option<&'static str> {
    let target_type = target_type?;
    if !is_object_declared_type(project, target_type, host_profile) {
        return None;
    }
    if is_variant_type(value_type)
        || is_explicit_nothing_expression(value_expression)
        || is_object_declared_type(project, value_type, host_profile)
    {
        return None;
    }
    if whole_array_info_for_expression(
        project,
        context.module_index,
        context.module,
        context.procedure,
        value_expression,
    )
    .is_some()
        || user_type_owner_index(project, context.module_index, value_type).is_some()
        || known_non_udt_type(
            project,
            context.module_index,
            context.module,
            value_type,
            host_profile,
        )
    {
        return Some("invalid_object_let_coercion");
    }
    None
}

fn is_object_declared_type(project: &Project, type_name: &str, host_profile: HostProfile) -> bool {
    normalized_type(type_name) == "object"
        || class_type_owner_index(project, type_name).is_some()
        || (host_profile == HostProfile::Excel && excel::is_known_type(type_name))
}

fn array_let_coercion_status(
    project: &Project,
    context: ArrayAssignmentContext<'_>,
    target_type: Option<&str>,
    value_type: &str,
    value_expression: &Expr,
    host_profile: HostProfile,
) -> Option<&'static str> {
    let module_index = context.assignment.module_index;
    let module = context.assignment.module;
    let target_array = context.target;
    let value_array = context.value;
    if let Some(target_array) = target_array {
        if target_array.is_fixed_size {
            if is_explicit_nothing_expression(value_expression)
                || is_object_declared_type(project, value_type, host_profile)
            {
                return None;
            }
            if value_array.is_some()
                || is_variant_type(value_type)
                || user_type_owner_index(project, module_index, value_type).is_some()
                || known_non_udt_type(project, module_index, module, value_type, host_profile)
            {
                return Some("invalid_array_let_coercion");
            }
            return None;
        }

        if let Some(value_array) = value_array {
            let target_is_byte = normalized_type(&target_array.element_type) == "byte";
            let value_is_byte = normalized_type(&value_array.element_type) == "byte";
            if target_is_byte || value_is_byte {
                return (target_is_byte && value_is_byte).then_some("compatible");
            }
            let target_identity = array_element_type_identity(
                project,
                module_index,
                module,
                &target_array.element_type,
                host_profile,
            );
            let value_identity = array_element_type_identity(
                project,
                module_index,
                module,
                &value_array.element_type,
                host_profile,
            );
            return match (target_identity, value_identity) {
                (Some(target), Some(value)) if target == value => Some("compatible"),
                (Some(_), Some(_)) => Some("invalid_array_let_coercion"),
                _ => None,
            };
        }

        if is_explicit_nothing_expression(value_expression) {
            return None;
        }
        if is_variant_type(value_type) {
            return Some("variant_or_host_dependent");
        }
        if is_object_declared_type(project, value_type, host_profile) {
            return None;
        }
        if normalized_type(&target_array.element_type) == "byte" {
            return is_numeric_boolean_date_type(value_type)
                .then_some("invalid_array_let_coercion");
        }
        if user_type_owner_index(project, module_index, value_type).is_some()
            || known_non_udt_type(project, module_index, module, value_type, host_profile)
        {
            return Some("invalid_array_let_coercion");
        }
        return None;
    }

    let value_array = value_array?;
    let target_type = target_type?;
    if normalized_type(target_type) == "variant" {
        let element_type = normalized_type(&value_array.element_type);
        if user_type_owner_index(project, module_index, &value_array.element_type).is_some()
            || element_type.starts_with("string*")
        {
            return Some("invalid_udt_let_coercion");
        }
        return Some("variant_or_host_dependent");
    }
    if normalized_type(&value_array.element_type) == "byte"
        || is_object_declared_type(project, target_type, host_profile)
    {
        return None;
    }
    if user_type_owner_index(project, module_index, target_type).is_some()
        || known_non_udt_type(project, module_index, module, target_type, host_profile)
    {
        return Some("invalid_array_let_coercion");
    }
    None
}

fn array_element_type_identity(
    project: &Project,
    module_index: usize,
    module: &Module,
    type_name: &str,
    host_profile: HostProfile,
) -> Option<String> {
    let type_name = effective_project_type_name(project, module_index, module, type_name);
    let key = normalized_type(&type_name);
    if matches!(key.as_str(), "longptr") || key.starts_with("string*") {
        return None;
    }
    if matches!(
        key.as_str(),
        "boolean"
            | "byte"
            | "integer"
            | "long"
            | "longlong"
            | "currency"
            | "single"
            | "double"
            | "date"
            | "string"
            | "variant"
            | "object"
    ) {
        return Some(format!("builtin:{key}"));
    }
    if let Some(owner) = user_type_owner_index(project, module_index, &type_name) {
        return Some(format!("udt:{owner}:{key}"));
    }
    if let Some(owner) = class_type_owner_index(project, &type_name) {
        return Some(format!("class:{owner}:{key}"));
    }
    if host_profile == HostProfile::Excel && excel::is_known_type(&type_name) {
        return Some(format!("host:{key}"));
    }
    None
}

fn is_numeric_boolean_date_type(type_name: &str) -> bool {
    matches!(
        normalized_type(type_name).as_str(),
        "boolean"
            | "byte"
            | "integer"
            | "long"
            | "longlong"
            | "longptr"
            | "currency"
            | "single"
            | "double"
            | "date"
    )
}

pub(crate) fn known_non_udt_type(
    project: &Project,
    module_index: usize,
    module: &Module,
    type_name: &str,
    host_profile: HostProfile,
) -> bool {
    let type_name = effective_project_type_name(project, module_index, module, type_name);
    if user_type_owner_index(project, module_index, &type_name).is_some() {
        return false;
    }
    let key = normalized_type(&type_name);
    matches!(
        key.as_str(),
        "boolean"
            | "byte"
            | "integer"
            | "long"
            | "longlong"
            | "longptr"
            | "currency"
            | "single"
            | "double"
            | "date"
            | "string"
            | "variant"
            | "object"
            | "null"
            | "nothing"
    ) || key.starts_with("string*")
        || class_type_owner_index(project, &type_name).is_some()
        || (host_profile == HostProfile::Excel && excel::is_known_type(&type_name))
}

fn intrinsic_return_type(name: &str) -> Option<&'static str> {
    Some(match name {
        "isempty" | "isnull" | "iserror" | "ismissing" | "isarray" | "isnumeric" | "isobject"
        | "isdate" => "Boolean",
        "cbool" => "Boolean",
        "cbyte" => "Byte",
        "cint" => "Integer",
        "clng" | "len" | "lenb" | "instr" | "instrrev" | "ubound" | "lbound" => "Long",
        "vartype" => "Integer",
        "typename" => "String",
        "csng" => "Single",
        "cdbl" => "Double",
        "ccur" => "Currency",
        "cdate" => "Date",
        "cdec" | "cverr" | "cvar" => "Variant",
        "cstr" | "lcase" | "ucase" | "trim" | "ltrim" | "rtrim" | "left" | "right" | "mid"
        | "replace" => "String",
        "iif" | "inputbox" | "msgbox" | "callbyname" => "Variant",
        _ => return None,
    })
}
fn canon(s: &str) -> String {
    s.trim_end_matches(['%', '&', '^', '@', '!', '#', '$'])
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{analyze::AnalysisOptions, model::SourceUnit};
    #[test]
    fn propagates_declared_assignment_types() {
        let a=crate::analyze(&[SourceUnit{name:"M.bas".into(),text:"Option Explicit\nPrivate amount As Long\nPrivate Const limit As Long = 10\nPublic Sub S()\nDim total As Long\ntotal = amount + 1\nEnd Sub\n".into()}],&AnalysisOptions::default()).unwrap();
        let f = a.type_facts.iter().find(|f| f.target == "total").unwrap();
        assert_eq!(f.target_type.as_deref(), Some("Long"));
        assert_eq!(f.value_type, "Long");
        assert_eq!(f.status, "compatible");
        assert!(
            a.data_flow
                .iter()
                .any(|x| x.transfer == "constant_initializer" && x.target == "limit")
        );
    }

    #[test]
    fn recognizes_longlong_caret_type_characters_on_names_and_literals() {
        let analysis = crate::analyze(
            &[SourceUnit {
                name: "LongLongSuffix.bas".into(),
                text: "Public Function ReadWide^()\nReadWide^ = 1^\nEnd Function\nPublic Sub Caller()\nDim local^\nlocal^ = ReadWide^()\nEnd Sub\n".into(),
            }],
            &AnalysisOptions::default(),
        )
        .unwrap();
        let function_result = analysis
            .type_facts
            .iter()
            .find(|fact| fact.target == "ReadWide^")
            .unwrap();
        assert_eq!(function_result.target_type.as_deref(), Some("LongLong"));
        assert_eq!(function_result.value_type, "LongLong");

        let local_result = analysis
            .type_facts
            .iter()
            .find(|fact| fact.target == "local^")
            .unwrap();
        assert_eq!(local_result.target_type.as_deref(), Some("LongLong"));
        assert_eq!(local_result.value_type, "LongLong");
    }

    #[test]
    fn follows_vba_operator_specific_declared_type_rules() {
        assert_eq!(binary_type("+", "Byte", "Byte"), "Byte");
        assert_eq!(binary_type("+", "Boolean", "Boolean"), "Integer");
        assert_eq!(binary_type("+", "Single", "Long"), "Double");
        assert_eq!(binary_type("+", "Currency", "Double"), "Currency");
        assert_eq!(binary_type("+", "String", "String * 12"), "String");
        assert_eq!(binary_type("/", "Integer", "Integer"), "Double");
        assert_eq!(binary_type("\\", "Double", "LongLong"), "Long");
        assert_eq!(binary_type("\\", "LongLong", "Integer"), "LongLong");
        assert_eq!(binary_type("Mod", "Byte", "Byte"), "Byte");
        assert_eq!(binary_type("^", "Long", "Long"), "Double");
        assert_eq!(binary_type("-", "Date", "Date"), "Double");
        assert_eq!(binary_type("*", "Currency", "Double"), "Double");
        assert_eq!(binary_type("And", "Boolean", "Boolean"), "Boolean");
        assert_eq!(binary_type("Or", "Byte", "Byte"), "Byte");
        assert_eq!(binary_type("Xor", "Double", "Integer"), "Long");
        assert_eq!(binary_type("Eqv", "LongLong", "Integer"), "LongLong");
        assert_eq!(binary_type("=", "Integer", "Integer"), "Boolean");
        assert_eq!(binary_type("=", "Variant", "Integer"), "Variant");
        assert_eq!(binary_type("Is", "Variant", "Object"), "Boolean");
        assert_eq!(logical_not_type("Byte"), "Byte");
        assert_eq!(logical_not_type("Single"), "Long");
        assert_eq!(logical_not_type("LongLong"), "LongLong");
        assert_eq!(unary_minus_type("Byte"), "Integer");

        let analysis = crate::analyze(
            &[SourceUnit {
                name: "Operators.bas".into(),
                text: "Public Sub Check()\nDim leftByte As Byte, rightByte As Byte\nDim sum As Byte\nsum = leftByte + rightByte\nDim quotient As Double\nquotient = leftByte / rightByte\nDim power As Double\npower = leftByte ^ rightByte\nDim complement As Byte\ncomplement = Not leftByte\nDim matches As Boolean\nmatches = leftByte = rightByte\nEnd Sub\n".into(),
            }],
            &AnalysisOptions::default(),
        )
        .unwrap();
        for (target, expected) in [
            ("sum", "Byte"),
            ("quotient", "Double"),
            ("power", "Double"),
            ("complement", "Byte"),
            ("matches", "Boolean"),
        ] {
            let fact = analysis
                .type_facts
                .iter()
                .find(|fact| fact.target.eq_ignore_ascii_case(target))
                .unwrap_or_else(|| {
                    panic!("missing type fact for {target}: {:?}", analysis.type_facts)
                });
            assert_eq!(fact.target_type.as_deref(), Some(expected), "{target}");
            assert_eq!(fact.value_type, expected, "{target}");
        }
    }

    #[test]
    fn infers_array_element_types_and_checks_known_index_rank() {
        let analysis = crate::analyze(
            &[SourceUnit {
                name: "ArrayIndex.bas".into(),
                text: "Public Sub Check()\nDim matrix(1 To 2, 1 To 2) As Long\nDim values(1 To 3) As Currency\nDim dynamicValues() As Long\nDim index As Long\nDim integerResult As Long\nDim currencyResult As Currency\nDim dynamicResult As Long\nDim wholeArray As Variant\nDim wrongRank As Variant\nDim namedIndex As Long\nintegerResult = matrix(index, index)\ncurrencyResult = values(index)\ndynamicResult = dynamicValues(index)\nwholeArray = values()\nwrongRank = matrix(index)\nnamedIndex = values(row:=index)\nmatrix(index) = integerResult\nEnd Sub\nPrivate Function ReadValue(ByRef items() As Long, ByVal index As Long) As Long\nReadValue = items(index)\nEnd Function\n".into(),
            }],
            &AnalysisOptions::default(),
        )
        .unwrap();

        for (target, expected) in [
            ("integerResult", "Long"),
            ("currencyResult", "Currency"),
            ("dynamicResult", "Long"),
            ("ReadValue", "Long"),
            ("wholeArray", "Array<Currency>"),
            ("wrongRank", "Variant"),
        ] {
            let fact = analysis
                .type_facts
                .iter()
                .find(|fact| fact.target.eq_ignore_ascii_case(target))
                .unwrap_or_else(|| {
                    panic!("missing type fact for {target}: {:?}", analysis.type_facts)
                });
            assert_eq!(fact.value_type, expected, "{target}");
        }

        let rank_errors = analysis
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "VBA2087")
            .collect::<Vec<_>>();
        assert_eq!(rank_errors.len(), 3, "{rank_errors:?}");
        assert_eq!(
            rank_errors
                .iter()
                .filter(|diagnostic| diagnostic.message.contains("rank 2")
                    && diagnostic.message.contains("1 arguments"))
                .count(),
            2,
            "{rank_errors:?}"
        );
        assert!(
            rank_errors
                .iter()
                .any(|diagnostic| diagnostic.message.contains("named arguments"))
        );

        let cross_module = crate::analyze(
            &[
                SourceUnit {
                    name: "SharedArrays.bas".into(),
                    text: "Public amounts(1 To 8) As Currency\n".into(),
                },
                SourceUnit {
                    name: "ArrayConsumer.bas".into(),
                    text: "Public Sub ReadAmount()\nDim index As Long\nDim amount As Currency\namount = amounts(index)\nEnd Sub\n".into(),
                },
            ],
            &AnalysisOptions::default(),
        )
        .unwrap();
        let public_array_read = cross_module
            .type_facts
            .iter()
            .find(|fact| fact.target == "amount")
            .unwrap();
        assert_eq!(public_array_read.value_type, "Currency");

        let class_array = crate::analyze(
            &[
                SourceUnit {
                    name: "Box.cls".into(),
                    text: "Public items(1 To 4) As Long\n".into(),
                },
                SourceUnit {
                    name: "BoxReader.bas".into(),
                    text: "Public Sub ReadItem(ByVal box As Box)\nDim index As Long\nDim value As Long\nvalue = box.items(index)\nEnd Sub\n".into(),
                },
            ],
            &AnalysisOptions::default(),
        )
        .unwrap();
        let class_element = class_array
            .type_facts
            .iter()
            .find(|fact| fact.target == "value")
            .unwrap();
        assert_eq!(class_element.value_type, "Long");
    }

    #[test]
    fn checks_lbound_ubound_arity_known_rank_and_scalar_arguments() {
        let analysis = crate::analyze(
            &[SourceUnit {
                name: "ArrayBounds.bas".into(),
                text: "Public Sub Check()\nDim matrix(1 To 2, 0 To 3) As Long\nDim dynamicValues() As Long\nDim maybeArray As Variant\nDim scalar As Long\nDim dimension As Long\nDim result As Long\nresult = LBound(matrix)\nresult = UBound(matrix, 2)\nresult = LBound(matrix, 0)\nresult = UBound(matrix, 3)\nresult = LBound(matrix, dimension)\nresult = UBound(matrix, &H2)\nresult = LBound(matrix, -1)\nresult = LBound(scalar)\nresult = LBound(dynamicValues, 2)\nresult = LBound(maybeArray, 2)\nresult = UBound()\nresult = UBound(matrix, 1, 2)\nEnd Sub\n".into(),
            }],
            &AnalysisOptions::default(),
        )
        .unwrap();

        let dimension_errors = analysis
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "VBA2089")
            .collect::<Vec<_>>();
        assert_eq!(dimension_errors.len(), 3, "{dimension_errors:?}");
        assert!(
            dimension_errors
                .iter()
                .any(|diagnostic| diagnostic.message.contains("dimension 0"))
        );
        assert!(
            dimension_errors
                .iter()
                .any(|diagnostic| diagnostic.message.contains("dimension 3"))
        );
        assert!(
            dimension_errors
                .iter()
                .any(|diagnostic| diagnostic.message.contains("dimension -1"))
        );

        let scalar_errors = analysis
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "VBA2090")
            .collect::<Vec<_>>();
        assert_eq!(scalar_errors.len(), 1, "{scalar_errors:?}");
        assert!(scalar_errors[0].message.contains("non-array type 'Long'"));

        let arity_errors = analysis
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "VBA2088")
            .collect::<Vec<_>>();
        assert_eq!(arity_errors.len(), 2, "{arity_errors:?}");
        assert!(
            arity_errors
                .iter()
                .all(|diagnostic| diagnostic.severity == crate::model::Severity::Error)
        );
        assert!(
            dimension_errors
                .iter()
                .all(|diagnostic| diagnostic.severity == crate::model::Severity::Warning)
        );
        assert!(
            scalar_errors
                .iter()
                .all(|diagnostic| diagnostic.severity == crate::model::Severity::Warning)
        );
        let result_fact = analysis
            .type_facts
            .iter()
            .find(|fact| fact.target.eq_ignore_ascii_case("result"))
            .unwrap();
        assert_eq!(result_fact.value_type, "Long");

        let shadowed_intrinsic = crate::analyze(
            &[SourceUnit {
                name: "ShadowedLBound.bas".into(),
                text: "Private Function LBound(ByVal value As Long) As Long\nLBound = value\nEnd Function\nPublic Sub Check()\nDim scalar As Long\nDim result As Long\nresult = LBound(scalar)\nEnd Sub\n".into(),
            }],
            &AnalysisOptions::default(),
        )
        .unwrap();
        assert!(
            !shadowed_intrinsic
                .diagnostics
                .iter()
                .any(|diagnostic| { matches!(diagnostic.code, "VBA2088" | "VBA2089" | "VBA2090") })
        );
    }

    #[test]
    fn validates_for_each_array_control_variables_udt_arrays_and_next_names() {
        let analysis = crate::analyze(
            &[SourceUnit {
                name: "ForEach.bas".into(),
                text: "Private Type Record\nvalue As Long\nEnd Type\nPublic Sub Walk()\nDim values(1 To 2) As Long\nDim records(1 To 2) As Record\nDim item As Long\nDim value As Variant\nFor Each item In values\nNext item\nFor Each value In values\nNext value\nFor Each item In records\nNext other\nFor Each value In records\nNext value\nEnd Sub\n".into(),
            }],
            &AnalysisOptions::default(),
        )
        .unwrap();

        let control_errors = analysis
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "VBA2092")
            .collect::<Vec<_>>();
        assert_eq!(control_errors.len(), 2, "{control_errors:?}");
        assert!(
            control_errors
                .iter()
                .all(|diagnostic| diagnostic.message.contains("requires Variant"))
        );

        let udt_array_errors = analysis
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "VBA2093")
            .collect::<Vec<_>>();
        assert_eq!(udt_array_errors.len(), 2, "{udt_array_errors:?}");

        let next_errors = analysis
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "VBA2091")
            .collect::<Vec<_>>();
        assert_eq!(next_errors.len(), 1, "{next_errors:?}");
        assert!(
            next_errors[0].message.contains("item") && next_errors[0].message.contains("other")
        );

        let for_counters = crate::analyze(
            &[SourceUnit {
                name: "ForCounters.bas".into(),
                text: "Public Sub Count()\nDim index As Long\nDim enabled As Boolean\nDim values(1 To 2) As Long\nFor index = 1 To 3\nNext index\nFor enabled = 1 To 2\nNext enabled\nFor values(1) = 1 To 2\nNext values(1)\nFor index = 1 To 2\nNext other\nEnd Sub\n".into(),
            }],
            &AnalysisOptions::default(),
        )
        .unwrap();
        let counter_errors = for_counters
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "VBA2094")
            .collect::<Vec<_>>();
        assert_eq!(counter_errors.len(), 2, "{counter_errors:?}");
        assert!(counter_errors[0].message.contains("Boolean"));
        assert!(
            counter_errors
                .iter()
                .any(|diagnostic| diagnostic.message.contains("array element"))
        );
        let next_errors = for_counters
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "VBA2091")
            .collect::<Vec<_>>();
        assert_eq!(next_errors.len(), 1, "{next_errors:?}");
    }

    #[test]
    fn validates_nested_loop_variables_from_multi_counter_next_in_inner_to_outer_order() {
        let analysis = crate::analyze(
            &[SourceUnit {
                name: "NestedLoops.bas".into(),
                text: "Public Sub Walk()\nDim values(1 To 2) As Long\nDim outer As Long\nDim item As Variant\nFor outer = 1 To 2\nFor Each item In values\nDebug.Print item\nNext item, outer\nEnd Sub\n".into(),
            }],
            &AnalysisOptions::default(),
        )
        .unwrap();
        assert!(
            !analysis
                .diagnostics
                .iter()
                .any(|diagnostic| { matches!(diagnostic.code, "VBA1023" | "VBA2091") }),
            "{:?}",
            analysis.diagnostics
        );
        assert_eq!(
            analysis.control_flow[0]
                .nodes
                .iter()
                .filter(|node| node.kind == "loop_test")
                .count(),
            2
        );
        assert!(
            analysis.control_flow[0].complete,
            "{:?}",
            analysis.control_flow[0]
        );
    }

    #[test]
    fn checks_for_bounds_and_step_against_known_noncoercible_types() {
        let analysis = crate::analyze(
            &[SourceUnit {
                name: "ForBounds.bas".into(),
                text: "Private Type Record\nvalue As Long\nEnd Type\nPublic Sub Walk()\nDim values(1 To 2) As Long\nDim record As Record\nDim wide As LongLong\nDim index As Long\nFor index = values To 2\nNext index\nFor index = 1 To record\nNext index\nFor index = 1 To 2 Step values\nNext index\nFor index = Nothing To 2\nNext index\nFor index = wide To 2\nNext index\nFor index = \"1\" To \"2\"\nNext index\nFor index = 1 To 2\nNext index\nEnd Sub\n".into(),
            }],
            &AnalysisOptions::default(),
        )
        .unwrap();
        let errors = analysis
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "VBA2095")
            .collect::<Vec<_>>();
        assert_eq!(errors.len(), 5, "{errors:?}");
        assert!(
            errors
                .iter()
                .any(|diagnostic| diagnostic.message.contains("For start"))
        );
        assert!(
            errors
                .iter()
                .any(|diagnostic| diagnostic.message.contains("For end"))
        );
        assert!(
            errors
                .iter()
                .any(|diagnostic| diagnostic.message.contains("For Step"))
        );
        assert!(
            errors
                .iter()
                .any(|diagnostic| diagnostic.message.contains("LongLong"))
        );
        assert!(
            errors
                .iter()
                .all(|diagnostic| diagnostic.severity == crate::model::Severity::Error)
        );
    }

    #[test]
    fn warns_for_unparseable_string_literals_in_for_bounds() {
        let analysis = crate::analyze(
            &[SourceUnit {
                name: "ForStringBounds.bas".into(),
                text: "Public Sub Walk()\nDim index As Long\nFor index = \"words\" To 2\nNext index\nFor index = 1 To \"letters\"\nNext index\nFor index = 1 To 2 Step \"unknown\"\nNext index\nFor index = \"1e2\" To \"3\"\nNext index\nFor index = \"12 kr\" To 3\nNext index\nEnd Sub\n".into(),
            }],
            &AnalysisOptions::default(),
        )
        .unwrap();
        let warnings = analysis
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "VBA2135")
            .collect::<Vec<_>>();
        assert_eq!(warnings.len(), 3, "{:?}", analysis.diagnostics);
        let mut lines = warnings
            .iter()
            .map(|diagnostic| diagnostic.span.line)
            .collect::<Vec<_>>();
        lines.sort_unstable();
        assert_eq!(lines, [3, 5, 7]);
        assert!(warnings.iter().all(|diagnostic| {
            diagnostic.severity == crate::model::Severity::Warning
                && diagnostic.message.contains("runtime error 13")
        }));
        assert!(!analysis.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "VBA2135" && matches!(diagnostic.span.line, 9 | 11)
        }));
    }

    #[test]
    fn infers_indexed_default_member_types_from_exported_member_attributes() {
        let analysis = crate::analyze(
            &[
                SourceUnit {
                    name: "Indexed.cls".into(),
                    text: "Public Property Get Item(ByVal index As Long) As String\nItem = CStr(index)\nEnd Property\nAttribute Item.VB_UserMemId = 0\nPublic Property Let Item(ByVal index As Long, ByVal value As String)\nEnd Property\nAttribute Item.VB_UserMemId = 0\n".into(),
                },
                SourceUnit {
                    name: "Reader.bas".into(),
                    text: "Private values As Indexed\nPublic Sub Read()\nDim item As String\nDim wrongArguments As Variant\nitem = values(1)\nvalues(2) = \"updated\"\nwrongArguments = values(1, 2)\nEnd Sub\n".into(),
                },
            ],
            &AnalysisOptions::default(),
        )
        .unwrap();
        let item = analysis
            .type_facts
            .iter()
            .find(|fact| fact.target == "item")
            .unwrap();
        assert_eq!(item.value_type, "String");
        assert_eq!(item.status, "compatible");
        let default_property_write = analysis
            .type_facts
            .iter()
            .find(|fact| fact.target == "values(2)")
            .unwrap();
        assert_eq!(default_property_write.value_type, "String");
        assert_eq!(default_property_write.status, "compatible");
        let wrong_arguments = analysis
            .type_facts
            .iter()
            .find(|fact| fact.target == "wrongArguments")
            .unwrap();
        assert_eq!(wrong_arguments.value_type, "host-dependent Variant");
        assert!(
            analysis
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "VBA2111")
        );
    }

    #[test]
    fn evaluates_simple_class_values_through_zero_argument_default_getters() {
        let analysis = crate::analyze(
            &[
                SourceUnit {
                    name: "Scalar.cls".into(),
                    text: "Private stored As String\nPublic Property Get Value() As String\nValue = stored\nEnd Property\nAttribute Value.VB_UserMemId = 0\n".into(),
                },
                SourceUnit {
                    name: "Reader.bas".into(),
                    text: "Private item As Scalar\nPublic Sub Read()\nDim value As String\nDim copy As Scalar\nvalue = item & \"!\"\nSet copy = item\nEnd Sub\n".into(),
                },
            ],
            &AnalysisOptions::default(),
        )
        .unwrap();
        let value = analysis
            .type_facts
            .iter()
            .find(|fact| fact.target == "value")
            .unwrap();
        assert_eq!(value.value_type, "String");
        assert_eq!(value.status, "compatible");
        let copy = analysis
            .type_facts
            .iter()
            .find(|fact| fact.target == "copy")
            .unwrap();
        assert_eq!(copy.value_type, "Scalar");
        assert_eq!(copy.status, "compatible");
    }

    #[test]
    fn resolves_nested_and_indexed_udt_fields() {
        let analysis = crate::analyze(
            &[
                SourceUnit {
                    name: "PostalTypes.bas".into(),
                    text: "Public Type Postal\nCode As Long\nEnd Type\n".into(),
                },
                SourceUnit {
                    name: "CustomerTypes.bas".into(),
                    text: "Public Type Customer\nAddress As Postal\nPrices(1 To 4) As Currency\nEnd Type\n".into(),
                },
                SourceUnit {
                    name: "CustomerReader.bas".into(),
                    text: "Public Sub ReadCustomer()\nDim customer As Customer\nDim postalCode As Long\nDim price As Currency\nDim invalidIndex As Variant\npostalCode = customer.Address.Code\nprice = customer.Prices(1)\ninvalidIndex = customer.Prices(1, 2)\nEnd Sub\n".into(),
                },
            ],
            &AnalysisOptions::default(),
        )
        .unwrap();
        let postal_code = analysis
            .type_facts
            .iter()
            .find(|fact| fact.target == "postalCode")
            .unwrap();
        assert_eq!(postal_code.value_type, "Long");
        let price = analysis
            .type_facts
            .iter()
            .find(|fact| fact.target == "price")
            .unwrap();
        assert_eq!(price.value_type, "Currency");
        let index_errors = analysis
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "VBA2087")
            .collect::<Vec<_>>();
        assert_eq!(index_errors.len(), 1, "{index_errors:?}");
        assert!(index_errors[0].message.contains("rank 1"));
    }

    #[test]
    fn binds_with_dot_members_to_nested_udt_bases() {
        let analysis = crate::analyze(
            &[SourceUnit {
                name: "WithUdt.bas".into(),
                text: "Private Type Postal\nCode As Long\nEnd Type\nPrivate Type Customer\nAddress As Postal\nEnd Type\nPublic Sub Update()\nDim customer As Customer\nDim code As Long\nWith customer\nWith .Address\n.Code = 7\ncode = .Code\nEnd With\nEnd With\nEnd Sub\n".into(),
            }],
            &AnalysisOptions::default(),
        )
        .unwrap();
        let code_facts = analysis
            .type_facts
            .iter()
            .filter(|fact| fact.target.eq_ignore_ascii_case("code") || fact.target == ".Code")
            .collect::<Vec<_>>();
        assert_eq!(code_facts.len(), 2, "{code_facts:?}");
        assert!(
            code_facts
                .iter()
                .all(|fact| fact.target_type.as_deref() == Some("Long")),
            "{code_facts:?}"
        );
        assert!(code_facts.iter().any(|fact| fact.value_type == "Integer"));
        assert!(code_facts.iter().any(|fact| fact.value_type == "Long"));
        assert!(
            !analysis
                .diagnostics
                .iter()
                .any(|diagnostic| { diagnostic.code == "VBA2003" || diagnostic.code == "VBA2013" })
        );
    }

    #[test]
    fn validates_with_block_variable_types_and_binds_dot_members() {
        let analysis = crate::analyze(
            &[
                SourceUnit {
                    name: "RecordTypes.bas".into(),
                    text: "Public Type Record\nValue As Long\nEnd Type\n".into(),
                },
                SourceUnit {
                    name: "Box.cls".into(),
                    text: "Public Value As Currency\n".into(),
                },
                SourceUnit {
                    name: "WithReader.bas".into(),
                    text: "Public Sub Check()\nDim amount As Long\nDim text As String\nDim record As Record\nDim box As Box\nDim dynamic As Variant\nDim recordResult As Long\nDim boxResult As Currency\nWith amount\n.Value = 1\nEnd With\nWith text\n.Value = \"x\"\nEnd With\nWith dynamic\n.Value = 1\nEnd With\nWith record\n.Value = 1\nrecordResult = .Value\nEnd With\nWith box\nboxResult = .Value\nEnd With\nEnd Sub\n".into(),
                },
            ],
            &AnalysisOptions::default(),
        )
        .unwrap();
        let invalid = analysis
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "VBA1039")
            .collect::<Vec<_>>();
        assert_eq!(invalid.len(), 2, "{invalid:?}");
        assert!(
            invalid
                .iter()
                .any(|diagnostic| diagnostic.message.contains("Long"))
        );
        assert!(
            invalid
                .iter()
                .any(|diagnostic| diagnostic.message.contains("String"))
        );
        assert!(
            analysis
                .type_facts
                .iter()
                .any(|fact| { fact.target == "recordResult" && fact.value_type == "Long" })
        );
        assert!(
            analysis
                .type_facts
                .iter()
                .any(|fact| { fact.target == "boxResult" && fact.value_type == "Currency" })
        );
    }
}
