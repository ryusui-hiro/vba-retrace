//! Conservative expression and assignment type propagation.

use crate::host::{HostProfile, excel};
use crate::model::{
    Declaration, Expr, LiteralKind, Module, Procedure, Project, Statement, TypeFact,
};

pub fn infer_assignment_types(project: &Project, host_profile: HostProfile) -> Vec<TypeFact> {
    let mut out = Vec::new();
    for module in &project.modules {
        for procedure in &module.procedures {
            visit_statements(
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

fn visit_statements(
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
            let target_type = symbol_type(module, procedure, target_name);
            let value_type = infer_expr(module, procedure, value, host_profile);
            let status = assignment_status(target_type.as_deref(), &value_type);
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
        visit_statements(module, procedure, &statement.children, host_profile, out);
    }
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

fn symbol_type(module: &Module, procedure: &Procedure, name: &str) -> Option<String> {
    if let Some(p) = module
        .procedures
        .iter()
        .find(|p| p.name.eq_ignore_ascii_case(name))
    {
        return Some(
            p.return_type
                .clone()
                .unwrap_or_else(|| suffix_type(&p.name).unwrap_or_else(|| "Variant".into())),
        );
    }
    if let Some(parameter) = procedure
        .parameters
        .iter()
        .find(|p| p.name.eq_ignore_ascii_case(name))
    {
        return Some(
            parameter.type_name.clone().unwrap_or_else(|| {
                suffix_type(&parameter.name).unwrap_or_else(|| "Variant".into())
            }),
        );
    }
    if let Some(decl) = find_local(&procedure.statements, name) {
        return Some(declaration_type(decl));
    }
    module
        .declarations
        .iter()
        .find(|d| {
            d.name.eq_ignore_ascii_case(name)
                && !matches!(d.kind.as_str(), "user_type" | "enum" | "field")
        })
        .map(declaration_type)
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
fn declaration_type(d: &Declaration) -> String {
    d.type_name
        .clone()
        .unwrap_or_else(|| suffix_type(&d.name).unwrap_or_else(|| "Variant".into()))
}
fn suffix_type(name: &str) -> Option<String> {
    Some(
        match name.chars().last()? {
            '%' => "Integer",
            '&' => "Long",
            '@' => "Currency",
            '!' => "Single",
            '#' => "Double",
            '$' => "String",
            _ => return None,
        }
        .into(),
    )
}

fn infer_expr(
    module: &Module,
    procedure: &Procedure,
    expr: &Expr,
    host_profile: HostProfile,
) -> String {
    match expr {
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
            if matches!(low.as_str(), "nothing" | "me") {
                return "Object".into();
            }
            symbol_type(module, procedure, name).unwrap_or_else(|| "Variant".into())
        }
        Expr::Group(value, _) => infer_expr(module, procedure, value, host_profile),
        Expr::Unary { op, value, .. } => {
            if op.eq_ignore_ascii_case("not") {
                "Boolean".into()
            } else if op.eq_ignore_ascii_case("new") {
                "host-dependent Object".into()
            } else if op.eq_ignore_ascii_case("addressof") {
                "LongPtr".into()
            } else {
                infer_expr(module, procedure, value, host_profile)
            }
        }
        Expr::Member { .. } => "host-dependent Variant".into(),
        Expr::NamedArgument { value, .. } => infer_expr(module, procedure, value, host_profile),
        Expr::Unknown(..) => "Variant".into(),
        Expr::Binary {
            left, op, right, ..
        } => {
            let a = infer_expr(module, procedure, left, host_profile);
            let b = infer_expr(module, procedure, right, host_profile);
            binary_type(op, &a, &b)
        }
        Expr::Call { callee, args, .. } => {
            let name = match callee.as_ref() {
                Expr::Identifier(n, _) => canon(n),
                Expr::Member { member, .. } => canon(member),
                _ => String::new(),
            };
            if let Some(ty) = intrinsic_return_type(&name) {
                return ty.into();
            }
            if name == "iif" && args.len() >= 3 {
                let a = infer_expr(module, procedure, &args[1], host_profile);
                let b = infer_expr(module, procedure, &args[2], host_profile);
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
                    .unwrap_or_else(|| suffix_type(&p.name).unwrap_or_else(|| "Variant".into()));
            }
            "host-dependent Variant".into()
        }
    }
}

fn binary_type(op: &str, a: &str, b: &str) -> String {
    let op = canon(op);
    if matches!(
        op.as_str(),
        "=" | "<>" | "<" | ">" | "<=" | ">=" | "is" | "like"
    ) {
        return "Boolean".into();
    }
    if op == "&" {
        return "String".into();
    }
    if matches!(op.as_str(), "and" | "or" | "xor" | "eqv" | "imp") {
        return if a == "Boolean" && b == "Boolean" {
            "Boolean".into()
        } else {
            "Long".into()
        };
    }
    if matches!(op.as_str(), "+" | "-" | "*" | "/" | "\\" | "mod" | "^") {
        if a == "String" && b == "String" && op == "+" {
            return "String".into();
        }
        return numeric_widen(a, b).unwrap_or_else(|| "Variant".into());
    }
    "Variant".into()
}
fn numeric_widen(a: &str, b: &str) -> Option<String> {
    let order = [
        "Byte", "Integer", "Long", "LongLong", "Single", "Double", "Currency", "Decimal",
    ];
    let ai = order.iter().position(|x| x.eq_ignore_ascii_case(a))?;
    let bi = order.iter().position(|x| x.eq_ignore_ascii_case(b))?;
    Some(order[ai.max(bi)].into())
}
fn numeric_literal_type(text: &str) -> String {
    if let Some(ty) = suffix_type(text) {
        return ty;
    }
    let number = text.trim_end_matches(['%', '&', '@', '!', '#']);
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
fn intrinsic_return_type(name: &str) -> Option<&'static str> {
    Some(match name {
        "cbool" => "Boolean",
        "cbyte" => "Byte",
        "cint" => "Integer",
        "clng" | "len" | "instr" | "ubound" | "lbound" => "Long",
        "csng" => "Single",
        "cdbl" => "Double",
        "ccur" => "Currency",
        "cdate" => "Date",
        "cstr" | "lcase" | "ucase" | "trim" | "left" | "right" | "mid" => "String",
        "iif" | "inputbox" | "msgbox" => "Variant",
        _ => return None,
    })
}
fn canon(s: &str) -> String {
    s.trim_end_matches(['%', '&', '@', '!', '#', '$'])
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use crate::{analyze::AnalysisOptions, model::SourceUnit};
    #[test]
    fn propagates_declared_assignment_types() {
        let a=crate::analyze(&[SourceUnit{name:"M.bas".into(),text:"Option Explicit\nPrivate amount As Long\nPublic Sub S()\nDim total As Long\ntotal = amount + 1\nEnd Sub\n".into()}],&AnalysisOptions::default()).unwrap();
        let f = a.type_facts.iter().find(|f| f.target == "total").unwrap();
        assert_eq!(f.target_type.as_deref(), Some("Long"));
        assert_eq!(f.value_type, "Long");
        assert_eq!(f.status, "compatible");
    }
}
