//! Conservative address-reference candidates for stored SpreadsheetML formulas.
//!
//! This is deliberately not a formula evaluator or a complete Excel formula
//! parser. It skips quoted text and structured-reference brackets, and records
//! only cell, rectangular cell-range, whole-row, and whole-column operands.

use crate::model::{
    CellRangeBounds, WorkbookCellInfo, WorkbookDefinedNameInfo, WorkbookFormulaReferenceInfo,
    WorkbookSheetInfo, WorkbookTableInfo,
};
use std::collections::{BTreeMap, HashMap};

const MAX_ROW: u32 = 1_048_576;
const MAX_COLUMN: u32 = 16_384;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Endpoint {
    Cell(u32, u32),
    Column(u32),
    Row(u32),
}

#[derive(Clone, Debug)]
struct ParsedArea {
    end: usize,
    bounds: CellRangeBounds,
    kind: &'static str,
}

#[derive(Clone, Copy)]
struct SharedFormulaMaster {
    cell_index: usize,
    bounds: CellRangeBounds,
}

#[derive(Clone, Copy)]
struct FormulaNameEnvironment<'a> {
    current_sheet_index: usize,
    sheets: &'a [WorkbookSheetInfo],
    defined_names: &'a [FormulaNameMetadata],
    defined_names_by_name: &'a HashMap<String, Vec<usize>>,
}

#[derive(Clone)]
struct FormulaNameMetadata {
    name: String,
    local_sheet_id: Option<u32>,
    local_sheet_name: Option<String>,
    scope_resolution: String,
}

fn formula_name_metadata(defined_names: &[WorkbookDefinedNameInfo]) -> Vec<FormulaNameMetadata> {
    defined_names
        .iter()
        .map(|defined_name| FormulaNameMetadata {
            name: defined_name.name.clone(),
            local_sheet_id: defined_name.local_sheet_id,
            local_sheet_name: defined_name.local_sheet_name.clone(),
            scope_resolution: defined_name.scope_resolution.clone(),
        })
        .collect()
}

struct FormulaNameToken<'a> {
    name: &'a str,
    start: usize,
    end: usize,
    qualified: bool,
    external: bool,
    callable: bool,
}

/// Attach formula reference candidates and links to populated cells. Both
/// candidate and link counts are capped independently at project scope.
pub(crate) fn populate_formula_reference_candidates(
    cells: &mut [WorkbookCellInfo],
    sheets: &[WorkbookSheetInfo],
    defined_names: &mut [WorkbookDefinedNameInfo],
    tables: &[WorkbookTableInfo],
    max_references: usize,
    max_cell_links: usize,
    cell_inventory_truncated: bool,
) {
    let formula_name_metadata = formula_name_metadata(defined_names);
    let defined_names_by_name = index_defined_names(&formula_name_metadata);
    let mut possible_masters = HashMap::<(usize, u32), Vec<SharedFormulaMaster>>::new();
    for (cell_index, cell) in cells.iter().enumerate() {
        if !is_shared_formula(cell) {
            continue;
        }
        let (Some(shared_index), Some(formula), Some(reference), Some(row), Some(column)) = (
            cell.formula_shared_index,
            cell.formula.as_deref(),
            cell.formula_ref.as_deref(),
            cell.row,
            cell.column,
        ) else {
            continue;
        };
        if formula.is_empty() {
            continue;
        }
        let Some(bounds) = parse_shared_formula_bounds(reference) else {
            continue;
        };
        if !bounds_contains(bounds, row, column) {
            continue;
        }
        possible_masters
            .entry((cell.sheet_index, shared_index))
            .or_default()
            .push(SharedFormulaMaster { cell_index, bounds });
    }
    let shared_masters = possible_masters
        .into_iter()
        .filter_map(|(group, masters)| (masters.len() == 1).then_some((group, masters[0])))
        .collect::<HashMap<_, _>>();

    let mut remaining_references = max_references;
    for (cell_index, cell) in cells.iter_mut().enumerate() {
        if is_shared_formula(cell) {
            let Some(shared_index) = cell.formula_shared_index else {
                cell.formula_reference_resolution = "shared_formula_group_unresolved".into();
                continue;
            };
            if shared_masters
                .get(&(cell.sheet_index, shared_index))
                .is_none_or(|master| master.cell_index != cell_index)
            {
                cell.formula_reference_resolution = if cell
                    .formula
                    .as_deref()
                    .is_some_and(|formula| !formula.is_empty())
                {
                    "shared_formula_group_unresolved".into()
                } else {
                    "shared_formula_text_absent_unresolved".into()
                };
                continue;
            }
        }
        let Some(formula) = cell.formula.as_deref() else {
            cell.formula_reference_resolution = "no_formula".into();
            continue;
        };
        if formula.is_empty() {
            cell.formula_reference_resolution = if cell
                .formula_type
                .as_deref()
                .is_some_and(|kind| kind.eq_ignore_ascii_case("shared"))
            {
                "shared_formula_text_absent_unresolved".into()
            } else {
                "formula_text_empty_unresolved".into()
            };
            continue;
        }
        let (mut references, mut truncated) =
            scan_formula_references(formula, cell.sheet_index, sheets, remaining_references);
        remaining_references = remaining_references.saturating_sub(references.len());
        let (defined_name_references, names_truncated) = scan_formula_defined_names(
            formula,
            FormulaNameEnvironment {
                current_sheet_index: cell.sheet_index,
                sheets,
                defined_names: &formula_name_metadata,
                defined_names_by_name: &defined_names_by_name,
            },
            &references,
            remaining_references,
        );
        remaining_references = remaining_references.saturating_sub(defined_name_references.len());
        references.extend(defined_name_references);
        let (table_references, tables_truncated) = scan_structured_table_references(
            formula,
            cell.sheet_index,
            cell.row,
            cell.column,
            tables,
            remaining_references,
        );
        remaining_references = remaining_references.saturating_sub(table_references.len());
        references.extend(table_references);
        let (dynamic_references, dynamic_truncated) =
            scan_dynamic_reference_functions(formula, remaining_references);
        remaining_references = remaining_references.saturating_sub(dynamic_references.len());
        references.extend(dynamic_references);
        references.sort_by_key(|reference| (reference.start_byte, reference.end_byte));
        truncated |= names_truncated || tables_truncated || dynamic_truncated;
        cell.formula_reference_resolution = if truncated {
            "reference_candidate_limit_truncated".into()
        } else {
            "partial_formula_reference_scan".into()
        };
        cell.formula_reference_source_cell_index = Some(cell_index);
        cell.formula_reference_candidates = references;
        cell.formula_references_truncated = truncated;
    }

    for follower_index in 0..cells.len() {
        if !is_shared_formula(&cells[follower_index]) {
            continue;
        }
        let cell = &cells[follower_index];
        let Some(shared_index) = cell.formula_shared_index else {
            continue;
        };
        let Some(master) = shared_masters
            .get(&(cell.sheet_index, shared_index))
            .copied()
        else {
            continue;
        };
        if master.cell_index == follower_index {
            continue;
        }
        let (Some(source_row), Some(source_column), Some(target_row), Some(target_column)) = (
            cells[master.cell_index].row,
            cells[master.cell_index].column,
            cell.row,
            cell.column,
        ) else {
            continue;
        };
        if !bounds_contains(master.bounds, target_row, target_column) {
            cells[follower_index].formula_reference_resolution =
                "shared_formula_follower_outside_master_range_unresolved".into();
            continue;
        }
        let row_delta = i64::from(target_row) - i64::from(source_row);
        let column_delta = i64::from(target_column) - i64::from(source_column);
        let source_references = cells[master.cell_index]
            .formula_reference_candidates
            .clone();
        let source_truncated = cells[master.cell_index].formula_references_truncated;
        let mut references = Vec::new();
        let mut translation_unresolved = false;
        for reference in source_references {
            if remaining_references == 0 {
                cells[follower_index].formula_references_truncated = true;
                break;
            }
            let translated =
                translate_shared_formula_reference(reference, row_delta, column_delta, tables);
            translation_unresolved |= translated.cell_range_bounds.is_none()
                && !translated.reference_kind.starts_with("defined_name_")
                && translated.reference_kind != "dynamic_reference_function_candidate";
            references.push(translated);
            remaining_references = remaining_references.saturating_sub(1);
        }
        let was_truncated = cells[follower_index].formula_references_truncated || source_truncated;
        cells[follower_index].formula_reference_source_cell_index = Some(master.cell_index);
        cells[follower_index].formula_reference_candidates = references;
        cells[follower_index].formula_references_truncated = was_truncated;
        cells[follower_index].formula_reference_resolution = if was_truncated {
            "shared_formula_reference_candidate_limit_truncated".into()
        } else if translation_unresolved {
            "shared_formula_translation_partially_unresolved".into()
        } else {
            "shared_formula_relative_candidates_translated".into()
        };
    }

    populate_defined_name_formula_references(
        defined_names,
        sheets,
        tables,
        &formula_name_metadata,
        &defined_names_by_name,
        &mut remaining_references,
    );

    let mut cells_by_row = BTreeMap::<(usize, u32), Vec<(u32, usize)>>::new();
    for (cell_index, cell) in cells.iter().enumerate() {
        let (Some(row), Some(column)) = (cell.row, cell.column) else {
            continue;
        };
        cells_by_row
            .entry((cell.sheet_index, row))
            .or_default()
            .push((column, cell_index));
    }
    for columns in cells_by_row.values_mut() {
        columns.sort_unstable();
    }

    let mut links = 0usize;
    let mut exhausted = false;
    for formula_cell in cells.iter_mut() {
        link_formula_references_to_cells(
            &mut formula_cell.formula_reference_candidates,
            &cells_by_row,
            max_cell_links,
            &mut links,
            &mut exhausted,
            cell_inventory_truncated,
        );
    }
    for defined_name in defined_names.iter_mut() {
        link_formula_references_to_cells(
            &mut defined_name.formula_reference_candidates,
            &cells_by_row,
            max_cell_links,
            &mut links,
            &mut exhausted,
            cell_inventory_truncated,
        );
    }
}

fn link_formula_references_to_cells(
    references: &mut [WorkbookFormulaReferenceInfo],
    cells_by_row: &BTreeMap<(usize, u32), Vec<(u32, usize)>>,
    max_cell_links: usize,
    links: &mut usize,
    exhausted: &mut bool,
    cell_inventory_truncated: bool,
) {
    for reference in references {
        if !can_link_sheet(&reference.sheet_resolution) {
            continue;
        }
        let (Some(sheet_index), Some(bounds)) =
            (reference.sheet_index_candidate, reference.cell_range_bounds)
        else {
            continue;
        };
        if *exhausted {
            reference.workbook_cell_matches_truncated = true;
            continue;
        }
        reference.workbook_cell_matches_truncated = cell_inventory_truncated;

        let rows =
            cells_by_row.range((sheet_index, bounds.first_row)..=(sheet_index, bounds.last_row));
        'matching_rows: for ((_, _row), columns) in rows {
            let first = columns.partition_point(|(column, _)| *column < bounds.first_column);
            for (column, cell_index) in &columns[first..] {
                if *column > bounds.last_column {
                    break;
                }
                if *links >= max_cell_links {
                    reference.workbook_cell_matches_truncated = true;
                    *exhausted = true;
                    break 'matching_rows;
                }
                reference.workbook_cell_indices.push(*cell_index);
                *links += 1;
            }
        }
    }
}

fn populate_defined_name_formula_references(
    defined_names: &mut [WorkbookDefinedNameInfo],
    sheets: &[WorkbookSheetInfo],
    tables: &[WorkbookTableInfo],
    formula_names: &[FormulaNameMetadata],
    formula_names_by_name: &HashMap<String, Vec<usize>>,
    remaining_references: &mut usize,
) {
    for defined_name in defined_names {
        if defined_name.formula.is_empty() {
            defined_name.formula_reference_resolution =
                "defined_name_formula_empty_unresolved".into();
            continue;
        }
        let current_sheet_index = if defined_name.scope_resolution == "sheet_scope_candidate" {
            defined_name
                .local_sheet_id
                .map_or(usize::MAX, |index| index as usize)
        } else {
            usize::MAX
        };
        let (mut references, mut truncated) = scan_formula_references(
            &defined_name.formula,
            current_sheet_index,
            sheets,
            *remaining_references,
        );
        *remaining_references = remaining_references.saturating_sub(references.len());
        let (defined_name_references, names_truncated) = scan_formula_defined_names(
            &defined_name.formula,
            FormulaNameEnvironment {
                current_sheet_index,
                sheets,
                defined_names: formula_names,
                defined_names_by_name: formula_names_by_name,
            },
            &references,
            *remaining_references,
        );
        *remaining_references = remaining_references.saturating_sub(defined_name_references.len());
        references.extend(defined_name_references);
        let (table_references, tables_truncated) = scan_structured_table_references(
            &defined_name.formula,
            current_sheet_index,
            None,
            None,
            tables,
            *remaining_references,
        );
        *remaining_references = remaining_references.saturating_sub(table_references.len());
        references.extend(table_references);
        let (dynamic_references, dynamic_truncated) =
            scan_dynamic_reference_functions(&defined_name.formula, *remaining_references);
        *remaining_references = remaining_references.saturating_sub(dynamic_references.len());
        references.extend(dynamic_references);
        references.sort_by_key(|reference| (reference.start_byte, reference.end_byte));
        truncated |= names_truncated || tables_truncated || dynamic_truncated;
        for reference in &mut references {
            if is_address_reference_kind(&reference.reference_kind)
                && !reference_address_is_absolute(&reference.reference)
            {
                reference.sheet_index_candidate = None;
                reference.sheet_name_candidate = None;
                reference.cell_range_bounds = None;
                reference.workbook_cell_indices.clear();
                reference.sheet_resolution =
                    "relative_defined_name_formula_reference_unresolved".into();
            }
        }
        defined_name.formula_reference_resolution = if truncated {
            "reference_candidate_limit_truncated".into()
        } else {
            "partial_formula_reference_scan".into()
        };
        defined_name.formula_reference_candidates = references;
        defined_name.formula_references_truncated = truncated;
    }
}

fn is_address_reference_kind(kind: &str) -> bool {
    matches!(
        kind,
        "cell_reference"
            | "cell_range_reference"
            | "whole_row_reference"
            | "whole_column_reference"
    )
}

fn reference_address_is_absolute(reference: &str) -> bool {
    let address_start = reference.rfind('!').map_or(0, |bang| bang + 1);
    let address = &reference[address_start..];
    let mut endpoints = address.split(':');
    let Some(first) = endpoints
        .next()
        .and_then(|token| parse_relative_endpoint(token).ok())
    else {
        return false;
    };
    let Some(second) = (match endpoints.next() {
        Some(token) => parse_relative_endpoint(token).ok(),
        None => Some(first),
    }) else {
        return false;
    };
    if endpoints.next().is_some() {
        return false;
    }
    [first, second].into_iter().all(|endpoint| match endpoint {
        RelativeEndpoint::Cell {
            row_absolute,
            column_absolute,
            ..
        } => row_absolute && column_absolute,
        RelativeEndpoint::Column { absolute, .. } | RelativeEndpoint::Row { absolute, .. } => {
            absolute
        }
    })
}

fn is_shared_formula(cell: &WorkbookCellInfo) -> bool {
    cell.formula_type
        .as_deref()
        .is_some_and(|kind| kind.eq_ignore_ascii_case("shared"))
}

fn parse_shared_formula_bounds(reference: &str) -> Option<CellRangeBounds> {
    let area = parse_area(reference, 0)?;
    (area.end == reference.len() && matches!(area.kind, "cell_reference" | "cell_range_reference"))
        .then_some(area.bounds)
}

fn bounds_contains(bounds: CellRangeBounds, row: u32, column: u32) -> bool {
    (bounds.first_row..=bounds.last_row).contains(&row)
        && (bounds.first_column..=bounds.last_column).contains(&column)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RelativeEndpoint {
    Cell {
        row: u32,
        column: u32,
        row_absolute: bool,
        column_absolute: bool,
    },
    Column {
        column: u32,
        absolute: bool,
    },
    Row {
        row: u32,
        absolute: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SharedReferenceTranslationError {
    Unsupported,
    OutsideGrid,
}

fn translate_shared_formula_reference(
    mut reference: WorkbookFormulaReferenceInfo,
    row_delta: i64,
    column_delta: i64,
    tables: &[WorkbookTableInfo],
) -> WorkbookFormulaReferenceInfo {
    if reference.reference_kind.starts_with("defined_name_")
        || reference.reference_kind == "dynamic_reference_function_candidate"
    {
        reference.workbook_cell_indices.clear();
        reference.workbook_cell_matches_truncated = false;
        return reference;
    }
    if reference.reference_kind == "structured_table_reference_candidate" {
        if reference.table_section.as_deref() == Some("this_row") {
            let Some(mut bounds) = reference.cell_range_bounds else {
                return reference;
            };
            let Some(first_row) = i64::from(bounds.first_row)
                .checked_add(row_delta)
                .and_then(|row| u32::try_from(row).ok())
            else {
                reference.cell_range_bounds = None;
                reference.table_resolution = Some("shared_table_row_out_of_grid_unresolved".into());
                reference.workbook_cell_indices.clear();
                return reference;
            };
            let Some(last_row) = i64::from(bounds.last_row)
                .checked_add(row_delta)
                .and_then(|row| u32::try_from(row).ok())
            else {
                reference.cell_range_bounds = None;
                reference.table_resolution = Some("shared_table_row_out_of_grid_unresolved".into());
                reference.workbook_cell_indices.clear();
                return reference;
            };
            bounds.first_row = first_row;
            bounds.last_row = last_row;
            let in_table = reference
                .table_index_candidate
                .and_then(|index| tables.get(index))
                .is_some_and(|table| {
                    table_data_contains_cell(table, first_row, bounds.first_column)
                        && table.cell_range_bounds.is_some_and(|table_bounds| {
                            bounds.last_column <= table_bounds.last_column
                        })
                });
            if in_table {
                reference.cell_range_bounds = Some(bounds);
                reference.workbook_cell_indices.clear();
            } else {
                reference.cell_range_bounds = None;
                reference.table_resolution =
                    Some("shared_table_row_outside_data_unresolved".into());
                reference.workbook_cell_indices.clear();
            }
        }
        reference.workbook_cell_matches_truncated = false;
        return reference;
    }
    match translate_reference_address(&reference.reference, row_delta, column_delta) {
        Ok((translated, bounds, kind)) => {
            reference.reference = translated;
            reference.cell_range_bounds = Some(bounds);
            reference.reference_kind = kind.into();
            reference.workbook_cell_indices.clear();
            reference.workbook_cell_matches_truncated = false;
        }
        Err(SharedReferenceTranslationError::Unsupported) => {
            reference.cell_range_bounds = None;
            reference.workbook_cell_indices.clear();
            reference.workbook_cell_matches_truncated = false;
            reference.sheet_resolution = "shared_formula_translation_unresolved".into();
        }
        Err(SharedReferenceTranslationError::OutsideGrid) => {
            reference.cell_range_bounds = None;
            reference.workbook_cell_indices.clear();
            reference.workbook_cell_matches_truncated = false;
            reference.sheet_resolution = "shared_formula_translation_out_of_grid_unresolved".into();
        }
    }
    reference
}

fn translate_reference_address(
    reference: &str,
    row_delta: i64,
    column_delta: i64,
) -> Result<(String, CellRangeBounds, &'static str), SharedReferenceTranslationError> {
    let address_start = reference.rfind('!').map_or(0, |bang| bang + 1);
    let (qualifier, address) = reference.split_at(address_start);
    let (first_text, last_text) = if let Some((first, last)) = address.split_once(':') {
        if last.contains(':') {
            return Err(SharedReferenceTranslationError::Unsupported);
        }
        (first, Some(last))
    } else {
        (address, None)
    };
    let first = parse_relative_endpoint(first_text)?;
    let last = last_text
        .map(parse_relative_endpoint)
        .transpose()?
        .unwrap_or(first);
    let first = shift_relative_endpoint(first, row_delta, column_delta)?;
    let last = shift_relative_endpoint(last, row_delta, column_delta)?;
    let (bounds, kind) = match (first, last, last_text.is_some()) {
        (
            RelativeEndpoint::Cell {
                row: first_row,
                column: first_column,
                ..
            },
            RelativeEndpoint::Cell {
                row: last_row,
                column: last_column,
                ..
            },
            false,
        ) if first_row == last_row && first_column == last_column => (
            CellRangeBounds {
                first_row,
                first_column,
                last_row,
                last_column,
            },
            "cell_reference",
        ),
        (
            RelativeEndpoint::Cell {
                row: first_row,
                column: first_column,
                ..
            },
            RelativeEndpoint::Cell {
                row: last_row,
                column: last_column,
                ..
            },
            true,
        ) if first_row <= last_row && first_column <= last_column => (
            CellRangeBounds {
                first_row,
                first_column,
                last_row,
                last_column,
            },
            "cell_range_reference",
        ),
        (
            RelativeEndpoint::Column {
                column: first_column,
                ..
            },
            RelativeEndpoint::Column {
                column: last_column,
                ..
            },
            true,
        ) if first_column <= last_column => (
            CellRangeBounds {
                first_row: 1,
                first_column,
                last_row: MAX_ROW,
                last_column,
            },
            "whole_column_reference",
        ),
        (
            RelativeEndpoint::Row { row: first_row, .. },
            RelativeEndpoint::Row { row: last_row, .. },
            true,
        ) if first_row <= last_row => (
            CellRangeBounds {
                first_row,
                first_column: 1,
                last_row,
                last_column: MAX_COLUMN,
            },
            "whole_row_reference",
        ),
        _ => return Err(SharedReferenceTranslationError::Unsupported),
    };
    let translated_first = format_relative_endpoint(first);
    let translated_address = if last_text.is_some() {
        format!("{translated_first}:{}", format_relative_endpoint(last))
    } else {
        translated_first
    };
    Ok((format!("{qualifier}{translated_address}"), bounds, kind))
}

fn parse_relative_endpoint(
    reference: &str,
) -> Result<RelativeEndpoint, SharedReferenceTranslationError> {
    let bytes = reference.as_bytes();
    let mut cursor = 0usize;
    let column_absolute = if bytes.first() == Some(&b'$') {
        cursor += 1;
        true
    } else {
        false
    };
    if bytes.get(cursor).is_some_and(u8::is_ascii_alphabetic) {
        let column_start = cursor;
        while bytes.get(cursor).is_some_and(u8::is_ascii_alphabetic) {
            cursor += 1;
        }
        if !(1..=3).contains(&(cursor - column_start)) {
            return Err(SharedReferenceTranslationError::Unsupported);
        }
        let column = bytes[column_start..cursor]
            .iter()
            .fold(0u32, |value, byte| {
                value * 26 + u32::from(byte.to_ascii_uppercase() - b'A' + 1)
            });
        if !(1..=MAX_COLUMN).contains(&column) {
            return Err(SharedReferenceTranslationError::OutsideGrid);
        }
        let row_absolute = bytes.get(cursor) == Some(&b'$');
        if row_absolute {
            cursor += 1;
        }
        let row_start = cursor;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        if cursor == row_start {
            return (cursor == bytes.len())
                .then_some(RelativeEndpoint::Column {
                    column,
                    absolute: column_absolute,
                })
                .ok_or(SharedReferenceTranslationError::Unsupported);
        }
        if cursor != bytes.len() {
            return Err(SharedReferenceTranslationError::Unsupported);
        }
        let row = reference[row_start..cursor]
            .parse::<u32>()
            .map_err(|_| SharedReferenceTranslationError::OutsideGrid)?;
        if !(1..=MAX_ROW).contains(&row) {
            return Err(SharedReferenceTranslationError::OutsideGrid);
        }
        return Ok(RelativeEndpoint::Cell {
            row,
            column,
            row_absolute,
            column_absolute,
        });
    }
    let row_start = cursor;
    while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
        cursor += 1;
    }
    if cursor == row_start || cursor != bytes.len() {
        return Err(SharedReferenceTranslationError::Unsupported);
    }
    let row = reference[row_start..cursor]
        .parse::<u32>()
        .map_err(|_| SharedReferenceTranslationError::OutsideGrid)?;
    if !(1..=MAX_ROW).contains(&row) {
        return Err(SharedReferenceTranslationError::OutsideGrid);
    }
    Ok(RelativeEndpoint::Row {
        row,
        absolute: column_absolute,
    })
}

fn shift_relative_endpoint(
    endpoint: RelativeEndpoint,
    row_delta: i64,
    column_delta: i64,
) -> Result<RelativeEndpoint, SharedReferenceTranslationError> {
    let shift = |value: u32, delta: i64, absolute: bool, max: u32| {
        let shifted = if absolute {
            i64::from(value)
        } else {
            i64::from(value) + delta
        };
        if !(1..=i64::from(max)).contains(&shifted) {
            return Err(SharedReferenceTranslationError::OutsideGrid);
        }
        Ok(shifted as u32)
    };
    match endpoint {
        RelativeEndpoint::Cell {
            row,
            column,
            row_absolute,
            column_absolute,
        } => Ok(RelativeEndpoint::Cell {
            row: shift(row, row_delta, row_absolute, MAX_ROW)?,
            column: shift(column, column_delta, column_absolute, MAX_COLUMN)?,
            row_absolute,
            column_absolute,
        }),
        RelativeEndpoint::Column { column, absolute } => Ok(RelativeEndpoint::Column {
            column: shift(column, column_delta, absolute, MAX_COLUMN)?,
            absolute,
        }),
        RelativeEndpoint::Row { row, absolute } => Ok(RelativeEndpoint::Row {
            row: shift(row, row_delta, absolute, MAX_ROW)?,
            absolute,
        }),
    }
}

fn format_relative_endpoint(endpoint: RelativeEndpoint) -> String {
    match endpoint {
        RelativeEndpoint::Cell {
            row,
            column,
            row_absolute,
            column_absolute,
        } => format!(
            "{}{}{}{}",
            if column_absolute { "$" } else { "" },
            column_label(column),
            if row_absolute { "$" } else { "" },
            row
        ),
        RelativeEndpoint::Column { column, absolute } => {
            format!(
                "{}{}",
                if absolute { "$" } else { "" },
                column_label(column)
            )
        }
        RelativeEndpoint::Row { row, absolute } => {
            format!("{}{}", if absolute { "$" } else { "" }, row)
        }
    }
}

fn column_label(mut column: u32) -> String {
    let mut bytes = Vec::new();
    while column > 0 {
        let digit = (column - 1) % 26;
        bytes.push(b'A' + digit as u8);
        column = (column - 1) / 26;
    }
    bytes.reverse();
    String::from_utf8(bytes).expect("column labels contain only ASCII letters")
}

fn can_link_sheet(resolution: &str) -> bool {
    matches!(
        resolution,
        "formula_worksheet_candidate"
            | "workbook_worksheet_name_candidate"
            | "workbook_table_candidate"
    )
}

fn scan_formula_defined_names(
    formula: &str,
    environment: FormulaNameEnvironment<'_>,
    address_references: &[WorkbookFormulaReferenceInfo],
    max_references: usize,
) -> (Vec<WorkbookFormulaReferenceInfo>, bool) {
    let mut references = Vec::new();
    let mut cursor = 0usize;
    while cursor < formula.len() {
        let Some(character) = formula[cursor..].chars().next() else {
            break;
        };
        if character == '"' {
            cursor = skip_formula_string(formula, cursor + 1);
            continue;
        }
        if character == '[' {
            cursor = skip_bracketed_reference(formula, cursor);
            continue;
        }
        if character == '\'' {
            if let Some((_, _, next)) = parse_quoted_sheet_prefix(formula, cursor) {
                cursor = next;
            } else {
                cursor += character.len_utf8();
            }
            continue;
        }
        if !is_defined_name_boundary_before(formula, cursor) || !is_defined_name_start(character) {
            cursor += character.len_utf8();
            continue;
        }
        let end = scan_defined_name_token(formula, cursor);
        if end == cursor {
            cursor += character.len_utf8();
            continue;
        }
        let token = &formula[cursor..end];
        let previous = formula[..cursor].chars().next_back();
        let next = formula[end..].chars().next();
        let qualified = previous == Some('!');
        let external = previous == Some(']');
        let is_sheet_qualifier = matches!(next, Some('!' | ':'));
        let overlaps_address = address_references
            .iter()
            .any(|reference| cursor < reference.end_byte && reference.start_byte < end);
        if !is_sheet_qualifier
            && !overlaps_address
            && let Some(reference) = formula_defined_name_candidate(
                FormulaNameToken {
                    name: token,
                    start: cursor,
                    end,
                    qualified,
                    external,
                    callable: next == Some('('),
                },
                environment,
            )
        {
            if references.len() >= max_references {
                return (references, true);
            }
            references.push(reference);
        }
        cursor = end;
    }
    (references, false)
}

fn scan_dynamic_reference_functions(
    formula: &str,
    max_references: usize,
) -> (Vec<WorkbookFormulaReferenceInfo>, bool) {
    let mut references = Vec::new();
    let mut cursor = 0usize;
    while cursor < formula.len() {
        let Some(character) = formula[cursor..].chars().next() else {
            break;
        };
        if character == '"' {
            cursor = skip_formula_string(formula, cursor + 1);
            continue;
        }
        if character == '[' {
            cursor = skip_bracketed_reference(formula, cursor);
            continue;
        }
        if character == '\'' {
            if let Some((_, _, next)) = parse_quoted_sheet_prefix(formula, cursor) {
                cursor = next;
            } else {
                cursor += character.len_utf8();
            }
            continue;
        }
        if !is_formula_boundary_before(formula, cursor) || !character.is_ascii_alphabetic() {
            cursor += character.len_utf8();
            continue;
        }
        let mut end = cursor + character.len_utf8();
        while end < formula.len() {
            let Some(next) = formula[end..].chars().next() else {
                break;
            };
            if !(next.is_ascii_alphanumeric() || next == '_') {
                break;
            }
            end += next.len_utf8();
        }
        let function = &formula[cursor..end];
        let mut opening_paren = end;
        while opening_paren < formula.len() {
            let Some(next) = formula[opening_paren..].chars().next() else {
                break;
            };
            if !next.is_whitespace() {
                break;
            }
            opening_paren += next.len_utf8();
        }
        if matches!(
            function.to_ascii_uppercase().as_str(),
            "INDIRECT" | "OFFSET"
        ) && formula[opening_paren..].starts_with('(')
        {
            if references.len() >= max_references {
                return (references, true);
            }
            references.push(WorkbookFormulaReferenceInfo {
                start_byte: cursor,
                end_byte: end,
                reference: function.into(),
                reference_kind: "dynamic_reference_function_candidate".into(),
                defined_name_resolution: Some("dynamic_formula_target_unresolved".into()),
                sheet_resolution: "dynamic_formula_target_unresolved".into(),
                ..WorkbookFormulaReferenceInfo::default()
            });
            cursor = opening_paren + 1;
        } else {
            cursor = end;
        }
    }
    (references, false)
}

#[derive(Default)]
struct StructuredTableSpec {
    section: Option<String>,
    current_row: bool,
    columns: Vec<String>,
    column_range: bool,
    unsupported: bool,
}

struct StructuredReferenceText<'a> {
    raw_reference: &'a str,
    start: usize,
    end: usize,
    table_name: Option<&'a str>,
    content: &'a str,
}

struct StructuredFormulaContext<'a> {
    current_sheet_index: usize,
    formula_row: Option<u32>,
    formula_column: Option<u32>,
    tables: &'a [WorkbookTableInfo],
}

fn scan_structured_table_references(
    formula: &str,
    current_sheet_index: usize,
    formula_row: Option<u32>,
    formula_column: Option<u32>,
    tables: &[WorkbookTableInfo],
    max_references: usize,
) -> (Vec<WorkbookFormulaReferenceInfo>, bool) {
    let mut references = Vec::new();
    let mut cursor = 0usize;
    while cursor < formula.len() {
        let Some(character) = formula[cursor..].chars().next() else {
            break;
        };
        if character == '"' {
            cursor = skip_formula_string(formula, cursor + 1);
            continue;
        }
        if character == '\'' {
            if let Some((_, _, next)) = parse_quoted_sheet_prefix(formula, cursor) {
                cursor = next;
            } else {
                cursor += character.len_utf8();
            }
            continue;
        }
        if character != '[' {
            cursor += character.len_utf8();
            continue;
        }
        let Some(end) = find_structured_reference_end(formula, cursor) else {
            cursor += character.len_utf8();
            continue;
        };
        let raw_reference = &formula[cursor..end];
        let table_name = table_name_before_bracket(formula, cursor);
        let inner = &formula[cursor + 1..end - 1];
        let structured_text = StructuredReferenceText {
            raw_reference,
            start: cursor,
            end,
            table_name,
            content: inner,
        };
        let context = StructuredFormulaContext {
            current_sheet_index,
            formula_row,
            formula_column,
            tables,
        };
        let candidate = if let Some(table_name) = table_name {
            let mut structured_text = structured_text;
            structured_text.table_name = Some(table_name);
            structured_table_candidate(structured_text, context)
        } else if is_current_row_structured_spec(inner)
            || (formula_row.is_some()
                && formula_column.is_some()
                && !looks_like_external_workbook_reference(formula, end))
        {
            structured_table_candidate(structured_text, context)
        } else {
            None
        };
        if let Some(candidate) = candidate {
            if references.len() >= max_references {
                return (references, true);
            }
            references.push(candidate);
        }
        cursor = end;
    }
    (references, false)
}

fn looks_like_external_workbook_reference(formula: &str, after_bracket: usize) -> bool {
    let remainder = &formula[after_bracket..];
    let Some(first) = remainder.chars().next() else {
        return false;
    };
    if first == '!' {
        return true;
    }
    if !(first.is_ascii_alphanumeric() || first == '_') {
        return false;
    }
    let token_end = scan_unquoted_sheet_token(formula, after_bracket).unwrap_or(after_bracket);
    formula[token_end..].starts_with('!')
        || token_end > after_bracket
            && formula[after_bracket..token_end]
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_')
}

fn table_name_before_bracket(formula: &str, bracket_start: usize) -> Option<&str> {
    let prefix = &formula[..bracket_start];
    let mut start = bracket_start;
    while start > 0 {
        let character = formula[..start].chars().next_back()?;
        if !is_defined_name_character(character) {
            break;
        }
        start -= character.len_utf8();
    }
    if start == bracket_start || !is_defined_name_boundary_before(formula, start) {
        return None;
    }
    let name = &prefix[start..];
    is_defined_name_start(name.chars().next()?).then_some(name)
}

fn is_current_row_structured_spec(content: &str) -> bool {
    let content = content.trim_start();
    content.starts_with('@') || content.starts_with("[#This Row]")
}

fn find_structured_reference_end(formula: &str, start: usize) -> Option<usize> {
    let bytes = formula.as_bytes();
    let mut depth = 0usize;
    let mut cursor = start;
    while cursor < bytes.len() {
        if bytes[cursor] == b'\''
            && bytes
                .get(cursor + 1)
                .is_some_and(|next| matches!(next, b'[' | b']' | b'#' | b'@' | b'\''))
        {
            cursor += 2;
            continue;
        }
        match bytes[cursor] {
            b'[' => depth = depth.saturating_add(1),
            b']' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(cursor + 1);
                }
            }
            _ => {}
        }
        cursor += 1;
    }
    None
}

fn structured_table_candidate(
    structured_text: StructuredReferenceText<'_>,
    context: StructuredFormulaContext<'_>,
) -> Option<WorkbookFormulaReferenceInfo> {
    let StructuredReferenceText {
        raw_reference,
        start,
        end,
        table_name,
        content,
    } = structured_text;
    let StructuredFormulaContext {
        current_sheet_index,
        formula_row,
        formula_column,
        tables,
    } = context;
    let mut spec = parse_structured_table_spec(content);
    if let Some(spec) = spec.as_mut()
        && spec.section.is_none()
    {
        spec.section = Some(if table_name.is_none() {
            "this_row".into()
        } else {
            "data".into()
        });
        spec.current_row = table_name.is_none();
    }
    let table_matches = if let Some(table_name) = table_name {
        tables
            .iter()
            .enumerate()
            .filter(|(_, table)| {
                table.display_name.eq_ignore_ascii_case(table_name)
                    || table.name.eq_ignore_ascii_case(table_name)
            })
            .collect::<Vec<_>>()
    } else {
        tables
            .iter()
            .enumerate()
            .filter(|(_, table)| {
                table.sheet_index == current_sheet_index
                    && formula_row
                        .zip(formula_column)
                        .is_some_and(|(row, column)| table_data_contains_cell(table, row, column))
            })
            .collect::<Vec<_>>()
    };
    let (table_index, table) = match table_matches.as_slice() {
        [candidate] => *candidate,
        [] => {
            if table_name.is_none() {
                return Some(WorkbookFormulaReferenceInfo {
                    start_byte: start,
                    end_byte: end,
                    reference: raw_reference.into(),
                    reference_kind: "structured_table_reference_candidate".into(),
                    table_resolution: Some("unresolved_current_table_context".into()),
                    sheet_resolution: "unresolved_workbook_table_candidate".into(),
                    ..WorkbookFormulaReferenceInfo::default()
                });
            }
            return Some(WorkbookFormulaReferenceInfo {
                start_byte: start,
                end_byte: end,
                reference: raw_reference.into(),
                reference_kind: "structured_table_reference_candidate".into(),
                table_resolution: Some("unresolved_workbook_table_name".into()),
                sheet_resolution: "unresolved_workbook_table_candidate".into(),
                ..WorkbookFormulaReferenceInfo::default()
            });
        }
        _ => {
            return Some(WorkbookFormulaReferenceInfo {
                start_byte: start,
                end_byte: end,
                reference: raw_reference.into(),
                reference_kind: "structured_table_reference_candidate".into(),
                table_resolution: Some("ambiguous_workbook_table_name".into()),
                sheet_resolution: "ambiguous_workbook_table_candidate".into(),
                ..WorkbookFormulaReferenceInfo::default()
            });
        }
    };
    let base = WorkbookFormulaReferenceInfo {
        start_byte: start,
        end_byte: end,
        reference: raw_reference.into(),
        reference_kind: "structured_table_reference_candidate".into(),
        table_index_candidate: Some(table_index),
        sheet_index_candidate: Some(table.sheet_index),
        sheet_name_candidate: Some(table.sheet_name.clone()),
        sheet_resolution: "workbook_table_candidate".into(),
        ..WorkbookFormulaReferenceInfo::default()
    };
    let Some(spec) = spec else {
        return Some(WorkbookFormulaReferenceInfo {
            table_resolution: Some("unsupported_structured_table_specifier".into()),
            ..base
        });
    };
    if spec.unsupported {
        return Some(WorkbookFormulaReferenceInfo {
            table_resolution: Some("unsupported_structured_table_specifier".into()),
            ..base
        });
    }
    if table.resolution != "resolved_internal" {
        return Some(WorkbookFormulaReferenceInfo {
            table_resolution: Some(table.resolution.clone()),
            ..base
        });
    }
    let Some(table_bounds) = table.cell_range_bounds else {
        return Some(WorkbookFormulaReferenceInfo {
            table_resolution: Some("table_range_unresolved".into()),
            ..base
        });
    };
    let width = usize::try_from(table_bounds.last_column - table_bounds.first_column + 1).ok();
    if width.is_none_or(|width| width != table.columns.len()) {
        return Some(WorkbookFormulaReferenceInfo {
            table_resolution: Some("table_column_metadata_unresolved".into()),
            ..base
        });
    }
    let column_bounds = if spec.columns.is_empty() {
        (table_bounds.first_column, table_bounds.last_column, None)
    } else {
        let mut indexes = Vec::new();
        for name in &spec.columns {
            let matches = table
                .columns
                .iter()
                .enumerate()
                .filter(|(_, column)| column.eq_ignore_ascii_case(name))
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            match matches.as_slice() {
                [index] => indexes.push(*index),
                [] => {
                    return Some(WorkbookFormulaReferenceInfo {
                        table_resolution: Some("unresolved_table_column_name".into()),
                        ..base
                    });
                }
                _ => {
                    return Some(WorkbookFormulaReferenceInfo {
                        table_resolution: Some("ambiguous_table_column_name".into()),
                        ..base
                    });
                }
            }
        }
        if indexes.len() > 2
            || (indexes.len() == 2 && (!spec.column_range || indexes[0] > indexes[1]))
        {
            return Some(WorkbookFormulaReferenceInfo {
                table_resolution: Some("unsupported_table_column_selection".into()),
                ..base
            });
        }
        let first = indexes[0];
        let last = *indexes.last().unwrap_or(&first);
        (
            table_bounds.first_column + first as u32,
            table_bounds.first_column + last as u32,
            (indexes.len() == 1).then_some(first),
        )
    };
    let section = spec.section.as_deref().unwrap_or("data");
    let (first_row, last_row) = match section {
        "all" => (table_bounds.first_row, table_bounds.last_row),
        "headers" => {
            if table.header_row_count == 0 {
                return Some(WorkbookFormulaReferenceInfo {
                    table_resolution: Some("table_has_no_header_row".into()),
                    ..base
                });
            }
            (
                table_bounds.first_row,
                table_bounds.first_row + table.header_row_count - 1,
            )
        }
        "totals" => {
            if table.totals_row_count == 0 {
                return Some(WorkbookFormulaReferenceInfo {
                    table_resolution: Some("table_has_no_totals_row".into()),
                    ..base
                });
            }
            (
                table_bounds.last_row - table.totals_row_count + 1,
                table_bounds.last_row,
            )
        }
        "this_row" => {
            let Some(row) = formula_row else {
                return Some(WorkbookFormulaReferenceInfo {
                    table_resolution: Some("current_table_row_unresolved".into()),
                    ..base
                });
            };
            let data_first = table_bounds.first_row + table.header_row_count;
            let data_last = table_bounds.last_row.saturating_sub(table.totals_row_count);
            if row < data_first || row > data_last {
                return Some(WorkbookFormulaReferenceInfo {
                    table_resolution: Some("current_row_outside_table_data".into()),
                    ..base
                });
            }
            (row, row)
        }
        "data" => {
            let data_first = table_bounds.first_row + table.header_row_count;
            let data_last = table_bounds.last_row.saturating_sub(table.totals_row_count);
            if data_first > data_last {
                return Some(WorkbookFormulaReferenceInfo {
                    table_resolution: Some("table_data_rows_empty".into()),
                    ..base
                });
            }
            (data_first, data_last)
        }
        _ => {
            return Some(WorkbookFormulaReferenceInfo {
                table_resolution: Some("unresolved_table_section".into()),
                ..base
            });
        }
    };
    Some(WorkbookFormulaReferenceInfo {
        table_column_index_candidate: column_bounds.2,
        table_section: Some(section.into()),
        cell_range_bounds: Some(CellRangeBounds {
            first_row,
            first_column: column_bounds.0,
            last_row,
            last_column: column_bounds.1,
        }),
        table_resolution: Some(
            match section {
                "all" => "structured_table_all_candidate",
                "headers" => "structured_table_headers_candidate",
                "totals" => "structured_table_totals_candidate",
                "this_row" => "structured_table_current_row_candidate",
                _ => "structured_table_data_candidate",
            }
            .into(),
        ),
        ..base
    })
}

fn table_data_contains_cell(table: &WorkbookTableInfo, row: u32, column: u32) -> bool {
    let Some(bounds) = table.cell_range_bounds else {
        return false;
    };
    row >= bounds.first_row + table.header_row_count
        && row <= bounds.last_row.saturating_sub(table.totals_row_count)
        && (bounds.first_column..=bounds.last_column).contains(&column)
}

fn parse_structured_table_spec(content: &str) -> Option<StructuredTableSpec> {
    let content = content.trim();
    if content.is_empty() {
        return None;
    }
    if content.starts_with("@[") {
        let end = find_structured_reference_end(content, 1)?;
        if end != content.len() {
            return None;
        }
        return Some(StructuredTableSpec {
            section: Some("this_row".into()),
            current_row: true,
            columns: vec![decode_structured_column_name(&content[2..end - 1])?],
            ..StructuredTableSpec::default()
        });
    }
    if !has_unescaped_open_bracket(content) {
        let term = classify_structured_term(content)?;
        let mut spec = StructuredTableSpec::default();
        apply_structured_term(&mut spec, term)?;
        return Some(spec);
    }
    let (terms, separators) = parse_nested_structured_terms(content)?;
    let mut spec = StructuredTableSpec::default();
    let mut previous_column = false;
    for (index, term) in terms.into_iter().enumerate() {
        let classified = classify_structured_term(&term)?;
        match classified {
            StructuredTerm::Item(item) => {
                apply_structured_item(&mut spec, &item)?;
                previous_column = false;
            }
            StructuredTerm::CurrentRow(column) => {
                spec.current_row = true;
                spec.section = Some("this_row".into());
                if let Some(column) = column {
                    spec.columns.push(column);
                }
                previous_column = false;
            }
            StructuredTerm::Column(column) => {
                if previous_column {
                    match separators.get(index.saturating_sub(1)) {
                        Some(':') if spec.columns.len() == 1 => spec.column_range = true,
                        _ => spec.unsupported = true,
                    }
                } else if !spec.columns.is_empty() {
                    spec.unsupported = true;
                }
                spec.columns.push(column);
                previous_column = true;
            }
        }
    }
    Some(spec)
}

enum StructuredTerm {
    Item(String),
    CurrentRow(Option<String>),
    Column(String),
}

fn classify_structured_term(term: &str) -> Option<StructuredTerm> {
    let term = term.trim();
    if term.starts_with('\'') {
        return Some(StructuredTerm::Column(decode_structured_column_name(term)?));
    }
    if let Some(column) = term.strip_prefix('@') {
        return Some(StructuredTerm::CurrentRow(if column.trim().is_empty() {
            None
        } else {
            Some(decode_structured_column_name(column)?)
        }));
    }
    if term.starts_with('#') {
        return Some(StructuredTerm::Item(
            term.trim_start_matches('#').to_ascii_lowercase(),
        ));
    }
    Some(StructuredTerm::Column(decode_structured_column_name(term)?))
}

fn apply_structured_term(spec: &mut StructuredTableSpec, term: StructuredTerm) -> Option<()> {
    match term {
        StructuredTerm::Item(item) => apply_structured_item(spec, &item),
        StructuredTerm::CurrentRow(column) => {
            spec.current_row = true;
            spec.section = Some("this_row".into());
            if let Some(column) = column {
                spec.columns.push(column);
            }
            Some(())
        }
        StructuredTerm::Column(column) => {
            spec.columns.push(column);
            Some(())
        }
    }
}

fn apply_structured_item(spec: &mut StructuredTableSpec, item: &str) -> Option<()> {
    let section = match item.trim().to_ascii_lowercase().as_str() {
        "all" => "all",
        "data" => "data",
        "headers" => "headers",
        "totals" => "totals",
        "this row" => "this_row",
        _ => {
            spec.unsupported = true;
            return Some(());
        }
    };
    if spec.section.is_some() {
        spec.unsupported = true;
    }
    spec.section = Some(section.into());
    spec.current_row = section == "this_row";
    Some(())
}

fn has_unescaped_open_bracket(content: &str) -> bool {
    let bytes = content.as_bytes();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        if bytes[cursor] == b'\''
            && bytes
                .get(cursor + 1)
                .is_some_and(|next| matches!(next, b'[' | b']' | b'#' | b'@' | b'\''))
        {
            cursor += 2;
        } else if bytes[cursor] == b'[' {
            return true;
        } else {
            cursor += 1;
        }
    }
    false
}

fn parse_nested_structured_terms(content: &str) -> Option<(Vec<String>, Vec<char>)> {
    let mut terms = Vec::new();
    let mut separators = Vec::new();
    let mut cursor = 0usize;
    while cursor < content.len() {
        while content[cursor..]
            .chars()
            .next()
            .is_some_and(char::is_whitespace)
        {
            cursor += content[cursor..].chars().next()?.len_utf8();
        }
        if cursor == content.len() {
            break;
        }
        if content.as_bytes().get(cursor) != Some(&b'[') {
            return None;
        }
        let end = find_structured_reference_end(content, cursor)?;
        terms.push(content[cursor + 1..end - 1].to_owned());
        cursor = end;
        while content[cursor..]
            .chars()
            .next()
            .is_some_and(char::is_whitespace)
        {
            cursor += content[cursor..].chars().next()?.len_utf8();
        }
        if cursor == content.len() {
            break;
        }
        let separator = content.as_bytes()[cursor] as char;
        if !matches!(separator, ',' | ':') {
            return None;
        }
        separators.push(separator);
        cursor += 1;
    }
    Some((terms, separators))
}

fn decode_structured_column_name(name: &str) -> Option<String> {
    let mut output = String::new();
    let mut cursor = 0usize;
    while cursor < name.len() {
        let character = name[cursor..].chars().next()?;
        if character == '\''
            && let Some(next) = name[cursor + 1..].chars().next()
            && matches!(next, '[' | ']' | '#' | '@' | '\'')
        {
            output.push(next);
            cursor += 1 + next.len_utf8();
        } else {
            output.push(character);
            cursor += character.len_utf8();
        }
    }
    let output = output.trim().to_owned();
    (!output.is_empty()).then_some(output)
}

fn index_defined_names(defined_names: &[FormulaNameMetadata]) -> HashMap<String, Vec<usize>> {
    let mut by_name = HashMap::<String, Vec<usize>>::new();
    for (index, defined_name) in defined_names.iter().enumerate() {
        by_name
            .entry(defined_name.name.to_ascii_lowercase())
            .or_default()
            .push(index);
    }
    by_name
}

fn formula_defined_name_candidate(
    token: FormulaNameToken<'_>,
    environment: FormulaNameEnvironment<'_>,
) -> Option<WorkbookFormulaReferenceInfo> {
    let matches = environment
        .defined_names_by_name
        .get(&token.name.to_ascii_lowercase())
        .into_iter()
        .flatten()
        .filter_map(|index| {
            environment
                .defined_names
                .get(*index)
                .map(|name| (*index, name))
        })
        .collect::<Vec<_>>();
    if matches.is_empty() {
        return None;
    }
    let (name_index, sheet_index, sheet_name, resolution, sheet_resolution): (
        Option<usize>,
        Option<usize>,
        Option<String>,
        &'static str,
        &'static str,
    ) = if token.external {
        (
            None,
            None,
            None,
            "external_defined_name_unresolved",
            "external_defined_name_unresolved",
        )
    } else if token.qualified {
        (
            None,
            None,
            None,
            "qualified_defined_name_unresolved",
            "qualified_defined_name_unresolved",
        )
    } else if let Ok(current_sheet_id) = u32::try_from(environment.current_sheet_index) {
        let local_matches = matches
            .iter()
            .filter(|(_, defined_name)| {
                defined_name.scope_resolution == "sheet_scope_candidate"
                    && defined_name.local_sheet_id == Some(current_sheet_id)
            })
            .collect::<Vec<_>>();
        match local_matches.as_slice() {
            [(index, defined_name)] => (
                Some(*index),
                Some(environment.current_sheet_index),
                defined_name.local_sheet_name.clone().or_else(|| {
                    environment
                        .sheets
                        .get(environment.current_sheet_index)
                        .map(|sheet| sheet.name.clone())
                }),
                "sheet_scoped_defined_name_candidate",
                "formula_worksheet_candidate",
            ),
            [_, _, ..] => (
                None,
                Some(environment.current_sheet_index),
                environment
                    .sheets
                    .get(environment.current_sheet_index)
                    .map(|sheet| sheet.name.clone()),
                "ambiguous_sheet_scoped_defined_name",
                "ambiguous_workbook_defined_name",
            ),
            [] => {
                let workbook_matches = matches
                    .iter()
                    .filter(|(_, defined_name)| defined_name.scope_resolution == "workbook_scope")
                    .collect::<Vec<_>>();
                match workbook_matches.as_slice() {
                    [(index, _)] => (
                        Some(*index),
                        None,
                        None,
                        "workbook_defined_name_candidate",
                        "workbook_scope_candidate",
                    ),
                    [_, _, ..] => (
                        None,
                        None,
                        None,
                        "ambiguous_workbook_defined_name",
                        "ambiguous_workbook_defined_name",
                    ),
                    [] if matches.len() == 1 => {
                        let (index, defined_name) = matches[0];
                        if defined_name.scope_resolution == "sheet_scope_candidate" {
                            (
                                Some(index),
                                defined_name.local_sheet_id.map(|id| id as usize),
                                defined_name.local_sheet_name.clone(),
                                "defined_name_out_of_scope_candidate",
                                "defined_name_scope_unresolved",
                            )
                        } else {
                            (
                                Some(index),
                                None,
                                None,
                                "workbook_defined_name_metadata_candidate",
                                "workbook_defined_name_metadata_candidate",
                            )
                        }
                    }
                    [] => (
                        None,
                        None,
                        None,
                        "ambiguous_workbook_defined_name_metadata",
                        "ambiguous_workbook_defined_name",
                    ),
                }
            }
        }
    } else {
        (
            None,
            None,
            None,
            "workbook_defined_name_scope_unresolved",
            "workbook_defined_name_metadata_candidate",
        )
    };
    Some(WorkbookFormulaReferenceInfo {
        start_byte: token.start,
        end_byte: token.end,
        reference: token.name.into(),
        reference_kind: if token.callable {
            "defined_name_function_candidate".into()
        } else {
            "defined_name_candidate".into()
        },
        defined_name_index_candidate: name_index,
        defined_name_resolution: Some(if token.callable {
            match resolution {
                "workbook_defined_name_candidate" => "workbook_defined_name_function_candidate",
                "sheet_scoped_defined_name_candidate" => {
                    "sheet_scoped_defined_name_function_candidate"
                }
                other => other,
            }
            .into()
        } else {
            resolution.into()
        }),
        sheet_index_candidate: sheet_index,
        sheet_name_candidate: sheet_name,
        sheet_resolution: sheet_resolution.into(),
        ..WorkbookFormulaReferenceInfo::default()
    })
}

fn is_defined_name_boundary_before(formula: &str, index: usize) -> bool {
    index == 0
        || formula[..index]
            .chars()
            .next_back()
            .is_none_or(|character| !is_defined_name_character(character))
}

fn is_defined_name_start(character: char) -> bool {
    character.is_alphabetic() || matches!(character, '_' | '\\')
}

fn is_defined_name_character(character: char) -> bool {
    character.is_alphanumeric() || matches!(character, '_' | '.' | '\\')
}

fn scan_defined_name_token(formula: &str, start: usize) -> usize {
    let mut cursor = start;
    while cursor < formula.len() {
        let Some(character) = formula[cursor..].chars().next() else {
            break;
        };
        if !is_defined_name_character(character) {
            break;
        }
        cursor += character.len_utf8();
    }
    cursor
}

fn scan_formula_references(
    formula: &str,
    current_sheet_index: usize,
    sheets: &[WorkbookSheetInfo],
    max_references: usize,
) -> (Vec<WorkbookFormulaReferenceInfo>, bool) {
    let mut references = Vec::new();
    let mut cursor = 0usize;
    while cursor < formula.len() {
        let Some(character) = formula[cursor..].chars().next() else {
            break;
        };
        if character == '"' {
            cursor = skip_formula_string(formula, cursor + 1);
            continue;
        }
        if character == '[' {
            if let Some((reference, next)) = parse_external_reference(formula, cursor) {
                if references.len() >= max_references {
                    return (references, true);
                }
                references.push(resolve_reference(
                    reference,
                    current_sheet_index,
                    sheets,
                    true,
                    false,
                ));
                cursor = next;
            } else {
                cursor = skip_bracketed_reference(formula, cursor);
            }
            continue;
        }
        if character == '\'' {
            if let Some((sheet_name, bang, next)) = parse_quoted_sheet_prefix(formula, cursor) {
                if let Some(area) = parse_area(formula, bang + 1) {
                    if references.len() >= max_references {
                        return (references, true);
                    }
                    let is_external = sheet_name.contains('[') && sheet_name.contains(']');
                    let is_three_dimensional = sheet_name.contains(':') && !is_external;
                    let reference = make_reference(
                        formula,
                        cursor,
                        area.end,
                        area.kind,
                        area.bounds,
                        Some(sheet_name),
                    );
                    references.push(resolve_reference(
                        reference,
                        current_sheet_index,
                        sheets,
                        is_external,
                        is_three_dimensional,
                    ));
                    cursor = next.max(area.end);
                } else {
                    cursor = next;
                }
            } else {
                cursor += character.len_utf8();
            }
            continue;
        }

        if is_formula_boundary_before(formula, cursor)
            && let Some((qualifier, bang, three_dimensional)) =
                parse_unquoted_sheet_prefix(formula, cursor)
            && let Some(area) = parse_area(formula, bang + 1)
        {
            if references.len() >= max_references {
                return (references, true);
            }
            let reference = make_reference(
                formula,
                cursor,
                area.end,
                area.kind,
                area.bounds,
                Some(qualifier),
            );
            references.push(resolve_reference(
                reference,
                current_sheet_index,
                sheets,
                false,
                three_dimensional,
            ));
            cursor = area.end;
            continue;
        }

        if is_formula_boundary_before(formula, cursor)
            && let Some(area) = parse_area(formula, cursor)
            && is_formula_boundary_after(formula, area.end)
        {
            if references.len() >= max_references {
                return (references, true);
            }
            let reference = make_reference(formula, cursor, area.end, area.kind, area.bounds, None);
            references.push(resolve_reference(
                reference,
                current_sheet_index,
                sheets,
                false,
                false,
            ));
            cursor = area.end;
            continue;
        }
        cursor += character.len_utf8();
    }
    (references, false)
}

fn make_reference(
    formula: &str,
    start: usize,
    end: usize,
    kind: &'static str,
    bounds: CellRangeBounds,
    sheet_selector: Option<String>,
) -> WorkbookFormulaReferenceInfo {
    WorkbookFormulaReferenceInfo {
        start_byte: start,
        end_byte: end,
        reference: formula[start..end].to_owned(),
        reference_kind: kind.to_owned(),
        sheet_selector,
        cell_range_bounds: Some(bounds),
        ..WorkbookFormulaReferenceInfo::default()
    }
}

fn resolve_reference(
    mut reference: WorkbookFormulaReferenceInfo,
    current_sheet_index: usize,
    sheets: &[WorkbookSheetInfo],
    external: bool,
    three_dimensional: bool,
) -> WorkbookFormulaReferenceInfo {
    if external {
        reference.sheet_resolution = "external_workbook_reference_unresolved".into();
        return reference;
    }
    if three_dimensional {
        reference.sheet_resolution = "three_dimensional_sheet_range_unresolved".into();
        return reference;
    }
    let candidates = if let Some(sheet_name) = reference.sheet_selector.as_deref() {
        sheets
            .iter()
            .enumerate()
            .filter(|(_, sheet)| sheet.name.eq_ignore_ascii_case(sheet_name))
            .collect::<Vec<_>>()
    } else {
        sheets
            .get(current_sheet_index)
            .map(|sheet| vec![(current_sheet_index, sheet)])
            .unwrap_or_default()
    };
    let (index, sheet) = match candidates.as_slice() {
        [] => {
            reference.sheet_resolution = if reference.sheet_selector.is_some() {
                "unresolved_workbook_worksheet_candidate".into()
            } else {
                "unresolved_formula_worksheet_context".into()
            };
            return reference;
        }
        [candidate] => *candidate,
        _ => {
            reference.sheet_resolution = "ambiguous_workbook_worksheet_candidate".into();
            return reference;
        }
    };
    reference.sheet_index_candidate = Some(index);
    reference.sheet_name_candidate = Some(sheet.name.clone());
    reference.sheet_resolution = if !sheet.kind.eq_ignore_ascii_case("worksheet") {
        "known_nonworksheet_sheet_candidate".into()
    } else if reference.sheet_selector.is_some() {
        "workbook_worksheet_name_candidate".into()
    } else {
        "formula_worksheet_candidate".into()
    };
    reference
}

fn parse_quoted_sheet_prefix(formula: &str, start: usize) -> Option<(String, usize, usize)> {
    let bytes = formula.as_bytes();
    let mut cursor = start.checked_add(1)?;
    let mut value = String::new();
    while cursor < bytes.len() {
        if bytes[cursor] == b'\'' {
            if bytes.get(cursor + 1) == Some(&b'\'') {
                value.push('\'');
                cursor += 2;
                continue;
            }
            let qualifier_end = cursor + 1;
            if bytes.get(qualifier_end) != Some(&b'!') {
                return None;
            }
            return Some((value, qualifier_end, qualifier_end + 1));
        }
        let character = formula[cursor..].chars().next()?;
        value.push(character);
        cursor += character.len_utf8();
    }
    None
}

fn parse_unquoted_sheet_prefix(formula: &str, start: usize) -> Option<(String, usize, bool)> {
    let bytes = formula.as_bytes();
    let first_end = scan_unquoted_sheet_token(formula, start)?;
    if first_end == start {
        return None;
    }
    if bytes.get(first_end) == Some(&b':') {
        let second_start = first_end + 1;
        let second_end = scan_unquoted_sheet_token(formula, second_start)?;
        if second_end == second_start || bytes.get(second_end) != Some(&b'!') {
            return None;
        }
        return Some((formula[start..second_end].to_owned(), second_end, true));
    }
    if bytes.get(first_end) != Some(&b'!') {
        return None;
    }
    Some((formula[start..first_end].to_owned(), first_end, false))
}

fn scan_unquoted_sheet_token(formula: &str, start: usize) -> Option<usize> {
    let mut cursor = start;
    while cursor < formula.len() {
        let character = formula[cursor..].chars().next()?;
        if !(character.is_ascii_alphanumeric() || character == '_' || character == '.') {
            break;
        }
        cursor += character.len_utf8();
    }
    Some(cursor)
}

fn parse_external_reference(
    formula: &str,
    start: usize,
) -> Option<(WorkbookFormulaReferenceInfo, usize)> {
    if !is_formula_boundary_before(formula, start) {
        return None;
    }
    let close = formula[start + 1..].find(']')? + start + 1;
    let after_book = close + 1;
    let mut cursor = after_book;
    while cursor < formula.len() {
        let character = formula[cursor..].chars().next()?;
        if !(character.is_ascii_alphanumeric() || character == '_' || character == '.') {
            break;
        }
        cursor += character.len_utf8();
    }
    let (sheet, area_start) = if formula.as_bytes().get(cursor) == Some(&b'!') {
        (Some(formula[after_book..cursor].to_owned()), cursor + 1)
    } else {
        (None, after_book)
    };
    let area = parse_area(formula, area_start)?;
    if !is_reference_terminator(formula, area.end) {
        return None;
    }
    let reference = make_reference(formula, start, area.end, area.kind, area.bounds, sheet);
    Some((reference, area.end))
}

fn parse_area(formula: &str, start: usize) -> Option<ParsedArea> {
    let (first, first_end) = parse_endpoint(formula, start)?;
    if formula.as_bytes().get(first_end) == Some(&b':') {
        let (last, end) = parse_endpoint(formula, first_end + 1)?;
        let (bounds, kind) = match (first, last) {
            (Endpoint::Cell(first_row, first_column), Endpoint::Cell(last_row, last_column))
                if first_row <= last_row && first_column <= last_column =>
            {
                (
                    CellRangeBounds {
                        first_row,
                        first_column,
                        last_row,
                        last_column,
                    },
                    "cell_range_reference",
                )
            }
            (Endpoint::Column(first_column), Endpoint::Column(last_column))
                if first_column <= last_column =>
            {
                (
                    CellRangeBounds {
                        first_row: 1,
                        first_column,
                        last_row: MAX_ROW,
                        last_column,
                    },
                    "whole_column_reference",
                )
            }
            (Endpoint::Row(first_row), Endpoint::Row(last_row)) if first_row <= last_row => (
                CellRangeBounds {
                    first_row,
                    first_column: 1,
                    last_row,
                    last_column: MAX_COLUMN,
                },
                "whole_row_reference",
            ),
            _ => return None,
        };
        if !is_reference_terminator(formula, end) {
            return None;
        }
        return Some(ParsedArea { end, bounds, kind });
    }
    let Endpoint::Cell(row, column) = first else {
        return None;
    };
    if !is_reference_terminator(formula, first_end) {
        return None;
    }
    Some(ParsedArea {
        end: first_end,
        bounds: CellRangeBounds {
            first_row: row,
            first_column: column,
            last_row: row,
            last_column: column,
        },
        kind: "cell_reference",
    })
}

fn parse_endpoint(formula: &str, start: usize) -> Option<(Endpoint, usize)> {
    let bytes = formula.as_bytes();
    let mut cursor = start;
    if bytes.get(cursor) == Some(&b'$') {
        cursor += 1;
    }
    let coordinate_start = cursor;
    if bytes.get(cursor).is_some_and(u8::is_ascii_alphabetic) {
        while bytes.get(cursor).is_some_and(u8::is_ascii_alphabetic) {
            cursor += 1;
        }
        let column_length = cursor - coordinate_start;
        if !(1..=3).contains(&column_length) {
            return None;
        }
        let column = bytes[coordinate_start..cursor]
            .iter()
            .fold(0u32, |value, byte| {
                value * 26 + u32::from(byte.to_ascii_uppercase() - b'A' + 1)
            });
        if !(1..=MAX_COLUMN).contains(&column) {
            return None;
        }
        if bytes.get(cursor) == Some(&b'$') {
            cursor += 1;
        }
        let row_start = cursor;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        if row_start == cursor {
            return Some((Endpoint::Column(column), cursor));
        }
        let row = formula[row_start..cursor].parse::<u32>().ok()?;
        if !(1..=MAX_ROW).contains(&row) {
            return None;
        }
        return Some((Endpoint::Cell(row, column), cursor));
    }
    if bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        let row = formula[coordinate_start..cursor].parse::<u32>().ok()?;
        return (1..=MAX_ROW)
            .contains(&row)
            .then_some((Endpoint::Row(row), cursor));
    }
    None
}

fn is_formula_boundary_before(formula: &str, index: usize) -> bool {
    index == 0
        || formula[..index]
            .chars()
            .next_back()
            .is_none_or(|character| !is_formula_identifier_character(character))
}

fn is_formula_boundary_after(formula: &str, index: usize) -> bool {
    formula[index..]
        .chars()
        .next()
        .is_none_or(|character| !is_formula_identifier_character(character))
}

fn is_reference_terminator(formula: &str, index: usize) -> bool {
    is_formula_boundary_after(formula, index) && !formula[index..].starts_with('(')
}

fn is_formula_identifier_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '$')
}

fn skip_formula_string(formula: &str, mut cursor: usize) -> usize {
    let bytes = formula.as_bytes();
    while cursor < bytes.len() {
        if bytes[cursor] == b'"' {
            if bytes.get(cursor + 1) == Some(&b'"') {
                cursor += 2;
            } else {
                return cursor + 1;
            }
        } else {
            let character = formula[cursor..].chars().next().unwrap_or('\0');
            cursor += character.len_utf8();
        }
    }
    cursor
}

fn skip_bracketed_reference(formula: &str, start: usize) -> usize {
    find_structured_reference_end(formula, start).unwrap_or(formula.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sheet(name: &str, kind: &str) -> WorkbookSheetInfo {
        WorkbookSheetInfo {
            name: name.into(),
            kind: kind.into(),
            resolution: "resolved_internal".into(),
            ..WorkbookSheetInfo::default()
        }
    }

    fn defined_name(
        name: &str,
        formula: &str,
        scope_resolution: &str,
        local_sheet_id: Option<u32>,
        local_sheet_name: Option<&str>,
    ) -> WorkbookDefinedNameInfo {
        WorkbookDefinedNameInfo {
            name: name.into(),
            formula: formula.into(),
            scope_resolution: scope_resolution.into(),
            local_sheet_id,
            local_sheet_name: local_sheet_name.map(str::to_owned),
            ..WorkbookDefinedNameInfo::default()
        }
    }

    #[test]
    fn finds_cell_and_range_operands_without_treating_strings_as_references() {
        let sheets = [sheet("Orders", "worksheet")];
        let (references, truncated) = scan_formula_references(
            "IF(A1=\"B2 and \"\"C3\"\"\",SUM($D$4:D8),0)",
            0,
            &sheets,
            32,
        );
        assert!(!truncated);
        assert_eq!(references.len(), 2);
        assert_eq!(references[0].reference, "A1");
        assert_eq!(
            references[0].sheet_resolution,
            "formula_worksheet_candidate"
        );
        assert_eq!(references[1].reference, "$D$4:D8");
        assert_eq!(references[1].reference_kind, "cell_range_reference");
        assert_eq!(references[1].cell_range_bounds.unwrap().last_row, 8);
        let (function, _) = scan_formula_references("LOG10(A1)", 0, &sheets, 32);
        assert_eq!(function.len(), 1);
        assert_eq!(function[0].reference, "A1");
    }

    #[test]
    fn resolves_quoted_unquoted_and_three_dimensional_sheet_references() {
        let sheets = [
            sheet("Orders", "worksheet"),
            sheet("Input Sheet", "worksheet"),
            sheet("ChartOne", "chartsheet"),
        ];
        let (references, _) = scan_formula_references(
            "'Input Sheet'!A1+Orders!B2+ChartOne!C3+'Orders:Input Sheet'!D4",
            0,
            &sheets,
            32,
        );
        assert_eq!(references.len(), 4);
        assert_eq!(references[0].sheet_index_candidate, Some(1));
        assert_eq!(
            references[0].sheet_name_candidate.as_deref(),
            Some("Input Sheet")
        );
        assert_eq!(references[1].sheet_index_candidate, Some(0));
        assert_eq!(
            references[2].sheet_resolution,
            "known_nonworksheet_sheet_candidate"
        );
        assert_eq!(
            references[3].sheet_resolution,
            "three_dimensional_sheet_range_unresolved"
        );
    }

    #[test]
    fn recognizes_whole_rows_columns_and_skips_structured_or_external_references() {
        let sheets = [sheet("Data", "worksheet")];
        let (references, _) = scan_formula_references(
            "SUM(A:A)+SUM(1:2)+Table1[A1]+[Book.xlsx]Data!B3+\"C4\"",
            0,
            &sheets,
            32,
        );
        assert_eq!(references.len(), 3);
        assert_eq!(references[0].reference_kind, "whole_column_reference");
        assert_eq!(references[1].reference_kind, "whole_row_reference");
        assert_eq!(
            references[2].sheet_resolution,
            "external_workbook_reference_unresolved"
        );
        assert_eq!(references[2].sheet_index_candidate, None);
    }

    #[test]
    fn matches_formula_defined_names_with_local_scope_precedence() {
        let sheets = [sheet("Input", "worksheet"), sheet("Output", "worksheet")];
        let names = [
            defined_name("TaxRate", "0.05", "workbook_scope", None, None),
            defined_name(
                "TaxRate",
                "0.075",
                "sheet_scope_candidate",
                Some(0),
                Some("Input"),
            ),
            defined_name(
                "Threshold",
                "'Output'!$A$1",
                "sheet_scope_candidate",
                Some(1),
                Some("Output"),
            ),
            defined_name("Discount", "=LAMBDA(x,x*0.9)", "workbook_scope", None, None),
        ];
        let formula_names = formula_name_metadata(&names);
        let formula_names_by_name = index_defined_names(&formula_names);
        let formula = "IF(A1>=Threshold,TaxRate,Discount(1))+Output!Threshold+\"TaxRate\"+Table1[TaxRate]+[Book.xlsx]TaxRate";
        let (address_references, _) = scan_formula_references(formula, 0, &sheets, 64);
        let (references, truncated) = scan_formula_defined_names(
            formula,
            FormulaNameEnvironment {
                current_sheet_index: 0,
                sheets: &sheets,
                defined_names: &formula_names,
                defined_names_by_name: &formula_names_by_name,
            },
            &address_references,
            64,
        );
        assert!(!truncated);
        assert_eq!(references.len(), 5);
        assert_eq!(references[0].reference, "Threshold");
        assert_eq!(references[0].defined_name_index_candidate, Some(2));
        assert_eq!(
            references[0].defined_name_resolution.as_deref(),
            Some("defined_name_out_of_scope_candidate")
        );
        assert_eq!(references[1].reference, "TaxRate");
        assert_eq!(references[1].defined_name_index_candidate, Some(1));
        assert_eq!(
            references[1].defined_name_resolution.as_deref(),
            Some("sheet_scoped_defined_name_candidate")
        );
        assert_eq!(references[2].reference, "Discount");
        assert_eq!(
            references[2].reference_kind,
            "defined_name_function_candidate"
        );
        assert_eq!(references[2].defined_name_index_candidate, Some(3));
        assert_eq!(references[3].reference, "Threshold");
        assert_eq!(
            references[3].defined_name_resolution.as_deref(),
            Some("qualified_defined_name_unresolved")
        );
        assert_eq!(references[4].reference, "TaxRate");
        assert_eq!(
            references[4].defined_name_resolution.as_deref(),
            Some("external_defined_name_unresolved")
        );
    }

    #[test]
    fn formula_address_and_defined_name_candidates_share_the_global_cap() {
        let sheets = [sheet("Input", "worksheet")];
        let mut names = [defined_name(
            "TaxRate",
            "0.075",
            "workbook_scope",
            None,
            None,
        )];
        let mut cells = vec![WorkbookCellInfo {
            sheet_index: 0,
            sheet_name: "Input".into(),
            cell_ref: "B2".into(),
            row: Some(2),
            column: Some(2),
            formula: Some("A1+TaxRate".into()),
            ..WorkbookCellInfo::default()
        }];
        populate_formula_reference_candidates(&mut cells, &sheets, &mut names, &[], 1, 8, false);
        assert_eq!(cells[0].formula_reference_candidates.len(), 1);
        assert_eq!(cells[0].formula_reference_candidates[0].reference, "A1");
        assert_eq!(
            cells[0].formula_reference_resolution,
            "reference_candidate_limit_truncated"
        );
        assert!(cells[0].formula_references_truncated);
    }

    #[test]
    fn marks_indirect_and_offset_targets_dynamic_without_losing_argument_inputs() {
        let sheets = [sheet("Data", "worksheet")];
        let formula = "INDIRECT(A1)+OFFSET(B2,1,0)+\"INDIRECT(C3)\"+MyOFFSET(D4)";
        let (dynamic, truncated) = scan_dynamic_reference_functions(formula, 8);
        assert!(!truncated);
        assert_eq!(dynamic.len(), 2);
        assert_eq!(dynamic[0].reference, "INDIRECT");
        assert_eq!(dynamic[1].reference, "OFFSET");
        assert!(
            dynamic
                .iter()
                .all(|candidate| candidate.cell_range_bounds.is_none())
        );
        let (addresses, _) = scan_formula_references(formula, 0, &sheets, 8);
        assert_eq!(
            addresses
                .iter()
                .map(|reference| reference.reference.as_str())
                .collect::<Vec<_>>(),
            vec!["A1", "B2", "D4"]
        );
        let mut workbook_cells = vec![
            WorkbookCellInfo {
                sheet_index: 0,
                sheet_name: "Data".into(),
                cell_ref: "E1".into(),
                row: Some(1),
                column: Some(5),
                formula: Some(formula.into()),
                ..WorkbookCellInfo::default()
            },
            WorkbookCellInfo {
                sheet_index: 0,
                sheet_name: "Data".into(),
                cell_ref: "A1".into(),
                row: Some(1),
                column: Some(1),
                value: Some("B3".into()),
                ..WorkbookCellInfo::default()
            },
            WorkbookCellInfo {
                sheet_index: 0,
                sheet_name: "Data".into(),
                cell_ref: "B2".into(),
                row: Some(2),
                column: Some(2),
                value: Some("2".into()),
                ..WorkbookCellInfo::default()
            },
            WorkbookCellInfo {
                sheet_index: 0,
                sheet_name: "Data".into(),
                cell_ref: "D4".into(),
                row: Some(4),
                column: Some(4),
                value: Some("4".into()),
                ..WorkbookCellInfo::default()
            },
        ];
        populate_formula_reference_candidates(
            &mut workbook_cells,
            &sheets,
            &mut [],
            &[],
            16,
            16,
            false,
        );
        let candidates = &workbook_cells[0].formula_reference_candidates;
        assert_eq!(
            candidates
                .iter()
                .filter(|candidate| {
                    candidate.reference_kind == "dynamic_reference_function_candidate"
                })
                .count(),
            2
        );
        assert!(candidates.iter().any(|candidate| {
            candidate.reference == "A1" && candidate.workbook_cell_indices == vec![1]
        }));
    }

    #[test]
    fn resolves_structured_table_data_totals_and_this_row_candidates() {
        let sheets = [sheet("Orders", "worksheet")];
        let tables = [WorkbookTableInfo {
            name: "OrdersTable".into(),
            display_name: "OrdersTable".into(),
            sheet_index: 0,
            sheet_name: "Orders".into(),
            cell_range_bounds: Some(CellRangeBounds {
                first_row: 1,
                first_column: 1,
                last_row: 4,
                last_column: 2,
            }),
            header_row_count: 1,
            totals_row_count: 1,
            columns: vec!["Order".into(), "Amount".into()],
            resolution: "resolved_internal".into(),
            ..WorkbookTableInfo::default()
        }];
        let formula = "SUM(OrdersTable[Amount])+SUM(OrdersTable[[#Totals],[Amount]])+OrdersTable[@Order]+[@[Amount]]+OrdersTable[[#Headers],[Amount]]+OrdersTable[#All]+[Order]+OrdersTable[[Order],[Amount]]+[Book.xlsx]Orders!A1";
        let mut cells = vec![
            WorkbookCellInfo {
                sheet_index: 0,
                sheet_name: "Orders".into(),
                cell_ref: "A2".into(),
                row: Some(2),
                column: Some(1),
                formula: Some(formula.into()),
                ..WorkbookCellInfo::default()
            },
            WorkbookCellInfo {
                sheet_index: 0,
                sheet_name: "Orders".into(),
                cell_ref: "A1".into(),
                row: Some(1),
                column: Some(1),
                value: Some("Order".into()),
                ..WorkbookCellInfo::default()
            },
            WorkbookCellInfo {
                sheet_index: 0,
                sheet_name: "Orders".into(),
                cell_ref: "B1".into(),
                row: Some(1),
                column: Some(2),
                value: Some("Amount".into()),
                ..WorkbookCellInfo::default()
            },
            WorkbookCellInfo {
                sheet_index: 0,
                sheet_name: "Orders".into(),
                cell_ref: "B2".into(),
                row: Some(2),
                column: Some(2),
                value: Some("10".into()),
                ..WorkbookCellInfo::default()
            },
            WorkbookCellInfo {
                sheet_index: 0,
                sheet_name: "Orders".into(),
                cell_ref: "B3".into(),
                row: Some(3),
                column: Some(2),
                value: Some("20".into()),
                ..WorkbookCellInfo::default()
            },
            WorkbookCellInfo {
                sheet_index: 0,
                sheet_name: "Orders".into(),
                cell_ref: "B4".into(),
                row: Some(4),
                column: Some(2),
                value: Some("30".into()),
                ..WorkbookCellInfo::default()
            },
        ];
        populate_formula_reference_candidates(&mut cells, &sheets, &mut [], &tables, 32, 32, false);
        let table_refs = cells[0]
            .formula_reference_candidates
            .iter()
            .filter(|reference| reference.reference_kind == "structured_table_reference_candidate")
            .collect::<Vec<_>>();
        assert_eq!(table_refs.len(), 8);
        assert_eq!(table_refs[0].table_column_index_candidate, Some(1));
        assert_eq!(
            table_refs[0].cell_range_bounds,
            Some(CellRangeBounds {
                first_row: 2,
                first_column: 2,
                last_row: 3,
                last_column: 2,
            })
        );
        assert_eq!(table_refs[0].workbook_cell_indices, vec![3, 4]);
        assert_eq!(table_refs[1].table_section.as_deref(), Some("totals"));
        assert_eq!(table_refs[1].workbook_cell_indices, vec![5]);
        assert_eq!(table_refs[2].table_section.as_deref(), Some("this_row"));
        assert_eq!(table_refs[2].workbook_cell_indices, vec![0]);
        assert_eq!(table_refs[3].workbook_cell_indices, vec![3]);
        assert_eq!(table_refs[4].table_section.as_deref(), Some("headers"));
        assert_eq!(table_refs[4].workbook_cell_indices, vec![2]);
        assert_eq!(table_refs[5].table_section.as_deref(), Some("all"));
        assert_eq!(table_refs[5].workbook_cell_indices, vec![1, 2, 0, 3, 4, 5]);
        assert_eq!(table_refs[6].table_section.as_deref(), Some("this_row"));
        assert_eq!(table_refs[6].workbook_cell_indices, vec![0]);
        assert_eq!(
            table_refs[7].table_resolution.as_deref(),
            Some("unsupported_structured_table_specifier")
        );
        assert!(table_refs[7].cell_range_bounds.is_none());
        assert!(
            cells[0]
                .formula_reference_candidates
                .iter()
                .any(|reference| {
                    reference.sheet_resolution == "external_workbook_reference_unresolved"
                })
        );
    }

    #[test]
    fn translates_shared_table_this_row_references_to_the_follower_row() {
        let sheets = [sheet("Orders", "worksheet")];
        let tables = [WorkbookTableInfo {
            name: "OrdersTable".into(),
            display_name: "OrdersTable".into(),
            sheet_index: 0,
            sheet_name: "Orders".into(),
            cell_range_bounds: Some(CellRangeBounds {
                first_row: 1,
                first_column: 1,
                last_row: 3,
                last_column: 2,
            }),
            header_row_count: 1,
            columns: vec!["Order".into(), "Amount".into()],
            resolution: "resolved_internal".into(),
            ..WorkbookTableInfo::default()
        }];
        let mut cells = vec![
            WorkbookCellInfo {
                sheet_index: 0,
                sheet_name: "Orders".into(),
                cell_ref: "A2".into(),
                row: Some(2),
                column: Some(1),
                formula: Some("[@Amount]".into()),
                formula_type: Some("shared".into()),
                formula_ref: Some("A2:A3".into()),
                formula_shared_index: Some(12),
                ..WorkbookCellInfo::default()
            },
            WorkbookCellInfo {
                sheet_index: 0,
                sheet_name: "Orders".into(),
                cell_ref: "A3".into(),
                row: Some(3),
                column: Some(1),
                formula: Some(String::new()),
                formula_type: Some("shared".into()),
                formula_shared_index: Some(12),
                ..WorkbookCellInfo::default()
            },
            WorkbookCellInfo {
                sheet_index: 0,
                sheet_name: "Orders".into(),
                cell_ref: "B2".into(),
                row: Some(2),
                column: Some(2),
                value: Some("10".into()),
                ..WorkbookCellInfo::default()
            },
            WorkbookCellInfo {
                sheet_index: 0,
                sheet_name: "Orders".into(),
                cell_ref: "B3".into(),
                row: Some(3),
                column: Some(2),
                value: Some("20".into()),
                ..WorkbookCellInfo::default()
            },
        ];
        populate_formula_reference_candidates(&mut cells, &sheets, &mut [], &tables, 32, 32, false);
        assert_eq!(
            cells[1].formula_reference_resolution,
            "shared_formula_relative_candidates_translated"
        );
        let translated = &cells[1].formula_reference_candidates[0];
        assert_eq!(translated.reference, "[@Amount]");
        assert_eq!(translated.table_section.as_deref(), Some("this_row"));
        assert_eq!(
            translated.cell_range_bounds,
            Some(CellRangeBounds {
                first_row: 3,
                first_column: 2,
                last_row: 3,
                last_column: 2,
            })
        );
        assert_eq!(translated.workbook_cell_indices, vec![3]);
    }

    #[test]
    fn defined_name_formulas_link_absolute_cells_but_leave_relative_anchors_unresolved() {
        let sheets = [sheet("Data", "worksheet")];
        let mut names = vec![
            defined_name(
                "Relative",
                "A1",
                "sheet_scope_candidate",
                Some(0),
                Some("Data"),
            ),
            defined_name(
                "Absolute",
                "=$A$1",
                "sheet_scope_candidate",
                Some(0),
                Some("Data"),
            ),
            defined_name(
                "QualifiedGlobal",
                "='Data'!$A$1",
                "workbook_scope",
                None,
                None,
            ),
        ];
        let mut cells = vec![WorkbookCellInfo {
            sheet_index: 0,
            sheet_name: "Data".into(),
            cell_ref: "A1".into(),
            row: Some(1),
            column: Some(1),
            value: Some("15".into()),
            ..WorkbookCellInfo::default()
        }];
        populate_formula_reference_candidates(&mut cells, &sheets, &mut names, &[], 16, 16, false);
        assert_eq!(
            names[0].formula_reference_candidates[0].sheet_resolution,
            "relative_defined_name_formula_reference_unresolved"
        );
        assert!(
            names[0].formula_reference_candidates[0]
                .workbook_cell_indices
                .is_empty()
        );
        assert_eq!(
            names[1].formula_reference_candidates[0].workbook_cell_indices,
            vec![0]
        );
        assert_eq!(
            names[2].formula_reference_candidates[0].workbook_cell_indices,
            vec![0]
        );
    }

    #[test]
    fn defined_name_formula_links_only_absolute_or_explicitly_resolvable_cells() {
        let sheets = [sheet("Data", "worksheet")];
        let mut names = vec![
            defined_name(
                "RelativeCell",
                "A1",
                "sheet_scope_candidate",
                Some(0),
                Some("Data"),
            ),
            defined_name(
                "AbsoluteCell",
                "=$A$1",
                "sheet_scope_candidate",
                Some(0),
                Some("Data"),
            ),
            defined_name("GlobalUnqualified", "=$A$1", "workbook_scope", None, None),
        ];
        let mut cells = vec![WorkbookCellInfo {
            sheet_index: 0,
            sheet_name: "Data".into(),
            cell_ref: "A1".into(),
            row: Some(1),
            column: Some(1),
            value: Some("15".into()),
            ..WorkbookCellInfo::default()
        }];
        populate_formula_reference_candidates(&mut cells, &sheets, &mut names, &[], 16, 16, false);
        assert_eq!(
            names[0].formula_reference_candidates[0].sheet_resolution,
            "relative_defined_name_formula_reference_unresolved"
        );
        assert!(
            names[0].formula_reference_candidates[0]
                .workbook_cell_indices
                .is_empty()
        );
        assert_eq!(
            names[1].formula_reference_candidates[0].workbook_cell_indices,
            vec![0]
        );
        assert_eq!(
            names[2].formula_reference_candidates[0].sheet_resolution,
            "unresolved_formula_worksheet_context"
        );
        assert!(
            names[2].formula_reference_candidates[0]
                .workbook_cell_indices
                .is_empty()
        );
    }

    #[test]
    fn retains_only_populated_cell_links_and_reports_both_caps() {
        let sheets = [sheet("Data", "worksheet")];
        let mut cells = vec![
            WorkbookCellInfo {
                sheet_index: 0,
                sheet_name: "Data".into(),
                cell_ref: "A1".into(),
                row: Some(1),
                column: Some(1),
                formula: Some("B1+D1+\"C1\"".into()),
                ..WorkbookCellInfo::default()
            },
            WorkbookCellInfo {
                sheet_index: 0,
                sheet_name: "Data".into(),
                cell_ref: "B1".into(),
                row: Some(1),
                column: Some(2),
                value: Some("2".into()),
                ..WorkbookCellInfo::default()
            },
            WorkbookCellInfo {
                sheet_index: 0,
                sheet_name: "Data".into(),
                cell_ref: "C1".into(),
                row: Some(1),
                column: Some(3),
                value: Some("3".into()),
                ..WorkbookCellInfo::default()
            },
            WorkbookCellInfo {
                sheet_index: 0,
                sheet_name: "Data".into(),
                cell_ref: "D1".into(),
                row: Some(1),
                column: Some(4),
                value: Some("4".into()),
                ..WorkbookCellInfo::default()
            },
        ];
        populate_formula_reference_candidates(&mut cells, &sheets, &mut [], &[], 1, 10, false);
        assert_eq!(cells[0].formula_reference_candidates.len(), 1);
        assert_eq!(cells[0].formula_reference_candidates[0].reference, "B1");
        assert_eq!(
            cells[0].formula_reference_candidates[0].workbook_cell_indices,
            vec![1]
        );
        assert!(cells[0].formula_references_truncated);

        populate_formula_reference_candidates(&mut cells, &sheets, &mut [], &[], 10, 1, false);
        assert_eq!(cells[0].formula_reference_candidates.len(), 2);
        assert_eq!(
            cells[0].formula_reference_candidates[0].workbook_cell_indices,
            vec![1]
        );
        assert!(cells[0].formula_reference_candidates[1].workbook_cell_matches_truncated);

        populate_formula_reference_candidates(&mut cells, &sheets, &mut [], &[], 10, 10, true);
        assert!(cells[0].formula_reference_candidates[0].workbook_cell_matches_truncated);
    }

    #[test]
    fn marks_shared_formula_followers_without_formula_text_unresolved() {
        let sheets = [sheet("Data", "worksheet")];
        let mut cells = vec![WorkbookCellInfo {
            sheet_index: 0,
            sheet_name: "Data".into(),
            cell_ref: "A2".into(),
            row: Some(2),
            column: Some(1),
            formula: Some(String::new()),
            formula_type: Some("shared".into()),
            formula_shared_index: Some(4),
            ..WorkbookCellInfo::default()
        }];
        populate_formula_reference_candidates(&mut cells, &sheets, &mut [], &[], 16, 16, false);
        assert_eq!(
            cells[0].formula_reference_resolution,
            "shared_formula_text_absent_unresolved"
        );
        assert_eq!(cells[0].formula_reference_source_cell_index, None);
        assert!(cells[0].formula_reference_candidates.is_empty());
    }

    #[test]
    fn translates_shared_formula_relative_and_absolute_reference_axes() {
        let sheets = [sheet("Data", "worksheet")];
        let mut cells = vec![
            WorkbookCellInfo {
                sheet_index: 0,
                sheet_name: "Data".into(),
                cell_ref: "B2".into(),
                row: Some(2),
                column: Some(2),
                formula: Some("A1+$C$3+D$4+$E5+A:A+1:1".into()),
                formula_type: Some("shared".into()),
                formula_ref: Some("$B$2:$C$3".into()),
                formula_shared_index: Some(9),
                ..WorkbookCellInfo::default()
            },
            WorkbookCellInfo {
                sheet_index: 0,
                sheet_name: "Data".into(),
                cell_ref: "C3".into(),
                row: Some(3),
                column: Some(3),
                formula: Some(String::new()),
                formula_type: Some("shared".into()),
                formula_shared_index: Some(9),
                ..WorkbookCellInfo::default()
            },
        ];
        populate_formula_reference_candidates(&mut cells, &sheets, &mut [], &[], 32, 32, false);
        assert_eq!(
            cells[0].formula_reference_resolution,
            "partial_formula_reference_scan"
        );
        assert_eq!(
            cells[1].formula_reference_resolution,
            "shared_formula_relative_candidates_translated"
        );
        assert_eq!(cells[1].formula_reference_source_cell_index, Some(0));
        let references = &cells[1].formula_reference_candidates;
        assert_eq!(
            references
                .iter()
                .map(|reference| reference.reference.as_str())
                .collect::<Vec<_>>(),
            vec!["B2", "$C$3", "E$4", "$E6", "B:B", "2:2"]
        );
        assert_eq!(references[0].workbook_cell_indices, vec![0]);
        assert_eq!(references[1].workbook_cell_indices, vec![1]);
        assert!(references[4].workbook_cell_indices.contains(&0));
    }

    #[test]
    fn shared_master_overrides_a_follower_formula_text() {
        let sheets = [sheet("Data", "worksheet")];
        let mut cells = vec![
            WorkbookCellInfo {
                sheet_index: 0,
                sheet_name: "Data".into(),
                cell_ref: "A1".into(),
                row: Some(1),
                column: Some(1),
                formula: Some("B1".into()),
                formula_type: Some("shared".into()),
                formula_ref: Some("A1:A2".into()),
                formula_shared_index: Some(11),
                ..WorkbookCellInfo::default()
            },
            WorkbookCellInfo {
                sheet_index: 0,
                sheet_name: "Data".into(),
                cell_ref: "A2".into(),
                row: Some(2),
                column: Some(1),
                formula: Some("XFD1048576".into()),
                formula_type: Some("shared".into()),
                formula_shared_index: Some(11),
                ..WorkbookCellInfo::default()
            },
        ];
        populate_formula_reference_candidates(&mut cells, &sheets, &mut [], &[], 16, 16, false);
        assert_eq!(
            cells[1].formula_reference_resolution,
            "shared_formula_relative_candidates_translated"
        );
        assert_eq!(cells[1].formula_reference_candidates.len(), 1);
        assert_eq!(cells[1].formula_reference_candidates[0].reference, "B2");
        assert_eq!(cells[1].formula_reference_source_cell_index, Some(0));
    }

    #[test]
    fn marks_shared_formula_relative_references_out_of_grid_unresolved() {
        let sheets = [sheet("Data", "worksheet")];
        let mut cells = vec![
            WorkbookCellInfo {
                sheet_index: 0,
                sheet_name: "Data".into(),
                cell_ref: "A2".into(),
                row: Some(2),
                column: Some(1),
                formula: Some("A1".into()),
                formula_type: Some("shared".into()),
                formula_ref: Some("A1:A2".into()),
                formula_shared_index: Some(10),
                ..WorkbookCellInfo::default()
            },
            WorkbookCellInfo {
                sheet_index: 0,
                sheet_name: "Data".into(),
                cell_ref: "A1".into(),
                row: Some(1),
                column: Some(1),
                formula: Some(String::new()),
                formula_type: Some("shared".into()),
                formula_shared_index: Some(10),
                ..WorkbookCellInfo::default()
            },
        ];
        populate_formula_reference_candidates(&mut cells, &sheets, &mut [], &[], 16, 16, false);
        assert_eq!(
            cells[1].formula_reference_resolution,
            "shared_formula_translation_partially_unresolved"
        );
        assert_eq!(
            cells[1].formula_reference_candidates[0].sheet_resolution,
            "shared_formula_translation_out_of_grid_unresolved"
        );
        assert!(
            cells[1].formula_reference_candidates[0]
                .cell_range_bounds
                .is_none()
        );
    }
}
