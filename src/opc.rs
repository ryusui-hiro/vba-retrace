//! Minimal, bounded Open Packaging Convention relationship lookup.
//!
//! Relationship targets, rather than conventional ZIP paths, identify the
//! workbook and its VBA project part. XML external entities are not expanded.

use crate::model::{
    CellRangeBounds, WorkbookCellInfo, WorkbookDefinedNameInfo, WorkbookSheetInfo,
    WorkbookTableInfo,
};
use crate::source::decode_text;
use crate::zip::{ZipArchive, ZipEntry};
use std::collections::{HashMap, HashSet};

const RELATIONSHIPS_NS: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
const STRICT_RELATIONSHIPS_NS: &str = "http://purl.oclc.org/ooxml/package/relationships";
const OFFICE_DOCUMENT_REL: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument";
const STRICT_OFFICE_DOCUMENT_REL: &str =
    "http://purl.oclc.org/ooxml/officeDocument/relationships/officeDocument";
const VBA_PROJECT_REL: &str = "http://schemas.microsoft.com/office/2006/relationships/vbaProject";
const SHARED_STRINGS_REL: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings";
const STRICT_SHARED_STRINGS_REL: &str =
    "http://purl.oclc.org/ooxml/officeDocument/relationships/sharedStrings";
const TABLE_REL: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/table";
const STRICT_TABLE_REL: &str = "http://purl.oclc.org/ooxml/officeDocument/relationships/table";
const SPREADSHEET_NS: &str = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
const STRICT_SPREADSHEET_NS: &str = "http://purl.oclc.org/ooxml/spreadsheetml/main";
const OFFICE_RELATIONSHIPS_NS: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
const STRICT_OFFICE_RELATIONSHIPS_NS: &str =
    "http://purl.oclc.org/ooxml/officeDocument/relationships";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TargetMode {
    Internal,
    External,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Relationship {
    pub(crate) id: String,
    pub(crate) relationship_type: String,
    pub(crate) target: String,
    pub(crate) target_mode: TargetMode,
}

pub(crate) struct XlsmPackageParts {
    pub vba_project_part: String,
    pub workbook_code_name: Option<String>,
    pub workbook_sheets: Vec<WorkbookSheetInfo>,
    pub workbook_defined_names: Vec<WorkbookDefinedNameInfo>,
    pub workbook_tables: Vec<WorkbookTableInfo>,
    pub workbook_tables_truncated: bool,
    pub workbook_cells: Vec<WorkbookCellInfo>,
    pub workbook_cells_truncated: bool,
    pub workbook_diagnostics: Vec<String>,
}

#[derive(Default)]
struct WorkbookMetadata {
    workbook_code_name: Option<String>,
    sheets: Vec<WorkbookSheetInfo>,
    defined_names: Vec<WorkbookDefinedNameInfo>,
    tables: Vec<WorkbookTableInfo>,
    tables_truncated: bool,
    cells: Vec<WorkbookCellInfo>,
    cells_truncated: bool,
    diagnostics: Vec<String>,
}

#[derive(Clone, Copy)]
struct WorkbookReadLimits {
    max_relationships: usize,
    max_sheets: usize,
    max_workbook_cells: usize,
    max_formula_references: usize,
    max_formula_cell_links: usize,
    max_workbook_tables: usize,
}

/// Resolve the workbook and VBA parts through OPC relationships and inventory sheets.
pub(crate) fn resolve_xlsm_package(
    archive: &ZipArchive<'_>,
    max_relationships: usize,
    max_workbook_cells: usize,
    max_formula_references: usize,
    max_formula_cell_links: usize,
    max_workbook_tables: usize,
) -> Result<XlsmPackageParts, String> {
    let relationship_limit = max_relationships.max(1);
    let package_relationships = read_relationships(archive, "_rels/.rels", relationship_limit)?;
    let workbook_relationship = unique_relationship(
        &package_relationships,
        |relationship| is_office_document_relationship(&relationship.relationship_type),
        "package officeDocument",
    )?;
    if workbook_relationship.target_mode != TargetMode::Internal {
        return Err("officeDocument relationship must target a package part".into());
    }
    let workbook_part = resolve_part_target(None, &workbook_relationship.target)?;
    let workbook_relationships_part = relationship_part_name(&workbook_part)?;
    let workbook_relationships =
        read_relationships(archive, &workbook_relationships_part, relationship_limit)?;
    let vba_relationship = unique_relationship(
        &workbook_relationships,
        |relationship| relationship.relationship_type == VBA_PROJECT_REL,
        "workbook VBA project",
    )?;
    if vba_relationship.target_mode != TargetMode::Internal {
        return Err("VBA project relationship must target a package part".into());
    }
    let vba_part = resolve_part_target(Some(&workbook_part), &vba_relationship.target)?;
    let entry = unique_zip_entry(archive, &vba_part)?
        .ok_or_else(|| format!("VBA project relationship target is missing: {vba_part}"))?;
    let (workbook_metadata, workbook_diagnostics) = match read_workbook_metadata(
        archive,
        &workbook_part,
        &workbook_relationships,
        WorkbookReadLimits {
            max_relationships: relationship_limit,
            max_sheets: relationship_limit,
            max_workbook_cells,
            max_formula_references,
            max_formula_cell_links,
            max_workbook_tables,
        },
    ) {
        Ok(metadata) => {
            let mut diagnostics = metadata.diagnostics.clone();
            diagnostics.extend(
                metadata
                    .sheets
                    .iter()
                    .filter(|sheet| sheet.resolution != "resolved_internal")
                    .map(|sheet| {
                        format!(
                            "worksheet '{}' relationship is {}",
                            sheet.name, sheet.resolution
                        )
                    }),
            );
            (metadata, diagnostics)
        }
        Err(error) => (
            WorkbookMetadata::default(),
            vec![format!("workbook metadata unavailable: {error}")],
        ),
    };
    Ok(XlsmPackageParts {
        vba_project_part: entry.name.clone(),
        workbook_code_name: workbook_metadata.workbook_code_name,
        workbook_sheets: workbook_metadata.sheets,
        workbook_defined_names: workbook_metadata.defined_names,
        workbook_tables: workbook_metadata.tables,
        workbook_tables_truncated: workbook_metadata.tables_truncated,
        workbook_cells: workbook_metadata.cells,
        workbook_cells_truncated: workbook_metadata.cells_truncated,
        workbook_diagnostics,
    })
}

fn is_office_document_relationship(relationship_type: &str) -> bool {
    matches!(
        relationship_type,
        OFFICE_DOCUMENT_REL | STRICT_OFFICE_DOCUMENT_REL
    )
}

fn unique_relationship<'a>(
    relationships: &'a [Relationship],
    matches: impl Fn(&Relationship) -> bool,
    description: &str,
) -> Result<&'a Relationship, String> {
    let mut found = relationships
        .iter()
        .filter(|relationship| matches(relationship));
    let relationship = found
        .next()
        .ok_or_else(|| format!("missing {description} relationship"))?;
    if found.next().is_some() {
        return Err(format!("multiple {description} relationships"));
    }
    Ok(relationship)
}

pub(crate) fn read_relationships(
    archive: &ZipArchive<'_>,
    part_name: &str,
    max_relationships: usize,
) -> Result<Vec<Relationship>, String> {
    let entry = unique_zip_entry(archive, part_name)?
        .ok_or_else(|| format!("missing OPC relationships part: {part_name}"))?;
    let bytes = archive.read(entry)?;
    let xml = decode_text(&bytes, None).map_err(|error| error.to_string())?;
    parse_relationship_xml(&xml, max_relationships)
}

fn read_workbook_metadata(
    archive: &ZipArchive<'_>,
    workbook_part: &str,
    relationships: &[Relationship],
    limits: WorkbookReadLimits,
) -> Result<WorkbookMetadata, String> {
    let entry = unique_zip_entry(archive, workbook_part)?
        .ok_or_else(|| format!("workbook relationship target is missing: {workbook_part}"))?;
    let bytes = archive.read(entry)?;
    let xml = decode_text(&bytes, None).map_err(|error| error.to_string())?;
    let mut metadata = parse_workbook_metadata_xml(
        archive,
        &xml,
        workbook_part,
        relationships,
        limits.max_sheets,
    )?;
    let (shared_strings, shared_strings_truncated) = match read_shared_strings(
        archive,
        workbook_part,
        relationships,
        limits.max_workbook_cells,
    ) {
        Ok(shared_strings) => shared_strings,
        Err(error) => {
            metadata
                .diagnostics
                .push(format!("shared string table unavailable: {error}"));
            (Vec::new(), false)
        }
    };
    metadata.cells_truncated |= shared_strings_truncated;
    let mut remaining_cells = limits.max_workbook_cells;
    let mut remaining_tables = limits.max_workbook_tables;
    let mut sheet_code_names = Vec::new();
    for (sheet_index, sheet) in metadata.sheets.iter().enumerate() {
        if !sheet.kind.eq_ignore_ascii_case("worksheet")
            && !sheet.kind.eq_ignore_ascii_case("macrosheet")
            && !sheet.kind.eq_ignore_ascii_case("dialogsheet")
        {
            continue;
        }
        let Some(part_name) = sheet.part_name.as_deref() else {
            continue;
        };
        match read_worksheet_cells(
            archive,
            part_name,
            sheet_index,
            &sheet.name,
            &shared_strings,
            remaining_cells,
            remaining_tables,
        ) {
            Ok(worksheet) => {
                if let Some(code_name) = worksheet.code_name {
                    sheet_code_names.push((sheet_index, code_name));
                }
                remaining_cells = remaining_cells.saturating_sub(worksheet.cells.len());
                metadata.cells.extend(worksheet.cells);
                if worksheet.cells_truncated {
                    metadata.cells_truncated = true;
                }
                if worksheet.table_relationships_truncated {
                    metadata.tables_truncated = true;
                }
                if !worksheet.table_relationship_ids.is_empty() && remaining_tables > 0 {
                    match read_worksheet_tables(
                        archive,
                        part_name,
                        sheet_index,
                        &sheet.name,
                        &worksheet.table_relationship_ids,
                        limits.max_relationships,
                        remaining_tables,
                    ) {
                        Ok((tables, truncated, diagnostics)) => {
                            remaining_tables = remaining_tables.saturating_sub(tables.len());
                            metadata.tables.extend(tables);
                            metadata.tables_truncated |= truncated;
                            metadata.diagnostics.extend(diagnostics);
                        }
                        Err(error) => metadata.diagnostics.push(format!(
                            "worksheet '{}' table metadata unavailable: {error}",
                            sheet.name
                        )),
                    }
                } else if !worksheet.table_relationship_ids.is_empty()
                    || worksheet.table_relationships_truncated
                {
                    metadata.tables_truncated = true;
                }
            }
            Err(error) => metadata.diagnostics.push(format!(
                "worksheet '{}' cell metadata unavailable: {error}",
                sheet.name
            )),
        }
    }
    for (sheet_index, code_name) in sheet_code_names {
        if let Some(sheet) = metadata.sheets.get_mut(sheet_index) {
            sheet.code_name = Some(code_name);
        }
    }
    crate::excel_formula::populate_formula_reference_candidates(
        &mut metadata.cells,
        &metadata.sheets,
        &mut metadata.defined_names,
        &metadata.tables,
        limits.max_formula_references,
        limits.max_formula_cell_links,
        metadata.cells_truncated,
    );
    Ok(metadata)
}

fn read_shared_strings(
    archive: &ZipArchive<'_>,
    workbook_part: &str,
    relationships: &[Relationship],
    max_items: usize,
) -> Result<(Vec<String>, bool), String> {
    let mut shared_string_relationships = relationships
        .iter()
        .filter(|relationship| is_shared_strings_relationship(&relationship.relationship_type));
    let Some(relationship) = shared_string_relationships.next() else {
        return Ok((Vec::new(), false));
    };
    if shared_string_relationships.next().is_some() {
        return Err("multiple shared string table relationships".into());
    }
    if relationship.target_mode == TargetMode::External {
        return Err("shared string table relationship targets an external resource".into());
    }
    let target = resolve_part_target(Some(workbook_part), &relationship.target)?;
    let entry = unique_zip_entry(archive, &target)?
        .ok_or_else(|| format!("shared string table relationship target is missing: {target}"))?;
    let bytes = archive.read(entry)?;
    let xml = decode_text(&bytes, None).map_err(|error| error.to_string())?;
    parse_shared_strings_xml(&xml, max_items)
}

fn is_shared_strings_relationship(relationship_type: &str) -> bool {
    matches!(
        relationship_type,
        SHARED_STRINGS_REL | STRICT_SHARED_STRINGS_REL
    )
}

fn parse_shared_strings_xml(xml: &str, max_items: usize) -> Result<(Vec<String>, bool), String> {
    let mut strings = Vec::new();
    let mut stack = Vec::<(String, HashMap<String, String>)>::new();
    let mut current_item: Option<(usize, String)> = None;
    let mut text_capture: Option<(usize, String)> = None;
    let mut cursor = 0usize;
    let mut root_seen = false;
    let mut root_closed = false;
    let mut tag_count = 0usize;
    let max_tags = max_items.saturating_mul(64).saturating_add(65_536);

    while cursor < xml.len() {
        let Some(relative) = xml[cursor..].find('<') else {
            if let Some((_, value)) = text_capture.as_mut() {
                value.push_str(&decode_xml_entities(&xml[cursor..])?);
            } else if stack.is_empty()
                && xml[cursor..]
                    .chars()
                    .any(|character| !is_xml_whitespace(character))
            {
                return Err("non-whitespace text outside shared string table root".into());
            }
            break;
        };
        let opening = cursor + relative;
        if let Some((_, value)) = text_capture.as_mut() {
            value.push_str(&decode_xml_entities(&xml[cursor..opening])?);
        } else if stack.is_empty()
            && xml[cursor..opening]
                .chars()
                .any(|character| !is_xml_whitespace(character))
        {
            return Err("unexpected text outside shared string table root".into());
        }
        if xml[opening..].starts_with("<!--") {
            cursor = skip_xml_delimited(xml, opening + 4, "-->")?;
            continue;
        }
        if xml[opening..].starts_with("<?") {
            cursor = skip_xml_delimited(xml, opening + 2, "?>")?;
            continue;
        }
        if xml[opening..].starts_with("<![CDATA[") {
            let content_start = opening + 9;
            let content_end = content_start
                + xml[content_start..]
                    .find("]]>")
                    .ok_or("unterminated shared-string CDATA section")?;
            if let Some((_, value)) = text_capture.as_mut() {
                value.push_str(&xml[content_start..content_end]);
            }
            cursor = content_end + 3;
            continue;
        }
        if xml[opening..].starts_with("<!") {
            return Err("DTD and XML declarations are not supported in shared strings".into());
        }
        let (tag, next) = parse_xml_tag(xml, opening)?;
        cursor = next;
        tag_count += 1;
        if tag_count > max_tags {
            return Err("shared string table XML element limit exceeded".into());
        }
        if tag.closing {
            if stack
                .last()
                .is_none_or(|(name, _)| name.as_str() != tag.name)
            {
                return Err("mismatched closing tag in shared string table".into());
            }
            let depth = stack.len().saturating_sub(1);
            let local = local_name(&tag.name);
            if local == "t"
                && let Some((capture_depth, value)) = text_capture.take()
                && capture_depth == depth
                && let Some((_, item_text)) = current_item.as_mut()
            {
                item_text.push_str(&value);
            }
            if local == "si"
                && let Some((item_depth, value)) = current_item.take()
                && item_depth == depth
            {
                strings.push(value);
            }
            let (name, _) = stack.pop().ok_or("unexpected shared string closing tag")?;
            debug_assert_eq!(name, tag.name);
            if stack.is_empty() {
                root_closed = true;
            }
            continue;
        }

        let depth = stack.len();
        let parent = stack.last().map(|(name, _)| local_name(name));
        let mut namespaces = stack
            .last()
            .map(|(_, namespaces)| namespaces.clone())
            .unwrap_or_default();
        add_xml_namespaces(&tag, &mut namespaces);
        let local = local_name(&tag.name);
        let namespace = element_namespace(&tag.name, &namespaces).unwrap_or("");
        if depth == 0 {
            if root_seen || local != "sst" || !is_spreadsheet_namespace(namespace) {
                return Err("invalid SpreadsheetML shared string table root or namespace".into());
            }
            root_seen = true;
            if tag.self_closing {
                root_closed = true;
            }
        } else if depth == 1
            && parent == Some("sst")
            && local == "si"
            && is_spreadsheet_namespace(namespace)
        {
            if strings.len() >= max_items {
                return Ok((strings, true));
            }
            current_item = Some((depth, String::new()));
            if tag.self_closing {
                strings.push(String::new());
                current_item = None;
            }
        } else if current_item.is_some()
            && local == "t"
            && is_spreadsheet_namespace(namespace)
            && matches!(parent, Some("si" | "r"))
            && !tag.self_closing
        {
            text_capture = Some((depth, String::new()));
        }
        if !tag.self_closing {
            stack.push((tag.name, namespaces));
        }
    }
    if !root_seen || !root_closed || !stack.is_empty() || current_item.is_some() {
        return Err("incomplete SpreadsheetML shared string table XML".into());
    }
    Ok((strings, false))
}

struct WorksheetReadResult {
    cells: Vec<WorkbookCellInfo>,
    cells_truncated: bool,
    table_relationship_ids: Vec<String>,
    table_relationships_truncated: bool,
    code_name: Option<String>,
}

fn read_worksheet_cells(
    archive: &ZipArchive<'_>,
    part_name: &str,
    sheet_index: usize,
    sheet_name: &str,
    shared_strings: &[String],
    max_cells: usize,
    max_table_parts: usize,
) -> Result<WorksheetReadResult, String> {
    let entry = unique_zip_entry(archive, part_name)?
        .ok_or_else(|| format!("worksheet relationship target is missing: {part_name}"))?;
    let bytes = archive.read(entry)?;
    let xml = decode_text(&bytes, None).map_err(|error| error.to_string())?;
    let (cells, cells_truncated) =
        parse_worksheet_cells_xml(&xml, sheet_index, sheet_name, shared_strings, max_cells)?;
    let (table_relationship_ids, table_ids_truncated, code_name) =
        parse_worksheet_table_relationship_ids(&xml, max_table_parts)?;
    Ok(WorksheetReadResult {
        cells,
        cells_truncated,
        table_relationship_ids,
        table_relationships_truncated: table_ids_truncated,
        code_name,
    })
}

#[derive(Default)]
struct ParsedTableDefinition {
    name: String,
    display_name: String,
    reference: String,
    header_row_count: u32,
    totals_row_count: u32,
    columns: Vec<String>,
    columns_truncated: bool,
}

fn read_worksheet_tables(
    archive: &ZipArchive<'_>,
    worksheet_part: &str,
    sheet_index: usize,
    sheet_name: &str,
    relationship_ids: &[String],
    max_relationships: usize,
    max_tables: usize,
) -> Result<(Vec<WorkbookTableInfo>, bool, Vec<String>), String> {
    let relationships_part = relationship_part_name(worksheet_part)?;
    let entry = unique_zip_entry(archive, &relationships_part)?
        .ok_or_else(|| format!("missing worksheet relationships part: {relationships_part}"))?;
    let bytes = archive.read(entry)?;
    let xml = decode_text(&bytes, None).map_err(|error| error.to_string())?;
    let relationships = parse_relationship_xml(&xml, max_relationships.max(1))?;
    let mut tables = Vec::new();
    let mut diagnostics = Vec::new();
    let mut truncated = false;
    let mut seen_ids = HashSet::new();
    for relationship_id in relationship_ids {
        if !seen_ids.insert(relationship_id.as_str()) {
            diagnostics.push(format!(
                "worksheet '{}' repeats table relationship id '{}'",
                sheet_name, relationship_id
            ));
            continue;
        }
        let mut candidates = relationships
            .iter()
            .filter(|relationship| relationship.id == *relationship_id);
        let Some(relationship) = candidates.next() else {
            diagnostics.push(format!(
                "worksheet '{}' table relationship '{}' is missing",
                sheet_name, relationship_id
            ));
            continue;
        };
        if candidates.next().is_some() {
            diagnostics.push(format!(
                "worksheet '{}' table relationship '{}' is ambiguous",
                sheet_name, relationship_id
            ));
            continue;
        }
        if !is_table_relationship(&relationship.relationship_type) {
            diagnostics.push(format!(
                "worksheet '{}' tablePart '{}' does not target a table relationship",
                sheet_name, relationship_id
            ));
            continue;
        }
        if relationship.target_mode == TargetMode::External {
            diagnostics.push(format!(
                "worksheet '{}' table relationship '{}' targets an external part",
                sheet_name, relationship_id
            ));
            continue;
        }
        if tables.len() >= max_tables {
            truncated = true;
            break;
        }
        let target = resolve_part_target(Some(worksheet_part), &relationship.target)?;
        let Some(table_entry) = unique_zip_entry(archive, &target)? else {
            diagnostics.push(format!(
                "worksheet '{}' table relationship '{}' target is missing",
                sheet_name, relationship_id
            ));
            continue;
        };
        let bytes = archive.read(table_entry)?;
        let table_xml = decode_text(&bytes, None).map_err(|error| error.to_string())?;
        let definition = match parse_table_definition_xml(&table_xml, 16_384) {
            Ok(definition) => definition,
            Err(error) => {
                diagnostics.push(format!(
                    "worksheet '{}' table part '{}' is invalid: {error}",
                    sheet_name, target
                ));
                continue;
            }
        };
        let cell_range_bounds = parse_table_range_bounds(&definition.reference);
        let resolution = if definition.name.is_empty() || definition.display_name.is_empty() {
            "table_name_metadata_unresolved"
        } else if definition.columns_truncated {
            "table_column_inventory_truncated"
        } else if cell_range_bounds.is_none() {
            "table_range_unresolved"
        } else if let Some(bounds) = cell_range_bounds
            && usize::try_from(bounds.last_column - bounds.first_column + 1)
                .ok()
                .is_some_and(|width| width != definition.columns.len())
        {
            "table_column_count_mismatch"
        } else {
            "resolved_internal"
        };
        tables.push(WorkbookTableInfo {
            name: definition.name,
            display_name: definition.display_name,
            sheet_index,
            sheet_name: sheet_name.into(),
            part_name: Some(target),
            cell_range_bounds,
            header_row_count: definition.header_row_count,
            totals_row_count: definition.totals_row_count,
            columns: definition.columns,
            resolution: resolution.into(),
        });
    }
    Ok((tables, truncated, diagnostics))
}

fn is_table_relationship(relationship_type: &str) -> bool {
    matches!(relationship_type, TABLE_REL | STRICT_TABLE_REL)
}

fn parse_table_definition_xml(
    xml: &str,
    max_columns: usize,
) -> Result<ParsedTableDefinition, String> {
    let mut definition = ParsedTableDefinition {
        header_row_count: 1,
        ..ParsedTableDefinition::default()
    };
    let mut stack = Vec::<(String, HashMap<String, String>)>::new();
    let mut cursor = 0usize;
    let mut root_seen = false;
    let mut root_closed = false;
    let mut tag_count = 0usize;
    let max_tags = max_columns.saturating_mul(16).saturating_add(4096);
    while cursor < xml.len() {
        let Some(relative) = xml[cursor..].find('<') else {
            if stack.is_empty()
                && xml[cursor..]
                    .chars()
                    .any(|character| !is_xml_whitespace(character))
            {
                return Err("non-whitespace text outside table XML root".into());
            }
            break;
        };
        let opening = cursor + relative;
        if stack.is_empty()
            && xml[cursor..opening]
                .chars()
                .any(|character| !is_xml_whitespace(character))
        {
            return Err("unexpected text outside table XML root".into());
        }
        if xml[opening..].starts_with("<!--") {
            cursor = skip_xml_delimited(xml, opening + 4, "-->")?;
            continue;
        }
        if xml[opening..].starts_with("<?") {
            cursor = skip_xml_delimited(xml, opening + 2, "?>")?;
            continue;
        }
        if xml[opening..].starts_with("<![CDATA[") {
            let content_start = opening + 9;
            let content_end = content_start
                + xml[content_start..]
                    .find("]]>")
                    .ok_or("unterminated table CDATA section")?;
            if stack.is_empty()
                && xml[content_start..content_end]
                    .chars()
                    .any(|character| !is_xml_whitespace(character))
            {
                return Err("unexpected CDATA outside table XML root".into());
            }
            cursor = content_end + 3;
            continue;
        }
        if xml[opening..].starts_with("<!") {
            return Err("DTD and XML declarations are not supported in table XML".into());
        }
        let (tag, next) = parse_xml_tag(xml, opening)?;
        cursor = next;
        tag_count += 1;
        if tag_count > max_tags {
            return Err("table XML element limit exceeded".into());
        }
        if tag.closing {
            if stack
                .last()
                .is_none_or(|(name, _)| name.as_str() != tag.name)
            {
                return Err("mismatched closing tag in table XML".into());
            }
            let (name, _) = stack.pop().ok_or("unexpected table closing tag")?;
            debug_assert_eq!(name, tag.name);
            if stack.is_empty() {
                root_closed = true;
            }
            continue;
        }
        let depth = stack.len();
        let parent = stack.last().map(|(name, _)| local_name(name));
        let mut namespaces = stack
            .last()
            .map(|(_, namespaces)| namespaces.clone())
            .unwrap_or_default();
        add_xml_namespaces(&tag, &mut namespaces);
        let local = local_name(&tag.name);
        let namespace = element_namespace(&tag.name, &namespaces).unwrap_or("");
        if depth == 0 {
            if root_seen || local != "table" || !is_spreadsheet_namespace(namespace) {
                return Err("invalid SpreadsheetML table root or namespace".into());
            }
            root_seen = true;
            definition.name = attribute(&tag, "name").unwrap_or_default();
            definition.display_name =
                attribute(&tag, "displayName").unwrap_or_else(|| definition.name.clone());
            definition.reference = attribute(&tag, "ref").unwrap_or_default();
            definition.header_row_count =
                parse_table_row_count(&tag, "headerRowCount")?.unwrap_or(1);
            definition.totals_row_count = parse_table_row_count(&tag, "totalsRowCount")?
                .or_else(|| {
                    attribute(&tag, "totalsRowShown")
                        .and_then(|value| parse_xml_bool(&value))
                        .filter(|shown| *shown)
                        .map(|_| 1)
                })
                .unwrap_or(0);
            if definition.header_row_count > 1 || definition.totals_row_count > 1 {
                return Err("unsupported table header/totals row count".into());
            }
            if tag.self_closing {
                root_closed = true;
            }
        } else if depth == 2
            && parent == Some("tableColumns")
            && stack
                .first()
                .is_some_and(|(name, _)| local_name(name) == "table")
            && local == "tableColumn"
            && is_spreadsheet_namespace(namespace)
        {
            if definition.columns.len() >= max_columns {
                definition.columns_truncated = true;
                return Ok(definition);
            }
            definition
                .columns
                .push(attribute(&tag, "name").unwrap_or_default());
        }
        if !tag.self_closing {
            stack.push((tag.name, namespaces));
        }
    }
    if !root_seen || !root_closed || !stack.is_empty() {
        return Err("incomplete SpreadsheetML table XML".into());
    }
    Ok(definition)
}

fn parse_table_row_count(tag: &XmlTag, name: &str) -> Result<Option<u32>, String> {
    attribute(tag, name)
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|_| format!("invalid table {name}"))
        })
        .transpose()
}

fn parse_table_range_bounds(reference: &str) -> Option<CellRangeBounds> {
    let mut parts = reference.split(':');
    let first = parse_workbook_cell_reference(parts.next()?);
    let (Some(first_row), Some(first_column)) = first else {
        return None;
    };
    let (last_row, last_column) = if let Some(last) = parts.next() {
        if parts.next().is_some() {
            return None;
        }
        match parse_workbook_cell_reference(last) {
            (Some(row), Some(column)) => (row, column),
            _ => return None,
        }
    } else {
        (first_row, first_column)
    };
    if first_row > last_row || first_column > last_column {
        return None;
    }
    Some(CellRangeBounds {
        first_row,
        first_column,
        last_row,
        last_column,
    })
}

fn parse_worksheet_table_relationship_ids(
    xml: &str,
    max_table_parts: usize,
) -> Result<(Vec<String>, bool, Option<String>), String> {
    let mut relationship_ids = Vec::new();
    let mut code_name = None;
    let mut stack = Vec::<(String, HashMap<String, String>)>::new();
    let mut cursor = 0usize;
    let mut root_seen = false;
    let mut root_closed = false;
    let mut tag_count = 0usize;
    let max_tags = max_table_parts.saturating_mul(64).saturating_add(65_536);
    while cursor < xml.len() {
        let Some(relative) = xml[cursor..].find('<') else {
            if stack.is_empty()
                && xml[cursor..]
                    .chars()
                    .any(|character| !is_xml_whitespace(character))
            {
                return Err("non-whitespace text outside worksheet XML root".into());
            }
            break;
        };
        let opening = cursor + relative;
        if stack.is_empty()
            && xml[cursor..opening]
                .chars()
                .any(|character| !is_xml_whitespace(character))
        {
            return Err("unexpected text outside worksheet XML root".into());
        }
        if xml[opening..].starts_with("<!--") {
            cursor = skip_xml_delimited(xml, opening + 4, "-->")?;
            continue;
        }
        if xml[opening..].starts_with("<?") {
            cursor = skip_xml_delimited(xml, opening + 2, "?>")?;
            continue;
        }
        if xml[opening..].starts_with("<![CDATA[") {
            let content_start = opening + 9;
            let content_end = content_start
                + xml[content_start..]
                    .find("]]>")
                    .ok_or("unterminated worksheet CDATA section")?;
            if stack.is_empty()
                && xml[content_start..content_end]
                    .chars()
                    .any(|character| !is_xml_whitespace(character))
            {
                return Err("unexpected CDATA outside worksheet XML root".into());
            }
            cursor = content_end + 3;
            continue;
        }
        if xml[opening..].starts_with("<!") {
            return Err("DTD and XML declarations are not supported in worksheet XML".into());
        }
        let (tag, next) = parse_xml_tag(xml, opening)?;
        cursor = next;
        tag_count += 1;
        if tag_count > max_tags {
            return Err("worksheet table-part XML element limit exceeded".into());
        }
        if tag.closing {
            if stack
                .last()
                .is_none_or(|(name, _)| name.as_str() != tag.name)
            {
                return Err("mismatched closing tag in worksheet table-part XML".into());
            }
            let (name, _) = stack.pop().ok_or("unexpected worksheet closing tag")?;
            debug_assert_eq!(name, tag.name);
            if stack.is_empty() {
                root_closed = true;
            }
            continue;
        }
        let depth = stack.len();
        let parent = stack.last().map(|(name, _)| local_name(name));
        let mut namespaces = stack
            .last()
            .map(|(_, namespaces)| namespaces.clone())
            .unwrap_or_default();
        add_xml_namespaces(&tag, &mut namespaces);
        let local = local_name(&tag.name);
        let namespace = element_namespace(&tag.name, &namespaces).unwrap_or("");
        if depth == 0 {
            if root_seen
                || (!local.eq_ignore_ascii_case("worksheet")
                    && !local.eq_ignore_ascii_case("macrosheet")
                    && !local.eq_ignore_ascii_case("dialogsheet"))
                || !is_spreadsheet_namespace(namespace)
            {
                return Err("invalid SpreadsheetML worksheet root for table parts".into());
            }
            root_seen = true;
            if tag.self_closing {
                root_closed = true;
            }
        } else if depth == 2
            && parent == Some("tableParts")
            && stack
                .first()
                .is_some_and(|(name, _)| local_name(name) == "worksheet")
            && local == "tablePart"
            && is_spreadsheet_namespace(namespace)
        {
            if relationship_ids.len() >= max_table_parts {
                return Ok((relationship_ids, true, code_name));
            }
            let relationship_id = relationship_id_attribute(&tag, &namespaces)
                .ok_or("worksheet tablePart has no relationship id")?;
            relationship_ids.push(relationship_id);
        } else if depth == 1
            && parent == Some("worksheet")
            && local == "sheetPr"
            && is_spreadsheet_namespace(namespace)
        {
            code_name = attribute(&tag, "codeName");
        }
        if !tag.self_closing {
            stack.push((tag.name, namespaces));
        }
    }
    if !root_seen || !root_closed || !stack.is_empty() {
        return Err("incomplete worksheet table-part XML".into());
    }
    Ok((relationship_ids, false, code_name))
}

#[derive(Clone, Copy)]
enum WorksheetCellTextKind {
    Formula,
    StoredValue,
    InlineString,
}

struct WorksheetCellTextCapture {
    depth: usize,
    kind: WorksheetCellTextKind,
    value: String,
}

struct WorksheetCellBuilder {
    depth: usize,
    cell_ref: Option<String>,
    cell_type: String,
    formula: Option<String>,
    formula_type: Option<String>,
    formula_ref: Option<String>,
    formula_shared_index: Option<u32>,
    stored_value: Option<String>,
    inline_string: String,
}

fn parse_worksheet_cells_xml(
    xml: &str,
    sheet_index: usize,
    sheet_name: &str,
    shared_strings: &[String],
    max_cells: usize,
) -> Result<(Vec<WorkbookCellInfo>, bool), String> {
    let mut cells = Vec::new();
    let mut stack = Vec::<(String, HashMap<String, String>)>::new();
    let mut active_cell: Option<WorksheetCellBuilder> = None;
    let mut text_capture: Option<WorksheetCellTextCapture> = None;
    let mut cursor = 0usize;
    let mut root_seen = false;
    let mut root_closed = false;
    let mut tag_count = 0usize;
    let max_tags = max_cells.saturating_mul(64).saturating_add(65_536);

    while cursor < xml.len() {
        let Some(relative) = xml[cursor..].find('<') else {
            if let Some(capture) = text_capture.as_mut() {
                capture
                    .value
                    .push_str(&decode_xml_entities(&xml[cursor..])?);
            } else if stack.is_empty()
                && xml[cursor..]
                    .chars()
                    .any(|character| !is_xml_whitespace(character))
            {
                return Err("non-whitespace text outside worksheet root".into());
            }
            break;
        };
        let opening = cursor + relative;
        if let Some(capture) = text_capture.as_mut() {
            capture
                .value
                .push_str(&decode_xml_entities(&xml[cursor..opening])?);
        } else if stack.is_empty()
            && xml[cursor..opening]
                .chars()
                .any(|character| !is_xml_whitespace(character))
        {
            return Err("unexpected text outside worksheet root".into());
        }
        if xml[opening..].starts_with("<!--") {
            cursor = skip_xml_delimited(xml, opening + 4, "-->")?;
            continue;
        }
        if xml[opening..].starts_with("<?") {
            cursor = skip_xml_delimited(xml, opening + 2, "?>")?;
            continue;
        }
        if xml[opening..].starts_with("<![CDATA[") {
            let content_start = opening + 9;
            let content_end = content_start
                + xml[content_start..]
                    .find("]]>")
                    .ok_or("unterminated worksheet CDATA section")?;
            if let Some(capture) = text_capture.as_mut() {
                capture.value.push_str(&xml[content_start..content_end]);
            }
            cursor = content_end + 3;
            continue;
        }
        if xml[opening..].starts_with("<!") {
            return Err("DTD and XML declarations are not supported in worksheet cells".into());
        }
        let (tag, next) = parse_xml_tag(xml, opening)?;
        cursor = next;
        tag_count += 1;
        if tag_count > max_tags {
            return Err("worksheet cell XML element limit exceeded".into());
        }
        if tag.closing {
            if stack
                .last()
                .is_none_or(|(name, _)| name.as_str() != tag.name)
            {
                return Err("mismatched closing tag in worksheet XML".into());
            }
            let depth = stack.len().saturating_sub(1);
            let local = local_name(&tag.name);
            let closes_text_capture = text_capture
                .as_ref()
                .is_some_and(|capture| capture.depth == depth);
            if closes_text_capture {
                let capture = text_capture
                    .take()
                    .ok_or("worksheet cell text capture state was lost")?;
                if let Some(cell) = active_cell.as_mut() {
                    match capture.kind {
                        WorksheetCellTextKind::Formula => cell.formula = Some(capture.value),
                        WorksheetCellTextKind::StoredValue => {
                            cell.stored_value = Some(capture.value)
                        }
                        WorksheetCellTextKind::InlineString => {
                            cell.inline_string.push_str(&capture.value)
                        }
                    }
                }
            }
            if local == "c"
                && let Some(cell) = active_cell.as_ref()
                && cell.depth == depth
            {
                let builder = active_cell
                    .take()
                    .ok_or("worksheet cell parser state was lost")?;
                if let Some(cell) =
                    finish_worksheet_cell(builder, sheet_index, sheet_name, shared_strings)
                {
                    if cells.len() >= max_cells {
                        return Ok((cells, true));
                    }
                    cells.push(cell);
                }
            }
            let (name, _) = stack.pop().ok_or("unexpected worksheet closing tag")?;
            debug_assert_eq!(name, tag.name);
            if stack.is_empty() {
                root_closed = true;
            }
            continue;
        }

        let depth = stack.len();
        let parent = stack.last().map(|(name, _)| local_name(name));
        let mut namespaces = stack
            .last()
            .map(|(_, namespaces)| namespaces.clone())
            .unwrap_or_default();
        add_xml_namespaces(&tag, &mut namespaces);
        let local = local_name(&tag.name);
        let namespace = element_namespace(&tag.name, &namespaces).unwrap_or("");
        if depth == 0 {
            if root_seen
                || (!local.eq_ignore_ascii_case("worksheet")
                    && !local.eq_ignore_ascii_case("macrosheet")
                    && !local.eq_ignore_ascii_case("dialogsheet"))
                || !is_spreadsheet_namespace(namespace)
            {
                return Err("invalid SpreadsheetML worksheet root or namespace".into());
            }
            root_seen = true;
            if tag.self_closing {
                root_closed = true;
            }
        } else if depth == 3
            && parent == Some("row")
            && stack
                .get(1)
                .is_some_and(|(name, _)| local_name(name) == "sheetData")
            && local == "c"
            && is_spreadsheet_namespace(namespace)
        {
            active_cell = Some(WorksheetCellBuilder {
                depth,
                cell_ref: attribute(&tag, "r"),
                cell_type: attribute(&tag, "t").unwrap_or_else(|| "n".into()),
                formula: None,
                formula_type: None,
                formula_ref: None,
                formula_shared_index: None,
                stored_value: None,
                inline_string: String::new(),
            });
            if tag.self_closing {
                let builder = active_cell
                    .take()
                    .ok_or("worksheet cell parser state was lost")?;
                if let Some(cell) =
                    finish_worksheet_cell(builder, sheet_index, sheet_name, shared_strings)
                {
                    if cells.len() >= max_cells {
                        return Ok((cells, true));
                    }
                    cells.push(cell);
                }
            }
        } else if let Some(cell) = active_cell.as_mut()
            && depth == cell.depth + 1
            && parent == Some("c")
            && is_spreadsheet_namespace(namespace)
            && local == "f"
        {
            cell.formula = Some(String::new());
            cell.formula_type = attribute(&tag, "t");
            cell.formula_ref = attribute(&tag, "ref");
            cell.formula_shared_index = attribute(&tag, "si").and_then(|value| value.parse().ok());
            if !tag.self_closing {
                text_capture = Some(WorksheetCellTextCapture {
                    depth,
                    kind: WorksheetCellTextKind::Formula,
                    value: String::new(),
                });
            }
        } else if let Some(cell) = active_cell.as_mut()
            && depth == cell.depth + 1
            && parent == Some("c")
            && is_spreadsheet_namespace(namespace)
            && local == "v"
        {
            cell.stored_value = Some(String::new());
            if !tag.self_closing {
                text_capture = Some(WorksheetCellTextCapture {
                    depth,
                    kind: WorksheetCellTextKind::StoredValue,
                    value: String::new(),
                });
            }
        } else if let Some(cell) = active_cell.as_ref()
            && cell.cell_type.eq_ignore_ascii_case("inlineStr")
            && local == "t"
            && is_spreadsheet_namespace(namespace)
            && matches!(parent, Some("is" | "r"))
            && !tag.self_closing
        {
            text_capture = Some(WorksheetCellTextCapture {
                depth,
                kind: WorksheetCellTextKind::InlineString,
                value: String::new(),
            });
        }
        if !tag.self_closing {
            stack.push((tag.name, namespaces));
        }
    }
    if !root_seen || !root_closed || !stack.is_empty() || active_cell.is_some() {
        return Err("incomplete SpreadsheetML worksheet XML".into());
    }
    Ok((cells, false))
}

fn finish_worksheet_cell(
    cell: WorksheetCellBuilder,
    sheet_index: usize,
    sheet_name: &str,
    shared_strings: &[String],
) -> Option<WorkbookCellInfo> {
    let cell_type = cell.cell_type.to_ascii_lowercase();
    let inline = cell_type == "inlinestr";
    if cell.formula.is_none() && cell.stored_value.is_none() && !inline {
        return None;
    }
    let (value, resolution) = match cell_type.as_str() {
        "s" => match cell
            .stored_value
            .as_deref()
            .and_then(|index| index.parse::<usize>().ok())
        {
            Some(index) => match shared_strings.get(index) {
                Some(value) => (
                    Some(value.clone()),
                    if cell.formula.is_some() {
                        "formula_cached_shared_string"
                    } else {
                        "shared_string"
                    },
                ),
                None => (None, "unresolved_shared_string_index"),
            },
            None => (None, "invalid_shared_string_index"),
        },
        "inlinestr" => (Some(cell.inline_string), "inline_string"),
        "b" => match cell.stored_value.as_deref() {
            Some("0") => (Some("false".into()), "boolean_value"),
            Some("1") => (Some("true".into()), "boolean_value"),
            Some(value) => (Some(value.into()), "invalid_boolean_value"),
            None => (None, "missing_boolean_value"),
        },
        "e" => (cell.stored_value.clone(), "stored_error_value"),
        "str" => (
            cell.stored_value.clone(),
            if cell.formula.is_some() {
                "formula_cached_string"
            } else {
                "stored_string_value"
            },
        ),
        "d" => (cell.stored_value.clone(), "stored_date_value"),
        "n" | "" => (
            cell.stored_value.clone(),
            if cell.formula.is_some() {
                if cell.stored_value.is_some() {
                    "formula_cached_value"
                } else {
                    "formula_without_cached_value"
                }
            } else if cell.stored_value.is_some() {
                "stored_numeric_value"
            } else {
                "missing_numeric_value"
            },
        ),
        _ => (cell.stored_value.clone(), "unknown_cell_type"),
    };
    let cell_ref = cell.cell_ref.unwrap_or_default();
    let (row, column) = parse_workbook_cell_reference(&cell_ref);
    let formula_present = cell.formula.is_some();
    Some(WorkbookCellInfo {
        sheet_index,
        sheet_name: sheet_name.into(),
        cell_ref,
        row,
        column,
        cell_type,
        formula: cell.formula,
        formula_type: cell.formula_type,
        formula_ref: cell.formula_ref,
        formula_shared_index: cell.formula_shared_index,
        stored_value: cell.stored_value,
        value,
        resolution: resolution.into(),
        formula_reference_resolution: if formula_present {
            "unscanned".into()
        } else {
            "no_formula".into()
        },
        formula_reference_source_cell_index: None,
        formula_reference_candidates: Vec::new(),
        formula_references_truncated: false,
    })
}

fn parse_workbook_cell_reference(cell_ref: &str) -> (Option<u32>, Option<u32>) {
    let cell_ref = cell_ref.strip_prefix('$').unwrap_or(cell_ref);
    let column_length = cell_ref.bytes().take_while(u8::is_ascii_alphabetic).count();
    if column_length == 0 || column_length > 3 || column_length >= cell_ref.len() {
        return (None, None);
    }
    let column = cell_ref[..column_length].bytes().fold(0u32, |value, byte| {
        value * 26 + u32::from(byte.to_ascii_uppercase() - b'A' + 1)
    });
    let row_ref = cell_ref[column_length..]
        .strip_prefix('$')
        .unwrap_or(&cell_ref[column_length..]);
    let row = row_ref.parse::<u32>().ok();
    match (row, (1..=16_384).contains(&column)) {
        (Some(row), true) if (1..=1_048_576).contains(&row) => (Some(row), Some(column)),
        _ => (None, None),
    }
}

fn parse_workbook_metadata_xml(
    archive: &ZipArchive<'_>,
    xml: &str,
    workbook_part: &str,
    relationships: &[Relationship],
    max_sheets: usize,
) -> Result<WorkbookMetadata, String> {
    let mut metadata = WorkbookMetadata::default();
    let mut active_defined_name: Option<(usize, DefinedNameBuilder)> = None;
    let mut stack = Vec::<(String, HashMap<String, String>)>::new();
    let mut cursor = 0usize;
    let mut root_seen = false;
    let mut root_closed = false;
    let mut tag_count = 0usize;
    let max_tags = max_sheets.saturating_mul(16).max(256);
    while cursor < xml.len() {
        let Some(relative) = xml[cursor..].find('<') else {
            if let Some((_, defined_name)) = active_defined_name.as_mut() {
                defined_name
                    .formula
                    .push_str(&decode_xml_entities(&xml[cursor..])?);
            } else if stack.is_empty()
                && xml[cursor..]
                    .chars()
                    .any(|character| !is_xml_whitespace(character))
            {
                return Err("non-whitespace text outside workbook XML root".into());
            }
            break;
        };
        let opening = cursor + relative;
        if let Some((_, defined_name)) = active_defined_name.as_mut() {
            defined_name
                .formula
                .push_str(&decode_xml_entities(&xml[cursor..opening])?);
        } else if stack.is_empty()
            && xml[cursor..opening]
                .chars()
                .any(|character| !is_xml_whitespace(character))
        {
            return Err("unexpected text outside workbook XML root".into());
        }
        if xml[opening..].starts_with("<!--") {
            cursor = skip_xml_delimited(xml, opening + 4, "-->")?;
            continue;
        }
        if xml[opening..].starts_with("<?") {
            cursor = skip_xml_delimited(xml, opening + 2, "?>")?;
            continue;
        }
        if xml[opening..].starts_with("<![CDATA[") {
            let content_start = opening + 9;
            let content_end = content_start
                + xml[content_start..]
                    .find("]]>")
                    .ok_or("unterminated XML CDATA section")?;
            if let Some((_, defined_name)) = active_defined_name.as_mut() {
                defined_name
                    .formula
                    .push_str(&xml[content_start..content_end]);
            }
            cursor = content_end + 3;
            continue;
        }
        if xml[opening..].starts_with("<!") {
            return Err("DTD and XML declarations are not supported in workbook metadata".into());
        }
        let (tag, next) = parse_xml_tag(xml, opening)?;
        cursor = next;
        tag_count += 1;
        if tag_count > max_tags {
            return Err("workbook XML element limit exceeded".into());
        }
        if tag.closing {
            if stack
                .last()
                .is_none_or(|(name, _)| name.as_str() != tag.name)
            {
                return Err("mismatched closing tag in workbook XML".into());
            }
            if local_name(&tag.name) == "definedName"
                && let Some((defined_name_depth, _)) = active_defined_name.as_ref()
                && stack.len().saturating_sub(1) == *defined_name_depth
            {
                let (_, builder) = active_defined_name
                    .take()
                    .ok_or("defined name parser state was lost")?;
                metadata.defined_names.push(builder.finish());
            }
            let (name, _) = stack
                .pop()
                .ok_or("unexpected closing tag in workbook XML")?;
            debug_assert_eq!(name, tag.name);
            if stack.is_empty() {
                root_closed = true;
            }
            continue;
        }

        let depth = stack.len();
        let parent = stack.last().map(|(name, _)| local_name(name));
        let mut namespaces = stack
            .last()
            .map(|(_, namespaces)| namespaces.clone())
            .unwrap_or_default();
        add_xml_namespaces(&tag, &mut namespaces);
        let local = local_name(&tag.name);
        let namespace = element_namespace(&tag.name, &namespaces).unwrap_or("");
        if depth == 0 {
            if root_seen || local != "workbook" || !is_spreadsheet_namespace(namespace) {
                return Err("invalid SpreadsheetML workbook root or namespace".into());
            }
            root_seen = true;
            if tag.self_closing {
                root_closed = true;
            }
        } else if depth == 1
            && parent == Some("workbook")
            && local == "workbookPr"
            && is_spreadsheet_namespace(namespace)
        {
            metadata.workbook_code_name = attribute(&tag, "codeName");
        } else if depth == 1
            && parent == Some("workbook")
            && local == "sheets"
            && !is_spreadsheet_namespace(namespace)
        {
            return Err("invalid SpreadsheetML sheets namespace".into());
        } else if depth == 2
            && parent == Some("sheets")
            && local == "sheet"
            && is_spreadsheet_namespace(namespace)
        {
            if metadata.sheets.len() >= max_sheets {
                return Err("workbook sheet count exceeds configured limit".into());
            }
            let name = attribute(&tag, "name")
                .ok_or("SpreadsheetML sheet element has no name attribute")?;
            let sheet_id = attribute(&tag, "sheetId").and_then(|value| value.parse().ok());
            let state = attribute(&tag, "state");
            let relationship_id = relationship_id_attribute(&tag, &namespaces);
            let relationship = relationship_id.as_deref().and_then(|id| {
                relationships
                    .iter()
                    .find(|relationship| relationship.id == id)
            });
            let kind = relationship
                .map(|relationship| sheet_kind(&relationship.relationship_type))
                .unwrap_or_else(|| "unknown".into());
            let (part_name, resolution) = match (relationship_id.as_deref(), relationship) {
                (None, _) => (None, "missing_relationship_id"),
                (Some(_), None) => (None, "unresolved_relationship"),
                (Some(_), Some(relationship))
                    if relationship.target_mode == TargetMode::External =>
                {
                    (None, "external_target")
                }
                (Some(_), Some(relationship)) => {
                    match resolve_part_target(Some(workbook_part), &relationship.target) {
                        Err(_) => (None, "invalid_target"),
                        Ok(target) => match unique_zip_entry(archive, &target)? {
                            Some(entry) => (Some(entry.name.clone()), "resolved_internal"),
                            None => (None, "missing_part"),
                        },
                    }
                }
            };
            metadata.sheets.push(WorkbookSheetInfo {
                name,
                code_name: None,
                sheet_id,
                state,
                kind,
                relationship_id,
                part_name,
                resolution: resolution.into(),
            });
        } else if depth == 1
            && parent == Some("workbook")
            && local == "definedNames"
            && !is_spreadsheet_namespace(namespace)
        {
            return Err("invalid SpreadsheetML definedNames namespace".into());
        } else if depth == 2
            && parent == Some("definedNames")
            && local == "definedName"
            && is_spreadsheet_namespace(namespace)
        {
            if metadata.defined_names.len() >= max_sheets {
                return Err("workbook defined-name count exceeds configured limit".into());
            }
            let name = attribute(&tag, "name")
                .ok_or("SpreadsheetML definedName element has no name attribute")?;
            let local_sheet_id_text = attribute(&tag, "localSheetId");
            let local_sheet_id = local_sheet_id_text
                .as_deref()
                .and_then(|value| value.parse::<u32>().ok());
            let hidden = attribute(&tag, "hidden")
                .as_deref()
                .and_then(parse_xml_bool);
            let builder = DefinedNameBuilder {
                name,
                formula: String::new(),
                local_sheet_id,
                invalid_local_sheet_id: local_sheet_id_text.is_some() && local_sheet_id.is_none(),
                hidden,
            };
            if tag.self_closing {
                metadata.defined_names.push(builder.finish());
            } else {
                active_defined_name = Some((depth, builder));
            }
        }
        if active_defined_name.is_some() && depth > 2 {
            return Err("nested elements in SpreadsheetML definedName are unsupported".into());
        }
        if !tag.self_closing {
            stack.push((tag.name, namespaces));
        }
    }
    if !root_seen || !root_closed || !stack.is_empty() {
        return Err("incomplete SpreadsheetML workbook XML".into());
    }
    for defined_name in &mut metadata.defined_names {
        match (
            defined_name.local_sheet_id,
            defined_name.scope_resolution.as_str(),
        ) {
            (_, "invalid_local_sheet_id") => {}
            (None, _) => defined_name.scope_resolution = "workbook_scope".into(),
            (Some(sheet_index), _) => {
                if let Some(sheet) = metadata.sheets.get(sheet_index as usize) {
                    defined_name.local_sheet_name = Some(sheet.name.clone());
                    defined_name.scope_resolution = "sheet_scope_candidate".into();
                } else {
                    defined_name.scope_resolution = "invalid_local_sheet_id".into();
                }
            }
        }
    }
    Ok(metadata)
}

struct DefinedNameBuilder {
    name: String,
    formula: String,
    local_sheet_id: Option<u32>,
    invalid_local_sheet_id: bool,
    hidden: Option<bool>,
}

impl DefinedNameBuilder {
    fn finish(self) -> WorkbookDefinedNameInfo {
        let built_in = self.name.to_ascii_lowercase().starts_with("_xlnm.");
        WorkbookDefinedNameInfo {
            name: self.name,
            formula: self.formula,
            local_sheet_id: self.local_sheet_id,
            local_sheet_name: None,
            hidden: self.hidden,
            built_in,
            scope_resolution: if self.invalid_local_sheet_id {
                "invalid_local_sheet_id"
            } else if self.local_sheet_id.is_some() {
                "unresolved_sheet_scope"
            } else {
                "workbook_scope"
            }
            .into(),
            formula_reference_resolution: "unscanned".into(),
            formula_reference_candidates: Vec::new(),
            formula_references_truncated: false,
        }
    }
}

fn parse_xml_bool(value: &str) -> Option<bool> {
    match value {
        "1" | "true" => Some(true),
        "0" | "false" => Some(false),
        _ => None,
    }
}

fn add_xml_namespaces(tag: &XmlTag, namespaces: &mut HashMap<String, String>) {
    for (name, value) in &tag.attributes {
        if name == "xmlns" {
            namespaces.insert(String::new(), value.clone());
        } else if let Some(prefix) = name.strip_prefix("xmlns:") {
            namespaces.insert(prefix.to_owned(), value.clone());
        }
    }
}

fn local_name(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

fn element_namespace<'a>(name: &str, namespaces: &'a HashMap<String, String>) -> Option<&'a str> {
    let prefix = name.split_once(':').map(|(prefix, _)| prefix).unwrap_or("");
    namespaces.get(prefix).map(String::as_str)
}

fn is_spreadsheet_namespace(namespace: &str) -> bool {
    matches!(namespace, SPREADSHEET_NS | STRICT_SPREADSHEET_NS)
}

fn relationship_id_attribute(tag: &XmlTag, namespaces: &HashMap<String, String>) -> Option<String> {
    tag.attributes.iter().find_map(|(name, value)| {
        let (prefix, local) = name.split_once(':')?;
        (local == "id"
            && namespaces
                .get(prefix)
                .is_some_and(|namespace| is_office_relationships_namespace(namespace)))
        .then(|| value.clone())
    })
}

fn is_office_relationships_namespace(namespace: &str) -> bool {
    matches!(
        namespace,
        OFFICE_RELATIONSHIPS_NS | STRICT_OFFICE_RELATIONSHIPS_NS
    )
}

fn sheet_kind(relationship_type: &str) -> String {
    match relationship_type
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "worksheet" => "worksheet",
        "chartsheet" => "chartsheet",
        "dialogsheet" => "dialogsheet",
        "xlmacrosheet" | "intlmacrosheet" => "macrosheet",
        _ => "unknown",
    }
    .into()
}

fn unique_zip_entry<'a>(
    archive: &'a ZipArchive<'_>,
    part_name: &str,
) -> Result<Option<&'a ZipEntry>, String> {
    let expected = normalize_zip_name(part_name);
    let mut found = archive
        .entries
        .iter()
        .filter(|entry| normalize_zip_name(&entry.name).eq_ignore_ascii_case(&expected));
    let entry = found.next();
    if found.next().is_some() {
        return Err(format!("ambiguous duplicate ZIP part name: {part_name}"));
    }
    Ok(entry)
}

fn normalize_zip_name(name: &str) -> String {
    name.replace('\\', "/").trim_start_matches('/').to_owned()
}

fn relationship_part_name(source_part: &str) -> Result<String, String> {
    let normalized = normalize_zip_name(source_part);
    if normalized.is_empty() || normalized.ends_with('/') {
        return Err(format!("invalid OPC source part name: {source_part}"));
    }
    if let Some((directory, file)) = normalized.rsplit_once('/') {
        if directory.is_empty() || file.is_empty() {
            return Err(format!("invalid OPC source part name: {source_part}"));
        }
        Ok(format!("{directory}/_rels/{file}.rels"))
    } else {
        Ok(format!("_rels/{normalized}.rels"))
    }
}

fn resolve_part_target(source_part: Option<&str>, target: &str) -> Result<String, String> {
    if target.is_empty() || target.contains(['?', '#', '\\']) || target.starts_with("//") {
        return Err("invalid internal OPC relationship target URI".into());
    }
    let decoded = decode_unreserved_uri_chars(target)?;
    if decoded
        .split('/')
        .next()
        .is_some_and(|segment| segment.contains(':'))
    {
        return Err("internal OPC relationship target cannot be an absolute URI".into());
    }
    let absolute = decoded.starts_with('/');
    let mut segments = Vec::<String>::new();
    if !absolute
        && let Some(source_part) = source_part
        && let Some((directory, _)) = normalize_zip_name(source_part).rsplit_once('/')
    {
        segments.extend(directory.split('/').map(str::to_owned));
    }
    for segment in decoded.trim_start_matches('/').split('/') {
        match segment {
            "" => return Err("OPC relationship target contains an empty path segment".into()),
            "." => {}
            ".." => {
                if segments.pop().is_none() {
                    return Err("OPC relationship target escapes the package root".into());
                }
            }
            _ => segments.push(segment.to_owned()),
        }
    }
    if segments.is_empty() {
        return Err("OPC relationship target resolves to the package root".into());
    }
    Ok(segments.join("/"))
}

fn decode_unreserved_uri_chars(target: &str) -> Result<String, String> {
    let bytes = target.as_bytes();
    let mut output = String::with_capacity(target.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            let character = target[index..]
                .chars()
                .next()
                .ok_or("invalid UTF-8 in OPC relationship target")?;
            output.push(character);
            index += character.len_utf8();
            continue;
        }
        let Some(pair) = bytes.get(index + 1..index + 3) else {
            return Err("incomplete percent escape in OPC relationship target".into());
        };
        let high = (pair[0] as char)
            .to_digit(16)
            .ok_or("invalid percent escape in OPC relationship target")?;
        let low = (pair[1] as char)
            .to_digit(16)
            .ok_or("invalid percent escape in OPC relationship target")?;
        let decoded = ((high << 4) | low) as u8;
        if decoded.is_ascii_alphanumeric() || matches!(decoded, b'-' | b'.' | b'_' | b'~') {
            output.push(decoded as char);
        } else {
            output.push('%');
            output.push((pair[0] as char).to_ascii_uppercase());
            output.push((pair[1] as char).to_ascii_uppercase());
        }
        index += 3;
    }
    Ok(output)
}

fn parse_relationship_xml(
    xml: &str,
    max_relationships: usize,
) -> Result<Vec<Relationship>, String> {
    let mut relationships = Vec::new();
    let mut relationship_ids = HashSet::new();
    let mut stack = Vec::<(String, HashMap<String, String>)>::new();
    let mut cursor = 0usize;
    let mut root_seen = false;
    let mut root_closed = false;
    let mut tag_count = 0usize;
    let max_tags = max_relationships.saturating_mul(8).max(64);
    while cursor < xml.len() {
        let Some(relative) = xml[cursor..].find('<') else {
            if xml[cursor..]
                .chars()
                .any(|character| !is_xml_whitespace(character))
            {
                return Err("non-whitespace text outside OPC relationship elements".into());
            }
            break;
        };
        let opening = cursor + relative;
        if xml[cursor..opening]
            .chars()
            .any(|character| !is_xml_whitespace(character))
        {
            return Err("unexpected text in OPC relationships XML".into());
        }
        if xml[opening..].starts_with("<!--") {
            cursor = skip_xml_delimited(xml, opening + 4, "-->")?;
            continue;
        }
        if xml[opening..].starts_with("<?") {
            cursor = skip_xml_delimited(xml, opening + 2, "?>")?;
            continue;
        }
        if xml[opening..].starts_with("<![CDATA[") {
            cursor = skip_xml_delimited(xml, opening + 9, "]]>")?;
            continue;
        }
        if xml[opening..].starts_with("<!") {
            return Err("DTD and XML declarations are not supported in OPC relationships".into());
        }
        let (tag, next) = parse_xml_tag(xml, opening)?;
        cursor = next;
        tag_count += 1;
        if tag_count > max_tags {
            return Err("OPC relationships XML element limit exceeded".into());
        }
        if tag.closing {
            let (name, _) = stack
                .pop()
                .ok_or("unexpected closing tag in OPC relationships XML")?;
            if name != tag.name {
                return Err("mismatched closing tag in OPC relationships XML".into());
            }
            if stack.is_empty() {
                root_closed = true;
            }
            continue;
        }

        let depth = stack.len();
        let mut namespaces = stack
            .last()
            .map(|(_, namespaces)| namespaces.clone())
            .unwrap_or_default();
        for (name, value) in &tag.attributes {
            if name == "xmlns" {
                namespaces.insert(String::new(), value.clone());
            } else if let Some(prefix) = name.strip_prefix("xmlns:") {
                namespaces.insert(prefix.to_owned(), value.clone());
            }
        }
        let local_name = tag.name.rsplit(':').next().unwrap_or(&tag.name);
        let prefix = tag
            .name
            .split_once(':')
            .map(|(prefix, _)| prefix)
            .unwrap_or("");
        let namespace = namespaces.get(prefix).map(String::as_str).unwrap_or("");
        if depth == 0 {
            if root_seen || local_name != "Relationships" || !is_relationships_namespace(namespace)
            {
                return Err("invalid OPC relationships XML root or namespace".into());
            }
            root_seen = true;
            if tag.self_closing {
                root_closed = true;
            }
        } else if depth == 1 && local_name == "Relationship" {
            if !is_relationships_namespace(namespace) {
                return Err("invalid OPC Relationship element namespace".into());
            }
            if relationships.len() >= max_relationships {
                return Err("OPC relationship count exceeds configured limit".into());
            }
            let id = attribute(&tag, "Id")
                .filter(|id| !id.is_empty())
                .ok_or("OPC Relationship element has no Id attribute")?;
            if !relationship_ids.insert(id.clone()) {
                return Err("duplicate relationship Id in OPC relationships part".into());
            }
            let relationship_type =
                attribute(&tag, "Type").ok_or("OPC Relationship element has no Type attribute")?;
            let target = attribute(&tag, "Target")
                .ok_or("OPC Relationship element has no Target attribute")?;
            let target_mode = match attribute(&tag, "TargetMode") {
                None => TargetMode::Internal,
                Some(value) if value.eq_ignore_ascii_case("internal") => TargetMode::Internal,
                Some(value) if value.eq_ignore_ascii_case("external") => TargetMode::External,
                Some(_) => return Err("invalid OPC Relationship TargetMode".into()),
            };
            relationships.push(Relationship {
                id,
                relationship_type,
                target,
                target_mode,
            });
        }
        if !tag.self_closing {
            stack.push((tag.name, namespaces));
        }
    }
    if !root_seen || !root_closed || !stack.is_empty() {
        return Err("incomplete OPC relationships XML document".into());
    }
    Ok(relationships)
}

fn is_relationships_namespace(namespace: &str) -> bool {
    matches!(namespace, RELATIONSHIPS_NS | STRICT_RELATIONSHIPS_NS)
}

fn attribute(tag: &XmlTag, name: &str) -> Option<String> {
    tag.attributes
        .iter()
        .find_map(|(attribute, value)| (attribute == name).then(|| value.clone()))
}

struct XmlTag {
    name: String,
    attributes: Vec<(String, String)>,
    closing: bool,
    self_closing: bool,
}

fn parse_xml_tag(xml: &str, opening: usize) -> Result<(XmlTag, usize), String> {
    let bytes = xml.as_bytes();
    let mut cursor = opening + 1;
    let closing = bytes.get(cursor) == Some(&b'/');
    if closing {
        cursor += 1;
    }
    let name_start = cursor;
    while cursor < bytes.len()
        && !is_xml_whitespace_byte(bytes[cursor])
        && !matches!(bytes[cursor], b'/' | b'>')
    {
        cursor += 1;
    }
    if cursor == name_start {
        return Err("empty XML element name in OPC relationships".into());
    }
    let name = xml[name_start..cursor].to_owned();
    if closing {
        skip_xml_whitespace(bytes, &mut cursor);
        if bytes.get(cursor) != Some(&b'>') {
            return Err("malformed closing tag in OPC relationships XML".into());
        }
        return Ok((
            XmlTag {
                name,
                attributes: Vec::new(),
                closing: true,
                self_closing: false,
            },
            cursor + 1,
        ));
    }

    let mut attributes = Vec::new();
    let mut seen = HashSet::new();
    loop {
        skip_xml_whitespace(bytes, &mut cursor);
        match bytes.get(cursor) {
            Some(b'>') => {
                return Ok((
                    XmlTag {
                        name,
                        attributes,
                        closing: false,
                        self_closing: false,
                    },
                    cursor + 1,
                ));
            }
            Some(b'/') if bytes.get(cursor + 1) == Some(&b'>') => {
                return Ok((
                    XmlTag {
                        name,
                        attributes,
                        closing: false,
                        self_closing: true,
                    },
                    cursor + 2,
                ));
            }
            None => return Err("truncated start tag in OPC relationships XML".into()),
            _ => {}
        }
        let attribute_start = cursor;
        while cursor < bytes.len()
            && !is_xml_whitespace_byte(bytes[cursor])
            && !matches!(bytes[cursor], b'=' | b'/' | b'>')
        {
            cursor += 1;
        }
        if cursor == attribute_start {
            return Err("malformed attribute in OPC relationships XML".into());
        }
        let attribute_name = xml[attribute_start..cursor].to_owned();
        if !seen.insert(attribute_name.clone()) {
            return Err("duplicate attribute in OPC relationships XML".into());
        }
        skip_xml_whitespace(bytes, &mut cursor);
        if bytes.get(cursor) != Some(&b'=') {
            return Err("missing equals sign in OPC XML attribute".into());
        }
        cursor += 1;
        skip_xml_whitespace(bytes, &mut cursor);
        let quote = *bytes
            .get(cursor)
            .ok_or("missing quote in OPC XML attribute")?;
        if !matches!(quote, b'\'' | b'"') {
            return Err("unquoted attribute in OPC relationships XML".into());
        }
        cursor += 1;
        let value_start = cursor;
        while cursor < bytes.len() && bytes[cursor] != quote {
            if bytes[cursor] == b'<' {
                return Err("less-than sign in OPC XML attribute".into());
            }
            cursor += 1;
        }
        if cursor == bytes.len() {
            return Err("unterminated attribute in OPC relationships XML".into());
        }
        let value = decode_xml_entities(&xml[value_start..cursor])?;
        attributes.push((attribute_name, value));
        cursor += 1;
    }
}

fn skip_xml_delimited(xml: &str, start: usize, closing: &str) -> Result<usize, String> {
    let relative = xml[start..]
        .find(closing)
        .ok_or("unterminated XML comment or processing instruction")?;
    Ok(start + relative + closing.len())
}

fn skip_xml_whitespace(bytes: &[u8], cursor: &mut usize) {
    while bytes
        .get(*cursor)
        .is_some_and(|byte| is_xml_whitespace_byte(*byte))
    {
        *cursor += 1;
    }
}

fn is_xml_whitespace_byte(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

fn is_xml_whitespace(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\r' | '\n')
}

fn decode_xml_entities(value: &str) -> Result<String, String> {
    let mut output = String::with_capacity(value.len());
    let mut cursor = 0usize;
    while let Some(relative) = value[cursor..].find('&') {
        let ampersand = cursor + relative;
        output.push_str(&value[cursor..ampersand]);
        let entity_start = ampersand + 1;
        let relative_end = value[entity_start..]
            .find(';')
            .ok_or("unterminated XML entity reference")?;
        let entity_end = entity_start + relative_end;
        let entity = &value[entity_start..entity_end];
        let decoded = if let Some(number) = entity
            .strip_prefix("#x")
            .or_else(|| entity.strip_prefix("#X"))
        {
            let value = u32::from_str_radix(number, 16)
                .map_err(|_| "invalid hexadecimal XML character reference")?;
            char::from_u32(value).ok_or("invalid XML character reference")?
        } else if let Some(number) = entity.strip_prefix('#') {
            let value = number
                .parse::<u32>()
                .map_err(|_| "invalid decimal XML character reference")?;
            char::from_u32(value).ok_or("invalid XML character reference")?
        } else {
            match entity {
                "amp" => '&',
                "lt" => '<',
                "gt" => '>',
                "apos" => '\'',
                "quot" => '"',
                _ => return Err("unsupported XML entity reference".into()),
            }
        };
        output.push(decoded);
        cursor = entity_end + 1;
    }
    output.push_str(&value[cursor..]);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_relationship_targets_against_package_or_source_part() {
        assert_eq!(
            resolve_part_target(None, "xl/workbook.xml").unwrap(),
            "xl/workbook.xml"
        );
        assert_eq!(
            resolve_part_target(Some("xl/workbook.xml"), "../custom/vbaProject.bin").unwrap(),
            "custom/vbaProject.bin"
        );
        assert_eq!(
            resolve_part_target(Some("xl/workbook.xml"), "/custom/./vbaProject.bin").unwrap(),
            "custom/vbaProject.bin"
        );
        assert!(resolve_part_target(None, "../../escape.bin").is_err());
        assert!(resolve_part_target(None, "https://example.test/project.bin").is_err());
        assert_eq!(
            relationship_part_name("xl/workbook.xml").unwrap(),
            "xl/_rels/workbook.xml.rels"
        );
        assert_eq!(
            relationship_part_name("workbook.xml").unwrap(),
            "_rels/workbook.xml.rels"
        );
    }

    #[test]
    fn parses_namespaced_relationships_and_xml_entities_without_dtds() {
        let xml = r#"<?xml version="1.0"?><r:Relationships xmlns:r="http://schemas.openxmlformats.org/package/2006/relationships"><r:Relationship Id="r1" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="../custom/VBA%20Project.bin"/><r:Relationship Id='r2' Type='custom' Target='x&amp;y' TargetMode='External'/></r:Relationships>"#;
        let relationships = parse_relationship_xml(xml, 10).unwrap();
        assert_eq!(relationships.len(), 2);
        assert_eq!(relationships[0].target, "../custom/VBA%20Project.bin");
        assert_eq!(relationships[0].target_mode, TargetMode::Internal);
        assert_eq!(relationships[1].target, "x&y");
        assert_eq!(relationships[1].target_mode, TargetMode::External);
        assert!(parse_relationship_xml(
            "<!DOCTYPE Relationships [<!ENTITY x SYSTEM 'file:///tmp/x'>]><Relationships xmlns='http://schemas.openxmlformats.org/package/2006/relationships'/>",
            10
        )
        .is_err());
    }

    #[test]
    fn parses_and_expands_ooxml_shared_formula_references() {
        let xml = r#"<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="2"><c r="B2"><f t="shared" ref="B2:C3" si="7">A1+$C$3</f><v>1</v></c></row><row r="3"><c r="C3"><f t="shared" si="7"/><v>2</v></c></row></sheetData></worksheet>"#;
        let (mut cells, truncated) = parse_worksheet_cells_xml(xml, 0, "Data", &[], 10).unwrap();
        assert!(!truncated);
        assert_eq!(cells.len(), 2);
        assert_eq!(cells[0].formula.as_deref(), Some("A1+$C$3"));
        assert_eq!(cells[1].formula.as_deref(), Some(""));
        assert_eq!(cells[0].formula_ref.as_deref(), Some("B2:C3"));
        crate::excel_formula::populate_formula_reference_candidates(
            &mut cells,
            &[WorkbookSheetInfo {
                name: "Data".into(),
                kind: "worksheet".into(),
                resolution: "resolved_internal".into(),
                ..WorkbookSheetInfo::default()
            }],
            &mut [],
            &[],
            10,
            10,
            false,
        );
        assert_eq!(
            cells[1].formula_reference_resolution,
            "shared_formula_relative_candidates_translated"
        );
        assert_eq!(cells[1].formula_reference_source_cell_index, Some(0));
        assert_eq!(
            cells[1]
                .formula_reference_candidates
                .iter()
                .map(|reference| reference.reference.as_str())
                .collect::<Vec<_>>(),
            vec!["B2", "$C$3"]
        );
    }
}
