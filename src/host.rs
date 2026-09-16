//! Host-application knowledge kept outside the VBA language core.

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum HostProfile {
    #[default]
    Unknown,
    Excel,
}

pub(crate) fn direct_host_entry_candidate(trigger: &str) -> bool {
    matches!(
        trigger,
        "legacy_excel_auto_macro_candidate"
            | "workbook_event_candidate"
            | "worksheet_event_candidate"
            | "manual_macro_candidate"
            | "excel_ontime_scheduled_macro_candidate"
            | "excel_application_event_handler_candidate"
    )
}

pub mod excel {
    /// Excel object-model names that are useful data-access anchors. These are
    /// candidates only; runtime workbook and range binding remain unresolved.
    pub fn is_data_access_name(name: &str) -> bool {
        matches!(
            name.to_ascii_lowercase().as_str(),
            "range"
                | "cells"
                | "listobjects"
                | "listcolumns"
                | "listrows"
                | "databodyrange"
                | "headerrowrange"
                | "totalsrowrange"
                | "add"
                | "delete"
                | "resize"
                | "rows"
                | "columns"
                | "worksheets"
                | "sheets"
                | "workbooks"
                | "names"
                | "referstorange"
                | "offset"
                | "currentregion"
                | "usedrange"
                | "value"
                | "value2"
                | "formula"
                | "formula2"
                | "formular1c1"
                | "formula2r1c1"
        )
    }

    pub fn is_known_type(name: &str) -> bool {
        matches!(
            name.to_ascii_lowercase().as_str(),
            "application"
                | "workbook"
                | "worksheet"
                | "range"
                | "name"
                | "names"
                | "referstorange"
                | "workbooks"
                | "worksheets"
                | "chart"
                | "chartobject"
                | "chartobjects"
                | "shape"
                | "shapes"
                | "listobject"
                | "listrow"
                | "listcolumn"
                | "pivottable"
                | "pivotcache"
                | "querytable"
                | "connection"
                | "slicer"
                | "sliceritem"
        )
    }

    pub fn is_constant(name: &str) -> bool {
        matches!(
            name.to_ascii_lowercase().as_str(),
            "xldown"
                | "xlup"
                | "xltoright"
                | "xltoleft"
                | "xlvalues"
                | "xlformulas"
                | "xlwhole"
                | "xlpart"
                | "xlbyrows"
                | "xlbycolumns"
                | "xlnext"
                | "xlprevious"
                | "xlnone"
                | "xlsolid"
                | "xlcontinuous"
                | "xledgebottom"
                | "xledgeleft"
                | "xledgedright"
                | "xledgetop"
                | "xlcenter"
                | "xlleft"
                | "xlright"
                | "xlopenxmlworkbook"
                | "xlopenxmlworkbookmacroenabled"
                | "xlcalculationmanual"
                | "xlcalculationautomatic"
                | "xlcelltypevisible"
                | "xlcelltypeformulas"
                | "xlcelltypeconstants"
        )
    }

    pub fn is_known_member(name: &str) -> bool {
        matches!(
            name.to_ascii_lowercase().as_str(),
            "range"
                | "cells"
                | "listobjects"
                | "listcolumns"
                | "listrows"
                | "databodyrange"
                | "headerrowrange"
                | "totalsrowrange"
                | "rows"
                | "columns"
                | "value"
                | "value2"
                | "formula"
                | "formula2"
                | "formular1c1"
                | "formula2r1c1"
                | "offset"
                | "end"
                | "resize"
                | "currentregion"
                | "usedrange"
                | "worksheets"
                | "sheets"
                | "workbooks"
                | "names"
                | "save"
                | "saveas"
                | "close"
                | "open"
                | "calculate"
                | "clearcontents"
                | "clearformats"
                | "copy"
                | "paste"
                | "delete"
                | "find"
                | "findnext"
                | "sort"
                | "autofilter"
                | "specialcells"
                | "interior"
                | "font"
                | "borders"
                | "activate"
                | "select"
                | "add"
        )
    }
}
