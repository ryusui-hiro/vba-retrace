//! Host-application knowledge kept outside the VBA language core.

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum HostProfile {
    #[default]
    Unknown,
    Excel,
}

pub mod excel {
    /// Excel object-model names that are useful data-access anchors. These are
    /// candidates only; runtime workbook and range binding remain unresolved.
    pub fn is_data_access_name(name: &str) -> bool {
        matches!(
            name.to_ascii_lowercase().as_str(),
            "range"
                | "cells"
                | "rows"
                | "columns"
                | "worksheets"
                | "sheets"
                | "workbooks"
                | "names"
                | "offset"
                | "currentregion"
                | "usedrange"
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
                | "rows"
                | "columns"
                | "value"
                | "value2"
                | "formula"
                | "formulatext"
                | "offset"
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
