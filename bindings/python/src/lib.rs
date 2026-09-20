use pyo3::exceptions::{PyIOError, PyValueError};
use pyo3::prelude::*;
use std::fs;

use vba_insight::export::{
    Disclosure, disasm_to_json, disasm_to_markdown, inspect_to_json, inspect_to_markdown,
    inspection_to_sarif, to_json,
};
use vba_insight::{AnalysisOptions, HostProfile, SourceUnit, inspect_macro_file};

fn read_input_bytes(input: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    if let Ok(bytes) = input.extract::<Vec<u8>>() {
        Ok(bytes)
    } else if let Ok(path) = input.extract::<std::path::PathBuf>() {
        fs::read(&path).map_err(|e| {
            PyIOError::new_err(format!("failed to read file '{}': {e}", path.display()))
        })
    } else {
        Err(PyValueError::new_err(
            "expected bytes, bytearray, or path string/PathLike as input",
        ))
    }
}

#[pyfunction]
#[pyo3(signature = (data, include_source = true))]
fn inspect_macro_file_json(data: &Bound<'_, PyAny>, include_source: bool) -> PyResult<String> {
    let bytes = read_input_bytes(data)?;
    let disclosure = if include_source {
        Disclosure::IncludeSource
    } else {
        Disclosure::StructureOnly
    };
    let options = AnalysisOptions {
        host_profile: HostProfile::Excel,
        ..Default::default()
    };
    let inspection = inspect_macro_file(&bytes, &options)
        .map_err(|e| PyValueError::new_err(format!("inspection failed: {e}")))?;

    Ok(inspect_to_json(&inspection, disclosure))
}

#[pyfunction]
fn inspect_macro_file_markdown(data: &Bound<'_, PyAny>) -> PyResult<String> {
    let bytes = read_input_bytes(data)?;
    let options = AnalysisOptions {
        host_profile: HostProfile::Excel,
        ..Default::default()
    };
    let inspection = inspect_macro_file(&bytes, &options)
        .map_err(|e| PyValueError::new_err(format!("inspection failed: {e}")))?;

    Ok(inspect_to_markdown(&inspection))
}

#[pyfunction]
#[pyo3(signature = (data, file_uri = "macro_container"))]
fn inspect_macro_file_sarif(data: &Bound<'_, PyAny>, file_uri: &str) -> PyResult<String> {
    let bytes = read_input_bytes(data)?;
    let options = AnalysisOptions {
        host_profile: HostProfile::Excel,
        ..Default::default()
    };
    let inspection = inspect_macro_file(&bytes, &options)
        .map_err(|e| PyValueError::new_err(format!("inspection failed: {e}")))?;

    Ok(inspection_to_sarif(&inspection, file_uri))
}

#[pyfunction]
fn disasm_macro_file_json(data: &Bound<'_, PyAny>) -> PyResult<String> {
    let bytes = read_input_bytes(data)?;
    let options = AnalysisOptions {
        host_profile: HostProfile::Excel,
        ..Default::default()
    };
    let inspection = inspect_macro_file(&bytes, &options)
        .map_err(|e| PyValueError::new_err(format!("inspection failed: {e}")))?;

    Ok(disasm_to_json(&inspection.pcode_disassembly))
}

#[pyfunction]
fn disasm_macro_file_markdown(data: &Bound<'_, PyAny>) -> PyResult<String> {
    let bytes = read_input_bytes(data)?;
    let options = AnalysisOptions {
        host_profile: HostProfile::Excel,
        ..Default::default()
    };
    let inspection = inspect_macro_file(&bytes, &options)
        .map_err(|e| PyValueError::new_err(format!("inspection failed: {e}")))?;

    Ok(disasm_to_markdown(&inspection.pcode_disassembly))
}

#[pyfunction]
#[pyo3(signature = (sources, include_source = true))]
fn analyze_sources_json(sources: Vec<(String, String)>, include_source: bool) -> PyResult<String> {
    let units: Vec<SourceUnit> = sources
        .into_iter()
        .map(|(name, text)| SourceUnit { name, text })
        .collect();
    let disclosure = if include_source {
        Disclosure::IncludeSource
    } else {
        Disclosure::StructureOnly
    };
    let options = AnalysisOptions::default();
    let analysis = vba_insight::analyze(&units, &options)
        .map_err(|e| PyValueError::new_err(format!("analysis failed: {e}")))?;

    Ok(to_json(&analysis, None, disclosure))
}

#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(inspect_macro_file_json, m)?)?;
    m.add_function(wrap_pyfunction!(inspect_macro_file_markdown, m)?)?;
    m.add_function(wrap_pyfunction!(inspect_macro_file_sarif, m)?)?;
    m.add_function(wrap_pyfunction!(disasm_macro_file_json, m)?)?;
    m.add_function(wrap_pyfunction!(disasm_macro_file_markdown, m)?)?;
    m.add_function(wrap_pyfunction!(analyze_sources_json, m)?)?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    Ok(())
}
