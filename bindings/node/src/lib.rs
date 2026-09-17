use napi::bindgen_prelude::*;
use napi_derive::napi;
use vba_insight::export::{
    Disclosure, inspect_to_json, inspect_to_markdown, stomping_to_sarif, to_json,
};
use vba_insight::{AnalysisOptions, HostProfile, SourceUnit, inspect_macro_file};

#[napi(object)]
pub struct SourceEntry {
    pub name: String,
    pub text: String,
}

#[napi]
pub fn inspect_macro_file_json(data: Buffer, include_source: Option<bool>) -> napi::Result<String> {
    let disclosure = if include_source.unwrap_or(true) {
        Disclosure::IncludeSource
    } else {
        Disclosure::StructureOnly
    };
    let options = AnalysisOptions {
        host_profile: HostProfile::Excel,
        ..Default::default()
    };
    let inspection = inspect_macro_file(data.as_ref(), &options).map_err(|e| {
        napi::Error::new(
            napi::Status::GenericFailure,
            format!("inspection failed: {e}"),
        )
    })?;

    Ok(inspect_to_json(&inspection, disclosure))
}

#[napi]
pub fn inspect_macro_file_markdown(data: Buffer) -> napi::Result<String> {
    let options = AnalysisOptions {
        host_profile: HostProfile::Excel,
        ..Default::default()
    };
    let inspection = inspect_macro_file(data.as_ref(), &options).map_err(|e| {
        napi::Error::new(
            napi::Status::GenericFailure,
            format!("inspection failed: {e}"),
        )
    })?;

    Ok(inspect_to_markdown(&inspection))
}

#[napi]
pub fn inspect_macro_file_sarif(data: Buffer, file_uri: Option<String>) -> napi::Result<String> {
    let options = AnalysisOptions {
        host_profile: HostProfile::Excel,
        ..Default::default()
    };
    let inspection = inspect_macro_file(data.as_ref(), &options).map_err(|e| {
        napi::Error::new(
            napi::Status::GenericFailure,
            format!("inspection failed: {e}"),
        )
    })?;

    let uri = file_uri.as_deref().unwrap_or("macro_container");
    Ok(stomping_to_sarif(&inspection.stomping_report, uri))
}

#[napi]
pub fn analyze_sources_json(
    sources: Vec<SourceEntry>,
    include_source: Option<bool>,
) -> napi::Result<String> {
    let units: Vec<SourceUnit> = sources
        .into_iter()
        .map(|entry| SourceUnit {
            name: entry.name,
            text: entry.text,
        })
        .collect();
    let disclosure = if include_source.unwrap_or(true) {
        Disclosure::IncludeSource
    } else {
        Disclosure::StructureOnly
    };
    let options = AnalysisOptions::default();
    let analysis = vba_insight::analyze(&units, &options).map_err(|e| {
        napi::Error::new(
            napi::Status::GenericFailure,
            format!("analysis failed: {e}"),
        )
    })?;

    Ok(to_json(&analysis, None, disclosure))
}

#[napi]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
