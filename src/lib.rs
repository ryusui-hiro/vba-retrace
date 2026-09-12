//! Static analysis primitives for VBA source and macro-enabled Office files.
//!
//! The crate never executes macros and never performs network access. Findings
//! distinguish facts from unresolved or host-dependent behavior.

pub mod analyze;
pub mod cfb;
pub mod compiled;
pub mod deflate;
pub mod error_handling;
pub mod export;
pub mod extract;
pub mod flow;
pub mod host;
pub mod lexer;
pub mod model;
pub mod ovba;
pub mod parser;
pub mod preprocessor;
pub mod source;
pub mod typecheck;
pub mod zip;

pub use analyze::{AnalysisOptions, analyze};
pub use model::{Analysis, Diagnostic, Limits, Module, Project, Severity, SourceUnit, Span};

/// Analyze already-decoded VBA text units using default resource limits.
pub fn analyze_sources(sources: &[SourceUnit]) -> Result<Analysis, String> {
    analyze(sources, &AnalysisOptions::default())
}
