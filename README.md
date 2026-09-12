# vba-insight

Dependency-free Rust library and CLI for inspecting exported VBA source and extracting source modules from macro-enabled Excel workbooks (`.xlsm`). It does not execute macros or make network requests.

> **Development status: pre-1.0.** This is a static-analysis foundation, not a VBA compiler or a complete implementation of all VBA static/runtime semantics. Results deliberately identify unresolved behavior and incomplete analysis.

## What it does today

- Tokenizes VBA text while retaining UTF-8 byte spans and line/column locations.
- Parses common module declarations, `Sub`/`Function`/`Property` headers, arguments, variable declarations, `Type` and `Enum` blocks, and common structured statements (`If`, `Select Case`, loops, `With`, labels, `GoTo`, and exits).
- Evaluates a conservative subset of `#Const`/`#If`/`#ElseIf`/`#Else` when callers supply compile-time constants; unresolved branches stay visible and make affected flow graphs incomplete.
- Builds structural control-flow graphs and reports call candidates, unresolved names, Excel object-model access candidates under the Excel host profile, and selected host-operation candidates.
- Propagates primitive and declared types through assignment expressions, while keeping implicit conversions and host-provided types explicitly uncertain.
- Follows direct writes to `ByRef` parameters back to simple caller arguments; transitive calls and mutation through referenced objects remain unresolved.
- Resolves `On Error GoTo` labels and exposes tested per-procedure error-policy transitions (`Resume Next`, handler-active propagation, and `Resume`); CFG paths involving handlers remain marked incomplete.
- Reads ordinary ZIP/Deflate OOXML packages, CFB storages/streams, and MS-OVBA compressed source containers with bounded resource use. It extracts `VBA/dir`, module streams, code-page metadata, references from `PROJECT`, and source text from `.xlsm`.
- Records module/project performance-cache boundaries, lengths, and fingerprints. It does **not** decode p-code opcodes.
- Offers an explicit `vba7-observed` p-code line-map profile that validates `CA FE` framing and extracts raw per-source-line byte ranges without assigning opcode meanings.
- Produces JSON or Graphviz DOT without third-party Cargo dependencies.

## Build and use

```sh
cargo test --all-targets
cargo build --release

# Parse exported source; identifiers, expressions, names, and source paths are redacted by default.
cargo run -- analyze examples/approval.bas --host excel

# Include original source expressions and text in local output.
cargo run -- analyze examples/approval.bas --include-source

# Extract and analyze the VBA project in a macro-enabled workbook.
cargo run -- analyze workbook.xlsm

# Extract raw VBA7-observed p-code line ranges, without opcode interpretation.
cargo run -- analyze workbook.xlsm --pcode-profile vba7-observed

# Resolve conditional compilation for a particular build environment.
cargo run -- analyze examples/conditional.bas --define VBA7=True

# Read a legacy exported .bas file in Japanese Windows code page.
cargo run -- analyze Module1.bas --code-page 932

# Emit CFGs as Graphviz DOT.
cargo run -- analyze examples/approval.bas --format dot
```

Library entry point:

```rust
use vba_insight::{analyze, AnalysisOptions, SourceUnit};

let result = analyze(&[SourceUnit {
    name: "Module1.bas".into(),
    text: "Public Sub Start()\nEnd Sub\n".into(),
}], &AnalysisOptions::default())?;
assert!(!result.project.code_executed);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Conditional compilation can be resolved for a supplied target by passing constants such as `VBA7`, `Win64`, or project-specific `#Const` values through `AnalysisOptions::conditional_constants`. Unknown conditions retain alternatives, produce diagnostics, and mark affected CFGs incomplete.

The CLI selects the Excel host profile automatically for `.xlsm`; exported source defaults to an unknown host unless `--host excel` is specified. Host-specific reads and writes remain candidates, never confirmed workbook/cell effects.

## Important boundaries

- `semantic_analysis_complete` remains `false`. VBA syntax and semantics are broad, and host libraries, references, unsupported compile-time expressions, late binding, runtime state, and error handling can change meaning.
- CFG edges describe structural paths, not proven feasible inputs. `On Error`, dynamic dispatch, and some loop/exit forms are not fully represented; affected results are marked incomplete or diagnosed.
- Call and data-access results are candidates. A name match does not establish a binding, and an Excel member name does not prove which workbook or cell is affected.
- The MS-OVBA specification says module performance caches are implementation- and version-dependent and must be ignored on interoperable reads. This crate reports their boundaries and fingerprints but does not treat them as verified p-code or disassemble them. That is the current compiled-representation limit.
- `--pcode-profile vba7-observed` parses only an observed CAFE/line-directory layout. It does not decode opcodes, resolve operands, identify the Office build, or prove that the cache matches the source. A malformed or mismatched version may yield no line map. With `--include-source`, JSON also includes the raw p-code bytes for each extracted line.
- `.xlsm` package input supports non-encrypted ZIP entries using Store or Deflate and classic ZIP32. ZIP64 and encrypted entries are not supported. The CFB reader supports sector and mini-sector chains with cycle and size guards.
- Source decoding accepts UTF-8, UTF-8 BOM, UTF-16LE/BE BOM, and Windows-1252. On macOS/Linux, other declared legacy code pages use the system `iconv`; on other platforms unsupported code pages are returned as explicit errors. No lossy fallback is used for module source.
- A `.frm` text file is parsed as code only; its companion `.frx`, designer layout, and controls are not interpreted.
- Default JSON/DOT suppresses identifiers, expressions, source paths, and diagnostic text while retaining structure, counts, line numbers, and resolution states. `--include-source` reveals names and source expressions as well as source text. Neither mode is a secret scrubber, and structure/line counts can still disclose information.

The default resource limits are defined in `Limits::bounded()`. Applications handling untrusted workbooks should keep finite limits and should surface extraction errors instead of retrying with unlimited sizes.

## Project status and contributions

The implementation is a small independently written parser and container reader, without imported grammar files or third-party Rust crates. See [format references and provenance](docs/PROVENANCE.md) and [analysis model and known gaps](docs/ARCHITECTURE_JA.md). Before publishing a release, confirm that the copyright notice in `LICENSE` names the intended holder and run the release checks against representative Office files that you are authorized to use. The source repository is [ryusui-hiro/vba-retrace](https://github.com/ryusui-hiro/vba-retrace).
