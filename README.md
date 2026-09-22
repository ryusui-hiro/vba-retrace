# vba-insight

[English](README.md) | [日本語](README.ja.md) | [简体中文](README.zh.md)

[![crates.io](https://img.shields.io/crates/v/vba-insight.svg)](https://crates.io/crates/vba-insight)
[![PyPI](https://img.shields.io/pypi/v/vba-insight.svg)](https://pypi.org/project/vba-insight/)
[![npm](https://img.shields.io/npm/v/vba-insight.svg)](https://www.npmjs.com/package/vba-insight)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](Cargo.toml)

High-performance, **zero-dependency** static analysis, P-code disassembly, and automated **VBA Stomping / tampering detection** engine for Office macros (`.xlsm`, `.xlsb`, `.docm`, `.pptm`, legacy `.xls`, `vbaProject.bin`) in pure Rust.

It executes purely in memory without invoking Office, running script interpreters, or making network requests.

---

## Key Highlights

- **Fast & Zero Third-Party Dependencies**: Core crate is written entirely using the Rust Standard Library (`std`). No external C libraries, no OpenSSL, no regex crates—guaranteeing deterministic compilation, minimal binary footprints, and high throughput.
- **Direct Macro Extraction**: Directly unpacks macro streams from OOXML containers (`.xlsm`, `.docm`, `.pptm`), Compound File Binary (`.xls`, `vbaProject.bin`), and handles MS-OVBA decompression and OPC package resolution natively.
- **Full Standard P-Code Disassembler**: Built-in disassembler for 264 standard VBA opcodes covering VBA6 and VBA7 (32-bit & 64-bit architectures), resolving identifiers and literals directly from `_VBA_PROJECT` metadata without external tables.
- **Automated VBA Stomping & Tampering Detection**: Automatically flags discrepancies between decompressed VBA source code and compiled P-code (purged source code, procedures hidden only in bytecode, dangerous Win32 API calls, suspicious URLs/IPs, and ghost GUI modules).
- **Worksheet Cell Threat Scanner**: Scans workbook formulas for Dynamic Data Exchange (DDE) execution (`=cmd|...`), legacy XLM 4.0 macros (`=EXEC(...)`, `=CALL(...)`), remote UNC/HTTP injection, `=WEBSERVICE(...)` data exfiltration, suspicious executable hyperlinks, full-width evasion normalization, and auto-executing defined names (`Auto_Open`).
- **SARIF v2.1.0 Security Reports**: Native output to OASIS SARIF v2.1.0 for seamless integration with GitHub Advanced Security code scanning, GitLab CI, and enterprise SIEM pipelines.
- **First-Class Multi-Language Bindings**: Full native bindings for **Rust**, **Python** (via PyO3 / ABI3 wheels), and **Node.js** (via N-API native addons with TypeScript declarations).

---

## Installation

| Platform / Language | Package Name | Install Command | Description |
|---|---|---|---|
| **Rust Library** | `vba-insight` | `cargo add vba-insight` | Zero-dependency static analysis library |
| **Python (3.10+)** | `vba-insight` | `pip install vba-insight` | Pre-built universal ABI3 wheels with type hints |
| **Node.js (18+)** | `vba-insight` | `npm install vba-insight` | High-performance N-API addon with TypeScript definitions |
| **CLI Binary** | `vba-insight` | `cargo install vba-insight` | Or download pre-built binaries from [Releases](https://github.com/ryusui-hiro/vba-retrace/releases) |

---

## CLI Usage

The `vba-insight` CLI provides four dedicated modes:

```sh
# 1. Comprehensive all-in-one macro container inspection (VBA AST + P-Code + Stomping + Cell Threats)
vba-insight inspect sample.xlsm --format markdown
vba-insight inspect suspicious.docm --format sarif > results.sarif

# 2. Automated VBA Stomping & Tampering Detection
vba-insight stomping malicious.xlsm --format sarif
vba-insight stomping malicious.xlsb --format markdown

# 3. Compiled P-Code Bytecode Disassembly
vba-insight disasm sample.xlsm --format markdown
vba-insight disasm vbaProject.bin --format json

# 4. Pure VBA Source Code Semantic Analysis
vba-insight analyze examples/approval.bas --host excel
vba-insight analyze examples/approval.bas --include-source
vba-insight analyze examples/approval.bas --format dot > cfg.dot
```

---

## Code Examples

### 1. Rust Library API

#### Complete Macro Container Inspection & SARIF Export

```rust
use vba_insight::{
    inspect_macro_file, inspect_to_markdown, inspection_to_sarif, AnalysisOptions,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let container_bytes = std::fs::read("suspicious.xlsm")?;
    let options = AnalysisOptions::default();

    // Inspect container: unpacks streams, parses AST, disassembles P-code, detects stomping & cell threats
    let inspection = inspect_macro_file(&container_bytes, &options)?;

    println!("Extracted Modules: {}", inspection.extracted.modules.len());
    println!("Has Stomping: {}", inspection.stomping_report.has_stomping);

    // Export SARIF v2.1.0 (includes both stomping and cell threats) for GitHub Code Scanning
    let sarif = inspection_to_sarif(&inspection, "suspicious.xlsm");
    std::fs::write("audit.sarif", sarif)?;

    // Generate Markdown report
    let md = inspect_to_markdown(&inspection);
    println!("{md}");

    Ok(())
}
```

#### Dedicated VBA Stomping & Tampering Detection

```rust
use vba_insight::{
    detect_project_stomping, extract_macro_container, stomping_to_sarif, Limits,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = std::fs::read("target.docm")?;
    let extracted = extract_macro_container(&bytes, &Limits::bounded())?;
    let report = detect_project_stomping(&extracted)?;

    if report.has_stomping {
        eprintln!("ALERT: Stomping detected! Overall Severity: {:?}", report.overall_severity);
        for m in &report.modules {
            if m.is_stomped {
                eprintln!(" Module {}: {} findings", m.module_name, m.findings.len());
                for finding in &m.findings {
                    eprintln!("  - [{:?}] {}", finding.severity, finding.description);
                }
            }
        }
        for finding in &report.project_findings {
            eprintln!(" - [{:?}] {}", finding.severity, finding.description);
        }
    }

    Ok(())
}
```

#### Disassembling Compiled P-Code Bytecode

```rust
use vba_insight::{
    disassemble_extracted_project, disasm_to_markdown, extract_macro_container, Limits,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = std::fs::read("sample.xlsm")?;
    let extracted = extract_macro_container(&bytes, &Limits::bounded())?;
    let disassembly = disassemble_extracted_project(&extracted)?;

    let md = disasm_to_markdown(&disassembly);
    println!("{md}");

    Ok(())
}
```

#### Pure VBA Source Code Static Analysis

```rust
use vba_insight::{analyze_sources, AnalysisOptions, SourceUnit};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sources = vec![SourceUnit {
        name: "Module1.bas".to_string(),
        text: r#"
            Public Sub ExecuteAction()
                Dim cmd As String
                cmd = "calc.exe"
                Call Shell(cmd, vbNormalFocus)
            End Sub
        "#.to_string(),
    }];

    let report = analyze_sources(&sources)?;
    assert!(!report.project.code_executed);
    println!("Procedures analyzed: {}", report.project.modules[0].procedures.len());

    Ok(())
}
```

---

### 2. Python API (`pip install vba-insight`)

Pre-compiled universal ABI3 binary wheels are available for Python 3.10 and later on Linux, macOS, and Windows.

```python
import json
import vba_insight

# 1. Inspect an Office macro container (.xlsm, .xlsb, .docm, .pptm, .xls, or raw vbaProject.bin)
report = vba_insight.inspect_file("suspicious.xlsm")

print(f"Project Name: {report.get('project_name')}")
stomping = report.get("stomping", {})

if stomping.get("has_stomping"):
    print(f"[!] VBA Stomping Detected! Severity: {stomping.get('overall_severity')}")
    for finding in stomping.get("project_findings", []):
        print(f"  - [{finding['rule_id']}] {finding['description']}")
    for mod in stomping.get("modules", []):
        if mod.get("is_stomped"):
            print(f"  Module {mod.get('module_name')}:")
            for finding in mod.get("findings", []):
                print(f"    - [{finding['rule_id']}] {finding['description']}")

# 2. Check for dangerous worksheet cell threats (DDE, XLM, WEBSERVICE)
analysis = report.get("analysis", {})
workbook = analysis.get("workbook_structure", {})
cell_threats = workbook.get("cell_threats", [])
if cell_threats:
    print(f"[!] Found {len(cell_threats)} dangerous cell formulas:")
    for threat in cell_threats:
        print(f"  - [{threat['rule_id']}] {threat['coordinate']}: {threat['threat_kind']} ({threat['formula']})")

# 3. Export OASIS SARIF v2.1.0 report for GitHub Advanced Security / CI integration
# (Includes both VBA Stomping VBA-STOMP-001..010 and Container/Cell Threat VBA-CELL-001..017 rules)
sarif_json = vba_insight.inspect_file_sarif("suspicious.xlsm")
with open("security_report.sarif", "w", encoding="utf-8") as f:
    f.write(sarif_json)

# 4. Disassemble compiled VBA P-code bytecode instructions
pcode_modules = vba_insight.disasm_file("suspicious.xlsm")
for mod in pcode_modules:
    print(f"Module: {mod['module_name']} - {len(mod['lines'])} pcode lines")

# 5. Export a formatted Markdown inspection summary
markdown_summary = vba_insight.inspect_file_markdown("suspicious.xlsm")
print(markdown_summary)

# 6. Pure static analysis of VBA source units
vba_sources = [
    ("Module1.bas", "Public Sub Test()\n    MsgBox \"Hello\"\nEnd Sub\n")
]
ast_report = vba_insight.analyze_sources(vba_sources)
print("Modules parsed:", len(ast_report["project"]["modules"]))
```

---

### 3. Node.js & TypeScript API (`npm install vba-insight`)

High-performance native N-API addon with bundled TypeScript type definitions.

```typescript
import * as fs from 'node:fs';
import {
  inspectMacroFileJson,
  inspectMacroFileSarif,
  inspectMacroFileMarkdown,
  disasmMacroFileJson,
  analyzeSourcesJson,
} from 'vba-insight';

// 1. Read macro container into a Buffer
const fileBuffer = fs.readFileSync('suspicious.xlsm');

// 2. Perform complete macro file inspection (returns JSON string)
const rawJson = inspectMacroFileJson(fileBuffer, true);
const report = JSON.parse(rawJson);

console.log('Project Name:', report.project_name);
if (report.stomping?.has_stomping) {
  console.error(`[!] Stomping Detected! Severity: ${report.stomping.overall_severity}`);
  for (const finding of report.stomping.project_findings ?? []) {
    console.error(`  - [${finding.rule_id}] ${finding.description}`);
  }
  for (const mod of report.stomping.modules ?? []) {
    if (mod.is_stomped) {
      console.error(`  Module ${mod.module_name}:`);
      for (const finding of mod.findings ?? []) {
        console.error(`    - [${finding.rule_id}] ${finding.description}`);
      }
    }
  }
}

// Check dangerous worksheet cell threats (DDE, XLM, WEBSERVICE)
const cellThreats = report.analysis?.workbook_structure?.cell_threats ?? [];
for (const threat of cellThreats) {
  console.warn(`  - [${threat.rule_id}] ${threat.coordinate}: ${threat.threat_kind} (${threat.formula})`);
}

// 3. Export SARIF v2.1.0 report for CI code scanning
const sarifReport = inspectMacroFileSarif(fileBuffer, 'suspicious.xlsm');
fs.writeFileSync('macro-scan.sarif', sarifReport);

// 4. Disassemble compiled P-code instructions
const pcodeJson = disasmMacroFileJson(fileBuffer);
console.log('P-Code modules count:', JSON.parse(pcodeJson).length);

// 5. Generate GitHub-flavored Markdown inspection report
const markdownReport = inspectMacroFileMarkdown(fileBuffer);
console.log(markdownReport);

// 6. Static analysis of raw VBA source text
const sourceUnits = [
  {
    name: 'Module1.bas',
    text: 'Sub Auto_Open()\n    Shell "powershell -enc ...", 0\nEnd Sub',
  },
];
const analysisJson = analyzeSourcesJson(sourceUnits, true);
const parsedAnalysis = JSON.parse(analysisJson);
console.log('Analysis completed. Code executed:', parsedAnalysis.project.code_executed); // always false
```

---

## Threat Detection Engines

### 1. VBA Stomping & Tampering Detection Rules

`vba-insight` implements 10 specialized rules covering discrepancy analysis between source text and compiled P-code bytecode:

| Rule ID | Finding Kind | Severity | Description & Detection Logic |
|---|---|:---:|---|
| `VBA-STOMP-001` | `SourcePurged` | **Critical** | VBA source code has been completely stripped or purged while compiled P-code bytecode remains present and executable. |
| `VBA-STOMP-002` | `ProcedureHiddenInPCode` | **High** | A procedure exists in the compiled P-code stream but does not appear anywhere in the decompressed VBA source text. |
| `VBA-STOMP-003` | `SuspiciousLiteralInPCode` | **High** | Suspicious string literal (URL, IPv4 address, script command, or executable) exists in compiled P-code but is absent from source code. |
| `VBA-STOMP-004` | `SensitiveCallInPCode` | **Critical** | Dangerous system API or process injection hook (e.g., `VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`, `InternetOpen`) is invoked in P-code but omitted from source text. |
| `VBA-STOMP-005` | `LineCountDiscrepancy` | **Medium** | Significant discrepancy between source code physical line count and compiled P-code line count. |
| `VBA-STOMP-006` | `ProcedureMissingInPCode` | **Low** | A procedure declared in source text is missing from the compiled P-code stream. |
| `VBA-STOMP-007` | `PerformanceCachePurged` | **Medium** | Compiled P-code performance cache has been deliberately wiped while source procedures remain (VBA Purging evasion). |
| `VBA-STOMP-008` | `HiddenGuiModule` | **High** | Module is declared in the `dir` stream but omitted from the `PROJECT` manifest, hiding it from the VBA IDE viewer (Evil Clippy technique). |
| `VBA-STOMP-009` | `ProjectLockedOrUnviewable` | **Low** | VBA project has protection/lock attributes (`CMG`, `DPB`, `GC`) rendering it unviewable in the standard Office VBA IDE. |
| `VBA-STOMP-010` | `SourceCorruptedWithValidPCode` | **Critical** | Source code container fails MS-OVBA decompression or is corrupted while valid compiled P-code remains executable. |

### 2. Container Package & Worksheet Cell Threat Scanner

`vba-insight` scans container packages (OOXML relationships, embedded OLE parts), workbook cell formulas, defined names, and worksheet metadata against 28 dedicated security rules:

| Rule ID | Finding Kind | Severity | Description & Detection Logic |
|---|---|:---:|---|
| `VBA-CELL-001` | `DDEExecutionFormula` | **Critical** | Worksheet cell or defined name contains a formula executing commands via Dynamic Data Exchange (DDE). |
| `VBA-CELL-002` | `XlmMacroExecutionFormula` | **Critical** | Worksheet cell or defined name contains an Excel 4.0 (XLM) macro expression executing code or launching processes. |
| `VBA-CELL-003` | `RemoteWorkbookLink` | **High** | Worksheet cell formula references remote external workbook paths over UNC (`\\server\share`) or HTTP/HTTPS. |
| `VBA-CELL-004` | `DataExfiltrationFormula` | **Medium** | Worksheet cell uses `=WEBSERVICE(...)` or `FILTERXML` capable of silently transmitting sensitive cell values externally. |
| `VBA-CELL-005` | `SuspiciousDownloadHyperlink` | **High** | Worksheet `=HYPERLINK(...)` formula points to an executable, script, archive, or custom protocol handler (`.exe`, `.scr`, `.bat`, `search-ms:`, etc.). |
| `VBA-CELL-006` | `AutoExecDefinedName` | **High** | Workbook defined name (such as `Auto_Open`, `_xlnm.Auto_Open`, or `Auto_Close`) triggers automatic macro execution. |
| `VBA-CELL-007` | `VeryHiddenWorksheet` | **Low** | Worksheet visibility is set to `state="veryHidden"` to cloak malicious macro payloads from the standard Excel UI. |
| `VBA-CELL-008` | `XlmMacroSheetPresent` | **Critical** | Workbook contains a legacy Excel 4.0 macro sheet, frequently leveraged in evasion payloads. |
| `VBA-CELL-009` | `DeobfuscatedThreatFormula` | **Critical** | Formula obfuscation (`CHAR`, `CONCATENATE`, string substitution) dynamically resolves to an executable, command, or DDE payload. |
| `VBA-CELL-010` | `RemoteTemplateInjection` | **Critical** | Relationship links to an external template over HTTP/HTTPS/SMB (`attachedTemplate`), loading remote malicious dotm payloads. |
| `VBA-CELL-011` | `EmbeddedOlePackage` | **High** | OOXML package contains embedded OLE binary or packager payload in `/embeddings/` (e.g., CVE-2017-11882 exploit droppers). |
| `VBA-CELL-012` | `ExternalOleObject` | **High** | Relationship links to an external OLE object over HTTP/HTTPS/SMB (`oleObject`), enabling remote Moniker or exploit execution. |
| `VBA-CELL-013` | `ActiveXControlPresent` | **Medium** | OOXML package contains embedded ActiveX control binary in `/activex/`, enabling macro-less exploitation. |
| `VBA-CELL-014` | `ExternalSubdocumentReference` | **High** | Relationship links to an external subdocument or frame over HTTP/HTTPS/SMB (`subDocument` / `frame`). |
| `VBA-CELL-015` | `SuspiciousPrinterSettings` | **High** | Package contains printer settings (`printerSettings*.bin`) with external UNC paths (`\\host\share`), remote URLs, or command triggers (CVE-2023-36884 / Storm-0978). |
| `VBA-CELL-016` | `CustomXmlPayloadSmuggling` | **High** | Custom XML parts (`/customXml/*.xml`) contain smuggled base64 PE executables, XXE injection, or script/HTML payloads. |
| `VBA-CELL-017` | `SuspiciousProtocolHandler` | **Critical** | Relationship target references dangerous URI schemes (`ms-msdt:` / Follina CVE-2022-30190, `search-ms:`, `ms-appinstaller:`, `mhtml:`, `javascript:`, `vbscript:`). |
| `VBA-CELL-018` | `SuspiciousDrawingAction` | **High** | Drawing shape, slide trigger, or VML button action defines mouse hover execution (`<a:hlinkHover>`), macro action link (`ppaction://macro`, `<x:FmlaMacro>`), or dangerous target payload. |
| `VBA-CELL-019` | `ExternalDataConnection` | **High** | External data connection (`/xl/connections.xml`, query table, or mail merge) contains UNC paths for NTLM coercion, remote web queries, or database command execution (`xp_cmdshell`, PowerShell). |
| `VBA-CELL-020` | `RealTimeDataExecution` | **Critical** | Worksheet cell or defined name contains an `=RTD(...)` formula to invoke COM automation servers (`WScript.Shell`, `Shell.Application`) or remote DCOM hosts. |
| `VBA-CELL-021` | `SuspiciousSvgVector` | **High** | Container package contains an embedded SVG image (`/media/*.svg`) with malicious script elements (`<script>`), event handlers, or XXE external entities. |
| `VBA-CELL-022` | `TamperedVbaProjectSignature` | **High** | VBA project digital signature (`vbaProjectSignature*.bin`) is truncated, malformed, or presents dangling relationship references (signature stripping/spoofing). |
| `VBA-CELL-023` | `WordFieldCodeExecution` | **Critical** | Word document parts (`word/document.xml`, headers, footers) contain suspicious field codes executing commands via DDE/DDEAUTO, downloading remote documents via INCLUDETEXT/LINK, or coercing credentials via UNC paths. |
| `VBA-CELL-024` | `PowerPointSlideAction` | **Critical** | PowerPoint presentation parts (`ppt/slides/slide*.xml`, layouts, masters) contain action or hover triggers (`ppaction://program`, `<a:hlinkHover>`) executing external programs, macros, or linking to executable files. |
| `VBA-CELL-025` | `SuspiciousAltChunkPayload` | **Critical** | Word Alternative Format Chunk (`aFChunk`) relationships or parts reference remote exploit templates or contain smuggled HTML scripts, embedded RTF exploits, or executable payloads. |
| `VBA-CELL-026` | `CustomUiRibbonCallback` | **Critical** | Custom UI Ribbon XML (`customUI/customUI*.xml`) registers `onLoad` automatic execution callbacks upon document open or control `onAction` macro triggers. |
| `VBA-CELL-027` | `LegacyDialogSheetMacro` | **High** | Legacy Excel 5.0/95 Dialog Sheet (`xl/dialogsheets/sheet*.xml`) contains embedded control macro bindings (`<x:FmlaMacro>`) or auto-popup social engineering dialogs. |
| `VBA-CELL-028` | `ContentTypeAnomaly` | **Critical** | Package `[Content_Types].xml` contains path traversal PartNames (`/../`), dangerous executable MIME types (`application/x-msdownload`, `application/hta`), or MIME extension spoofing (cloaking `vbaProject` under image or non-macro extensions). |
| `VBA-CELL-029` | `ExternalLinkTargetAnomaly` | **Critical** | External link cache (`xl/externalLinks/externalLink*.xml`) or relationship targets remote UNC paths, dangerous executables, exploit protocols, or registers hidden DDE/OLE server links. |
| `VBA-CELL-030` | `WebSettingsScriptOrReload` | **Critical** | Document web settings (`word/webSettings.xml`) injects remote framesets, frame reload triggers, or exploit protocol targets rendered in web layout view. |
| `VBA-CELL-031` | `WorkbookProtectionEvasion` | **High** | Workbook protection (`xl/workbook.xml`) locks structure (`lockStructure="1"`) while cloaking veryHidden sheets, or applies anomalous password protection hashes to impede inspection. |

- **Container-Level Threat Inspection**: Automatically scans OOXML package relationships, drawings, data connections, embedded SVG images, digital signatures, Word field codes (`w:fldSimple`, `w:instrText`), PowerPoint slide actions, AltChunk format payload smuggling parts, Custom UI Ribbon XML callbacks, legacy dialog sheets, `[Content_Types].xml` MIME declarations, external link caches (`xl/externalLinks/`), Word web settings framesets (`word/webSettings.xml`), and workbook protection cloaking structures (`xl/workbook.xml`) for Remote Template Injection, embedded OLE packager binaries, external Moniker links, ActiveX controls, printer settings UNC coercion, custom XML payload smuggling, drawing hover/macro actions, data connections / NTLM coercion, SVG script vectors, signature tampering/stripping, and dangerous protocol handlers even in macro-less weaponized containers.
- **Dynamic Formula De-Obfuscation**: Evaluates complex obfuscated formulas across the workbook grid with Excel 365 lambda helper functions (`MAP()`, `REDUCE()`, `SCAN()`, `BYROW()`, `BYCOL()`, `MAKEARRAY()`, `ISOMITTED()`), native array literals (`{...}`), custom lambda functions (`LAMBDA()`), scoped variable evaluation (`LET()`), dynamic URL encoding (`ENCODEURL()`), radix conversions (`BIN2HEX()`, `HEX2BIN()`, `OCT2HEX()`, `HEX2OCT()`, `BASE()`, `DECIMAL()`, `HEX2DEC()`, `BIN2DEC()`), locale-independent parsing (`NUMBERVALUE()`), recursive reference resolution (`INDIRECT()`, `OFFSET()`, `ADDRESS()`), cross-cell formula inspection (`FORMULATEXT()`), dynamic array filtering and sorting (`FILTER()`, `SORT()`, `SORTBY()`, `UNIQUE()`, `WRAPROWS()`, `WRAPCOLS()`), bitwise decryption (`BITXOR()`, `BITAND()`, `BITOR()`, `BITLSHIFT()`, `BITRSHIFT()`), Roman numeral conversions (`ROMAN()`, `ARABIC()`), modern dynamic array reshaping (`TAKE()`, `DROP()`, `CHOOSEROWS()`, `CHOOSECOLS()`, `TOROW()`, `TOCOL()`, `EXPAND()`), modern dynamic lookups (`XLOOKUP()`, `XMATCH()`), text dissection and serialization (`TEXTBEFORE()`, `TEXTAFTER()`, `TEXTSPLIT()`, `ARRAYTOTEXT()`, `VALUETOTEXT()`), multi-cell range aggregations (`CONCAT()`, `TEXTJOIN()`), 2D table lookups (`INDEX()`, `VLOOKUP()`, `HLOOKUP()`, `MATCH()`), Unicode conversions (`UNICHAR()`, `UNICODE()`), and mathematical/string operations (`CHAR()`, `MID()`, `SUBSTITUTE()`, `CHOOSE()`, `HYPERLINK()`, `ROWS()`, `COLUMNS()`, `MROUND()`, `TYPE()`, `ISNONTEXT()`) to uncover hidden LOLBins, multi-cell DDE execution, RTD COM automation, and remote download payloads that evade static pattern matching.
- **Full-Width Character Evasion Defense**: Automatically normalizes full-width Unicode characters (`U+FF01`–`U+FF5E`, `U+3000`) to standard ASCII prior to formula inspection, neutralizing obfuscation tricks.

---

## Core Semantic Engine Details

- Tokenizes VBA text while retaining exact UTF-8 byte spans and line/column locations.
- Treats documented VBA whitespace separators, including full-width Japanese ideographic space (`U+3000`), as separators rather than identifier characters.
- Applies VBA line-continuation rules before conditional-compilation evaluation (`#If`, `#Const`), keeping logical lines coherent while masking inactive branches.
- Parses module declarations, procedure headers (`Sub`, `Function`, `Property`), arguments, variables, `Type` and `Enum` blocks, and structured statements (`If`, `Select Case`, loops, `With`, labels, `GoTo`, computed `On...GoTo`/`On...GoSub`).
- Resolves expression precedence, dot member access, bang dictionary access, and type suffixes (`!`, `#`, `$`, `%`, `&`, `@`, `^`).
- Constructs structural Control-Flow Graphs (CFG), reaching definitions, acyclic constant folding, and error propagation graphs.
- Direct MS-OVBA decompression, Compound File Binary (CFB) stream parsing, and OPC Open Packaging Conventions resolving from standard `.xlsm`, `.xlsb`, `.docm`, `.pptm`, legacy `.xls`, and raw `vbaProject.bin`.

---

## Security Boundaries & Safety Guarantees

- **No Code Execution**: The engine never invokes host scripting interpreters, Office automation, or JIT runtimes.
- **No Network Access**: The crate has no network socket capabilities and never initiates remote requests.
- **Bounded Resource Limits**: Implements strict recursion depth, buffer allocation caps, and iteration limits (`Limits::bounded()`) to defend against ZIP bombs, decompression loops, and CFB mini-stream cycle attacks.
- **Static Approximation Boundary**: Control-flow paths represent structural candidates rather than concrete execution proofs. Late-bound object references, dynamic host evaluation (`Evaluate`), and unmodeled external type libraries remain explicitly unresolved.

---

## Documentation & References

- [Architecture & Analysis Model (JA)](docs/ARCHITECTURE_JA.md)
- [Specifications & Format Provenance](docs/PROVENANCE.md)
- [Post-Publication Roadmap (JA)](docs/ROADMAP_JA.md)
- [Publishing & Release Pipeline Guide](docs/PUBLISHING.md)
- [Contribution Guidelines](CONTRIBUTING.md)
- [License (MIT)](LICENSE)

Source repository: [ryusui-hiro/vba-retrace](https://github.com/ryusui-hiro/vba-retrace)
