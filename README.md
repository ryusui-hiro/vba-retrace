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

`vba-insight` scans container packages (OOXML relationships, embedded OLE parts), workbook cell formulas, defined names, and worksheet metadata against 91 dedicated security rules:

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
| `VBA-CELL-032` | `SmuggledContainerPayload` | **Critical** | Container package contains smuggled executable binaries (`.exe`, `.dll`, `.sys`, `.scr`, `.bat`, `.cmd`, `.ps1`, `.vbs`, `.hta`, `.lnk`, `.iso`), cloaked PE headers (`MZ`/`PE`), Windows Shell Links, ELF, Mach-O, or staged script files. |
| `VBA-CELL-033` | `WorksheetViewEvasion` | **High** | Worksheet view definition (`xl/worksheets/sheet*.xml`) cloaks formula payloads within hidden columns (`hidden="1"` / `width="0"`), hidden rows (`hidden="1"` / `ht="0"`), extreme viewport displacement (`topLeftCell`), or concealed grid headers (`showGridLines="0"` and `showRowColHeaders="0"`). |
| `VBA-CELL-034` | `ActiveXObjectDeclarationAnomaly` | **Critical** | ActiveX XML declaration (`/activeX/activeX*.xml`) contains weaponized CLSIDs (`WScript.Shell`, Equation Editor 3.0, `XMLHTTP`, `Shell.Explorer`, `Scriptlet.TypeLib`, `ADODB.Stream`), remote UNC paths, executable file references, or dangerous URL schemes. |
| `VBA-CELL-035` | `GlossaryDocumentAnomaly` | **Critical** | Word glossary document parts (`word/glossary/document.xml`, `settings.xml`) or relationships contain remote template injection (`attachedTemplate`), dangerous URI schemes (`ms-msdt:`, `search-ms:`), command field codes (`DDE`, `EXEC`), remote subdocument references, or AltChunk payload smuggling. |
| `VBA-CELL-036` | `EmbeddedFontObfuscationOrSmuggling` | **Critical** | Embedded font streams (`.odttf`, `.ttf`, `.woff`) or font relationships contain smuggled executable binaries (`MZ`/`PE`), Windows Shell Links (`.lnk`), scripts, or reversed GUID XOR-obfuscated ODTTF fonts cloaking PE headers. |
| `VBA-CELL-037` | `DigitalInkDefinitionAnomaly` | **Critical** | Digital Ink markup parts (`xl/ink/`, `word/ink/`, `ppt/ink/`, `.bin`, `.isf`) or relationships contain interactive click/hover triggers (`<a:hlinkClick>`, `<a:hlinkHover>`, `ppaction://program`), UNC credential coercion, weaponized CLSIDs, or smuggled executable binaries. |
| `VBA-CELL-038` | `DocumentPropertyPayloadSmuggling` | **Critical** | Document property parts (`docProps/core.xml`, `docProps/app.xml`, `docProps/custom.xml`) contain smuggled Base64 Windows PE binaries, command line payloads (`powershell`, `cmd.exe`, `wscript.exe`, `mshta`, `rundll32`, `certutil`), dangerous URI schemes, or remote UNC paths enabling NTLM credential coercion. |
| `VBA-CELL-039` | `WebExtensionOrTaskpaneAnomaly` | **Critical** | Office Web Add-in and Taskpane parts (`word/webextensions/`, `xl/webextensions/`, `ppt/webextensions/`, `word/taskpanes/`, `xl/taskpanes/`, `ppt/taskpanes/`) or relationships contain automatic display triggers (`canAutoShow="1"`, `visibility="visible"`), remote external web targets, dangerous URI schemes, or embedded script code enabling macro-less execution. |
| `VBA-CELL-040` | `PivotCacheDataConnectionAnomaly` | **Critical** | Workbook PivotCache definitions (`xl/pivotCache/pivotCacheDefinition*.xml`) or relationships contain external UNC connection paths for NTLM credential coercion, database shell execution commands (`xp_cmdshell`, `sp_OACreate`, `OPENROWSET`), or dangerous URI schemes. |
| `VBA-CELL-041` | `MetafileExploitOrPayloadSmuggling` | **Critical** | Windows Metafile (WMF/EMF) graphics parts (`*.wmf`, `*.emf`, `/media/`) contain CVE-2005-4560 `META_SETABORTPROC` records (`0x052F`), cloaked Windows PE executable headers (`MZ`/`PE`), embedded Windows Shell Links (`.lnk`), or embedded shell execution commands. |
| `VBA-CELL-042` | `XsltTransformOrScriptInjection` | **Critical** | XML parts or stylesheets (`styles.xml`, `settings.xml`, `customXml/`, `*.xsl`, `*.xslt`) contain executable `<msxsl:script>` elements (`language="JScript"` / `"VBScript"`), remote `<w:saveThroughXslt>` transform targets, dangerous XPath `document()` SSRF / NTLM coercion functions, or Windows Shell automation objects. |
| `VBA-CELL-043` | `RelationshipTargetCloakingOrEvasion` | **Critical** | Relationship files (`*.rels`) contain evasion characters (null bytes `%00` / `\0` or Unicode bidirectional overrides `\u{202E}`), percent-encoded dangerous URI protocols (`m%73-m%73dt:`, `s%65arch-ms:`, `m%68tml:`), or local IPC named pipe / loopback coercion targets (`\\.\pipe\`, `\\127.0.0.1\`, `\\localhost\`). |
| `VBA-CELL-044` | `SmartArtOrDiagramPayloadAnomaly` | **Critical** | SmartArt diagram parts (`*/diagrams/*.xml`, `data*.xml`, `layout*.xml`, `drawing*.xml`) or relationships contain interactive action triggers (`<dgm:hlinkClick>`, `<a:hlinkHover>`, `ppaction://program`), dangerous URI protocols (`ms-msdt:`, `search-ms:`, `mhtml:`), remote UNC paths, or cloaked executable/shell command payloads. |
| `VBA-CELL-045` | `MailMergeDataSourceOrCoercionAnomaly` | **Critical** | Word MailMerge settings (`word/settings.xml`) or relationships contain remote UNC connection strings (`<w:connectString>`) enabling NTLM credential coercion, database command injection queries (`xp_cmdshell`, `sp_OACreate`), auto-merge triggers, or external relationships targeting dangerous executable/script files (`.iqy`, `.hta`, `.vbs`, `.bat`, `.ps1`, `.exe`). |
| `VBA-CELL-046` | `QueryTableOrExternalQueryAnomaly` | **Critical** | Excel QueryTable definitions (`xl/queryTables/queryTable*.xml`) or relationships configure automatic refresh (`refreshOnLoad="1"`, `autoRefresh="1"`), external Web Query files (`.iqy`, `.dqy`), UNC credential coercion paths, database command execution (`xp_cmdshell`), or environment variable exfiltration tokens (`%USERNAME%`). |
| `VBA-CELL-047` | `PowerQueryFormulaOrMashupAnomaly` | **Critical** | Excel Power Query definitions (`xl/powerQuery/powerQuery.xml`), Data Mashup parts (`customXml/`, `customData/`), or M code queries contain arbitrary code/script execution via `Web.Page`, remote data exfiltration via `Web.Contents`, remote UNC paths via `File.Contents` or string literals for NTLM credential coercion, smuggled Windows PE executables, or database command execution (`xp_cmdshell`, `OPENROWSET`). |
| `VBA-CELL-048` | `PackageMonikerOrActivationAnomaly` | **Critical** | Embedded OLE object parts, drawings, slides, or package relationships configure dangerous Moniker URI/protocol handlers (`moniker:`, `file:`, `script:`, `composite:`, `ms-msdt:`, `search-ms:`, `ms-appinstaller:`), silent auto-activation flags (`UpdateMode="Always"`, `autoUpdate="1"`, `autoActivate="1"`), deceptive icon aspect cloaking of executable payloads (`DrawAspect="Icon"` with executable extensions or `ProgID="Package"`), or weaponized Packager/Moniker CLSIDs. |
| `VBA-CELL-049` | `NamespaceCloakingOrSchemaSpoofingAnomaly` | **Critical** | OOXML XML parts or relationships configure remote UNC namespace declarations (`xmlns:...="\\host\share..."`) or `xsi:schemaLocation` coercion targets enabling NTLM credential theft, Document Type Definition (DTD) and external entity declarations (`<!DOCTYPE`, `<!ENTITY %`) for XXE injection, or Cyrillic/Unicode homoglyphs or zero-width spaces cloaking standard Office schemas. |
| `VBA-CELL-039` | `WebExtensionOrTaskpaneAnomaly` | **Critical** | Web extension or Office Add-in taskpane parts (`xl/webextensions/`, `word/webextensions/`, `ppt/webextensions/`) configure automatic visibility (`<we:taskpane visibility="1">`), execute external script framesets, or target remote UNC shares. |
| `VBA-CELL-040` | `PivotCacheDataConnectionAnomaly` | **Critical** | Excel PivotCache definitions (`xl/pivotCache/pivotCacheDefinition*.xml`) configure external data connections pointing to remote UNC shares or HTTP/HTTPS endpoints. |
| `VBA-CELL-041` | `MetafileExploitOrPayloadSmuggling` | **Critical** | WMF/EMF metafile records contain embedded MSXSL scripts, cloaked PE binaries, or GDI vulnerability exploit payloads. |
| `VBA-CELL-042` | `XsltTransformOrScriptInjection` | **Critical** | XSLT transform parts contain `<msxsl:script>` blocks, dangerous namespace declarations (`urn:schemas-microsoft-com:xslt`), or remote stylesheet inclusions. |
| `VBA-CELL-043` | `RelationshipTargetCloakingOrEvasion` | **Critical** | Package relationship parts use path traversal (`../`), URL encoding (`%2e%2e`), or protocol obfuscation to conceal external links to malicious payloads. |
| `VBA-CELL-044` | `SmartArtOrDiagramPayloadAnomaly` | **Critical** | SmartArt diagrams or diagram relationships configure click actions, shell execution commands, remote UNC targets, or smuggled binaries. |
| `VBA-CELL-045` | `MailMergeDataSourceOrCoercionAnomaly` | **Critical** | Word document MailMerge settings configure external data source connections to remote UNC paths or invoke database query commands. |
| `VBA-CELL-046` | `QueryTableOrExternalQueryAnomaly` | **Critical** | Excel QueryTable definitions configure external web queries or database connections pointing to remote UNC shares or command execution procedures. |
| `VBA-CELL-047` | `DataMashupOrPowerQueryFormulaAnomaly` | **Critical** | Power Query / Data Mashup parts contain malicious M formulas invoking shell execution (`Expression.Evaluate`, `Web.Contents`, `File.Contents`). |
| `VBA-CELL-048` | `MonikerOrOlePersistenceAnomaly` | **Critical** | Embedded OLE objects configure composite Monikers (`file:`, `http:`, `link`), auto-activation directives (`UpdateMode="Always"`), or cloaked icon representations. |
| `VBA-CELL-049` | `XmlNamespaceOrSchemaEvasion` | **Critical** | Package XML parts declare anomalous namespaces or schema locations designed to bypass static signature filters or trigger parser confusion. |
| `VBA-CELL-050` | `SlicerOrTimelineCacheAnomaly` | **Critical** | Excel Slicer or Timeline definitions configure external cache connections targeting remote UNC shares or database procedures. |
| `VBA-CELL-051` | `BibliographyOrCitationAnomaly` | **Critical** | Word bibliography or citation data sources (`sources.xml`, `customXml`) contain dangerous URI protocols, remote UNC paths, or executable payloads. |
| `VBA-CELL-052` | `CustomXmlDataBindingOrXPathAnomaly` | **Critical** | Word structured document tags (SDT) configure XML data binding with malicious XPath expressions or external XML namespaces. |
| `VBA-CELL-053` | `XmlMapsOrSchemaDefinitionAnomaly` | **Critical** | Excel XML Maps or table schema definitions contain XXE entity declarations, remote UNC schema paths, or XPath SSRF triggers. |
| `VBA-CELL-054` | `DocumentCommentOrAnnotationAnomaly` | **Critical** | Word, PowerPoint, or Excel comments and modern annotations contain smuggled PE executables, shell commands, or remote UNC paths. |
| `VBA-CELL-055` | `ThemeFontOrCoercionAnomaly` | **Critical** | Office Theme parts configure font face names targeting remote UNC paths (NTLM credential coercion vector) or remote theme template URLs. |
| `VBA-CELL-056` | `CustomXmlPropertiesOrItemSchemaAnomaly` | **Critical** | Custom XML item properties or schema references configure remote UNC schema paths enabling NTLM credential coercion, dangerous exploit URI schemes, external relationships to executables, or smuggled PE binaries. |
| `VBA-CELL-057` | `VbaDataStreamOrProjectRelsAnomaly` | **Critical** | VBA project relationship parts or vbaData streams configure external relationships to remote UNC paths or binaries, exploit protocol handlers, shell execution commands, or smuggled PE binaries. |
| `VBA-CELL-058` | `WordGlossaryOrBuildingBlocksRelsAnomaly` | **Critical** | Word glossary definitions or building blocks relationships configure remote template injection, remote UNC paths enabling NTLM credential coercion, exploit protocol handlers, or smuggled PE binaries. |
| `VBA-CELL-059` | `WordDocVariablesOrNotesAnomaly` | **Critical** | Word document variable definitions (docVars) or footnotes and endnotes parts contain smuggled Windows PE binaries, shell execution commands, remote UNC paths, or dangerous exploit URI schemes. |
| `VBA-CELL-060` | `PowerPointTagsOrMastersAnomaly` | **Critical** | PowerPoint programmable tags, presentation relationships, masters, or font tables contain smuggled Windows PE binaries, shell execution commands, remote template injection, or remote UNC paths. |
| `VBA-CELL-061` | `ScenarioManagerOrConsolidationAnomaly` | **Critical** | Excel Scenario Manager replacement cells or Data Consolidation definitions contain cloaked DDE execution formulas, Excel 4.0 macros, shell commands, or remote UNC workbook paths enabling NTLM credential coercion. |
| `VBA-CELL-062` | `PowerPointAnimationOrTimeNodeAnomaly` | **Critical** | PowerPoint slide animation timing nodes (`ppt/slides/slide*.xml`), media nodes (`<p:cMediaNode>`, `<p:media>`), or slide relationships contain shell command execution triggers (`<p:cmd>`), remote UNC media streams enabling NTLM credential coercion, dangerous exploit URI schemes, or smuggled Windows PE binaries. |
| `VBA-CELL-063` | `WordHeaderFooterOrWatermarkAnomaly` | **Critical** | Word headers, footers (`word/header*.xml`, `word/footer*.xml`), VML watermarks (`<v:imagedata src="\\..."/>`), or their relationships configure remote UNC paths enabling NTLM credential coercion, dangerous exploit URI schemes, executable or script targets, shell commands, or smuggled PE binaries. |
| `VBA-CELL-064` | `ExcelDataModelOrFormulaCacheAnomaly` | **Critical** | Excel DataModel definitions (`xl/model/dataModel.xml`) or worksheet shared formula caches (`<f t="shared">`) contain remote UNC connections enabling NTLM credential coercion, database command execution strings (`xp_cmdshell`), XXE declarations, cloaked DDE execution, or smuggled PE binaries. |
| `VBA-CELL-065` | `ExcelPivotCacheOrDefinitionAnomaly` | **Critical** | Excel PivotCache definitions (`xl/pivotCache/pivotCacheDefinition*.xml`), records (`pivotCacheRecords*.xml`), or relationships configure remote UNC connection targets enabling NTLM credential coercion, database command execution procedures (`xp_cmdshell`), dangerous exploit URI schemes, cloaked DDE execution, or smuggled PE binaries. |
| `VBA-CELL-066` | `WordOrPowerPointEmbeddedPackageAnomaly` | **Critical** | Word or PowerPoint embedded packages, OLE binary streams (`word/embeddings/*.bin`, `ppt/embeddings/*.bin`), or auto-activation directives disguise Windows PE executables (verified `MZ`/`PE\0\0` headers), staged shell scripts, remote UNC paths, dangerous exploit URI schemes, or auto-activating OLE handlers. |
| `VBA-CELL-067` | `ExcelExternalBookOrSheetPathAnomaly` | **Critical** | Excel external workbook links (`xl/externalLinks/externalLink*.xml`), relationship parts, or supporting workbook caches configure remote UNC workbook paths enabling NTLM credential coercion, dangerous exploit URI schemes, cloaked DDE execution in defined names, or smuggled PE binaries. |
| `VBA-CELL-068` | `ActiveXBinaryStorageOrPropertyStreamAnomaly` | **Critical** | ActiveX binary property persistence streams (`xl/activeX/activeX*.bin`, `word/activeX/activeX*.bin`, `ppt/activeX/activeX*.bin`) and property storage streams disguise Windows PE executables, staged shell scripts, remote UNC paths, dangerous exploit URI schemes, or weaponized CLSIDs. |
| `VBA-CELL-069` | `XmlDigitalSignatureOrOriginPartAnomaly` | **Critical** | Package digital signatures (`_xmlsignatures/origin.sigs`, `_xmlsignatures/sig*.xml`, `package.sigs`) configure remote UNC reference URIs forcing NTLM credential coercion, dangerous exploit URI schemes, XSLT transform execution filters, XXE declarations, or Base64-smuggled PE binaries. |
| `VBA-CELL-070` | `ExcelControlPropertiesOrFormActionAnomaly` | **Critical** | Excel form control properties (`xl/ctrlProps/ctrlProp*.xml`) or legacy drawing form actions configure linked cell formulas containing cloaked DDE execution, Excel 4.0 macros, remote UNC paths, dangerous exploit URI schemes, or staged shell execution commands. |
| `VBA-CELL-071` | `PowerPointMediaTrackOrActionAnomaly` | **Critical** | PowerPoint media parts (`ppt/media/*`), slide media nodes (`<p:cMediaNode>`), or timing triggers disguise Windows PE executables, ELF/Mach-O binaries, LNK shortcuts, staged scripts, remote UNC streams forcing NTLM coercion, or dangerous exploit URI schemes. |
| `VBA-CELL-072` | `ExcelTableOrSlicerNativeConnectionAnomaly` | **Critical** | Excel table definitions (`xl/tables/table*.xml`), slicers (`xl/slicers/slicer*.xml`), or timeline caches configure remote UNC connections enabling NTLM credential coercion, cloaked DDE execution in slicer captions or formulas, database command execution, or smuggled PE binaries. |
| `VBA-CELL-073` | `WordMailMergeHeaderSourceOrRecipientAnomaly` | **Critical** | Word mail merge settings (`word/settings.xml` `<w:mailMerge>`) or recipient data caches configure remote UNC header sources enabling NTLM credential coercion, dangerous exploit URI schemes, weaponized external relationship targets, or SQL query command injection. |
| `VBA-CELL-074` | `PowerPointSlideShowOrPresentationPropsAnomaly` | **Critical** | PowerPoint presentation properties (`ppt/presProps.xml`), view properties (`ppt/viewProps.xml`), or presentation XML markup configure remote UNC stream paths, dangerous exploit URI schemes, evasive kiosk full-screen mode with continuous loop/broadcast, or staged shell execution commands. |
| `VBA-CELL-075` | `ExcelThreadedCommentOrPersonAnomaly` | **Critical** | Excel modern threaded comments (`xl/threadedComments/threadedComment*.xml`), person caches (`xl/persons/person*.xml`), or author metadata embed cloaked DDE formula strings (`=cmd|`, `=powershell|`), remote UNC mention paths forcing NTLM credential coercion, dangerous exploit URI schemes, or staged shell execution commands. |
| `VBA-CELL-076` | `OfficeThemeOverrideOrFormatSchemeAnomaly` | **Critical** | Office theme override definitions (`xl/theme/themeOverride*.xml`, `word/theme/themeOverride*.xml`, `ppt/theme/themeOverride*.xml`), format schemes, or theme relationship parts configure remote UNC font/theme resource targets enabling NTLM credential coercion, dangerous exploit URI schemes, external relationships targeting weaponized payloads, or staged shell execution commands. |
| `VBA-CELL-077` | `PowerPointSyncOrCommentAuthorsAnomaly` | **Critical** | PowerPoint comment authors (`ppt/commentAuthors.xml`), sync information (`ppt/syncInfo.xml`), or slide sync parts configure remote UNC resource targets enabling NTLM credential coercion, cloaked DDE command formulas, dangerous exploit URI schemes, or staged shell execution commands. |
| `VBA-CELL-078` | `WordKeyMapOrCustomizationAnomaly` | **Critical** | Word keyboard mapping definitions (`word/keyMap.xml`) or customizations (`word/customizations.xml`, `word/customizations.bin`) configure shortcut keys bound to malicious macro/shell commands, remote UNC references enabling NTLM credential coercion, dangerous exploit URI schemes, or weaponized payload targets. |
| `VBA-CELL-079` | `ExcelWebPublishingOrSparklineAnomaly` | **Critical** | Excel web publishing configuration (`xl/webPublishing.xml`), publish items (`xl/webPublishItems.xml`), or sparkline groups configure remote UNC publish destinations or sparkline data targets enabling silent data exfiltration or NTLM credential coercion, dangerous exploit URI schemes, or staged shell execution commands. |
| `VBA-CELL-080` | `PowerPointHandoutOrNotesMasterAnomaly` | **Critical** | PowerPoint handout master (`ppt/handoutMasters/handoutMaster*.xml`), notes master (`ppt/notesMasters/notesMaster*.xml`), or relationship parts configure remote UNC resource targets enabling NTLM credential coercion, cloaked DDE command formulas, dangerous exploit URI schemes, or staged shell execution commands. |
| `VBA-CELL-081` | `WordGlossarySettingsOrFontTableAnomaly` | **Critical** | Word glossary settings (`word/glossary/settings.xml`), web settings (`word/glossary/webSettings.xml`), or font tables (`word/glossary/fontTable.xml`) configure remote UNC references enabling NTLM credential coercion, macro auto-execution hooks, dangerous exploit URI schemes, or weaponized payload targets. |
| `VBA-CELL-082` | `ExcelCustomPropertyOrCustomDataAnomaly` | **Critical** | Excel custom property parts (`xl/customProperty*.bin`), custom data parts (`xl/customData/customData*.xml`), or data model binary streams configure remote UNC resource paths enabling NTLM credential coercion, dangerous exploit URI schemes, serialized .NET binary formatter markers, or staged shell execution commands. |
| `VBA-CELL-083` | `WordSubDocumentOrMasterDocumentAnomaly` | **Critical** | Word subdocument parts (`word/subDocument*.xml`), master document parts, or subdocument relationships configure remote UNC resource paths enabling NTLM credential coercion, dangerous exploit URI schemes, staged shell execution commands, or smuggled Windows PE binaries. |
| `VBA-CELL-084` | `PowerPointFontTableOrEmbeddedFontAnomaly` | **Critical** | PowerPoint font table parts (`ppt/fontTable.xml`), embedded font stream files (`ppt/fonts/*`), or font relationships configure remote UNC resource references enabling NTLM credential coercion, dangerous exploit URI schemes, staged shell execution commands, or smuggled Windows PE binaries. |
| `VBA-CELL-085` | `ExcelQueryTableOrDataFeedAnomaly` | **Critical** | Excel query table parts (`xl/queryTables/queryTable*.xml`), data feed connection parts (`xl/dataFeeds/dataFeed*.xml`), or query relationships configure remote UNC resource destinations enabling NTLM credential coercion, dangerous exploit URI schemes, database command execution procedures, cloaked DDE command formulas, or staged shell execution commands. |
| `VBA-CELL-086` | `PowerPointSlideGuideOrGridAnomaly` | **Critical** | PowerPoint slide guide parts (`ppt/viewProps.xml` `<p:guide>`, `ppt/slideGuides/*`, `ppt/guides/*`), view properties, or guide relationships configure remote UNC resource paths enabling NTLM credential coercion, dangerous exploit URI schemes, staged shell execution commands, or smuggled Windows PE binaries. |
| `VBA-CELL-087` | `WordMailMergeHeaderFilterOrRecipientItemAnomaly` | **Critical** | Word mail merge filter parts (`word/mailMergeFilter*.xml`), recipient data item parts (`word/recipientData*.xml`), or recipient relationships configure remote UNC resource paths enabling NTLM credential coercion, dangerous exploit URI schemes, database command execution procedures, staged shell execution commands, or smuggled Windows PE binaries. |
| `VBA-CELL-088` | `ExcelExternalDataFeedOrDataServiceAnomaly` | **Critical** | Excel external data feed definitions (`xl/dataServices/*`, `xl/externalDataFeeds/*`, `xl/dataFeeds/*`), connection XMLs (`xl/connections/dataService*.xml`), or service relationships configure remote UNC service endpoints enabling NTLM credential coercion, dangerous exploit URI schemes, database command execution procedures, cloaked DDE command formulas, or staged shell execution commands. |
| `VBA-CELL-089` | `PowerPointSlideMasterOrLayoutPartAnomaly` | **Critical** | PowerPoint slide master parts (`ppt/slideMasters/slideMaster*.xml`), slide layout parts (`ppt/slideLayouts/slideLayout*.xml`), or slide master relationships configure remote UNC resource endpoints enabling NTLM credential coercion, dangerous exploit URI schemes, staged shell execution commands, cloaked DDE command formulas, or smuggled Windows PE binaries. |
| `VBA-CELL-090` | `WordDocumentTemplateOrAttachedTemplateAnomaly` | **Critical** | Word document template settings (`word/settings.xml` with `<w:attachedTemplate>`), template parts (`word/template*.xml`, `word/templateSettings.xml`), or template relationships configure remote UNC template paths enabling NTLM credential coercion, dangerous exploit URI schemes, staged shell execution commands, or smuggled Windows PE binaries. |
| `VBA-CELL-091` | `ExcelXmlSpreadsheetOrDataBindingAnomaly` | **Critical** | Excel XML spreadsheet data binding parts (`xl/dataBindings/*`, `xl/bindings/*`), connection XMLs (`xl/connections/binding*.xml`), or binding relationships configure remote UNC endpoints enabling NTLM credential coercion, dangerous exploit URI schemes, database command execution procedures, cloaked DDE command formulas, or staged shell execution commands. |

- **Container-Level Threat Inspection**: Automatically scans OOXML package relationships, drawings, data connections, embedded SVG images, digital signatures, Word field codes (`w:fldSimple`, `w:instrText`), PowerPoint slide actions, AltChunk format payload smuggling parts, Custom UI Ribbon XML callbacks, legacy dialog sheets, `[Content_Types].xml` MIME declarations, external link caches (`xl/externalLinks/`), Word web settings framesets (`word/webSettings.xml`), workbook protection cloaking structures (`xl/workbook.xml`), smuggled executable/script payloads or cloaked PE headers (`VBA-CELL-032`), worksheet view evasion / hidden grid cloaking (`VBA-CELL-033`), ActiveX object CLSID / property declarations (`VBA-CELL-034`), Word glossary document injection (`VBA-CELL-035`), font payload smuggling and ODTTF obfuscation (`VBA-CELL-036`), digital ink action anomalies (`VBA-CELL-037`), document property payload smuggling (`VBA-CELL-038`), web extension/taskpane auto-show (`VBA-CELL-039`), PivotCache data connection anomaly (`VBA-CELL-040`), metafile exploit records and PE cloaking (`VBA-CELL-041`), XSLT transform and MSXSL script injection (`VBA-CELL-042`), relationship target cloaking or evasion (`VBA-CELL-043`), SmartArt and diagram action/payload smuggling (`VBA-CELL-044`), Word MailMerge coercion and query injection (`VBA-CELL-045`), Excel QueryTable external query abuse (`VBA-CELL-046`), Power Query M formulas and Data Mashup parts (`VBA-CELL-047`), OLE object Moniker and auto-activation / icon cloaking (`VBA-CELL-048`), XML namespace cloaking / schema spoofing (`VBA-CELL-049`), Excel Slicer and Timeline cache anomalies (`VBA-CELL-050`), Word bibliography and citation anomalies (`VBA-CELL-051`), Custom XML SDT data binding / XPath injection (`VBA-CELL-052`), XML Maps and table schemas (`VBA-CELL-053`), document comments and modern annotations (`VBA-CELL-054`), theme fonts and remote template coercion (`VBA-CELL-055`), custom XML properties and schema anomalies (`VBA-CELL-056`), VBA project relationships and data stream anomalies (`VBA-CELL-057`), Word glossary building blocks relationships (`VBA-CELL-058`), Word document variables and notes (`VBA-CELL-059`), PowerPoint programmable tags and master slides (`VBA-CELL-060`), Excel Scenario Manager and consolidation sources (`VBA-CELL-061`), PowerPoint animation and timenode triggers (`VBA-CELL-062`), Word header/footer and watermark anomalies (`VBA-CELL-063`), Excel DataModel and shared formula cache anomalies (`VBA-CELL-064`), Excel PivotCache and definition anomalies (`VBA-CELL-065`), Word and PowerPoint embedded package anomalies (`VBA-CELL-066`), Excel external workbook and sheet path anomalies (`VBA-CELL-067`), ActiveX binary storage parts and persistence streams (`VBA-CELL-068`), XML digital signature origin and reference anomaly (`VBA-CELL-069`), Excel form control properties and form action anomalies (`VBA-CELL-070`), PowerPoint media track and slide action anomalies (`VBA-CELL-071`), Excel table and slicer native connection anomalies (`VBA-CELL-072`), Word mail merge header source and recipient anomalies (`VBA-CELL-073`), PowerPoint presentation properties and slideshow anomalies (`VBA-CELL-074`), Excel modern threaded comments and person anomalies (`VBA-CELL-075`), Office theme override and format scheme anomalies (`VBA-CELL-076`), PowerPoint sync and comment author anomalies (`VBA-CELL-077`), Word keyboard map and customization anomalies (`VBA-CELL-078`), Excel web publishing and sparkline anomalies (`VBA-CELL-079`), PowerPoint handout and notes master anomalies (`VBA-CELL-080`), Word glossary settings and font table anomalies (`VBA-CELL-081`), Excel custom property and custom data anomalies (`VBA-CELL-082`), Word subdocument and master document anomalies (`VBA-CELL-083`), PowerPoint font table and embedded font anomalies (`VBA-CELL-084`), Excel query table and data feed anomalies (`VBA-CELL-085`), PowerPoint slide guide and grid anomalies (`VBA-CELL-086`), Word mail merge header filter and recipient item anomalies (`VBA-CELL-087`), Excel external data feed and data service anomalies (`VBA-CELL-088`), PowerPoint slide master and layout anomalies (`VBA-CELL-089`), Word document template and attached template anomalies (`VBA-CELL-090`), and Excel XML spreadsheet and data binding anomalies (`VBA-CELL-091`) for Remote Template Injection, embedded OLE packager binaries, external Moniker links, ActiveX controls, printer settings UNC coercion, custom XML payload smuggling, drawing hover/macro actions, data connections / NTLM coercion, SVG script vectors, signature tampering/stripping, and dangerous protocol handlers even in macro-less weaponized containers.
- **Dynamic Formula De-Obfuscation**: Evaluates complex obfuscated formulas across the workbook grid with Beta distribution and quantile inversion (`BETADIST()`, `BETA.DIST()`, `BETAINV()`, `BETA.INV()`), maturity securities pricing and yield (`PRICEMAT()`, `YIELDMAT()`), coupon schedule functions (`COUPNUM()`, `COUPDAYS()`, `COUPDAYBS()`, `COUPDAYSNC()`), Treasury bill pricing and yield (`TBILLPRICE()`, `TBILLYIELD()`), fractional dollar conversion (`DOLLARDE()`, `DOLLARFR()`), accrued maturity interest (`ACCRINTM()`), gamma distribution and quantile inversion (`GAMMADIST()`, `GAMMA.DIST()`, `GAMMAINV()`, `GAMMA.INV()`), securities duration and interest rate (`DURATION()`, `MDURATION()`, `INTRATE()`), chi-square distribution and quantile inversion (`CHISQ.DIST()`, `CHIDIST()`, `CHISQ.DIST.RT()`, `CHISQ.INV()`, `CHISQ.INV.RT()`, `CHIINV()`), interest rate conversion (`EFFECT()`, `NOMINAL()`), loan amortization and cumulative payment (`IPMT()`, `PPMT()`, `CUMIPMT()`, `CUMPRINC()`), inverse binomial distribution (`CRITBINOM()`, `BINOM.INV()`), cash flow valuation and internal rates of return (`IRR()`, `MIRR()`), discounted security pricing and yield (`DISC()`, `PRICEDISC()`, `RECEIVED()`), discrete hypergeometric distribution (`HYPGEOMDIST()`, `HYPGEOM.DIST()`), financial valuation and loan amortization (`SLN()`, `SYD()`, `NPV()`, `PV()`, `FV()`, `PMT()`), discrete and continuous probability distributions (`LOGNORMDIST()`, `LOGNORM.DIST()`, `POISSON()`, `POISSON.DIST()`, `BINOMDIST()`, `BINOM.DIST()`), statistical and normal distributions (`STANDARDIZE()`, `NORMSDIST()`, `NORM.S.DIST()`, `NORMDIST()`, `NORM.DIST()`), exponential and Weibull reliability distributions (`EXPONDIST()`, `EXPON.DIST()`, `WEIBULL()`, `WEIBULL.DIST()`), physical unit conversions across distance, mass, time, temperature, pressure, force, energy, power, volume, area, and digital memory (`CONVERT()`), formula inspection and error classification (`ISFORMULA()`, `ERROR.TYPE()`), Bessel functions (`BESSELJ()`, `BESSELI()`, `BESSELY()`, `BESSELK()`), error and complementary error functions (`ERF()`, `ERF.PRECISE()`, `ERFC()`, `ERFC.PRECISE()`), probability and distribution functions (`GAUSS()`, `PHI()`), complex argument and conjugate functions (`IMARGUMENT()`, `IMCONJUGATE()`), complex trigonometry and logarithms (`IMSIN()`, `IMCOS()`, `IMTAN()`, `IMSINH()`, `IMCOSH()`, `IMSEC()`, `IMCSC()`, `IMCOT()`, `IMLOG10()`, `IMLOG2()`), Gamma and Log-Gamma functions (`GAMMA()`, `GAMMALN()`), complex arithmetic and powers (`IMSUM()`, `IMSUB()`, `IMPRODUCT()`, `IMDIV()`, `IMPOWER()`, `IMSQRT()`, `IMEXP()`, `IMLN()`), multiset combinatorics and permutations (`COMBINA()`, `PERMUTATIONA()`), integer parity predicates (`ISODD()`, `ISEVEN()`), complex numbers and difference sums (`COMPLEX()`, `IMREAL()`, `IMAGINARY()`, `IMABS()`, `IMCONJG()`, `SUMXMY2()`, `SUMX2MY2()`, `SUMX2PY2()`, `MULTINOMIAL()`), matrix determinant and inversion (`MDETERM()`, `MINVERSE()`), flooring and polynomial series (`INT()`, `SERIESSUM()`), matrix algebra (`MMULT()`, `MUNIT()`), reciprocal trigonometry and hyperbolics (`SEC()`, `CSC()`, `COT()`, `SECH()`, `CSCH()`, `COTH()`), inverse cotangents (`ACOT()`, `ACOTH()`), hyperbolic and inverse hyperbolic trigonometry (`SINH()`, `COSH()`, `TANH()`, `ASINH()`, `ACOSH()`, `ATANH()`), square root with $\pi$ (`SQRTPI()`), sum of squares (`SUMSQ()`), mathematical constants and exponentials (`PI()`, `EXP()`), logarithms (`LN()`, `LOG10()`, `LOG()`), combinatorics and permutations (`COMBIN()`, `PERMUTATIONA()`, `PERMUT()`), multi-array inner product summation (`SUMPRODUCT()`), dynamic sequence generation (`SEQUENCE()`), implicit intersection extraction (`SINGLE()`), Excel 365 dynamic array stacking (`VSTACK()`, `HSTACK()`), logical branching (`IFS()`, `SWITCH()`, `XOR()`), lambda helper functions (`MAP()`, `REDUCE()`, `SCAN()`, `BYROW()`, `BYCOL()`, `MAKEARRAY()`, `ISOMITTED()`), native array literals (`{...}`), custom lambda functions (`LAMBDA()`), scoped variable evaluation (`LET()`), dynamic URL encoding (`ENCODEURL()`), radix conversions (`BIN2HEX()`, `HEX2BIN()`, `OCT2HEX()`, `HEX2OCT()`, `BASE()`, `DECIMAL()`, `HEX2DEC()`, `BIN2DEC()`), locale-independent parsing (`NUMBERVALUE()`), recursive reference resolution (`INDIRECT()`, `OFFSET()`, `ADDRESS()`), cross-cell formula inspection (`FORMULATEXT()`), dynamic array filtering and sorting (`FILTER()`, `SORT()`, `SORTBY()`, `UNIQUE()`, `WRAPROWS()`, `WRAPCOLS()`), bitwise decryption (`BITXOR()`, `BITAND()`, `BITOR()`, `BITLSHIFT()`, `BITRSHIFT()`), Roman numeral conversions (`ROMAN()`, `ARABIC()`), modern dynamic array reshaping (`TAKE()`, `DROP()`, `CHOOSEROWS()`, `CHOOSECOLS()`, `TOROW()`, `TOCOL()`, `EXPAND()`), modern dynamic lookups (`XLOOKUP()`, `XMATCH()`), array inversion (`TRANSPOSE()`), vector/array lookup (`LOOKUP()`), branchless conditional evaluation (`DELTA()`, `GESTEP()`, `SIGN()`), DBCS double-byte character slicing (`LENB()`, `LEFTB()`, `RIGHTB()`, `MIDB()`), integer arithmetic and even/odd rounding (`QUOTIENT()`, `EVEN()`, `ODD()`), factorial calculations (`FACT()`, `FACTDOUBLE()`), number-theoretic reductions (`GCD()`, `LCM()`), text dissection and serialization (`TEXTBEFORE()`, `TEXTAFTER()`, `TEXTSPLIT()`, `ARRAYTOTEXT()`, `VALUETOTEXT()`), multi-cell range aggregations (`CONCAT()`, `TEXTJOIN()`), 2D table lookups (`INDEX()`, `VLOOKUP()`, `HLOOKUP()`, `MATCH()`), Unicode conversions (`UNICHAR()`, `UNICODE()`), and mathematical/string operations (`CHAR()`, `MID()`, `SUBSTITUTE()`, `CHOOSE()`, `HYPERLINK()`, `ROWS()`, `COLUMNS()`, `MROUND()`, `TYPE()`, `ISNONTEXT()`) to uncover hidden LOLBins, multi-cell DDE execution, RTD COM automation, and remote download payloads that evade static pattern matching.
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
