# vba-insight

[English](README.md) | [日本語](README.ja.md) | [简体中文](README.zh.md)

[![crates.io](https://img.shields.io/crates/v/vba-insight.svg)](https://crates.io/crates/vba-insight)
[![PyPI](https://img.shields.io/pypi/v/vba-insight.svg)](https://pypi.org/project/vba-insight/)
[![npm](https://img.shields.io/npm/v/vba-insight.svg)](https://www.npmjs.com/package/vba-insight)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](Cargo.toml)

基于纯 Rust (`std`) 实现的高性能、**零第三方依赖（Zero-dependency）** VBA 静态语义分析、P-Code（中间字节码）反汇编以及 **VBA Stomping / 宏篡改自动检测** 引擎。支持直接从 Office 宏容器（`.xlsm`、`.xlsb`、`.docm`、`.pptm`、传统 `.xls` 以及原始二进制 `vbaProject.bin`）解包并检查。

本引擎完全在内存中执行，绝不调用 Office 运行时、不运行任何脚本解释器、不发起任何网络请求。

---

## 核心特性

- **超高性能与零第三方依赖 (`std`)**: 核心库完全基于 Rust 标准库编写。无任何外部 C 依赖、无 OpenSSL、无第三方正则引擎，确保确定性编译、最小二进制体积与极高的分析吞吐率。
- **直接解包 Office 宏容器**: 原生支持解压 OOXML 容器（`.xlsm`、`.docm`、`.pptm`）、解析复合文档二进制格式（CFB / `.xls`、`vbaProject.bin`）、解压 MS-OVBA 压缩流并解析 OPC 规范关系。
- **内置标准 P-Code 反汇编器**: 完整覆盖 264 个标准 VBA 操作码（VBA6 与 VBA7，全面支持 32 位与 64 位架构），直接从 `_VBA_PROJECT` 元数据中解析标识符与字符串字面量，无需外挂指令表。
- **自动化 VBA Stomping 与篡改检测**: 自动比对源码文本与编译后 P-Code 字节码差异（检测源码被清除/Purged、仅隐藏在字节码中的过程、危险 Win32 系统 API 调用、可疑 URL/IP 以及 GUI 隐藏的幽灵模块等）。
- **工作表单元格威胁扫描器**: 扫描工作表公式中的动态数据交换（DDE）执行（`=cmd|...`）、传统 XLM 4.0 宏（`=EXEC(...)`、`=CALL(...)`）、远程 UNC / HTTP 注入、`=WEBSERVICE(...)` 数据外发回连、可疑可执行文件超链接、全角字符混淆逃逸标准化以及工作簿自动执行定义名（`Auto_Open` 等）。
- **SARIF v2.1.0 安全报告输出**: 原生生成 OASIS SARIF v2.1.0 格式报告，与 GitHub Advanced Security Code Scanning、GitLab CI 及企业 SIEM 审计平台无缝集成。
- **完善的多语言绑定**: 原生支持 **Rust**、**Python**（PyO3 / ABI3 通用轮子）与 **Node.js**（N-API 原生插件，附带完整 TypeScript 类型定义）。

---

## 安装指南

| 语言 / 平台 | 软件包名 | 安装命令 | 说明 |
|---|---|---|---|
| **Rust 库** | `vba-insight` | `cargo add vba-insight` | 零依赖静态分析与反汇编库 |
| **Python (3.10+)** | `vba-insight` | `pip install vba-insight` | 预编译 ABI3 跨平台轮子，附类型注解 |
| **Node.js (18+)** | `vba-insight` | `npm install vba-insight` | 高性能 N-API 原生扩展，附 TypeScript 类型声明 |
| **CLI 命令行** | `vba-insight` | `cargo install vba-insight` | 或从 [Releases](https://github.com/ryusui-hiro/vba-retrace/releases) 直接下载预编译二进制文件 |

---

## CLI 命令行使用

`vba-insight` 命令行工具提供四种核心工作模式：

```sh
# 1. 宏容器全面综合审计（VBA AST + P-Code 反汇编 + Stomping 检测 + 单元格威胁扫描）
vba-insight inspect sample.xlsm --format markdown
vba-insight inspect suspicious.docm --format sarif > results.sarif

# 2. 自动化 VBA Stomping 与篡改检测
vba-insight stomping malicious.xlsm --format sarif
vba-insight stomping malicious.xlsb --format markdown

# 3. 编译后 P-Code 字节码反汇编
vba-insight disasm sample.xlsm --format markdown
vba-insight disasm vbaProject.bin --format json

# 4. VBA 源代码静态语义与控制流分析
vba-insight analyze examples/approval.bas --host excel
vba-insight analyze examples/approval.bas --include-source
vba-insight analyze examples/approval.bas --format dot > cfg.dot
```

---

## 代码示例

### 1. Rust 库 API

#### 综合宏文件检查与 SARIF 导出

```rust
use vba_insight::{
    inspect_macro_file, inspect_to_markdown, inspection_to_sarif, AnalysisOptions,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let container_bytes = std::fs::read("suspicious.xlsm")?;
    let options = AnalysisOptions::default();

    // 综合检查：直接解包、构建 AST、反汇编 P-Code、全面执行 Stomping 与单元格威胁检测
    let inspection = inspect_macro_file(&container_bytes, &options)?;

    println!("提取模块数量: {}", inspection.extracted.modules.len());
    println!("是否存在 Stomping: {}", inspection.stomping_report.has_stomping);

    // 导出用于 GitHub Code Scanning 的 SARIF v2.1.0 报告（包含 Stomping 与单元格威胁）
    let sarif = inspection_to_sarif(&inspection, "suspicious.xlsm");
    std::fs::write("audit.sarif", sarif)?;

    // 导出 Markdown 报告
    let md = inspect_to_markdown(&inspection);
    println!("{md}");

    Ok(())
}
```

#### 专用 VBA Stomping 与篡改检测

```rust
use vba_insight::{
    detect_project_stomping, extract_macro_container, stomping_to_sarif, Limits,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = std::fs::read("target.docm")?;
    let extracted = extract_macro_container(&bytes, &Limits::bounded())?;
    let report = detect_project_stomping(&extracted)?;

    if report.has_stomping {
        eprintln!("警告: 发现 VBA Stomping 篡改！总体严重级别: {:?}", report.overall_severity);
        for m in &report.modules {
            if m.is_stomped {
                eprintln!(" 模块 {}: 违规项数量 {}", m.module_name, m.findings.len());
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

#### 反汇编已编译 P-Code 字节码

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

#### 纯 VBA 源码静态语义分析

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
    println!("分析过程数: {}", report.project.modules[0].procedures.len());

    Ok(())
}
```

---

### 2. Python API (`pip install vba-insight`)

支持 Python 3.10 及以上版本，跨 Linux、macOS 与 Windows 提供预编译 universal ABI3 轮子。

```python
import json
import vba_insight

# 1. 检查 Office 宏文件（.xlsm、.xlsb、.docm、.pptm、.xls、vbaProject.bin）
report = vba_insight.inspect_file("suspicious.xlsm")

print(f"项目名称: {report.get('project_name')}")
stomping = report.get("stomping", {})

if stomping.get("has_stomping"):
    print(f"[!] 发现 VBA Stomping！威胁级别: {stomping.get('overall_severity')}")
    for finding in stomping.get("project_findings", []):
        print(f"  - [{finding['rule_id']}] {finding['description']}")
    for mod in stomping.get("modules", []):
        if mod.get("is_stomped"):
            print(f"  模块 {mod.get('module_name')}:")
            for finding in mod.get("findings", []):
                print(f"    - [{finding['rule_id']}] {finding['description']}")

# 2. 检查工作表中的危险单元格公式（DDE、XLM、WEBSERVICE 等）
analysis = report.get("analysis", {})
workbook = analysis.get("workbook_structure", {})
cell_threats = workbook.get("cell_threats", [])
if cell_threats:
    print(f"[!] 发现 {len(cell_threats)} 处危险单元格公式:")
    for threat in cell_threats:
        print(f"  - [{threat['rule_id']}] {threat['coordinate']}: {threat['threat_kind']} ({threat['formula']})")

# 3. 导出符合 OASIS SARIF v2.1.0 标准的安全报告（对接 GitHub Code Scanning / CI）
# (包含 VBA Stomping VBA-STOMP-001..010 与 容器/单元格威胁 VBA-CELL-001..017 规则)
sarif_json = vba_insight.inspect_file_sarif("suspicious.xlsm")
with open("security_report.sarif", "w", encoding="utf-8") as f:
    f.write(sarif_json)

# 4. 反编译提取已编译的 VBA P-Code 字节码指令
pcode_modules = vba_insight.disasm_file("suspicious.xlsm")
for mod in pcode_modules:
    print(f"模块: {mod['module_name']} - {len(mod['lines'])} 行 P-Code")

# 5. 导出格式化的 Markdown 检查摘要
markdown_summary = vba_insight.inspect_file_markdown("suspicious.xlsm")
print(markdown_summary)

# 6. 针对纯 VBA 源码模块进行语法分析
vba_sources = [
    ("Module1.bas", "Public Sub Test()\n    MsgBox \"Hello\"\nEnd Sub\n")
]
ast_report = vba_insight.analyze_sources(vba_sources)
print("解析模块数量:", len(ast_report["project"]["modules"]))
```

---

### 3. Node.js & TypeScript API (`npm install vba-insight`)

基于 N-API 封装的原生扩展，附带完整的 TypeScript 类型定义文件。

```typescript
import * as fs from 'node:fs';
import {
  inspectMacroFileJson,
  inspectMacroFileSarif,
  inspectMacroFileMarkdown,
  disasmMacroFileJson,
  analyzeSourcesJson,
} from 'vba-insight';

// 1. 读取宏文件至 Buffer
const fileBuffer = fs.readFileSync('suspicious.xlsm');

// 2. 执行宏容器全面审计（返回 JSON 字符串）
const rawJson = inspectMacroFileJson(fileBuffer, true);
const report = JSON.parse(rawJson);

console.log('项目名称:', report.project_name);
if (report.stomping?.has_stomping) {
  console.error(`[!] 检测到 VBA Stomping！级别: ${report.stomping.overall_severity}`);
  for (const finding of report.stomping.project_findings ?? []) {
    console.error(`  - [${finding.rule_id}] ${finding.description}`);
  }
  for (const mod of report.stomping.modules ?? []) {
    if (mod.is_stomped) {
      console.error(`  模块 ${mod.module_name}:`);
      for (const finding of mod.findings ?? []) {
        console.error(`    - [${finding.rule_id}] ${finding.description}`);
      }
    }
  }
}

// 检查危险的工作表单元格威胁（DDE, XLM, WEBSERVICE 等）
const cellThreats = report.analysis?.workbook_structure?.cell_threats ?? [];
for (const threat of cellThreats) {
  console.warn(`  - [${threat.rule_id}] ${threat.coordinate}: ${threat.threat_kind} (${threat.formula})`);
}

// 3. 导出用于 CI 代码扫描的 SARIF v2.1.0 报告
const sarifReport = inspectMacroFileSarif(fileBuffer, 'suspicious.xlsm');
fs.writeFileSync('macro-scan.sarif', sarifReport);

// 4. 反编译提取编译后 P-Code 指令
const pcodeJson = disasmMacroFileJson(fileBuffer);
console.log('P-Code 模块数:', JSON.parse(pcodeJson).length);

// 5. 生成 GitHub 风格 Markdown 审计报告
const markdownReport = inspectMacroFileMarkdown(fileBuffer);
console.log(markdownReport);

// 6. 纯 VBA 源码静态分析
const sourceUnits = [
  {
    name: 'Module1.bas',
    text: 'Sub Auto_Open()\n    Shell "powershell -enc ...", 0\nEnd Sub',
  },
];
const analysisJson = analyzeSourcesJson(sourceUnits, true);
const parsedAnalysis = JSON.parse(analysisJson);
console.log('静态分析完成。是否执行代码:', parsedAnalysis.project.code_executed); // 始终为 false
```

---

## 威胁检测引擎

### 1. VBA Stomping 与篡改检测规则

内置 10 项专业检测规则，深度比对源代码文本与编译后 P-Code 字节码差异：

| 规则编号 | 违规类型 | 严重程度 | 规则描述与检测逻辑 |
|---|---|:---:|---|
| `VBA-STOMP-001` | `SourcePurged` | **Critical** | VBA 源代码被完全清除（Purged），但编译后的有效 P-Code 字节码依然存在并可执行。 |
| `VBA-STOMP-002` | `ProcedureHiddenInPCode` | **High** | 某个过程仅存在于编译后 P-Code 字节码中，但在解压后的 VBA 源代码文本中完全隐匿。 |
| `VBA-STOMP-003` | `SuspiciousLiteralInPCode` | **High** | 可疑字符串字面量（URL、IPv4 地址、脚本命令或可执行程序名）存在于 P-Code 中，但在源码中被抹除。 |
| `VBA-STOMP-004` | `SensitiveCallInPCode` | **Critical** | 危险系统 API 或内存注入调用（例如 `VirtualAlloc`、`WriteProcessMemory`、`CreateRemoteThread`、`InternetOpen` 等）在 P-Code 中被调用，但源代码中不可见。 |
| `VBA-STOMP-005` | `LineCountDiscrepancy` | **Medium** | 源代码物理行数与编译后 P-Code 行数存在显著异常差异。 |
| `VBA-STOMP-006` | `ProcedureMissingInPCode` | **Low** | 源代码中声明的过程在 P-Code 字节码流中缺失。 |
| `VBA-STOMP-007` | `PerformanceCachePurged` | **Medium** | 源代码依然存在，但编译后 P-Code 性能缓存被蓄意抹除（VBA Purging 规避手法）。 |
| `VBA-STOMP-008` | `HiddenGuiModule` | **High** | 模块在 `dir` 流中声明，但在 `PROJECT` 清单中被剔除，在 Office VBA IDE 视图中不可见（Evil Clippy 手法）。 |
| `VBA-STOMP-009` | `ProjectLockedOrUnviewable` | **Low** | VBA 项目包含保护/锁定属性（`CMG`、`DPB`、`GC`），导致在常规 Office VBA IDE 中无法查看代码。 |
| `VBA-STOMP-010` | `SourceCorruptedWithValidPCode` | **Critical** | 模块源代码容器在 MS-OVBA 解压时损坏，但有效的已编译 P-Code 仍可正常执行。 |

### 2. 容器包与工作表单元格威胁扫描器

`vba-insight` 针对容器包结构（OOXML 关系、内嵌 OLE 部件）、工作簿公式、定义名及工作表元数据进行 94 项专业安全规则筛查：

| 规则编号 | 违规类型 | 严重程度 | 规则描述与检测逻辑 |
|---|---|:---:|---|
| `VBA-CELL-001` | `DDEExecutionFormula` | **Critical** | 工作表单元格或定义名称包含通过动态数据交换（DDE）启动外部进程的公式。 |
| `VBA-CELL-002` | `XlmMacroExecutionFormula` | **Critical** | 工作表单元格或定义名称包含 Excel 4.0（XLM）宏执行函数（如 `EXEC`, `CALL`, `REGISTER` 等）。 |
| `VBA-CELL-003` | `RemoteWorkbookLink` | **High** | 单元格公式引用远端外部工作簿路径（UNC 共享 `\\server\share` 或 HTTP/HTTPS）。 |
| `VBA-CELL-004` | `DataExfiltrationFormula` | **Medium** | 单元格使用 `=WEBSERVICE(...)` 或 `FILTERXML` 公式，可隐蔽将敏感数据发送至外部。 |
| `VBA-CELL-005` | `SuspiciousDownloadHyperlink` | **High** | 工作表 `=HYPERLINK(...)` 公式指向可执行文件、脚本、压缩包或伪协议（`.exe`, `.bat`, `search-ms:` 等）。 |
| `VBA-CELL-006` | `AutoExecDefinedName` | **High** | 工作簿定义名称（如 `Auto_Open`、`_xlnm.Auto_Open`、`Auto_Close`）触发宏自动执行。 |
| `VBA-CELL-007` | `VeryHiddenWorksheet` | **Low** | 工作表被标记为 `state="veryHidden"`，在标准 Excel 用户界面中不可见，通常用于隐匿恶意载荷。 |
| `VBA-CELL-008` | `XlmMacroSheetPresent` | **Critical** | 工作簿包含容易被恶意利用的传统 Excel 4.0 宏工作表。 |
| `VBA-CELL-009` | `DeobfuscatedThreatFormula` | **Critical** | 公式混淆（`CHAR`, `CONCATENATE`, 字符串替换等）动态解析为可执行文件、命令行或 DDE 载荷。 |
| `VBA-CELL-010` | `RemoteTemplateInjection` | **Critical** | 关系文件引用外部远程模板（`attachedTemplate`，HTTP/HTTPS/SMB），加载恶意远程 dotm 载荷。 |
| `VBA-CELL-011` | `EmbeddedOlePackage` | **High** | OOXML 容器包在 `/embeddings/` 中包含嵌入式 OLE 二进制或包装载荷（如 CVE-2017-11882 公式编辑器利用程序）。 |
| `VBA-CELL-012` | `ExternalOleObject` | **High** | 关系文件引用外部 OLE 对象（`oleObject`，HTTP/HTTPS/SMB），实现远程 Moniker 或漏洞利用。 |
| `VBA-CELL-013` | `ActiveXControlPresent` | **Medium** | OOXML 容器包在 `/activex/` 中包含嵌入式 ActiveX 控件，可用于无宏利用。 |
| `VBA-CELL-014` | `ExternalSubdocumentReference` | **High** | 关系文件引用外部子文档或框架（`subDocument` / `frame`，HTTP/HTTPS/SMB）。 |
| `VBA-CELL-015` | `SuspiciousPrinterSettings` | **High** | 打印机设置（`printerSettings*.bin`）包含外部 UNC 路径（`\\host\share`）、远程 URL 或命令执行触发器（CVE-2023-36884 / Storm-0978）。 |
| `VBA-CELL-016` | `CustomXmlPayloadSmuggling` | **High** | 自定义 XML 部件（`/customXml/*.xml`）中走私 Base64 编码 PE 可执行文件、XXE 实体注入或脚本/HTML 载荷。 |
| `VBA-CELL-017` | `SuspiciousProtocolHandler` | **Critical** | 关系目标引用危险协议处理程序（`ms-msdt:` / Follina CVE-2022-30190、`search-ms:`、`ms-appinstaller:`、`mhtml:`、`javascript:`、`vbscript:` 等）。 |
| `VBA-CELL-018` | `SuspiciousDrawingAction` | **High** | 绘图形状、幻灯片触发器或 VML 按钮动作定义了鼠标悬停执行（`<a:hlinkHover>`）、宏动作链接（`ppaction://macro`、`<x:FmlaMacro>`）或危险可执行文件目标。 |
| `VBA-CELL-019` | `ExternalDataConnection` | **High** | 外部数据连接（`/xl/connections.xml`、查询表或邮件合并）包含用于 NTLM 凭据窃取的 UNC 路径、远程 Web 查询或命令注入（`xp_cmdshell`、PowerShell 等）。 |
| `VBA-CELL-020` | `RealTimeDataExecution` | **Critical** | 单元格公式或定义名称包含 `=RTD(...)`，试图调用外部 COM 自动化服务（`WScript.Shell`, `Shell.Application` 等）或远端 DCOM 服务器执行命令或窃取 NTLM 凭据。 |
| `VBA-CELL-021` | `SuspiciousSvgVector` | **High** | 容器包含的内嵌 SVG 矢量图（`/media/*.svg`）携带恶意脚本（`<script>`）、内联事件处理程序、XML 外部实体（XXE）或危险伪协议。 |
| `VBA-CELL-022` | `TamperedVbaProjectSignature` | **High** | VBA 项目数字签名二进制文件（`vbaProjectSignature*.bin`）被截断、损坏或存在孤立签名关系引用（数字签名剥离与伪造逃避）。 |
| `VBA-CELL-023` | `WordFieldCodeExecution` | **Critical** | Word 文档部件（`word/document.xml`、页眉、页脚等）包含可疑域代码（`w:fldSimple`、`w:instrText`），通过 DDE/DDEAUTO 执行外部命令、通过 INCLUDETEXT/LINK 远程注入文档或通过 UNC 路径诱导窃取凭据。 |
| `VBA-CELL-024` | `PowerPointSlideAction` | **Critical** | PowerPoint 演示文稿部件（`ppt/slides/slide*.xml`、版式、母版）包含单击或鼠标悬停动作触发器（`ppaction://program`、`<a:hlinkHover>`），执行外部程序、调用宏或链接至可执行文件。 |
| `VBA-CELL-025` | `SuspiciousAltChunkPayload` | **Critical** | Word 替代格式导入块（`aFChunk`）关系或部件（HTML、MHT、RTF、BIN）引用外部远程模板，或携带走私 HTML 脚本、内嵌 RTF 漏洞代码或 PE 二进制载荷。 |
| `VBA-CELL-026` | `CustomUiRibbonCallback` | **Critical** | Custom UI 功能区 XML（`customUI/customUI*.xml`）注册文档打开自动运行回调（`onLoad`）或控件宏操作触发器（`onAction`）。 |
| `VBA-CELL-027` | `LegacyDialogSheetMacro` | **High** | 传统 Excel 5.0/95 对话框工作表（`xl/dialogsheets/sheet*.xml`）内嵌控件宏绑定（`<x:FmlaMacro>`）或自动弹出钓鱼诱饵对话框。 |
| `VBA-CELL-028` | `ContentTypeAnomaly` | **Critical** | 容器清单 `[Content_Types].xml` 包含路径遍历部件名（`/../`）、危险可执行 MIME 类型（`application/x-msdownload`, `application/hta`）或扩展名伪装走私（将 `vbaProject` 伪装为图像或非宏扩展名）。 |
| `VBA-CELL-029` | `ExternalLinkTargetAnomaly` | **Critical** | 外部链接缓存（`xl/externalLinks/externalLink*.xml`）或关系目标引用远程 UNC 路径、危险可执行文件、漏洞利用协议，或注册隐蔽的 DDE/OLE 服务器链接。 |
| `VBA-CELL-030` | `WebSettingsScriptOrReload` | **Critical** | 文档 Web 设置（`word/webSettings.xml`）在 Web 视图中注入远程框架集、框架重新加载触发器或漏洞利用协议目标。 |
| `VBA-CELL-031` | `WorkbookProtectionEvasion` | **High** | 工作簿保护（`xl/workbook.xml`）锁定结构（`lockStructure="1"`）同时隐匿 veryHidden 工作表，或应用异常密码保护哈希妨碍安全审查。 |
| `VBA-CELL-032` | `SmuggledContainerPayload` | **Critical** | 容器包内包含走私的可执行二进制或脚本（`.exe`, `.dll`, `.sys`, `.scr`, `.bat`, `.cmd`, `.ps1`, `.vbs`, `.hta`, `.lnk`, `.iso` 等）、伪装在非可执行扩展名下的 PE 头（`MZ`/`PE`）、Windows Shell Link 快捷方式、ELF/Mach-O 或者是暂存脚本文件。 |
| `VBA-CELL-033` | `WorksheetViewEvasion` | **High** | 工作表视图定义（`xl/worksheets/sheet*.xml`）在隐藏列（`hidden="1"` / `width="0"`）、隐藏行（`hidden="1"` / `ht="0"`）、极端视口偏移（`topLeftCell`）或隐藏行列标题及网格线中隐匿公式载荷。 |
| `VBA-CELL-034` | `ActiveXObjectDeclarationAnomaly` | **Critical** | ActiveX XML 声明（`/activeX/activeX*.xml`）包含武器化 CLSID（`WScript.Shell`, 公式编辑器 3.0, `XMLHTTP`, `Shell.Explorer`, `Scriptlet.TypeLib`, `ADODB.Stream`）、远程 UNC 路径、可执行文件引用或危险协议方案。 |
| `VBA-CELL-035` | `GlossaryDocumentAnomaly` | **Critical** | Word 词汇表/常用文档部件（`word/glossary/document.xml`, `settings.xml`）或关系包含远程模板注入（`attachedTemplate`）、危险协议方案（`ms-msdt:`, `search-ms:`）、命令域代码（`DDE`, `EXEC`）、远程子文档引用或 AltChunk 载荷走私。 |
| `VBA-CELL-036` | `EmbeddedFontObfuscationOrSmuggling` | **Critical** | 内嵌字体流（`.odttf`, `.ttf`, `.woff`）或字体关系包含走私可执行二进制（`MZ`/`PE`）、Windows 快捷方式（`.lnk`）、脚本，或通过反转 GUID XOR 混淆隐匿 PE 头的 ODTTF 字体。 |
| `VBA-CELL-037` | `DigitalInkDefinitionAnomaly` | **Critical** | 数字墨迹定义部件（`xl/ink/`, `word/ink/`, `ppt/ink/`, `.bin`, `.isf`）或关系包含交互式单击/悬停触发器（`<a:hlinkClick>`, `<a:hlinkHover>`, `ppaction://program`）、UNC 凭据窃取、武器化 CLSID 或走私可执行二进制。 |
| `VBA-CELL-038` | `DocumentPropertyPayloadSmuggling` | **Critical** | 文档属性部件（`docProps/core.xml`, `docProps/app.xml`, `docProps/custom.xml`）包含走私的 Base64 编码 PE 可执行二进制、命令行载荷（`powershell`, `cmd.exe`, `wscript.exe`, `mshta`, `rundll32`, `certutil`）、危险 URI 协议或诱导 NTLM 凭据窃取的远程 UNC 路径。 |
| `VBA-CELL-039` | `WebExtensionOrTaskpaneAnomaly` | **Critical** | Office Web 外接程序与任务窗格部件（`word/webextensions/`, `xl/webextensions/`, `ppt/webextensions/`, `word/taskpanes/`, `xl/taskpanes/`, `ppt/taskpanes/`）或关系包含自动显示触发器（`canAutoShow="1"`, `visibility="visible"`）、远端 Web 目标、危险 URI 协议或支持无宏执行的内嵌脚本。 |
| `VBA-CELL-040` | `PivotCacheDataConnectionAnomaly` | **Critical** | 工作簿透视表缓存定义（`xl/pivotCache/pivotCacheDefinition*.xml`）或关系包含用于 NTLM 凭据窃取的外部 UNC 连接路径、数据库命令注入（`xp_cmdshell`, `sp_OACreate`, `OPENROWSET`）或危险 URI 协议。 |
| `VBA-CELL-041` | `MetafileExploitOrPayloadSmuggling` | **Critical** | Windows 图元文件图形部件（`*.wmf`, `*.emf`, `/media/`）包含 CVE-2005-4560 记录（`META_SETABORTPROC`）、伪装在图像中的 PE 可执行文件头（`MZ`/`PE`）、Windows 快捷方式（`.lnk`）、Shell 命令执行载荷或远程 UNC 路径。 |
| `VBA-CELL-042` | `XsltTransformOrScriptInjection` | **Critical** | XML 部件或样式表（`styles.xml`, `settings.xml`, `customXml/`, `*.xsl`, `*.xslt`）包含可执行 `<msxsl:script>` 元素（`language="JScript"` / `"VBScript"`）、远程 `<w:saveThroughXslt>` 转换目标、危险 XPath `document()` SSRF / NTLM 诱导函数或 Windows Shell 自动化对象。 |
| `VBA-CELL-043` | `RelationshipTargetCloakingOrEvasion` | **Critical** | 关系文件（`*.rels`）包含规避字符（空字节 `%00` / `\0` 或 Unicode 双向覆盖字符 `\u{202E}`）、百分号编码危险 URI 协议（`m%73-m%73dt:`, `s%65arch-ms:`, `m%68tml:`）或本地 IPC 命名管道 / 回环诱导目标（`\\.\pipe\`, `\\127.0.0.1\`, `\\localhost\`）。 |
| `VBA-CELL-044` | `SmartArtOrDiagramPayloadAnomaly` | **Critical** | SmartArt / 图表部件（`*/diagrams/*.xml`、`data*.xml`、`layout*.xml`、`drawing*.xml`）或关系包含交互式动作触发器（`<dgm:hlinkClick>`、`<a:hlinkHover>`、`ppaction://program`）、危险 URI 协议（`ms-msdt:`、`search-ms:`、`mhtml:`）、远程 UNC 路径或伪装的 PE 可执行文件头 / Shell 执行命令。 |
| `VBA-CELL-045` | `MailMergeDataSourceOrCoercionAnomaly` | **Critical** | Word 邮件合并设置（`word/settings.xml`）或关系包含用于 NTLM 凭据诱导的远程 UNC 连接字符串（`<w:connectString>`）、数据库命令注入（`xp_cmdshell`、`sp_OACreate`）、自动合并配置或指向危险可执行/脚本文件（`.iqy`、`.hta`、`.vbs`、`.bat`、`.ps1`、`.exe`）的外部关系。 |
| `VBA-CELL-046` | `QueryTableOrExternalQueryAnomaly` | **Critical** | Excel QueryTable 定义（`xl/queryTables/queryTable*.xml`）或关系配置自动刷新（`refreshOnLoad="1"`、`autoRefresh="1"`）、外部 Web 查询文件（`.iqy`、`.dqy`）、NTLM 凭据诱导 UNC 路径、数据库命令执行（`xp_cmdshell`）或环境变量外传标记（`%USERNAME%`）。 |
| `VBA-CELL-047` | `PowerQueryFormulaOrMashupAnomaly` | **Critical** | Excel Power Query 定义（`xl/powerQuery/powerQuery.xml`）、Data Mashup 部件（`customXml/`、`customData/`）或 M 语言查询包含通过 `Web.Page` 执行任意脚本/代码、通过 `Web.Contents` 进行远程数据外传/载荷下载、诱导 NTLM 凭据窃取的 UNC 远程路径（`File.Contents` 等）、走私的 PE 可执行二进制，或数据库命令执行（`xp_cmdshell`、`OPENROWSET`）。 |
| `VBA-CELL-048` | `PackageMonikerOrActivationAnomaly` | **Critical** | 内嵌 OLE 对象部件、绘图、幻灯片或关系配置了危险 Moniker URI / 协议处理程序（`moniker:`、`file:`、`script:`、`composite:`、`ms-msdt:`、`search-ms:`、`ms-appinstaller:`）、静默自动激活标记（`UpdateMode="Always"`、`autoUpdate="1"`、`autoActivate="1"`）、可执行文件图标伪装欺骗（`DrawAspect="Icon"` 配合可执行扩展名或 `ProgID="Package"`），或武器化 Packager/Moniker CLSID。 |
| `VBA-CELL-049` | `NamespaceCloakingOrSchemaSpoofingAnomaly` | **Critical** | OOXML XML 部件或关系包含诱导 NTLM 凭据窃取的 UNC 命名空间声明（`xmlns:...="\\host\share..."`）或 `xsi:schemaLocation` 诱导目标、引发 XXE 外部实体注入的 DTD / 外部实体声明（`<!DOCTYPE`、`<!ENTITY %`），或伪装标准 Office 架构的西里尔/Unicode 同形文字或零宽空格。 |
| `VBA-CELL-050` | `SlicerOrTimelineCacheAnomaly` | **Critical** | Excel 切片器或日程表定义（`xl/slicers/`、`xl/timelines/`）或关系中包含用于强制 NTLM 身份验证窃取的高危远程 UNC 路径、危险利用协议（`ms-msdt:`、`search-ms:`、`mhtml:`、`javascript:`、`powershell:`）、可执行文件/脚本目标（`.exe`、`.bat`、`.vbs`、`.ps1`、`.hta`）、数据库命令执行（`xp_cmdshell`、`sp_OACreate`、`OPENROWSET`）或环境变量外发窃取令牌（`%USERNAME%`）。 |
| `VBA-CELL-051` | `BibliographyOrCitationAnomaly` | **Critical** | Word 书目与引文定义（`word/bibliography/sources.xml`、`customXml/`）中包含诱导 NTLM 凭据窃取的远程 UNC 路径、危险利用协议（`ms-msdt:`、`search-ms:`、`ms-appinstaller:`、`mhtml:`、`powershell:`）、Shell 执行命令（`powershell`、`cmd.exe`、`wscript.exe`、`cscript.exe`、`mshta`、`rundll32`、`certutil`）或走私的 Windows PE 二进制文件。 |
| `VBA-CELL-052` | `CustomXmlDataBindingOrXPathAnomaly` | **Critical** | 结构化文档标记（SDT）或自定义 XML 数据绑定（`<w:dataBinding>`、`<m:dataBinding>`、`<p:dataBinding>`）中包含触发 SSRF 或 NTLM 凭据窃取的外部文档解析函数（`document()`、`doc()`）的 XPath 查询、数据库/Shell 命令注入，或在 `prefixMappings` / `storeItemID` 中声明的远程 UNC / 危险协议命名空间。 |
| `VBA-CELL-053` | `XmlMapsOrSchemaDefinitionAnomaly` | **Critical** | Excel XML 映射定义（`xl/xmlMaps.xml`）、表格 XML 列映射（`xl/tables/table*.xml`）或关系中包含用于强制 NTLM 身份验证窃取的高危远程 UNC 路径、危险利用协议（`ms-msdt:`、`search-ms:`、`ms-appinstaller:`、`mhtml:`、`powershell:`）、XXE DTD/外部实体声明、走私的 Windows PE 二进制文件、Shell 执行命令（`powershell`、`cmd.exe`、`wscript.exe`）或表格列 XPath 外部文档解析函数（`document()`、`doc()`）。 |
| `VBA-CELL-054` | `CommentAnnotationOrAuthorAnomaly` | **Critical** | 文档批注与新版批注部件（`word/comments*.xml`、`ppt/comments/*.xml`、`ppt/modernComments/*.xml`、`xl/comments*.xml`、`xl/threadedComments/*.xml`）或关系中包含诱导 NTLM 凭据窃取的远程 UNC 路径、危险利用协议、走私的 Windows PE 二进制文件、Shell 执行命令（`powershell`、`cmd.exe`、`mshta`、`rundll32`）或可执行载荷目标（`.exe`、`.bat`、`.ps1`、`.hta`、`.lnk`）。 |
| `VBA-CELL-055` | `ThemeFontOrEffectCoercionAnomaly` | **Critical** | Office 主题部件（`*/theme/theme*.xml`、`themeOverride*.xml`）或关系中，字体 typeface 声明（`<a:latin typeface="\\..."/>`、`<a:ea typeface="\\..."/>`、`<a:cs typeface="\\..."/>`）包含诱导 NTLM 凭据窃取或字体引擎漏洞利用的远程 UNC 路径、危险利用协议、外部远程主题/模板引用或走私的 Windows PE 二进制文件。 |
| `VBA-CELL-056` | `CustomXmlPropertiesOrItemSchemaAnomaly` | **Critical** | 自定义 XML 属性部件（`customXml/itemProps*.xml`）、数据部件或关系中，架构引用声明（`ds:schemaRef`、`targetNamespace`、`schemaRef`）包含诱导 NTLM 凭据窃取的远程 UNC 路径、危险利用协议（`ms-msdt:`、`search-ms:`、`ms-appinstaller:`、`mhtml:`、`powershell:`）、外部可执行文件引用或走私的 Windows PE 二进制文件。 |
| `VBA-CELL-057` | `VbaDataStreamOrProjectRelsAnomaly` | **Critical** | VBA 项目关系部件（`xl/_rels/vbaProject.bin.rels`、`vbaProjectSignature*.bin.rels`）或补充 VBA 数据流（`xl/vbaData.xml`）包含指向远程 UNC 路径或二进制文件的外部关系、危险利用协议、走私的 Windows PE 二进制文件或 Shell 执行命令。 |
| `VBA-CELL-058` | `WordGlossaryOrBuildingBlocksRelsAnomaly` | **Critical** | Word 词汇表与构建基块定义（`word/glossary/settings.xml`、`document.xml`）或关系中，包含通过 `attachedTemplate` 注入外部模板、诱导 NTLM 凭据窃取的远程 UNC 路径、危险利用协议、外部可执行文件引用或走私的 Windows PE 二进制文件。 |
| `VBA-CELL-059` | `WordDocVariablesOrNotesAnomaly` | **Critical** | Word 文档变量（`word/settings.xml` `<w:docVars>`）、脚注（`word/footnotes.xml`）或尾注（`word/endnotes.xml`）中包含走私的 Windows PE 二进制文件、Shell 执行命令、危险利用协议（`ms-msdt:`、`search-ms:`、`mhtml:`、`powershell:`）、诱导 NTLM 凭据窃取的远程 UNC 路径或指向可执行/脚本载荷的外部关系。 |
| `VBA-CELL-060` | `PowerPointTagsOrMastersAnomaly` | **Critical** | PowerPoint 可编程标签（`ppt/tags/tag*.xml`）、演示文稿关系、字体表、讲义母版或备注母版中包含走私的 Windows PE 二进制文件、Shell 执行命令、危险利用协议、诱导 NTLM 凭据窃取的远程 UNC 路径或外部可执行文件引用。 |
| `VBA-CELL-061` | `ScenarioManagerOrConsolidationAnomaly` | **Critical** | Excel 方案管理器定义（`xl/scenarios/`、`<scenarios>`）、方案输入单元格或工作簿数据合并引用中包含隐蔽 DDE 执行命令、Excel 4.0 (XLM) 宏执行函数（`EXEC(`、`CALL(`）、Shell 执行命令、走私的 Windows PE 二进制文件或合并数据中诱导 NTLM 凭据窃取的远程 UNC 工作簿路径。 |
| `VBA-CELL-062` | `PowerPointAnimationOrTimeNodeAnomaly` | **Critical** | PowerPoint 幻灯片动画时间节点（`ppt/slides/slide*.xml`）、媒体节点（`<p:cMediaNode>`、`<p:media>`）或幻灯片关系包含 Shell 执行命令触发器（`<p:cmd>`）、诱导 NTLM 凭据窃取的远程 UNC 媒体流、危险利用协议或走私的 Windows PE 二进制文件。 |
| `VBA-CELL-063` | `WordHeaderFooterOrWatermarkAnomaly` | **Critical** | Word 页眉/页脚（`word/header*.xml`、`word/footer*.xml`）、VML 水印（`<v:imagedata src="\\..."/>`）或关系中包含诱导 NTLM 凭据窃取的远程 UNC 路径、危险利用协议、可执行/脚本目标、Shell 执行命令或走私的 PE 二进制文件。 |
| `VBA-CELL-064` | `ExcelDataModelOrFormulaCacheAnomaly` | **Critical** | Excel DataModel 数据模型定义（`xl/model/dataModel.xml`）或工作表共享公式缓存（`<f t="shared">`）中包含诱导 NTLM 凭据窃取的远程 UNC 连接、数据库命令执行字符串（`xp_cmdshell`）、XXE 实体注入、隐蔽 DDE 命令执行或走私的 PE 二进制文件。 |
| `VBA-CELL-065` | `ExcelPivotCacheOrDefinitionAnomaly` | **Critical** | Excel PivotCache 定义（`xl/pivotCache/pivotCacheDefinition*.xml`）、记录（`pivotCacheRecords*.xml`）或关系中包含诱导 NTLM 凭据窃取的远程 UNC 连接、数据库命令执行存储过程（`xp_cmdshell`）、危险利用协议、隐蔽 DDE 执行命令或走私的 PE 二进制文件。 |
| `VBA-CELL-066` | `WordOrPowerPointEmbeddedPackageAnomaly` | **Critical** | Word 或 PowerPoint 内嵌包装对象、OLE 二进制流（`word/embeddings/*.bin`、`ppt/embeddings/*.bin`）或自动激活指令中伪装走私的 Windows PE 独立执行文件（验证 `MZ`/`PE\0\0` 头）、暂存脚本文件、远程 UNC 路径、危险利用协议或自动激活 OLE 处理程序。 |
| `VBA-CELL-067` | `ExcelExternalBookOrSheetPathAnomaly` | **Critical** | Excel 外部链接定义（`xl/externalLinks/externalLink*.xml`）、关系部件或关联工作簿缓存包含打开时诱导 NTLM 凭据窃取的远程 UNC 工作簿路径、危险利用协议、定义名称中的隐蔽 DDE 执行或走私的 PE 二进制文件。 |
| `VBA-CELL-068` | `ActiveXBinaryStorageOrPropertyStreamAnomaly` | **Critical** | ActiveX 二进制属性持久化流（`xl/activeX/activeX*.bin`、`word/activeX/activeX*.bin`、`ppt/activeX/activeX*.bin`）或属性存储流中伪装走私 Windows PE 可执行二进制文件（验证 `MZ`/`PE\0\0` 头）、暂存脚本文件、诱导 NTLM 凭据窃取的远程 UNC 路径、危险利用协议或武器化 CLSID。 |
| `VBA-CELL-069` | `XmlDigitalSignatureOrOriginPartAnomaly` | **Critical** | 容器包数字签名部件（`_xmlsignatures/origin.sigs`、`_xmlsignatures/sig*.xml`、`package.sigs`）配置诱导 NTLM 凭据窃取的远程 UNC 摘要/引用 URI、危险利用协议、XSLT 转换执行过滤器、XXE 外部实体声明或走私的 PE 二进制文件。 |
| `VBA-CELL-070` | `ExcelControlPropertiesOrFormActionAnomaly` | **Critical** | Excel 表单控件属性（`xl/ctrlProps/ctrlProp*.xml`）或传统绘图表单动作关联包含隐蔽 DDE 执行命令、Excel 4.0 (XLM) 宏执行函数、远程 UNC 工作簿路径、危险利用协议或暂存 Shell 命令的单元格公式。 |
| `VBA-CELL-071` | `PowerPointMediaTrackOrActionAnomaly` | **Critical** | PowerPoint 媒体部件（`ppt/media/*`）、幻灯片媒体节点（`<p:cMediaNode>`）或时间触发器伪装 Windows PE 可执行文件、ELF/Mach-O 二进制文件、LNK 快捷方式、暂存脚本、强制 NTLM 凭据窃取的远程 UNC 媒体流或危险利用协议。 |
| `VBA-CELL-072` | `ExcelTableOrSlicerNativeConnectionAnomaly` | **Critical** | Excel 表格定义（`xl/tables/table*.xml`）、切片器（`xl/slicers/slicer*.xml`）或日程表缓存配置诱导 NTLM 凭据窃取的远程 UNC 数据连接、切片器标题或公式中的隐蔽 DDE 执行、数据库命令执行存储过程或走私的 PE 二进制文件。 |
| `VBA-CELL-073` | `WordMailMergeHeaderSourceOrRecipientAnomaly` | **Critical** | Word 邮件合并设置（`word/settings.xml` `<w:mailMerge>`）或收件人数据缓存配置诱导 NTLM 凭据窃取的远程 UNC 表头源、危险利用协议、武器化外部关系目标或 SQL 查询命令注入。 |
| `VBA-CELL-074` | `PowerPointSlideShowOrPresentationPropsAnomaly` | **Critical** | PowerPoint 演示文稿属性（`ppt/presProps.xml`）、视图属性（`ppt/viewProps.xml`）或演示文稿 XML 配置诱导 NTLM 凭据窃取的远程 UNC 路径、危险利用协议、全屏循环/广播结合的展台模式 UI 锁定，或暂存 Shell 执行命令。 |
| `VBA-CELL-075` | `ExcelThreadedCommentOrPersonAnomaly` | **Critical** | Excel 现代线索化批注部件（`xl/threadedComments/threadedComment*.xml`）、人员缓存（`xl/persons/person*.xml`）或作者元数据中包含隐蔽 DDE 执行公式（`=cmd|`, `=powershell|`）、诱导 NTLM 凭据窃取的远程 UNC 提及路径、危险利用协议或暂存 Shell 执行命令。 |
| `VBA-CELL-076` | `OfficeThemeOverrideOrFormatSchemeAnomaly` | **Critical** | Office 主题覆盖定义（`xl/theme/themeOverride*.xml`、`word/theme/themeOverride*.xml`、`ppt/theme/themeOverride*.xml`）、格式方案或主题关系配置诱导 NTLM 凭据窃取的远程 UNC 字体/主题资源、危险利用协议、武器化外部关系目标或暂存 Shell 命令。 |
| `VBA-CELL-077` | `PowerPointSyncOrCommentAuthorsAnomaly` | **Critical** | PowerPoint 批注作者信息（`ppt/commentAuthors.xml`）、同步信息（`ppt/syncInfo.xml`）或幻灯片同步部件配置诱导 NTLM 凭据窃取的远程 UNC 资源、隐匿 DDE 命令公式、危险利用协议或暂存 Shell 命令。 |
| `VBA-CELL-078` | `WordKeyMapOrCustomizationAnomaly` | **Critical** | Word 键盘映射定义（`word/keyMap.xml`）或自定义部件（`word/customizations.xml`、`word/customizations.bin`）配置绑定至恶意宏或 Shell 命令的快捷键、诱导 NTLM 凭据窃取的远程 UNC 引用、危险利用协议或武器化外部关系目标。 |
| `VBA-CELL-079` | `ExcelWebPublishingOrSparklineAnomaly` | **Critical** | Excel Web 发布配置（`xl/webPublishing.xml`）、发布项目（`xl/webPublishItems.xml`）或迷你图组配置诱导静默数据外发或 NTLM 凭据窃取的远程 UNC 发布目标、危险利用协议或暂存 Shell 命令。 |
| `VBA-CELL-080` | `PowerPointHandoutOrNotesMasterAnomaly` | **Critical** | PowerPoint 讲义母版（`ppt/handoutMasters/handoutMaster*.xml`）、备注母版（`ppt/notesMasters/notesMaster*.xml`）或关系部件配置诱导 NTLM 凭据窃取的远程 UNC 资源、隐匿 DDE 命令公式、危险利用协议或暂存 Shell 命令。 |
| `VBA-CELL-081` | `WordGlossarySettingsOrFontTableAnomaly` | **Critical** | Word 词汇表设置（`word/glossary/settings.xml`）、Web 设置（`word/glossary/webSettings.xml`）或字体表（`word/glossary/fontTable.xml`）配置诱导 NTLM 凭据窃取的远程 UNC 引用、宏自动执行钩子、危险利用协议或武器化外部关系目标。 |
| `VBA-CELL-082` | `ExcelCustomPropertyOrCustomDataAnomaly` | **Critical** | Excel 自定义属性部件（`xl/customProperty*.bin`）、自定义数据（`xl/customData/customData*.xml`）或数据模型二进制流配置诱导 NTLM 凭据窃取的远程 UNC 资源、危险利用协议、序列化 .NET 二进制格式化程序标记或暂存 Shell 命令。 |
| `VBA-CELL-083` | `WordSubDocumentOrMasterDocumentAnomaly` | **Critical** | Word 子文档部件（`word/subDocument*.xml`）、主文档或子文档关系配置诱导 NTLM 凭据窃取的远程 UNC 资源路径、危险利用协议、暂存 Shell 命令或走私的 Windows PE 二进制文件。 |
| `VBA-CELL-084` | `PowerPointFontTableOrEmbeddedFontAnomaly` | **Critical** | PowerPoint 字体表部件（`ppt/fontTable.xml`）、内嵌字体流文件（`ppt/fonts/*`）或字体关系配置诱导 NTLM 凭据窃取的远程 UNC 资源、危险利用协议、暂存 Shell 命令或走私的 Windows PE 伪装二进制。 |
| `VBA-CELL-085` | `ExcelQueryTableOrDataFeedAnomaly` | **Critical** | Excel 查询表部件（`xl/queryTables/queryTable*.xml`）、数据源连接部件（`xl/dataFeeds/dataFeed*.xml`）或查询关系配置诱导 NTLM 凭据窃取的远程 UNC 目标、危险利用协议、数据库命令执行存储过程、隐匿 DDE 命令公式或暂存 Shell 命令。 |
| `VBA-CELL-086` | `PowerPointSlideGuideOrGridAnomaly` | **Critical** | PowerPoint 幻灯片参考线部件（`ppt/viewProps.xml` `<p:guide>`、`ppt/slideGuides/*`、`ppt/guides/*`）、视图属性或参考线关系配置诱导 NTLM 凭据窃取的远程 UNC 资源路径、危险利用协议、暂存 Shell 命令或走私的 Windows PE 二进制文件。 |
| `VBA-CELL-087` | `WordMailMergeHeaderFilterOrRecipientItemAnomaly` | **Critical** | Word 邮件合并筛选部件（`word/mailMergeFilter*.xml`）、收件人数据部件（`word/recipientData*.xml`）或关系配置诱导 NTLM 凭据窃取的远程 UNC 路径、危险利用协议、数据库命令执行存储过程、暂存 Shell 命令或走私的 Windows PE 二进制文件。 |
| `VBA-CELL-088` | `ExcelExternalDataFeedOrDataServiceAnomaly` | **Critical** | Excel 外部数据源定义（`xl/dataServices/*`、`xl/externalDataFeeds/*`、`xl/dataFeeds/*`）、连接 XML（`xl/connections/dataService*.xml`）或服务关系配置诱导 NTLM 凭据窃取的远程 UNC 服务端点、危险利用协议、数据库命令执行存储过程、隐匿 DDE 命令公式或暂存 Shell 命令。 |
| `VBA-CELL-089` | `PowerPointSlideMasterOrLayoutPartAnomaly` | **Critical** | PowerPoint 幻灯片母版部件（`ppt/slideMasters/slideMaster*.xml`）、幻灯片版式部件（`ppt/slideLayouts/slideLayout*.xml`）或母版关系配置诱导 NTLM 凭据窃取的远程 UNC 服务端点、危险利用协议、暂存 Shell 命令、隐匿 DDE 命令公式或走私的 Windows PE 二进制文件。 |
| `VBA-CELL-090` | `WordDocumentTemplateOrAttachedTemplateAnomaly` | **Critical** | Word 文档模板设置（`word/settings.xml` 内的 `<w:attachedTemplate>`）、模板部件（`word/template*.xml`、`word/templateSettings.xml`）或模板关系配置诱导 NTLM 凭据窃取的远程 UNC 模板路径、危险利用协议、暂存 Shell 命令或走私的 Windows PE 二进制文件。 |
| `VBA-CELL-091` | `ExcelXmlSpreadsheetOrDataBindingAnomaly` | **Critical** | Excel XML 电子表格数据绑定部件（`xl/dataBindings/*`、`xl/bindings/*`）、连接 XML（`xl/connections/binding*.xml`）或绑定关系配置诱导 NTLM 凭据窃取的远程 UNC 服务端点、危险利用协议、数据库命令执行存储过程、隐匿 DDE 命令公式或暂存 Shell 命令。 |
| `VBA-CELL-092` | `PowerPointViewPropertiesOrTableStylesAnomaly` | **Critical** | PowerPoint 视图属性部件（`ppt/viewProps.xml`）、表格样式部件（`ppt/tableStyles.xml`）或视图关系配置诱导 NTLM 凭据窃取的远程 UNC 服务端点、危险利用协议、暂存 Shell 命令或走私的 Windows PE 二进制文件。 |
| `VBA-CELL-093` | `WordNumberingDefinitionOrOutlineAnomaly` | **Critical** | Word 编号定义部件（`word/numbering.xml`）、多级大纲定义（`<w:abstractNum>`、`<w:lvlText>`）或编号关系配置诱导 NTLM 凭据窃取的远程 UNC 路径、危险利用协议、暂存 Shell 命令或走私的 Windows PE 二进制文件。 |
| `VBA-CELL-094` | `ExcelCellMetadataOrRichValueAnomaly` | **Critical** | Excel 单元格元数据定义部件（`xl/metadata.xml`）、现代富值结构部件（`xl/richData/rdrichvalue.xml`、`xl/richData/richValueRel.xml`、`xl/richData/*`）或元数据关系配置诱导 NTLM 凭据窃取的远程 UNC 服务端点、危险利用协议、暂存 Shell 命令或走私的 Windows PE 二进制文件。 |

- **容器级威胁深度审查**: 即使在无宏代码的 DOCX/XLSX 样本中，也能自动审查 OOXML 关系、绘图对象、外部数据连接、内嵌 SVG 矢量图、数字签名、Word 域代码（`w:fldSimple`、`w:instrText`）、PowerPoint 幻灯片动作、AltChunk 外部格式载荷走私部件、Custom UI 功能区 XML 回调、传统对话框工作表、`[Content_Types].xml` 清单声明结构、外部链接缓存（`xl/externalLinks/`）、Word Web 设置框架集（`word/webSettings.xml`）、工作簿保护隐匿结构（`xl/workbook.xml`）、走私可执行二进制与 PE 头伪装（`VBA-CELL-032`）、工作表视图隐藏与视口偏移（`VBA-CELL-033`）、ActiveX 对象 CLSID 与属性声明（`VBA-CELL-034`）、Word 词汇表文档注入（`VBA-CELL-035`）、字体载荷走私与 ODTTF 混淆（`VBA-CELL-036`）、数字墨迹动作异常（`VBA-CELL-037`）、文档属性载荷走私（`VBA-CELL-038`）、Web 外接程序与任务窗格自动运行异常（`VBA-CELL-039`）、数据透视表连接异常（`VBA-CELL-040`）、图元文件漏洞利用与 PE 伪装（`VBA-CELL-041`）、XSLT 脚本注入（`VBA-CELL-042`）、关系目标伪装与协议混淆规避（`VBA-CELL-043`）、SmartArt与图表载荷走私（`VBA-CELL-044`）、Word邮件合并数据源伪装与NTLM诱导（`VBA-CELL-045`）、Excel QueryTable外部查询滥用（`VBA-CELL-046`）、Excel Power Query M语言公式与数据混搭部件异常（`VBA-CELL-047`）、OLE Moniker与静默激活/图标伪装（`VBA-CELL-048`）、XML命名空间伪装与XXE实体注入（`VBA-CELL-049`）、Excel 切片器与日程表缓存异常（`VBA-CELL-050`）、Word 书目与引文异常（`VBA-CELL-051`）、自定义 XML SDT 数据绑定/XPath 注入（`VBA-CELL-052`）、XML 映射与表格架构（`VBA-CELL-053`）、文档批注与现代注释（`VBA-CELL-054`）、主题字体与远程模板诱导（`VBA-CELL-055`）、自定义 XML 属性与架构异常（`VBA-CELL-056`）、VBA 项目关系与数据流异常（`VBA-CELL-057`）、Word 词汇表与构建基块关系异常（`VBA-CELL-058`）、Word 文档变量与脚注尾注异常（`VBA-CELL-059`）、PowerPoint 标签与母版幻灯片异常（`VBA-CELL-060`）、Excel 方案管理器与合并计算异常（`VBA-CELL-061`）、PowerPoint 动画与时间节点异常（`VBA-CELL-062`）、Word 页眉页脚与水印异常（`VBA-CELL-063`）、Excel 数据模型与公式缓存异常（`VBA-CELL-064`）、Excel PivotCache 与定义异常（`VBA-CELL-065`）、Word 与 PowerPoint 内嵌包异常（`VBA-CELL-066`）、Excel 外部工作簿与工作表路径异常（`VBA-CELL-067`）、ActiveX 二进制属性持久化流异常（`VBA-CELL-068`）、XML 数字签名与源部件异常（`VBA-CELL-069`）、Excel 表单控件属性与表单动作异常（`VBA-CELL-070`）、PowerPoint 媒体轨道与幻灯片动作异常（`VBA-CELL-071`）、Excel 表格与切片器原生连接异常（`VBA-CELL-072`）、Word 邮件合并表头源与收件人异常（`VBA-CELL-073`）、PowerPoint 演示文稿属性与放映异常（`VBA-CELL-074`）、Excel 线索化批注与人员元数据异常（`VBA-CELL-075`）、Office 主题覆盖与格式方案异常（`VBA-CELL-076`）、PowerPoint 同步与批注作者异常（`VBA-CELL-077`）、Word 键盘映射与自定义异常（`VBA-CELL-078`）、Excel Web 发布与迷你图异常（`VBA-CELL-079`）、PowerPoint 讲义与备注母版异常（`VBA-CELL-080`）、Word 词汇表设置与字体表异常（`VBA-CELL-081`）、Excel 自定义属性与自定义数据异常（`VBA-CELL-082`）、Word 子文档与主文档异常（`VBA-CELL-083`）、PowerPoint 字体表与内嵌字体异常（`VBA-CELL-084`）、Excel 查询表与数据源异常（`VBA-CELL-085`）、PowerPoint 幻灯片参考线与网格异常（`VBA-CELL-086`）、Word 邮件合并表头筛选与收件人项异常（`VBA-CELL-087`）、Excel 外部数据源与数据服务异常（`VBA-CELL-088`）、PowerPoint 幻灯片母版与版式异常（`VBA-CELL-089`）、Word 文档模板与附加模板异常（`VBA-CELL-090`）、Excel XML 电子表格与数据绑定异常（`VBA-CELL-091`）、PowerPoint 视图属性与表格样式异常（`VBA-CELL-092`）、Word 编号定义与多级大纲异常（`VBA-CELL-093`）以及 Excel 单元格元数据与富值结构异常（`VBA-CELL-094`），检测远程模板注入、内嵌 OLE 漏洞载荷、外部 Moniker 链接、ActiveX 控件、打印机设置 UNC 诱导、自定义 XML 载荷走私、绘图鼠标悬停/宏动作、外部数据连接/NTLM 诱导、SVG 恶意脚本、数字签名篡改及危险协议处理程序。
- **动态公式反混淆求值（De-obfuscation）**: 对 F 分布与分位数反函数（`F.DIST()`、`FDIST()`、`F.DIST.RT()`、`F.INV()`、`FINV()`、`F.INV.RT()`）、学生 t 分布与分位数反函数（`T.DIST()`、`TDIST()`、`T.DIST.RT()`、`T.DIST.2T()`、`T.INV()`、`TINV()`、`T.INV.2T()`）、短期国债债券等价收益率（`TBILLEQ()`）、贴现证券年收益率（`YIELDDISC()`）、未来值复利日程计算（`FVSCHEDULE()`）、贝塔分布与分位数反函数（`BETADIST()`、`BETA.DIST()`、`BETAINV()`、`BETA.INV()`）、到期付息证券定价与收益率（`PRICEMAT()`、`YIELDMAT()`）、票息日程计算函数（`COUPNUM()`、`COUPDAYS()`、`COUPDAYBS()`、`COUPDAYSNC()`）、短期国债定价与收益率（`TBILLPRICE()`、`TBILLYIELD()`）、分数美元价格转换（`DOLLARDE()`、`DOLLARFR()`）、到期计息计算（`ACCRINTM()`）、伽玛分布与分位数反函数（`GAMMADIST()`、`GAMMA.DIST()`、`GAMMAINV()`、`GAMMA.INV()`）、证券久期与贴现利率（`DURATION()`、`MDURATION()`、`INTRATE()`）、卡方分布与分位数反函数（`CHISQ.DIST()`、`CHIDIST()`、`CHISQ.DIST.RT()`、`CHISQ.INV()`、`CHISQ.INV.RT()`、`CHIINV()`）、利率转换（`EFFECT()`、`NOMINAL()`）、等额本息/本金还款及累积摊销（`IPMT()`、`PPMT()`、`CUMIPMT()`、`CUMPRINC()`）、逆二项分布（`CRITBINOM()`、`BINOM.INV()`）、现金流估值与内部收益率（`IRR()`、`MIRR()`）、贴现证券定价与到期收益（`DISC()`、`PRICEDISC()`、`RECEIVED()`）、离散超几何分布（`HYPGEOMDIST()`、`HYPGEOM.DIST()`）、财务估值与折旧摊销函数（`SLN()`、`SYD()`、`NPV()`、`PV()`、`FV()`、`PMT()`）、离散与连续概率分布（`LOGNORMDIST()`、`LOGNORM.DIST()`、`POISSON()`、`POISSON.DIST()`、`BINOMDIST()`、`BINOM.DIST()`）、统计与正态分布函数（`STANDARDIZE()`、`NORMSDIST()`、`NORM.S.DIST()`、`NORMDIST()`、`NORM.DIST()`）、指数分布与威布尔可靠性分布（`EXPONDIST()`、`EXPON.DIST()`、`WEIBULL()`、`WEIBULL.DIST()`）、跨距离/质量/时间/温度/压力/力/能量/功率/体积/面积/数据内存的物理单位转换（`CONVERT()`）、公式检查与错误分类谓词（`ISFORMULA()`、`ERROR.TYPE()`）、贝塞尔函数（`BESSELJ()`、`BESSELI()`、`BESSELY()`、`BESSELK()`）、误差函数与互补误差函数（`ERF()`、`ERF.PRECISE()`、`ERFC()`、`ERFC.PRECISE()`）、概率与标准正态分布密度函数（`GAUSS()`、`PHI()`）、复数幅角与共轭函数（`IMARGUMENT()`、`IMCONJUGATE()`）、复数三角函数与对数函数（`IMSIN()`、`IMCOS()`、`IMTAN()`、`IMSINH()`、`IMCOSH()`、`IMSEC()`、`IMCSC()`、`IMCOT()`、`IMLOG10()`、`IMLOG2()`）、伽玛函数与对数伽玛函数（`GAMMA()`、`GAMMALN()`）、复数四则运算/幂/初等超越函数（`IMSUM()`、`IMSUB()`、`IMPRODUCT()`、`IMDIV()`、`IMPOWER()`、`IMSQRT()`、`IMEXP()`、`IMLN()`）、重复组合与重复排列（`COMBINA()`、`PERMUTATIONA()`）、整数奇偶判断谓词（`ISODD()`、`ISEVEN()`）、复数构建与平方差和及多项式系数（`COMPLEX()`、`IMREAL()`、`IMAGINARY()`、`IMABS()`、`IMCONJG()`、`SUMXMY2()`、`SUMX2MY2()`、`SUMX2PY2()`、`MULTINOMIAL()`）、矩阵行列式与逆矩阵（`MDETERM()`、`MINVERSE()`）、整数取整与幂级数多项式求和（`INT()`、`SERIESSUM()`）、矩阵代数（`MMULT()`、`MUNIT()`）、正割/余割/余切及双曲函数（`SEC()`、`CSC()`、`COT()`、`SECH()`、`CSCH()`、`COTH()`）、反余切函数（`ACOT()`、`ACOTH()`）、双曲三角函数与反双曲函数（`SINH()`、`COSH()`、`TANH()`、`ASINH()`、`ACOSH()`、`ATANH()`）、含 $\pi$ 平方根（`SQRTPI()`）、平方和累加（`SUMSQ()`）、数学常数与指数运算（`PI()`、`EXP()`）、对数运算（`LN()`、`LOG10()`、`LOG()`）、排列组合（`COMBIN()`、`PERMUT()`）、多维数组内积求和（`SUMPRODUCT()`）、动态序列生成（`SEQUENCE()`）、隐式交集标量提取（`SINGLE()`）、Excel 365 动态数组堆叠（`VSTACK()`, `HSTACK()`）、逻辑分支（`IFS()`, `SWITCH()`, `XOR()`）、Lambda 辅助函数（`MAP()`、`REDUCE()`、`SCAN()`、`BYROW()`、`BYCOL()`、`MAKEARRAY()`、`ISOMITTED()`）、原生数组常量字面量（`{...}`）、自定义 Lambda 函数（`LAMBDA()`）、变量作用域求值（`LET()`）、动态 URL 编码（`ENCODEURL()`）、进制转换（`BIN2HEX()`, `HEX2BIN()`, `OCT2HEX()`, `HEX2OCT()`, `BASE()`, `DECIMAL()`, `HEX2DEC()`, `BIN2DEC()`）、区域无关数值解析（`NUMBERVALUE()`）、网格动态解析（`INDIRECT()`, `OFFSET()`, `ADDRESS()`）、跨单元格公式审查（`FORMULATEXT()`）、动态数组过滤与排序（`FILTER()`, `SORT()`, `SORTBY()`, `UNIQUE()`, `WRAPROWS()`, `WRAPCOLS()`）、位运算解密（`BITXOR()`, `BITAND()`, `BITOR()`, `BITLSHIFT()`, `BITRSHIFT()`）、罗马数字转换（`ROMAN()`, `ARABIC()`）、现代动态数组变形（`TAKE()`, `DROP()`, `CHOOSEROWS()`, `CHOOSECOLS()`, `TOROW()`, `TOCOL()`, `EXPAND()`）、现代动态检索（`XLOOKUP()`, `XMATCH()`）、数组转置（`TRANSPOSE()`）、向量/数组查找（`LOOKUP()`）、无分支条件评估（`DELTA()`, `GESTEP()`, `SIGN()`）、DBCS 双字节字符截取（`LENB()`, `LEFTB()`, `RIGHTB()`, `MIDB()`）、整数除法与奇偶舍入（`QUOTIENT()`, `EVEN()`, `ODD()`）、阶乘计算（`FACT()`, `FACTDOUBLE()`）、数论约数倍数（`GCD()`, `LCM()`）、文本拆解与序列化（`TEXTBEFORE()`, `TEXTAFTER()`, `TEXTSPLIT()`, `ARRAYTOTEXT()`, `VALUETOTEXT()`）、多单元格区域拼接（`CONCAT()`, `TEXTJOIN()`）、二维表格检索（`INDEX()`, `VLOOKUP()`, `HLOOKUP()`, `MATCH()`）、Unicode 转换（`UNICHAR()`, `UNICODE()`）以及数学/字符串/类型判断函数（`CHAR()`, `MID()`, `SUBSTITUTE()`, `CHOOSE()`, `HYPERLINK()`, `ROWS()`, `COLUMNS()`, `MROUND()`, `TYPE()`, `ISNONTEXT()`）的复杂混淆公式执行有界求值与递归解析，自动还原并捕获规避静态匹配的异或解密与多单元格拼接 DDE 命令、RTD COM 自动化、LOLBins 及远程恶意下载载荷。
- **全角字符混淆逃逸防御**: 在检查公式前，自动将全角字符（`U+FF01`–`U+FF5E`、`U+3000`）规范化映射为标准 ASCII，破坏利用全角字符绕过安全检查的企图。

---

## 核心语义分析引擎规格

- 分词并保留精确的 UTF-8 字节跨度及物理行号/列号。
- 正确识别全角空格（`U+3000`）等空白字符为合法分隔符，而非标识符字符。
- 严格遵循 VBA 行续行规则，在预处理器计算条件编译（`#If`、`#Const`）时保持逻辑行完整并对屏蔽分支进行掩码。
- 全面解析模块声明、过程头（`Sub`、`Function`、`Property`）、形参、局部/全局变量、`Type` 与 `Enum` 块以及结构化控制语句（`If`、`Select Case`、循环、`With`、标签、`GoTo`、计算型 `On...GoTo` / `On...GoSub`）。
- 准确处理表达式优先级、点号成员访问、感叹号字典成员访问以及各种类型后缀（`!`、`#`、`$`、`%`、`&`、`@`、`^`）。
- 构建结构化控制流图（CFG）、到达定义链、无环常量折叠以及异常传播模拟图。
- 原生实现 `.xlsm`、`.xlsb`、`.docm`、`.pptm`、旧版 `.xls` 以及独立 `vbaProject.bin` 的 MS-OVBA 解压缩、Compound File Binary (CFB) 结构解析及 OPC 包装解算。

---

## 安全边界与安全保证

- **绝不执行任何代码**: 引擎完全不依赖也不调用宿主脚本解释器、Office 自动化接口或 JIT 运行时。
- **绝不发起网络访问**: 核心库不具备任何套接字或网络栈调用能力，绝不主动外连。
- **严格的有界资源限制**: 针对解压爆炸（ZIP Bomb）、解压死循环、CFB 迷你扇区环形引用攻击等，内置严格的递归深度、缓冲区上限及迭代步数约束（`Limits::bounded()`）。
- **静态近似边界**: 控制流路径仅作为结构化推断依据，并非动态运行时执行判定。后期绑定、宿主动态公式求解（`Evaluate`）与外部未建模类型库显式保持未解析状态。

---

## 相关文档与链接

- [架构设计与分析模型 (JA)](docs/ARCHITECTURE_JA.md)
- [格式出处与规格说明 (PROVENANCE)](docs/PROVENANCE.md)
- [后续发布路线图 (JA)](docs/ROADMAP_JA.md)
- [软件包发布与发布流水线指南](docs/PUBLISHING.md)
- [贡献指南](CONTRIBUTING.md)
- [开源协议 (MIT)](LICENSE)

源代码仓库: [ryusui-hiro/vba-retrace](https://github.com/ryusui-hiro/vba-retrace)
