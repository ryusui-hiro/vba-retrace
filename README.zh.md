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

`vba-insight` 针对容器包结构（OOXML 关系、内嵌 OLE 部件）、工作簿公式、定义名及工作表元数据进行 22 项专业安全规则筛查：

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

- **容器级威胁深度审查**: 即使在无宏代码的 DOCX/XLSX 攻击样本中，也能自动审查 OOXML 关系、绘图对象、外部数据连接、内嵌 SVG 矢量图、数字签名及部件结构，检测远程模板注入、内嵌 OLE 漏洞载荷、外部 Moniker 链接、ActiveX 控件、打印机设置 UNC 诱导、自定义 XML 载荷走私、绘图鼠标悬停/宏动作、外部数据连接/NTLM 诱导、SVG 恶意脚本、数字签名篡改及危险协议处理程序。
- **动态公式反混淆求值（De-obfuscation）**: 对网格动态解析（`INDIRECT()`, `OFFSET()`, `ADDRESS()`）、跨单元格公式审查（`FORMULATEXT()`）、动态数组过滤与排序（`FILTER()`, `SORT()`, `SORTBY()`, `UNIQUE()`, `WRAPROWS()`, `WRAPCOLS()`）、位运算解密（`BITXOR()`, `BITAND()`, `BITOR()`, `BITLSHIFT()`, `BITRSHIFT()`）、进制与罗马数字转换（`BASE()`, `DECIMAL()`, `ROMAN()`, `ARABIC()`, `HEX2DEC()`, `BIN2DEC()`）、现代动态数组变形（`TAKE()`, `DROP()`, `CHOOSEROWS()`, `CHOOSECOLS()`, `TOROW()`, `TOCOL()`, `EXPAND()`）、现代动态检索（`XLOOKUP()`, `XMATCH()`）、文本拆解与序列化（`TEXTBEFORE()`, `TEXTAFTER()`, `TEXTSPLIT()`, `ARRAYTOTEXT()`, `VALUETOTEXT()`）、多单元格区域拼接（`CONCAT()`, `TEXTJOIN()`）、二维表格检索（`INDEX()`, `VLOOKUP()`, `HLOOKUP()`, `MATCH()`）、Unicode 转换（`UNICHAR()`, `UNICODE()`）以及数学/字符串/类型判断函数（`CHAR()`, `MID()`, `SUBSTITUTE()`, `CHOOSE()`, `HYPERLINK()`, `ROWS()`, `COLUMNS()`, `MROUND()`, `TYPE()`, `ISNONTEXT()`）的复杂混淆公式执行有界求值与递归解析，自动还原并捕获规避静态匹配的异或解密与多单元格拼接 DDE 命令、RTD COM 自动化、LOLBins 及远程恶意下载载荷。
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
