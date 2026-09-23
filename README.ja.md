# vba-insight

[English](README.md) | [日本語](README.ja.md) | [简体中文](README.zh.md)

[![crates.io](https://img.shields.io/crates/v/vba-insight.svg)](https://crates.io/crates/vba-insight)
[![PyPI](https://img.shields.io/pypi/v/vba-insight.svg)](https://pypi.org/project/vba-insight/)
[![npm](https://img.shields.io/npm/v/vba-insight.svg)](https://www.npmjs.com/package/vba-insight)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](Cargo.toml)

純粋な Rust (`std` のみ) で実装された、**サードパーティ依存関係ゼロ（Zero-dependency）** の VBA 静的解析、P-Code（中間バイトコード）逆アセンブラ、および **VBA Stomping / 改ざん自動検知** エンジンです。Office マクロコンテナ（`.xlsm`、`.xlsb`、`.docm`、`.pptm`、旧形式 `.xls`、生バイナリ `vbaProject.bin`）から直接展開して検査します。

Office アプリケーションやスクリプト実行エンジンを呼び出さず、ネットワーク通信も一切行わずにメモリ内のみで安全に高速実行されます。

---

## 主な特徴

- **高速 & サードパーティ依存関係ゼロ (`std` のみ)**: コアクレートは Rust 標準ライブラリのみで完結。外部 C ライブラリ、OpenSSL、外部正規表現エンジンに依存しないため、決定論的ビルド、最小限のバイナリフットプリント、および極めて高い解析スループットを実現。
- **Office コンテナからの直接マクロ抽出**: OOXML パッケージ（`.xlsm`、`.docm`、`.pptm`）、Compound File Binary（CFB / `.xls`、`vbaProject.bin`）からの直接ストリーム抽出、MS-OVBA 伸張、および OPC パッケージ解決をネイティブ処理。
- **標準 P-Code 逆アセンブラ内蔵**: 外部オペコードテーブルに頼ることなく、VBA6 / VBA7（32-bit / 64-bit）を網羅する 264 の標準 VBA オペコードに対応し、`_VBA_PROJECT` メタデータから直接識別子や文字列リテラルを解決。
- **VBA Stomping & 改ざん自動検知**: 解凍された VBA ソースコードとコンパイル済み P-Code バイトコード間の乖離を自動特定（ソースコードの消去・パージ、バイトコードにのみ隠蔽されたプロシージャ、危険な Win32 API 呼び出し、不審な URL / IP、GUI 非表示のゴーストモジュール等を検出）。
- **ワークシート・セル脅威スキャナー**: DDE（Dynamic Data Exchange）実行（`=cmd|...`）、旧形式 XLM 4.0 マクロ（`=EXEC(...)`、`=CALL(...)`）、リモート UNC / HTTP インジェクション、`=WEBSERVICE(...)` によるデータ外部持ち出し、不審な実行可能ファイルへのハイパーリンク、全角文字による難読化回避の正規化、および自動実行定義名（`Auto_Open` 等）を検知。
- **SARIF v2.1.0 セキュリティレポート出力**: GitHub Advanced Security の Code Scanning、GitLab CI、または各種 SIEM パイプラインとシームレスに統合可能な OASIS SARIF v2.1.0 形式を出力。
- **ファーストクラスのマルチ言語バインディング**: **Rust**、**Python**（PyO3 / ABI3 ホイール）、**Node.js**（N-API ネイティブアドオン + TypeScript 型定義）に対応。

---

## インストール

| 言語 / プラットフォーム | パッケージ名 | インストールコマンド | 概要 |
|---|---|---|---|
| **Rust ライブラリ** | `vba-insight` | `cargo add vba-insight` | 依存関係ゼロの静的解析ライブラリ |
| **Python (3.10+)** | `vba-insight` | `pip install vba-insight` | 事前ビルド済み ABI3 ホイール（型ヒント完備） |
| **Node.js (18+)** | `vba-insight` | `npm install vba-insight` | 高速 N-API ネイティブアドオン（TypeScript 型定義付属） |
| **CLI バイナリ** | `vba-insight` | `cargo install vba-insight` | または [Releases](https://github.com/ryusui-hiro/vba-retrace/releases) からバイナリを直接取得 |

---

## CLI の使い方

`vba-insight` コマンドラインツールには、4 つの主要モードが備わっています。

```sh
# 1. マクロコンテナの総合検査（VBA AST + P-Code + Stomping + セル脅威を一度に検査）
vba-insight inspect sample.xlsm --format markdown
vba-insight inspect suspicious.docm --format sarif > results.sarif

# 2. VBA Stomping & 改ざん検知
vba-insight stomping malicious.xlsm --format sarif
vba-insight stomping malicious.xlsb --format markdown

# 3. コンパイル済み P-Code バイトコードの逆アセンブル
vba-insight disasm sample.xlsm --format markdown
vba-insight disasm vbaProject.bin --format json

# 4. VBA ソースコードの静的構文・意味解析
vba-insight analyze examples/approval.bas --host excel
vba-insight analyze examples/approval.bas --include-source
vba-insight analyze examples/approval.bas --format dot > cfg.dot
```

---

## コード例

### 1. Rust ライブラリ API

#### マクロコンテナの総合検査 & SARIF エクスポート

```rust
use vba_insight::{
    inspect_macro_file, inspect_to_markdown, inspection_to_sarif, AnalysisOptions,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let container_bytes = std::fs::read("suspicious.xlsm")?;
    let options = AnalysisOptions::default();

    // コンテナ検査: ストリーム抽出、AST 解析、P-Code 逆アセンブル、Stomping / セル脅威検知を一括実行
    let inspection = inspect_macro_file(&container_bytes, &options)?;

    println!("抽出モジュール数: {}", inspection.extracted.modules.len());
    println!("Stomping 検知の有無: {}", inspection.stomping_report.has_stomping);

    // GitHub Code Scanning 用の SARIF v2.1.0（Stomping およびセル脅威を網羅）を生成
    let sarif = inspection_to_sarif(&inspection, "suspicious.xlsm");
    std::fs::write("audit.sarif", sarif)?;

    // Markdown サマリーを出力
    let md = inspect_to_markdown(&inspection);
    println!("{md}");

    Ok(())
}
```

#### VBA Stomping / 改ざんの専門検知

```rust
use vba_insight::{
    detect_project_stomping, extract_macro_container, stomping_to_sarif, Limits,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = std::fs::read("target.docm")?;
    let extracted = extract_macro_container(&bytes, &Limits::bounded())?;
    let report = detect_project_stomping(&extracted)?;

    if report.has_stomping {
        eprintln!("警告: VBA Stomping を検知しました！ 全体重要度: {:?}", report.overall_severity);
        for m in &report.modules {
            if m.is_stomped {
                eprintln!(" モジュール {}: 発見数 {}", m.module_name, m.findings.len());
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

#### コンパイル済み P-Code バイトコードの逆アセンブル

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

#### VBA ソースコードの静的解析

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
    println!("解析プロシージャ数: {}", report.project.modules[0].procedures.len());

    Ok(())
}
```

---

### 2. Python API (`pip install vba-insight`)

Python 3.10 以降向けに、Linux、macOS、Windows 対応の universal ABI3 バイナリホイールが提供されています。

```python
import json
import vba_insight

# 1. Office マクロコンテナ（.xlsm, .xlsb, .docm, .pptm, .xls, vbaProject.bin）を検査
report = vba_insight.inspect_file("suspicious.xlsm")

print(f"プロジェクト名: {report.get('project_name')}")
stomping = report.get("stomping", {})

if stomping.get("has_stomping"):
    print(f"[!] VBA Stomping 検知！ 重要度: {stomping.get('overall_severity')}")
    for finding in stomping.get("project_findings", []):
        print(f"  - [{finding['rule_id']}] {finding['description']}")
    for mod in stomping.get("modules", []):
        if mod.get("is_stomped"):
            print(f"  モジュール {mod.get('module_name')}:")
            for finding in mod.get("findings", []):
                print(f"    - [{finding['rule_id']}] {finding['description']}")

# 2. ワークシートの危険なセル数式（DDE, XLM, WEBSERVICE）を検査
analysis = report.get("analysis", {})
workbook = analysis.get("workbook_structure", {})
cell_threats = workbook.get("cell_threats", [])
if cell_threats:
    print(f"[!] {len(cell_threats)} 個の危険なセル数式を検出:")
    for threat in cell_threats:
        print(f"  - [{threat['rule_id']}] {threat['coordinate']}: {threat['threat_kind']} ({threat['formula']})")

# 3. GitHub Advanced Security / CI 統合用の OASIS SARIF v2.1.0 レポートを出力
# (VBA Stomping VBA-STOMP-001..010 および コンテナ・セル脅威 VBA-CELL-001..017 の双方を含みます)
sarif_json = vba_insight.inspect_file_sarif("suspicious.xlsm")
with open("security_report.sarif", "w", encoding="utf-8") as f:
    f.write(sarif_json)

# 4. コンパイル済み VBA P-Code バイトコード逆アセンブリの取得
pcode_modules = vba_insight.disasm_file("suspicious.xlsm")
for mod in pcode_modules:
    print(f"モジュール: {mod['module_name']} - {len(mod['lines'])} 行の P-Code")

# 5. 整形済み Markdown 検査サマリーを取得
markdown_summary = vba_insight.inspect_file_markdown("suspicious.xlsm")
print(markdown_summary)

# 6. 純粋な VBA ソースコードの静的構文解析
vba_sources = [
    ("Module1.bas", "Public Sub Test()\n    MsgBox \"Hello\"\nEnd Sub\n")
]
ast_report = vba_insight.analyze_sources(vba_sources)
print("解析モジュール数:", len(ast_report["project"]["modules"]))
```

---

### 3. Node.js & TypeScript API (`npm install vba-insight`)

TypeScript 型定義がバンドルされた、高速な N-API ネイティブアドオンです。

```typescript
import * as fs from 'node:fs';
import {
  inspectMacroFileJson,
  inspectMacroFileSarif,
  inspectMacroFileMarkdown,
  disasmMacroFileJson,
  analyzeSourcesJson,
} from 'vba-insight';

// 1. マクロコンテナを Buffer に読み込み
const fileBuffer = fs.readFileSync('suspicious.xlsm');

// 2. マクロコンテナの総合検査を実行（JSON 文字列が返却されます）
const rawJson = inspectMacroFileJson(fileBuffer, true);
const report = JSON.parse(rawJson);

console.log('プロジェクト名:', report.project_name);
if (report.stomping?.has_stomping) {
  console.error(`[!] Stomping を検知！ 重要度: ${report.stomping.overall_severity}`);
  for (const finding of report.stomping.project_findings ?? []) {
    console.error(`  - [${finding.rule_id}] ${finding.description}`);
  }
  for (const mod of report.stomping.modules ?? []) {
    if (mod.is_stomped) {
      console.error(`  モジュール ${mod.module_name}:`);
      for (const finding of mod.findings ?? []) {
        console.error(`    - [${finding.rule_id}] ${finding.description}`);
      }
    }
  }
}

// 危険なワークシートセル脅威の確認（DDE, XLM, WEBSERVICE 等）
const cellThreats = report.analysis?.workbook_structure?.cell_threats ?? [];
for (const threat of cellThreats) {
  console.warn(`  - [${threat.rule_id}] ${threat.coordinate}: ${threat.threat_kind} (${threat.formula})`);
}

// 3. CI コードスキャン用の SARIF v2.1.0 レポートを出力
const sarifReport = inspectMacroFileSarif(fileBuffer, 'suspicious.xlsm');
fs.writeFileSync('macro-scan.sarif', sarifReport);

// 4. コンパイル済み P-Code 命令の逆アセンブリ
const pcodeJson = disasmMacroFileJson(fileBuffer);
console.log('P-Code モジュール数:', JSON.parse(pcodeJson).length);

// 5. GitHub 形式の Markdown 検査レポートを生成
const markdownReport = inspectMacroFileMarkdown(fileBuffer);
console.log(markdownReport);

// 6. VBA ソースコードの静的解析
const sourceUnits = [
  {
    name: 'Module1.bas',
    text: 'Sub Auto_Open()\n    Shell "powershell -enc ...", 0\nEnd Sub',
  },
];
const analysisJson = analyzeSourcesJson(sourceUnits, true);
const parsedAnalysis = JSON.parse(analysisJson);
console.log('解析完了。コード実行の有無:', parsedAnalysis.project.code_executed); // 常に false
```

---

## 脅威検知エンジン

### 1. VBA Stomping & 改ざん検知ルール

ソースコードテキストとコンパイル済み P-Code バイトコードの間の差異を分析する、10 個の専門ルールを実装しています。

| ルール ID | 検知種別 | 重要度 | 検出ロジックと概要 |
|---|---|:---:|---|
| `VBA-STOMP-001` | `SourcePurged` | **Critical** | VBA ソースコードが完全に削除・消去（パージ）されているにもかかわらず、実行可能なコンパイル済み P-Code バイトコードが残存している。 |
| `VBA-STOMP-002` | `ProcedureHiddenInPCode` | **High** | コンパイル済み P-Code ストリーム内には存在するが、伸張された VBA ソースコードテキスト内には存在しない隠蔽プロシージャ。 |
| `VBA-STOMP-003` | `SuspiciousLiteralInPCode` | **High** | 不審な文字列リテラル（URL、IPv4 アドレス、スクリプトコマンド、実行可能ファイル名等）が P-Code に存在するが、ソースコード上からは隠蔽されている。 |
| `VBA-STOMP-004` | `SensitiveCallInPCode` | **Critical** | 危険なシステム API やプロセスインジェクション関数（`VirtualAlloc`、`WriteProcessMemory`、`CreateRemoteThread`、`InternetOpen` 等）が P-Code で呼び出されているが、ソースコード上に存在しない。 |
| `VBA-STOMP-005` | `LineCountDiscrepancy` | **Medium** | ソースコードの実コード行数とコンパイル済み P-Code 行数との間に顕著な乖離がある。 |
| `VBA-STOMP-006` | `ProcedureMissingInPCode` | **Low** | ソースコードで宣言されたプロシージャが、P-Code バイトコードストリーム側に見当たらない。 |
| `VBA-STOMP-007` | `PerformanceCachePurged` | **Medium** | ソースコードは存在するが、コンパイル済み P-Code パフォーマンスキャッシュが意図的に消去されている（VBA Purging 回避手法）。 |
| `VBA-STOMP-008` | `HiddenGuiModule` | **High** | `dir` ストリーム内では宣言されているが、`PROJECT` マニフェストから除外されており、VBA IDE 上で不可視化されている（Evil Clippy 手法）。 |
| `VBA-STOMP-009` | `ProjectLockedOrUnviewable` | **Low** | VBA プロジェクトに保護・ロック属性（`CMG`, `DPB`, `GC`）が付与されており、標準の Office VBA IDE から閲覧できないように隠蔽されている。 |
| `VBA-STOMP-010` | `SourceCorruptedWithValidPCode` | **Critical** | モジュールのソースコード格納コンテナが MS-OVBA 解凍に失敗または破損しているにもかかわらず、有効で実行可能な P-Code が存在している。 |

### 2. コンテナパッケージ & ワークシート・セル脅威スキャナー

`vba-insight` は、コンテナパッケージ（OOXML リレーションシップ、埋め込み OLE パッケージ）、ワークシート数式、定義名、シートメタデータを以下の 82 の専用セキュリティルールで検査します：

| ルール ID | 検知種別 | 重要度 | 検出ロジックと概要 |
|---|---|:---:|---|
| `VBA-CELL-001` | `DDEExecutionFormula` | **Critical** | セル数式または定義名に DDE（Dynamic Data Exchange）経由で外部プロセスを起動する式が含まれている。 |
| `VBA-CELL-002` | `XlmMacroExecutionFormula` | **Critical** | セル数式または定義名に Excel 4.0（XLM）マクロ関数（`EXEC`, `CALL`, `REGISTER` 等）によるコード実行が含まれている。 |
| `VBA-CELL-003` | `RemoteWorkbookLink` | **High** | セル数式が UNC リモートパス（`\\server\share`）や外部 URL（HTTP/HTTPS）を参照している。 |
| `VBA-CELL-004` | `DataExfiltrationFormula` | **Medium** | セル数式で `=WEBSERVICE(...)` や `FILTERXML` を使用し、機密データを外部へ送信可能な状態になっている。 |
| `VBA-CELL-005` | `SuspiciousDownloadHyperlink` | **High** | `=HYPERLINK(...)` 数式が実行可能ファイル、スクリプト、アーカイブ、カスタムプロトコル（`.exe`, `.bat`, `search-ms:` 等）を指している。 |
| `VBA-CELL-006` | `AutoExecDefinedName` | **High** | ブック定義名（`Auto_Open`、`_xlnm.Auto_Open`、`Auto_Close` 等）がマクロ自動実行をトリガーする。 |
| `VBA-CELL-007` | `VeryHiddenWorksheet` | **Low** | ワークシートが `state="veryHidden"` に設定されており、Excel 通常 UI から悪意あるシートが隠蔽されている。 |
| `VBA-CELL-008` | `XlmMacroSheetPresent` | **Critical** | マルウェアの攻撃ペイロードとして多用される、旧形式の Excel 4.0 マクロシートが存在する。 |
| `VBA-CELL-009` | `DeobfuscatedThreatFormula` | **Critical** | 数式難読化（`CHAR`, `CONCATENATE`, 文字列置換等）が動的に評価され、実行可能ファイル、コマンド、または DDE ペイロードに解決される。 |
| `VBA-CELL-010` | `RemoteTemplateInjection` | **Critical** | リレーションシップが外部テンプレート（`attachedTemplate`）を HTTP/HTTPS/SMB 経由で参照し、遠隔の不正 dotm ペイロードを読み込む。 |
| `VBA-CELL-011` | `EmbeddedOlePackage` | **High** | OOXML コンテナ内の `/embeddings/` に埋め込み OLE バイナリまたはパッケージ（CVE-2017-11882 数式エディタ攻撃等）が存在する。 |
| `VBA-CELL-012` | `ExternalOleObject` | **High** | リレーションシップが外部 OLE オブジェクト（`oleObject`）を HTTP/HTTPS/SMB 経由で参照し、遠隔 Moniker や脆弱性悪用を可能にする。 |
| `VBA-CELL-013` | `ActiveXControlPresent` | **Medium** | OOXML コンテナ内の `/activex/` に埋め込み ActiveX コントロールが存在し、マクロレス悪用を可能にする。 |
| `VBA-CELL-014` | `ExternalSubdocumentReference` | **High** | リレーションシップが外部サブドキュメントまたはフレーム（`subDocument` / `frame`）を HTTP/HTTPS/SMB 経由で参照している。 |
| `VBA-CELL-015` | `SuspiciousPrinterSettings` | **High** | プリンター設定（`printerSettings*.bin`）に外部 UNC パス（`\\host\share`）、遠隔 URL、またはコマンド実行トリガー（CVE-2023-36884 / Storm-0978）が含まれている。 |
| `VBA-CELL-016` | `CustomXmlPayloadSmuggling` | **High** | カスタム XML パーツ（`/customXml/*.xml`）内に Base64 化された PE 実行バイナリ、XXE 外部実体インジェクション、またはスクリプト/HTML ペイロードが隠蔽密輸されている。 |
| `VBA-CELL-017` | `SuspiciousProtocolHandler` | **Critical** | リレーションシップのターゲットが危険なカスタムプロトコルハンドラー（`ms-msdt:` / Follina CVE-2022-30190、`search-ms:`、`ms-appinstaller:`、`mhtml:`、`javascript:`、`vbscript:` 等）を参照している。 |
| `VBA-CELL-018` | `SuspiciousDrawingAction` | **High** | 描画シェイプ、スライドトリガー、または VML ボタンのアクションにマウスホバー実行（`<a:hlinkHover>`）、マクロ実行リンク（`ppaction://macro`、`<x:FmlaMacro>`）、危険な実行可能ファイルリンクが定義されている。 |
| `VBA-CELL-019` | `ExternalDataConnection` | **High** | 外部データ接続（`/xl/connections.xml`、クエリテーブル、差し込み印刷等）に NTLM 認証詐取を狙う UNC パス、リモート Web クエリ、またはコマンドインジェクション（`xp_cmdshell`、PowerShell 等）が含まれている。 |
| `VBA-CELL-020` | `RealTimeDataExecution` | **Critical** | セル数式または定義名に `=RTD(...)` 数式が含まれ、COM オートメーションサーバー（`WScript.Shell`、`Shell.Application` 等）や遠隔 DCOM ホスト経由でのコード実行・NTLM 詐取を試みている。 |
| `VBA-CELL-021` | `SuspiciousSvgVector` | **High** | コンテナ内の埋め込み SVG ベクター画像（`/media/*.svg`）に不正スクリプト（`<script>`）、インラインイベントハンドラー、または XXE 外部実体定義が含まれている。 |
| `VBA-CELL-022` | `TamperedVbaProjectSignature` | **High** | VBA プロジェクトのデジタル署名バイナリ（`vbaProjectSignature*.bin`）が切り詰め/改竄されているか、署名参照リレーションが孤立（Dangling）している（署名偽装・剥奪回避）。 |
| `VBA-CELL-023` | `WordFieldCodeExecution` | **Critical** | Word ドキュメントパーツ（`word/document.xml`、ヘッダー、フッター等）に DDE/DDEAUTO によるコマンド実行、INCLUDETEXT/LINK による遠隔文書取得、UNC 認証詐取を仕組む不審なフィールドコード（`w:fldSimple`、`w:instrText`）が含まれている。 |
| `VBA-CELL-024` | `PowerPointSlideAction` | **Critical** | PowerPoint プレゼンテーションパーツ（`ppt/slides/slide*.xml`、レイアウト、マスター）に外部プログラム起動、マクロ実行、または実行可能ファイルへのリンクを仕組むクリック・ホバーアクション（`ppaction://program`、`<a:hlinkHover>`）が設定されている。 |
| `VBA-CELL-025` | `SuspiciousAltChunkPayload` | **Critical** | Word の代替フォーマットインポートチャンク（`aFChunk`）リレーションシップまたはパーツ（HTML、MHT、RTF、BIN）が外部リモートテンプレートを参照しているか、HTML Smuggling スクリプト、RTF 脆弱性悪用コード、または PE 実行可能バイナリを含んでいる。 |
| `VBA-CELL-026` | `CustomUiRibbonCallback` | **Critical** | Custom UI リボン XML（`customUI/customUI*.xml`）で文書読み込み時の自動実行コールバック（`onLoad`）やコントロールマクロトリガー（`onAction`）が設定されている。 |
| `VBA-CELL-027` | `LegacyDialogSheetMacro` | **High** | レガシー Excel 5.0/95 ダイアログシート（`xl/dialogsheets/sheet*.xml`）にコントロールマクロ連携（`<x:FmlaMacro>`）や自動ポップアップ偽装ダイアログが含まれている。 |
| `VBA-CELL-028` | `ContentTypeAnomaly` | **Critical** | パッケージ `[Content_Types].xml` にパストラバーサル（`/../`）、危険な実行可能 MIME（`application/x-msdownload`, `application/hta`）、または拡張子偽装（`vbaProject` を画像や無害な拡張子に偽装）が含まれている。 |
| `VBA-CELL-029` | `ExternalLinkTargetAnomaly` | **Critical** | 外部リンクキャッシュ（`xl/externalLinks/externalLink*.xml`）またはリレーションシップが遠隔UNCパス、危険な実行可能ファイル、攻撃プロトコルを参照しているか、隠蔽されたDDE/OLEサーバーリンクを登録している。 |
| `VBA-CELL-030` | `WebSettingsScriptOrReload` | **Critical** | ドキュメントWeb設定（`word/webSettings.xml`）にWebレイアウトで描画されるリモートフレームセット、フレームリロードトリガー、または攻撃プロトコルターゲットが注入されている。 |
| `VBA-CELL-031` | `WorkbookProtectionEvasion` | **High** | ワークブック保護（`xl/workbook.xml`）により構造ロック（`lockStructure="1"`) を行いながらveryHiddenシートを隠蔽しているか、検査を妨害する異常なパスワード保護ハッシュが適用されている。 |
| `VBA-CELL-032` | `SmuggledContainerPayload` | **Critical** | コンテナパッケージ内に密輸された実行可能バイナリ・スクリプト（`.exe`, `.dll`, `.sys`, `.scr`, `.bat`, `.cmd`, `.ps1`, `.vbs`, `.hta`, `.lnk`, `.iso` 等）、画像等に偽装された PE ヘッダー（`MZ`/`PE`）、Windows ショートカット（`.lnk`）、ELF/Mach-O バイナリ、またはステージングスクリプトが存在する。 |
| `VBA-CELL-033` | `WorksheetViewEvasion` | **High** | ワークシートビュー定義（`xl/worksheets/sheet*.xml`）において、非表示列（`hidden="1"` / `width="0"`）、非表示行（`hidden="1"` / `ht="0"`）、極端な表示位置スクロール（`topLeftCell`）、または行列ヘッダー・グリッド線非表示により悪意ある数式ペイロードを隠蔽している。 |
| `VBA-CELL-034` | `ActiveXObjectDeclarationAnomaly` | **Critical** | ActiveX XML 定義（`/activeX/activeX*.xml`）に武器化 CLSID（`WScript.Shell`, 数式エディタ 3.0, `XMLHTTP`, `Shell.Explorer`, `Scriptlet.TypeLib`, `ADODB.Stream`）、外部 UNC パス、実行可能ファイル参照、または危険なプロトコルハンドラーが含まれている。 |
| `VBA-CELL-035` | `GlossaryDocumentAnomaly` | **Critical** | Word用語集・定型句ドキュメントパーツ（`word/glossary/document.xml`、`settings.xml`）またはリレーションシップにリモートテンプレートインジェクション（`attachedTemplate`）、危険なURIスキーム（`ms-msdt:`、`search-ms:`）、コマンドフィールドコード（`DDE`、`EXEC`）、遠隔サブドキュメント参照、またはAltChunkペイロード密輸が含まれている。 |
| `VBA-CELL-036` | `EmbeddedFontObfuscationOrSmuggling` | **Critical** | 埋め込みフォントストリーム（`.odttf`、`.ttf`、`.woff`）またはフォントリレーションシップに密輸された実行可能バイナリ（`MZ`/`PE`）、Windowsショートカット（`.lnk`）、スクリプト、または反転GUID XOR難読化によりPEヘッダーを隠蔽したODTTFフォントが含まれている。 |
| `VBA-CELL-037` | `DigitalInkDefinitionAnomaly` | **Critical** | デジタルインク定義パーツ（`xl/ink/`、`word/ink/`、`ppt/ink/`、`.bin`、`.isf`）またはリレーションシップに対話型クリック/ホバートリガー（`<a:hlinkClick>`、`<a:hlinkHover>`、`ppaction://program`）、UNC認証詐取、武器化CLSID、または密輸された実行可能バイナリが含まれている。 |
| `VBA-CELL-038` | `DocumentPropertyPayloadSmuggling` | **Critical** | ドキュメントプロパティパーツ（`docProps/core.xml`、`docProps/app.xml`、`docProps/custom.xml`）に密輸されたBase64化PE実行可能バイナリ、シェル実行コマンド（`powershell`、`cmd.exe`、`wscript.exe`、`mshta`、`rundll32`、`certutil`）、危険なURIスキーム、またはNTLM認証詐取を誘発するUNCパスが含まれている。 |
| `VBA-CELL-039` | `WebExtensionOrTaskpaneAnomaly` | **Critical** | Office Webアドイン・作業ウィンドウパーツ（`word/webextensions/`、`xl/webextensions/`、`ppt/webextensions/`、`word/taskpanes/`、`xl/taskpanes/`、`ppt/taskpanes/`）またはリレーションシップに自動表示トリガー（`canAutoShow="1"`、`visibility="visible"`）、遠隔Webターゲット、危険なURIスキーム、またはマクロレス実行を可能にする埋め込みスクリプトが含まれている。 |
| `VBA-CELL-040` | `PivotCacheDataConnectionAnomaly` | **Critical** | ワークブックPivotCache定義（`xl/pivotCache/pivotCacheDefinition*.xml`）またはリレーションシップにNTLM認証詐取を狙う外部UNC接続パス、データベース経由のシェル実行コマンド（`xp_cmdshell`、`sp_OACreate`、`OPENROWSET`）、または危険なURIスキームが含まれている。 |
| `VBA-CELL-041` | `MetafileExploitOrPayloadSmuggling` | **Critical** | Windows メタファイルグラフィックスパーツ（`*.wmf`, `*.emf`, `/media/`）に CVE-2005-4560 レコード（`META_SETABORTPROC`）、画像に偽装された PE 実行可能ヘッダー（`MZ`/`PE`）、Windows ショートカット（`*.lnk`）、シェル実行コマンド、またはリモート UNC パスが含まれている。 |
| `VBA-CELL-042` | `XsltTransformOrScriptInjection` | **Critical** | XML パーツまたはスタイルシート（`styles.xml`, `settings.xml`, `customXml/`, `*.xsl`, `*.xslt`）に実行可能 `<msxsl:script>` 要素（`language="JScript"` / `"VBScript"`）、遠隔 `<w:saveThroughXslt>` 変換ターゲット、危険な XPath `document()` SSRF / NTLM 誘導関数、または Windows Shell オートメーションオブジェクトが含まれている。 |
| `VBA-CELL-043` | `RelationshipTargetCloakingOrEvasion` | **Critical** | リレーションシップファイル（`*.rels`）に検知回避文字（ヌルバイト `%00` / `\0` や Unicode 双方向オーバーライド `\u{202E}`）、パーセントエンコードされた危険な URI プロトコル（`m%73-m%73dt:`, `s%65arch-ms:`, `m%68tml:`）、またはローカル IPC 名前付きパイプ / ループバック誘導ターゲット（`\\.\pipe\`, `\\127.0.0.1\`, `\\localhost\`）が含まれている。 |
| `VBA-CELL-044` | `SmartArtOrDiagramPayloadAnomaly` | **Critical** | SmartArt / ダイアグラムパーツ（`*/diagrams/*.xml`、`data*.xml`、`layout*.xml`、`drawing*.xml`）またはリレーションシップに対話型アクション（`<dgm:hlinkClick>`、`<a:hlinkHover>`、`ppaction://program`）、危険な URI スキーム（`ms-msdt:`、`search-ms:`、`mhtml:`）、リモート UNC パス、または画像等に偽装された PE 実行可能ヘッダー / シェル実行コマンドが含まれている。 |
| `VBA-CELL-045` | `MailMergeDataSourceOrCoercionAnomaly` | **Critical** | Word 差し込み印刷設定（`word/settings.xml`）またはリレーションシップに NTLM 認証詐取を狙う外部 UNC 接続文字列（`<w:connectString>`）、データベース経由のコマンドインジェクション（`xp_cmdshell`、`sp_OACreate`）、自動差し込み実行設定、または危険な実行可能・スクリプトファイル（`.iqy`、`.hta`、`.vbs`、`.bat`、`.ps1`、`.exe`）を指す外部リレーションシップが含まれている。 |
| `VBA-CELL-046` | `QueryTableOrExternalQueryAnomaly` | **Critical** | Excel QueryTable 定義（`xl/queryTables/queryTable*.xml`）またはリレーションシップで自動更新（`refreshOnLoad="1"`、`autoRefresh="1"`）、外部 Web クエリファイル（`.iqy`、`.dqy`）、NTLM 認証詐取 UNC パス、データベースコマンド実行（`xp_cmdshell`）、または環境変数詐取トークン（`%USERNAME%`）が設定されている。 |
| `VBA-CELL-047` | `PowerQueryFormulaOrMashupAnomaly` | **Critical** | Excel Power Query 定義（`xl/powerQuery/powerQuery.xml`）、Data Mashup パーツ（`customXml/`、`customData/`）、または M 式クエリに `Web.Page` による任意のスクリプト/コード実行、`Web.Contents` による遠隔データ持ち出し/ペイロード取得、NTLM 認証詐取を狙う UNC リモートパス（`File.Contents` 等）、密輸された PE 実行バイナリ、またはデータベース経由のコマンド実行（`xp_cmdshell`、`OPENROWSET`）が含まれている。 |
| `VBA-CELL-048` | `PackageMonikerOrActivationAnomaly` | **Critical** | 埋め込み OLE オブジェクトパーツ、描画、スライド、またはリレーションシップに危険な Moniker URI / プロトコルハンドラー（`moniker:`、`file:`、`script:`、`composite:`、`ms-msdt:`、`search-ms:`、`ms-appinstaller:`）、サイレント自動有効化フラグ（`UpdateMode="Always"`、`autoUpdate="1"`、`autoActivate="1"`）、実行可能ファイルのアイコン偽装（`DrawAspect="Icon"` かつ実行可能拡張子または `ProgID="Package"`）、または武器化 Packager/Moniker CLSID が設定されている。 |
| `VBA-CELL-049` | `NamespaceCloakingOrSchemaSpoofingAnomaly` | **Critical** | OOXML XML パーツまたはリレーションシップに NTLM 認証詐取を狙う UNC 名前空間宣言（`xmlns:...="\\host\share..."`）や `xsi:schemaLocation` 誘導、XXE インジェクションを引き起こす DTD / 外部実体宣言（`<!DOCTYPE`、`<!ENTITY %`）、または標準 Office スキーマを偽装するキリル文字等のホモグリフやゼロ幅スペースが含まれている。 |
| `VBA-CELL-050` | `SlicerOrTimelineCacheAnomaly` | **Critical** | Excel スライサーまたはタイムライン定義（`xl/slicers/`、`xl/timelines/`）やリレーションシップに NTLM 認証詐取を狙うリモート UNC 接続パス、危険な exploit URI スキーム（`ms-msdt:`、`search-ms:`、`mhtml:`、`javascript:`、`powershell:`）、実行可能・スクリプトターゲット（`.exe`、`.bat`、`.vbs`、`.ps1`、`.hta`）、データベースコマンド実行（`xp_cmdshell`、`sp_OACreate`、`OPENROWSET`）、または環境変数詐取トークン（`%USERNAME%`）が含まれている。 |
| `VBA-CELL-051` | `BibliographyOrCitationAnomaly` | **Critical** | Word 参考文献・引用文献定義（`word/bibliography/sources.xml`、`customXml/`）に NTLM 認証詐取を狙うリモート UNC パス、危険な exploit URI スキーム（`ms-msdt:`、`search-ms:`、`ms-appinstaller:`、`mhtml:`、`powershell:`）、シェル実行コマンド（`powershell`、`cmd.exe`、`wscript.exe`、`cscript.exe`、`mshta`、`rundll32`、`certutil`）、または密輸された Windows PE バイナリが含まれている。 |
| `VBA-CELL-052` | `CustomXmlDataBindingOrXPathAnomaly` | **Critical** | 構造化ドキュメントタグ（SDT）またはカスタム XML データバインディング（`<w:dataBinding>`、`<m:dataBinding>`、`<p:dataBinding>`）において、SSRF や NTLM 認証詐取を引き起こす外部ドキュメント解決関数（`document()`、`doc()`）を含む XPath クエリ、データベース・シェルコマンドインジェクション、または `prefixMappings` や `storeItemID` 内のリモート UNC / exploit プロトコル名前空間宣言が含まれている。 |
| `VBA-CELL-053` | `XmlMapsOrSchemaDefinitionAnomaly` | **Critical** | Excel XML マップ定義（`xl/xmlMaps.xml`）、テーブル XML カラムマッピング（`xl/tables/table*.xml`）、またはリレーションシップに NTLM 認証詐取を狙うリモート UNC パス、危険な exploit URI スキーム（`ms-msdt:`、`search-ms:`、`ms-appinstaller:`、`mhtml:`、`powershell:`）、XXE DTD/外部実体宣言、密輸された Windows PE 実行バイナリ、シェル実行コマンド（`powershell`、`cmd.exe`、`wscript.exe`）、またはテーブル列 XPath SSRF 外部ドキュメント解決関数（`document()`、`doc()`）が含まれている。 |
| `VBA-CELL-054` | `CommentAnnotationOrAuthorAnomaly` | **Critical** | ドキュメントコメントおよびモダン注釈パーツ（`word/comments*.xml`、`ppt/comments/*.xml`、`ppt/modernComments/*.xml`、`xl/comments*.xml`、`xl/threadedComments/*.xml`）やリレーションシップに NTLM 認証詐取を狙うリモート UNC パス、危険な exploit URI スキーム、密輸された Windows PE 実行バイナリ、シェル実行コマンド（`powershell`、`cmd.exe`、`mshta`、`rundll32`）、または実行可能ペイロードターゲット（`.exe`、`.bat`、`.ps1`、`.hta`、`.lnk`）が含まれている。 |
| `VBA-CELL-055` | `ThemeFontOrEffectCoercionAnomaly` | **Critical** | Office テーマパーツ（`*/theme/theme*.xml`、`themeOverride*.xml`）またはリレーションシップにおいて、フォント typeface 定義（`<a:latin typeface="\\..."/>`、`<a:ea typeface="\\..."/>`、`<a:cs typeface="\\..."/>`）に NTLM 認証詐取やフォントエンジン脆弱性悪用を狙うリモート UNC パス、危険な exploit URI スキーム、外部リモートテーマ/テンプレート参照、または密輸された Windows PE バイナリが含まれている。 |
| `VBA-CELL-056` | `CustomXmlPropertiesOrItemSchemaAnomaly` | **Critical** | Custom XML アイテムプロパティ（`customXml/itemProps*.xml`）、データパーツ、またはリレーションシップにおいて、スキーマ参照（`ds:schemaRef`、`targetNamespace`、`schemaRef`）に NTLM 認証詐取を狙うリモート UNC パス、危険な exploit URI スキーム（`ms-msdt:`、`search-ms:`、`ms-appinstaller:`、`mhtml:`、`powershell:`）、外部実行ファイル参照、または密輸された Windows PE バイナリが含まれている。 |
| `VBA-CELL-057` | `VbaDataStreamOrProjectRelsAnomaly` | **Critical** | VBA プロジェクトリレーションシップ（`xl/_rels/vbaProject.bin.rels`、`vbaProjectSignature*.bin.rels`）または補助 VBA データストリーム（`xl/vbaData.xml`）に、リモート UNC パスやバイナリへの外部リレーション、危険な exploit URI スキーム、密輸された Windows PE 実行可能バイナリ、またはシェル実行コマンドが含まれている。 |
| `VBA-CELL-058` | `WordGlossaryOrBuildingBlocksRelsAnomaly` | **Critical** | Word 用語集・文書パーツ定義（`word/glossary/settings.xml`、`document.xml`）またはリレーションシップにおいて、`attachedTemplate` による外部テンプレートへのリモートテンプレートインジェクション、NTLM 認証詐取を狙うリモート UNC パス、危険な exploit URI スキーム、外部実行ファイル参照、または密輸された Windows PE バイナリが含まれている。 |
| `VBA-CELL-059` | `WordDocVariablesOrNotesAnomaly` | **Critical** | Word ドキュメント変数（`word/settings.xml` `<w:docVars>`）、脚注（`word/footnotes.xml`）、または文末脚注（`word/endnotes.xml`）に、密輸された Windows PE バイナリ、シェル実行コマンド、危険な exploit URI スキーム（`ms-msdt:`、`search-ms:`、`mhtml:`、`powershell:`）、NTLM 認証詐取を狙うリモート UNC パス、または実行可能・スクリプトターゲットへの外部リレーションが含まれている。 |
| `VBA-CELL-060` | `PowerPointTagsOrMastersAnomaly` | **Critical** | PowerPoint プログラマブルタグ（`ppt/tags/tag*.xml`）、プレゼンテーションリレーションシップ、フォントテーブル、配布資料マスタ、またはノートマスタに、密輸された Windows PE バイナリ、シェル実行コマンド、危険な exploit URI スキーム、NTLM 認証詐取を狙うリモート UNC パス、または外部実行ファイル参照が含まれている。 |
| `VBA-CELL-061` | `ScenarioManagerOrConsolidationAnomaly` | **Critical** | Excel シナリオマネージャー定義（`xl/scenarios/`、`<scenarios>`）、シナリオ入力セル、または統合（Consolidation）参照に、隠蔽 DDE 実行コマンド、Excel 4.0（XLM）マクロ実行関数（`EXEC(`、`CALL(`）、シェル実行コマンド、密輸された Windows PE バイナリ、または NTLM 認証詐取を狙うデータ統合リモート UNC ブックパスが含まれている。 |
| `VBA-CELL-062` | `PowerPointAnimationOrTimeNodeAnomaly` | **Critical** | PowerPoint スライドアニメーションタイミングノード（`ppt/slides/slide*.xml`）、メディアノード（`<p:cMediaNode>`、`<p:media>`）、またはスライドリレーションシップに、シェル実行コマンドトリガー（`<p:cmd>`）、NTLM 認証詐取を狙うリモート UNC メディアストリーム、危険な exploit URI スキーム、または密輸された Windows PE バイナリが含まれている。 |
| `VBA-CELL-063` | `WordHeaderFooterOrWatermarkAnomaly` | **Critical** | Word ヘッダー・フッター（`word/header*.xml`、`word/footer*.xml`）、VML 透かし（`<v:imagedata src="\\..."/>`）、またはリレーションシップに、NTLM 認証詐取を狙うリモート UNC パス、危険な exploit URI スキーム、実行可能・スクリプトターゲット、シェル実行コマンド、または密輸された PE バイナリが含まれている。 |
| `VBA-CELL-064` | `ExcelDataModelOrFormulaCacheAnomaly` | **Critical** | Excel DataModel 定義（`xl/model/dataModel.xml`）またはワークシート共有数式キャッシュ（`<f t="shared">`）に、NTLM 認証詐取を狙うリモート UNC 接続、データベースコマンド実行文字列（`xp_cmdshell`）、XXE 宣言、隠蔽 DDE 実行、または密輸された PE バイナリが含まれている。 |
| `VBA-CELL-065` | `ExcelPivotCacheOrDefinitionAnomaly` | **Critical** | Excel PivotCache 定義（`xl/pivotCache/pivotCacheDefinition*.xml`）、レコード（`pivotCacheRecords*.xml`）、またはリレーションシップに、NTLM 認証詐取を狙うリモート UNC 接続、データベースコマンド実行プロシージャ（`xp_cmdshell`）、危険な exploit URI スキーム、隠蔽 DDE 実行、または密輸された PE バイナリが含まれている。 |
| `VBA-CELL-066` | `WordOrPowerPointEmbeddedPackageAnomaly` | **Critical** | Word または PowerPoint 埋め込みパッケージ、OLE バイナリストリーム（`word/embeddings/*.bin`、`ppt/embeddings/*.bin`）、または自動有効化ディレクティブが、偽装された Windows PE 実行可能バイナリ（検証済み `MZ`/`PE\0\0` ヘッダー）、ステージングされたシェルスクリプト、リモート UNC パス、危険な exploit URI スキーム、または自動有効化 OLE ハンドラーを含んでいる。 |
| `VBA-CELL-067` | `ExcelExternalBookOrSheetPathAnomaly` | **Critical** | Excel 外部リンク定義（`xl/externalLinks/externalLink*.xml`）、リレーションシップ、または支援ブックキャッシュに、ファイル開放時に NTLM 認証詐取を狙うリモート UNC ブックパス、危険な exploit URI スキーム、定義名内の隠蔽 DDE 実行、または密輸された PE バイナリが含まれている。 |
| `VBA-CELL-068` | `ActiveXBinaryStorageOrPropertyStreamAnomaly` | **Critical** | ActiveX バイナリプロパティ永続化ストリーム（`xl/activeX/activeX*.bin`、`word/activeX/activeX*.bin`、`ppt/activeX/activeX*.bin`）やプロパティストレージストリームに、偽装された Windows PE 実行可能バイナリ（検証済み `MZ`/`PE\0\0` ヘッダー）、ステージングされたシェルスクリプト、NTLM 認証詐取を狙うリモート UNC パス、危険な exploit URI スキーム、または武器化 CLSID が含まれている。 |
| `VBA-CELL-069` | `XmlDigitalSignatureOrOriginPartAnomaly` | **Critical** | パッケージデジタル署名パーツ（`_xmlsignatures/origin.sigs`、`_xmlsignatures/sig*.xml`、`package.sigs`）に、NTLM 認証詐取を狙うリモート UNC ダイジェスト/参照 URI、危険な exploit URI スキーム、XSLT 変換実行フィルター、XXE 外部実体宣言、または Base64 密輸された PE バイナリが含まれている。 |
| `VBA-CELL-070` | `ExcelControlPropertiesOrFormActionAnomaly` | **Critical** | Excel フォームコントロールプロパティ（`xl/ctrlProps/ctrlProp*.xml`）やレガシー描画フォームアクションに、隠蔽 DDE 実行コマンド、Excel 4.0（XLM）マクロ実行関数、リモート UNC ブックパス、危険な exploit URI スキーム、またはステージングされたシェル実行コマンドを含むセル連携数式が設定されている。 |
| `VBA-CELL-071` | `PowerPointMediaTrackOrActionAnomaly` | **Critical** | PowerPoint メディアパーツ（`ppt/media/*`）、スライドメディアノード（`<p:cMediaNode>`）、またはタイミングトリガーに、Windows PE 実行バイナリ、ELF/Mach-O バイナリ、LNK ショートカット、ステージングされたシェルスクリプト、NTLM 認証詐取を強制するリモート UNC メディアストリーム、または危険な exploit URI スキームが含まれている。 |
| `VBA-CELL-072` | `ExcelTableOrSlicerNativeConnectionAnomaly` | **Critical** | Excel テーブル定義（`xl/tables/table*.xml`）、スライサー（`xl/slicers/slicer*.xml`）、またはタイムラインキャッシュに、NTLM 認証詐取を狙うリモート UNC 接続、スライサーキャプションや数式内の隠蔽 DDE 実行、データベースコマンド実行プロシージャ、または密輸された PE バイナリが含まれている。 |
| `VBA-CELL-073` | `WordMailMergeHeaderSourceOrRecipientAnomaly` | **Critical** | Word 差し込み印刷設定（`word/settings.xml` `<w:mailMerge>`）または宛先データキャッシュに、NTLM 認証詐取を狙うリモート UNC ヘッダーソース、危険な exploit URI スキーム、武器化された外部リレーションシップターゲット、または SQL クエリコマンドインジェクションが含まれている。 |
| `VBA-CELL-074` | `PowerPointSlideShowOrPresentationPropsAnomaly` | **Critical** | PowerPoint プレゼンテーションプロパティ（`ppt/presProps.xml`）、表示設定（`ppt/viewProps.xml`）、またはプレゼンテーション XML に、NTLM 認証詐取を狙うリモート UNC パス、危険な exploit URI スキーム、全画面ループ/遠隔ブロードキャストを組み合わせたキオスクモードUIロックアップ、またはステージングされたシェル実行コマンドが含まれている。 |
| `VBA-CELL-075` | `ExcelThreadedCommentOrPersonAnomaly` | **Critical** | Excel スレッド化コメントパーツ（`xl/threadedComments/threadedComment*.xml`）、メンション対象者（`xl/persons/person*.xml`）、またはコメント作成者メタデータに、隠蔽 DDE 実行数式文字列（`=cmd|`, `=powershell|`）、NTLM 認証詐取を狙うリモート UNC メンションパス、危険な exploit URI スキーム、またはステージングされたシェル実行コマンドが含まれている。 |
| `VBA-CELL-076` | `OfficeThemeOverrideOrFormatSchemeAnomaly` | **Critical** | Office テーマ上書き定義（`xl/theme/themeOverride*.xml`、`word/theme/themeOverride*.xml`、`ppt/theme/themeOverride*.xml`）、書式スキーム、またはテーマリレーションシップに、NTLM 認証詐取を狙うリモート UNC フォント/テーマ参照、危険な exploit URI スキーム、武器化された外部リレーションシップターゲット、またはステージングされたシェル実行コマンドが含まれている。 |
| `VBA-CELL-077` | `PowerPointSyncOrCommentAuthorsAnomaly` | **Critical** | PowerPoint コメント作成者情報（`ppt/commentAuthors.xml`）、同期情報（`ppt/syncInfo.xml`）、またはスライド同期パーツに、NTLM 認証詐取を狙うリモート UNC 参照、隠蔽された DDE コマンド数式、危険な exploit URI スキーム、またはステージングされたシェル実行コマンドが含まれている。 |
| `VBA-CELL-078` | `WordKeyMapOrCustomizationAnomaly` | **Critical** | Word キーボード割り当て定義（`word/keyMap.xml`）またはカスタマイズパーツ（`word/customizations.xml`、`word/customizations.bin`）に、悪意あるマクロやシェルコマンドにバインドされたショートカットキー、NTLM 認証詐取を狙うリモート UNC 参照、危険な exploit URI スキーム、または武器化された外部リレーションシップターゲットが含まれている。 |
| `VBA-CELL-079` | `ExcelWebPublishingOrSparklineAnomaly` | **Critical** | Excel Web 発行設定（`xl/webPublishing.xml`）、発行項目（`xl/webPublishItems.xml`）、またはスパークライングループに、静的データ持ち出しや NTLM 認証詐取を狙うリモート UNC 発行先、危険な exploit URI スキーム、またはステージングされたシェル実行コマンドが含まれている。 |
| `VBA-CELL-080` | `PowerPointHandoutOrNotesMasterAnomaly` | **Critical** | PowerPoint 配布資料マスター（`ppt/handoutMasters/handoutMaster*.xml`）、ノートマスター（`ppt/notesMasters/notesMaster*.xml`）、またはリレーションシップパーツに、NTLM 認証詐取を狙うリモート UNC 参照、隠蔽された DDE コマンド数式、危険な exploit URI スキーム、またはステージングされたシェル実行コマンドが含まれている。 |
| `VBA-CELL-081` | `WordGlossarySettingsOrFontTableAnomaly` | **Critical** | Word 用語集設定（`word/glossary/settings.xml`）、Web 設定（`word/glossary/webSettings.xml`）、またはフォントテーブル（`word/glossary/fontTable.xml`）に、NTLM 認証詐取を狙うリモート UNC 参照、マクロ自動実行フック、危険な exploit URI スキーム、または武器化された外部リレーションシップターゲットが含まれている。 |
| `VBA-CELL-082` | `ExcelCustomPropertyOrCustomDataAnomaly` | **Critical** | Excel カスタムプロパティ（`xl/customProperty*.bin`）、カスタムデータ（`xl/customData/customData*.xml`）、またはデータモデルバイナリに、NTLM 認証詐取を狙うリモート UNC 参照、危険な exploit URI スキーム、シリアライズされた .NET バイナリフォーマッターマーカー、またはステージングされたシェル実行コマンドが含まれている。 |

- **コンテナレベル脅威検査**: マクロが存在しない DOCX/XLSX コンテナであっても、OOXML リレーションシップ、描画オブジェクト、外部データ接続、埋め込み SVG ベクター画像、デジタル署名、Word フィールドコード（`w:fldSimple`、`w:instrText`）、PowerPoint スライドアクション、AltChunk ペイロード密輸パーツ構造、Custom UI リボン XML コールバック、レガシーダイアログシート、`[Content_Types].xml` MIME 宣言、外部リンクキャッシュ（`xl/externalLinks/`）、Word Web設定フレームセット（`word/webSettings.xml`）、ワークブック保護隠蔽構造（`xl/workbook.xml`）、密輸された実行可能バイナリ・PE偽装ヘッダー（`VBA-CELL-032`）、ワークシートビュー非表示・スクロール隠蔽（`VBA-CELL-033`）、ActiveX オブジェクト CLSID / プロパティ定義（`VBA-CELL-034`）、Word用語集ドキュメントインジェクション（`VBA-CELL-035`）、埋め込みフォントペイロード密輸・ODTTF難読化（`VBA-CELL-036`）、デジタルインク異常アクション（`VBA-CELL-037`）、ドキュメントプロパティペイロード密輸（`VBA-CELL-038`）、Webアドイン・作業ウィンドウ自動表示異常（`VBA-CELL-039`）、PivotCacheデータ接続異常（`VBA-CELL-040`）、メタファイル脆弱性・PE偽装（`VBA-CELL-041`）、XSLTスクリプトインジェクション（`VBA-CELL-042`）、リレーションシップ偽装・プロトコル難読化回避（`VBA-CELL-043`）、SmartArt・ダイアグラム操作・ペイロード密輸（`VBA-CELL-044`）、Word差し込み印刷データソース偽装・NTLM誘導（`VBA-CELL-045`）、Excel QueryTable外部クエリ悪用（`VBA-CELL-046`）、Excel Power Query M式・Data Mashup異常（`VBA-CELL-047`）、OLE Moniker・パッケージ自動有効化・アイコン偽装（`VBA-CELL-048`）、XML名前空間偽装・スキーマ誘導・XXEインジェクション（`VBA-CELL-049`）、Excel スライサー・タイムラインキャッシュ異常（`VBA-CELL-050`）、Word 参考文献・引用文献異常（`VBA-CELL-051`）、カスタム XML SDT データバインディング・XPath インジェクション（`VBA-CELL-052`）、XML マップおよびテーブルスキーマ（`VBA-CELL-053`）、ドキュメントコメント・モダン注釈（`VBA-CELL-054`）、テーマフォント・リモートテンプレート誘導（`VBA-CELL-055`）、カスタム XML プロパティ・スキーマ異常（`VBA-CELL-056`）、VBA プロジェクトリレーション・データストリーム異常（`VBA-CELL-057`）、Word 用語集・文書パーツリレーション異常（`VBA-CELL-058`）、Word ドキュメント変数・脚注異常（`VBA-CELL-059`）、PowerPoint タグ・マスタースライド異常（`VBA-CELL-060`）、Excel シナリオ・データ統合異常（`VBA-CELL-061`）、PowerPoint アニメーション・タイムノード異常（`VBA-CELL-062`）、Word ヘッダー・フッター・透かし異常（`VBA-CELL-063`）、Excel DataModel・数式キャッシュ異常（`VBA-CELL-064`）、Excel PivotCache・定義異常（`VBA-CELL-065`）、Word・PowerPoint 埋め込みパッケージ異常（`VBA-CELL-066`）、Excel 外部リンク・シートパス異常（`VBA-CELL-067`）、ActiveX バイナリプロパティ永続化ストリーム異常（`VBA-CELL-068`）、XML デジタル署名・起点パーツ異常（`VBA-CELL-069`）、Excel フォームコントロールプロパティ・フォームアクション異常（`VBA-CELL-070`）、PowerPoint メディアトラック・スライドアクション異常（`VBA-CELL-071`）、Excel テーブル・スライサーネイティブ接続異常（`VBA-CELL-072`）、Word 差し込み印刷ヘッダーソース・宛先異常（`VBA-CELL-073`）、PowerPoint プレゼンテーションプロパティ・スライドショー異常（`VBA-CELL-074`）、Excel スレッド化コメント・人物メタデータ異常（`VBA-CELL-075`）、Office テーマ上書き・書式スキーム異常（`VBA-CELL-076`）、PowerPoint 同期・コメント作成者異常（`VBA-CELL-077`）、Word キーマップ・カスタマイズ異常（`VBA-CELL-078`）、Excel Web発行・スパークライン異常（`VBA-CELL-079`）、PowerPoint 配布資料・ノートマスター異常（`VBA-CELL-080`）、Word 用語集設定・フォントテーブル異常（`VBA-CELL-081`）、および Excel カスタムプロパティ・カスタムデータ異常（`VBA-CELL-082`）からリモートテンプレートインジェクション、埋め込み OLE パッケージ、外部 Moniker リンク、ActiveX コントロール、プリンター設定 UNC 誘導、カスタム XML ペイロード密輸、描画ホバー/マクロアクション、外部データ接続 / NTLM 誘導、SVG スクリプト、署名改竄/剥奪、および危険なプロトコルハンドラーを自動検出。
- **動的数式難読化解除**: ワークブック全体のセルグリッドにまたがる難読化数式を、金利変換（`EFFECT()`、`NOMINAL()`）、元利均等・元金均等返済および累積償却（`IPMT()`、`PPMT()`、`CUMIPMT()`、`CUMPRINC()`）、逆二項分布（`CRITBINOM()`、`BINOM.INV()`）、キャッシュフロー評価・内部収益率（`IRR()`、`MIRR()`）、割引債券価格・利回り（`DISC()`、`PRICEDISC()`、`RECEIVED()`）、離散超幾何分布（`HYPGEOMDIST()`、`HYPGEOM.DIST()`）、財務評価・償却関数（`SLN()`、`SYD()`、`NPV()`、`PV()`、`FV()`、`PMT()`）、離散・連続確率分布（`LOGNORMDIST()`、`LOGNORM.DIST()`、`POISSON()`、`POISSON.DIST()`、`BINOMDIST()`、`BINOM.DIST()`）、統計・正規分布関数（`STANDARDIZE()`、`NORMSDIST()`、`NORM.S.DIST()`、`NORMDIST()`、`NORM.DIST()`）、指数分布・ワイブル信頼性分布（`EXPONDIST()`、`EXPON.DIST()`、`WEIBULL()`、`WEIBULL.DIST()`）、距離・質量・時間・温度・圧力・力・エネルギー・仕事率・体積・面積・情報メモリの物理単位変換（`CONVERT()`）、数式検査・エラー分類述語（`ISFORMULA()`、`ERROR.TYPE()`）、ベッセル関数（`BESSELJ()`、`BESSELI()`、`BESSELY()`、`BESSELK()`）、誤差関数・相補誤差関数（`ERF()`、`ERF.PRECISE()`、`ERFC()`、`ERFC.PRECISE()`）、確率・標準正規分布密度関数（`GAUSS()`、`PHI()`）、複素数偏角・共役（`IMARGUMENT()`、`IMCONJUGATE()`）、複素数三角関数・対数関数（`IMSIN()`、`IMCOS()`、`IMTAN()`、`IMSINH()`、`IMCOSH()`、`IMSEC()`、`IMCSC()`、`IMCOT()`、`IMLOG10()`、`IMLOG2()`）、ガンマ関数・対数ガンマ関数（`GAMMA()`、`GAMMALN()`）、複素数四則演算・累乗・初等超越関数（`IMSUM()`、`IMSUB()`、`IMPRODUCT()`、`IMDIV()`、`IMPOWER()`、`IMSQRT()`、`IMEXP()`、`IMLN()`）、重複組合せ・重複順列（`COMBINA()`、`PERMUTATIONA()`）、整数偶奇判定述語（`ISODD()`、`ISEVEN()`）、複素数構築・二乗差和・多項係数（`COMPLEX()`、`IMREAL()`、`IMAGINARY()`、`IMABS()`、`IMCONJG()`、`SUMXMY2()`、`SUMX2MY2()`、`SUMX2PY2()`、`MULTINOMIAL()`）、行列式・逆行列計算（`MDETERM()`、`MINVERSE()`）、整数丸め・級数多項式総和（`INT()`、`SERIESSUM()`）、行列演算（`MMULT()`、`MUNIT()`）、割線・余割・余接三角関数および双曲線関数（`SEC()`、`CSC()`、`COT()`、`SECH()`、`CSCH()`、`COTH()`）、逆余接関数（`ACOT()`、`ACOTH()`）、双曲線関数・逆双曲線関数（`SINH()`、`COSH()`、`TANH()`、`ASINH()`、`ACOSH()`、`ATANH()`）、$\pi$ 乗算平方根（`SQRTPI()`）、平方和（`SUMSQ()`）、数学定数・指数関数（`PI()`、`EXP()`）、対数計算（`LN()`、`LOG10()`、`LOG()`）、順列・組合せ（`COMBIN()`、`PERMUT()`）、多次元配列内積総和（`SUMPRODUCT()`）、動的配列シーケンス生成（`SEQUENCE()`）、暗黙的共通集合スカラー抽出（`SINGLE()`）、Excel 365 動的配列連結（`VSTACK()`、`HSTACK()`）、論理分岐（`IFS()`、`SWITCH()`、`XOR()`）、ラムダヘルパー関数（`MAP()`、`REDUCE()`、`SCAN()`、`BYROW()`、`BYCOL()`、`MAKEARRAY()`、`ISOMITTED()`）、ネイティブ配列定数リテラル（`{...}`）、カスタムラムダ関数評価（`LAMBDA()`）、スコープ変数定義評価（`LET()`）、動的 URL エンコード（`ENCODEURL()`）、基数変換（`BIN2HEX()`、`HEX2BIN()`、`OCT2HEX()`、`HEX2OCT()`、`BASE()`、`DECIMAL()`、`HEX2DEC()`、`BIN2DEC()`）、ロケール非依存数値解析（`NUMBERVALUE()`）、動的セル参照解決（`INDIRECT()`、`OFFSET()`、`ADDRESS()`）、セル間数式検査（`FORMULATEXT()`）、動的配列フィルタリング・ソート（`FILTER()`、`SORT()`、`SORTBY()`、`UNIQUE()`、`WRAPROWS()`、`WRAPCOLS()`）、ビット演算復号（`BITXOR()`、`BITAND()`、`BITOR()`、`BITLSHIFT()`、`BITRSHIFT()`）、ローマ数字変換（`ROMAN()`、`ARABIC()`）、最新動的配列変形（`TAKE()`、`DROP()`、`CHOOSEROWS()`、`CHOOSECOLS()`、`TOROW()`、`TOCOL()`、`EXPAND()`）、最新動的検索（`XLOOKUP()`、`XMATCH()`）、配列転置（`TRANSPOSE()`）、ベクトル/配列検索（`LOOKUP()`）、ブランチレス条件評価（`DELTA()`、`GESTEP()`、`SIGN()`）、DBCS 2バイト文字スライス（`LENB()`、`LEFTB()`、`RIGHTB()`、`MIDB()`）、整数除算・偶数奇数丸め（`QUOTIENT()`、`EVEN()`、`ODD()`）、階乗計算（`FACT()`、`FACTDOUBLE()`）、数論約数倍数（`GCD()`、`LCM()`）、テキスト分解・シリアライズ（`TEXTBEFORE()`、`TEXTAFTER()`、`TEXTSPLIT()`、`ARRAYTOTEXT()`、`VALUETOTEXT()`）、複数セル範囲結合（`CONCAT()`、`TEXTJOIN()`）、2D テーブル参照（`INDEX()`、`VLOOKUP()`、`HLOOKUP()`、`MATCH()`）、Unicode 変換（`UNICHAR()`、`UNICODE()`）、および文字列・数学・型検査関数（`CHAR()`、`MID()`、`SUBSTITUTE()`、`CHOOSE()`、`HYPERLINK()`、`ROWS()`、`COLUMNS()`、`MROUND()`、`TYPE()`、`ISNONTEXT()`）を有界評価することで、静的パターン照合を回避する隠蔽 LOLBins、セル連携 DDE 実行、RTD COM オートメーション、遠隔ダウンロードペイロードを動的に復元検知。
- **全角文字難読化回避の正規化**: 数式検査前に全角英数字・記号（`U+FF01`〜`U+FF5E`、`U+3000`）を標準 ASCII に正規化し、難読化による検知回避を無力化。

---

## 構文・意味解析エンジンの詳細

- UTF-8 バイトスパンおよび正確な行・列番号を保持しながら VBA コードをトークン化。
- 全角スペース（`U+3000`）を含む VBA 仕様準拠の空白文字を、識別子文字ではなく区切り文字として正確に処理。
- 条件付きコンパイル（`#If`、`#Const`）の行継続ルールを忠実に反映し、除外ブロックをマスクしつつ論理行を維持。
- モジュール宣言、プロシージャ（`Sub`、`Function`、`Property`）、引数、変数宣言、`Type` / `Enum` ブロック、制御構文（`If`、`Select Case`、各種ループ、`With`、ラベル、`GoTo`、計算型 `On...GoTo` / `On...GoSub`）を構文解析。
- 式の優先順位、ドットメンバアクセス、感嘆符辞書アクセス、型サフィックス（`!`、`#`、`$`、`%`、`&`、`@`、`^`）の解決。
- 構造的制御フローグラフ（CFG）、到達定義、非巡回定数伝播・畳み込み、エラー伝播グラフの構築。
- `.xlsm`、`.xlsb`、`.docm`、`.pptm`、旧形式 `.xls`、生バイナリ `vbaProject.bin` からの MS-OVBA 解凍、Compound File Binary（CFB）ストリーム解析、および OPC パッケージ解決。

---

## セキュリティ境界 & 安全性の保証

- **コード実行の完全排除**: ホストスクリプトエンジン、Office オートメーション、JIT ランタイムを実行することは一切ありません。
- **ネットワークアクセスの完全遮断**: 本クレートはネットワーク通信機能を一切含んでおらず、外部へのリクエスト送信も行いません。
- **厳格なリソース制限**: ZIP 爆弾、解凍ループ、CFB ミニストリーム循環参照攻撃を防ぐため、厳格な再帰深度・バッファ割り当て制限（`Limits::bounded()`）を実装。
- **静的近似の境界**: 制御フローパスは構造的な候補を示したものであり、動的実行を証明するものではありません。レイトバインド、動的ホスト評価（`Evaluate`）、未モデル化の外部タイプライブラリは明示的に未解決として扱われます。

---

## ドキュメント & 関連情報

- [アーキテクチャおよび解析モデル詳細](docs/ARCHITECTURE_JA.md)
- [仕様およびフォーマットの出所 (PROVENANCE)](docs/PROVENANCE.md)
- [今後のロードマップ (ROADMAP)](docs/ROADMAP_JA.md)
- [パッケージ公開 & リリース手順ガイド](docs/PUBLISHING.md)
- [コントリビューションガイド](CONTRIBUTING.md)
- [ライセンス (MIT)](LICENSE)

ソースリポジトリ: [ryusui-hiro/vba-retrace](https://github.com/ryusui-hiro/vba-retrace)
