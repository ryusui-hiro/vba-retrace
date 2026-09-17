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
    inspect_macro_file, inspect_to_markdown, stomping_to_sarif, AnalysisOptions,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let container_bytes = std::fs::read("suspicious.xlsm")?;
    let options = AnalysisOptions::default();

    // コンテナ検査: ストリーム抽出、AST 解析、P-Code 逆アセンブル、Stomping 検知を一括実行
    let inspection = inspect_macro_file(&container_bytes, &options)?;

    println!("抽出モジュール数: {}", inspection.extracted.modules.len());
    println!("Stomping 検知の有無: {}", inspection.stomping_report.is_stomped);

    // GitHub Code Scanning 用の SARIF v2.1.0 を生成
    let sarif = stomping_to_sarif(&inspection.stomping_report, "suspicious.xlsm");
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

    if report.is_stomped {
        eprintln!("警告: VBA Stomping を検知しました！ 発見数: {}", report.findings.len());
        for finding in &report.findings {
            eprintln!(" - [{:?}] {}: {}", finding.severity, finding.rule_id, finding.description);
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

# 2. ワークシートの危険なセル数式（DDE, XLM, WEBSERVICE）を検査
analysis = report.get("analysis", {})
workbook = analysis.get("workbook_structure", {})
cell_threats = workbook.get("cell_threats", [])
if cell_threats:
    print(f"[!] {len(cell_threats)} 個の危険なセル数式を検出:")
    for threat in cell_threats:
        print(f"  - {threat['coordinate']}: {threat['threat_kind']} ({threat['formula']})")

# 3. GitHub Advanced Security / CI 統合用の OASIS SARIF v2.1.0 レポートを出力
sarif_json = vba_insight.inspect_file_sarif("suspicious.xlsm")
with open("security_report.sarif", "w", encoding="utf-8") as f:
    f.write(sarif_json)

# 4. 整形済み Markdown 検査サマリーを取得
markdown_summary = vba_insight.inspect_file_markdown("suspicious.xlsm")
print(markdown_summary)

# 5. 純粋な VBA ソースコードの静的構文解析
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
  for (const finding of report.stomping.project_findings) {
    console.error(`  - [${finding.rule_id}] ${finding.description}`);
  }
}

// 3. CI コードスキャン用の SARIF v2.1.0 レポートを出力
const sarifReport = inspectMacroFileSarif(fileBuffer, 'suspicious.xlsm');
fs.writeFileSync('macro-scan.sarif', sarifReport);

// 4. GitHub 形式の Markdown 検査レポートを生成
const markdownReport = inspectMacroFileMarkdown(fileBuffer);
console.log(markdownReport);

// 5. VBA ソースコードの静的解析
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

### 2. ワークシート・セル & ブック脅威スキャナー

ワークシートのセル数式、定義名、シートメタデータを検査します。

- **DDE（Dynamic Data Exchange）インジェクション**: `=cmd|'/c calc'!A0` や `="cmd.exe"|...` などの DDE 実行数式を検出。
- **旧形式 XLM 4.0 マクロ**: `=EXEC(...)`、`=CALL(...)`、`=REGISTER(...)` 等の Excel 4.0 マクロ数式を検出。
- **データ外部持ち出し（Data Exfiltration）**: 機密セル情報を外部サーバーへ自動送信可能な `=WEBSERVICE(...)` 数式を検出。
- **リモートインジェクション**: UNC リモートパス（`\\attacker\share`）やリモート URL（`http://`、`ftp://`）を検知。
- **不審なハイパーリンク**: 実行可能ファイルやスクリプト（`.exe`、`.scr`、`.bat`、`.ps1`、`.vbs`、`.js`）を指す `=HYPERLINK(...)` 数式を検知。
- **全角文字難読化回避の正規化**: 数式検査前に全角英数字・記号（`U+FF01`〜`U+FF5E`、`U+3000`）を標準 ASCII に正規化し、難読化による検知回避を無力化。
- **ブック自動実行トリガー**: ブック定義名の `Auto_Open`、`_xlnm.Auto_Open`、`Auto_Close` 等の自動実行トリガーを検知。
- **veryHidden ワークシート検知**: 悪意あるマクロペイロードを隠蔽するためによく使われる、`state="veryHidden"` 属性を持つ不可視シートを検知。

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
