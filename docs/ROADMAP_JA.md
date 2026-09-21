# 公開後ロードマップ

このプロジェクトは、VBAを実行せずに、根拠付きの構造・型・経路候補を抽出するRustライブラリです。`semantic_analysis_complete` は、ホストライブラリ、実行時Variant、動的dispatch、locale、Office固有のコンパイル済み命令表を含む未解決領域がある限り `false` です。

## 現在の基盤

- VBAエクスポートテキストのlexer/parser、型・宣言・CFG、`On Error`/`GoSub`を含むbounded経路解析。
- `.xlsm`、`.xlsb`、`.docm`、`.pptm`、レガシー`.xls`、生`vbaProject.bin`のZIP/OPC・CFB・MS-OVBA直接マクロ抽出。
- 組み込み標準VBA P-code命令スキーマ（VBA6/VBA7、32-bit/64-bit、全264 opcode）および`_VBA_PROJECT`識別子テーブル解決による高精度P-code逆アセンブラ。
- ソース非公開・隠しプロシージャ・不審な文字列・危険API呼出の乖離を自動診断するVBA Stomping・改竄検出エンジン。
- ワークシート危険セル脅威スキャン（DDE数式実行、XLM/Excel 4.0マクロ、RemoteLink、WEBSERVICE/FILTERXML、不審な外部URLハイパーリンク、自動実行定義名、`xlSheetVeryHidden`不可視化、XLMマクロシート）。
- エンドツーエンドの`inspect_macro_file`統合検査APIおよびCLIコマンド（`disasm`, `stomping`, `inspect`、`--format sarif|json|markdown|text`）。
- OASIS SARIF v2.1.0 準拠レポート出力（`stomping_to_sarif`, `inspection_to_sarif`）による GitHub Advanced Security / Code Scanning / CI 連携。
- Python（universal ABI3）および Node.js（N-API）向け高パフォーマンスネイティブバインディングの提供。
- ByRef、ParamArray slot、caller/callee戻り値、配列境界、Date/文字列/数値intrinsicの安全な部分集合。
- caller提供opcode/operand/semantic schemaによるp-code抽象stack、local slot、branch/path、Null/Empty/Error、float、known-return summary。
- source disclosure、有限resource limits、MITライセンス、CI、security policy、最低Rust版1.88.0の検証。

## 次に実装する範囲

1. 利用許諾を確認したOffice版ごとのp-code観測資料と標準スキーマの追加検証。資料のない未同定opcodeは推測せずUnknownのまま保持する。
2. Optional Variantの省略状態をcallsite/path単位で分離し、`IsMissing`へ実引数経路を接続するところまで実装済み。ParamArrayの空slot、動的・混在callsiteの完全な実行時状態は引き続き未解決。
3. literal/constantの`ReDim`/`Erase`状態と`LBound`/`UBound`をpath stateへ統合済み。Variant targetの`IsArray`と循環しない単純aliasにも伝播する。要素alias、固定配列boundsとの完全な共通state、Variant配列payload、動的shapeは引き続き候補または未解決。
4. `formula_eval::evaluate_formula`として、保存済みcacheを書き換えず、非formula cell値に対する純粋な算術・文字列・比較・限定集計/参照関数のbounded evaluatorを実装済み。`INDIRECT`、`OFFSET`、外部参照、formula cellの再帰再計算、locale依存関数は未解決。
5. Windows/macOS/Linuxのcode page・OOXML・CFB・MS-OVBA代表fixtureを、再配布可能性を確認した上でCI matrixへ追加する。

## 境界と検証方針

- Officeを起動せず、マクロを実行せず、ネットワークへ接続しない。
- すべての探索・展開・経路数に上限を設け、上限到達をtruncated/incompleteとして出力する。
- 実行可能性を証明できない関係は`not_checked`またはUnknownとして保持し、候補を事実と表示しない。
- 外部資料、実データfixture、opcode table、顧客Workbookは、ライセンスと秘密情報を確認しない限り取り込まない。
- リリース前には`CONTRIBUTING.md`のformat/test/clippy/doc/package手順、最低Rust版、CI publication checkをすべて通す。
