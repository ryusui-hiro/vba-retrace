# 形式仕様と出所

この実装は公開仕様を確認して独自に記述しています。第三者の逆コンパイラー、既存パーサー、生成済み命令表、VBA文法ファイルからコードを移植していません。仕様の記述そのものをソースコードへ転載するのではなく、構造・境界・アルゴリズムを実装しています。

実装時に参照した一次資料:

- [MS-VBAL: VBA Language Specification](https://learn.microsoft.com/en-us/openspecs/microsoft_general_purpose_programming_languages/ms-vbal/d5418146-0bd2-45eb-9c7a-fd9502722c74) — 言語の構文、静的意味、実行時意味の範囲。
- [MS-CFB: Compound File Binary File Format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/53989ce4-7b05-4f8d-829b-d08d6148375b) — セクター、FAT、MiniFAT、ディレクトリとストリーム。
- [MS-OVBA: dir stream](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/3d07f2c3-dee0-4ae3-b91f-3e32b789c534) — プロジェクト、参照、モジュール情報。
- [MS-OVBA: Module Stream](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/c66b58a6-f8ba-4141-9382-0612abce9926) — モジュールキャッシュと圧縮ソースの境界。
- [MS-OVBA: Decompression Algorithm](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/492124cc-5afc-48c8-b439-b42ad7087a7b), [CompressedChunkHeader](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/ec1bc788-27de-47d9-8db4-6be2b5cff52b), and [CopyToken](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/c821c6f8-ec48-40a9-88fa-8c2b89589aec) — OVBA圧縮形式。
- [MS-OVBA: versioning and localization](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/4d20e95c-0c17-47d6-84b9-8da95d8ea129) — 性能キャッシュのバージョン依存性と相互運用上の扱い。
- [MS-Pcode-Assembler: Module Cache notes](https://github.com/Beakerboy/MS-Pcode-Assembler/blob/main/docs/Module_Cache.md) and [pyOpenVBA's p-code module](https://github.com/WilliamSmithEdward/pyOpenVBA/blob/main/src/pyopenvba/vba_pcode.py) — 非公式な、観測ベースのCAFE/行ディレクトリ資料。プロファイル選択型の生バイト境界検査の設計確認にだけ参照し、両リポジトリのソースコード、opcode表、テストファイルは取り込んでいません。これらの資料はMS-OVBAの規範的仕様ではありません。

公開仕様の確認は、特許、著作権、商標、顧客コードの権利確認を代替しません。バイナリのテストは本リポジトリ内で合成した小さなコンテナ・圧縮・p-code行マップに限定し、実際のOffice生成ブックでの互換性はまだ検証していません。実データを追加する場合は利用許諾・出所・Officeバージョンを記録してください。詳細はリポジトリのMIT `LICENSE`と貢献者が追加する第三者資料のライセンスを確認してください。
