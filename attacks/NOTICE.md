# attacks/ の出典とライセンス

このフォルダは、[bellx2/JP-Bootcamp](https://github.com/bellx2/JP-Bootcamp) の `attacks/` をコピーし、下の変更を加えたものです。

- 元: bellx2/JP-Bootcamp（[r0r0x-xx/JP-Bootcamp](https://github.com/r0r0x-xx/JP-Bootcamp) の日本語化 fork）
- コピー元のコミット: `58f434074bc1199cefbb195a3a3c99909c0c7e0e`（2026-11-23）
- 著作権: Copyright (C) 2026 Starsec
- ライセンス: GPL-3.0-or-later（[LICENSE](LICENSE)）
- 変更（2026-11-24）:
  - 各スクリプトの `#` コメントと docstring を日本語に書き換え、初心者向けに補足した。コード・出力される文字列は変えていない（docstring を除いた構文木が元と一致することを確認済み）。
  - 元のコメントのうち、コードと食い違っていた説明（存在しない `Bench/` フォルダ、`07` の `secure_link_bit` の戻り値、`lib/benchstate.py` のゲート状態の判定）は、訳す際にコードに合わせて直した。
  - 攻撃スクリプト 10 本の先頭の `#` コメントのかたまりを、そのまま docstring（`"""…"""`）にした。元のスクリプトは argparse に `description=__doc__` を渡しているが docstring がなく、`--help` に説明が出なかったため。コードは変えていない（docstring を除いた構文木が元と一致することを確認済み）。
  - `README.md` の実行例を `python3 ...` から `uv run python ...` に変えた。
  - `__pycache__` などの生成物は除いた。

このフォルダのスクリプトを変更して配布する場合は、GPL-3.0 の条件に従い、変更した旨と日付をここに書き足してください。
