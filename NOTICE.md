# NOTICE

このリポジトリは、次のプロジェクトに基づく、または関連する教材です。

| プロジェクト | ライセンス | 関係 |
|---|---|---|
| [Pwnsat/FlatSat](https://github.com/Pwnsat/FlatSat) | GPL-2.0-or-later | 元の脆弱な衛星模擬機・攻撃スクリプト |
| [r0r0x-xx/JP-Bootcamp](https://github.com/r0r0x-xx/JP-Bootcamp) | `firmware/` は GPL-2.0-or-later、`c3/` は MIT（一部 GPL-3.0）、その他は GPL-3.0-or-later | 2 日間の講座・攻撃スクリプト・Space IDS |
| [bellx2/JP-Bootcamp](https://github.com/bellx2/JP-Bootcamp) | 上と同じ | 上の日本語化 fork（README とドキュメントのみ翻訳） |
| [bellx2/FlatSat-Geek](https://github.com/bellx2/FlatSat-Geek) | GPL-2.0-or-later | RP2350-GEEK 向けファームウェア |

## 確認事項（公開・販売の前に）

- [ ] 同梱した `attacks/`（GPL-3.0-or-later）を配布するときは、`attacks/LICENSE` と `attacks/NOTICE.md` を必ず一緒に配布する。スクリプトを変更した場合は、`attacks/NOTICE.md` に変更の旨と日付を書く。
- [ ] 販売物に `attacks/` を含める場合は、GPL-3.0 の条件（ソースの提供、追加の制限を付けない）を満たしているか確認する。
- [ ] 新しく書いた演習の文章に別のライセンス（CC BY-SA など）を付ける場合は、元の文章を含まないことを確認する。
- [ ] 商品ページの「ライセンス」欄を、実態に合わせて書く。
- [ ] 判断に迷う場合は、専門家に確認する。

## 方針

- 攻撃スクリプトは、JP-Bootcamp の `attacks/` を `attacks/` に同梱する。変更はコメントの日本語化と実行例だけにとどめ、コードの動作は変えない。出典とライセンスは `attacks/NOTICE.md` と `attacks/LICENSE` にある。
- Space IDS（センサー）は同梱せず、JP-Bootcamp のものを使う。
- 各段階の解説・ヒント・問いは、このリポジトリのオリジナルとして書く。
