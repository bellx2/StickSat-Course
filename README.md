# FlatSat-Geek Course

USB でつなぐ衛星セキュリティ演習ボード **FlatSat-Geek**（RP2350-GEEK、画面付き、無線なし）で学ぶ、初心者向けの演習です。

> 状態: 作成中。段階カード 01〜06 と手順書の本文はそろいましたが、実機での通しの確認はまだです。

## この演習でやること

衛星の通信システムを題材に、意図的に脆弱な模擬機を**自分が所有するボード**に対して攻撃し、
「なぜ成立したか」と「どう直すか」までを学びます。全段階 USB だけで完結し、電波は一切送信しません。

## 進め方

各段階は同じ流れです。

1. 背景を読む
2. **予想する**（実行前に、何が起きるか考える）
3. 操作する
4. 観察する（ボードの返事と、画面の変化を見る）
5. 解説を読んで、**直し方**を考える

AI アシスタントを使うことを前提にしています。使い方は [docs/how-to-use-ai.md](docs/how-to-use-ai.md) を読んでください。

## 段階

| # | テーマ | ねらい | 元の攻撃 |
|---|---|---|---|
| 1 | [偵察](stages/01-recon.md) | 使える命令を自分で調べる | `00` |
| 2 | [リプレイ](stages/02-replay.md) | 暗号は「新しさ」を保証しない | `05` |
| 3 | [認証のないコマンド](stages/03-command-injection.md) | 誰が送ったかを確認しない命令 | `02` |
| 4 | [位置のなりすまし](stages/04-position-spoofing.md) | 位置情報が権限になる危うさ | `03` |
| 5 | [地上局のなりすまし](stages/05-gs-auth-spoofing.md) | 弱い認証と、攻撃の連鎖 | `04` |
| 6 | [暗号のダウングレード](stages/06-downgrade.md) | 1 バイトで暗号が切れる | `07` |

「元の攻撃」の番号は [attacks/](attacks/) のものです。`attacks/` は [JP-Bootcamp](https://github.com/bellx2/JP-Bootcamp) の `attacks/` を同梱し、コメントを日本語にしたものです（GPL-3.0-or-later、[attacks/NOTICE.md](attacks/NOTICE.md)）。
[tools/](tools/) は、カードの手順で使う小さな補助スクリプトです（`attacks/lib` を使います）。

## 用意するもの

- FlatSat-Geek（書き込み済みのボード。または RP2350-GEEK に [FlatSat-Geek](https://github.com/bellx2/FlatSat-Geek) の UF2 を書き込んだもの）
- PC（Python 3 と [uv](https://docs.astral.sh/uv/)）
- JP-Bootcamp（Space IDS に使う。[docs/00-start.md](docs/00-start.md) を参照）。なくてもボード単体で進められる（アラートの観察だけできなくなる。同 §6）

## 注意

- 攻撃の対象は、**自分が所有するボードだけ**です。AI に手伝わせる場合も同じです。
- 学習・研究目的に限ります。実在する衛星や機器には使えません。
- 10 種類を連続で実行しないでください。1 つずつ実行し、合間にリセットします（[docs/00-start.md](docs/00-start.md)）。

## 元のプロジェクト

| プロジェクト | ライセンス | 関係 |
|---|---|---|
| [Pwnsat/FlatSat](https://github.com/Pwnsat/FlatSat)（astrobyte / Cromulence / Hack-A-Sat） | GPL-2.0-or-later | 元の脆弱な衛星模擬機・攻撃スクリプト |
| [r0r0x-xx/JP-Bootcamp](https://github.com/r0r0x-xx/JP-Bootcamp) | `firmware/` は GPL-2.0-or-later、`c3/` は MIT（一部 GPL-3.0）、その他は GPL-3.0-or-later | 2 日間の講座・攻撃スクリプト・Space IDS |
| [bellx2/JP-Bootcamp](https://github.com/bellx2/JP-Bootcamp) | 上と同じ | 上の日本語化 fork（README とドキュメントのみ翻訳） |
| [bellx2/FlatSat-Geek](https://github.com/bellx2/FlatSat-Geek) | GPL-2.0-or-later | RP2350-GEEK 向けファームウェア |

## ライセンス

このリポジトリは、部分ごとにライセンスが異なります。

| 対象 | ライセンス |
|---|---|
| 演習の文章（`stages/`、`docs/`、`README.md`、`AGENTS.md`） | [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/deed.ja) |
| 攻撃スクリプト（`attacks/`） | GPL-3.0-or-later（JP-Bootcamp からの同梱。[attacks/NOTICE.md](attacks/NOTICE.md)） |
| 補助スクリプト（`tools/`） | GPL-3.0-or-later（`attacks/lib` を使うため） |

- 文章を再利用するときは、出典（このリポジトリ）を示し、同じ CC BY-SA 4.0 で公開してください。
- 元のプロジェクトとそのライセンスは、上の「元のプロジェクト」にあります。
- 詳しくは [LICENSE](LICENSE) を参照してください。
