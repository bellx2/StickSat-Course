# StickSat Course

USB でつなぐ衛星セキュリティ演習ボード **StickSat**（RP2350-GEEK、画面付き、無線なし）で学ぶ、初心者向けの演習です。

> この演習は、[JP-Bootcamp](https://github.com/r0r0x-xx/JP-Bootcamp) の FlatSat を使った講座を日本語にし、AI アシスタントによる学習の支援を加えたものです。元の講座と攻撃スクリプトは JP-Bootcamp のもので、StickSat 向けに手順を組み直しています（詳しくは「[元のプロジェクト](#元のプロジェクト)」）。

## この演習でやること

衛星の通信システムを題材に、**自分が所有するボード**で動く、意図的に脆弱に作った衛星の模擬機（ファームウェア）を攻撃し、
「なぜ成立したか」と「どう直すか」までを学びます。全ステップ USB だけで完結し、電波は一切送信しません。

## はじめかた

このリポジトリを取得し、**そのフォルダで** AI アシスタントを起動します。

    git clone https://github.com/bellx2/StickSat-Course.git
    cd StickSat-Course
    claude        # Claude Code の場合。Codex なら codex

起動したら、次のように頼みます。

> 初めて使います。セットアップから手伝ってください。

- AI は、PC の OS、ボードが手元にあるか、センサー（IDS）を使うかを尋ねてから、[docs/00-start.md](docs/00-start.md) の順に 1 手順ずつ進めます。ほかに使うリポジトリ（JP-Bootcamp、StickSat）の取得も、その中で案内します。
- 必ずこのフォルダで起動してください。AI は起動したフォルダの `AGENTS.md`（Claude Code は `CLAUDE.md`）を読み、家庭教師としての振る舞い方を知ります。別のフォルダで起動して URL を渡すだけでは、この指示が読み込まれないことがあります。
- Claude Code や Codex のインストール、ChatGPT などのチャットで進める方法は、[docs/how-to-use-ai.md](docs/how-to-use-ai.md) を読んでください。
- AI を使わずに進める場合は、[docs/00-start.md](docs/00-start.md) から読み始めます。

## 進め方

各ステップは同じ流れです。

1. 背景を読む
2. **予想する**（実行前に、何が起きるか考える）
3. 操作する
4. 観察する（ボードの返事と、画面の変化を見る）
5. 解説を読んで、**直し方**を考える

AI アシスタントを使うことを前提にしています。Codex・Claude Code・ChatGPT などの種類ごとの使い方は [docs/how-to-use-ai.md](docs/how-to-use-ai.md) を読んでください。

## ステップ

| # | テーマ | ねらい | 元の攻撃 |
|---|---|---|---|
| 1 | [命令の洗い出し](stages/01-recon.md) | 使える命令を自分で調べる | `00` |
| 2 | [リプレイ](stages/02-replay.md) | 暗号化しても、使い回しは防げない | `05` |
| 3 | [認証のないコマンド](stages/03-command-injection.md) | 誰が送ったかを確認しない命令 | `02` |
| 4 | [取り消しのきかないコマンド](stages/04-resetc.md) | 気付けても止められない | `06` |
| 5 | [フラッシュの読み出し](stages/05-flash-read.md) | 配られた値は鍵にならない | `08` |
| 6 | [位置のなりすまし](stages/06-position-spoofing.md) | 位置情報が権限になる危うさ | `03` |
| 7 | [地上局のなりすまし](stages/07-gs-auth-spoofing.md) | 弱い認証と、攻撃の連鎖 | `04` |
| 8 | [除外された命令の悪用](stages/08-gate-exemption.md) | 例外の命令が入口になる | `09` |
| 9 | [暗号のダウングレード](stages/09-downgrade.md) | 1 バイトで暗号が切れる | `07` |
| 10 | [長さ計算のアンダーフロー](stages/10-underflow.md) | 短い入力でボードが落ちる | `01` |

「元の攻撃」の番号は [attacks/](attacks/) のものです。`attacks/` は [JP-Bootcamp](https://github.com/bellx2/JP-Bootcamp) の `attacks/` を同梱し、コメントを日本語にしたものです（GPL-3.0-or-later、[attacks/NOTICE.md](attacks/NOTICE.md)）。
[tools/](tools/) は、カードの手順で使う小さな補助スクリプトです（`attacks/lib` を使います）。

## 用意するもの

- StickSat（書き込み済みのボード。[BOOTH で頒布](https://bellx2.booth.pm/items/9193868)。または RP2350-GEEK に [StickSat](https://github.com/bellx2/StickSat) の UF2 を書き込んだもの）
- PC（Python 3 と [uv](https://docs.astral.sh/uv/)）
- JP-Bootcamp（Space IDS に使う。[docs/00-start.md](docs/00-start.md) を参照）。なくてもボード単体で進められる（アラートの観察だけできなくなる。同 §6）

## 注意

- 攻撃の対象は**自分が所有するボードだけ**です。AI に手伝わせる場合も同じです。
- 学習・研究目的に限ります。実在する衛星や機器には使えません。
- 攻撃スクリプト（`attacks/` の 10 種類）を連続で実行しないでください。1 つずつ実行し、合間にリセットします（[docs/00-start.md](docs/00-start.md)）。

## 元のプロジェクト

| プロジェクト | ライセンス | 関係 |
|---|---|---|
| [Pwnsat/FlatSat](https://github.com/Pwnsat/FlatSat)（astrobyte / Cromulence / Hack-A-Sat） | GPL-2.0-or-later | 元の脆弱な衛星模擬機・攻撃スクリプト |
| [r0r0x-xx/JP-Bootcamp](https://github.com/r0r0x-xx/JP-Bootcamp) | `firmware/` は GPL-2.0-or-later、`c3/` は MIT（一部 GPL-3.0）、その他は GPL-3.0-or-later | 2 日間の講座・攻撃スクリプト・Space IDS |
| [bellx2/JP-Bootcamp](https://github.com/bellx2/JP-Bootcamp) | 上と同じ | 上の日本語化 fork（README とドキュメントのみ翻訳） |
| [bellx2/StickSat](https://github.com/bellx2/StickSat) | GPL-2.0-or-later | RP2350-GEEK 向けファームウェア（旧名 FlatSat-Geek） |

## ライセンス

このリポジトリは、部分ごとにライセンスが異なります。

| 対象 | ライセンス |
|---|---|
| 演習の文章（`stages/`、`docs/`、`README.md`、`AGENTS.md`、`CLAUDE.md`） | [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/deed.ja) |
| 攻撃スクリプト（`attacks/`） | GPL-3.0-or-later（JP-Bootcamp からの同梱。[attacks/NOTICE.md](attacks/NOTICE.md)） |
| 補助スクリプト（`tools/`） | GPL-3.0-or-later（`attacks/lib` を使うため） |

- 文章を再利用するときは、出典（このリポジトリ）を示し、同じ CC BY-SA 4.0 で公開してください。
- 元のプロジェクトとそのライセンスは上の「元のプロジェクト」にあります。
- 詳しくは [LICENSE](LICENSE) を参照してください。
