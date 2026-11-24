#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""運用者の立場で、地上局モードを有効にする（ステップ 5 の手順 2）。

GS_MODE に 1 を送る。成功すると何も表示せず、ボードの画面に `GS ON` が出る。
拒否されたときだけ `ERROR:` と理由を表示する。元に戻すには attacks/lib/reset_bench.py を使う。
"""
import sys
from pathlib import Path

# attacks/lib の通信部品を使う
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "attacks" / "lib"))

from benchstate import next_seq  # noqa: E402
from flatsat import FlatSat, TC_GS_MODE  # noqa: E402

with FlatSat(verbose=False) as f:
    # シーケンス番号を毎回変え、同じフレームの再送（リプレイ）と誤検知されないようにする
    for p in f.send(TC_GS_MODE, b"\x01", seq=next_seq(), listen=1.5):
        if p.apid == 0x09:
            print("ERROR:", f.plaintext(p).split(b"\x00", 1)[0].decode("ascii", "replace"))
