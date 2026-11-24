#!/usr/bin/env python3
"""地上局とのハンドシェイクを始められるかを確かめる（段階 4 の手順 3）。

GS_ACCESS を 1 回送り、ボードの返事を表示するだけ。チャレンジには答えないので、
セッションは開かない。

    ERROR: ...            拒否された。後ろが拒否の理由
    GS_ACCESS reply: ...  ハンドシェイクが始まった。返事の中身（16 進数）
"""
import sys
from pathlib import Path

# attacks/lib の通信部品を使う
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "attacks" / "lib"))

from benchstate import next_seq  # noqa: E402
from flatsat import FlatSat, TC_GS_ACCESS  # noqa: E402

with FlatSat(verbose=False) as f:
    # シーケンス番号を毎回変え、同じフレームの再送（リプレイ）と誤検知されないようにする
    for p in f.send(TC_GS_ACCESS, b"\x00", seq=next_seq(), listen=1.5):
        body = f.plaintext(p)
        if p.apid == 0x09:
            print("ERROR:", body.split(b"\x00", 1)[0].decode("ascii", "replace"))
        elif p.apid == TC_GS_ACCESS:
            print("GS_ACCESS reply:", body.hex())
