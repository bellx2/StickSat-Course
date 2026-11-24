#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 00_recon_apid_enum_usb.py -- 誰も文書化していないボードのコマンド一覧を、
# USB経由で自分で作る。
#
# 通信の形式（プロトコル）はわかっているが、どんなコマンドがあるかの一覧
# （コマンド辞書）はない。これが普通の状況である。学ぶべきは手順そのもので、
# 一度に1つの項目だけを変え、返事がないこと（無応答）も含めてすべての反応を
# 記録し、その表を残しておく。
#
# 大事なのは無応答の読み方である。エラーコード付きで拒否されたなら、パケットは
# 解釈（パース）まで進んでいる。つまり形は正しく、中身だけが違っていた。
# 無応答なら、それより手前で捨てられている。この2つの境目を見れば、
# 入力の検証がどこで行われているかがわかる。
#
# 安全のための注意: 探りに使うペイロード（コマンドの中身）は、ゼロでない
# 4オクテット（1オクテット = 8ビット = 1バイト）である。BROADCAST_MSG (0x06) に長さ0の
# ペイロードを送ると攻撃01のアンダーフローになり、SET_BEACON_RATE (0x05) に
# 0を送るとビーコン（定期送信）が洪水のように出続ける。どちらもスイープで
# 送るべきものではない。

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from flatsat import FlatSat, TM_NAMES  # noqa: E402

ERROR_TM = 0x09
PROBE = bytes([0x01, 0x01, 0x01, 0x01])

# スイープで送らない識別子（APID。パケットの種類を示す番号）と、その理由。
# 対象を再起動させてしまうスイープは何も調べられない。RESETC は2番目の探りに
# 対してUSBデバイスを切り離して応え、それ以降の識別子はすべて無応答に見えた。
# 2026年11月7日より前、実機でこのスイープが「12個中0個が応答」と報告したのは
# これが原因で、実際にはボードは応答していた。
#
# 何を送ってよいかを決めることも、偵察ツールの役目の一部である。飛ばした
# 識別子は黙って除かずに表示する。受講者が作る一覧の抜けは、一覧の上で
# 見えなければならないからだ。
SKIP = {
    0x02: "RESETC reboots the board and the rest of the sweep reads silence",
}


def classify(apid: int, replies) -> str:
    for p in replies:
        if p.apid == apid:
            return "answers"
        if p.apid == ERROR_TM:
            return "rejects"
    return "silent"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default=None)
    ap.add_argument("--start", type=lambda x: int(x, 0), default=0x01)
    ap.add_argument("--end", type=lambda x: int(x, 0), default=0x18, help="inclusive")
    # ボードはUSBへの出力を1秒周期（1 Hz）で処理するので、返事はコマンドから
    # 最大1秒遅れて届く。以前の0.6秒の待ち時間では返事が届く前に打ち切られ、
    # すべての識別子が無応答に見えていた。
    ap.add_argument("--listen", type=float, default=1.5)
    ap.add_argument("--cleartext", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    table = []
    with FlatSat(port=args.port, encrypt=not args.cleartext, verbose=False) as fsat:
        print("\n=== 1. who talks? two minutes of telemetry ===")
        for p in fsat.listen(5.0):
            if p.apid not in [t[0] for t in table]:
                print(f"    heard 0x{p.apid:03X}  {p.name}")

        print(f"\n=== 2. who listens? sweeping 0x{args.start:02X}..0x{args.end:02X} ===")
        for n, apid in enumerate(range(args.start, args.end + 1)):
            if apid in SKIP:
                table.append((apid, "not probed", 0))
                if not args.quiet:
                    print(f"  0x{apid:03X}  {TM_NAMES.get(apid, '?'):16} "
                          f"not probed  ({SKIP[apid]})")
                continue
            replies = fsat.send(apid, PROBE, seq=(n + 1) & 0x3FFF,
                                listen=args.listen)
            verdict = classify(apid, replies)
            table.append((apid, verdict, len(replies)))
            if not args.quiet:
                print(f"    0x{apid:03X}  {TM_NAMES.get(apid, '?'):16} {verdict}")
            time.sleep(0.05)

    print(f"\n{'APID':6} {'NAME':18} {'VERDICT':9} REPLIES")
    for apid, verdict, n in table:
        print(f"0x{apid:03X}  {TM_NAMES.get(apid, 'unknown'):18} {verdict:9} {n}")

    answers = [a for a, v, _ in table if v == "answers"]
    print(f"\n[+] {len(answers)} of {len(table)} identifiers answered.")
    print("Keep this table. Every attack after this one starts from it.")
    print("\nWhat the sensor should have shown: the rate of identifiers nobody "
          "implements.\nNo single probe looks wrong.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
