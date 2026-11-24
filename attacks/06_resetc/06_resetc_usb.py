#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 06_resetc_usb.py -- 取り消しのきかないコマンドと、「検知できる」ことと
# 「もう手遅れ」であることの間の差。
#
# RESETC (0x02) はフライトコンピュータ（衛星を制御する主コンピュータ）を
# 再起動する。机上なら少し面倒なだけだが、軌道上では、パス（地上局と通信
# できる時間帯）の途中で再起動するとそのパスの残りを失い、次の通信機会は
# 何時間も先かもしれない。再起動を繰り返す状態になると、誰かが修正を
# アップリンク（地上から衛星へ送信）するまで、すべてのパスを失う。しかも
# アップリンクには正常に動く受信機が必要である。
#
# **これは元に戻せる代替である。** あえて不可逆なコマンドにはしておらず、
# ここにあるスクリプトはどれも不可逆なコマンドを送らない。測るのは、防御側が
# 最初に気付けた時点と、効果がもう取り消せなくなった時点の差であり、
# 再起動でもそれを忠実に示せる。
#
# 期待される結果: CDC ポート（USB のシリアルポート）がいったん消えて再認識され、
# STATUS の稼働時間がゼロに戻る。

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from flatsat import FlatSat, TC_RESETC, TC_GET_STATUS  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default=None)
    ap.add_argument("--seq", type=int, default=1)
    ap.add_argument("--cleartext", action="store_true")
    ap.add_argument("--yes", action="store_true", help="skip the confirmation")
    args = ap.parse_args()

    if not args.yes:
        print("This reboots the board. The port will drop and come back.")
        if input("Continue? [y/N] ").strip().lower() not in ("y", "yes"):
            return 1

    t0 = time.time()
    try:
        with FlatSat(port=args.port, encrypt=not args.cleartext) as fsat:
            print("\n=== 1. uptime before ===")
            fsat.send(TC_GET_STATUS, b"", seq=args.seq, listen=1.2)

            print("\n=== 2. RESETC. No authentication, no acknowledgement, no undo ===")
            sent_at = time.time()
            fsat.send(TC_RESETC, b"", seq=args.seq + 1, listen=1.5)
    except Exception as exc:
        sent_at = time.time()
        print(f"[+] the link dropped ({type(exc).__name__}) -- that is the reboot.")

    print(f"\n[*] command sent at T+{sent_at - t0:.1f}s")
    print("[*] waiting for the board to come back...")
    for attempt in range(20):
        time.sleep(1.0)
        try:
            with FlatSat(port=None, encrypt=not args.cleartext, verbose=False) as fsat:
                replies = fsat.send(TC_GET_STATUS, b"", seq=1, listen=1.0)
                if replies:
                    back = time.time()
                    print(f"[+] back at T+{back - t0:.1f}s "
                          f"({back - sent_at:.1f}s of silence)")
                    break
        except Exception:
            print(f"    still gone ({attempt + 1}s)")
    else:
        print("[!] it did not come back. Replug it.")

    print("\nNow the only question that matters: how long before a human would "
          "have known,\nand was that before or after the effect could no longer "
          "be undone?")
    print("\nFor this class of command the alert is correct, fast, and too "
          "late. Prevention is the only meaningful control.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
