#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# reset_bench.py -- FlatSat を、どの演習も前提にしている状態に戻す。
#
# どの攻撃もきれいな状態のボードを前提にしているが、終わった後にきれいな状態を
# 残す攻撃はない。攻撃03は偽の位置を残し、攻撃04はゲートを閉じてセッションが
# ない状態を残し、攻撃07はセキュアリンク（AESによる暗号化通信）をオフにしたままにする。
#
# きれいな状態とは次のとおり:
#
#   セキュアリンク  オン   -- 攻撃スクリプトは encrypt=True で接続を開くため
#   地上局モード    オフ   -- モードがオフならゲートは効かないので、各演習が
#                             必要なゲートの状態を自分で作れる
#   位置            東京   -- sensors.cpp の COURSE_GPS_*。ファームウェアの初期値
#
# 使用済みのボードに対して実行して見つかった障害が2つある:
#
#   1. ボードが平文で待ち受けている場合がある。攻撃07がセキュアリンクをオフに
#      したままか、攻撃00がUSBデバッグをオンにしたままのときである。そのため、
#      暗号化の状態は決めつけずに実際に試して確かめる。平文を先に試す（reset() を参照）。
#
#   2. ゲートが閉じている場合がある。地上局モードがオンで、セッションがなく、
#      位置が範囲外だと、ゲート対象のコマンドはすべて拒否される。GS_MODE も
#      例外ではなく、完全に締め出される。抜け道は、ファームウェアがわざと開けて
#      いる扉である。SPP_APID_TC_GS_ACCESS はゲートの対象外になっている
#      （worker.cpp:424）。そこでリセットは攻撃04と同じ鍵でハンドシェイク
#      （認証のためのやりとり）を行い、それで開いたセッションを使って残りの
#      コマンドを通す。

import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from flatsat import (FlatSat, TC_AES_CONFIG, TC_DEBUG_CONFIG, TC_GS_ACCESS,  # noqa: E402
                     TC_GS_STATUS)
import benchstate as B  # noqa: E402

CLEAN_POSITION = B.TOKYO

#: worker.cpp:148。ゲートのチャレンジレスポンス（ボードが出す問題に正しく答えて
#: 認証する仕組み）は、この定数との排他的論理和（XOR）を取るだけである。
#: これが攻撃04で突く弱点であり、このスクリプトの裏口でもある。
GS_AUTH_KEY = 0xC0DEFACE


def _talking(fs: FlatSat) -> bool:
    st = B.read_state(fs, tries=2)
    return st.latitude is not None or st.gs_mode is not None


def _open_session(fs: FlatSat, *, verbose: bool = True) -> bool:
    """地上局のハンドシェイクを最後まで行い、ゲート対象のコマンドが通るようにする。

    セッションが開いたら True を返す。送る2つのフレームは攻撃04が送るものと同じ。
    チャレンジ（ボードが出す問題の値）は GS_ACCESS の返事の6オクテット目（0から数えた位置5）から4オクテット、
    リトルエンディアン（下位バイトが先に並ぶ順序）で入っている。その前には
    宇宙機ID、フェーズ、認証状態、ステータス2オクテットが並ぶ。
    """
    def say(*a):
        if verbose:
            print(*a)

    replies = fs.send(TC_GS_ACCESS, b"\x00", seq=B.next_seq(), listen=1.5)
    challenge = None
    for p in replies:
        body = fs.plaintext(p)
        if p.apid == TC_GS_ACCESS and len(body) >= 9:
            challenge = struct.unpack_from("<I", body, 5)[0]
    if challenge is None:
        say("  [!] the gate issued no challenge. Power-cycle the board.")
        return False

    resp = challenge ^ GS_AUTH_KEY
    say(f"  [*] gate was shut; opened a session "
        f"(challenge 0x{challenge:08X})")
    fs.send(TC_GS_ACCESS, b"\x01" + resp.to_bytes(4, "big"),
            seq=B.next_seq(), listen=1.5)
    time.sleep(0.2)
    return True


def _is_locked_out(st) -> bool:
    """ゲートが有効で、ゲート対象のコマンドが1つも通らない状態なら True を返す。"""
    if st.gs_mode is not True:
        return False
    if st.session_open:
        return False
    return True


def reset(verbose: bool = True) -> bool:
    """ボードを演習が前提にしている状態に戻す。戻せたら True を返す。"""
    def say(*a):
        if verbose:
            print(*a)

    # 平文を先に試す。USBデバッグがオンのボードは、上り（地上からボードへの
    # 通信）を復号せずに読む。そのため暗号化したコマンドは暗号文のまま解釈され、
    # 位置がでたらめな値になる（攻撃00の直後のリセットで位置が戻らなかった原因）。
    # 平文で話せるのはUSBデバッグがオンか、セキュアリンクがオフのときだけで、
    # どちらの場合も平文で送るのが正しい。通常の暗号化された状態のボードは平文の
    # 要求に応答しないので、読めた位置が得られず、暗号化での試行に進む。
    for encrypt in (False, True):
        with FlatSat(verbose=False, encrypt=encrypt) as fs:
            if not _talking(fs):
                continue
            say(f"  [*] the board is listening in "
                f"{'ciphertext' if encrypt else 'cleartext'}")
            st = B.read_state(fs)
            say("  [*] before:", st)

            if _is_locked_out(st):
                if not _open_session(fs, verbose=verbose):
                    return False

            B.set_gs_mode(fs, False)
            B.set_position(fs, CLEAN_POSITION)
            fs.send(TC_AES_CONFIG, b"\x01", seq=B.next_seq(), encrypt=encrypt, listen=2.0)

            # USBデバッグをオフにする。見た目以上に重要な処理である。
            # mission_ctx.usbDebugEnabled が立っていると、ボードはセキュアリンクを
            # 丸ごと迂回する（worker.cpp:707）。その間は暗号化したコマンドがすべて
            # 平文として読まれ、意味のないデータとして処理される。
            #
            # 攻撃00（偵察、演習1.8）は、副作用としてこれをオンにする。識別子の
            # スイープが DEBUG_CONFIG も他のAPID（パケットの種類を示す番号）と同じように
            # 探るため、フラグが切り替わってしまう。偵察の後に暗号化を使う演習を
            # 実行した受講者は、演習が壊れているように見える失敗に出会う。
            #
            # これを「最後」に行うのは意図的である。gate-exemption-chain ルールは、
            # 一定時間内に DEBUG_CONFIG の後に GS_MODE が来ると発火する。この並びは
            # 攻撃09（演習2.8）で見つかる攻撃の連鎖である。GS_MODE より前にフラグを
            # 消すと、リセットのたびにこのルールが発火してしまい、受講者全員に
            # 重大なアラートを無視する癖をつけてしまう。
            fs.send(TC_DEBUG_CONFIG, b"\x00", seq=B.next_seq(), encrypt=encrypt, listen=1.5)
            time.sleep(0.3)

        # 直前の処理で通信の暗号化状態が変わったかもしれない。そのため確認は、
        # このスクリプトが最終的に残したい状態である暗号化オンで接続し直して行う。
        with FlatSat(verbose=False, encrypt=True) as fs:
            st = B.read_state(fs)
            say("  [*] after: ", st)
            ok = (st.latitude is not None
                  and abs(st.latitude - 35.7122) < 0.01)
            say("  [+] bench clean" if ok
                else "  [!] the position did not go back")
            return ok

    say("  [!] the board did not answer in either mode. Power-cycle it:")
    say("      unplug the USB cable, count to three, plug it back in.")
    return False


if __name__ == "__main__":
    raise SystemExit(0 if reset() else 1)
