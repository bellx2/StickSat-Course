"""ボードが今どんな状態にあるかを、決めつけずにボード自身に問い合わせる。

2日目の演習はどれも、ボードの状態を前提にして始まる。ボードが報告する位置、
地上局モード（オンにするとゲート対象のコマンドに制限がかかるモード）がオンかどうか、
セッションが開いているかどうか、の3つである。以前のキットはこれを一切確認して
いなかった。そのため、位置を動かす演習の後に別の演習を実行すると、その演習の
出力だけでは説明のつかない理由で失敗していた。

読み取りは再試行する。1回の待ち時間に返事がなかっただけでは答えにならないからだ。
ボードは1秒周期（1 Hz）で返事をするので、待ち時間に間に合わなかった返事は
拒否を意味しない。
"""
from __future__ import annotations

import itertools
import struct
import time
from dataclasses import dataclass
from typing import Optional

from flatsat import FlatSat

TC_GET_STATUS = 0x0C
TC_GET_NAV = 0x0E
TC_GS_MODE = 0x11
TC_GPS_OVERRIDE = 0x14
TM_ERROR = 0x09

# 下の TOKYO は演習用ファームウェアが起動時に報告する位置、SAPPORO は認可する
# 地上局の位置である。両者は830 km離れているので、ゲート（地上局モードの関門）は
# 閉じた状態から始まる。
# シーケンス番号（パケットごとの通し番号）は呼び出しごとに進める。同じ番号で
# 送り直すと、センサー（Space IDS。攻撃を見張る検知器）には本物のリプレイ（盗み取った通信の
# 再送）と区別できず、duplicate-frame ルールが発火する。起点を現在時刻から取るので、
# 続けて実行しても前回の番号と重なりにくい。
_SEQ = itertools.count(int(time.time() * 10))


def next_seq() -> int:
    """14ビットのSPP（Space Packet Protocol。宇宙機用の標準パケット形式）のシーケンス番号を1つ払い出す。"""
    return next(_SEQ) & 0x3FFF


TOKYO = (357122000, 1397038000, 3500, 11)
SAPPORO = (430618000, 1413545000, 2000, 11)


@dataclass
class BenchState:
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    gs_mode: Optional[bool] = None
    session_open: Optional[bool] = None
    last_error: str = ""

    def __str__(self) -> str:
        where = ("unknown" if self.latitude is None
                 else f"{self.latitude:.4f},{self.longitude:.4f}")
        return (f"position={where} gs_mode={self.gs_mode} "
                f"session={self.session_open} last_error={self.last_error or '-'}")


def _errors(fs: FlatSat, replies) -> str:
    out = []
    for p in replies:
        if p.apid == TM_ERROR and p.payload:
            out.append(fs.plaintext(p).split(b"\x00")[0].decode("ascii", "replace"))
    return " | ".join(out)


#: mission.h の SPACECRAFT_ID。NAVペイロードの先頭オクテット（1オクテット = 8ビット = 1バイト）。
SPACECRAFT_ID = 0x01


def _nav_position(body: bytes):
    """NAVペイロードから (緯度, 経度) を取り出す。読めた位置として扱えないときは None を返す。

    暗号文を平文として読んでしまったペイロードは、先頭の宇宙機IDが合わない。
    それで見分ける。座標が正しい範囲にあるかでは判定しない。攻撃00のスイープは
    USBデバッグをオンにした後に GPS_OVERRIDE も探るので、ボードが本当に
    あり得ない位置を持っていることがある。それも「読めた位置」として扱い、
    リセットの対象にする必要があるからだ。
    """
    if len(body) < 15 or body[0] != SPACECRAFT_ID:
        return None
    lat, lon, _alt = struct.unpack_from("<iii", body, 3)
    return lat / 1e7, lon / 1e7


def read_state(fs: FlatSat, tries: int = 3) -> BenchState:
    st = BenchState()

    for _ in range(tries):
        r = fs.send(TC_GET_NAV, b"\x00", seq=next_seq(), listen=2.5)
        for p in r:
            if p.apid != TC_GET_NAV:
                continue
            pos = _nav_position(fs.plaintext(p))
            if pos is not None:
                st.latitude, st.longitude = pos
        err = _errors(fs, r)
        if err:
            st.last_error = err
        if st.latitude is not None or err:
            break
        time.sleep(0.4)

    # ゲート対象のコマンドに返事があれば、ゲートは開いている。地上局モードが
    # オフか、オンでもセッションが開いているかのどちらかである。ただし、どちらなのかは
    # これだけではわからない。返事がなくエラーが返った場合は、その内容でモードの状態がわかる。
    for _ in range(tries):
        r = fs.send(TC_GET_STATUS, b"\x00", seq=next_seq(), listen=2.5)
        answered = any(p.apid == TC_GET_STATUS for p in r)
        err = _errors(fs, r)
        if answered:
            st.session_open = True
            st.gs_mode = None            # 開いている。これだけではモードのオン・オフはわからない
            return st
        if "AUTH REQUIRED" in err:
            st.gs_mode, st.session_open, st.last_error = True, False, err
            return st
        if "RANGE LOCK" in err or "GPS" in err:
            st.gs_mode, st.session_open, st.last_error = True, False, err
            return st
        if err:
            st.last_error = err
        time.sleep(0.4)

    return st


def set_position(fs: FlatSat, where=TOKYO, seq: Optional[int] = None) -> None:
    """ゲートが開いている間しか効かない。GPS_OVERRIDE もゲート対象のコマンドなので、
    地上局モードがオンでセッションがなければ、他のコマンドと同じように拒否される。"""
    lat, lon, alt, sats = where
    fs.send(TC_GPS_OVERRIDE, struct.pack("<iii", lat, lon, alt) + bytes([sats]),
            seq=next_seq() if seq is None else seq, listen=2.5)


def set_gs_mode(fs: FlatSat, on: bool, seq: Optional[int] = None) -> None:
    fs.send(TC_GS_MODE, bytes([1 if on else 0]),
            seq=next_seq() if seq is None else seq, listen=2.5)
