"""攻撃スクリプトが FlatSat と USB で通信するための、単体で完結した通信部品。

演習機材に必要なものはすべて `attacks/` の中にそろっている（元の英文は `Bench/` と書いているが、実際のフォルダは `attacks/`）。このフォルダの外から
import しないので、元のプロジェクト全体を入れていないノート PC でもそのまま動く。

**IDS（侵入検知システム）とは、あえてパケットの解析処理（コーデック）を共有しない。**
攻撃側と同じ解析処理を使う検知器は、その解析処理が読み違えるフレームを見逃してしまう。
実装を 2 つ独立に持つのは意図したものであり、まとめるべき重複ではない。

APID（パケットの種類を示す番号）はファームウェアの `mission.h` から、AES による暗号化の
包み方は `pwnsat_crypto.py` から、1 バイト単位でそのまま写している。
"""
from __future__ import annotations

import os
import socket
import struct
import sys
import time
from dataclasses import dataclass
from typing import Optional

import serial
import serial.tools.list_ports

BAUD = 921600

# FlatSat が USB 上で名乗る識別子（ベンダー ID とプロダクト ID の組）。IDS が照合に
# 使うものと同じ組なので、攻撃側と IDS 側で「どれがボードか」の判断が一致する。
FLATSAT_VID_PID = (0x239A, 0xCAFE)

# CDC-ACM ポート（USB シリアル）を開くと DTR 信号が立ち、ボードは応答できるように
# なるまで少し時間がかかる。待たないと最初に書いたフレームが捨てられる。
# 2026 年 11 月 7 日の実機測定では、1 回だけの疎通確認が正しく返るのは約半分で、
# open() 直後の最初のコマンドは毎回失われていた。
PORT_SETTLE_S = 0.35
PROBE_ATTEMPTS = 4

# ボードは USB への出力を 1 秒ごと（1 Hz）にまとめて送るので、返事はコマンドの
# 約 1 秒後に届く。2026 年 11 月 7 日の測定では、連続したコマンドで 1.007、1.014、
# 1.010、1.008 秒だった。ポートを開いた直後の最初のコマンドだけは別で、ボードが
# 動き出すのを待つため、同じ測定で 2.67 秒かかった。待ち時間がどちらかより短いと
# 何も受け取れず、「ボードが何も返さない」と判定してしまう。フラッシュ読み出しの
# 演習が最初の手順で毎回失敗していた原因はこれである。
BOARD_TICK_S = 1.0
WARMUP_TIMEOUT_S = 5.0

# 新しく接続した最初のコマンドは、2 回目以降より時間がかかる（2.67 秒に対し、
# 以降は安定して 1.01 秒）。送る前に長く待っても変わらないので、この遅れはポートで
# はなく最初のコマンド自体に付くものである。そのため、毎回の送信に上乗せせず、
# 最初のコマンドの待ち時間で 1 回だけ吸収する。
FIRST_COMMAND_S = 4.0

# 前のスクリプトのテレメトリ（衛星から地上への状態報告）がまだ届いている最中に次の
# スクリプトを始めると、その残りを自分への返事と読み違える。reset_input_buffer が
# 消すのは PC 側の受信バッファだけで、ボードはその後も数秒間送り続ける。そこで、
# 最初のコマンドの前に回線が静かになるまで待つ。ただし勝手に話し続けるボードでも
# 動かなくならないよう、待つのは一定時間までとする。
QUIET_FOR_S = 0.5
QUIESCE_TIMEOUT_S = 6.0

# センサー（Space IDS。攻撃を見張る検知器）を間に挟むと、シリアルポートはセンサーが占有する。そのため攻撃は
# センサーを迂回せず、センサーを通ってボードに届く。これが演習機材のねらいで、
# 攻撃の実行中にアラートが上がる。センサーはこのソケット上でボードと同じフレーム
# 形式を話すので、通信路より上の層（send() や listen()、各攻撃スクリプト）は何も変えなくてよい。
DEFAULT_IDS_ENDPOINT = "127.0.0.1:5010"
SYNC = 0xAA
TC_PREFIX = b"\xAA\x55"
SPP_HEADER = 6

# --- テレコマンド（地上から衛星への命令）の APID。mission.h から ------------------
TC_PING = 0x01
TC_RESETC = 0x02
TC_SEND_FW = 0x03
TC_SET_THRUSTER = 0x04
TC_SET_BEACON_RATE = 0x05
TC_BROADCAST_MSG = 0x06
TC_FLASH = 0x07
TC_AES_CONFIG = 0x0A
TC_FLASH_READ = 0x0B
TC_GET_STATUS = 0x0C
TC_SET_MISSION_MODE = 0x0D
TC_GET_NAV = 0x0E
TC_GET_PAYLOAD_STATUS = 0x0F
TC_DEBUG_CONFIG = 0x10
TC_GS_MODE = 0x11
TC_GS_ACCESS = 0x12
TC_GS_STATUS = 0x13
TC_GPS_OVERRIDE = 0x14          # 演習用ビルドにだけある。mission.h を参照

# 地上局ゲート（地上局を名乗る相手を認証する仕組み）の共有秘密鍵。PWNSAT-C3 の settings.py から。
GS_AUTH_KEY = 0xC0DEFACE

# --- テレメトリ --------------------------------------------
def gs_response(challenge: int, auth_key: int = GS_AUTH_KEY) -> int:
    """ゲートのチャレンジレスポンス認証の全体。固定値との排他的論理和（XOR）をとるだけである。"""
    return (challenge ^ auth_key) & 0xFFFFFFFF


TM_NAMES = {
    0x01: "PING", 0x02: "RESETC", 0x03: "SEND_FW", 0x04: "SET_THRUSTER",
    0x05: "SET_BEACON_RATE", 0x06: "BROADCAST_MSG", 0x07: "FLASH",
    0x08: "SEND_TM", 0x09: "ERROR", 0x0A: "AES_CONFIG", 0x0B: "FLASH_READ",
    0x0C: "STATUS", 0x0D: "MISSION_MODE", 0x0E: "NAV", 0x0F: "PAYLOAD_STATUS",
    0x10: "DEBUG_CONFIG", 0x11: "GS_MODE", 0x12: "GS_ACCESS",
    0x13: "GS_STATUS", 0x14: "GPS_OVERRIDE", 0x20: "IDS_EVENT",
}

# --- わざと弱く作った AES による暗号化。pwnsat_crypto.py から ------------------------
AES_KEY = b"PWNsatLabKey1234"
AES_BLOCK = 16


def _aes_ecb(data: bytes, key: bytes, encrypt: bool) -> bytes:
    try:
        from Cryptodome.Cipher import AES
    except ImportError:
        try:
            from Crypto.Cipher import AES
        except ImportError:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            c = Cipher(algorithms.AES(key), modes.ECB())
            op = c.encryptor() if encrypt else c.decryptor()
            return op.update(data) + op.finalize()
    c = AES.new(key, AES.MODE_ECB)
    return c.encrypt(data) if encrypt else c.decrypt(data)


def encrypt_payload(payload: bytes, key: bytes = AES_KEY) -> bytes:
    """先頭に 2 バイトのビッグエンディアン（上位バイトが先）の長さを付け、続けてペイロードを置き、16 バイトの倍数になるまでゼロで埋める。"""
    plain = len(payload).to_bytes(2, "big") + payload
    padded = (len(plain) + AES_BLOCK - 1) & ~(AES_BLOCK - 1)
    return _aes_ecb(plain.ljust(padded, b"\x00"), key, True)


def decrypt_payload(payload: bytes, key: bytes = AES_KEY) -> bytes:
    if not payload or len(payload) % AES_BLOCK:
        raise ValueError("ciphertext must be a non-zero multiple of 16 octets")
    plain = _aes_ecb(payload, key, False)
    n = int.from_bytes(plain[:2], "big")
    if n > len(plain) - 2:
        raise ValueError("length prefix does not fit the plaintext")
    return plain[2:2 + n]


# --- SPP（Space Packet Protocol。宇宙機用の標準パケット形式） ------------------

@dataclass
class Packet:
    apid: int
    seq: int
    payload: bytes
    raw: bytes
    is_tc: bool
    sec_hdr: bool

    @property
    def name(self) -> str:
        return TM_NAMES.get(self.apid, f"0x{self.apid:03X}")

    def __str__(self) -> str:
        return f"{self.name:16} seq={self.seq:<5} {len(self.payload)} octets"


def build_tc(apid: int, payload: bytes = b"", *, seq: int = 1,
             encrypt: bool = True, sec_hdr: bool = False) -> bytes:
    if encrypt:
        data = encrypt_payload(payload)
    elif len(payload) == 1:
        # ファームウェアは SPP の長さフィールドが 0 より大きいときしかペイロードを
        # コピーしない。そのため 1 バイトの平文コマンドには 1 バイト足して送る。
        data = payload + b"\x00"
    else:
        data = payload
    ident = (0 << 13) | (1 << 12) | (int(sec_hdr) << 11) | (apid & 0x7FF)
    seq_field = (0b11 << 14) | (seq & 0x3FFF)
    return struct.pack(">HHH", ident, seq_field, max(len(data) - 1, 0)) + data


def parse(raw: bytes) -> Packet:
    ident, seq, _length = struct.unpack(">HHH", raw[:SPP_HEADER])
    return Packet(apid=ident & 0x7FF, seq=seq & 0x3FFF, payload=raw[SPP_HEADER:],
                  raw=raw, is_tc=bool((ident >> 12) & 1),
                  sec_hdr=bool((ident >> 11) & 1))


def frame(raw_spp: bytes) -> bytes:
    return TC_PREFIX + len(raw_spp).to_bytes(2, "big") + raw_spp


def deframe(stream: bytes) -> tuple[list[bytes], bytes]:
    out, off = [], 0
    while off < len(stream):
        if stream[off] != SYNC:
            off += 1
            continue
        if len(stream) - off < SPP_HEADER + 2:
            break
        total = 1 + SPP_HEADER + int.from_bytes(stream[off + 5:off + 7], "big") + 1
        if len(stream) - off < total:
            break
        out.append(stream[off + 1:off + total])
        off += total
    return out, stream[off:]


def list_boards(serial_number: Optional[str] = None) -> list[dict]:
    """この PC から見える FlatSat をすべて返す。

    デバイス名のパターンではなく USB の識別子で照合する。そのため macOS の
    /dev/cu.usbmodem* でも Linux の /dev/ttyACM* でも、どちらの名前もこのファイルに
    書かずに同じ呼び出しで動く。
    """
    out = []
    for p in serial.tools.list_ports.comports():
        if (p.vid, p.pid) != FLATSAT_VID_PID:
            continue
        if serial_number and (p.serial_number or "") != serial_number:
            continue
        out.append({"port": p.device, "serial": p.serial_number or "?",
                    "product": p.product or "?"})
    return sorted(out, key=lambda d: d["port"])


def candidate_ports(serial_number: Optional[str] = None) -> list[str]:
    """疎通確認する価値のあるポートを、毎回同じ順序で返す。

    USB の識別子で絞り込むので、Mac の Bluetooth 用デバイスや Linux の /dev/ttyS* を
    片端から開かずに済む。どちらも開くのが遅く、止まってしまうこともある。
    シリアル番号を指定しておらず、一致するものもなければ全ポートを候補にする。別の識別子で書き込み直したボードは
    そう見えるためである。

    macOS では各ポートの /dev/tty.* 側の片割れを外す。こちらは開こうとするとキャリア検出を
    待ったまま止まってしまうため、使えるのは /dev/cu.* 側である。
    """
    mine = [b["port"] for b in list_boards(serial_number)]
    if mine:
        return mine
    if serial_number:
        return []
    every = [p.device for p in serial.tools.list_ports.comports()]
    if sys.platform == "darwin":
        every = [d for d in every if "/tty." not in d] or every
    return sorted(every)


class _SocketLink:
    """ソケットを、このファイルの他の部分が期待するシリアルオブジェクトに見せかけたもの。

    5 つのメソッドを同じ名前・同じ意味で持つので、send() と listen() からは、
    ケーブル直結なのか、間にセンサーが挟まっているのかを区別できない。
    """

    def __init__(self, endpoint: str, timeout: float = 0.2):
        host, _, port = endpoint.rpartition(":")
        self._sock = socket.create_connection((host or "127.0.0.1", int(port)),
                                              timeout=5.0)
        self._sock.settimeout(timeout)

    def write(self, data: bytes) -> int:
        self._sock.sendall(data)
        return len(data)

    def read(self, n: int = 1) -> bytes:
        try:
            return self._sock.recv(n)
        except socket.timeout:
            return b""
        except OSError:
            return b""

    def reset_input_buffer(self) -> None:
        self._sock.settimeout(0.01)
        try:
            while self._sock.recv(4096):
                pass
        except OSError:
            pass
        self._sock.settimeout(0.2)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


# --- 通信路 -------------------------------------------------------------------

class FlatSat:
    """USB でつないだボード。

    FlatSat は同じシリアル番号の CDC インターフェース（USB シリアルの口）を 2 つ出す。
    どちらがバイナリ通信用かは、抜き差しするたびに変わりうる。そこで、ファームウェアの
    応答を手がかりにポートを探す。暗号化しない PING を送り、返事の中に同期バイト 0xAA が
    含まれていた方を選ぶ。"""

    def __init__(self, port: Optional[str] = None, *, encrypt: bool = True,
                 verbose: bool = True, serial_number: Optional[str] = None):
        # FLATSAT_PORT と FLATSAT_SERIAL を使うと、どのスクリプトにも新しいオプションを
        # 足さずに特定のボードを狙える。1 台のノート PC に 2 台つないでいるときは
        # FLATSAT_SERIAL を export すれば、10 種類の攻撃すべてがそのボードに向く。
        self.port = port or os.environ.get("FLATSAT_PORT") or None
        # FLATSAT_HOST を設定すると、攻撃の宛先がケーブルではなくセンサーになる。
        # "1" は既定の接続先を意味するので、ポート番号を覚えなくても演習で有効にできる。
        host = os.environ.get("FLATSAT_HOST")
        if host in ("1", "yes", "true"):
            host = DEFAULT_IDS_ENDPOINT
        self.endpoint = host or None
        self.serial_number = (serial_number
                              or os.environ.get("FLATSAT_SERIAL") or None)
        self.encrypt = encrypt
        self.verbose = verbose
        self._ser: Optional[serial.Serial] = None
        self._rx = b""
        self._first_send = True

    # -- 下回りの処理 ----------------------------------------------------------

    def _say(self, msg: str) -> None:
        if self.verbose:
            print(msg, flush=True)

    @staticmethod
    def _probe(port: str, attempts: int = PROBE_ATTEMPTS) -> bool:
        """このポートで FlatSat が応答するかを調べる。

        わざと再試行している。1 回の確認では信頼できる答えにならないためである。
        DTR が立った後、ポートが落ち着くまでボードはフレームを受け付けず、早すぎる
        確認はそのまま失われる。PermissionError は握りつぶさずにそのまま投げる。
        呼び出し側が「ボードがない」と「ボードを開く権限がない」を区別できるように
        するためで、Linux ではこれがケーブルの不足とグループ所属の不足の違いになる。
        """
        probe = frame(build_tc(TC_PING, b"", seq=1, encrypt=False))
        for attempt in range(max(1, attempts)):
            try:
                with serial.Serial(port, BAUD, timeout=1.0) as s:
                    time.sleep(PORT_SETTLE_S)
                    s.reset_input_buffer()
                    s.write(probe)
                    s.flush()
                    if SYNC in s.read(64):
                        return True
            except PermissionError:
                raise
            except (OSError, serial.SerialException):
                pass
            time.sleep(0.2)
        return False

    def find_port(self) -> str:
        denied: list[str] = []
        ports = candidate_ports(self.serial_number)
        for p in ports:
            try:
                if self._probe(p):
                    return p
            except PermissionError:
                denied.append(p)

        lines = ["no FlatSat answered a PING on any serial port."]
        if denied:
            lines.append(f"  - permission denied on: {', '.join(denied)}")
            if sys.platform.startswith("linux"):
                lines.append("    on Ubuntu the account has to be in the "
                             "dialout group, then log out and back in:")
                lines.append("      sudo usermod -aG dialout \"$USER\"")
        if not ports:
            lines.append("  - no USB device with the FlatSat identity "
                         f"{FLATSAT_VID_PID[0]:04x}:{FLATSAT_VID_PID[1]:04x} "
                         "is plugged in")
        if self.serial_number:
            lines.append(f"  - looking only for serial {self.serial_number}; "
                         "unset FLATSAT_SERIAL to take any board")
        lines.append("  - a charge-only USB cable enumerates nothing; "
                     "try another cable")
        lines.append("  - if the IDS is running it owns the port exclusively; "
                     "stop it first")
        raise RuntimeError("\n".join(lines))

    def open(self) -> "FlatSat":
        if self.endpoint:
            self._ser = _SocketLink(self.endpoint)       # type: ignore[assignment]
            self.port = self.endpoint
            self._say(f"[*] FlatSat via Space IDS at {self.endpoint}"
                      f"  ({'encrypted' if self.encrypt else 'cleartext'} link)")
            self._first_send = True
            self._quiesce()
            return self
        self.port = self.port or self.find_port()
        self._ser = serial.Serial(self.port, BAUD, timeout=0.2)
        # 疎通確認と同じだけ待つ。待たないと、どのスクリプトも最初のコマンドを
        # まだ受け付けていないポートに書くことになる。以前、PING 5 回のうち 4 回しか
        # 返事がなかったのはこれが原因である。
        time.sleep(PORT_SETTLE_S)
        self._ser.reset_input_buffer()
        self._first_send = True
        self._quiesce()
        self._say(f"[*] FlatSat on {self.port} @ {BAUD}"
                  f"  ({'encrypted' if self.encrypt else 'cleartext'} link)")
        return self

    def _quiesce(self) -> None:
        """ボードが送信をやめるまで（最大 QUIESCE_TIMEOUT_S 秒）待ち、最初に受け取る返事が自分のものになるようにする。

        まだ届いている途中のデータは、直前に動いていたスクリプトのものである。それを返事として
        読んだせいで、フラッシュのダンプが PING の応答をつなぎ合わせたイメージになったり、
        APID の総当たりが別のスクリプトのテレメトリを「その APID が有効な証拠」と
        数えたりしたことがある。
        """
        deadline = time.time() + QUIESCE_TIMEOUT_S
        last = time.time()
        while time.time() < deadline:
            chunk = self._ser.read(512)              # type: ignore[union-attr]
            if chunk:
                last = time.time()
            elif time.time() - last >= QUIET_FOR_S:
                break
            else:
                time.sleep(0.02)
        self._rx = b""
        try:
            self._ser.reset_input_buffer()           # type: ignore[union-attr]
        except Exception:
            pass

    def close(self) -> None:
        if self._ser:
            self._ser.close()
            self._ser = None

    def __enter__(self) -> "FlatSat":
        return self.open()

    def __exit__(self, *a) -> None:
        self.close()

    # -- 送受信 ----------------------------------------------------------------

    def send(self, apid: int, payload: bytes = b"", *, seq: int = 1,
             encrypt: Optional[bool] = None, sec_hdr: bool = False,
             listen: float = BOARD_TICK_S * 1.6) -> list[Packet]:
        enc = self.encrypt if encrypt is None else encrypt
        # この接続で最初のコマンドは、ボードの応答が遅いので長めに待つ。スクリプトが
        # 独自の待ち時間を渡していても、この 1 回だけは最低でもこの長さを確保する。
        # 最初の手順であきらめる演習は、2 番目の手順にたどり着けないためである。
        if self._first_send:
            listen = max(listen, FIRST_COMMAND_S)
            self._first_send = False
        raw = build_tc(apid, payload, seq=seq, encrypt=enc, sec_hdr=sec_hdr)
        self._say(f"[>] {TM_NAMES.get(apid, hex(apid)):16} seq={seq} "
                  f"{len(payload)} octets{'' if enc else '  (cleartext)'}")
        self._ser.write(frame(raw))                      # type: ignore[union-attr]
        return self.listen(listen)

    def send_raw(self, raw_spp: bytes, *, listen: float = 1.0) -> list[Packet]:
        """決まったバイト列をそのまま回線に流す必要がある演習のためのもの。"""
        self._ser.write(frame(raw_spp))                  # type: ignore[union-attr]
        return self.listen(listen)

    def listen(self, seconds: float = 1.0) -> list[Packet]:
        packets: list[Packet] = []
        deadline = time.time() + seconds
        while time.time() < deadline:
            chunk = self._ser.read(4096)                 # type: ignore[union-attr]
            if chunk:
                self._rx += chunk
                frames, self._rx = deframe(self._rx)
                for f in frames:
                    if len(f) >= SPP_HEADER:
                        packets.append(parse(f))
            else:
                time.sleep(0.01)
        for p in packets:
            self._say(f"[<] {p}")
        return packets

    def plaintext(self, p: Packet) -> bytes:
        """ペイロードを返す。通信路が暗号化モードなら復号してから返す。"""
        if not self.encrypt or not p.payload:
            return p.payload
        try:
            return decrypt_payload(p.payload)
        except ValueError:
            return p.payload


def hexdump(data: bytes, width: int = 16) -> str:
    out = []
    for i in range(0, len(data), width):
        c = data[i:i + width]
        hx = " ".join(f"{b:02x}" for b in c)
        tx = "".join(chr(b) if 32 <= b < 127 else "." for b in c)
        out.append(f"{i:06x}  {hx:<{width * 3}} |{tx}|")
    return "\n".join(out)
