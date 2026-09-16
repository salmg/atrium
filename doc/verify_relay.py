"""Drive ATRIUM's NFCGate transport against NFCGate's real server.

Peer A is `transport.nfcgate.NFCGateTransport` — the real code, not a stand-in.
Peer B is forty lines of stdlib standing in for a phone in reader mode.
Between them sits NFCGate's own `server.py`, unmodified.

    python3 doc/verify_relay.py [path-to-nfcgate-server]

Needs only the standard library and a clone of
https://github.com/nfcgate/server — no protobuf, no Android.
"""
import pathlib
import socket
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from nfcgate.proto import (
    CARD, CONTINUATION, INITIAL, OP_ACK, OP_PSH, OP_SYN,
    decode_nfcdata, decode_serverdata, encode_nfcdata, encode_serverdata,
)
from transport.nfcgate import NFCGateTransport

SRV = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "nfcgate-server")
if not (SRV / "server.py").is_file():
    sys.exit(f"No server.py under {SRV}. Clone https://github.com/nfcgate/server.git "
             f"and pass its path as the first argument.")

PORT, SESSION = 5566, 42
SELECT = bytes.fromhex("00A4040007A0000000031010")
RESP = bytes.fromhex("6F2F840E325041592E5359532E44444630319000")
# UID, SAK, ATQA and ATS historical bytes, as IsoDepReader would report them.
TAG = bytes([0x33, 4, 0x04, 0xA2, 0xB1, 0xC0,        # LA_NFCID1   — UID
             0x32, 1, 0x20,                          # LA_SEL_INFO — SAK
             0x30, 1, 0x04, 0x31, 1, 0x00,           # ATQA, in its two halves
             0x58, 1, 0x77,                          # LI_A_RATS_TB1 — FWI/SFGI
             0x59, 8, 0x80, 0x73, 0xC0, 0x21, 0xC0, 0x57, 0x59, 0x00])   # historical


class Phone:
    """NFCGate in reader mode, reduced to what the protocol needs."""

    def __init__(self):
        self.sock = socket.create_connection(("127.0.0.1", PORT), 5)
        self.sock.settimeout(10)

    def send(self, opcode, payload=b""):
        body = encode_serverdata(opcode, payload)
        self.sock.sendall(struct.pack("!IB", len(body), SESSION) + body)

    def read(self):
        (n,) = struct.unpack("!I", self._exact(4))
        return decode_serverdata(self._exact(n) if n else b"")

    def _exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("server closed")
            buf += chunk
        return buf

    def read_push(self):
        """
        Read until an OP_PSH, answering any SYN on the way.

        Both peers send SYN on connect, and the hub has no ordering guarantee
        between two clients joining, so each can end up seeing the other's SYN
        and replying ACK. A stray handshake frame can therefore turn up at any
        point, and a client that assumes the next frame is data will read an
        empty one. NFCGate's app loops for the same reason.
        """
        while True:
            opcode, payload = self.read()
            if opcode == OP_SYN:
                self.send(OP_ACK)
                continue
            if opcode == OP_PSH:
                return payload
            print(f"   phone: ignoring {opcode}")

    def handshake(self):
        """
        SYN, then wait for the peer — and do not relay before it answers.

        The hub forwards to whoever is in the session at that moment, so a tag
        announced before ATRIUM has joined goes to nobody and is lost.
        """
        self.send(OP_SYN)
        while True:
            opcode, _ = self.read()
            if opcode == OP_SYN:
                self.send(OP_ACK)
                return "SYN"
            if opcode == OP_ACK:
                return "ACK"

    def run(self):
        seen = self.handshake()
        print(f"2. phone: handshake settled (saw {seen})")

        self.send(OP_PSH, encode_nfcdata(TAG, data_source=CARD, data_type=INITIAL))
        print("3. phone: announced the tag it found")

        command = decode_nfcdata(self.read_push())
        print(f"4. phone: got C-APDU {command.data.hex().upper()}")
        assert command.data == SELECT, f"phone got {command.data.hex().upper()}, not the SELECT"
        self.send(OP_PSH, encode_nfcdata(RESP, data_source=CARD, data_type=CONTINUATION))


server = subprocess.Popen([sys.executable, "server.py"], cwd=SRV,
                          stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
try:
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", PORT), 1).close()
            break
        except OSError:
            time.sleep(0.1)
    print("1. NFCGate's own server.py is up on", PORT)

    phone = Phone()
    threading.Thread(target=phone.run, daemon=True).start()

    card = NFCGateTransport("127.0.0.1", PORT, SESSION, tag_wait=15, timeout=15)
    card.connect()
    print(f"5. ATRIUM: tag is {card.tag.describe()}")
    print(f"6. ATRIUM: ATS rebuilt as {card.get_atr().hex().upper()}"
          f"  (partial: {card.tag.ats_is_partial})")

    answer = card.transmit(SELECT)
    print(f"7. ATRIUM: card answered {answer.hex().upper()}")
    card.disconnect()

    ok = (answer == RESP
          and card.tag.uid == bytes.fromhex("04A2B1C0")
          and card.tag.sak == 0x20
          and card.get_atr() == bytes.fromhex("0B28778073C021C0575900"))
    print("\nRESULT:", "round trip OK" if ok else "MISMATCH")
    sys.exit(0 if ok else 1)
finally:
    server.terminate()
    server.wait(timeout=5)
