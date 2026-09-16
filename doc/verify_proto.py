"""Round-trip ATRIUM's hand-rolled codec against the real protobuf runtime.

Builds the two NFCGate messages from descriptors at run time (no protoc, and
none of NFCGate's own generated files, which no longer import), then checks
that `nfcgate.proto` — the codec ATRIUM actually ships — produces bytes the
real parser accepts and parses bytes the real serialiser produces.

Needs `pip install protobuf`. Nothing in ATRIUM does; that is the point.
"""
import pathlib, sys
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

# ── the real thing, built from the .proto definitions ────────────────────────
fdp = descriptor_pb2.FileDescriptorProto()
fdp.name, fdp.package, fdp.syntax = "c2s.proto", "nfcgate.c2s", "proto3"
m = fdp.message_type.add(); m.name = "ServerData"
e = m.enum_type.add(); e.name = "Opcode"
for i, nm in enumerate(["OP_PSH", "OP_SYN", "OP_ACK", "OP_FIN"]):
    v = e.value.add(); v.name, v.number = nm, i
f = m.field.add(); f.name, f.number = "opcode", 1
f.type, f.type_name, f.label = f.TYPE_ENUM, ".nfcgate.c2s.ServerData.Opcode", f.LABEL_OPTIONAL
f = m.field.add(); f.name, f.number = "data", 2
f.type, f.label = f.TYPE_BYTES, f.LABEL_OPTIONAL

fdp2 = descriptor_pb2.FileDescriptorProto()
fdp2.name, fdp2.package, fdp2.syntax = "c2c.proto", "nfcgate.c2c", "proto3"
m2 = fdp2.message_type.add(); m2.name = "NFCData"
for enum_name, names in (("DataSource", ["READER", "CARD"]),
                         ("DataType", ["INITIAL", "CONTINUATION"])):
    en = m2.enum_type.add(); en.name = enum_name
    for i, nm in enumerate(names):
        v = en.value.add(); v.name, v.number = nm, i
for name, num, typ, tname in (("data_source", 1, "enum", ".nfcgate.c2c.NFCData.DataSource"),
                              ("data_type",   2, "enum", ".nfcgate.c2c.NFCData.DataType"),
                              ("data",        3, "bytes", None),
                              ("timestamp",   4, "int64", None)):
    f = m2.field.add(); f.name, f.number, f.label = name, num, 1
    f.type = {"enum": f.TYPE_ENUM, "bytes": f.TYPE_BYTES, "int64": f.TYPE_INT64}[typ]
    if tname: f.type_name = tname

pool = descriptor_pool.DescriptorPool()
pool.Add(fdp); pool.Add(fdp2)
ServerData = message_factory.GetMessageClass(pool.FindMessageTypeByName("nfcgate.c2s.ServerData"))
NFCData    = message_factory.GetMessageClass(pool.FindMessageTypeByName("nfcgate.c2c.NFCData"))

# ── the hand-rolled version, as actually shipped ─────────────────────────────
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from nfcgate.proto import (  # noqa: E402
    decode_nfcdata, decode_serverdata, encode_nfcdata, encode_serverdata,
)

def enc_nfcdata(source, dtype, data, timestamp):
    return encode_nfcdata(data, data_source=source, data_type=dtype, timestamp=timestamp)

def enc_serverdata(opcode, data=b""):
    return encode_serverdata(opcode, data)

# ── checks ───────────────────────────────────────────────────────────────────
ok = True

# 1. hand-encoded APDU message parses with the real runtime
apdu = bytes.fromhex("00A4040007A0000000031010")
mine = enc_nfcdata(source=0, dtype=1, data=apdu, timestamp=1761400000123)
real = NFCData(); real.ParseFromString(mine)
assert real.data == apdu and real.data_type == 1 and real.data_source == 0, "field mismatch"
assert real.timestamp == 1761400000123
print("1. hand-encoded NFCData parsed by protobuf runtime:", real.data.hex().upper())

# 2. real-serialised message decodes with the hand-rolled reader
r = NFCData(data_source=1, data_type=0, data=bytes.fromhex("330407ABCDEF3201203004"), timestamp=7)
got = decode_nfcdata(r.SerializeToString())
assert got.data == r.data and got.data_source == 1 and got.timestamp == 7, got
print("2. protobuf-serialised NFCData decoded by hand:", got.data.hex().upper())

# 3. byte-for-byte identity in both directions
for kwargs in ({"data_source": 0, "data_type": 1, "data": apdu, "timestamp": 1},
               {"data_source": 1, "data_type": 0, "data": b"\x33\x04\x01\x02\x03\x04", "timestamp": 999999},
               {"data_source": 0, "data_type": 0, "data": b"", "timestamp": 0}):
    a = NFCData(**kwargs).SerializeToString()
    b = enc_nfcdata(kwargs["data_source"], kwargs["data_type"], kwargs["data"], kwargs["timestamp"])
    if a != b:
        ok = False
        print("   MISMATCH", kwargs, a.hex(), b.hex())
print("3. byte-identical NFCData encodings for every case:", ok)

for op in range(4):
    a = ServerData(opcode=op, data=enc_nfcdata(0, 1, apdu, 5)).SerializeToString()
    b = enc_serverdata(op, enc_nfcdata(0, 1, apdu, 5))
    if a != b:
        ok = False
        print("   MISMATCH opcode", op)
print("4. byte-identical ServerData encodings for OP_PSH/SYN/ACK/FIN:", ok)

for op in range(4):
    wrapped = ServerData(opcode=op, data=b"\x01\x02").SerializeToString()
    if decode_serverdata(wrapped) != (op, b"\x01\x02"):
        ok = False
        print("   MISMATCH decoding ServerData opcode", op)
print("5. protobuf-serialised ServerData decoded by hand for every opcode:", ok)
print("\nRESULT:", "hand-rolled codec is wire-identical" if ok else "MISMATCH")
