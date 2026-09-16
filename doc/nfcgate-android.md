# Bringing Android into the toolset via NFCGate

*Everything protocol-level below was read out of NFCGate's own source and then
exercised against its real server; the verification commands are at the end so
the claims can be re-checked.*

> **Since this was written, shape A is built.** A phone in reader mode is a card
> source — `nfcgate/`, `transport/nfcgate.py`, and a fourth **Source** in the
> Contactless view. See [the README](../README.md#a-phone-as-the-card-nfcgate)
> for using it. Shapes B and C are still assessments. One thing the build turned
> up that reading the source did not: see [§5](#5-what-would-actually-go-wrong).

[NFCGate](https://github.com/nfcgate/nfcgate) is an Android app for capturing,
relaying and replaying NFC traffic, built at TU Darmstadt's Secure Mobile
Networking Lab. Its relay mode puts two phones on either end of a
[server](https://github.com/nfcgate/server): one reads a tag, the other presents
it over Host Card Emulation. Both are Apache-2.0.

The question is whether ATRIUM can join that arrangement — and the answer is
that it can join it more cheaply than expected, because **the NFCGate server
does not understand NFC at all.**

---

## 1. What the server actually is

`server.py` is 190 lines of standard-library Python. It reads a length-prefixed
frame, notes a one-byte session number, and forwards the payload verbatim to
every other client in that session. It never parses the payload. There is no
authentication, no negotiation, and no notion of "reader" or "tag" — those are
roles the *clients* agree on between themselves.

That has one consequence worth stating plainly:

> **Anything that speaks the framing and joins the same session number is
> indistinguishable from a phone.**

ATRIUM does not have to bolt itself onto a two-phone relay. It can *be* one of
the two peers.

### The framing

Asymmetric, which is easy to get wrong:

| Direction | Header | Body |
|---|---|---|
| client → server | `uint32` big-endian length, then `uint8` session | `length` bytes |
| server → client | `uint32` big-endian length | `length` bytes |

Session is `1`–`255`. A frame with session `0` before any session is set closes
the connection. Changing the session byte mid-stream moves the client between
sessions.

### The payload

Two protobuf messages, both tiny. From `protocol/protobuf/`:

```proto
// c2s.proto — client ⇄ server
message ServerData {
  enum Opcode { OP_PSH = 0; OP_SYN = 1; OP_ACK = 2; OP_FIN = 3; }
  Opcode opcode = 1;
  bytes  data   = 2;
}

// c2c.proto — client ⇄ client, carried inside ServerData.data on OP_PSH
message NFCData {
  enum DataSource { READER = 0; CARD = 1; }
  enum DataType   { INITIAL = 0; CONTINUATION = 1; }
  DataSource data_source = 1;
  DataType   data_type   = 2;
  bytes      data        = 3;
  int64      timestamp   = 4;   // unix millis
}
```

The handshake is `OP_SYN` on connect; a peer already in the session answers
`OP_ACK`, a peer arriving later sends its own `OP_SYN` which you answer with
`OP_ACK`. `OP_FIN` on the way out. Everything else is `OP_PSH`.

The four `NFCData` combinations carry the whole relay:

| `data_source` | `data_type` | Meaning |
|---|---|---|
| `CARD` | `INITIAL` | the tag's NCI configuration — sent once, on discovery |
| `READER` | `CONTINUATION` | a C-APDU |
| `CARD` | `CONTINUATION` | an R-APDU |
| `READER` | `INITIAL` | unused in practice |

### The INITIAL payload is where the card's identity lives

`NFCData.data` on an `INITIAL` message is an **NCI config stream** — a flat run
of `[type:1][len:1][value:len]` records, built by `ConfigBuilder`. The types that
matter here (`OptionType.java`):

| Type | Name | Carries |
|---|---|---|
| `0x30` | `LA_BIT_FRAME_SDD` | ATQA[0] |
| `0x31` | `LA_PLATFORM_CONFIG` | ATQA[1] |
| `0x32` | `LA_SEL_INFO` | SAK |
| `0x33` | `LA_NFCID1` | **UID** |
| `0x58` | `LI_A_RATS_TB1` | FWI / SFGI |
| `0x59` | `LI_A_HIST_BY` | **ATS historical bytes** |
| `0x5B` | `LI_A_BIT_RATE` | max bit rate |
| `0x5C` | `LI_A_RATS_TC1` | NAD / CID support |

Type B uses `0x38`–`0x3E`, Type F uses `0x40`/`0x51`/`0x53`.

This is better than what `ContactlessTransport` gets from the ACR122U today.
`0x59` is literally the ATS historical bytes, so `get_atr()` has something
honest to return, and `card_fingerprint.py` gets UID, SAK and ATQA handed to it
rather than having to ask for them.

---

## 2. How it maps onto what already exists

`transport/base.py` asks for four methods — `connect`, `get_atr`, `transmit`,
`disconnect`. Everything above that line (fingerprinting, the mutation engine,
the AI agent, the Live Trace, DE55 on the host side) depends on nothing else.
That abstraction is the reason this is cheap.

### Shape A — the phone holds the card  ✅ built

```
ATRIUM ──► NFCGateTransport ──► session ──► phone (reader mode) ──RF──► card
```

`transport/nfcgate.py`, implementing `CardTransport`:

- `connect()` — open the socket, `OP_SYN`, wait for the peer's `OP_SYN`/`OP_ACK`,
  then block for the first `CARD`+`INITIAL` message and keep the parsed config.
- `get_atr()` — return the ATS reconstructed from `0x59` (+ `0x58`/`0x5C`), the
  same "this is an ATS, not an ATR" caveat `ContactlessTransport` already
  documents.
- `transmit(apdu)` — send `READER`+`CONTINUATION`, block for the matching
  `CARD`+`CONTINUATION`, return its bytes.
- `disconnect()` — `OP_FIN`, close.

Then one branch in `transport/source.py::open_card_source()` and a phrase for
the status line. Nothing else changed — which was the bet, and it held. A phone becomes a card source next to
"a card in a reader", "a recorded capture" and "a card on another host" — in the
CLI and in the **Contactless** view's existing *Source* dropdown alike.

**This shape needs only a stock phone**: NFC, the NFCGate app, no root.

### Shape B — the phone presents the card

```
terminal ──RF──► phone (HCE) ──► session ──► ATRIUM ──► any CardTransport
```

Here ATRIUM is the tag-side peer and the phone replaces the ACR122U as the thing
held to the terminal. That is worth doing on its own merits, because it retires
two of the three limitations `nfc/emulator.py` documents:

| ACR122U in target mode | Phone in NFCGate tag mode |
|---|---|
| NFCID1[0] forced to `0x08` — the "random UID" marker, so a terminal pinning a UID never sees the card's | `LA_NFCID1` sets the UID, via the native hook |
| 253 bytes per exchange; longer needs ISO 14443-4 chaining, unimplemented | Android's stack does ISO-DEP chaining |
| USB round trip per APDU | RF → phone → network → ATRIUM → card: **worse**, see §5 |

**This shape needs a rooted phone**: LSPosed/Xposed plus NFCGate's native hook
(`nfcd`), ARMv7 or ARMv8, and HCE support. Without the hook, HCE still works but
the UID and low-level config are the platform's, not the card's — which gives
back the one thing that made shape B worth it.

### Shape C — the phone captures, ATRIUM watches

Since the server broadcasts to *every* other client in a session, ATRIUM can
join a two-phone relay as a silent third peer and stream both directions into
the Live Trace without being in the path at all. Nearly free once shape A's
codec exists, and the only shape that adds no latency.

---

## 3. Who should run the server

Three options; the third is the recommendation.

1. **Point ATRIUM at an existing NFCGate server.** Fewest moving parts to write,
   most to set up — the operator runs a second project, and mutations have to
   happen inside ATRIUM's transport rather than in the path.
2. **Launch `server.py` as a subprocess.** Vendors a second project's code and
   its no-authentication posture into a tool that has otherwise gone to some
   trouble about that (see `secure_link.py`, and `_allowed_hosts` in
   `api/server.py`).
3. **Implement the server inside ATRIUM.** ~80 lines. The phone connects to
   ATRIUM directly, one process and one port, no second project to install. And
   it puts ATRIUM exactly where NFCGate's own plugin hook sits —
   `PluginHandler.filter()` is a rewrite-in-transit interface, which is
   `mutation_engine.py`'s job description.

Option 3 also means the security posture is ATRIUM's, not NFCGate's. NFCGate's
README is explicit that its server has no authentication and must not face a
network. ATRIUM already has pinned-certificate TLS with token auth for precisely
this problem, and a phone on the same WiFi is exactly the case that needs it.

---

## 4. The dependency question, and why there isn't one

The obvious cost is `protobuf`. Two things make it avoidable.

First, the shipped generated files do not work anyway. `plugins/c2s_pb2.py` was
generated against protobuf 3.x's C++ descriptor API and raises on import under
any modern runtime:

```
TypeError: Descriptors cannot be created directly.
If this call came from a _pb2.py file, your generated code is out of date
and must be regenerated with protoc >= 3.19.0.
```

So "just import NFCGate's plugins" is not on the table regardless; the choice is
between regenerating with `protoc` and encoding the messages directly.

Second, these two messages are about as small as protobuf gets: two varint
enums, one length-delimited `bytes` field, one varint `int64`, and proto3's rule
that zero-valued fields are omitted. That is roughly 40 lines of varint and
tag/length handling.

I wrote that codec and checked it against the real protobuf runtime — descriptors
built at run time, no `protoc` — across every enum combination in both messages:

```
1. hand-encoded NFCData parsed by protobuf runtime: 00A4040007A0000000031010
2. protobuf-serialised NFCData decoded by hand:     330407ABCDEF3201203004
3. byte-identical NFCData encodings for every case: True
4. byte-identical ServerData encodings for OP_PSH/SYN/ACK/FIN: True

RESULT: hand-rolled codec is wire-identical
```

**No new dependency.** That matters here: `requirements.txt` is deliberately
lean, the host layer's whole point is that it imports neither `pyscard` nor
`virtualsmartcard`, and this project already hand-rolls its wire formats in
`card_proxy.py`, `secure_link.py` and `host/iso8583/`.

I then ran NFCGate's actual `server.py` and relayed a real EMV exchange through
it between two stdlib clients — no protobuf, no Android:

```
1. handshake: A received opcode=1 (1 = OP_SYN from the peer)
2. handshake: B received opcode=2 (2 = OP_ACK)
3. tag config reached A: source=1 type=0 25 bytes  UID=04A2B1C0 SAK=20
4. C-APDU reached B: 00A4040007A0000000031010  (source=0 READER)
5. R-APDU reached A: 6F2F840E325041592E5359532E44444630319000  (source=1 CARD)

RESULT: round trip OK
```

The framing, the handshake, the session multiplexing and the config-stream
parsing are all confirmed against the real server rather than inferred.

---

## 5. What would actually go wrong

Ordered by how likely it is to matter.

**A stray `OP_ACK` can arrive at any point — found by building it.** Both peers
send `OP_SYN` on connect, and the hub has no ordering guarantee between two
clients joining a session. So each can end up seeing the other's SYN and
answering ACK, and that second ACK lands wherever it lands — including between
a command and its response. A client that assumes the next frame after a
command is the response reads an empty one instead. Running the transport
against NFCGate's real server hit this on roughly half the runs; reading the
source had not suggested it. The fix is to loop until an `OP_PSH`, which is
what NFCGate's app does and now what `nfcgate/session.py` does. The same
applies to a peer that re-announces itself mid-session: acknowledge it, do not
mistake it for data.

The related trap is ordering. The hub forwards to whoever is in the session *at
that moment*, and a client only joins by *sending* something. A peer that
relays before the other side has answered is broadcasting to nobody, and the
message is simply lost — so both sides must wait for the peer before the first
`OP_PSH`, not just announce themselves.

**Timing is the real limit.** EMV contactless kernels enforce a transaction
budget, and ISO 14443-4 enforces a frame waiting time. Shape B's path is RF →
phone NFC stack → phone CPU → WiFi → ATRIUM → USB → card and all the way back,
per APDU. NFCGate's own relay documentation flags timeouts as an expected
failure. This is the same class of caveat `nfc/emulator.py` already carries for
USB relaying, one hop worse. It does not stop protocol research, fingerprinting,
capture or replay; it does mean "a real terminal completes the tap" is not
something to promise. Mutation rules that *inject* extra commands spend the
budget twice, exactly as they already do on the ACR122U path.

Since this was written there is something to do about it rather than only note
it: **S(WTX)**, the extension ISO 14443-4 provides for exactly this case, is
implemented — see
[doc/contactless-timing.md](contactless-timing.md). It does not make the relay
faster; it makes the terminal willing to wait. That matters most for shape B,
where the network hop is inside the terminal's budget.

**Tag mode needs a rooted phone.** Shape A is stock-Android. Shape B without
LSPosed gets HCE but loses UID control — which is most of the reason to prefer a
phone over the ACR122U.

**HCE only routes declared AIDs.** Android delivers `SELECT` to an app only for
AIDs in its `apduservice.xml`. NFCGate declares a broad set, but an unrouted AID
never reaches the app, and this is per-target worth checking.

**The link is unauthenticated by default.** NFCGate's design assumes an isolated
network. Whatever ATRIUM does here must default to loopback and reuse
`secure_link.py`, not inherit that assumption.

**The app is being flagged as malware.** NFCGate's README currently warns that
it is being falsely detected as "NGate" by AV vendors. Not a technical blocker,
but it will come up when installing it on a test device.

---

## 6. Assessment

Feasible, and unusually well-matched to the code that is already here. The
server is a dumb broadcast bus, the protocol is two small messages that need no
dependency to speak, and `CardTransport` is exactly the seam a phone plugs into.

The order that front-loads the value:

1. ✅ **The codec and the session client** — `nfcgate/proto.py` and
   `nfcgate/session.py`. No dependency, tested against a fake peer the way
   `nfc/emulator.py` is tested against a fake chip.
2. ✅ **Shape A** — `transport/nfcgate.py` plus one branch in
   `open_card_source`. Stock phone, no root; every existing consumer worked
   unchanged on the day it landed.
3. **Shape C** — near-free now that (1) exists, and the only shape with no
   latency cost. A second session client that only listens, feeding the Live
   Trace.
4. **The built-in hub**, if shape B is wanted — this is where the security work
   and the mutation-in-transit hook belong.
5. **Shape B** last. It is the most valuable and the most conditional: it needs
   a rooted phone, and its timing behaviour has to be measured on real hardware
   before anything is claimed for it.

Steps 4–5 are a larger commitment that should follow a timing measurement, not
precede one. Nothing in 1–3 has been in front of a real phone yet; that is the
next thing worth doing, and it is the only way the timing question gets an
answer.

---

## Reproducing the verification

Both checks are self-contained and need no Android device:

```bash
git clone --depth 1 https://github.com/nfcgate/server.git nfcgate-server

# the wire format, against the real protobuf runtime  (needs: pip install protobuf)
python3 doc/verify_proto.py

# the shipped transport, against NFCGate's real server  (stdlib only)
python3 doc/verify_relay.py nfcgate-server
```

`verify_proto.py` builds the descriptors at run time, so neither script needs
`protoc` or NFCGate's generated `_pb2.py` files, and it checks the codec ATRIUM
actually ships rather than a copy of it. `verify_relay.py` drives the real
`NFCGateTransport` through NFCGate's real server against a stdlib stand-in for
a phone, and needs nothing but the standard library — which is the point it is
making.

`pytest tests/test_nfcgate.py` covers the same ground without either clone,
against a hub with the same broadcast semantics.

Source read for this assessment:

| Claim | Where |
|---|---|
| framing, session multiplexing, no auth | `server.py` — `NFCGateClientHandler.handle`, `send_to_clients` |
| the same framing from the app | `network/threading/{Send,Receive}Thread.java` |
| handshake opcodes | `network/NetworkManager.java` — `onReceive` |
| `NfcComm` *is* `c2c.NFCData` | `common/…/util/NfcComm.java` |
| INITIAL is an NCI config stream | `common/…/nfc/config/ConfigBuilder.java` |
| the config option types | `common/…/nfc/config/OptionType.java` |
| what a discovered tag contributes | `common/…/nfc/reader/{NfcA,IsoDep}Reader.java` |
| tag-mode config application | `nfc/NfcManager.java` — `applyData` |
| timing caveats, Xposed requirement | `doc/mode/Relay.md`, `README.md` |
