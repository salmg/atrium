# Host layer — acquirer / gateway / issuer testing

Sibling to ATRIUM. ATRIUM works the card-present layer (card ⇄ terminal); this
half works the message layer above it (acquirer ⇄ gateway ⇄ issuer).

The two meet at **DE55**: field 55 of an ISO 8583 authorisation carries ICC data
as BER-TLV — the same encoding a card emits — so both halves parse and mutate it
with the same TLV core.

Nothing here imports `pyscard` or `virtualsmartcard`. This runs on a machine
with no card reader attached — see `host/requirements.txt`, which is two lines
and is where that claim is kept honest.

> **Status: phase 5 — complete.** Framing, dialects, pack/unpack, the DE55
> bridge, dialect detection, a passive relay, a playbook-driven mutating proxy,
> corpus replay, and EMV key derivation and cryptogram verification.

---

## Why a dialect is a file, not code

"ISO 8583" names a family, not a protocol. Deployments differ on at least eight
independent axes, and hard-coding any of them is what makes host tools
single-target and disposable:

| Axis | Variants covered |
|---|---|
| MLI framing | 2-byte binary (excl./incl. itself), 4-byte ASCII, 2-byte BCD, 4-byte binary |
| TPDU | absent, or a 5-byte header ahead of the MTI |
| Body encoding | ASCII, EBCDIC (cp500) |
| MTI encoding | 4 ASCII characters, 2 bytes BCD |
| Bitmap | 8-byte binary, 16-character hex; secondary auto-detected |
| Numerics | packed BCD, ASCII |
| Length prefixes | BCD or ASCII; LLVAR / LLLVAR / LLLLVAR |
| Odd-digit padding | left with zero (quantities), right with `F` (PAN, track 2) |

So a dialect is a YAML file in `dialects/`, and `codec.py` contains no
dialect-specific code at all. Supporting a new switch means writing a file.

`extends:` keeps a new dialect to a short diff — most real ones are ISO
8583:1987 plus a handful of private-use fields:

```yaml
extends: iso8583-1987
name: my-acquirer

numeric_encoding: ascii
framing:
  tpdu: {present: true, length: 5}

fields:
  62: {name: Acquirer Private, type: ans, length: lllvar, max: 999}
```

### Shipped dialects

| Name | What it is |
|---|---|
| `iso8583-1987` | The common ancestor. Everything else extends it. |
| `postilion` | ACI Postilion — ASCII numerics and length prefixes. |
| `base24` | ACI BASE24 — 5-byte TPDU, BASE24 private fields. |

The scheme specifications (Visa, Mastercard, Amex) are **deliberately not
shipped**. They are confidential, and a reconstruction from public knowledge
would be wrong in ways you would only discover mid-engagement — worse than
having nothing. On a real engagement the authoritative interface spec comes from
the target's owner, which is exactly why dialects are user-authorable content.

---

## Usage

```python
from host.iso8583 import Message, load_dialect, pack, unpack

dialect = load_dialect("iso8583-1987")

msg  = Message(mti="0100", fields={2: "4111111111111111", 4: "000000001000"})
wire = pack(dialect, msg)                 # MLI + TPDU + MTI + bitmap + fields

back, consumed = unpack(dialect, wire)    # consumed lets you advance a stream
```

### When you do not know what the target speaks

Capture first, then let the bytes tell you:

```python
from host.iso8583.detect import detect, describe

print(describe(detect(captured_bytes)))
```
```
Ranked dialect candidates:
  1. base24 [2-byte binary, 5-byte TPDU]  score=0.95  MTI 0100; 6 fields; consumed exactly; framing matches the dialect default
  2. iso8583-1987 [2-byte binary, 5-byte TPDU]  score=0.90  MTI 0100; 6 fields; consumed exactly
```

Detection works because a *correct* configuration is strongly self-verifying:
the MLI predicts exactly where the message ends, the MTI is four digits of a
plausible class, the bitmap names fields the dialect defines, and decoding them
lands precisely on the final byte. Wrong configurations rarely satisfy all four.

Nothing scores 1.0. Two dialects that differ only in private-use fields really
are indistinguishable from a plain message, and the score says so rather than
pretending otherwise.

### DE55 and the cross-layer check

The amount appears twice in an authorisation: once as DE4, which the switch
routes and authorises on, and once as tag `9F02` inside DE55, which the
cryptogram covers.

```python
from host.iso8583 import de55

nodes = de55.from_message(msg)
print(de55.summary(nodes))          # cryptogram, CID, ATC, CVM results, TVR
for d in de55.cross_check(msg):
    print(d)                        # amount mismatch: DE4=...2000 but tag 9F02=...1000
```

A mismatch is not automatically a vulnerability — it is the signal worth
chasing. Whichever copy a downstream system trusts, disagreeing copies mean
something is deciding on numbers the cardholder never approved.

---

## The passive proxy

```
acquirer / terminal  ──►  [ proxy ]  ──►  gateway / issuer
                     ◄──            ◄──
```

```bash
python3 -m host.cli proxy \
    --listen 127.0.0.1:8583 \
    --target sim.test:5000 \
    --allow  sim.test:5000 \
    --dialect base24 \
    --capture logs/host.jsonl
```

Point the acquirer or terminal simulator at the listen address. Everything that
crosses is forwarded untouched and recorded:

```
[c1] seq=2 amount mismatch: DE4=000000002000 but tag 9F02=000000001000
[c1] seq=3 PAN 499988******6666 is outside the configured test ranges.
```

```bash
python3 -m host.cli inspect --capture logs/host.jsonl
```
```
6 messages captured.
  by MTI: 0100×3, 0110×3
  ** 1 DE55 discrepancies — see 'discrepancies' fields
  ** 1 scope warnings
```

### The rule the design rests on

**Bytes are forwarded exactly as received**, the instant they arrive, before
anything tries to understand them. The frame reader gets its own copy purely to
carve out messages for the capture, so decoding sits entirely off the relay
path — it cannot delay a byte, reorder one, or drop one.

A dialect is a guess about somebody else's system. A wrong guess must cost a
capture, never a transaction. When the framing itself turns out to be wrong the
connection drops to opaque relay: bytes keep flowing, decoding stops, and the
operator is told. `test_proxy.py::test_wrong_dialect_still_relays_byte_for_byte`
pins this by running the proxy with a deliberately wrong dialect and asserting
the far side received the original bytes intact.

### Scoping

This half reaches *out* by design, so it inverts ATRIUM's inbound hardening:

| Guard | Behaviour |
|---|---|
| Target allow-list | `--allow host:port`, checked before a socket exists. **Fails closed** — an unconfigured scope reaches nowhere. |
| Test-PAN awareness | PANs outside the configured BINs are flagged. `--abort-on-live-pan` stops the proxy instead. |
| Masking | DE2 and track data are masked at capture time, not on the way out. |

The default test BINs are the card numbers published in every payment API's
documentation. They are a convenience, not a substitute for the target's own
test ranges.

> **Captures are cardholder data.** The decoded view is masked, but `raw` is the
> wire bytes and the wire carries the PAN in the clear. Capture files are
> gitignored; `--no-raw` drops the bytes entirely, at the cost of replay.

---

## Mutation

```bash
python3 -m host.cli playbooks          # what ships
python3 -m host.cli mutate \
    --listen 127.0.0.1:8583 --target sim.test:5000 --allow sim.test:5000 \
    --playbook amount-mismatch --capture logs/host.jsonl
```
```
WARNING [c1] seq=1 mutated DE4 replace: 000000001000 -> 000000009999
```

A playbook is YAML in the same shape as ATRIUM's, with the same six modes
(`replace`, `delete`, `xor`, `flip_bit`, `prepend`, `append`). Where the card
side gates on the command being executed (`on_ins`), this gates on message type
and direction of travel:

```yaml
name: amount-mismatch
description: Raise DE4 while leaving the cryptogram's own amount untouched.
enabled: true

field_mutations:                 # ISO 8583 data elements
  - de: 4
    mode: replace
    value: "000000009999"
    direction: acquirer->issuer
    on_mti: ["0100", "0200"]

de55_mutations:                  # BER-TLV tags inside field 55
  - tag: "9F36"
    mode: replace
    value: "0001"
    direction: acquirer->issuer
    on_mti: ["0100"]
```

### Shipped playbooks

| Playbook | Question it asks |
|---|---|
| `amount-mismatch` | Does the host authorise DE4 or the amount the cryptogram covers? |
| `atc-replay` | Does anything track ATC progression, or are replays invisible? |
| `cryptogram-tamper` | Is the ARQC verified at all? Flips one bit — needs no keys. |
| `cvm-forgery` | Is a claimed offline PIN cross-checked against the TVR and CVM list? |
| `entry-mode-downgrade` | Are fallback rules applied while full ICC data is present? |
| `response-tamper` | Does anything downstream validate the ARPC in tag 91? |

### What mutation costs, and what contains it

Rewriting a message means re-encoding it from the decoded form, so for the
messages a rule touches the codec moves onto the relay path. That is a real
cost, and three rules keep it contained:

1. **Only messages a rule actually changed are re-encoded.** Everything else is
   forwarded byte for byte, exactly as in passive mode.
2. **A message that did not decode cleanly is never mutated.** Problems or
   trailing bytes mean the dialect is not a perfect fit, and re-encoding would
   silently drop whatever was not understood.
3. **A re-encode that fails forwards the original** and says so. A failed
   mutation is a bad experiment; a broken link is a bad afternoon.

`MutatingProxy` also store-and-forwards rather than streaming — a message
cannot be relayed until it is whole and the playbook has had its say — which
costs a little latency that `PassiveProxy` does not pay. If you do not need to
change anything, use the passive one.

Captures stay honest under mutation: `raw` is always what arrived, `sent`
appears only when what left differed, and `inspect` reports both.

---

## Replay

Phases 2 and 3 need a real terminal or acquirer feeding the link. This does not
— it plays the acquirer itself, reading messages out of a capture. That is why
phase 2 keeps raw bytes.

```bash
# Does the host notice it has seen this transaction before?
python3 -m host.cli replay --capture logs/host.jsonl \
    --target sim.test:5000 --allow sim.test:5000

# Is the cryptogram actually bound to the transaction identity?
python3 -m host.cli replay --capture logs/host.jsonl \
    --target sim.test:5000 --allow sim.test:5000 --freshen

# Phase 3 composes: run a playbook with no live acquirer involved
python3 -m host.cli replay --capture logs/host.jsonl \
    --target sim.test:5000 --allow sim.test:5000 --playbook cryptogram-tamper
```

```
  seq  MTI   sent        rc   rtt      note
  1    0100  verbatim    00   1ms        <-- APPROVED
  2    0100  verbatim    00   0ms        <-- APPROVED

** 2 of 2 byte-identical replays were APPROVED.
   The host answered the same STAN and RRN twice without objecting, which
   points at absent duplicate detection. Confirm by checking whether the
   original transactions also cleared — two settlements for one purchase is
   the impact worth reporting.
```

### The two modes, and why both matter

**Verbatim** resends exactly what was captured. Most hosts should decline it,
because the STAN and RRN have been seen before — and a host that *approves* a
byte-identical replay has no duplicate detection at all. Nothing clever is
needed to ask that, which is why it is the default. It also needs no decode, so
it works even when the dialect cannot read the traffic.

**Freshen** (`--freshen`) rewrites only the fields that identify *this*
transaction — DE7, DE11 (STAN), DE12, DE13, DE37 (RRN) — so the message looks
new. **DE55 is never touched**: reusing the captured cryptogram unaltered under
a fresh STAN is the experiment. An approval suggests the ARQC is not bound to
the transaction identity, which is the host-layer counterpart of ATRIUM's
COMBO-E pre-play work on the card side.

STANs come from a random base rather than counting from one, so a replay into a
host that has already seen the corpus cannot collide with the original traffic
by construction — otherwise the duplicate-detection result is ambiguous.

### Verdicts are leads, not conclusions

The report says what it saw and what would confirm it. Approval codes are
scheme-specific, and a test host may be configured to approve everything, so
"3 of 3 approved" is the start of an investigation rather than the end of one.

Replay is the most active thing in this toolkit — it originates transactions
rather than observing somebody else's — so the scoping guard applies in full,
and the PAN check matters more here than anywhere else: a corpus captured from
a live link would resend real cardholder data.

### Why replay is its own client

It is built on `TcpLink`, not on the proxy's upstream leg. The proxy uses a raw
socket precisely so pass-through stays byte-exact; replay constructs what it
sends. Those are opposite needs, and sharing the code would make each inherit
the other's constraints.

---

## Cryptography

```
IMK  ──(card: PAN + PSN)──►  UDK  ──(transaction: ATC)──►  SK  ──► ARQC
```

Key derivation and the MAC are EMV Book 2 and are the same everywhere. What
differs between schemes is *which bytes get MACed* — and that is precisely the
part the scheme specifications keep confidential, so it is a profile, exactly
as dialects are.

```bash
python3 -m host.cli profiles                     # what ships
python3 -m host.cli selftest                     # what has been checked

HOST_IMK=0123456789ABCDEFFEDCBA9876543210 \
python3 -m host.cli verify --capture logs/host.jsonl
```
```
  seq=1    ARQC verified (ATC 00FF)
  seq=2    ARQC MISMATCH (ATC 0100): found 3C19…, computed BE34…
  seq=3    ARQC not checked — DE55 is missing 9F37 — profile 'emv-book2' needs
           them, so any result would be meaningless
```

Verification is the useful direction. It closes the loop with phases 2–4: you
already have captures, and this says whether what is in them was really signed
by the card it claims to come from. It also distinguishes the three outcomes
that matter — verified, genuinely mismatched, and *not checkable* — rather than
collapsing the last two into a failure, because a wrong profile and a forged
cryptogram fail identically.

### Shipped profiles

| Profile | Composition |
|---|---|
| `emv-book2` | The EMV Book 2 recommended minimum AC data, CSK session key |
| `emv-book2-iad` | The same, with Issuer Application Data (9F10) appended |
| `udk-direct` | Book 2 data MACed under the UDK, no session key |

Scheme CVN profiles are **not shipped**, for the same reason scheme dialects
are not: they are confidential, and a reconstruction would be wrong in ways you
would only find mid-engagement. A profile is ten lines; write yours from the
spec your client provides.

### Re-signing: what it is actually for

`replay --imk` recomputes the ARQC after a playbook has changed the message.
That flips the question being asked:

| Run | Question answered |
|---|---|
| `--playbook atc-bump` | Does the host verify cryptograms at all? |
| `--playbook atc-bump --imk …` | Given a *valid* cryptogram, what else does the host check? |

Verified end to end: bumping the ATC inside DE55 produces a cryptogram the host
rejects — and with `--imk` the same modified message carries a cryptogram that
verifies. The report says which mode produced a result, because an approval
means opposite things in the two cases.

The mutating proxy does not re-sign yet; only replay does.

### What the crypto has and has not been validated against

`selftest` prints this, and it belongs here too:

- **Checked** — the DES primitive against pycryptodome (via the property that
  3DES with `K1 == K2` reduces to single DES), and that derivation, MACing and
  ARPC generation are self-consistent and correctly diversified by PAN, PSN and
  ATC.
- **Not checked** — that any profile matches a particular scheme's CVN. Validate
  against your target's own test vectors before treating a verification result
  as evidence in a report.

Option B UDK derivation raises rather than approximating. A half-right
derivation produces keys that look plausible and verify nothing, which is a
worse failure than an honest refusal.

### Handling issuer master keys

An IMK derives every card key in its range, so it is the most valuable secret
this toolkit touches. Nothing logs one, puts one in a `repr`, or writes one to a
capture. Sources are tried most-private first — `--imk-file`, then `$HOST_IMK`,
then `--imk`, and the last one warns, because argv is readable by every other
process on the machine.

---

## Driving it from the dashboard

The CLI is the primary interface; the **ISO 8583** view exists so an operator
already watching a card session can work the link above it without changing
terminals. It covers the passive and mutating proxy, a capture browser with
dialect detection, replay, and cryptogram verification.

Three guards carry over, because a browser button is an easier thing to press
by accident than a command line is to type:

| Guard | In the UI |
|---|---|
| Target allow-list | Mandatory field; **fails closed** — the request is refused before a socket exists |
| Mutation and replay | Both need `confirm: true`, and the UI asks first. The passive proxy does not — observing changes nothing |
| Issuer master keys | **Never travel through the API.** Verification reads `$HOST_IMK` or `$HOST_IMK_FILE` server-side; a key in a request body would land in access logs, proxy logs and browser history |

`tests/test_host_api.py` pins all three, plus capture-name traversal and the
rule that no request model may carry a key field at all.

---

## Design notes

**Degrade, never crash.** `unpack` records a problem and stops rather than
raising. Pointed at an unknown dialect that is close but not exact, a message
decoded up to field 43 is real evidence; an exception is not. Callers check
`Message.problems` and `Message.complete`. This mirrors `maybe_parse_tlv` on the
card side.

**The TLV core is vendored, not imported.** `iso8583/tlv.py` duplicates
ATRIUM's TLV code so this package needs no `pyscard` install. Duplication is
only safe while the copies agree, so `tests/test_tlv_parity.py` runs both over a
shared corpus and fails on any divergence. When a second consumer justifies it,
both collapse into a shared `paycore.tlv` and the guard retires with them.

**The length prefix counts different things per type.** Digits for `n`/`z`,
characters for `an`/`ans`, **bytes** for `b`. DE55 is `b`, so its LLLVAR prefix
is a byte count. This is the classic ISO 8583 foot-gun and it has a test.

---

## Tests

```bash
python3 -m pytest host/tests -q
```

The central codec fixture is assembled from explicit bytes rather than produced
by our own packer, so a symmetric bug — one that encodes and decodes wrongly in
the same direction — cannot pass.

---

## Roadmap

| Phase | Scope | State |
|---|---|---|
| 1 | Dialects, framing, codec, DE55 bridge, detection | **done** |
| 2 | Passive proxy, capture log, scoping guard | **done** |
| 3 | Mutation engine + playbooks | **done** |
| 4 | Corpus replay, freshening, verdict reporting | **done** |
| 5 | Key derivation, cryptogram verification, ARPC | **done** |

Cryptography came last on purpose. Everything above it answers real questions
without a single key, and `cryptogram-tamper` in particular asks whether the
ARQC is verified *at all* — which is worth knowing before investing in
computing one correctly.

Natural next steps, none of them started: re-signing inside the mutating proxy
(replay has it, the live path does not), UDK derivation Option B, and a
`paycore` extraction once the TLV parity guard has earned its retirement.
