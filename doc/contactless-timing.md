# Keeping a contactless relay alive

*Why a relayed transaction gets dropped, which clock does the dropping, and
what can actually be done about each. Every register value and byte layout
below was read out of an implementation and checked, not recalled; sources are
at the end.*

A contactless relay is slow. The card is somewhere else — down a USB cable,
across a network, inside a phone — and ISO/IEC 14443-4 gives a card one budget
to answer in. Miss it and the terminal abandons the transaction, with nothing
on the wire to say why.

The obvious move is to find the timeout and turn it up. That turns out to be
the wrong shape of answer, and understanding why is most of this document.

---

## 1. There are three clocks, and they belong to different people

Almost every "the relay disconnected" question is really a question about which
of these ran out.

| Clock | Whose | Bounds | Set by |
|---|---|---|---|
| **PN532 RF timeout** | ours, as *reader* | how long the chip waits for a card it is reading | `RFConfiguration` |
| **FWT** (frame waiting time) | the **terminal's** | how long it waits for the emulated card to answer | the **ATS** the card sends |
| **PC/SC escape read** | the host's | how long `SCardControl` waits for the reader | libccid / pcsc-lite |

They are not alternatives — they sit in different directions of different
conversations. Tuning the first will never affect the second, which is the trap
the next section is about.

---

## 2. What `RFConfiguration` can and cannot do

`RFConfiguration` (`0x32`) is the command usually reached for. Two of its
configuration items come up in this context, and the advice circulating about
them contains a mistake worth naming.

### The byte layouts, corrected

**`CfgItem 0x05` — MaxRetries.** Three bytes: `MxRtyATR`, `MxRtyPSL`,
`MxRtyPassiveActivation`. `0xFF` means "indefinitely".

```
32 05 FF 01 FF
```

This is correct as usually quoted, and ATRIUM has always sent it —
`nfc/pn532.py::set_retries`. But note what it controls: how many times
`InListPassiveTarget` retries **looking for a card**. It is about *finding* a
card, not about *holding* a session. It cannot keep anything alive.

**`CfgItem 0x02` — Various timings.** Commonly quoted as
`32 02 [ATR_TO] [Data_TO]`. **That is missing a byte.** It takes *three*
configuration bytes, the first RFU:

```
32 02 00 <ATR_RES_Timeout> <RetryTimeout>
      ^^ RFU — omit it and every value lands one slot early
```

Sent the short way, the ATR timeout is written into the RFU slot and the data
timeout becomes the ATR timeout. Defaults are `0x0B` (102.4 ms) for
`ATR_RES_Timeout` and `0x0A` (51.2 ms) for `RetryTimeout` — and "the default is
roughly 102.4 ms" is often quoted for the wrong one of the two.

### The value table

| Value | Timeout | | Value | Timeout |
|---|---|---|---|---|
| `0x00` | **no timeout** | | `0x0A` | 51.2 ms *(RetryTimeout default)* |
| `0x01` | 100 µs | | `0x0B` | 102.4 ms *(ATR_RES default)* |
| `0x02` | 200 µs | | `0x0C` | 204.8 ms |
| … | doubling | | `0x0F` | 1.64 s |
| `0x09` | 25.6 ms | | `0x10` | **3.28 s — the maximum** |

So the largest settable RF timeout is `0x10` ≈ 3.28 s, and `0x00` means "wait
forever". Neither `0xFF` nor anything above `0x10` means anything.

### Why neither one helps

**`RetryTimeout` does not cover the traffic we care about.** Its documented
scope is `InCommunicateThru`, and `InDataExchange` **when the target is a
FeliCa or a Mifare card**. ATRIUM's contactless transport refuses anything that
is not ISO 14443-4 (`transport/contactless.py` checks `is_iso14443_4`), and for
those the PN532 honours **the FWT the card itself declared in its ATS TB(1)** —
correct ISO behaviour, and already up to ~4.9 s. That is why contactless reads
work today without this ever being set.

**`RFConfiguration` configures an initiator.** In target mode we are not the
one waiting — the terminal is. No configuration item reaches it.

> **The one case where `CfgItem 0x02` would matter** is raw framing via
> `InCommunicateThru`, or a Mifare/FeliCa target. ATRIUM does neither, which is
> why the knob is deliberately *not* exposed: a control that looks like it
> helps and does nothing is worse than its absence.

---

## 3. The terminal's clock is in the ATS, and the chip owns the ATS

The terminal's patience is FWT, and FWT comes from **FWI** in the ATS's TB(1)
byte:

```
FWT = (256 × 16 / 13.56 MHz) × 2^FWI      FWI 0–14, max ≈ 4.949 s
```

`TgInitAsTarget` accepts MifareParams (6), FeliCaParams (18), NFCID3t (10),
General bytes, and **Tk — historical bytes — only**. There is no field for
TA(1)/TB(1)/TC(1). The PN532 synthesises the ATS around whatever historical
bytes it is given.

**So with the chip doing ISO-DEP, FWI is not yours.** Nor is there any way to
send S(WTX), nor to chain a long response. Three limits, one cause.

---

## 4. S(WTX) — the mechanism the standard actually provides

ISO/IEC 14443-4 §7.3 has an answer for a card that needs longer than FWT: ask.

```
card → reader   S(WTX) request    F2 <WTXM>        WTXM = 1..59
reader → card   S(WTX) response   F2 <WTXM'>       WTXM' ≤ WTXM
                new budget = FWT × WTXM'
```

The reader may grant less than was asked; the smaller number is the one that
applies. This repeats for as long as the card keeps asking, which is what makes
it survivable for a relay of unknown slowness.

Reaching it means taking the block layer from the chip:

1. `SetParameters` with `PARAM_14443_4_PICC` (`0x20`) **clear**
2. mode byte `PTM_PASSIVE_ONLY` (`0x01`), dropping `PTM_ISO14443_4_PICC_ONLY`
3. `TgGetInitiatorCommand` (`0x88`) / `TgResponseToInitiator` (`0x90`) instead
   of `TgGetData` / `TgSetData` — blocks, not APDUs
4. implement ISO-DEP: RATS/ATS, I/R/S blocks, block numbering, chaining, WTX

That is `nfc/isodep.py` (the layer, pure) and `IsoDepEmulator` in
`nfc/emulator.py` (the driver).

### What it buys

| | Chip does ISO-DEP (default) | `--own-isodep` |
|---|---|---|
| FWI in the ATS | firmware's, card-like | **ours**, up to ~4.9 s |
| S(WTX) | never sent | **sent for as long as the card takes** |
| Response > one frame | refused, relayed unmutated | **chained** |

### How the relay stays answerable

The transport call runs on a worker thread so the RF side stays free. That is
the whole trick: a relay is slow because of something happening *elsewhere*,
and S(WTX) has to go out **while** it happens.

```
receive I-block ─► start relay on a worker
                   │
                   ├─ budget elapsed, worker still running?
                   │     └─► send S(WTX), read the grant, extend, repeat
                   │
                   └─ worker done ─► send the response, chained if long
```

`wtx_at` (default 0.6) is the fraction of the budget to spend before asking —
the rest is headroom for the round trip that carrying the S(WTX) itself costs.
Lower it on a slow link.

---

## 5. What is verified, and what is not

**Verified, in `tests/test_isodep.py`:** every block shape and its PCB bits, the
ATS we build and parse, FWT/FSC arithmetic, chaining in both directions, block
numbering, CID handling, R(NAK) retransmission, DESELECT, and S(WTX) including
a reduced grant.

The fake terminal implements the **reader half** rather than scripting both
sides, and it **has a clock**: it records any block that misses its deadline. A
control test runs the same slow card with S(WTX) disabled and asserts the
deadline *is* blown — so the harness demonstrably detects the failure it exists
to catch. Without that, "no timeouts" would prove nothing.

**Not verified, and not verifiable here:** anything on the air. Whether the
ACR122U's CCID bridge passes the raw target commands at all. Whether a real
terminal accepts our ATS. Whether the timing holds once a physical RF link and
a real card are in the path. libnfc never implemented this path — it returns
`NFC_ENOTIMPL` with a "TODO support by software" comment — so there is no prior
art to lean on.

This is why `--own-isodep` is **off by default**. The chip's own layer stays
the proven one.

---

## 6. Hardware bring-up, in order

Each step's failure has a different cause, so do them in this order and stop at
the first that fails.

### 1. Reach the chip at all

The PN532's own commands do not travel as ordinary APDUs. They need
`SCardControl`, and there are two separate ways that fails — which look
identical from Python and need opposite fixes.

```
Escape said: Failed to control Feature not supported.
Raw transmit said: the reader accepted the transmit but answered nothing …
```

The second line is the fallback also failing, which is *expected* on pcsc-lite:
a direct connection has no negotiated protocol for `SCardTransmit` to use. It
is not a second problem. The first line is the one that matters, and
**`pcscd`'s log says which of the two causes it is**:

```bash
sudo journalctl -u pcscd -f
```

| pcscd logs | Meaning | Fix |
|---|---|---|
| `Card not transacted: 606` | `IFD_ERROR_NOT_SUPPORTED` — `IFDHControl`'s **default** return. The control code was not recognised at all | **wrong escape code** — below |
| `Card not transacted: 612` | `IFD_COMMUNICATION_ERROR` — the escape branch was entered and refused | **not authorised** — below |
| `ifd exchange (Escape command) not allowed` | the same, said plainly | **not authorised** |

**The escape control code is not one number.** This is the trap, because the
symptom impersonates the authorisation problem:

| Stack | Control code |
|---|---|
| Linux / libccid | `SCARD_CTL_CODE(1)` — `IOCTL_SMARTCARD_VENDOR_IFD_EXCHANGE` |
| Windows | `SCARD_CTL_CODE(3500)` |
| macOS, BSD | `((0x31) << 16) \| (3500 << 2)` |

Send libccid the Windows number and `IFDHControl` falls through every branch to
its default — 606, surfacing as "Feature not supported". No amount of editing
`ifdDriverOptions` changes that, which is what makes it so confusing: the
obvious fix is applied, pcscd is restarted, and nothing improves.

ATRIUM asks rather than guesses. PC/SC part 10 defines a feature query
(`CM_IOCTL_GET_FEATURE_REQUEST`), and libccid answers it with the control code
to use — but it only lists `FEATURE_CCID_ESC_COMMAND` **when escape is
authorised**. So one query settles both questions, and the error names the
cause it actually found. Platform guesses are the fallback when a driver will
not answer the query.

**If it is the authorisation** (612, or the feature query answered with no
escape feature):

```bash
# The path differs by distribution, so find it rather than assume it.
plist=$(ls /etc/libccid_Info.plist \
           /usr/lib*/pcsc/drivers/ifd-ccid.bundle/Contents/Info.plist \
           /usr/local/lib*/pcsc/drivers/ifd-ccid.bundle/Contents/Info.plist \
        2>/dev/null | head -1)

grep -A1 ifdDriverOptions "$plist"        # what it is now

sudo sed -i '/ifdDriverOptions/{n;s|<string>0x[0-9A-Fa-f]*</string>|<string>0x0001</string>|}' "$plist"
sudo systemctl restart pcscd.socket pcscd.service
```

`0x0001` is `DRIVER_OPTION_CCID_EXCHANGE_AUTHORIZED`. The sed anchors on the
key and edits the line after it, so it stays correct when the value is already
something other than `0x0000` — a global `0x0000 → 0x0001` silently does
nothing in that case and looks like the fix failed.

### 2. Confirm the escape path reaches the chip

```bash
python3 atrium.py nfc info
```

A firmware version coming back means every command below can reach the PN532.
Everything after this point is RF behaviour rather than plumbing.

If instead it says **"No usable response to command 14 (got incomplete, 0
bytes)"**, the escape channel is working and the *framing* is wrong. What the
ACR122U wants is the **bare** command, because its own microcontroller builds
the normal information frame:

```
FF 00 00 00 <Lc> D4 <command> <parameters…>      Lc counts the D4
```

and it answers in kind, with its own status word appended:

```
D5 <command+1> <data…> 90 00
```

Hand it a command that is already framed — preamble, LEN, LCS, DCS and all —
and it returns **nothing at all**: no error, an empty reply, which is exactly
the symptom above. `nfc/acr122.py` unwraps on the way out and re-frames on the
way back, so the chip layer above it still deals in whole frames and knows
nothing about this.

For comparison, a correct GetFirmwareVersion on the wire is seven bytes:

```
FF 00 00 00 02 D4 02
```

### 3. When a command answers nothing, look before guessing

Three bring-up failures on this reader produced the same sentence — the reader
accepted a command and returned nothing — and each had a different cause. Two
of the three diagnoses were wrong, because the message the code produced could
not tell them apart.

```bash
python3 atrium.py nfc probe
```

sends the pseudo-APDUs by hand, prints every byte in both directions with the
time it took, and then says which explanation the trace supports. Nothing in it
interprets a reply into a PN532 frame, because that layer is one of the things
under suspicion.

| What the trace shows | What it means |
| --- | --- |
| the reader will not name itself | the escape channel, not the chip |
| `GetFirmwareVersion` unanswered | the wrapper reaches the reader, not the PN532 |
| answered only on a later read | the bridge defers; the answer needs collecting |
| answered only after being sent again | the bridge **discards**; re-arming is the way |
| `TgInitAsTarget` silent with a terminal present | this bridge does not carry target mode |

#### What the ACR122U actually does

Two runs of the probe, minutes apart, settled a question three rounds of
guessing had not. With a terminal already on the reader:

```
[  0.267s] → FF0000002BD48C0104000102032000…0475339203   TgInitAsTarget
[  2.541s] ← D58D00E0809000  (2274 ms)
```

`D5 8D` is the reply, `00` the mode byte — 106 kbps, Mifare framing, PICC off,
DEP off, which is precisely what raw ISO-DEP wants — and `E0 80` is the
**RATS**: FSDI 8, so 256-byte frames, CID 0. Target mode works, the bridge
carries it, and the activation data hands over the RATS to answer.

With no terminal:

```
[  0.027s] → FF0000002BD48C…      TgInitAsTarget
[  5.042s] ← (nothing)            5015 ms later
[  5.293s] → FFC0000000  ×30      GET RESPONSE, every 250 ms
           ← (nothing)            on all thirty
[ 13.353s] → FF00000003D41214     SetParameters — answered in 131 ms
```

Three facts in that trace, none of them guessable from above:

1. The bridge blocks for about **five seconds** and then gives up.
2. It **discards** the command rather than deferring it — thirty GET RESPONSEs
   found nothing, because there was nothing left to find.
3. The chip is **not wedged** by the timeout. `SetParameters` answered
   normally, so the reader's microcontroller cancelled cleanly.

Taken together: polling for a deferred answer is wasted traffic here, and
sending the command again is both necessary and safe.

#### What the code does with that

`PN532.call` now distinguishes the two silences, and the ACK is what tells them
apart:

* **The chip acknowledged.** The answer is genuinely coming, so it is collected
  by reading again. A directly-attached PN532 behaves this way.
* **Nothing came back at all.** The bridge's timeout took the command with it,
  so the answer is to send it again — which for `TgInitAsTarget` means
  *re-arming target mode until a terminal turns up*.

The distinction is sticky: once the chip has acknowledged, a quiet read means
"not finished", never "start over". Re-sending an acknowledged
`TgInitAsTarget` would restart target mode on every poll and never get past the
first one.

Only three commands may be re-sent — `TgInitAsTarget`, `TgGetData`,
`TgGetInitiatorCommand`. The first re-arms; the other two are reads with no
side effect. Nothing else: `TgSetData` twice would put a response on the air
twice.

The deadlines are three different lengths because they are three different
questions:

| | Wait | Why |
| --- | --- | --- |
| the chip answering itself | 1 s | a round trip over USB |
| a terminal mid-session | 20 s | silent this long and it has gone |
| a terminal that has not arrived | 60 s, or 300 s from the emulator | a person carrying a reader to a till |

The wait is interruptible throughout, so `stop()` and Ctrl-C end it rather than
being ignored until the deadline.

Before this, `PN532.call` only polled when the first frame parsed as an ACK — an
"incomplete" one raised immediately, and on this reader it is always incomplete
because the escape path synthesises `90 00` and the `61 xx` continuation can
never fire. That is the whole of the 40 ms failure:

```
TgInitAsTarget (D4 8C) … returned nothing
```

Two smaller things fell out of the same change:

* An empty reply is not an error at the link any more. It means *not yet*, and
  the deadline lives one layer up, where the command is known.
* The trailing `90 00` is stripped **only** on the escape path. A transmit has
  already had its status word separated by the driver, so stripping there took
  the `90 00` off the end of every relayed response that had succeeded.

#### Three things that only showed up once it was running

**The reply's mode byte is not the command's.** `TgInitAsTarget` takes a mode
*parameter* and answers with a mode *byte*, and they are laid out differently:

```
parameter   b0 PassiveOnly   b1 DEPOnly   b2 PICCOnly

reply       b2 b1 b0  baud     000 = 106 kbps, 001 = 212, 010 = 424
            b3        activated as an ISO/IEC 14443-4 PICC
            b4        activated in DEP mode
            b6 b5     framing  00 = Mifare, 01 = Active, 10 = FeliCa
```

Reading the reply by the parameter's masks turned a working activation into a
rejection. The chip answered `08` to a command that had asked for **PICC
only** — read as the parameter, that is "DEP", which is precisely what
PICC-only forbids. The impossibility is what settled it: bit 3 is the PICC bit,
and `08` meant the fix below had worked. There is one decoder now,
`describe_target_mode`, because the two that existed had drifted apart and were
each wrong differently.

The test fixtures had carried an arbitrary `04` for as long as nothing read the
byte — a reserved baud rate with ISO-DEP off, which no chip would ever send.

**The firmware path needs `PARAM_14443_4_PICC` on, and nothing was setting
it.** That bit runs the chip's ISO-DEP state machine as a PICC, and `TgGetData`
carries APDUs only while it does. It is deliberately not in the reader baseline
(`DEFAULT_PARAMETERS` is `0x14` — `AUTO_ATR_RES | AUTO_RATS`, because a reader
has no use for PICC), and `wait_for_terminal` only ever *cleared* bits. So the
default path activated with ISO-DEP off and relayed nothing, with no error
anywhere to say why. `_borrow_chip` now sets as well as clears, and an
activation whose mode byte comes back without bit 2 is refused where the cause
is still in view rather than becoming a relay that sits at zero.

**Stopping used to close the link out from under the relay thread.** That was
right when nothing could unblock a thread parked in `TgInitAsTarget`; once the
wait became interruptible it only raced — `Link is not connected` thrown from
the middle of a command — and it took away the link `_return_chip` needs, so
every stop left `AUTO_RATS` cleared on a reader that then failed to activate
cards.

The flag is enough now. The route sets it and gives the thread eight seconds to
come back, which is the re-arm cycle the flag is checked in plus room for the
exchange in flight; the thread unwinds through its own `finally`, restores the
parameter byte and closes the link it opened. The reply carries
`chip_restored`, so a caller can tell a clean stop from the fallback — and the
fallback, closing the link, survives only for a thread that never reads the
flag at all. An exception that escapes after a requested stop is logged as a
stop rather than a failure, which is what put `Card emulation failed: Link is
not connected` in front of an operator who had simply pressed the button.

This one was found and fixed twice over, in two sessions at once, from the same
log. Worth recording only because the duplicate is the tell: a bug whose
symptom is a traceback on the ordinary path gets everybody's attention, and the
quiet ones above it — a parameter bit never set, a reply read with its wrapping
on — got none until something forced a trace.

**A reply still has its wrapping on.** `D5 8D 00 E0 80 90 00` is the direction
byte, the echoed command, the answer, and the reader's status word. The probe
read `data[0]` off the whole thing and reported "mode D5 — 212 kbps, Active
framing, PICC on", every field of which is wrong; the mode byte is `00` and the
rest is a RATS. Anything that reads an answer rather than printing it wants
`_body()` first.

#### The five-second window is invisible, so the reader says so

The consequence of re-arming is that the reader is listening for about five
seconds at a time rather than continuously, and from the desk there is no way
to tell an armed relay from a broken one. So it blinks green and beeps once
when target mode opens — `--no-alert` turns it off, and the API takes
`alert: false`. The cue costs about 800 ms before arming, because the reader
holds the command open while it blinks.

It fires **once**, before the first arm, not on every re-arm. And nothing is
cued on *selection*: the terminal is waiting for the ATS at that moment, and an
800 ms blink would spend the entire frame waiting time on a light.

Each re-arm does say so in the log, though — roughly a line every five seconds:

```
Still waiting for a terminal — target mode re-armed (attempt 4, 20s).
```

and the count reaches the dashboard as `arm_attempts`, so "listening, nobody
has come" reads differently from "hung". Before that, a correct five-minute
wait and a dead thread produced identical output: none.

#### First relay through the chip's own ISO-DEP

It works, and then it stops, and both halves are worth having in writing.

```
Selected by a terminal — 106 kbps, Mifare framing, ISO-DEP on (mode byte 08)
→ 00A404000E325041592E5359532E444446303100        SELECT 2PAY.SYS.DDF01
← 6F40840E325041592E5359532E4444463031A52E…9000   the real card's PPSE
Terminal ended the transaction (released by the initiator)
Relay finished after 1 exchange(s)
```

A full PPSE, relayed off a real UK Mastercard — `A0000000041010`, `MCENGBRGBP`,
`mc en gbr gbp`. The chip's ISO-DEP carried it, the terminal accepted the
emulated card, and the bytes came back intact.

Then the terminal let go after one exchange, 187 ms after selecting. That is
the shape of a frame-waiting-time expiry rather than a transaction ending:

| | |
| --- | --- |
| a real card here answers | FWI 7 → **38.7 ms** |
| a relay through a second reader over PC/SC | tens to hundreds of ms |
| what the chip advertises on this path | its own FWI, and it will not say |

> The last row is why this section reads as it does. It was answered later, by
> measurement: FWI 9, **155 ms**. The 39 ms in the warning quoted below is
> therefore four times too strict, and several verdicts in the sections that
> follow are wrong for that reason. They are left as they were written — the
> wrong number is the story.

PN532 status `0x29` is "released by the initiator" whether the terminal
finished or gave up, so after one exchange the two are indistinguishable —
which is why the relay now times the card and says which it looks like:

```
Relay finished after 1 exchange(s); the card took 118 ms in total,
118 ms at its slowest
WARNING The terminal let go after 1 exchange(s), and the card's slowest
answer was 118 ms — longer than the 39 ms a card-like frame waiting time
allows. That reads as the terminal timing out, not finishing.
```

**This is the case `--own-isodep` was built for**, and it is the first time the
need has been demonstrated rather than argued: the chip picks its own FWI and
cannot send S(WTX), so a relay slower than a card is dropped with nothing said.

Two smaller things came out of the same run. The emulated card was advertising
the placeholder historical bytes `75339203` while relaying a card that says
`KONA` — the raw driver already wore the card's, and the firmware one now does
too, through the `Tk` field of `TgInitAsTarget`, which is the only part of the
ATS it gets a say in. And the chip takes **three** NFCID1 bytes and prepends
`08`, so an emulated card is always a 4-byte UID starting `08`: the card on this
rig is `04270F32C33B80`, seven bytes, and no amount of code will let the PN532
wear it.

#### First relay through our own ISO-DEP, and the field nobody had set

The raw path activates, answers RATS, and then loses the transaction two
different ways on two consecutive runs:

```
RATS: reader takes 256-byte frames, CID 0 — answering ATS 0A68C0024B4F4E411080
… nothing for 20 s, TgGetInitiatorCommand re-armed 4 times

RATS: … answering ATS 0A68C0024B4F4E411080
127 ms later: CRC error ×8 inside 40 ms → "this is an RF problem"
```

Both are the same cause, and it is in that ATS. `TB(1)` is `C0`: FWI 12 — the
long budget this driver exists to choose — and **SFGI 0**.

SFGI is the *start-up* frame guard time: how long the reader must wait after
the ATS before its first command. It is not FWI, it applies once, and it is the
one field a host-side implementation cannot leave at its default:

| | |
| --- | --- |
| SFGI 0 (ours) invites the first command after | **0.30 ms** |
| SFGI 1, what the real card here answers | 0.60 ms |
| measured: ATS on the air → back inside `TgGetInitiatorCommand` | **127 ms** |

Four hundred times sooner than anyone was listening. A real card answers SFGI 1
because a real card is ready in microseconds; this is two USB round trips
through a CCID bridge. One run lost the first command outright and then sat in
`TgGetInitiatorCommand` for twenty seconds; the next came back mid-frame to a
run of CRC errors. SFGI is now **10** — 309 ms, covering the measurement with
room for the variance this bridge shows (a plain firmware query has been seen
taking 130 ms).

**The retry budget was also spent before the reader could use it.** Eight CRC
errors inside 40 ms tripped `MAX_CONSECUTIVE_RF_ERRORS` and the relay declared
the air unusable — while the terminal, which retransmits after FWT, had not yet
had its first opportunity to try again. Giving up 1.2 seconds before the other
side speaks is not an RF verdict; it is a busy loop with an opinion. The budget
now spreads across a whole FWT and each read waits its share.

**And the relay times the whole turnaround, not just the card.** FWT is
measured from the terminal finishing its command, so what counts is the card's
share *plus* everything this process and the bridge add. Reporting only the
card understates it, and the difference is the part that is ours to fix:

```
Relay finished after 1 exchange(s); the card took 54 ms in total, 54 ms at
its slowest, and the terminal waited 71 ms at worst
```

#### The deadline that is not ours to choose

Every budget on this card is one the driver picks: FWI 12, WTXM 16, SFGI 10.
One is not. Before the ATS exists there is no FWI to read out of it, so
ISO/IEC 14443-4 §7.2 fixes the wait for the ATS at FWI 4 plus the reader's
tolerance:

```
FWT(4)    4.83 ms
ΔFWT      3.62 ms
          ────────
          8.46 ms   ← the whole budget for answering RATS
```

FWI 12 is a hundred and forty times longer than that. And answering RATS from
the host costs a USB round trip through the CCID bridge — the same order of
magnitude as the budget itself.

The hardware said so before the arithmetic did:

```
11:34:10,703  RATS: … answering ATS 0A68C0024B4F4E411080
11:34:10,721  RATS: … answering ATS 0A68C0024B4F4E411080   ← again, 18 ms later
11:34:10,738  TgGetInitiatorCommand: CRC error (1)
```

**A reader sends RATS twice only when no valid ATS reached it in time.** That
signal arrives before any CRC error, and it is far more specific: the run that
looked like an RF problem was an activation that never completed. The relay now
says so — it counts RATS, times the ATS, and names the deadline it missed
rather than leaving a burst of CRC errors to be misread as interference.

This is the honest limit of `--own-isodep` on an ACR122U over PC/SC. Everything
after activation is comfortable — FWI 12 gives 1.24 s and S(WTX) extends from
there — but the one deadline before it is shorter than the transport. The
chip's own ISO-DEP answers RATS in firmware, in microseconds, which is exactly
why the default path activates where this one does not.

That does not make the block layer wrong; it makes the ACR122U the wrong place
to run it. A PN532 on a UART or SPI, where a round trip is tens of
microseconds, has room for it. This reader does not.

**And it is not only the ATS.** A later run got the ATS out in time — one RATS,
no repeat — and then failed one frame further on:

```
12:51:38,382  RATS: … answering ATS      ← accepted, no repeat this time
12:51:38,397  TgGetInitiatorCommand: parity error (1)
…                                          seven more
```

The terminal moved on to its first command and every read of it came back
parity-garbled. That is the same ceiling one round trip later: each frame the
terminal sends has to be collected across USB, and a collection that misses the
RF window returns corruption however clean the air is. So the deadline is the
sharpest instance of the problem, not the whole of it — the whole of it is that
frame-by-frame target mode over a CCID bridge cannot hold the RF timing at any
stage.

Which is why the failure text no longer says "move the reader and the terminal
apart" when *no* command has completed. That advice is right for interference
and wrong here, and this reader relays fine on the default path and under other
software, which rules interference out. It is said only after at least one
clean exchange, when the bridge has demonstrably carried a frame.

#### Answering the predictable part without the card

Three escapes per exchange is the floor, and two of them are unavoidable while
the firmware owns ISO-DEP. The third — `InDataExchange` on the card's reader —
is avoidable for the exchanges that are identical every time.

The first two commands of every contactless EMV transaction are deterministic
*and* free of terminal input: `SELECT 2PAY.SYS.DDF01`, and `SELECT <AID>` where
the AID comes out of the PPSE's own directory. Both can be fetched while the
relay is waiting for a terminal — a window measured in minutes — and answered
from memory in one escape instead of three.

`--prefetch` does that, and it is off by default. What it is *not* allowed to
do is the more interesting half:

| | |
| --- | --- |
| `SELECT` by name | cached — deterministic, no terminal input |
| `READ RECORD` | cacheable but opt-in; reaching it needs a warm-up GPO, and most cards increment the ATC there |
| `GET PROCESSING OPTIONS` | **never** — qVSDC and some M/Chip profiles pick the AIP and AFL from the terminal's TTQ in the PDOL |
| `GENERATE AC` | **never** — covers a terminal-chosen unpredictable number |
| `EXCHANGE RELAY RESISTANCE DATA` | **never** — the terminal times it in microseconds, and it is the one command this rig exists to be caught by |

It is an allowlist rather than a denylist, because a denylist eventually meets a
command nobody thought of, and on this interface that command is the one that
measures how long the card took. Only `9000` is remembered: a cached `6A82`
would make the emulated card permanently refuse an application the real one
might serve next time.

Two things it has to get right that are easy to get wrong. It is a
`CardTransport` wrapping another one rather than logic inside `_relay`, so the
cache is keyed on the bytes that actually reach the card *after* mutation, a
cached response still passes through the response rules, and a warm-up read
never lands in `slowest_card` — which would otherwise make the relay report a
timeout on a run that worked. And it is applied *after* the mutation engine has
bound its `_OsShim`, because an injected command's whole value is the card's
real answer to something the terminal never sent.

Honestly, what it buys: the deterministic prefix and no more. A typical M/Chip
flow is SELECT PPSE (cached), SELECT AID (cached), GPO (live, over budget),
READ RECORDs, GENERATE AC (live, over budget). It moves the failure from the
first exchange to the third. That is a real advance — it proves the ATS, the
activation, the PPSE and the application selection all work end to end, and it
narrows what is left to one named command — but it does not complete a
transaction and should not be described as though it does.

#### Measuring the bridge instead of inferring it

Every timing conclusion here rests on what one escape costs, and that number had
only ever been arrived at by subtraction — turnaround minus card. The probe
measures it directly now, on `FF 00 48 00 00`, a reader command with no RF in it
at all, so what is left is purely pyscard, pcscd, libccid, USB and the reader's
microcontroller:

What it says, on the rig this was all written for:

```
── what one escape costs ───────────────────────────────────────
             polling on (as shipped): min 1.6 ms, median 2.8 ms, max 3.4 ms
             polling off:             min 1.8 ms, median 2.9 ms, max 4.5 ms
             polling is not where the milliseconds are; the cost is the bridge itself
```

**2.8 ms.** Not the ~27 ms this document had been reasoning with, which was
arrived at by subtracting the card from the turnaround and attributing the
remainder to the transport. Three escapes is about **8 ms**, not 81 — the bridge
is nearly free, and the reader's own PICC polling is not where anything went.

That inverted the diagnosis, and the card bench settled where the time actually
goes:

```
── PN532 escape path (what the transport does now) ──
  InDataExchange via SCardControl: n=20 min=49.8 med=50.3 p90=51.0 max=54.2 ms

── ordinary PC/SC card path ──
  SCardTransmit T=1:               n=20 min=49.5 med=50.1 p90=51.4 max=341.7 ms

  median difference: +0.3 ms per exchange
```

Both routes to the card are the same to within a third of a millisecond, and an
escape is 2.8 ms of the fifty. **So ~47 ms is the card and its RF.** The card is
the ceiling, not the transport.

Two consequences, and the first is the retraction. The ordinary PC/SC card path
is worth nothing — it was the obvious optimisation and it buys 0.3 ms, because
both paths end in the same `InDataExchange` inside the reader's own
microcontroller. And a live relayed exchange cannot fit inside a card-like
38.7 ms frame waiting time no matter what the host does, because the card alone
spends more than that.

> **Superseded in part.** The second half of that sentence rests on the chip
> advertising a card-like FWI, which was an assumption. It was later measured
> at FWI 9 — 155 ms — and a live exchange fits inside *that* comfortably. The
> first half stands: the card is the ceiling, and the PC/SC card path is worth
> 0.3 ms. See "The number that was being assumed" below.

Which is why `--prefetch` looked like the only lever at this point: a cached
exchange never asks the card, so it costs one escape — about 3 ms — rather than
fifty. It is still a real win. It is no longer the only way through.

#### Prefetch, measured

Same rig, same terminal, back to back:

```
without --prefetch
  Relay finished after 1 exchange(s); the card took 49 ms in total,
  49 ms at its slowest, and the terminal waited 74 ms at worst
  WARNING … 74 ms for one — 49 ms of that the card … allows 39 ms.
            That reads as the terminal timing out, not finishing.

with --prefetch
  Warmed the PPSE — 1 application(s): A0000000041010
  Warm-up holds 4 response(s); the card is resting on A0000000041010
  Relay finished after 1 exchange(s); the card took 0 ms in total,
  0 ms at its slowest, and the terminal waited 32 ms at worst
  1 exchange(s) answered from the warm-up, 0 went to the card.
```

**74 ms → 32 ms**, the card's 49 ms gone entirely, and no timeout warning: the
first exchange in this whole bring-up to land inside a card-like frame waiting
time. The mechanism works exactly as designed.

And the terminal still let go after one exchange.

That is worth stating plainly rather than glossing, because it is evidence
against the explanation this document has been building. If 74 ms was a
timeout, 32 ms should not have been — unless the budget is smaller than the
38.7 ms assumed, which brings the next section from interesting to load-bearing.

#### The number that was being assumed: FWI 9, not FWI 7

Every conclusion about the firmware path assumed the PN532 offers a card-like
FWI, because the real card in front of it does. That assumption was never
measured, and it was wrong.

With two readers the question answers itself — arm one as a card, read it with
the other:

```bash
python3 atrium.py nfc measure-ats
```

`InListPassiveTarget` on the second reader returns the ATS the first one is
really sending, FWI and all. On this rig:

```
  found: UID 08010203 ATQA 0004 SAK 20 ATS 7533920375339203
  The chip's own ATS: 7533920375339203
    interface bytes  75339203  — the chip's
    historical bytes 75339203  — ours, from TgInitAsTarget
  FWI 9 — a frame waiting time of 155 ms.
  FSCI 5 (64-byte frames), SFGI 2.
```

**FWI 9 — 155 ms, four times the 38.7 ms assumed.** A live 50 ms card fetch
fits inside it with room to spare, and so did every relayed exchange this
document called a timeout. `_RelayCore.CHIP_FWT` now carries the measured
number, and there is a test pinning it to `fwt_seconds(9)` so the guess cannot
creep back.

The ATS reading as the same four bytes twice is not a fault. `75 33 92 03` are
the chip's interface bytes — T0, TA(1), TB(1), TC(1) — and also, by
coincidence of provenance, ATRIUM's default historical bytes: the default is
libnfc's, and libnfc took it from this chip's own ATS. `EmulatedCard.historical`
is named for what it is now; it was called `ats`, which is what made the
duplicate look like a bug rather than a curiosity. A relay overwrites it with
the real card's bytes anyway.

#### What the wrong budget cost

Reporting is not decoration here. With `CHIP_FWT` four times too strict, every
relay that ended early got this:

```
  WARNING … waited 144 ms for one … allows 39 ms. That reads as the
  terminal timing out, not finishing.
```

…on a run that was *inside* its budget the whole time. Days of work went at
latency that was never the problem. The verdict now separates three endings
that used to be one message:

| what happened | how it is known | what it means |
|---|---|---|
| ended slower than FWT | status `29` and a turnaround over the budget | a real expiry; `--own-isodep` is the mechanism |
| ended **inside** FWT | status `29` and a turnaround under it | not a timeout — the terminal read something and chose to stop |
| field went away | status `2B` | the card was lifted, or the terminal stopped driving |

Statuses `29` and `2B` were previously collapsed into one branch, which threw
away the only evidence there is about which of the two happened. The middle row
also carries the last status word the terminal was given, because a deliberate
deselect is a decision about *something* and that is the something.

**Take the real card off the reading reader first.** An ACR122U finds whatever
is on its antenna, and on a relay rig that is a real card — which is what the
first run of this measured and reported as the chip's own ATS, identically to
the card's, without noticing. It now skips anything whose UID is not the
emulated card's: the PN532 takes three NFCID1 bytes and prepends `08`, so an
emulated card is always that exact four-byte UID and nothing else can be
mistaken for it.

The same run also reported a perfectly good ATS as unparseable.
`InListPassiveTarget` hands the ATS over without its `TL` byte while
`parse_ats` wants the wire shape; `with_length_byte` now reconciles the two
using the same test `historical_bytes` already used, so the two cannot disagree
about which form they are looking at.

#### The reader that keeps hunting while you are using it

With FWI 9 measured and the budget four times larger than believed, the next
run failed anyway — and not on timing:

```
INFO  Contactless card selected on …01 00: UID 0586CC7A956300 …
INFO  Entering target mode — present the reader to a terminal
      (2.1 seconds pass)
ERROR Relayed card failed on 00A404000E325041: InDataExchange failed:
      the command makes no sense in the current context
INFO  00A404000E325041592E5359532E444446303100 -> 6F00
INFO  Terminal ended the transaction
```

The `6F00` the terminal received was **ATRIUM's**, not the card's. `_relay`
answers `6F00` when it cannot reach the card at all, deliberately — a card
error is a legible outcome where a dropped RF link is a mystery — but it does
mean a log read quickly blames the card for a failure on our side of the
antenna. The card was never asked.

PN532 status `27` is "command not acceptable in the current context", which on
`InDataExchange` means the chip has no activated target. It had one 2.1 seconds
earlier. What happened in between is that **the ACR122U's firmware runs its own
polling loop, independently of the PN532 commands sent over the escape
channel.** Every sweep redoes anticollision, and that drops the target this
process activated.

It is invisible in ordinary use because ordinary use talks to the card
immediately. A relay does not: the card sits activated for as long as it takes
an operator to present a terminal, which is seconds, and the polling interval
is shorter. So the failure needs an idle gap to appear — which is why
`--prefetch` ran clean. Its warm-up happens inside `connect()`, microseconds
after activation, before the first sweep.

`ContactlessTransport` now suspends the reader's polling for as long as it
holds a card, with the same `PICC Operating Parameter` escape the probe already
used, and restores it on disconnect:

```
FF 00 51 7F 00     polling off
FF 00 51 FF 00     polling on
```

A reader that will not take the setting still works, and a target lost anyway
is recovered rather than turned into a card error — `InDataExchange` failing
with `27` triggers one re-activation and one retry. Recovery **refuses a
different card**: anticollision picks whatever is in the field, and on a relay
rig the field is where cards get put, so continuing against another one would
relay a card the operator did not choose. It also says out loud that the card
was re-activated, because activation resets it to the master file and a `6985`
two commands later is otherwise unattributable.

#### The terminal was coming back, and we were not there

With the card reachable and the budget right, the relay finally ran clean:

```
INFO  00A404000E325041592E5359532E444446303100 ->
      6F35840E325041592E5359532E4444463031A523BF0C20611E
      4F07A0000000041010 5010 4465626974204D6173746572636172 64 870101 9000
INFO  The terminal deselected us deliberately
WARNING  … waited 75 ms at worst against a frame waiting time of 155 ms.
         That is inside the budget, so this is not a timeout: the terminal
         got 9000 to the last command and chose to stop.
```

A well-formed PPSE — `A0000000041010`, "Debit Mastercard", priority 1 — 51 ms
from the card, `9000` to the terminal. And the terminal deselected.

Three runs now, at **32 ms, 75 ms and 144 ms**, all ending the same way after
exactly one exchange. Timing is not the variable; it was never the variable.
What was constant is the shape: *PPSE answered → S(DESELECT) → ATRIUM exits.*

That last step was ours. A terminal ending a session is not a reason to stop
presenting a card. Several EMV kernels look at a card once — read the PPSE, see
what applications it offers, build a candidate list — deselect, and come back to
transact. A phone does the same on every tag it discovers. `run()` exited on the
first `S(DESELECT)`, so **the second pass was never seen**, and every run in
this document reported "one exchange and it gave up" regardless of what the
terminal was actually doing.

The emulator now re-arms after each session and keeps presenting the card until
Ctrl-C:

```
INFO  Session 1 ended after 1 exchange(s)
INFO  Staying armed — a terminal that read this card once may come back
INFO  Session 2 — arming again; the terminal may be back
```

A session that ends with **no** exchanges still stops the run: activated and
asked nothing is a stray poll, and re-arming for it would leave the reader
beeping at an empty room.

Two things this needed on the way:

* the per-session counters are per session. `_why_it_ended` reading a run-wide
  `exchanges` would fall silent after the fourth exchange across all sessions,
  which is exactly when its verdict starts being useful;
* `_borrow_chip` records the chip's original parameter byte only on the first
  borrow. Saving on every borrow would record the *borrowed* byte as the
  baseline, and "restoring" it would leave the reader in target-mode
  parameters — a reader that no longer activates cards until it is unplugged.

It does come back. Two runs, and the same thing both times:

```
17:39:42,316  Session 1 ended after 1 exchange(s)
17:39:42,316  Staying armed — a terminal that read this card once may come back
17:39:44,424  Selected by a terminal — 106 kbps, Mifare framing, ISO-DEP on
```

**2.1 seconds, both runs, to the tenth.** The terminal is not walking away
after the PPSE; it is on a polling cycle, selecting this card over and over.
What happens after that second activation is still unknown, because both runs
were stopped within a second or two of it — and until now nothing was printed
between "Selected by a terminal" and the first APDU, so a session that
activates and says nothing looked exactly like a hang.

#### Making the quiet observable

`TgGetData`'s deadline is twenty seconds. That is right for a conversation in
progress and wrong for the first command of a session: a terminal that selects
a card and says nothing has decided something about the *activation*, and
waiting out twenty silent seconds for it — then raising — hides both the
decision and every session that would have followed.

So the first command of each session gets four seconds, and running out is an
ordinary outcome rather than an error:

```
INFO  The terminal selected us and then asked nothing for 4 s —
      ending this session and arming again
```

Counted as `silent_activations`, separately from a deselect, because the two
say different things: nothing we *answered* can explain a silent activation, so
the objection is to the activation itself — or the terminal was only looking.
A silent activation re-arms; a deselect with no exchange at all does not, since
that is a stray poll and re-arming for it leaves the reader beeping at an empty
room. `NoAnswer` is now its own exception for exactly this: for most commands a
timeout is a fault, and for the two that wait on somebody else it is the
answer.

#### What we present, next to what we relay

Everything the terminal could be objecting to other than the PPSE bytes is in
the activation, so the emulator now prints both identities on the first arming
rather than leaving them to be guessed at:

| | presented | relayed card |
|---|---|---|
| UID | `08010203` — 4 bytes, random ID | `0586CC7A956300` — 7 bytes |
| ATQA | `0004` | `0044` |
| frame size | FSCI 5 → **64 bytes** | FSCI 8 → 256 bytes |
| FWI | 9 → 155 ms | 7 → 38.7 ms |
| bit rates | TA1 `33` → offers 212 and 424 kbit/s | TA1 `00` → 106 only |
| historical bytes | `534C4A0130502310` — worn from the card | `534C4A0130502310` |

Only the last row is ours. The PN532 builds the rest in firmware: it takes
three NFCID1 bytes and prepends `08`, so the emulated UID is always four bytes
beginning with the random-ID prefix, and `CHIP_ATS` records the interface bytes
`measure-ats` read back. If a terminal takes the real card and refuses this
one, those rows are where to look — and none of them can be closed on this
path.

**But weigh them against what actually happened.** The terminal accepted the
activation well enough to send an APDU, so it did not object to the UID or the
ATS; it deselected only after reading a valid PPSE. And it did so at 32 ms with
`--prefetch` just as it did at 144 ms without, so it is not the speed either.
That leaves the PPSE's *content* — a standard Mastercard directory — or the
terminal's own state.

Which makes the next test the cheapest one available and not a code change at
all: **present the real card to the same terminal.** If it transacts and the
emulated one does not, the difference is in the table above. If the real card
gets the same two-second poll-and-drop, the terminal is not in a transaction —
no amount entered — or its candidate list does not contain `A0000000041010`,
and nothing about this emulator was ever the problem.

### The target-mode loop, command by command

Two readers, two roles, one loop. Reader A presents the card; reader B holds
the real one. Every line below is a CCID escape carrying a PN532 command:
`FF 00 00 00 <Lc> D4 <cmd> …` out, `D5 <cmd+1> …` back.

```
                 reader A (target)                    reader B (initiator)
  ─────────────────────────────────────────────────────────────────────────
  once, at start   SetParameters  D4 12 <p>            InListPassiveTarget
                     PICC on, AUTO_ATR_RES off           D4 4A 01 00
                                                       → D5 4B 01 01 0044 20 …
                                                         PICC polling off:
                                                         FF 00 51 7F 00

  1  arm           D4 8C <mode> <mifare 6> <felica 18> <nfcid3 10> 00 <Tk>
                   → D5 8D <mode> [InitiatorCommand…]
                        mode 08 = 106 kbps, Mifare framing, ISO-DEP running
                        the tail is the FIRST FRAME the chip received — the
                        terminal's opening SELECT lands here or in step 2,
                        and which one is a race

  2  read          D4 86                      TgGetData
                   → D5 87 00 00A404000E325041592E5359532E444446303100
                        byte 0 is status: 00 good, 29 deselected, 2B field off

  3  to the card                              D4 40 01 <the same APDU>
                                              → D5 41 00 6F35…9000

  4  answer        D4 8E 6F35…9000            TgSetData
                   → D5 8F 00

  5  read again    D4 86                      → back to step 2
                   → D5 87 29                   (or: released, session over)
```

Steps 2-5 are the loop. A response longer than one frame is chained by the
chip's own ISO-DEP, which is the trade the firmware path makes: `TgSetData`
takes the whole APDU and the firmware decides how many blocks it becomes.

**Step 1's tail is not decoration, and dropping it costs a whole session.**
The PN532 manual calls it `InitiatorCommand` — "the first valid frame received
by the PN532 once configured as target" — and libnfc's emulation examples
treat what `nfc_target_init` returns as the first APDU for exactly that reason.
Where the terminal's opening SELECT lands depends on whether it reached the
chip before or after the host collected the activation. If it rode along and
the host ignores it, the terminal is left waiting for an answer to a command
nobody saw, while `TgGetData` waits for a second command the terminal will
never send.

That is what the alternating sessions on this rig were:

```
21:34:33,912  Selected by a terminal … (mode byte 08)
21:34:39,483  The terminal selected us and then asked nothing for 4 s
21:34:41,250  Selected by a terminal … (mode byte 08)
21:34:41,341  00A404000E32…00 -> 6F35…9000
21:34:44,062  Selected by a terminal … (mode byte 08)
21:34:49,606  The terminal selected us and then asked nothing for 4 s
21:34:51,446  Selected by a terminal … (mode byte 08)
21:34:51,538  00A404000E32…00 -> 6F35…9000
```

Silent, relayed, silent, relayed — the race landing one way, then the other.
`CardEmulator` now relays what comes back with the activation, unless it is a
RATS (the chip answers that itself, and putting `E0 80` to a card would be
nonsense) or too short to be an APDU header.

The raw driver already did this: `IsoDepEmulator.run` has always fed the
activation to `_handle_rats`, because with the chip's PICC handling *off* the
frame that arrives there is the RATS and answering it is the whole job. The
two drivers read the same field and only one of them used it.

#### What we were adding that the protocol never asked for

Reading a relay's own log is reading an interpretation. The question "are we
dropping the communication, or not asking the reader for it?" is not answerable
from any layer that has already decided what the bytes mean — and on this rig
the interpretations have been wrong repeatedly: a `6F00` we fabricated
ourselves read as the card refusing, an exchange inside its budget read as a
timeout.

So `--trace-chip` writes down both directions at the one place every byte
passes through, with the wall clock:

```
→ FF000000 02 D486
← (no data) 9000   5512.3 ms   ← the reader answered with nothing
```

That line is the whole of a silent session, and no layer above it can produce
the same certainty.

Auditing what actually went out per arming turned up three things that were
ours rather than the protocol's:

| per re-arm | what it cost |
|---|---|
| `GetFirmwareVersion`, to time the link | an extra chip command immediately before `TgInitAsTarget`, every session |
| the LED-and-buzzer cue | **~800 ms in which target mode is not armed** — the ACR122U holds the command open while it blinks |
| `SetParameters` | nothing: `update_parameters` only writes when the byte changes |

The middle one is not a cosmetic cost. The terminal on this bench polls about
every 2.2 s, and each re-arm was punching an 800 ms hole in the card's
availability to cue an operator who was already standing at the reader holding
it. The cue earns its place before the *first* terminal, where there is no
other way to know when to present one; after that it is in the way. Both are
now once per run, and the link measurement is honest as well as cheaper — timed
on a re-arm it was measuring the reader's recovery from the previous session,
which is why it read 110 ms on the same link that reads 6.

The four-second first-command wait was also making a promise it could not keep.
The escape is a blocking PC/SC transmit: once `TgGetData` is with the reader,
the reader holds it until its own bridge timeout — about five seconds — and
nothing on this side gets a say until it returns. A deadline shorter than that
expires while the command is still in flight, which is why "asked nothing for
4 s" was printed **5.6 seconds** after activation, and why the next command to
the reader then cost 110 ms: it was queued behind the tail of a command we had
already given up on. It now sits just past the bridge's own timeout, one
`TgGetData` is allowed to run its course, and the log reports the time that
actually elapsed.

One more of the same family, found while looking: `TgSetData` was checked as
`if data and status != 0`. A reply carrying no status byte fell through as
success — an outcome nobody saw, recorded as delivered. The relay would then go
on to ask for the next command while the terminal was still waiting for the
last response. Both send paths now require the status byte.

### Where the relay actually stopped: 256 bytes

With the wire trace on, the flow ran further than it ever had:

```
D486        → 00A404000E325041592E5359532E444446303100   SELECT PPSE
D440 01     → 6F35 …  A0000000041010 "Debit Mastercard"  9000
D486        → 00A4040007A000000004101000                 SELECT AID
D440 01     → 6F54 …  9F4D 020B0A  9F6E 0704840000323000 9000
D486        → 80A8000002830000                           GET PROCESSING OPTIONS
D440 01     → 770E 8202 1980 9408 10010101 20010300      9000
D486        → 00B2011400                                  READ RECORD 1,SFI 2
D440 01     → 7081A3 … 5A08 2234539100654194 …           9000   (168 bytes)
D486        → 00B2012400                                  READ RECORD 2,SFI 2
D440 01     → 7081FB 9F46 81F7 …                          9000   (256 bytes)
ERROR  Relayed card failed on 00B2012400:
       259 bytes needs an extended frame, which is not implemented
D48E 6F00   ← what the terminal got instead
```

PPSE, AID, GPO and the first record all relayed cleanly. The second record —
`9F46`, the ICC public key certificate — is **256 bytes**, and it died twice
over in ways that had nothing to do with the card, the terminal or the timing.

**Coming in.** The chip hands an `InDataExchange` result back as `D5 41
<status>` plus the card's answer: 259 bytes. `build_frame` refused anything
past 255 with a comment saying extended frames "exist" and nothing here needed
one. Something did. The reader had the bytes, put them on the wire, and this
process threw them away on the doorstep. Frames now carry `FF FF` where the
single length byte goes and a two-byte length after it — not confusable with a
NACK (`FF 00`) or with a 255-byte normal frame, whose LCS is `01`.

**Going out.** One `TgSetData` carries **253** bytes here: `D4 8E` precedes the
response and the ACR122U wraps the lot in a pseudo-APDU whose `Lc` is a single
byte. The record is 256. Three bytes over, and the ceiling is the bridge's, not
the chip's.

`TgSetMetaData` looked like the chip's own answer to that, and the trace said
otherwise:

```
→ FF000000FF D494 7081FB9F46…      255-byte pseudo-APDU, Lc at its maximum
← (no data) 9000   12.3 ms          the reader answered nothing at all
```

Twelve milliseconds, not five seconds — an immediate refusal rather than a wait.
So `D4 94` is out, and the question narrows usefully, because **the chip is not
the obstacle**. Record 1 of the same transaction is 173 bytes and went out in
one `TgSetData`, over an ATS advertising 64-byte frames, and the terminal took
it and asked for record 2. The firmware chains fine once it has the bytes. The
only thing between here and a whole transaction is getting 258 bytes of
`D4 8E` + response into the reader.

…except that the twelve milliseconds were never about `D4 94` at all.

#### The size that damages the reader

Both `TgSetMetaData` attempts were sent at `Lc FF`. So was the first extended
experiment. And `Lc FF` is independently poisonous to this reader:

```
→ FF000000FF D494 …
← (no data) 9000   12.3 ms
```

and, on the next run:

```
→ FF000000FF D494 …
✗ Failed to control  Transaction failed. (tried 0x42000001)   after 30379.1 ms
```

Thirty seconds, then the PC/SC control transfer itself failed. The reader is
not declining an oversized command — it is being **damaged** by one, and the
damage outlives the process:

```
→ FF0000003B D48E 6F35…9000          the PPSE response. 57 bytes.
← (no data) 9000   9.5 ms
```

Three consecutive runs died there, on a `TgSetData` a quarter the size of the
one that had worked a minute earlier, in a fresh process, against a reader that
had never been unplugged. "The chip refuses `TgSetData`" was one wedged reader
telling the same lie three times.

What the trace actually brackets, and it is only a bracket:

| | |
|---|---|
| `Lc AA` — 175-byte APDU | answered, repeatedly, over days |
| `Lc FF` — 260-byte APDU | nothing back, then a wedged reader |

So `MAX_PSEUDO_APDU_PAYLOAD` is **192**, chosen to sit well inside the half that
works rather than tight against a boundary nobody has measured. The extended
form is gone: at 265 bytes it is further past that boundary, not around it. A
response bigger than one Direct Transmit is split, always — `TgSetMetaData` for
all but the last piece, `TgSetData` for the last — and each piece is now
comfortably inside what the reader has been answering all along.

#### The fair test, and its answer

```
→ FF000000AA D48E 7081A3…              173 bytes, record 1
← D58F00 9000   47.6 ms                 delivered

→ FF000000C0 D494 7081FB9F46…          190 bytes, record 2, first piece
← (no data) 9000   11.8 ms
```

Two hundred milliseconds apart, on a reader plugged in minutes earlier, at a
size the same reader had just carried. Both confounds gone. And the reader was
*fine* afterwards — the cleanup commands answered in 5.8, 6.1 and 8.4 ms — so
this was not a wedge either.

**This chip does not implement `TgSetMetaData`.** Measured, not suspected.

#### What that leaves

| route | status |
|---|---|
| one `TgSetData` carrying 258 bytes | needs a 263-byte Direct Transmit; the reader broke at 260 |
| `TgSetMetaData` splitting the response | the chip does not answer it |
| `--own-isodep`, chaining at the block layer ourselves | works at the byte level; blocked by the 8.5 ms ATS deadline |

#### One layer up

Every route *below* the APDU layer is now closed, and the last attempt closed
it the hard way: the same 192-byte `D4 94` that had returned cleanly in 11.8 ms
on one run **froze the reader** on the next. Unsupported and dangerous, so it
no longer reaches the wire at all, whatever a caller asks for.

But ISO 7816-4 has had an answer above that layer the whole time. `61 XX` —
*there are XX more bytes, ask for them* — and the terminal collects with
`GET RESPONSE`, at a size the card chooses. So the certificate record leaves as:

```
00B2012400  →  61BC                     "188 more, come and get them"
00C00000BC  →  <188 bytes> 61 42        "…and 66 more"
00C0000042  →  <66 bytes>  9000         the card's own status word
```

Three exchanges, of 2, 190 and 68 bytes. Nothing near the 260 that damages this
reader, and each with its own frame waiting time, so the card's 147 ms fetch is
paid once and the rest is small change. `--split-responses` turns it on.

**It is off by default, and that is not timidity.** The card answered in one
APDU and the terminal is told it answered in three, so a trace taken with this
on is a trace of a conversation ATRIUM shaped — and ATRIUM's whole worth is
that a trace says what the card did. The count is in the status readout for
the same reason.

`GET RESPONSE` is never relayed to the card while a response is held, and never
intercepted while one is not — some cards implement it themselves, and hiding
that would be its own kind of lie. A terminal that asks something else instead
of collecting has moved on, so the held bytes are dropped rather than served
later against a different question.

#### The terminal's answer: no

```
→ FF00000004 D48E 61BC              we offer 188 more
← D58F00 9000              9.5 ms   delivered
   00B2012400 -> 61BC
→ FF00000002 D486                   waiting for GET RESPONSE
← D58729 9000              7.7 ms   0x29 — deselected
```

**Eight milliseconds.** No `GET RESPONSE`; the terminal read `61 BC`, ended the
transaction, and re-polled. Twice, identically, on two sessions of the same run.

So this kernel does not implement `61 XX` over the air, which is the answer the
spec would lead you to expect: `GET RESPONSE` is a T=0 mechanism, and over
T=CL the block layer is supposed to make it unnecessary. It stays behind the
flag for anyone whose terminal disagrees, and the negative is worth having
written down — it is the difference between "untried" and "tried, and no".

Which closes the last idea above the APDU layer as well. The response must
reach the terminal as **one APDU**, so it must reach the chip as one
`TgSetData`, so 258 bytes must fit one Direct Transmit.

#### The only number left

The reader's true transmit ceiling is still only bracketed,
and it has never been measured — only bracketed between a 175-byte APDU that
works and a 260-byte one that damages the reader:

```bash
python3 atrium.py nfc transmit-limit
```

It climbs from a size known to work, one rung at a time, with a padded
`GetFirmwareVersion` — no RF, no card, nothing to leave in a bad state — and
stops at the first silence. If it reaches 258, raise
`MAX_PSEUDO_APDU_PAYLOAD` and the firmware path completes a transaction. If it
does not, the firmware ISO-DEP path cannot carry a contactless EMV transaction
on an ACR122U, and that is a hardware conclusion rather than a bug still worth
chasing.

Meanwhile a response that cannot be delivered no longer takes the run down with
it. The terminal is answered `6F00` — a legible card error — the session stays
up, and the trace goes on to show what the terminal does next. A traceback at
that point destroys precisely the evidence the run was for.

One thing this trace also exposed was mine. `run()` caught `NoAnswer` around the
whole session when it was written for the arming, so the unanswered
`TgSetMetaData` printed as **"No terminal turned up while the card was
presented"** — the wrong story, in the one place a right one was available.
The handler now wraps `wait_for_terminal` and nothing else.

This is why "the terminal said try again". It was not the ATS, not the UID, not
the frame waiting time, and not the PPSE's contents. Four commands into a
working EMV flow, the card's answer to the certificate record could not fit
through this process's own framing, and the terminal was handed `6F00` for the
one record every real transaction needs.

The silent sessions in the same trace are unrelated and now visible for what
they are:

```
D48C …      → D58D 08 E080          activated, RATS attached
D486        → (no data)  5559.5 ms  the reader held it and handed back nothing
```

`E080` is the RATS, which the chip answers itself on this path, so there is no
opening APDU riding along — the earlier guess that one was being dropped was
wrong, and the trace says so plainly. The terminal genuinely activates, says
nothing for the whole of the reader's five-second hold, and re-polls.

#### Knowing which code is running

Three rounds of this bring-up were spent reading output from a stale checkout —
a downloaded zip, run while the fixes for exactly those symptoms sat in the
branch. A zip carries no git metadata, so nothing in a log answered "is this
the code with the fix in it?"

Both entry points now print a build stamp:

```
  Build:       42edd60 (claude/nfcgate-android-integration-f8crpx)
  Build:       unknown build (not a git checkout — likely a downloaded zip)
```

The second line is the one worth having. Check it before reading anything else
in a trace.

### 4. Confirm ordinary emulation works

```bash
python3 atrium.py nfc emulate --from-file logs/apdu.hexlog
```

The chip's ISO-DEP, a replayed card, no second reader needed. If a terminal
selects this and reads it, the RF side is sound.

### 5. Only then, try owning the layer

```bash
python3 atrium.py nfc emulate --from-file logs/apdu.hexlog --own-isodep
```

**The question this answers is narrow and specific: does
`TgGetInitiatorCommand` return anything?** If the ACR122U's bridge refuses the
raw target commands, it fails here, immediately, and nothing else about the
implementation matters.

> **It does.** A terminal has selected a card emulated this way and read a
> complete PPSE relayed from a real one. The bridge passes the raw target
> commands, the ATS is accepted, and the block layer holds. The probe shows the
> same thing one command at a time: `D5 8D 00 E0 80` — target mode entered with
> PICC off, activated by a RATS for us to answer.

**Present the terminal when the reader beeps.** It arms for about five seconds
at a time and re-arms until something answers, so presenting the terminal
before the cue simply means the first window is missed. This is the single most
common way a working relay looks broken.

Two things showed up on that first run, both now fixed, both worth knowing
about because they are what a second rig will hit:

**A CRC error is not the end of a session.** One mangled frame used to raise
out of `TgGetInitiatorCommand` and tear the relay down — the terminal simply
showed a dead card. ISO/IEC 14443-4 expects the opposite: the card stays silent
and the reader retries. Reading again *is* staying silent, so that is what
happens now, up to eight in a row before it gives up and says the problem is
RF rather than protocol. The count is consecutive, so a merely noisy room does
not accumulate into a false failure.

**Target mode must not leave the chip changed.** `SetParameters` writes one
byte holding several unrelated flags, and there is no way to read it back. The
driver wrote the byte whole to clear `PARAM_14443_4_PICC` — which also cleared
`PARAM_AUTO_RATS`, and that setting is *persistent*. The reader kept working as
an emulator, and then the next session used it as the **card** side, where a
chip that no longer sends RATS activates nothing:

```
Contactless card selected on … 00 00: UID 04270F32C33B80 ATQA 0048 SAK 28
                                                     ↑ no ATS, where there was one
… Relayed card failed on 00A404000E325041: … returned nothing
```

Two runs apart, on a different reader, with nothing in the message pointing
back at target mode. Flags are changed by read-modify-write on a cached value
now, only the two that target mode is about, and put back when the relay ends;
`open_pn532` also writes a known baseline at every connect, so a chip left in a
bad state by anything else heals on the next run. A 14443-4 card that returns
no ATS is refused at selection with that explanation rather than failing later
inside `InDataExchange`.

**The emulated card wears the relayed card's historical bytes.** They are the
most recognisable thing in an ATS, and a terminal that reads them off the real
card and then off ours should get the same answer. FWI is deliberately *not*
copied — the real card's is sized for a card, and the longer budget is the
reason for owning this layer at all:

```
relayed card   78 80 71 02 4B 4F 4E 41 10 80      FWI 7,  "KONA"
emulated       0A 68 C0 02 4B 4F 4E 41 10 80      FWI 12, "KONA"
```

The log line for RATS prints the reader's FSD and CID and the ATS going back,
which is the quickest way to see this is right.

### 6. Then measure the thing all of this was for

```bash
python3 atrium.py nfc emulate --own-isodep --fwi 13 --wtxm 32
```

The run summary reports how many extensions were asked for and how many
responses were chained. With a chosen FWI and S(WTX) in hand, "did the terminal
drop us for timing?" stops being a guess.

---

## Reference

### PCB layouts (ISO/IEC 14443-4 §7.1)

```
I-block   0 0 0 c a d 1 n     c=chaining(0x10)  a=CID(0x08)  d=NAD(0x04)
R-block   1 0 1 k a 0 1 n     k=0 ACK / 1 NAK (0x10)
S-block   1 1 t t a 0 1 0     tt=00 DESELECT, 11 WTX
```

Chaining is bit 5 (`0x10`), which is easy to misremember as bit 4 — the bit
next to it is the CID flag.

| Block | Bytes |
|---|---|
| I-block, block number *n* | `02\|n`, chaining `12\|n` |
| R(ACK) / R(NAK) | `A2\|n` / `B2\|n` |
| S(DESELECT) / S(WTX) | `C2` / `F2 <WTXM>` |
| with a CID | add `0x08` to the PCB, CID byte after it |

### Frame sizes (FSDI / FSCI)

| Index | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
|---|---|---|---|---|---|---|---|---|---|
| Bytes | 16 | 24 | 32 | 40 | 48 | 64 | 96 | 128 | 256 |

Usable INF is FSD − 1 (PCB) − 2 (CRC), less one byte each for CID and NAD when
present. 253 for a 256-byte frame.

### Frame waiting time

| FWI | 4 | 7 | 8 | 11 | 12 | 13 | 14 |
|---|---|---|---|---|---|---|---|
| FWT | 4.8 ms | 38.7 ms | 77.3 ms | 619 ms | 1.24 s | 2.47 s | 4.95 s |

Plus ΔFWT = 49152 / fc ≈ 3.625 ms, which the reader adds before calling a
timeout.

### Sources

| Claim | Where |
|---|---|
| `CfgItem 0x02` takes three bytes, RFU first | libnfc `pn53x_RFConfiguration__Various_timings` |
| timeout table, `0x10` max, `0x00` = none | dotnet/iot `RfTimeout.cs`; libnfc `pn53x_int_to_timeout` |
| `RetryTimeout` scope is InCommunicateThru + FeliCa/Mifare | dotnet/iot `VariousTimingsMode.cs` |
| `TgInitAsTarget` takes only Tk, no interface bytes | libnfc `pn53x_TgInitAsTarget` |
| `PARAM_14443_4_PICC = 0x20`, and its use | libnfc `pn53x.h`, `pn53x_target_init` |
| software ISO-DEP is unimplemented there | libnfc `pn53x_target_receive_bytes` → `NFC_ENOTIMPL` |
| PCB bits, WTX handling, `miu = fsc - 3` | nfcpy `nfc/tag/tt4.py::IsoDepInitiator` |
| pyscard's empty-reply `IndexError` | pyscard `PCSCCardConnection.py` — `sw1 = response[-2]` |
| escape control code differs by stack | libnfc `drivers/acr122_pcsc.c`; CCID `ccid_ifdhandler.h` — `SCARD_CTL_CODE(1)` |
| 606 is `IFDHControl`'s default return | CCID `ifdhandler.c` — `RESPONSECODE return_value = IFD_ERROR_NOT_SUPPORTED` |
| unauthorised escape returns 612 | CCID `ifdhandler.c` — `if (!allowed) return IFD_COMMUNICATION_ERROR` |
| the feature query names the escape code | pcsc-lite `reader.h` — `CM_IOCTL_GET_FEATURE_REQUEST`, `FEATURE_CCID_ESC_COMMAND` |
| the pseudo-APDU carries a bare command, not a frame | libnfc `acr122_pcsc.c` — `ACR122_PCSC_WRAP_LEN` is 6: `FF 00 00 00 Lc D4` |
| the reply is bare plus a status word | libnfc `acr122_pcsc_receive` — keeps `abtRx + 2` for `szRx - 4` bytes |

[UM0701-02](https://www.nxp.com/docs/en/user-guide/141520.pdf) is the primary
reference for the PN532 commands; the implementations above were used to check
it because nxp.com was unreachable from the machine this was written on.
