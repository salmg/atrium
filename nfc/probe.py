"""
What the reader actually does, one command at a time.

Target mode on an ACR122U has failed here three times for three different
reasons, and each diagnosis was a guess that read the same from the outside:
the reader accepted a command and produced no frame.  "No frame" can mean the
chip refused, or that the bridge answered before the chip had anything to say,
or that this reader's firmware will not carry that command at all — and every
layer above this one turns all three into the same message.

So this goes underneath all of them.  It sends the pseudo-APDUs by hand, prints
every byte in both directions with the time it took, and then says which of
those three the trace is consistent with.  Nothing here interprets a reply into
a PN532 frame; ``nfc.pn532`` does that, and it is one of the things under
suspicion.

    python3 atrium.py nfc probe

Run it with nothing in the field and nothing plugged in but the reader.  The
one lasting change it makes is to the chip's parameter byte; it puts that back
at the end, and says so plainly when it could not — a chip left sitting in
target mode will not answer the command that would.
"""
from __future__ import annotations

import threading
import time

from nfc.acr122 import (
    ACR122Error,
    ACR122Link,
    FIRMWARE_QUERY,
    PICC_POLLING_OFF,
    PICC_POLLING_ON,
    PSEUDO_APDU_PREFIX,
    announce_armed,
    set_picc_polling,
)
from nfc.emulator import EmulatedCard, MODE_PASSIVE_ONLY
from nfc.pn532 import (
    CMD_GET_FIRMWARE_VERSION,
    CMD_SAM_CONFIGURATION,
    CMD_SET_PARAMETERS,
    CMD_TG_INIT_AS_TARGET,
    DEFAULT_PARAMETERS,
    HOST_TO_PN532,
    PARAM_AUTO_RATS,
    PN532_TO_HOST,
    RETRY_PAUSE,
    command_name,
    describe_target_mode,
)

GET_RESPONSE = bytes([0xFF, 0xC0, 0x00, 0x00, 0x00])

# How often to ask a reader that has gone quiet whether it has anything yet.
# Slow enough to read as it scrolls, fast enough to catch a reply that arrives
# the moment a terminal is presented.
POLL_EVERY = 0.25


def _hex(data: bytes) -> str:
    return data.hex().upper() or "(nothing)"


class _Trace:
    """Prints what crossed the wire, with the clock running from step one."""

    def __init__(self) -> None:
        self.start = time.monotonic()

    def now(self) -> float:
        return time.monotonic() - self.start

    def step(self, title: str) -> None:
        print(f"\n── {title} " + "─" * max(0, 60 - len(title)))

    def out(self, apdu: bytes, label: str = "") -> None:
        suffix = f"   {label}" if label else ""
        print(f"  [{self.now():7.3f}s] → {_hex(apdu)}{suffix}")

    def back(self, reply: bytes, elapsed: float, label: str = "") -> None:
        suffix = f"   {label}" if label else ""
        print(f"  [{self.now():7.3f}s] ← {_hex(reply)}  "
              f"({elapsed * 1000:.0f} ms){suffix}")

    def note(self, text: str) -> None:
        for line in text.splitlines():
            print(f"             {line}")


def _send(link: ACR122Link, trace: _Trace, apdu: bytes,
          label: str = "") -> bytes:
    """One pseudo-APDU, printed both ways, with no interpretation at all."""
    trace.out(apdu, label)
    began = time.monotonic()
    try:
        reply = link.raw(list(apdu))
    except ACR122Error as exc:
        elapsed = time.monotonic() - began
        print(f"  [{trace.now():7.3f}s] ✗ {exc}  ({elapsed * 1000:.0f} ms)")
        return b""
    trace.back(reply, time.monotonic() - began)
    return reply


def _chip(link: ACR122Link, trace: _Trace, command: int,
          body: bytes = b"") -> bytes:
    """A PN532 command inside the reader's wrapper: FF 00 00 00 Lc D4 …"""
    payload = bytes([HOST_TO_PN532, command]) + body
    apdu = PSEUDO_APDU_PREFIX + bytes([len(payload)]) + payload
    return _send(link, trace, apdu, command_name(command))


def _body(reply: bytes, command: int) -> bytes:
    """
    The chip's answer, without the reader's wrapping.

    A reply is ``D5 <command+1> <data…> 90 00``: the chip's direction byte, the
    echoed command, and the reader's own status word. The trace prints all of
    it on purpose, but anything that *reads* the answer wants only the middle —
    and forgetting that is how ``D5 8D 00 E0 80 90 00`` gets reported as "mode
    D5, 212 kbps, PICC on" when it is a mode byte of 00 and a RATS.
    """
    body = bytes(reply)
    if len(body) >= 2 and (body[-2], body[-1]) == (0x90, 0x00):
        body = body[:-2]
    if len(body) >= 2 and body[0] == PN532_TO_HOST and body[1] == (command + 1) & 0xFF:
        return body[2:]
    return body


def probe(reader_name: str, wait: float = 8.0) -> dict:
    """
    Walk a reader up to target mode by hand, printing everything.

    ``wait`` is how long to keep polling after TgInitAsTarget — long enough to
    present a terminal, if there is one to present. Returns what was observed,
    so a caller can assert on it; the useful output is what it prints.
    """
    trace = _Trace()
    found: dict = {"reader": reader_name}

    from util import build_stamp

    print(f"\nProbing {reader_name}")
    print(f"build {build_stamp()}\n")
    link = ACR122Link(reader_name, direct=True)
    link.connect()

    try:
        trace.step("escape channel")
        code = link._escape_code
        found["escape_code"] = code
        found["escape_authorised"] = link._escape_authorised
        if code is not None:
            trace.note(f"the driver named control code 0x{code:08X}")
        elif link._escape_authorised is False:
            trace.note("the driver answered the feature query and offers no "
                       "escape channel — escape is not authorised")
        else:
            trace.note("the driver would not answer the feature query; "
                       "platform guesses will be tried in turn")

        trace.step("the reader itself (no PN532 involved)")
        reply = _send(link, trace, FIRMWARE_QUERY, "reader firmware")
        found["path"] = link._path
        found["reader_firmware"] = (
            reply.split(b"\x00")[0].decode("ascii", "replace").strip())
        if found["reader_firmware"]:
            trace.note(f"reader says it is {found['reader_firmware']!r}")
        if link._path:
            trace.note(f"reaching it over the {link._path} path")

        trace.step("the chip (through the reader's wrapper)")
        found["firmware"] = _chip(link, trace, CMD_GET_FIRMWARE_VERSION)
        if not found["firmware"]:
            trace.note("nothing came back for a command that cannot block — "
                       "so silence here is the bridge, not the chip waiting")
            found["get_response"] = _poll(link, trace, seconds=1.0)

        trace.step("what one escape costs")
        found["escape_ms"] = _time_escapes(link, trace)

        trace.step("preparing target mode")
        _chip(link, trace, CMD_SAM_CONFIGURATION, bytes([0x01, 0x14, 0x00]))
        # AUTO_ATR_RES off, AUTO_RATS kept: libnfc clears the first for every
        # 14443-A target, and clearing the second would leave this reader
        # unable to activate cards long after the probe has exited.
        _chip(link, trace, CMD_SET_PARAMETERS, bytes([PARAM_AUTO_RATS]))

        trace.step(f"target mode — re-arming for {wait:.0f}s")
        announce_armed(link)
        trace.note("Present a terminal now. The reader is only listening for "
                   "about five seconds\nat a time — that is its own bridge "
                   "timeout — so this arms it again and again\nuntil something "
                   "answers.")
        body = EmulatedCard().init_body(mode=MODE_PASSIVE_ONLY)
        found["init_immediate"] = _arm(link, trace, body)
        found["init_polled"] = b""
        found["init_rearmed"] = b""
        if not found["init_immediate"]:
            # One GET RESPONSE, to record whether this reader defers the answer
            # or discards it. On an ACR122U it discards: thirty of these came
            # back empty while the command was already gone.
            found["init_polled"] = _body(
                _send(link, trace, GET_RESPONSE, "is it deferred?"),
                CMD_TG_INIT_AS_TARGET)
            if not found["init_polled"]:
                trace.note("nothing to collect — so the command was dropped "
                           "rather than deferred, and\nasking again is the "
                           "only way forward")
                found["init_rearmed"] = _rearm(link, trace, body, seconds=wait)
        else:
            # It answered first time, so nothing above exercised re-arming —
            # and re-arming is what the emulator now depends on. One more
            # TgInitAsTarget settles whether a second one works at all after a
            # first has already run, which is otherwise an untested assumption.
            trace.note("that answered first time, so this arms once more — the "
                       "emulator re-arms\nuntil a terminal turns up, and "
                       "whether a second one works is worth knowing.")
            found["second_arm"] = _arm(link, trace, body)

    finally:
        trace.step("putting the chip back")
        found["restored"] = _restore(link, trace)
        link.close()

    _verdict(found, wait)
    return found


def _restore(link: ACR122Link, trace: _Trace) -> bool:
    """
    Put the parameter byte back, and be honest when it could not be.

    A chip still sitting in TgInitAsTarget will not answer this — it is in the
    middle of a command and nothing has ended it. That leaves AUTO_ATR_RES off,
    which is persistent and which the reader carries into whatever it is used
    for next, where the symptom is a card that activates and produces no ATS.
    Worth a sentence rather than a silent shrug.
    """
    try:
        reply = _chip(link, trace, CMD_SET_PARAMETERS, bytes([DEFAULT_PARAMETERS]))
    except Exception:                                  # noqa: BLE001
        reply = b""
    if reply:
        trace.note("parameter byte restored")
        return True
    trace.note("The chip did not acknowledge, which is what a chip still\n"
               "sitting in target mode does. Unplug the reader and plug it\n"
               "back in before using it to read cards — the parameter byte\n"
               "survives a disconnect but not a power cycle.")
    return False


ESCAPE_SAMPLES = 20

# How long to give the arming thread to come back out of TgInitAsTarget. The
# reader holds that command for about five seconds before discarding it, so
# anything shorter would give up while it is still legitimately busy.
ARM_GRACE = 7.0


def _time_escapes(link: ACR122Link, trace: _Trace) -> dict:
    """
    Time the cheapest possible command, with the reader's polling on and off.

    Every timing conclusion in this project rests on what one escape costs, and
    that number has only ever been inferred by subtraction — turnaround minus
    card. This measures it directly, on a command with no RF in it at all, so
    what is left is purely pyscard, pcscd, libccid, USB and the reader's MCU.

    Then it does it again with the reader's own PICC polling switched off. The
    reader polls for cards continuously whenever it is not holding a card
    connection, and a direct connection does not stop it, so every escape may
    be queueing behind a poll cycle on the same antenna. If that is where the
    milliseconds are, this is where it shows.
    """
    def sample(label: str) -> list[float]:
        costs = []
        for _ in range(ESCAPE_SAMPLES):
            began = time.monotonic()
            try:
                link.raw(list(FIRMWARE_QUERY))
            except ACR122Error:
                break
            costs.append((time.monotonic() - began) * 1000)
        if costs:
            ordered = sorted(costs)
            trace.note(f"{label}: min {ordered[0]:.1f} ms, median "
                       f"{ordered[len(ordered) // 2]:.1f} ms, max "
                       f"{ordered[-1]:.1f} ms, over {len(ordered)} samples")
        return costs

    out: dict = {}
    polling_on = sample("polling on (as shipped)")
    out["polling_on"] = polling_on

    if set_picc_polling(link, PICC_POLLING_OFF) is not None:
        polling_off = sample("polling off")
        out["polling_off"] = polling_off
        set_picc_polling(link, PICC_POLLING_ON)
        trace.note("reader polling restored to the default")

        if polling_on and polling_off:
            before = sorted(polling_on)[len(polling_on) // 2]
            after = sorted(polling_off)[len(polling_off) // 2]
            saved = before - after
            out["saved_ms"] = saved
            if saved > 3:
                trace.note(f"turning the reader's polling off saves "
                           f"{saved:.1f} ms per escape — worth doing for real, "
                           f"and it costs three escapes per exchange")
            else:
                trace.note("polling is not where the milliseconds are; the "
                           "cost is the bridge itself")
    else:
        trace.note("this reader would not take a PICC operating parameter, so "
                   "the polling comparison could not be made")
    return out


def _arm(link: ACR122Link, trace: _Trace, body: bytes) -> bytes:
    """One TgInitAsTarget, with the reader's wrapping taken back off."""
    return _body(_chip(link, trace, CMD_TG_INIT_AS_TARGET, body),
                 CMD_TG_INIT_AS_TARGET)


def _poll(link: ACR122Link, trace: _Trace, seconds: float) -> bytes:
    """
    Ask GET RESPONSE until something arrives or the window closes.

    For a command that cannot block, this separates "the chip is slow" from
    "the bridge is not carrying the answer at all".
    """
    deadline = time.monotonic() + seconds
    attempts = 0
    while time.monotonic() < deadline:
        time.sleep(POLL_EVERY)
        attempts += 1
        reply = _send(link, trace, GET_RESPONSE, f"poll {attempts}")
        if reply:
            trace.note("↑ the answer arrived on a later read — the reader "
                       "defers, and polling is the way to collect it")
            return reply
    trace.note(f"{attempts} polls, nothing on any of them")
    return b""


def _rearm(link: ACR122Link, trace: _Trace, body: bytes,
           seconds: float) -> bytes:
    """
    Send TgInitAsTarget again each time the reader drops it.

    This is what the emulator does, shown one send at a time. Each attempt
    blocks at the reader for about five seconds and then comes back empty, so
    the loop paces itself; the pause is only a guard against a link that fails
    instantly instead.
    """
    deadline = time.monotonic() + seconds
    attempts = 1
    while time.monotonic() < deadline:
        attempts += 1
        reply = _arm(link, trace, body)
        if reply:
            trace.note(f"↑ answered on attempt {attempts} — re-arming is what "
                       "this reader needs")
            return reply
        time.sleep(RETRY_PAUSE)
    trace.note(f"{attempts} attempts, nothing on any of them")
    return b""


def _verdict(found: dict, wait: float) -> None:
    """Say which explanation the trace supports. Only the ones it supports."""
    print("\n── what this says " + "─" * 43)

    if not found.get("reader_firmware"):
        print("  The reader would not name itself, so nothing below it was\n"
              "  reachable either. This is the escape channel, not the chip.")
        if found.get("escape_authorised") is False:
            print("  The driver was explicit: escape commands are not "
                  "authorised.")
        print()
        return

    if not found.get("firmware") and not found.get("get_response"):
        print("  The reader answers its own commands and the chip answers\n"
              "  none — including GetFirmwareVersion, which cannot block.\n"
              "  The wrapper is reaching the reader but not the PN532.")
        print()
        return

    if found.get("firmware"):
        print("  The chip answers on the first read, so the escape path and\n"
              "  the pseudo-APDU wrapper are both correct.")

    elif found.get("get_response"):
        print("  The chip answers, but only on a later read — every command\n"
              "  needs polling on this reader, not just the blocking ones.")

    _read_escape_cost(found.get("escape_ms") or {})

    activation = found.get("init_immediate") or found.get("init_rearmed") or b""
    if activation:
        print("  Target mode works on this reader.")
        _read_activation(activation)
        if found.get("init_rearmed"):
            print("  It took re-arming to get there, which is the point: the\n"
                  "  bridge drops the command after about five seconds, so the\n"
                  "  emulator sends it again until a terminal turns up.")
        elif "second_arm" in found:
            if found["second_arm"]:
                print("  A second TgInitAsTarget answered too, so re-arming\n"
                      "  works — which is what the emulator relies on to wait\n"
                      "  longer than the bridge will hold the command open.")
            else:
                print("  A second TgInitAsTarget got nothing. That may only\n"
                      "  mean the terminal was taken away; run it again and\n"
                      "  leave the terminal in place to tell the two apart.")
    elif found.get("init_polled"):
        print("  TgInitAsTarget answered a GET RESPONSE, so this reader defers\n"
              "  rather than discarding. Worth knowing — it is not what an\n"
              "  ACR122U does.")
    else:
        print(f"  TgInitAsTarget said nothing for {wait:.0f}s.")
        print("  If a terminal was presented in that window, this reader's\n"
              "  bridge does not carry target mode — the ACR122U's CCID\n"
              "  firmware is known to be the weak point, and libnfc drives\n"
              "  this chip over raw USB rather than PC/SC for that reason.\n"
              "  If no terminal was presented, that is the expected trace and\n"
              "  it says nothing either way: run it again with one.")
    print()


def _read_escape_cost(timings: dict) -> None:
    """
    Turn the escape measurement into the number that decides everything.

    A relayed APDU costs three escapes — TgGetData and TgSetData on the
    emulating reader, InDataExchange on the card's — and they are causally
    ordered, so none can be overlapped. Three times the median is the floor for
    a relayed exchange before the card's own RF time is counted, and a card-like
    frame waiting time is 38.7 ms.
    """
    on = timings.get("polling_on") or []
    if not on:
        return
    median = sorted(on)[len(on) // 2]
    floor = median * 3
    print(f"  One escape costs about {median:.0f} ms on this bridge, and a "
          f"relayed\n  APDU needs three of them — so roughly {floor:.0f} ms "
          f"before the card\n  has done anything at all.")
    if floor > 38.7:
        print("  A card-like frame waiting time is 38.7 ms, so the bridge alone\n"
              "  already exceeds it. No amount of speeding up the card side\n"
              "  closes that; the transport is the ceiling.")
    else:
        print("  A card-like frame waiting time is 38.7 ms, so the bridge\n"
              "  leaves room — the card side is worth attacking.")
    saved = timings.get("saved_ms")
    if saved is not None and saved > 3:
        print(f"  Turning the reader's own polling off saves {saved:.0f} ms of "
              f"that\n  per escape, which is {saved * 3:.0f} ms per exchange.")


def _read_activation(data: bytes) -> None:
    """
    Say what the mode byte and the activation bytes mean.

    The whole point of getting this far is what these say, and reading them off
    a hex dump by hand is exactly the step where a bring-up goes wrong.
    """
    mode = data[0]
    seen = describe_target_mode(mode)
    print(f"  Mode {mode:02X}: {seen['baud']}, {seen['framing']} framing, "
          f"ISO-DEP {'on' if seen['picc'] else 'off'}"
          + (", DEP." if seen["dep"] else "."))
    if seen["picc"]:
        print("  ISO-DEP is on, so the chip is running the protocol itself —\n"
              "  that is the default path, not the one --own-isodep takes.")
    else:
        print("  ISO-DEP is off, so the block layer is ours to run — which is\n"
              "  what --own-isodep does, and what this probe asked for.")

    rest = data[1:]
    if not rest:
        print("  No activation data: the terminal selected us and said nothing\n"
              "  further before the reply came back.")
    elif rest[0] == 0xE0:
        from nfc.isodep import parse_rats

        rats = parse_rats(rest)
        print(f"  Activated by RATS ({rest.hex().upper()}): the terminal takes "
              f"{rats.fsd}-byte frames\n  (FSDI {rats.fsdi}) and asked for CID "
              f"{rats.cid}. Answering it is ours to do, which is\n"
              f"  what --own-isodep is for; the ATS goes back from there.")
    else:
        print(f"  Activation data {rest.hex().upper()}.")


# ── What FWI does the chip actually advertise? ───────────────────────────────
#
# The single most consequential unknown on the firmware path, and the one thing
# neither reader can tell us alone. The PN532 builds the ATS itself in PICC
# mode and offers no way to read it back, so every timing conclusion about that
# path has rested on assuming it is card-like — FWI 7, 38.7 ms — because the
# real card in front of it is.
#
# With two readers the question answers itself: arm one as a card and read it
# with the other. What comes back is the ATS the chip really sends, FWI and all.

def measure_emulated_ats(target_reader: str, reader_reader: str,
                         wait: float = 20.0) -> dict:
    """
    Arm one reader as a card, read it with another, and report its ATS.

    ``target_reader`` is armed with ``TgInitAsTarget`` in PICC mode, so the chip
    answers RATS itself with the ATS this is about. ``reader_reader`` then does
    an ordinary ``InListPassiveTarget``, which returns it.
    """
    from nfc.acr122 import open_pn532
    from nfc.isodep import fwt_seconds, parse_ats
    from nfc.pn532 import PARAM_14443_4_PICC, PARAM_AUTO_ATR_RES

    from util import build_stamp

    print(f"\nReading {target_reader}\n  with {reader_reader}")
    print(f"build {build_stamp()}\n")

    found: dict = {}
    target_link = ACR122Link(target_reader, direct=True)
    target_link.connect()
    chip = None

    # The arming thread owns target_link for its whole life. ACR122Link has no
    # lock, and a CCID exchange torn between two threads on an ACR122U does not
    # fail cleanly — it returns another command's response. So nothing else may
    # touch this link until the thread has joined, including the cleanup.
    stop = threading.Event()

    def arm() -> None:
        """Sit in target mode so the other reader has something to find."""
        body = EmulatedCard().init_body()          # PICC mode: the chip's ATS
        deadline = time.monotonic() + wait + ARM_GRACE
        while not stop.is_set() and time.monotonic() < deadline:
            reply = _body(_chip_quiet(target_link, CMD_TG_INIT_AS_TARGET, body),
                          CMD_TG_INIT_AS_TARGET)
            if reply:
                found["activation"] = reply
                return
            time.sleep(RETRY_PAUSE)

    armed = None
    try:
        from nfc.pn532 import PN532

        chip = PN532(target_link)
        chip.sam_configuration()
        # The chip must do ISO-DEP here — that is the whole point, its ATS is
        # what we are after — and AUTO_ATR_RES has to be off to enter target
        # mode at all.
        chip.update_parameters(set_bits=PARAM_14443_4_PICC,
                               clear_bits=PARAM_AUTO_ATR_RES)

        armed = threading.Thread(target=arm, daemon=True, name="probe-target")
        armed.start()
        time.sleep(0.5)                            # let it get into target mode

        # The PN532 takes three NFCID1 bytes and prepends 08, so the emulated
        # card is always this exact UID. Anything else in the reading reader's
        # field is a real card — and on a relay rig there is one sitting right
        # there, which is what the first run of this actually measured.
        ours = b"\x08" + bytes(EmulatedCard().nfcid1)
        print(f"  arming as a card (UID {ours.hex().upper()}), then reading it…\n")

        chip_b, link_b = open_pn532(reader_reader, direct=True)
        try:
            deadline = time.monotonic() + wait
            seen = None
            strangers: list[str] = []
            while time.monotonic() < deadline and seen is None:
                for candidate in chip_b.list_passive_targets(limit=2):
                    if bytes(candidate.uid) == ours:
                        seen = candidate
                        break
                    label = str(candidate)
                    if label not in strangers:
                        strangers.append(label)
                if seen is None:
                    time.sleep(POLL_EVERY)

            for stranger in strangers:
                print(f"  ignoring a real card in the field: {stranger}")

            if seen is None:
                print("\n  Never saw the emulated card.")
                if strangers:
                    print("  Something else is on this reader's antenna and an "
                          "ACR122U will\n  find that first. Take the real card "
                          "off it and run this again.")
                else:
                    print("  Hold the two antennas together and run it again.")
                print()
            else:
                found["target"] = str(seen)
                found["ats"] = bytes(seen.ats)
                print(f"  found: {seen}")
                _read_emulated_ats(bytes(seen.ats), fwt_seconds, parse_ats)
        finally:
            link_b.close()
    finally:
        # Get the link back before touching it. The thread is inside a command
        # the reader holds for about five seconds, so this is the wait, not a
        # formality.
        stop.set()
        if armed is not None:
            armed.join(ARM_GRACE)
        if armed is not None and armed.is_alive():
            print("\n  The arming thread has not come back, so its link is "
                  "still in use\n  and the parameter byte cannot be restored "
                  "safely. Unplug the reader\n  before using it to read "
                  "cards.\n")
        else:
            if chip is not None:
                try:
                    chip.set_parameters(DEFAULT_PARAMETERS)
                except Exception:                  # noqa: BLE001
                    print("  could not restore the parameter byte — unplug "
                          "the reader before using it to read cards")
            target_link.close()
    return found


def _chip_quiet(link: ACR122Link, command: int, body: bytes = b"") -> bytes:
    """A chip command with no tracing — the arming thread must not interleave."""
    payload = bytes([HOST_TO_PN532, command]) + body
    apdu = PSEUDO_APDU_PREFIX + bytes([len(payload)]) + payload
    try:
        return link.raw(list(apdu))
    except ACR122Error:
        return b""


def _read_emulated_ats(ats: bytes, fwt_seconds, parse_ats) -> None:
    """Say what the chip's own ATS means for a relay's budget."""
    from nfc.isodep import with_length_byte

    print()
    if not ats:
        print("  The emulated card offered no ATS at all, which means the chip\n"
              "  did not complete RATS — it is not doing ISO-DEP as a PICC.")
        return

    print(f"  The chip's own ATS: {ats.hex().upper()}")
    try:
        # InListPassiveTarget hands the ATS over without its TL byte, and
        # parse_ats wants the wire shape. Reading one as the other is what made
        # the first run of this report a perfectly good ATS as unparseable.
        parsed = parse_ats(with_length_byte(ats))
    except Exception:                              # noqa: BLE001
        print("  …and it does not parse, which is worth knowing on its own.")
        return

    # Split it, because the whole thing reads as a repeat and that stops
    # people trusting the number. The interface bytes are the chip's; the
    # historical bytes are whatever TgInitAsTarget was handed, and the
    # default for those is libnfc's copy of this very chip's ATS.
    tail = bytes(parsed.historical)
    interface = ats[:len(ats) - len(tail)] if tail else ats
    print(f"    interface bytes  {interface.hex().upper()}  — the chip's")
    if tail:
        print(f"    historical bytes {tail.hex().upper()}  — ours, from "
              f"TgInitAsTarget")
        if tail == interface:
            print("      (the same bytes twice is not a fault: the default "
                  "historical\n       bytes are libnfc's, and libnfc copied "
                  "them off this chip.)")

    budget = fwt_seconds(parsed.fwi)
    print(f"  FWI {parsed.fwi} — a frame waiting time of {budget * 1000:.0f} ms.")
    print(f"  FSCI {parsed.fsci} ({parsed.fsc}-byte frames), "
          f"SFGI {parsed.sfgi}.")
    print()
    print("  This is the number the whole firmware path lives inside, and\n"
          "  measuring it is the point of this command — _RelayCore.CHIP_FWT\n"
          "  carries it, and was four times too strict while it was a guess.\n"
          "  Against it:")
    print("    a card fetch on this rig    ~50 ms")
    print("    three escapes               ~8 ms")
    if budget * 1000 > 60:
        print("  So a live relayed exchange may fit after all — the assumption\n"
              "  that this path is card-limited was wrong.")
    else:
        print("  So a live relayed exchange does not fit, and only the\n"
              "  exchanges --prefetch answers from memory will.")


# ── how much the reader will actually carry ───────────────────────────────────

# Sizes to try, as payload bytes after the FF 00 00 00 Lc header. Ends at 255
# because that is where a single Lc byte ends and where this rig's reader was
# seen to break; the ladder is walked from the bottom so the answer is known
# before the damaging size is reached.
TRANSMIT_LADDER = (160, 176, 192, 208, 224, 240, 248, 252, 254, 255)


def measure_transmit_limit(reader_name: str) -> dict:
    """
    Find how large a Direct Transmit this reader answers, and stop there.

    The one number left standing between this project and a completed
    contactless transaction. A relayed EMV READ RECORD carrying an ICC public
    key certificate answers 256 bytes; ``D4 8E`` precedes it, so 258 have to
    reach the chip in one command, because ``TgSetMetaData`` — the chip's own
    way of splitting a response — is measured, not merely suspected, to go
    unanswered on this hardware.

    ACS document ``Lc`` as one byte and say nothing about a ceiling below 255.
    This rig's reader answered nothing to ``Lc FF`` and was then damaged: the
    next run's 57-byte ``TgSetData`` drew the same silence in a fresh process,
    and a second attempt failed its PC/SC control transfer after thirty
    seconds. So the ladder is climbed from a size known to work, one rung at a
    time, and stops at the first silence — which leaves the reader in whatever
    state that size puts it in, and says so.

    The command is ``GetFirmwareVersion`` with padding. It touches no RF state
    and needs no card, and whether the chip likes the trailing bytes does not
    matter: any framed answer means the reader carried them, which is the only
    question being asked.
    """
    from nfc.acr122 import PSEUDO_APDU_PREFIX, ACR122Link
    from nfc.pn532 import HOST_TO_PN532, CMD_GET_FIRMWARE_VERSION

    from util import build_stamp

    print(f"\nMeasuring how much '{reader_name}' carries in one Direct Transmit")
    print(f"build {build_stamp()}\n")
    print("  A contactless EMV certificate record needs 258 payload bytes in")
    print("  one TgSetData. Anything less and the firmware ISO-DEP path cannot")
    print("  finish a transaction on this reader.\n")

    link = ACR122Link(reader_name, direct=True)
    link.connect()
    results: list[tuple[int, bool]] = []
    try:
        for size in TRANSMIT_LADDER:
            payload = (bytes([HOST_TO_PN532, CMD_GET_FIRMWARE_VERSION])
                       + b"\x00" * (size - 2))
            apdu = PSEUDO_APDU_PREFIX + bytes([size]) + payload
            try:
                reply = link.raw(list(apdu))
            except Exception as exc:                   # noqa: BLE001
                print(f"  {size:3d} bytes  → the transfer itself failed: {exc}")
                results.append((size, False))
                break
            answered = bool(reply)
            results.append((size, answered))
            print(f"  {size:3d} bytes  → {reply[:12].hex().upper() or 'nothing'}")
            if not answered:
                break
    finally:
        link.close()

    carried = [size for size, ok in results if ok]
    best = max(carried) if carried else 0
    print()
    if not carried:
        print("  The reader answered nothing even at the smallest size tried.\n"
              "  It is wedged: unplug it, plug it back in, and run this again.\n")
    elif best >= 258:
        print(f"  It carries {best}. That is enough for a certificate record,\n"
              f"  so raise nfc.acr122.MAX_PSEUDO_APDU_PAYLOAD to {best} and the\n"
              f"  firmware path can complete a transaction.\n")
    else:
        print(f"  It carries {best}, and a certificate record needs 258.\n"
              f"  The firmware ISO-DEP path cannot finish a contactless EMV\n"
              f"  transaction on this reader — not for want of a fix here, but\n"
              f"  because the response will not fit through the bridge and the\n"
              f"  chip will not split it.\n")
        if best < max(TRANSMIT_LADDER):
            print(f"  The reader may need unplugging: {results[-1][0]} bytes went\n"
                  f"  unanswered, and on this hardware that has left it unable to\n"
                  f"  answer anything until it was power-cycled.\n")
    return {"carried": best, "results": results}
