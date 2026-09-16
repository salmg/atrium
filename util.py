import binascii
import string
import struct


def from_hex(line):
    return binascii.unhexlify(
        line.replace(' ', '').replace(':', '').replace('\n', '').replace('0x', '')
    )


def to_hex(msg):
    if isinstance(msg, str):
        msg = msg.encode('latin-1')
    return ' '.join('{:02X}'.format(b) for b in msg)


def to_hex_blocks(msg):
    if isinstance(msg, str):
        msg = msg.encode('latin-1')
    return "\n".join(to_hex(msg[i:i + 8]) for i in range(0, len(msg), 8))


def sxor(s1, s2):
    if isinstance(s1, str):
        s1 = s1.encode('latin-1')
    if isinstance(s2, str):
        s2 = s2.encode('latin-1')
    return bytes(a ^ b for a, b in zip(s1, s2))


def str_to_int(s):
    if isinstance(s, str):
        s = s.encode('latin-1')
    return int.from_bytes(s, 'big')


def str8_to_int(s):
    if isinstance(s, str):
        s = s.encode('latin-1')
    return struct.unpack('>Q', s)[0]


def int_to_str8(i):
    return struct.pack('>Q', i)


PRINTABLE_CHARS = " " + string.ascii_letters + string.digits + string.punctuation


def hexdump(data, indent=0, short=False, linelen=16, offset=0):
    """Generate a hex dump string from bytes or str data."""
    if isinstance(data, str):
        data = data.encode('latin-1')

    def hexable(chunk):
        elems = ['{:02X}'.format(b) for b in chunk]
        if not short:
            elems += ["  "] * (linelen - len(elems))
        return " ".join(elems)

    def printable(chunk):
        return "".join(chr(b) if chr(b) in PRINTABLE_CHARS else "." for b in chunk)

    if short:
        return "%s (%s)" % (hexable(data), printable(data))

    format_string = "%04x:  %s  %s"
    result = ""
    head, tail = data[:linelen], data[linelen:]
    pos = 0
    while head:
        if pos > 0:
            result += "\n%s" % (' ' * indent)
        addr = pos + offset
        result += format_string % (addr, hexable(head), printable(head))
        pos += len(head)
        head, tail = tail[:linelen], tail[linelen:]
    return result


def build_stamp():
    """
    A short, human-readable "which code is this" string.

    Three rounds of hardware debugging were spent on output from a stale
    checkout — a downloaded zip of an older commit, run while the fixes for
    exactly those symptoms sat in the branch. A zip carries no git metadata, so
    "am I running the right code?" had no answer visible from a log. This gives
    it one: the commit if this is a git checkout, and an unmistakable marker if
    it is not.

    Best-effort and never fatal. It runs `git` in this file's own directory, so
    it reports the code that is executing rather than wherever the process
    happens to have been launched from.
    """
    import subprocess
    from pathlib import Path

    here = Path(__file__).resolve().parent
    try:
        out = subprocess.run(
            ["git", "-C", str(here), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=2)
    except Exception:                                  # noqa: BLE001
        return "unknown build (git not available)"
    sha = out.stdout.strip()
    if out.returncode != 0 or not sha:
        # No .git here: almost always a downloaded zip or tarball, which is the
        # case worth naming outright because it is the one that misleads.
        return "unknown build (not a git checkout — likely a downloaded zip)"

    dirty = ""
    try:
        status = subprocess.run(
            ["git", "-C", str(here), "status", "--porcelain"],
            capture_output=True, text=True, timeout=2)
        if status.returncode == 0 and status.stdout.strip():
            dirty = " +local-changes"
    except Exception:                                  # noqa: BLE001
        pass

    branch = ""
    try:
        ref = subprocess.run(
            ["git", "-C", str(here), "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, timeout=2)
        if ref.returncode == 0 and ref.stdout.strip() not in ("", "HEAD"):
            branch = f" ({ref.stdout.strip()})"
    except Exception:                                  # noqa: BLE001
        pass

    return f"{sha}{branch}{dirty}"
