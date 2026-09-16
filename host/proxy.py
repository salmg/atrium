"""
Proxies — sit between two endpoints and watch, or rewrite, what crosses.

    acquirer / terminal  ──►  [ proxy ]  ──►  gateway / issuer
                         ◄──            ◄──

Two classes, and the difference between them is the whole safety story.

``PassiveProxy`` observes only.  **Bytes are forwarded exactly as received**,
the instant they arrive, before anything tries to understand them; decoding
gets its own copy and sits entirely off the relay path.  A dialect is a guess
about somebody else's system, and here a wrong guess degrades to "I could not
read that" rather than to a corrupted link.  When framing itself turns out to
be wrong the connection drops to opaque relay: bytes keep flowing, decoding
stops, the operator is told.  ``test_proxy.py`` pins this by running a
deliberately wrong dialect and asserting the far side got the original bytes.

``MutatingProxy`` gives that guarantee up on purpose, because rewriting a
message means re-encoding it from the decoded form.  It contains the cost
rather than pretending it away: only messages a rule actually changed are
re-encoded, a message that did not decode cleanly is never mutated, and a
failed re-encode forwards the original.  It also store-and-forwards instead of
streaming, which costs latency passive mode does not pay.

If you do not need to change anything, use the passive one.
"""
from __future__ import annotations

import logging
import socket
import threading

from host.capture import (
    ACQUIRER_TO_ISSUER,
    ISSUER_TO_ACQUIRER,
    CaptureLog,
    Correlator,
    observe,
)
from host.iso8583.codec import unpack_body
from host.iso8583.dialect import Dialect
from host.iso8583.framing import Framing, FramingError
from host.mutation import MutationError, mutate_wire
from host.scoping import Scope, ScopeError
from host.transport.link import FrameReader

log = logging.getLogger(__name__)


class PassiveProxy:
    """
    Relay one link and record what crosses it.

    Threads rather than asyncio, matching the rest of the project: one acceptor,
    then two pump threads per connection (one per direction).
    """

    def __init__(self, listen_host: str, listen_port: int,
                 target_host: str, target_port: int,
                 dialect: Dialect,
                 scope: Scope,
                 capture: CaptureLog | None = None,
                 framing: Framing | None = None,
                 connect_timeout: float = 15.0) -> None:
        # Checked before a socket exists, so an out-of-scope target cannot be
        # reached even momentarily.
        scope.check_target(target_host, target_port)

        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.dialect = dialect
        self.scope = scope
        self.capture = capture or CaptureLog(None)
        self.framing = framing or dialect.framing
        self.connect_timeout = connect_timeout

        self._server: socket.socket | None = None
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._conn_seq = 0
        self._lock = threading.Lock()

    # ── lifecycle ────────────────────────────────────────────────────────────

    @property
    def bound_port(self) -> int:
        """The port actually bound — useful when listen_port was 0."""
        return self._server.getsockname()[1] if self._server else self.listen_port

    def start(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.listen_host, self.listen_port))
        server.listen(8)
        server.settimeout(0.5)
        self._server = server

        thread = threading.Thread(target=self._accept_loop, daemon=True,
                                  name="host-proxy-accept")
        thread.start()
        self._threads.append(thread)
        log.info("Passive proxy listening on %s:%d, forwarding to %s:%d (dialect %s)",
                 self.listen_host, self.bound_port,
                 self.target_host, self.target_port, self.dialect.name)

    def stop(self, timeout: float = 3.0) -> None:
        self._stop.set()
        if self._server:
            try:
                self._server.close()
            except OSError:
                pass
            self._server = None
        for thread in list(self._threads):
            thread.join(timeout=timeout)
        self._threads.clear()

    def __enter__(self) -> "PassiveProxy":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    # ── accept ───────────────────────────────────────────────────────────────

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            server = self._server
            if server is None:
                break
            try:
                client, addr = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            with self._lock:
                self._conn_seq += 1
                conn_id = f"c{self._conn_seq}"
            log.info("[%s] client connected from %s:%d", conn_id, *addr[:2])

            thread = threading.Thread(
                target=self._handle, args=(client, conn_id), daemon=True,
                name=f"host-proxy-{conn_id}")
            thread.start()
            self._threads.append(thread)

    def _handle(self, client: socket.socket, conn_id: str) -> None:
        try:
            upstream = socket.create_connection(
                (self.target_host, self.target_port), timeout=self.connect_timeout)
        except OSError as exc:
            log.error("[%s] cannot reach %s:%d — %s", conn_id,
                      self.target_host, self.target_port, exc)
            client.close()
            return

        upstream.settimeout(0.5)
        client.settimeout(0.5)
        correlator = Correlator()
        state = {"opaque": False}

        pumps = [
            threading.Thread(
                target=self._pump, daemon=True, name=f"{conn_id}-a2i",
                args=(client, upstream, conn_id, ACQUIRER_TO_ISSUER, correlator, state)),
            threading.Thread(
                target=self._pump, daemon=True, name=f"{conn_id}-i2a",
                args=(upstream, client, conn_id, ISSUER_TO_ACQUIRER, correlator, state)),
        ]
        for p in pumps:
            p.start()
        for p in pumps:
            p.join()

        for sock in (client, upstream):
            try:
                sock.close()
            except OSError:
                pass
        if correlator.outstanding:
            log.info("[%s] closed with %d unanswered request(s)",
                     conn_id, correlator.outstanding)
        else:
            log.info("[%s] closed", conn_id)

    # ── relay ────────────────────────────────────────────────────────────────

    def _pump(self, src: socket.socket, dst: socket.socket, conn_id: str,
              leg: str, correlator: Correlator, state: dict) -> None:
        """
        Move bytes one way, decoding as a side effect.

        Every chunk is forwarded the instant it arrives, byte for byte, before
        anything tries to understand it.  The frame reader gets its own copy
        purely to carve out messages for the capture, so decoding sits entirely
        off the relay path: it cannot delay a byte, reorder one, or drop one,
        and a dialect that turns out to be wrong costs a capture rather than a
        transaction.

        The price is paid in the capture rather than on the wire: on a fast
        link the response can be recorded before the request it answers, so
        records may appear out of order and a round-trip time may be missing.
        That is the right way round — timing metadata is worth less than the
        guarantee that the bytes went through untouched.
        """
        reader = FrameReader(self.framing)
        seq = 0

        while not self._stop.is_set():
            try:
                chunk = src.recv(8192)
            except socket.timeout:
                continue
            except OSError:
                break
            if not chunk:
                break

            try:
                dst.sendall(chunk)                # byte-exact, unconditional
            except OSError:
                break

            if state["opaque"]:
                continue

            try:
                messages = reader.feed(chunk)
            except FramingError as exc:
                # The framing is wrong. Stop pretending to understand the link
                # and keep relaying it — a broken capture beats a broken test.
                log.warning("[%s] %s: %s — relaying opaquely from here on",
                            conn_id, leg, exc)
                state["opaque"] = True
                reader.drain()
                continue

            for body, raw in messages:
                seq += 1
                self._record(body, raw, conn_id, leg, seq, correlator)

    def _record(self, body: bytes, raw: bytes, conn_id: str, leg: str,
                seq: int, correlator: Correlator) -> None:
        tpdu, rest = b"", body
        try:
            tpdu, rest = self.framing.split_tpdu(body)
        except FramingError:
            pass

        try:
            record = observe(
                self.dialect, rest, raw, conn=conn_id, leg=leg, seq=seq,
                tpdu=tpdu, correlator=correlator, scope=self.scope,
            )
        except ScopeError as exc:
            log.error("[%s] %s", conn_id, exc)
            self._stop.set()
            return

        self.capture.write(record)
        if record.discrepancies:
            for line in record.discrepancies:
                log.warning("[%s] seq=%d %s", conn_id, seq, line)
        for line in record.warnings:
            log.warning("[%s] seq=%d %s", conn_id, seq, line)


class MutatingProxy(PassiveProxy):
    """
    A proxy that rewrites messages on the way through, driven by a playbook.

    This is the deliberate end of phase 2's byte-exactness guarantee, and the
    trade is worth stating plainly.  A mutated message must be re-encoded from
    its decoded form, so the codec moves onto the relay path for the messages a
    rule touches.  Three things keep that contained:

    * only messages a rule actually changed are re-encoded — everything else is
      forwarded verbatim, exactly as in passive mode;
    * a message that did not decode cleanly is never mutated, because
      re-encoding would drop whatever the dialect failed to understand;
    * a re-encode that fails forwards the original and says so.

    It also store-and-forwards rather than streaming: a message cannot be
    relayed until it is whole and the playbook has had its say.  That costs a
    little latency, which passive mode does not.
    """

    def __init__(self, *args, playbook=None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        if playbook is None or not playbook.active:
            raise MutationError(
                "A mutating proxy needs a playbook with at least one enabled "
                "rule. Use PassiveProxy to observe without changing anything."
            )
        self.playbook = playbook

    def _pump(self, src: socket.socket, dst: socket.socket, conn_id: str,
              leg: str, correlator: Correlator, state: dict) -> None:
        reader = FrameReader(self.framing)
        seq = 0

        while not self._stop.is_set():
            try:
                chunk = src.recv(8192)
            except socket.timeout:
                continue
            except OSError:
                break
            if not chunk:
                break

            if state["opaque"]:
                try:
                    dst.sendall(chunk)
                except OSError:
                    break
                continue

            try:
                messages = reader.feed(chunk)
            except FramingError as exc:
                # Framing is wrong, so nothing here can be understood well
                # enough to rewrite. Flush what was buffered — it has not been
                # forwarded yet in this mode — and relay blind from here.
                log.warning("[%s] %s: %s — relaying opaquely, mutations suspended",
                            conn_id, leg, exc)
                state["opaque"] = True
                try:
                    dst.sendall(reader.drain())
                except OSError:
                    break
                continue

            for body, raw in messages:
                seq += 1
                try:
                    outbound = self._decide(body, raw, conn_id, leg, seq, correlator)
                except ScopeError as exc:
                    log.error("[%s] %s", conn_id, exc)
                    self._stop.set()
                    return
                try:
                    dst.sendall(outbound)
                except OSError:
                    return

    def _decide(self, body: bytes, raw: bytes, conn_id: str, leg: str,
                seq: int, correlator: Correlator) -> bytes:
        """Record the message as it arrived, then decide what to send on."""
        tpdu, rest = b"", body
        try:
            tpdu, rest = self.framing.split_tpdu(body)
        except FramingError:
            pass

        record = observe(
            self.dialect, rest, raw, conn=conn_id, leg=leg, seq=seq,
            tpdu=tpdu, correlator=correlator, scope=self.scope,
        )

        outbound = raw
        try:
            msg = unpack_body(self.dialect, rest)
            msg.tpdu = tpdu
            mutated_raw, mutations, note = mutate_wire(
                self.playbook, self.dialect, msg, leg, self.framing)
            record.mutations = [m.to_dict() for m in mutations]
            record.note = note
            if mutated_raw is not None:
                outbound = mutated_raw
                record.sent = mutated_raw.hex().upper()
        except Exception as exc:                       # noqa: BLE001
            # Never let a mutation bug break the link.
            log.exception("[%s] seq=%d mutation failed, forwarding original", conn_id, seq)
            record.note = f"mutation raised {exc!r}; original forwarded"

        self.capture.write(record)

        for line in record.mutations:
            log.warning("[%s] seq=%d mutated %s %s: %s -> %s", conn_id, seq,
                        line["target"], line["mode"],
                        line["before"] or "(absent)", line["after"] or "(deleted)")
        if record.note:
            log.info("[%s] seq=%d %s", conn_id, seq, record.note)
        for line in record.discrepancies:
            log.warning("[%s] seq=%d %s", conn_id, seq, line)
        for line in record.warnings:
            log.warning("[%s] seq=%d %s", conn_id, seq, line)

        return outbound
