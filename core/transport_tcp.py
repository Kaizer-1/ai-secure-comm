"""Plain-TCP `SyncTransport` for the alice↔bob peer channel.

Architecture
------------
This is the concrete network transport that pairs with `LoopbackTransport`
(in-process) introduced in Phase 1.  Both implement the same
`SyncTransport` interface, so `SyncSession` and `TreeParityMachine` are
unaware of which one carries their bytes.

The TCP socket is **shared across the session's full lifetime**:

1. *Sync phase*  — `SyncSession` calls `send_tau` / `recv_tau` /
   `send_fingerprint` / `recv_fingerprint` / `exchange_seed`, which use
   the TAU / FINGERPRINT / SEED frame kinds.
2. *App phase*  — once sync completes, `PeerLink` reuses **the same**
   TCP connection for application traffic (`CHAT`, `FILE_META`,
   `FILE_CHUNK`, `CONTROL`).  We deliberately do NOT open a second
   connection; one socket = one session.

Frame format
------------

    +----------+--------------------+-------------------+
    | kind     | length (4 bytes,   | payload           |
    | (1 byte) |  big-endian)       | (length bytes)    |
    +----------+--------------------+-------------------+

The 5-byte header is fixed; payload size is bounded only by RAM.
Reads are looped until the requested bytes have arrived (TCP can
deliver them in any chunking).

Threading
---------
- `_send_frame` is guarded by `_send_lock`; multiple senders are
  fine.  In Phase 2 the `SyncSession` thread (during sync) and the
  Flask UI thread (chat / file uploads, after sync) both share one
  transport, so this matters.
- There is at most ONE reader at a time.  During sync that reader is
  `SyncSession`; after sync `PeerLink`'s reader thread takes over.
  Concurrent reads are not supported (TCP is stream-oriented and
  framing only works if reads are serialized).
"""

from __future__ import annotations

import logging
import socket
import struct
import threading
from typing import Optional, Tuple

import config
from .sync_protocol import SyncTransport, TransportTimeout


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Frame kinds — keep these stable; they are part of the wire protocol.
# ---------------------------------------------------------------------------
KIND_TAU: int = 0x01
KIND_FINGERPRINT: int = 0x02
KIND_SEED: int = 0x03
KIND_CHAT: int = 0x10
KIND_FILE_CHUNK: int = 0x11
KIND_FILE_META: int = 0x12
KIND_CONTROL: int = 0x20

KIND_NAME = {
    KIND_TAU: "TAU",
    KIND_FINGERPRINT: "FINGERPRINT",
    KIND_SEED: "SEED",
    KIND_CHAT: "CHAT",
    KIND_FILE_CHUNK: "FILE_CHUNK",
    KIND_FILE_META: "FILE_META",
    KIND_CONTROL: "CONTROL",
}

# Header is 1-byte kind + 4-byte big-endian unsigned length.
_HEADER_FMT = ">BI"
_HEADER_LEN = struct.calcsize(_HEADER_FMT)  # 5

# Payload encodings for the sync-phase kinds.
_TAU_FMT = ">b"     # 1 signed byte: -1 or +1
_SEED_FMT = ">Q"    # 8 unsigned big-endian bytes; matches secrets.randbits(64)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class PeerDisconnectedError(OSError):
    """Raised when the TCP peer closes the socket mid-read."""


class FrameKindMismatch(RuntimeError):
    """A `recv_typed` call saw an unexpected frame kind."""


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------


class TCPTransport(SyncTransport):
    """Plain-TCP `SyncTransport` over an established socket.

    Construct via the module-level helpers (`bind_and_accept`,
    `connect`) or `TCPListener.accept()` — the constructor itself just
    wraps an already-connected socket.

    Parameters
    ----------
    sock:
        A connected stream socket (AF_INET / SOCK_STREAM, TCP_NODELAY
        recommended but applied here).
    recv_timeout:
        Per-recv timeout in seconds; if no byte arrives within this
        window, `recv_*` raises `TransportTimeout`.  Pass ``None`` to
        block indefinitely (used by `PeerLink`'s app-phase reader).
    """

    def __init__(
        self,
        sock: socket.socket,
        recv_timeout: Optional[float] = None,
        attack_registry: Optional["object"] = None,
    ) -> None:
        self._sock = sock
        # Disable Nagle so 5-byte headers don't sit in the OS buffer
        # waiting for more data — sync rounds are tiny and latency-sensitive.
        try:
            self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        self._send_lock = threading.Lock()
        self._closed = False
        # Per-transport Phase-3 attack registry (duck-typed: any object
        # exposing `apply_outbound(kind, payload)` and `apply_inbound`).
        # Kept optional and per-transport so multiple PeerLinks in one
        # process (e.g. the training-data generator running alice + bob
        # in two threads) don't cross-contaminate.  When None, the
        # send/recv path stays exactly as it was in Phase 2.
        self._attack_registry = attack_registry
        self.set_recv_timeout(recv_timeout)

    def attach_attack_registry(self, registry: Optional[object]) -> None:
        """Late-bind a Phase-3 `AttackRegistry` (or None to detach)."""
        self._attack_registry = registry

    # -- timeout management ----------------------------------------------
    def set_recv_timeout(self, timeout: Optional[float]) -> None:
        """Set the recv timeout in seconds (or None for blocking)."""
        self._recv_timeout = timeout
        try:
            self._sock.settimeout(timeout)
        except OSError:
            pass

    # -- low-level framing -----------------------------------------------
    def _send_frame(self, kind: int, payload: bytes) -> None:
        if self._closed:
            raise PeerDisconnectedError("send on closed transport")

        # Phase-3 attack hook (zero-cost when no registry is attached).
        # Returning None drops the frame entirely; otherwise the
        # (possibly mutated) (kind, payload) tuple goes on the wire.
        if self._attack_registry is not None:
            result = self._attack_registry.apply_outbound(kind, payload)
            if result is None:
                return
            kind, payload = result

        header = struct.pack(_HEADER_FMT, kind & 0xFF, len(payload))
        with self._send_lock:
            try:
                self._sock.sendall(header + payload)
            except OSError as exc:
                self._closed = True
                raise PeerDisconnectedError(f"send failed: {exc}") from exc

    def _recv_exact(self, n: int) -> bytes:
        """Read exactly `n` bytes, looping over partial reads.

        Raises `TransportTimeout` on socket-level timeout, and
        `PeerDisconnectedError` if the peer closes mid-read.
        """
        buf = bytearray()
        while len(buf) < n:
            try:
                chunk = self._sock.recv(n - len(buf))
            except socket.timeout as exc:
                raise TransportTimeout(
                    f"recv timed out after {self._recv_timeout!r}s "
                    f"(got {len(buf)}/{n} bytes)"
                ) from exc
            except OSError as exc:
                self._closed = True
                raise PeerDisconnectedError(f"recv failed: {exc}") from exc
            if not chunk:
                self._closed = True
                raise PeerDisconnectedError(
                    f"peer closed after {len(buf)}/{n} bytes"
                )
            buf.extend(chunk)
        return bytes(buf)

    def recv_frame(self) -> Tuple[int, bytes]:
        """Read one full frame.  Public so `PeerLink`'s app reader can use it.

        Loops over inbound frames if the Phase-3 attack registry drops
        any (`apply_inbound` returns None) — the caller always gets
        the next frame the registry was happy to deliver.
        """
        while True:
            header = self._recv_exact(_HEADER_LEN)
            kind, length = struct.unpack(_HEADER_FMT, header)
            payload = self._recv_exact(length) if length else b""

            if self._attack_registry is None:
                return kind, payload

            result = self._attack_registry.apply_inbound(kind, payload)
            if result is None:
                # Frame dropped by an attack hook — keep reading.
                continue
            return result

    def _recv_typed(self, expected_kind: int) -> bytes:
        kind, payload = self.recv_frame()
        if kind != expected_kind:
            raise FrameKindMismatch(
                f"expected {KIND_NAME.get(expected_kind, hex(expected_kind))}, "
                f"got {KIND_NAME.get(kind, hex(kind))}"
            )
        return payload

    # -- SyncTransport interface -----------------------------------------
    def send_tau(self, tau: int) -> None:
        self._send_frame(KIND_TAU, struct.pack(_TAU_FMT, int(tau)))

    def recv_tau(self) -> int:
        payload = self._recv_typed(KIND_TAU)
        if len(payload) != struct.calcsize(_TAU_FMT):
            raise RuntimeError(
                f"TAU payload has wrong length: {len(payload)} != "
                f"{struct.calcsize(_TAU_FMT)}"
            )
        return int(struct.unpack(_TAU_FMT, payload)[0])

    def send_fingerprint(self, fp: bytes) -> None:
        self._send_frame(KIND_FINGERPRINT, bytes(fp))

    def recv_fingerprint(self) -> bytes:
        return self._recv_typed(KIND_FINGERPRINT)

    def exchange_seed(self, local_seed: int) -> int:
        """Symmetric XOR seed agreement (matches `LoopbackTransport`)."""
        payload = struct.pack(_SEED_FMT, int(local_seed) & 0xFFFFFFFFFFFFFFFF)
        self._send_frame(KIND_SEED, payload)
        peer_payload = self._recv_typed(KIND_SEED)
        if len(peer_payload) != struct.calcsize(_SEED_FMT):
            raise RuntimeError("SEED payload has wrong length")
        peer_seed = int(struct.unpack(_SEED_FMT, peer_payload)[0])
        return (int(local_seed) ^ peer_seed) & 0xFFFFFFFFFFFFFFFF

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._sock.close()
        except OSError:
            pass

    # -- app-layer convenience -------------------------------------------
    def send_chat(self, bundle: bytes) -> None:
        self._send_frame(KIND_CHAT, bundle)

    def send_file_meta(self, bundle: bytes) -> None:
        self._send_frame(KIND_FILE_META, bundle)

    def send_file_chunk(self, payload: bytes) -> None:
        self._send_frame(KIND_FILE_CHUNK, payload)

    def send_control(self, payload: bytes) -> None:
        self._send_frame(KIND_CONTROL, payload)

    @property
    def closed(self) -> bool:
        return self._closed


# ---------------------------------------------------------------------------
# Listener / connect helpers
# ---------------------------------------------------------------------------


class TCPListener:
    """A bind-once, accept-once listener.

    Phase 2 only ever accepts a single peer (alice and bob are the
    fixed two-party demo), so we don't bother with a long-running
    listen loop.  Construction binds; `accept()` blocks until the peer
    arrives or the timeout fires.

    Parameters
    ----------
    host, port:
        Bind endpoint.  Pass ``port=0`` for an OS-assigned port (used
        by tests).  Read the assigned port from the `port` property.
    backlog:
        socket.listen backlog.  ``1`` is fine — one peer is the design.
    """

    def __init__(self, host: str, port: int, backlog: int = 1) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(backlog)
        self._closed = False

    @property
    def host(self) -> str:
        return self._sock.getsockname()[0]

    @property
    def port(self) -> int:
        return self._sock.getsockname()[1]

    def accept(self, timeout: float = config.PEER_CONNECT_TIMEOUT,
               recv_timeout: Optional[float] = None) -> TCPTransport:
        """Block until the peer connects (or the timeout fires).

        `recv_timeout` is the per-recv timeout installed on the
        returned transport — it controls how long the *sync* phase will
        wait for a peer message.  After sync, callers typically reset
        it via `transport.set_recv_timeout(None)` for the app phase.
        """
        if recv_timeout is None:
            recv_timeout = config.PEER_RECV_TIMEOUT
        self._sock.settimeout(timeout)
        try:
            peer_sock, peer_addr = self._sock.accept()
        except socket.timeout as exc:
            raise TransportTimeout(
                f"no peer connected within {timeout}s"
            ) from exc
        logger.info("accepted peer connection from %s", peer_addr)
        return TCPTransport(peer_sock, recv_timeout=recv_timeout)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._sock.close()
        except OSError:
            pass


def bind_and_accept(
    host: str,
    port: int,
    timeout: float = config.PEER_CONNECT_TIMEOUT,
    recv_timeout: Optional[float] = None,
) -> TCPTransport:
    """Convenience: bind, accept one peer, close the listener."""
    listener = TCPListener(host, port)
    try:
        return listener.accept(timeout=timeout, recv_timeout=recv_timeout)
    finally:
        listener.close()


def connect(
    host: str,
    port: int,
    timeout: float = config.PEER_CONNECT_TIMEOUT,
    recv_timeout: Optional[float] = None,
    retry_interval: float = 0.2,
) -> TCPTransport:
    """Dial the peer; retry briefly if the listener isn't ready yet.

    Connection refused is the common case when the dialer races the
    listener (typical in tests and in launcher startup).  We retry
    with a short backoff until `timeout` is exhausted.
    """
    if recv_timeout is None:
        recv_timeout = config.PEER_RECV_TIMEOUT

    import time
    deadline = time.monotonic() + timeout
    last_exc: Optional[BaseException] = None
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(max(0.1, deadline - time.monotonic()))
            sock.connect((host, port))
            return TCPTransport(sock, recv_timeout=recv_timeout)
        except (ConnectionRefusedError, socket.timeout) as exc:
            last_exc = exc
            sock.close()
            if time.monotonic() >= deadline:
                break
            time.sleep(retry_interval)
        except OSError as exc:
            sock.close()
            raise TransportTimeout(f"connect failed: {exc}") from exc

    raise TransportTimeout(
        f"could not reach {host}:{port} within {timeout}s ({last_exc!r})"
    )
