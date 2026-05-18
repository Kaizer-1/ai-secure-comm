"""Tests for `core.transport_tcp.TCPTransport`.

Strategy:
- Use port 0 so each test gets a fresh OS-assigned port (no collisions
  between parallel test runs or with other dev tools).
- Use `socket.socketpair()` for the partial-read test so we can
  inject bytes byte-by-byte without going through bind/accept.
- Always close listeners and transports in finally / addCleanup so
  ports are released even if assertions fail.
"""

from __future__ import annotations

import socket
import struct
import threading
import time
import unittest

from core.sync_protocol import TransportTimeout
from core.transport_tcp import (
    KIND_CHAT,
    KIND_CONTROL,
    KIND_FILE_CHUNK,
    KIND_FILE_META,
    KIND_FINGERPRINT,
    KIND_SEED,
    KIND_TAU,
    FrameKindMismatch,
    PeerDisconnectedError,
    TCPListener,
    TCPTransport,
    bind_and_accept,
    connect,
)


def _make_pair(recv_timeout: float = 5.0) -> tuple[TCPTransport, TCPTransport, TCPListener]:
    """Build a connected pair on 127.0.0.1:0; return (server_t, client_t, listener)."""
    listener = TCPListener("127.0.0.1", 0)
    server_holder: list = [None]

    def server() -> None:
        server_holder[0] = listener.accept(timeout=5.0, recv_timeout=recv_timeout)

    th = threading.Thread(target=server, name="server", daemon=True)
    th.start()

    client_t = connect("127.0.0.1", listener.port,
                       timeout=5.0, recv_timeout=recv_timeout)
    th.join(timeout=5.0)
    if th.is_alive() or server_holder[0] is None:
        listener.close()
        client_t.close()
        raise RuntimeError("server thread did not produce a transport")
    return server_holder[0], client_t, listener


class TestTCPTransportRoundTrip(unittest.TestCase):
    def setUp(self) -> None:
        self.server_t, self.client_t, self.listener = _make_pair()

    def tearDown(self) -> None:
        self.client_t.close()
        self.server_t.close()
        self.listener.close()

    def test_tau_round_trip_both_directions(self) -> None:
        self.client_t.send_tau(1)
        self.assertEqual(self.server_t.recv_tau(), 1)
        self.server_t.send_tau(-1)
        self.assertEqual(self.client_t.recv_tau(), -1)

    def test_fingerprint_round_trip(self) -> None:
        fp_a = b"a" * 64
        fp_b = b"b" * 64
        self.client_t.send_fingerprint(fp_a)
        self.assertEqual(self.server_t.recv_fingerprint(), fp_a)
        self.server_t.send_fingerprint(fp_b)
        self.assertEqual(self.client_t.recv_fingerprint(), fp_b)

    def test_exchange_seed_xor_agreement(self) -> None:
        results: list = [None, None]

        def runner_client() -> None:
            results[0] = self.client_t.exchange_seed(0xDEAD_BEEF)

        def runner_server() -> None:
            results[1] = self.server_t.exchange_seed(0x0123_4567)

        ta = threading.Thread(target=runner_client, daemon=True)
        tb = threading.Thread(target=runner_server, daemon=True)
        ta.start(); tb.start(); ta.join(2); tb.join(2)
        # Both sides MUST agree.
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0], 0xDEAD_BEEF ^ 0x0123_4567)

    def test_app_layer_kinds_round_trip(self) -> None:
        """CHAT, FILE_META, FILE_CHUNK, CONTROL frames carry arbitrary bytes."""
        cases = [
            (KIND_CHAT, b"hello world"),
            (KIND_FILE_META, b'{"file_id":"x"}'),
            (KIND_FILE_CHUNK, bytes(range(256))),
            (KIND_CONTROL, b""),
        ]
        for kind, payload in cases:
            with self.subTest(kind=kind):
                self.client_t._send_frame(kind, payload)
                got_kind, got_payload = self.server_t.recv_frame()
                self.assertEqual(got_kind, kind)
                self.assertEqual(got_payload, payload)

    def test_typed_recv_rejects_wrong_kind(self) -> None:
        # Send a CHAT frame; ask for a TAU.
        self.client_t._send_frame(KIND_CHAT, b"oops")
        with self.assertRaises(FrameKindMismatch):
            self.server_t.recv_tau()


class TestTCPTransportFraming(unittest.TestCase):
    """Check that the framing layer survives partial TCP reads."""

    def test_handles_split_header_and_payload(self) -> None:
        sock_a, sock_b = socket.socketpair()
        transport = TCPTransport(sock_a, recv_timeout=2.0)
        try:
            # Construct a TAU frame: header(5) + payload(1)
            header = struct.pack(">BI", KIND_TAU, 1)
            payload = struct.pack(">b", -1)
            full = header + payload  # 6 bytes total

            def writer() -> None:
                # Send 1 byte, sleep, then 2 more, sleep, then the rest.
                sock_b.sendall(full[0:1])
                time.sleep(0.05)
                sock_b.sendall(full[1:3])
                time.sleep(0.05)
                sock_b.sendall(full[3:])

            th = threading.Thread(target=writer, daemon=True)
            th.start()
            # The reader must reassemble across three recvs.
            self.assertEqual(transport.recv_tau(), -1)
            th.join(2)
        finally:
            transport.close()
            sock_b.close()

    def test_large_payload_round_trip(self) -> None:
        """A multi-chunk payload arrives intact when send + recv overlap.

        We run the recv on a background thread so the kernel send
        buffer always has somewhere to drain — that's how every
        production caller (PeerLink reader thread) actually uses the
        transport.  A purely sequential send-then-recv would deadlock
        once the payload exceeds the kernel send buffer.
        """
        server_t, client_t, listener = _make_pair(recv_timeout=5.0)
        try:
            big = bytes(range(256)) * 4096  # 1 MiB of structured bytes
            received: list = [None]

            def reader() -> None:
                received[0] = server_t.recv_frame()

            th = threading.Thread(target=reader, daemon=True)
            th.start()
            client_t._send_frame(KIND_CHAT, big)
            th.join(timeout=10.0)

            self.assertIsNotNone(received[0])
            kind, got = received[0]
            self.assertEqual(kind, KIND_CHAT)
            self.assertEqual(got, big)
        finally:
            client_t.close()
            server_t.close()
            listener.close()


class TestTCPTransportTimeoutAndClose(unittest.TestCase):
    def test_recv_timeout_raises_transport_timeout(self) -> None:
        server_t, client_t, listener = _make_pair(recv_timeout=0.1)
        try:
            with self.assertRaises(TransportTimeout):
                server_t.recv_tau()
        finally:
            client_t.close()
            server_t.close()
            listener.close()

    def test_peer_close_raises_peer_disconnected(self) -> None:
        server_t, client_t, listener = _make_pair(recv_timeout=2.0)
        try:
            client_t.close()
            with self.assertRaises(PeerDisconnectedError):
                server_t.recv_tau()
        finally:
            server_t.close()
            listener.close()

    def test_close_is_idempotent(self) -> None:
        server_t, client_t, listener = _make_pair()
        try:
            client_t.close()
            client_t.close()  # second call must not raise
            self.assertTrue(client_t.closed)
        finally:
            server_t.close()
            listener.close()

    def test_send_after_close_raises(self) -> None:
        server_t, client_t, listener = _make_pair()
        try:
            client_t.close()
            with self.assertRaises(PeerDisconnectedError):
                client_t.send_tau(1)
        finally:
            server_t.close()
            listener.close()

    def test_listener_accept_timeout(self) -> None:
        listener = TCPListener("127.0.0.1", 0)
        try:
            with self.assertRaises(TransportTimeout):
                listener.accept(timeout=0.1)
        finally:
            listener.close()


class TestThreadSafeSends(unittest.TestCase):
    def test_concurrent_sends_do_not_interleave(self) -> None:
        """Multiple sender threads must produce framed bytes that are
        recoverable by the reader (no interleaving inside a frame)."""
        server_t, client_t, listener = _make_pair(recv_timeout=5.0)
        try:
            num_threads = 8
            per_thread = 10
            payloads = [
                f"thread-{tid}-msg-{mid}".encode()
                for tid in range(num_threads) for mid in range(per_thread)
            ]

            def sender(start: int, count: int) -> None:
                for i in range(count):
                    client_t._send_frame(
                        KIND_CHAT,
                        payloads[start + i],
                    )

            threads = [
                threading.Thread(
                    target=sender,
                    args=(tid * per_thread, per_thread),
                    daemon=True,
                )
                for tid in range(num_threads)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join(5.0)

            received: list[bytes] = []
            for _ in range(num_threads * per_thread):
                kind, payload = server_t.recv_frame()
                self.assertEqual(kind, KIND_CHAT)
                received.append(payload)

            # Order is unspecified across threads, but the *set* must match.
            self.assertEqual(sorted(received), sorted(payloads))
        finally:
            client_t.close()
            server_t.close()
            listener.close()


class TestBindAndAcceptHelper(unittest.TestCase):
    def test_bind_and_accept_returns_transport(self) -> None:
        # Use TCPListener directly to learn the port, then race two threads.
        listener = TCPListener("127.0.0.1", 0)
        port = listener.port
        listener.close()  # release the port; bind_and_accept will rebind it

        server_holder: list = [None]
        err: list = [None]

        def server() -> None:
            try:
                server_holder[0] = bind_and_accept(
                    "127.0.0.1", port, timeout=3.0, recv_timeout=2.0,
                )
            except Exception as e:  # noqa: BLE001
                err[0] = e

        th = threading.Thread(target=server, daemon=True)
        th.start()
        # Race the dialer; `connect()` retries until the rebind takes hold.
        client_t = connect("127.0.0.1", port, timeout=3.0, recv_timeout=2.0)
        th.join(3.0)
        try:
            self.assertIsNone(err[0], f"server raised: {err[0]!r}")
            self.assertIsNotNone(server_holder[0])
            # Sanity: smoke a frame through.
            client_t.send_tau(1)
            self.assertEqual(server_holder[0].recv_tau(), 1)
        finally:
            client_t.close()
            if server_holder[0] is not None:
                server_holder[0].close()


if __name__ == "__main__":
    unittest.main()
