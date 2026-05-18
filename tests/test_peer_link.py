"""End-to-end tests for `core.peer_link.PeerLink`.

These spin up two PeerLinks in two threads on 127.0.0.1, run the TPM
sync, then exchange chat messages and a small file, asserting that
every callback fires with the expected data.
"""

from __future__ import annotations

import os
import socket
import shutil
import tempfile
import threading
import time
import unittest

import config
from core.peer_link import PeerLink


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _run_pair(port: int, *, recv_timeout: float = 5.0) -> tuple[PeerLink, PeerLink]:
    """Build two PeerLinks (alice = initiator, bob = responder) and run
    `connect()` for each on its own thread.  Returns once both are
    in app mode (i.e. sync has completed)."""
    alice = PeerLink(
        role=config.ROLE_A,
        bind_host="127.0.0.1",
        peer_host="127.0.0.1",
        peer_port=port,
        initiator_role=config.ROLE_A,
        connect_timeout=5.0,
        recv_timeout=recv_timeout,
    )
    bob = PeerLink(
        role=config.ROLE_B,
        bind_host="127.0.0.1",
        peer_host="127.0.0.1",
        peer_port=port,
        initiator_role=config.ROLE_A,
        connect_timeout=5.0,
        recv_timeout=recv_timeout,
    )

    def run_alice() -> None:
        alice.connect()

    def run_bob() -> None:
        bob.connect()

    ta = threading.Thread(target=run_alice, name="alice-conn", daemon=True)
    tb = threading.Thread(target=run_bob, name="bob-conn", daemon=True)
    ta.start()
    # Tiny stagger so the listener is bound before the dialer arrives —
    # avoids the connect() retry loop kicking in during tests.
    time.sleep(0.05)
    tb.start()

    if not alice.wait_for_sync(timeout=15.0):
        alice.close(); bob.close()
        raise RuntimeError("alice did not sync in time")
    if not bob.wait_for_sync(timeout=15.0):
        alice.close(); bob.close()
        raise RuntimeError("bob did not sync in time")

    ta.join(timeout=5.0)
    tb.join(timeout=5.0)
    return alice, bob


class TestPeerLinkSync(unittest.TestCase):
    def test_two_peer_links_sync_to_matching_keys(self) -> None:
        port = _free_port()
        alice = bob = None
        try:
            progress_alice: list = []
            progress_bob: list = []
            sync_done_alice: list = [None]
            sync_done_bob: list = [None]

            def make_progress(target):
                def cb(rnd, matched, total):
                    target.append((rnd, matched, total))
                return cb

            def make_complete(target, link):
                def cb(result, fp_hex):
                    target[0] = (result, fp_hex)
                return cb

            alice = PeerLink(
                role=config.ROLE_A,
                bind_host="127.0.0.1", peer_host="127.0.0.1",
                peer_port=port, initiator_role=config.ROLE_A,
                connect_timeout=5.0,
            )
            bob = PeerLink(
                role=config.ROLE_B,
                bind_host="127.0.0.1", peer_host="127.0.0.1",
                peer_port=port, initiator_role=config.ROLE_A,
                connect_timeout=5.0,
            )
            alice.on_sync_progress = make_progress(progress_alice)
            bob.on_sync_progress = make_progress(progress_bob)
            alice.on_sync_complete = make_complete(sync_done_alice, alice)
            bob.on_sync_complete = make_complete(sync_done_bob, bob)

            ta = threading.Thread(target=alice.connect, daemon=True)
            tb = threading.Thread(target=bob.connect, daemon=True)
            ta.start(); time.sleep(0.05); tb.start()
            self.assertTrue(alice.wait_for_sync(timeout=15.0))
            self.assertTrue(bob.wait_for_sync(timeout=15.0))
            ta.join(timeout=5.0); tb.join(timeout=5.0)

            # Both sides must report success and identical key fingerprints.
            self.assertIsNotNone(sync_done_alice[0])
            self.assertIsNotNone(sync_done_bob[0])
            ra, fp_a = sync_done_alice[0]
            rb, fp_b = sync_done_bob[0]
            self.assertTrue(ra.success)
            self.assertTrue(rb.success)
            self.assertEqual(fp_a, fp_b)
            self.assertEqual(alice.key_fingerprint, bob.key_fingerprint)

            # Both sides should have observed at least one progress emit.
            self.assertGreater(len(progress_alice), 0)
            self.assertGreater(len(progress_bob), 0)
        finally:
            if alice is not None: alice.close()
            if bob is not None: bob.close()


class TestPeerLinkChat(unittest.TestCase):
    def test_chat_round_trip_fires_callback(self) -> None:
        port = _free_port()
        alice = bob = None
        try:
            alice, bob = _run_pair(port)

            received_at_bob: list = [None]
            recv_event = threading.Event()

            def on_chat(plaintext, bundle):
                received_at_bob[0] = (plaintext, bundle)
                recv_event.set()

            bob.on_chat_received = on_chat
            sent_bundle = alice.send_chat("Hello, Bob! 🔐")
            self.assertTrue(recv_event.wait(timeout=5.0),
                            "bob did not receive the chat in time")

            plaintext, bundle = received_at_bob[0]
            self.assertEqual(plaintext, "Hello, Bob! 🔐")
            self.assertGreater(len(bundle), 0)
            self.assertEqual(bundle, sent_bundle)
        finally:
            if alice is not None: alice.close()
            if bob is not None: bob.close()

    def test_multiple_chats_in_sequence(self) -> None:
        port = _free_port()
        alice = bob = None
        try:
            alice, bob = _run_pair(port)

            received: list = []
            recv_event = threading.Event()
            target_count = 5

            def on_chat(pt, bundle):
                received.append(pt)
                if len(received) >= target_count:
                    recv_event.set()

            bob.on_chat_received = on_chat
            for i in range(target_count):
                alice.send_chat(f"msg-{i}")
            self.assertTrue(recv_event.wait(timeout=5.0))
            self.assertEqual(received, [f"msg-{i}" for i in range(target_count)])
        finally:
            if alice is not None: alice.close()
            if bob is not None: bob.close()

    def test_send_chat_before_sync_raises(self) -> None:
        link = PeerLink(role=config.ROLE_A,
                        bind_host="127.0.0.1", peer_host="127.0.0.1",
                        peer_port=_free_port(), initiator_role=config.ROLE_A)
        with self.assertRaises(RuntimeError):
            link.send_chat("nope")


class TestPeerLinkFileTransfer(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="peerlink-test-")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_small_file_round_trip(self) -> None:
        port = _free_port()
        alice = bob = None
        try:
            alice, bob = _run_pair(port)

            content = b"the quick brown fox jumps over the lazy dog\n" * 50
            path = os.path.join(self.tmpdir, "src.txt")
            with open(path, "wb") as f:
                f.write(content)

            received: list = [None]
            done = threading.Event()

            def on_complete(meta, sha_ok, plaintext):
                received[0] = (meta, sha_ok, plaintext)
                done.set()

            bob.on_file_complete = on_complete
            sent_meta = alice.send_file(path)
            self.assertTrue(done.wait(timeout=10.0),
                            "bob did not receive the file in time")

            meta, sha_ok, plaintext = received[0]
            self.assertTrue(sha_ok)
            self.assertEqual(meta["filename"], "src.txt")
            self.assertEqual(meta["file_id"], sent_meta["file_id"])
            self.assertEqual(plaintext, content)
        finally:
            if alice is not None: alice.close()
            if bob is not None: bob.close()


if __name__ == "__main__":
    unittest.main()
