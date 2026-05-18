"""Tests for the transport / per-side session refactor.

Existing `test_sync.py` keeps exercising the Phase-1 surface
(`SyncProtocol(tpm_a, tpm_b)`).  This module exercises the *new* layers
directly: the `LoopbackTransport`, and two `SyncSession` instances paired
through it.
"""

from __future__ import annotations

import threading
import time
import unittest

import numpy as np

import config
from core.sync_protocol import (
    INITIATOR,
    RESPONDER,
    LoopbackTransport,
    SyncSession,
    TransportTimeout,
    make_loopback_pair,
)
from core.tpm import TreeParityMachine


def _join_all(threads: list[threading.Thread], timeout: float = 30.0) -> None:
    """Join with a hard ceiling so a wedged test never hangs the suite."""
    deadline = time.perf_counter() + timeout
    for t in threads:
        remaining = max(0.0, deadline - time.perf_counter())
        t.join(timeout=remaining)
    for t in threads:
        if t.is_alive():
            raise AssertionError(f"thread {t.name!r} did not finish in {timeout}s")


class TestLoopbackTransport(unittest.TestCase):
    def test_paired_transports_deliver_each_message_type(self) -> None:
        """tau, fingerprint, and seed are each delivered both directions."""
        t_a, t_b = make_loopback_pair(recv_timeout=2.0)
        results: dict[str, object] = {}

        def alice() -> None:
            t_a.send_tau(1)
            results["alice_tau"] = t_a.recv_tau()
            t_a.send_fingerprint(b"alice-fp")
            results["alice_fp"] = t_a.recv_fingerprint()
            results["alice_seed"] = t_a.exchange_seed(0xAA)

        def bob() -> None:
            results["bob_tau"] = t_b.recv_tau()
            t_b.send_tau(-1)
            results["bob_fp"] = t_b.recv_fingerprint()
            t_b.send_fingerprint(b"bob-fp")
            results["bob_seed"] = t_b.exchange_seed(0x55)

        ta = threading.Thread(target=alice, name="alice")
        tb = threading.Thread(target=bob, name="bob")
        ta.start(); tb.start()
        _join_all([ta, tb], timeout=5.0)

        self.assertEqual(results["alice_tau"], -1)
        self.assertEqual(results["bob_tau"], 1)
        self.assertEqual(results["alice_fp"], b"bob-fp")
        self.assertEqual(results["bob_fp"], b"alice-fp")
        # Both sides MUST agree on the seed.
        self.assertEqual(results["alice_seed"], 0xAA ^ 0x55)
        self.assertEqual(results["bob_seed"], 0xAA ^ 0x55)

    def test_recv_times_out_when_peer_silent(self) -> None:
        t_a, _t_b = make_loopback_pair(recv_timeout=0.05)
        with self.assertRaises(TransportTimeout):
            t_a.recv_tau()
        with self.assertRaises(TransportTimeout):
            t_a.recv_fingerprint()

    def test_recv_raises_on_unexpected_message_kind(self) -> None:
        """Wrong call order on the protocol surfaces as a clear error."""
        t_a, t_b = make_loopback_pair(recv_timeout=2.0)
        # Side B sends a fingerprint, side A asks for a tau — protocol bug.
        t_b.send_fingerprint(b"oops")
        with self.assertRaises(RuntimeError):
            t_a.recv_tau()


class TestSyncSessionDirectly(unittest.TestCase):
    def _fresh_pair(
        self, seed_a: int, seed_b: int
    ) -> tuple[TreeParityMachine, TreeParityMachine]:
        return (
            TreeParityMachine(config.TPM_K, config.TPM_N, config.TPM_L,
                              rng=np.random.default_rng(seed_a)),
            TreeParityMachine(config.TPM_K, config.TPM_N, config.TPM_L,
                              rng=np.random.default_rng(seed_b)),
        )

    def test_two_sessions_converge_through_paired_loopback(self) -> None:
        a, b = self._fresh_pair(seed_a=101, seed_b=202)
        self.assertNotEqual(a.weight_fingerprint(), b.weight_fingerprint())

        t_a, t_b = make_loopback_pair(recv_timeout=10.0)
        sess_a = SyncSession(a, t_a, role=INITIATOR, local_seed=0xDEAD_BEEF)
        sess_b = SyncSession(b, t_b, role=RESPONDER, local_seed=0)

        results: list = [None, None]

        def run(idx: int, sess: SyncSession) -> None:
            results[idx] = sess.synchronize()

        ta = threading.Thread(target=run, args=(0, sess_a), name="sess-a")
        tb = threading.Thread(target=run, args=(1, sess_b), name="sess-b")
        ta.start(); tb.start()
        _join_all([ta, tb], timeout=20.0)

        self.assertIsNotNone(results[0])
        self.assertIsNotNone(results[1])
        self.assertTrue(results[0].success)
        self.assertTrue(results[1].success)
        # Both sides must report the same rounds and fingerprint.
        self.assertEqual(results[0].rounds, results[1].rounds)
        self.assertEqual(results[0].final_fingerprint, results[1].final_fingerprint)
        # And the underlying TPM weights themselves must match.
        self.assertEqual(a.weight_fingerprint(), b.weight_fingerprint())
        self.assertTrue(np.array_equal(a.weights, b.weights))

    def test_session_returns_failure_when_peer_silent(self) -> None:
        """A wedged peer must NOT hang the session — recv_timeout fires."""
        a, _ = self._fresh_pair(seed_a=1, seed_b=2)
        # Solo transport: the paired side is intentionally unused, so
        # nothing ever arrives in t_a's recv queue.
        t_a, _t_b = make_loopback_pair(recv_timeout=0.05)
        sess = SyncSession(a, t_a, role=INITIATOR, local_seed=42)

        deadline = time.perf_counter() + 2.0
        result = sess.synchronize()
        self.assertLess(
            time.perf_counter(), deadline,
            "session should have timed out fast, not run for 2s",
        )
        self.assertFalse(result.success)
        # Should not have advanced the round counter past 0 — the timeout
        # fires during the seed handshake before any rounds run.
        self.assertEqual(result.rounds, 0)


class TestSyncSessionInputValidation(unittest.TestCase):
    def test_invalid_role_raises(self) -> None:
        a, _ = (
            TreeParityMachine(3, 10, 3),
            TreeParityMachine(3, 10, 3),
        )
        t_a, _t_b = make_loopback_pair(recv_timeout=1.0)
        with self.assertRaises(ValueError):
            SyncSession(a, t_a, role="spectator")

    def test_invalid_max_rounds_raises(self) -> None:
        a = TreeParityMachine(3, 10, 3)
        t_a, _t_b = make_loopback_pair(recv_timeout=1.0)
        with self.assertRaises(ValueError):
            SyncSession(a, t_a, role=INITIATOR, max_rounds=0)

    def test_invalid_fingerprint_check_every_raises(self) -> None:
        a = TreeParityMachine(3, 10, 3)
        t_a, _t_b = make_loopback_pair(recv_timeout=1.0)
        with self.assertRaises(ValueError):
            SyncSession(a, t_a, role=INITIATOR, fingerprint_check_every=0)


if __name__ == "__main__":
    unittest.main()
