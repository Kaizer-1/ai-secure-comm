"""Tests for `attacks.replay.ReplayAttack`."""

from __future__ import annotations

import threading
import time
import unittest
from typing import List, Tuple

from attacks.replay import ReplayAttack
from core.transport_tcp import KIND_CHAT, KIND_TAU


class _FakeTransport:
    """Minimal transport stub: records every `_send_frame` call."""

    def __init__(self) -> None:
        self.sent: List[Tuple[int, bytes]] = []
        self.lock = threading.Lock()

    def _send_frame(self, kind: int, payload: bytes) -> None:
        with self.lock:
            self.sent.append((kind, payload))


class TestReplayBuffering(unittest.TestCase):
    def test_inactive_does_not_buffer(self):
        attack = ReplayAttack(buffer_size=3, interval_s=10.0, rng_seed=0)
        # No start() — inactive.
        attack.on_outbound_frame(KIND_CHAT, b"a")
        attack.on_outbound_frame(KIND_CHAT, b"b")
        self.assertEqual(attack.get_stats()["frames_buffered"], 0)
        self.assertEqual(attack.get_stats()["buffer_occupancy"], 0)

    def test_active_buffers_chat_frames(self):
        attack = ReplayAttack(buffer_size=3, interval_s=10.0, rng_seed=0)
        attack.attach(_FakeTransport())
        attack.start()
        try:
            attack.on_outbound_frame(KIND_CHAT, b"a")
            attack.on_outbound_frame(KIND_CHAT, b"b")
            attack.on_outbound_frame(KIND_CHAT, b"c")
            self.assertEqual(attack.get_stats()["frames_buffered"], 3)
            self.assertEqual(attack.get_stats()["buffer_occupancy"], 3)
        finally:
            attack.stop()

    def test_active_does_not_buffer_sync_frames(self):
        attack = ReplayAttack(buffer_size=3, interval_s=10.0, rng_seed=0)
        attack.attach(_FakeTransport())
        attack.start()
        try:
            attack.on_outbound_frame(KIND_TAU, b"\x01")
            self.assertEqual(attack.get_stats()["frames_buffered"], 0)
        finally:
            attack.stop()

    def test_buffer_evicts_oldest_at_capacity(self):
        attack = ReplayAttack(buffer_size=2, interval_s=10.0, rng_seed=0)
        attack.attach(_FakeTransport())
        attack.start()
        try:
            for byte in (b"a", b"b", b"c"):
                attack.on_outbound_frame(KIND_CHAT, byte)
            # Capacity is 2, so a's b'a' was evicted.
            self.assertEqual(attack.get_stats()["buffer_occupancy"], 2)
            self.assertEqual(attack.get_stats()["frames_buffered"], 3)
        finally:
            attack.stop()

    def test_inbound_passthrough(self):
        attack = ReplayAttack(buffer_size=3, interval_s=10.0, rng_seed=0)
        attack.start()
        try:
            k, p = attack.on_inbound_frame(KIND_CHAT, b"abc")
            self.assertEqual(k, KIND_CHAT)
            self.assertEqual(p, b"abc")
        finally:
            attack.stop()


class TestReplayInjection(unittest.TestCase):
    def test_injects_buffered_frame_periodically(self):
        # Short interval so the test doesn't take long.
        attack = ReplayAttack(buffer_size=5, interval_s=0.1, rng_seed=42)
        ft = _FakeTransport()
        attack.attach(ft)
        attack.start()
        try:
            attack.on_outbound_frame(KIND_CHAT, b"alpha")
            attack.on_outbound_frame(KIND_CHAT, b"bravo")
            # Wait for a few injection ticks.
            time.sleep(0.45)
        finally:
            attack.stop()

        injected = list(ft.sent)
        self.assertGreaterEqual(len(injected), 2,
                                f"expected >=2 replays in 450ms, got {len(injected)}")
        # All injections should be CHAT kind and from the buffer.
        for kind, payload in injected:
            self.assertEqual(kind, KIND_CHAT)
            self.assertIn(payload, (b"alpha", b"bravo"))

        stats = attack.get_stats()
        self.assertGreaterEqual(stats["frames_replayed"], 2)
        # `replay_intervals_ms` is one shorter than `frames_replayed`
        # (no interval before the first replay).
        self.assertEqual(
            len(stats["replay_intervals_ms"]),
            max(0, stats["frames_replayed"] - 1),
        )

    def test_self_injected_frames_dont_loop_into_buffer(self):
        """An injected frame must not get re-buffered when it travels
        back through `on_outbound_frame`."""
        attack = ReplayAttack(buffer_size=2, interval_s=0.1, rng_seed=0)

        # Custom transport that re-feeds the injected frame back into
        # the attack's outbound hook (simulating what TCPTransport
        # _send_frame would do via the registry).
        class FeedbackTransport:
            def __init__(self):
                self.sent = []
                self.lock = threading.Lock()

            def _send_frame(self_inner, kind, payload):  # noqa: N805
                with self_inner.lock:
                    self_inner.sent.append((kind, payload))
                attack.on_outbound_frame(kind, payload)

        ft = FeedbackTransport()
        attack.attach(ft)
        attack.start()
        try:
            attack.on_outbound_frame(KIND_CHAT, b"original")
            time.sleep(0.35)
        finally:
            attack.stop()

        # The buffer should have only the *original* — never re-buffered
        # the re-injected copy.
        self.assertEqual(attack.get_stats()["frames_buffered"], 1)

    def test_stop_is_clean_and_idempotent(self):
        attack = ReplayAttack(buffer_size=2, interval_s=0.05, rng_seed=0)
        attack.attach(_FakeTransport())
        attack.start()
        attack.on_outbound_frame(KIND_CHAT, b"x")
        time.sleep(0.12)
        attack.stop()
        attack.stop()  # second call must not raise
        self.assertFalse(attack.is_active())


class TestReplayValidation(unittest.TestCase):
    def test_invalid_buffer_size_rejected(self):
        with self.assertRaises(ValueError):
            ReplayAttack(buffer_size=0)

    def test_invalid_interval_rejected(self):
        with self.assertRaises(ValueError):
            ReplayAttack(interval_s=0)
        with self.assertRaises(ValueError):
            ReplayAttack(interval_s=-1.0)


if __name__ == "__main__":
    unittest.main()
