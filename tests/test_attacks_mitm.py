"""Tests for `attacks.mitm.MITMAttack`."""

from __future__ import annotations

import unittest

from attacks.mitm import MITMAttack
from core.transport_tcp import (
    KIND_CHAT,
    KIND_FINGERPRINT,
    KIND_SEED,
    KIND_TAU,
)


class TestMITMAttack(unittest.TestCase):
    def test_inactive_passes_chat_through_unchanged(self):
        attack = MITMAttack(rng_seed=42)
        # Not started — inactive, should not tamper.
        kind, payload = attack.on_outbound_frame(KIND_CHAT, b"abcdef")
        self.assertEqual(kind, KIND_CHAT)
        self.assertEqual(payload, b"abcdef")
        self.assertEqual(attack.get_stats()["frames_seen"], 0)
        self.assertEqual(attack.get_stats()["frames_tampered"], 0)

    def test_sync_phase_frames_never_touched_even_when_active(self):
        attack = MITMAttack(tamper_probability=1.0, rng_seed=42)
        attack.start()
        for kind in (KIND_TAU, KIND_FINGERPRINT, KIND_SEED):
            with self.subTest(kind=kind):
                k, p = attack.on_outbound_frame(kind, b"\x01\x02\x03\x04")
                self.assertEqual(k, kind)
                self.assertEqual(p, b"\x01\x02\x03\x04")
        # No CHAT frames went through, so nothing tampered.
        self.assertEqual(attack.get_stats()["frames_tampered"], 0)

    def test_tampers_at_configured_rate(self):
        # Deterministic RNG so we can assert exact behaviour.  At 0.30
        # tamper rate over 1000 frames, with the default Python RNG
        # seeded to 42, we expect a count close to 300 (within a few %).
        attack = MITMAttack(tamper_probability=0.30, rng_seed=42)
        attack.start()
        n_frames = 1000
        tampered = 0
        for i in range(n_frames):
            payload = bytes(((i * 17) % 256 for _ in range(32)))
            _, out = attack.on_outbound_frame(KIND_CHAT, payload)
            if out != payload:
                tampered += 1
        # Allow ~6% slack — the RNG is stable under the same seed,
        # but we don't want a brittle exact-match test.
        self.assertGreater(tampered, n_frames * 0.24)
        self.assertLess(tampered, n_frames * 0.36)
        stats = attack.get_stats()
        self.assertEqual(stats["frames_seen"], n_frames)
        self.assertEqual(stats["frames_tampered"], tampered)

    def test_tamper_probability_one_tampers_every_nonempty_frame(self):
        attack = MITMAttack(tamper_probability=1.0, rng_seed=7)
        attack.start()
        for _ in range(50):
            payload = b"x" * 32
            _, out = attack.on_outbound_frame(KIND_CHAT, payload)
            self.assertNotEqual(out, payload)

    def test_empty_payload_counts_as_seen_but_not_tampered(self):
        attack = MITMAttack(tamper_probability=1.0, rng_seed=0)
        attack.start()
        _, out = attack.on_outbound_frame(KIND_CHAT, b"")
        self.assertEqual(out, b"")
        self.assertEqual(attack.get_stats()["frames_tampered"], 0)
        self.assertEqual(attack.get_stats()["frames_seen"], 1)

    def test_inbound_is_passthrough(self):
        attack = MITMAttack(tamper_probability=1.0, rng_seed=0)
        attack.start()
        k, p = attack.on_inbound_frame(KIND_CHAT, b"abcdef")
        self.assertEqual(k, KIND_CHAT)
        self.assertEqual(p, b"abcdef")

    def test_tampered_payload_differs_by_exactly_one_bit_default(self):
        attack = MITMAttack(tamper_probability=1.0,
                            flip_bits_per_frame=1, rng_seed=0)
        attack.start()
        original = b"hello world abc"
        _, out = attack.on_outbound_frame(KIND_CHAT, original)
        # Hamming distance of exactly 1 bit.
        diff_bits = sum(
            bin(a ^ b).count("1") for a, b in zip(original, out)
        )
        self.assertEqual(diff_bits, 1)

    def test_invalid_probability_rejected(self):
        with self.assertRaises(ValueError):
            MITMAttack(tamper_probability=-0.1)
        with self.assertRaises(ValueError):
            MITMAttack(tamper_probability=1.5)

    def test_invalid_flip_count_rejected(self):
        with self.assertRaises(ValueError):
            MITMAttack(flip_bits_per_frame=0)


if __name__ == "__main__":
    unittest.main()
