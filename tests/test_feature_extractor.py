"""Tests for `ai.feature_extractor.FeatureExtractor`."""

from __future__ import annotations

import unittest

from ai.feature_extractor import FEATURE_NAMES, FeatureExtractor
from core.transport_tcp import (
    KIND_CHAT,
    KIND_CONTROL,
    KIND_FILE_CHUNK,
    KIND_FILE_META,
)


class TestEmptyAndDegenerate(unittest.TestCase):
    def test_empty_window_returns_zeros_with_canonical_keys(self):
        ex = FeatureExtractor(window_size=20)
        feats = ex.extract_features()
        self.assertEqual(set(feats.keys()), set(FEATURE_NAMES))
        for v in feats.values():
            self.assertEqual(v, 0.0)

    def test_single_frame_window(self):
        ex = FeatureExtractor(window_size=20)
        ex.record(kind=KIND_CHAT, size=42, direction="out", timestamp=100.0)
        feats = ex.extract_features()
        # Single frame: no inter-arrival, no rate.
        self.assertEqual(feats["mean_inter_arrival_ms"], 0.0)
        self.assertEqual(feats["std_inter_arrival_ms"], 0.0)
        self.assertEqual(feats["frame_rate_per_second"], 0.0)
        # Mean/std payload size from the one observation.
        self.assertEqual(feats["mean_payload_size"], 42.0)
        self.assertEqual(feats["std_payload_size"], 0.0)
        # No decrypt observations recorded → failure rate 0.
        self.assertEqual(feats["decrypt_failure_rate"], 0.0)
        # Composition: 100% chat.
        self.assertEqual(feats["chat_frame_fraction"], 1.0)
        self.assertEqual(feats["file_frame_fraction"], 0.0)
        self.assertEqual(feats["control_frame_fraction"], 0.0)


class TestRegularTraffic(unittest.TestCase):
    def test_uniform_inter_arrival(self):
        ex = FeatureExtractor(window_size=20)
        # 10 frames, 100ms apart starting at t=0.
        for i in range(10):
            ex.record(
                kind=KIND_CHAT, size=50, direction="out",
                timestamp=i * 0.1,
            )
        feats = ex.extract_features()
        self.assertAlmostEqual(feats["mean_inter_arrival_ms"], 100.0, places=4)
        self.assertAlmostEqual(feats["std_inter_arrival_ms"], 0.0, places=4)
        # Rate: 10 frames over 0.9 s span → ~11.1 / s.
        self.assertGreater(feats["frame_rate_per_second"], 10.0)
        self.assertLess(feats["frame_rate_per_second"], 12.0)

    def test_payload_size_stats(self):
        ex = FeatureExtractor(window_size=20)
        sizes = [10, 20, 30, 40, 50]
        for i, s in enumerate(sizes):
            ex.record(kind=KIND_CHAT, size=s, direction="out",
                      timestamp=i * 0.05)
        feats = ex.extract_features()
        self.assertAlmostEqual(feats["mean_payload_size"], 30.0, places=4)
        self.assertGreater(feats["std_payload_size"], 0.0)


class TestDecryptFailureRate(unittest.TestCase):
    def test_outbound_frames_dont_count_in_failure_rate(self):
        ex = FeatureExtractor(window_size=20)
        # Outbound: decrypt_success None → not counted.
        for i in range(5):
            ex.record(kind=KIND_CHAT, size=50, direction="out",
                      timestamp=i * 0.05)
        self.assertEqual(ex.extract_features()["decrypt_failure_rate"], 0.0)

    def test_all_failures(self):
        ex = FeatureExtractor(window_size=20)
        for i in range(5):
            ex.record(kind=KIND_CHAT, size=50, direction="in",
                      decrypt_success=False, timestamp=i * 0.05)
        self.assertEqual(ex.extract_features()["decrypt_failure_rate"], 1.0)

    def test_partial_failures(self):
        ex = FeatureExtractor(window_size=20)
        # 3 successes, 2 failures.
        for ok in [True, True, True, False, False]:
            ex.record(kind=KIND_CHAT, size=50, direction="in",
                      decrypt_success=ok)
        feats = ex.extract_features()
        self.assertAlmostEqual(feats["decrypt_failure_rate"], 2 / 5)


class TestDuplicatePayloadCount(unittest.TestCase):
    def test_unique_payloads_zero_duplicates(self):
        ex = FeatureExtractor(window_size=20)
        for i in range(5):
            ex.record(kind=KIND_CHAT, size=10, direction="in",
                      payload_hash=bytes([i]) * 8)
        self.assertEqual(
            ex.extract_features()["duplicate_payload_count"], 0.0,
        )

    def test_one_repeated_payload(self):
        ex = FeatureExtractor(window_size=20)
        h = b"\xaa" * 8
        ex.record(kind=KIND_CHAT, size=10, direction="in", payload_hash=h)
        ex.record(kind=KIND_CHAT, size=10, direction="in", payload_hash=h)
        # 1 duplicate (second occurrence).
        self.assertEqual(
            ex.extract_features()["duplicate_payload_count"], 1.0,
        )

    def test_payload_repeated_three_times(self):
        ex = FeatureExtractor(window_size=20)
        h = b"\xaa" * 8
        for _ in range(3):
            ex.record(kind=KIND_CHAT, size=10, direction="in", payload_hash=h)
        # 2 duplicates (occurrences 2 and 3).
        self.assertEqual(
            ex.extract_features()["duplicate_payload_count"], 2.0,
        )

    def test_no_hash_means_no_duplicate_detection(self):
        ex = FeatureExtractor(window_size=20)
        ex.record(kind=KIND_CHAT, size=10, direction="in")
        ex.record(kind=KIND_CHAT, size=10, direction="in")
        self.assertEqual(
            ex.extract_features()["duplicate_payload_count"], 0.0,
        )


class TestKindComposition(unittest.TestCase):
    def test_mixed_kinds_split_proportionally(self):
        ex = FeatureExtractor(window_size=20)
        for k in (KIND_CHAT, KIND_CHAT, KIND_FILE_META, KIND_FILE_CHUNK,
                  KIND_CONTROL):
            ex.record(kind=k, size=20, direction="in")
        feats = ex.extract_features()
        self.assertAlmostEqual(feats["chat_frame_fraction"], 2 / 5)
        self.assertAlmostEqual(feats["file_frame_fraction"], 2 / 5)
        self.assertAlmostEqual(feats["control_frame_fraction"], 1 / 5)


class TestWindowMechanics(unittest.TestCase):
    def test_window_caps_at_size(self):
        ex = FeatureExtractor(window_size=3)
        for i in range(10):
            ex.record(kind=KIND_CHAT, size=i, direction="in")
        self.assertEqual(len(ex.window_snapshot()), 3)
        self.assertEqual(ex.total_observed(), 10)

    def test_record_returns_cumulative_count(self):
        ex = FeatureExtractor(window_size=20)
        n = ex.record(kind=KIND_CHAT, size=1, direction="out")
        self.assertEqual(n, 1)
        n = ex.record(kind=KIND_CHAT, size=2, direction="out")
        self.assertEqual(n, 2)

    def test_reset_clears_window_and_count(self):
        ex = FeatureExtractor(window_size=20)
        for i in range(5):
            ex.record(kind=KIND_CHAT, size=1, direction="out")
        ex.reset()
        self.assertEqual(ex.total_observed(), 0)
        self.assertEqual(len(ex.window_snapshot()), 0)


class TestFeatureExtractorValidation(unittest.TestCase):
    def test_invalid_window_size_rejected(self):
        with self.assertRaises(ValueError):
            FeatureExtractor(window_size=0)

    def test_invalid_direction_rejected(self):
        ex = FeatureExtractor(window_size=20)
        with self.assertRaises(ValueError):
            ex.record(kind=KIND_CHAT, size=10, direction="sideways")


if __name__ == "__main__":
    unittest.main()
