"""Unit tests for `core.sync_protocol.SyncProtocol`.

We run the full synchronisation 10 times with different seeds, verify
that the two TPMs reach identical weights every time, and print the
average / max round count for the record.
"""

from __future__ import annotations

import statistics
import unittest

import numpy as np

import config
from core.tpm import TreeParityMachine
from core.sync_protocol import SyncProtocol


def _fresh_pair(seed_a: int, seed_b: int) -> tuple[TreeParityMachine, TreeParityMachine]:
    """Build two TPMs with *different* secret weights but matching shape."""
    return (
        TreeParityMachine(config.TPM_K, config.TPM_N, config.TPM_L,
                          rng=np.random.default_rng(seed_a)),
        TreeParityMachine(config.TPM_K, config.TPM_N, config.TPM_L,
                          rng=np.random.default_rng(seed_b)),
    )


class TestSyncProtocol(unittest.TestCase):
    def test_mismatched_parameters_raise(self) -> None:
        a = TreeParityMachine(3, 10, 3)
        b = TreeParityMachine(3, 10, 4)  # different L
        with self.assertRaises(ValueError):
            SyncProtocol(a, b)

    def test_already_synced_returns_immediately(self) -> None:
        a = TreeParityMachine(3, 10, 3, rng=np.random.default_rng(1))
        b = TreeParityMachine(3, 10, 3, rng=np.random.default_rng(1))
        # Same seed -> identical weights -> already synchronised.
        self.assertEqual(a.weight_fingerprint(), b.weight_fingerprint())
        result = SyncProtocol(a, b, seed=0).synchronize()
        self.assertTrue(result.success)
        self.assertEqual(result.rounds, 0)

    def test_ten_runs_all_synchronise(self) -> None:
        rounds_taken: list[int] = []
        for trial in range(10):
            seed_a = 1000 + trial
            seed_b = 5000 + trial
            input_seed = 9000 + trial
            a, b = _fresh_pair(seed_a, seed_b)
            # Sanity: the two TPMs should NOT already share weights.
            self.assertNotEqual(a.weight_fingerprint(), b.weight_fingerprint())

            result = SyncProtocol(a, b, seed=input_seed).synchronize()

            self.assertTrue(result.success,
                            f"trial {trial}: failed to sync within "
                            f"{config.TPM_SYNC_MAX_ROUNDS} rounds")
            self.assertEqual(a.weight_fingerprint(), b.weight_fingerprint())
            self.assertTrue(np.array_equal(a.weights, b.weights))
            rounds_taken.append(result.rounds)

        avg = statistics.mean(rounds_taken)
        worst = max(rounds_taken)
        # Surface the figures so the test log is informative.
        print(f"\n[test_sync] 10 runs synced; avg={avg:.1f} worst={worst}")
        # Sanity bound: even under bad luck, default-parameter Hebbian
        # sync at K=3, N=10, L=3 finishes in well under 5 000 rounds.
        self.assertLess(worst, config.TPM_SYNC_MAX_ROUNDS)

    def test_returns_sync_result_dataclass(self) -> None:
        a, b = _fresh_pair(seed_a=11, seed_b=22)
        result = SyncProtocol(a, b, seed=33).synchronize()
        self.assertTrue(result.success)
        self.assertGreaterEqual(result.rounds, 1)
        self.assertGreater(result.elapsed_seconds, 0.0)
        self.assertEqual(result.final_fingerprint, a.weight_fingerprint())


if __name__ == "__main__":
    unittest.main()
