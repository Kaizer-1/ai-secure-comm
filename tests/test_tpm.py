"""Unit tests for `core.tpm.TreeParityMachine`."""

from __future__ import annotations

import unittest

import numpy as np

import config
from core.tpm import TreeParityMachine


class TestTreeParityMachine(unittest.TestCase):
    def setUp(self) -> None:
        self.rng = np.random.default_rng(seed=config.DEMO_SEED)
        self.tpm = TreeParityMachine(
            K=config.TPM_K, N=config.TPM_N, L=config.TPM_L, rng=self.rng
        )

    # ----- construction --------------------------------------------------
    def test_weight_shape_and_range(self) -> None:
        self.assertEqual(self.tpm.weights.shape, (config.TPM_K, config.TPM_N))
        self.assertTrue(np.all(self.tpm.weights >= -config.TPM_L))
        self.assertTrue(np.all(self.tpm.weights <= config.TPM_L))

    def test_invalid_construction_raises(self) -> None:
        for bad in [(0, 1, 1), (1, 0, 1), (1, 1, 0), (-1, 1, 1)]:
            with self.subTest(params=bad):
                with self.assertRaises(ValueError):
                    TreeParityMachine(*bad)

    # ----- forward pass --------------------------------------------------
    def test_inputs_are_plus_minus_one_with_correct_shape(self) -> None:
        inputs = self.tpm.generate_random_inputs()
        self.assertEqual(inputs.shape, (config.TPM_K, config.TPM_N))
        unique = set(np.unique(inputs).tolist())
        self.assertTrue(unique.issubset({-1, 1}))

    def test_compute_output_shapes_and_values(self) -> None:
        inputs = self.tpm.generate_random_inputs()
        tau, sigmas = self.tpm.compute_output(inputs)
        self.assertIn(tau, (-1, 1))
        self.assertEqual(sigmas.shape, (config.TPM_K,))
        self.assertTrue(np.all(np.isin(sigmas, (-1, 1))))
        # Network output is the product of sigmas.
        self.assertEqual(tau, int(np.prod(sigmas)))

    def test_compute_output_rejects_bad_shape(self) -> None:
        bad = np.ones((config.TPM_K + 1, config.TPM_N), dtype=np.int8)
        with self.assertRaises(ValueError):
            self.tpm.compute_output(bad)

    def test_compute_output_rejects_non_pm1_inputs(self) -> None:
        bad = np.zeros((config.TPM_K, config.TPM_N), dtype=np.int8)
        with self.assertRaises(ValueError):
            self.tpm.compute_output(bad)

    # ----- learning ------------------------------------------------------
    def test_unknown_learning_rule_raises(self) -> None:
        inputs = self.tpm.generate_random_inputs()
        with self.assertRaises(ValueError):
            self.tpm.update_weights(inputs, partner_output=1, learning_rule="bogus")

    def test_no_update_when_outputs_disagree(self) -> None:
        inputs = self.tpm.generate_random_inputs()
        tau, _ = self.tpm.compute_output(inputs)
        before = self.tpm.weights.copy()
        # Pass the *opposite* of our own output.
        changed = self.tpm.update_weights(inputs, partner_output=-tau)
        self.assertFalse(changed)
        self.assertTrue(np.array_equal(before, self.tpm.weights))

    def test_weights_remain_in_range_after_many_updates(self) -> None:
        for _ in range(500):
            inputs = self.tpm.generate_random_inputs()
            tau, _ = self.tpm.compute_output(inputs)
            for rule in ("hebbian", "anti_hebbian", "random_walk"):
                self.tpm.update_weights(inputs, partner_output=tau, learning_rule=rule)
        self.assertTrue(np.all(self.tpm.weights >= -config.TPM_L))
        self.assertTrue(np.all(self.tpm.weights <= config.TPM_L))

    def test_hebbian_actually_changes_weights_when_gate_open(self) -> None:
        # We agree with ourselves on tau, so the gate is guaranteed to open.
        inputs = self.tpm.generate_random_inputs()
        tau, _ = self.tpm.compute_output(inputs)
        # Repeat a few times: at least one update should have moved a weight,
        # unless the TPM happens to already be saturated everywhere — which
        # is statistically vanishingly unlikely with the demo parameters.
        moved_at_least_once = False
        for _ in range(10):
            inputs = self.tpm.generate_random_inputs()
            tau, _ = self.tpm.compute_output(inputs)
            if self.tpm.update_weights(inputs, partner_output=tau,
                                       learning_rule="hebbian"):
                moved_at_least_once = True
                break
        self.assertTrue(moved_at_least_once)

    # ----- export / fingerprint -----------------------------------------
    def test_export_weights_is_flat_int8(self) -> None:
        flat = self.tpm.export_weights()
        self.assertEqual(flat.shape, (config.TPM_K * config.TPM_N,))
        self.assertEqual(flat.dtype, np.int8)

    def test_fingerprint_changes_with_weights(self) -> None:
        fp_before = self.tpm.weight_fingerprint()
        self.tpm.weights[0, 0] = -self.tpm.weights[0, 0] if self.tpm.weights[0, 0] != 0 else 1
        fp_after = self.tpm.weight_fingerprint()
        self.assertNotEqual(fp_before, fp_after)

    def test_two_tpms_with_same_seed_have_same_fingerprint(self) -> None:
        a = TreeParityMachine(3, 10, 3, rng=np.random.default_rng(42))
        b = TreeParityMachine(3, 10, 3, rng=np.random.default_rng(42))
        self.assertEqual(a.weight_fingerprint(), b.weight_fingerprint())


if __name__ == "__main__":
    unittest.main()
