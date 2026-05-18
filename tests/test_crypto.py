"""Unit tests for `core.crypto_engine.CryptoEngine`."""

from __future__ import annotations

import unittest

import numpy as np
from cryptography.exceptions import InvalidTag

import config
from core.crypto_engine import CryptoEngine


class TestCryptoEngine(unittest.TestCase):
    def setUp(self) -> None:
        # A fixed weight matrix so derived keys are reproducible across cases.
        self.weights = np.arange(
            -config.TPM_L,
            -config.TPM_L + config.TPM_K * config.TPM_N,
        ).astype(np.int8) % (2 * config.TPM_L + 1) - config.TPM_L
        self.key = CryptoEngine.derive_key_from_tpm(self.weights)
        self.engine = CryptoEngine(self.key)

    # ----- key derivation ------------------------------------------------
    def test_derived_key_length(self) -> None:
        self.assertEqual(len(self.key), config.AES_KEY_BYTES)

    def test_derived_key_is_deterministic(self) -> None:
        again = CryptoEngine.derive_key_from_tpm(self.weights)
        self.assertEqual(self.key, again)

    def test_derived_key_matches_for_different_shapes_same_values(self) -> None:
        flat = self.weights.reshape(-1)
        matrix = flat.reshape(config.TPM_K, config.TPM_N) \
            if flat.size == config.TPM_K * config.TPM_N else flat
        self.assertEqual(
            CryptoEngine.derive_key_from_tpm(flat),
            CryptoEngine.derive_key_from_tpm(matrix),
        )

    def test_derived_key_accepts_iterable_of_ints(self) -> None:
        from_array = CryptoEngine.derive_key_from_tpm(self.weights)
        from_list = CryptoEngine.derive_key_from_tpm(self.weights.tolist())
        self.assertEqual(from_array, from_list)

    def test_derived_key_rejects_empty(self) -> None:
        with self.assertRaises(ValueError):
            CryptoEngine.derive_key_from_tpm(np.array([], dtype=np.int8))

    # ----- engine construction -----------------------------------------
    def test_wrong_key_length_rejected(self) -> None:
        with self.assertRaises(ValueError):
            CryptoEngine(b"\x00" * 16)  # 128-bit key not allowed in this demo

    def test_non_bytes_key_rejected(self) -> None:
        with self.assertRaises(TypeError):
            CryptoEngine("a" * config.AES_KEY_BYTES)  # type: ignore[arg-type]

    # ----- encryption / decryption round-trip ---------------------------
    def test_round_trip_various_sizes(self) -> None:
        cases = [
            b"",
            b"a",
            b"hello world",
            b"\x00\x01\x02\x03\x04",
            b"x" * 1024,
            b"y" * 65_537,            # > 64 KiB
        ]
        for plaintext in cases:
            with self.subTest(size=len(plaintext)):
                bundle = self.engine.encrypt(plaintext)
                self.assertEqual(
                    self.engine.decrypt(bundle), plaintext
                )

    def test_bundle_layout_lengths(self) -> None:
        plaintext = b"layout check"
        bundle = self.engine.encrypt(plaintext)
        expected = config.AES_NONCE_BYTES + len(plaintext) + config.AES_TAG_BYTES
        self.assertEqual(len(bundle), expected)

    def test_each_call_uses_a_fresh_nonce(self) -> None:
        plaintext = b"same input"
        b1 = self.engine.encrypt(plaintext)
        b2 = self.engine.encrypt(plaintext)
        self.assertNotEqual(b1, b2,
                            "two encryptions of the same plaintext must differ")
        self.assertNotEqual(
            b1[: config.AES_NONCE_BYTES],
            b2[: config.AES_NONCE_BYTES],
            "nonces must be unique per call",
        )

    # ----- tamper detection --------------------------------------------
    def test_tampered_ciphertext_raises(self) -> None:
        bundle = bytearray(self.engine.encrypt(b"important payload"))
        # Flip a bit somewhere in the ciphertext middle.
        idx = config.AES_NONCE_BYTES + 1
        bundle[idx] ^= 0x01
        with self.assertRaises(InvalidTag):
            self.engine.decrypt(bytes(bundle))

    def test_tampered_tag_raises(self) -> None:
        bundle = bytearray(self.engine.encrypt(b"important payload"))
        bundle[-1] ^= 0xFF
        with self.assertRaises(InvalidTag):
            self.engine.decrypt(bytes(bundle))

    def test_tampered_nonce_raises(self) -> None:
        bundle = bytearray(self.engine.encrypt(b"important payload"))
        bundle[0] ^= 0xFF
        with self.assertRaises(InvalidTag):
            self.engine.decrypt(bytes(bundle))

    def test_wrong_associated_data_raises(self) -> None:
        bundle = self.engine.encrypt(b"msg", associated_data=b"v1")
        with self.assertRaises(InvalidTag):
            self.engine.decrypt(bundle, associated_data=b"v2")

    def test_correct_associated_data_round_trips(self) -> None:
        bundle = self.engine.encrypt(b"msg", associated_data=b"hdr")
        self.assertEqual(
            self.engine.decrypt(bundle, associated_data=b"hdr"),
            b"msg",
        )

    def test_short_bundle_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.engine.decrypt(b"\x00" * 5)


if __name__ == "__main__":
    unittest.main()
