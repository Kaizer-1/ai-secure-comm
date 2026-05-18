"""Tests for `core.file_transfer` plus a per-chunk encrypt-decrypt round-trip
using `CryptoEngine` to confirm the AAD scheme actually catches tampering.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
import unittest

from cryptography.exceptions import InvalidTag

import config
from core.crypto_engine import CryptoEngine
from core.file_transfer import (
    aad_for_chunk,
    assemble_chunks,
    iter_chunks,
    make_file_meta,
    verify_sha256,
)


class TestFileMeta(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="ftrans-test-")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write(self, name: str, content: bytes) -> str:
        path = os.path.join(self.tmpdir, name)
        with open(path, "wb") as f:
            f.write(content)
        return path

    def test_meta_fields_for_small_file(self) -> None:
        path = self._write("small.txt", b"hello world\n")
        meta = make_file_meta(path, chunk_bytes=4)
        self.assertEqual(meta["filename"], "small.txt")
        self.assertEqual(meta["size"], 12)
        self.assertEqual(meta["chunk_bytes"], 4)
        self.assertEqual(meta["total_chunks"], 3)  # 12 / 4
        self.assertEqual(len(meta["file_id"]), 32)  # uuid4 hex
        self.assertEqual(meta["sha256"], hashlib.sha256(b"hello world\n").hexdigest())

    def test_empty_file_yields_one_chunk(self) -> None:
        path = self._write("empty.bin", b"")
        meta = make_file_meta(path)
        self.assertEqual(meta["size"], 0)
        self.assertEqual(meta["total_chunks"], 1)

    def test_oversize_file_rejected(self) -> None:
        # We don't create a file > FILE_MAX_BYTES on disk; just patch the cap.
        path = self._write("blob.bin", b"x" * 100)
        old = config.FILE_MAX_BYTES
        try:
            config.FILE_MAX_BYTES = 10
            with self.assertRaises(ValueError):
                make_file_meta(path)
        finally:
            config.FILE_MAX_BYTES = old


class TestIterChunks(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="ftrans-test-")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_chunks_match_total(self) -> None:
        path = os.path.join(self.tmpdir, "f.bin")
        data = bytes(range(256)) * 3 + b"abc"  # 771 bytes
        with open(path, "wb") as f:
            f.write(data)
        chunks = list(iter_chunks(path, chunk_bytes=200))
        self.assertEqual(len(chunks), 4)
        self.assertEqual(b"".join(c for _, c in chunks), data)
        self.assertEqual([i for i, _ in chunks], [0, 1, 2, 3])

    def test_empty_file_yields_one_empty_chunk(self) -> None:
        path = os.path.join(self.tmpdir, "empty.bin")
        open(path, "wb").close()
        chunks = list(iter_chunks(path, chunk_bytes=64))
        self.assertEqual(chunks, [(0, b"")])


class TestAAD(unittest.TestCase):
    def test_aad_format(self) -> None:
        aad = aad_for_chunk("abcd", 5, 10)
        self.assertEqual(aad, b"abcd:5/10")

    def test_invalid_indices_raise(self) -> None:
        with self.assertRaises(ValueError):
            aad_for_chunk("x", -1, 5)
        with self.assertRaises(ValueError):
            aad_for_chunk("x", 5, 5)
        with self.assertRaises(ValueError):
            aad_for_chunk("x", 0, 0)


class TestAssembly(unittest.TestCase):
    def test_round_trip_in_order(self) -> None:
        chunks = {0: b"abc", 1: b"de", 2: b"fghi"}
        out = assemble_chunks("fid", 3, chunks)
        self.assertEqual(out, b"abcdefghi")

    def test_missing_chunk_raises(self) -> None:
        with self.assertRaises(ValueError):
            assemble_chunks("fid", 3, {0: b"a", 2: b"c"})

    def test_verify_sha256_roundtrip(self) -> None:
        plaintext = b"the quick brown fox"
        digest = hashlib.sha256(plaintext).hexdigest()
        self.assertTrue(verify_sha256(plaintext, digest))
        self.assertFalse(verify_sha256(plaintext + b"x", digest))


class TestEncryptedRoundTrip(unittest.TestCase):
    """End-to-end: file → meta → chunks → AES-GCM → reassemble → verify."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="ftrans-test-")
        # 32-byte test key (fixed value — these tests aren't about secrecy).
        self.engine = CryptoEngine(b"\xab" * 32)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _round_trip(self, content: bytes, chunk_bytes: int) -> None:
        path = os.path.join(self.tmpdir, "payload.bin")
        with open(path, "wb") as f:
            f.write(content)

        meta = make_file_meta(path, chunk_bytes=chunk_bytes)
        # Sender: encrypt each chunk with its specific AAD.
        bundles: dict[int, bytes] = {}
        for idx, chunk in iter_chunks(path, chunk_bytes=chunk_bytes):
            aad = aad_for_chunk(meta["file_id"], idx, meta["total_chunks"])
            bundles[idx] = self.engine.encrypt(chunk, associated_data=aad)

        # Receiver: decrypt each chunk with the same AAD; reassemble.
        decrypted: dict[int, bytes] = {}
        for idx, bundle in bundles.items():
            aad = aad_for_chunk(meta["file_id"], idx, meta["total_chunks"])
            decrypted[idx] = self.engine.decrypt(bundle, associated_data=aad)

        plaintext = assemble_chunks(meta["file_id"],
                                    meta["total_chunks"], decrypted)
        self.assertEqual(plaintext, content)
        self.assertTrue(verify_sha256(plaintext, meta["sha256"]))

    def test_small_file(self) -> None:
        self._round_trip(b"hello world" * 100, chunk_bytes=64)  # ~1.1 KB

    def test_medium_file(self) -> None:
        # 2 MiB, exercises ~32 chunks at 64 KiB each.
        content = (bytes(range(256)) * 8192)
        self._round_trip(content, chunk_bytes=config.FILE_CHUNK_BYTES)

    def test_aad_tamper_detected(self) -> None:
        path = os.path.join(self.tmpdir, "p.bin")
        with open(path, "wb") as f:
            f.write(b"sensitive bytes")
        meta = make_file_meta(path, chunk_bytes=8)
        idx, chunk = next(iter(iter_chunks(path, chunk_bytes=8)))
        good_aad = aad_for_chunk(meta["file_id"], idx, meta["total_chunks"])
        bundle = self.engine.encrypt(chunk, associated_data=good_aad)

        # Pretend an attacker shifted the chunk_index in the wire frame.
        wrong_aad = aad_for_chunk(meta["file_id"], idx + 1,
                                  meta["total_chunks"])
        with self.assertRaises(InvalidTag):
            self.engine.decrypt(bundle, associated_data=wrong_aad)

    def test_assembled_sha_mismatch_detected(self) -> None:
        """If a chunk's plaintext is corrupted post-decrypt, SHA check fails."""
        path = os.path.join(self.tmpdir, "p.bin")
        with open(path, "wb") as f:
            f.write(b"abcdefghij")
        meta = make_file_meta(path, chunk_bytes=4)
        decrypted: dict[int, bytes] = {}
        for idx, chunk in iter_chunks(path, chunk_bytes=4):
            decrypted[idx] = chunk
        # Corrupt one chunk *after* the AEAD step (e.g. disk write error).
        decrypted[0] = b"ZZZZ"
        plaintext = assemble_chunks(meta["file_id"],
                                    meta["total_chunks"], decrypted)
        self.assertFalse(verify_sha256(plaintext, meta["sha256"]))


if __name__ == "__main__":
    unittest.main()
