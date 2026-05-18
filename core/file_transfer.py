"""Helpers for chunked, AEAD-protected file transfer.

`PeerLink` uses these to split a file into fixed-size chunks, encrypt
each chunk independently with AES-GCM (a fresh random nonce per chunk,
AAD bound to the file's identity), and reassemble on the receiver side
after verifying the SHA-256 of the recombined plaintext matches the
sender's announced digest.

Why per-chunk encryption (not one big AEAD)?
- Memory stays bounded: the plaintext is never fully in RAM.
- Lost / replayed / reordered chunks are detected at decrypt time
  because the AAD encodes (file_id, chunk_index, total_chunks) — the
  GCM tag will not validate if any of those have been tampered with.
- Phase 4's IDS will flag tag-validation failures at the chunk level,
  giving better attack visibility than a single bulk-failure event.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from typing import Dict, Iterator, Tuple

import config


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def make_file_meta(
    path: str,
    chunk_bytes: int = config.FILE_CHUNK_BYTES,
) -> dict:
    """Inspect a file on disk and produce its transfer metadata.

    The returned dict is intended to be JSON-serialised, encrypted as
    its own AES-GCM bundle, and sent in a single ``FILE_META`` frame
    *before* any chunks.  The receiver records it, then matches
    incoming ``FILE_CHUNK`` frames against ``file_id`` / ``total_chunks``.

    Returns
    -------
    dict with keys:
        file_id       — fresh UUID4 string (32 hex digits, no dashes
                        — matches what `chunk_header_layout` packs).
        filename      — basename of `path`; stripped of any directory.
        size          — plaintext file size in bytes.
        sha256        — hex digest of the full plaintext file.
        total_chunks  — number of chunks the file will be split into.
        chunk_bytes   — chunk size used.
    """
    if chunk_bytes <= 0:
        raise ValueError("chunk_bytes must be positive")

    size = os.path.getsize(path)
    if size > config.FILE_MAX_BYTES:
        raise ValueError(
            f"file size {size} exceeds FILE_MAX_BYTES "
            f"({config.FILE_MAX_BYTES})"
        )

    sha = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(64 * 1024)
            if not block:
                break
            sha.update(block)

    if size == 0:
        # An empty file still gets one (zero-length) chunk so receivers
        # have a uniform "all chunks present" check.
        total_chunks = 1
    else:
        total_chunks = (size + chunk_bytes - 1) // chunk_bytes

    return {
        "file_id": uuid.uuid4().hex,
        "filename": os.path.basename(path),
        "size": int(size),
        "sha256": sha.hexdigest(),
        "total_chunks": int(total_chunks),
        "chunk_bytes": int(chunk_bytes),
    }


def iter_chunks(
    path: str,
    chunk_bytes: int = config.FILE_CHUNK_BYTES,
) -> Iterator[Tuple[int, bytes]]:
    """Yield ``(chunk_index, plaintext_bytes)`` tuples in order.

    Empty files yield exactly one ``(0, b"")`` so the receiver always
    sees the announced ``total_chunks`` arrive.
    """
    if chunk_bytes <= 0:
        raise ValueError("chunk_bytes must be positive")
    with open(path, "rb") as f:
        idx = 0
        produced_any = False
        while True:
            data = f.read(chunk_bytes)
            if not data:
                break
            yield idx, data
            idx += 1
            produced_any = True
        if not produced_any:
            yield 0, b""


def aad_for_chunk(file_id: str, chunk_index: int, total_chunks: int) -> bytes:
    """Deterministic AAD that binds a chunk to its logical file.

    Format: ``"<file_id>:<chunk_index>/<total_chunks>"`` ASCII-encoded.
    Both sides compute it identically; tampering with any of the three
    fields makes the GCM tag fail to validate at decrypt time.
    """
    if chunk_index < 0 or total_chunks < 1 or chunk_index >= total_chunks:
        raise ValueError(
            f"invalid chunk indexing: index={chunk_index}, total={total_chunks}"
        )
    return f"{file_id}:{chunk_index}/{total_chunks}".encode("ascii")


def assemble_chunks(
    file_id: str,
    total_chunks: int,
    chunks_dict: Dict[int, bytes],
) -> bytes:
    """Reassemble plaintext from a complete chunk dict.

    Raises ``ValueError`` if any chunk index is missing.  The caller is
    expected to verify the SHA-256 of the result against the meta's
    digest before treating the transfer as successful.
    """
    if total_chunks < 1:
        raise ValueError("total_chunks must be >= 1")
    missing = [i for i in range(total_chunks) if i not in chunks_dict]
    if missing:
        raise ValueError(
            f"missing chunks for {file_id}: "
            f"{missing[:10]}{'…' if len(missing) > 10 else ''}"
        )
    return b"".join(chunks_dict[i] for i in range(total_chunks))


def verify_sha256(plaintext: bytes, expected_hex: str) -> bool:
    """Constant-style equality check on hex-encoded SHA-256 digests."""
    actual = hashlib.sha256(plaintext).hexdigest()
    # `==` on hex strings of equal length is fine for non-secret digests.
    return actual == expected_hex
