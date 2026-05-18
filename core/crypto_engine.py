"""AES-256-GCM authenticated-encryption wrapper.

This is a deliberately thin layer over
``cryptography.hazmat.primitives.ciphers.aead.AESGCM``.  It exists so that

1. Callers do not have to think about nonce generation, tag length, or
   bundle layout.
2. The bundle format is identical on both sides of the wire (Phase 2 will
   put this struct straight onto a SocketIO frame).
3. Key derivation from synchronised TPM weights is centralised in one
   place, with the hashing rule documented exactly once.

Bundle layout
-------------
``encrypt()`` returns one ``bytes`` object structured as::

    +-----------------+--------------------+----------------+
    | nonce (12 B)    | ciphertext (var.)  | tag (16 B)     |
    +-----------------+--------------------+----------------+

The 12-byte nonce is the NIST-recommended GCM size and must be unique
under each key.  We draw it from ``os.urandom`` for every single
encryption — never reuse a nonce with the same key.

The 16-byte tag is appended automatically by the underlying AES-GCM
implementation; ``decrypt()`` raises
``cryptography.exceptions.InvalidTag`` if any byte of nonce, ciphertext,
or tag has been altered.
"""

from __future__ import annotations

import hashlib
import os
from typing import Iterable, Union

import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import config


WeightLike = Union[np.ndarray, Iterable[int]]


class CryptoEngine:
    """AES-256-GCM authenticated encryption with TPM-derived keys.

    Parameters
    ----------
    key:
        A 32-byte symmetric key.  Use :py:meth:`derive_key_from_tpm` to
        produce one from synchronised TPM weights.
    """

    def __init__(self, key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key must be bytes")
        if len(key) != config.AES_KEY_BYTES:
            raise ValueError(
                f"key must be exactly {config.AES_KEY_BYTES} bytes "
                f"({config.AES_KEY_BYTES * 8}-bit AES); got {len(key)}"
            )
        self._key = bytes(key)
        self._aead = AESGCM(self._key)

    # ------------------------------------------------------------------
    # Key derivation
    # ------------------------------------------------------------------
    @classmethod
    def derive_key_from_tpm(cls, weights: WeightLike) -> bytes:
        """Derive a 256-bit AES key from synchronised TPM weights.

        The weights are first canonicalised to a flat ``int8`` NumPy array
        — the same representation `TreeParityMachine.export_weights`
        returns — and then hashed with SHA-256.  Because both sides of the
        protocol see the same weight matrix in the same order, both sides
        produce the same key.

        Parameters
        ----------
        weights:
            Either a NumPy array (any shape; will be flattened) or any
            iterable of integers (e.g. a list).

        Returns
        -------
        bytes:
            A 32-byte digest, suitable as an AES-256 key.
        """
        if isinstance(weights, np.ndarray):
            flat = weights.reshape(-1).astype(np.int8, copy=False)
        else:
            flat = np.fromiter((int(w) for w in weights), dtype=np.int8)

        if flat.size == 0:
            raise ValueError("cannot derive a key from an empty weight array")

        return hashlib.sha256(flat.tobytes()).digest()

    # ------------------------------------------------------------------
    # Encryption / decryption
    # ------------------------------------------------------------------
    def encrypt(
        self,
        plaintext: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        """Encrypt ``plaintext`` and return ``nonce || ciphertext || tag``.

        A fresh 12-byte nonce is drawn from ``os.urandom`` for every call;
        callers never need to manage nonces themselves.

        ``associated_data``, if supplied, is authenticated but not
        encrypted (the standard GCM "AAD" channel).  Phase 2 will use this
        for things like message sequence numbers.
        """
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("plaintext must be bytes")
        nonce = os.urandom(config.AES_NONCE_BYTES)
        # AESGCM.encrypt returns ciphertext || tag (tag is the last 16 bytes).
        ct_and_tag = self._aead.encrypt(nonce, bytes(plaintext), associated_data)
        return nonce + ct_and_tag

    def decrypt(
        self,
        bundle: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        """Inverse of :py:meth:`encrypt`.

        Raises ``cryptography.exceptions.InvalidTag`` if any byte of the
        bundle has been altered or if the supplied ``associated_data`` is
        wrong.  The exception is intentionally not caught here — Phase 4's
        IDS will rely on it being raised.
        """
        if not isinstance(bundle, (bytes, bytearray)):
            raise TypeError("bundle must be bytes")

        nonce_len = config.AES_NONCE_BYTES
        tag_len = config.AES_TAG_BYTES
        if len(bundle) < nonce_len + tag_len:
            raise ValueError(
                f"bundle too short: need at least {nonce_len + tag_len} bytes, "
                f"got {len(bundle)}"
            )

        nonce = bytes(bundle[:nonce_len])
        ct_and_tag = bytes(bundle[nonce_len:])
        # AESGCM.decrypt expects ciphertext || tag together.
        return self._aead.decrypt(nonce, ct_and_tag, associated_data)
