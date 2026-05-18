"""MITM simulator: bit-flips a configurable fraction of CHAT frames.

Models a post-handshake adversary that has access to the wire (or
the local NIC, in our in-process simulation) and can mutate
ciphertext bytes in flight.  Sync-phase frames (TAU/FINGERPRINT/SEED)
are intentionally left alone — Tree Parity Machine sync's security
assumes a passive observer, and a tampering simulator that broke it
would just measure "AES-GCM still detects garbage", not what the IDS
is supposed to learn.

What the receiver sees
----------------------
A bit-flipped AES-GCM ciphertext fails authentication.  The receiver's
`crypto_engine.decrypt` raises `cryptography.exceptions.InvalidTag`,
which `PeerLink._handle_chat` catches and turns into an `on_error`
callback.  Phase 4's IDS will see this as an elevated
`decrypt_failure_rate` in the feature window.
"""

from __future__ import annotations

import os
import random
import threading
from typing import Optional

import config
from core.transport_tcp import KIND_CHAT
from .base import Attack, HookResult


# The MITM only targets app-phase CHAT traffic.  See the module
# docstring for why sync-phase frames are off-limits.
_TARGET_KINDS = frozenset({KIND_CHAT})


class MITMAttack(Attack):
    """Tampers ~`tamper_probability` of outbound CHAT frames in place.

    The attack is in-process and asymmetric: it lives on the
    *attacker's* side and only touches that side's outbound traffic.
    The peer has no special code path — it just receives bytes that
    fail GCM authentication.

    Parameters
    ----------
    tamper_probability:
        Probability in [0, 1] that any given outbound CHAT frame is
        mutated.  Defaults to ``config.MITM_TAMPER_PROBABILITY``.
    flip_bits_per_frame:
        Number of random bit positions to flip when a frame is
        targeted.  Default 1 — even a single flipped bit defeats
        AES-GCM authentication, so more is overkill for the IDS
        signal we want to produce.
    rng_seed:
        Seed for reproducible tampering decisions in tests.  Pass
        ``None`` for OS entropy in production.
    """

    name = "mitm"

    def __init__(
        self,
        tamper_probability: float = config.MITM_TAMPER_PROBABILITY,
        flip_bits_per_frame: int = 1,
        rng_seed: Optional[int] = None,
    ) -> None:
        super().__init__()
        if not 0.0 <= tamper_probability <= 1.0:
            raise ValueError("tamper_probability must be in [0, 1]")
        if flip_bits_per_frame < 1:
            raise ValueError("flip_bits_per_frame must be >= 1")
        self.tamper_probability = float(tamper_probability)
        self.flip_bits_per_frame = int(flip_bits_per_frame)
        self._rng = random.Random(rng_seed)

        # Stats
        self._frames_seen = 0
        self._frames_tampered = 0

    # -- hooks -----------------------------------------------------------
    def on_outbound_frame(self, kind: int, payload: bytes) -> HookResult:
        if not self.is_active() or kind not in _TARGET_KINDS:
            return (kind, payload)

        with self._stats_lock:
            self._frames_seen += 1

        if self._rng.random() >= self.tamper_probability:
            return (kind, payload)
        if not payload:
            # Empty payload — nothing to flip; count it as seen but
            # not tampered (an attacker can't mutate zero bytes).
            return (kind, payload)

        mutated = bytearray(payload)
        n = len(mutated) * 8
        for _ in range(self.flip_bits_per_frame):
            bit_index = self._rng.randrange(n)
            mutated[bit_index // 8] ^= 1 << (bit_index % 8)

        with self._stats_lock:
            self._frames_tampered += 1
        return (kind, bytes(mutated))

    def on_inbound_frame(self, kind: int, payload: bytes) -> HookResult:
        # MITM is asymmetric — it only touches its own side's egress.
        return (kind, payload)

    # -- stats -----------------------------------------------------------
    def get_stats(self) -> dict:
        with self._stats_lock:
            seen = self._frames_seen
            tampered = self._frames_tampered
        base = super().get_stats()
        base.update({
            "frames_seen": seen,
            "frames_tampered": tampered,
            "tamper_probability": self.tamper_probability,
        })
        return base
