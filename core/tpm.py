"""Tree Parity Machine (TPM) — neural cryptography primitive.

A Tree Parity Machine is a feed-forward neural network with a very
restricted topology, used by the Kanter–Kinzel–Kanter neural-key-exchange
protocol.  Two TPMs that start with random secret weights and observe the
same public input vectors can synchronise their weights through repeated
mutual learning, yielding a shared secret without any explicit key
exchange.  An attacker that only sees the public inputs and outputs cannot
synchronise nearly as quickly, which is the basis of the protocol's
(empirical) security.

Network shape
-------------
                       tau  (network output, ±1)
                        ^
                        |  (product of sigmas)
                        |
            +-----------+-----------+
            |           |           |
         sigma_1     sigma_2     sigma_K       <-- K hidden perceptrons
          ^            ^             ^
          |            |             |
       N inputs     N inputs     N inputs       <-- each gets its own slice
       weights      weights      weights        <-- integers in [-L, L]

Each hidden perceptron `i` receives an `N`-vector of ±1 inputs and an
`N`-vector of integer weights.  It outputs::

    h_i     = sum_j w_{i,j} * x_{i,j}
    sigma_i = sign(h_i)        # with sign(0) := -1 by convention

The whole network outputs::

    tau = sigma_1 * sigma_2 * ... * sigma_K     (a single ±1)

Learning
--------
Two TPMs A and B exchange `tau_A` and `tau_B` after each input.  Updates
happen *only* when `tau_A == tau_B`, and even then a hidden unit's weights
are updated only if its own sigma equals tau.  Three learning rules are in
common use; this module implements all three:

- **Hebbian**:        ``w += sigma_i * tau * x``
- **anti-Hebbian**:   ``w -= sigma_i * tau * x``
- **Random walk**:    ``w += x``           (regardless of sigma_i, tau)

After every update each weight is clipped back into ``[-L, L]``.

Design notes for this implementation
------------------------------------
* Weights are stored as a NumPy ``int8`` array of shape ``(K, N)`` because
  ``L`` is small.  The integer dtype keeps fingerprints reproducible.
* ``sign(0)`` is defined as ``-1`` (the standard convention for TPMs;
  NumPy's ``np.sign`` returns 0 on zero, which we explicitly remap).
* The class owns its own ``numpy.random.Generator`` so weight initialisation
  is deterministic when a seed is supplied.
"""

from __future__ import annotations

import hashlib
from typing import Tuple

import numpy as np


_VALID_LEARNING_RULES = ("hebbian", "anti_hebbian", "random_walk")


class TreeParityMachine:
    """A configurable Tree Parity Machine.

    Parameters
    ----------
    K:
        Number of hidden perceptrons.  Must be >= 1.
    N:
        Number of inputs feeding each hidden perceptron.  Must be >= 1.
    L:
        Weights are integers in the closed interval ``[-L, L]``.  Must be >= 1.
    rng:
        Optional ``numpy.random.Generator`` used to initialise the secret
        weights.  Pass a seeded generator for reproducible tests; pass
        ``None`` to draw fresh OS entropy.
    """

    def __init__(
        self,
        K: int,
        N: int,
        L: int,
        rng: np.random.Generator | None = None,
    ) -> None:
        if K < 1 or N < 1 or L < 1:
            raise ValueError("K, N and L must all be >= 1")

        self.K = int(K)
        self.N = int(N)
        self.L = int(L)
        self._rng = rng if rng is not None else np.random.default_rng()

        # Initial secret weights: uniform integers in [-L, L].
        self.weights: np.ndarray = self._rng.integers(
            low=-self.L, high=self.L + 1, size=(self.K, self.N), dtype=np.int8
        )

    # ------------------------------------------------------------------
    # Forward pass
    # ------------------------------------------------------------------
    def generate_random_inputs(
        self, rng: np.random.Generator | None = None
    ) -> np.ndarray:
        """Return a fresh ``(K, N)`` array of ±1 inputs.

        If ``rng`` is supplied it is used instead of ``self._rng``; this is
        what ``SyncProtocol`` uses to feed both TPMs the same public input
        each round.
        """
        gen = rng if rng is not None else self._rng
        # randint of {0,1} mapped to {-1, +1}.
        bits = gen.integers(0, 2, size=(self.K, self.N), dtype=np.int8)
        return (bits * 2 - 1).astype(np.int8)

    def compute_output(
        self, inputs: np.ndarray
    ) -> Tuple[int, np.ndarray]:
        """Forward pass.

        Parameters
        ----------
        inputs:
            A ``(K, N)`` array of ±1 values.

        Returns
        -------
        (tau, sigmas):
            ``tau`` is the single ±1 network output.  ``sigmas`` is the
            length-``K`` array of per-hidden-unit ±1 outputs.
        """
        self._validate_inputs(inputs)

        # Per-hidden-unit pre-activation, then sign with sign(0) := -1.
        h = np.einsum("ij,ij->i", self.weights.astype(np.int32), inputs.astype(np.int32))
        sigmas = np.where(h > 0, 1, -1).astype(np.int8)

        # Product of K signs is ±1; cast to plain Python int for ergonomics.
        tau = int(np.prod(sigmas))
        return tau, sigmas

    # ------------------------------------------------------------------
    # Learning
    # ------------------------------------------------------------------
    def update_weights(
        self,
        inputs: np.ndarray,
        partner_output: int,
        learning_rule: str = "hebbian",
    ) -> bool:
        """Apply one mutual-learning step.

        Updates happen only when the local network output equals
        ``partner_output``.  Within that, a hidden unit's weights are only
        modified if its own ``sigma`` matches the local ``tau`` (this is
        the standard TPM update gate).

        Parameters
        ----------
        inputs:
            The ``(K, N)`` ±1 input array used in the most recent
            ``compute_output`` call.
        partner_output:
            The other TPM's ``tau`` (±1).
        learning_rule:
            One of ``"hebbian"``, ``"anti_hebbian"``, ``"random_walk"``.

        Returns
        -------
        bool:
            ``True`` if any weight changed this step, ``False`` otherwise.
            (Useful for instrumentation; not required by the protocol.)
        """
        if learning_rule not in _VALID_LEARNING_RULES:
            raise ValueError(
                f"Unknown learning rule {learning_rule!r}; "
                f"expected one of {_VALID_LEARNING_RULES}"
            )
        if partner_output not in (-1, 1):
            raise ValueError("partner_output must be -1 or +1")
        self._validate_inputs(inputs)

        tau, sigmas = self.compute_output(inputs)
        if tau != partner_output:
            return False  # mutual-learning gate: no update this round

        before = self.weights.copy()
        # Only hidden units whose sigma agrees with tau get updated.
        gate = (sigmas == tau)  # shape (K,)
        if not np.any(gate):
            return False

        if learning_rule == "hebbian":
            # w_i += sigma_i * tau * x_i  ==> with sigma_i==tau the sign is +1
            delta = inputs.astype(np.int32) * (tau * sigmas)[:, None]
        elif learning_rule == "anti_hebbian":
            delta = -inputs.astype(np.int32) * (tau * sigmas)[:, None]
        else:  # "random_walk"
            delta = inputs.astype(np.int32)

        # Apply gate row-wise: only updated hidden units actually move.
        delta = delta * gate[:, None]

        new_weights = self.weights.astype(np.int32) + delta
        np.clip(new_weights, -self.L, self.L, out=new_weights)
        self.weights = new_weights.astype(np.int8)

        return not np.array_equal(before, self.weights)

    # ------------------------------------------------------------------
    # Export / fingerprint
    # ------------------------------------------------------------------
    def export_weights(self) -> np.ndarray:
        """Return weights as a 1-D ``int8`` array, ready for hashing."""
        return self.weights.reshape(-1).astype(np.int8, copy=True)

    def weight_fingerprint(self) -> str:
        """SHA-256 hex digest of the canonicalised weight bytes.

        Two TPMs are synchronised iff their fingerprints match — used by
        ``SyncProtocol`` as the cheap sync-check at every round.
        """
        return hashlib.sha256(self.export_weights().tobytes()).hexdigest()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _validate_inputs(self, inputs: np.ndarray) -> None:
        if inputs.shape != (self.K, self.N):
            raise ValueError(
                f"inputs shape {inputs.shape} does not match TPM ({self.K}, {self.N})"
            )
        # The protocol is defined for ±1 inputs only; reject anything else.
        unique = np.unique(inputs)
        if not np.all(np.isin(unique, (-1, 1))):
            raise ValueError("inputs must contain only -1 and +1 values")

    def __repr__(self) -> str:
        return (
            f"TreeParityMachine(K={self.K}, N={self.N}, L={self.L}, "
            f"fingerprint={self.weight_fingerprint()[:8]}…)"
        )
