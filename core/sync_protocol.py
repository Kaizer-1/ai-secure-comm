"""Two-party Tree-Parity-Machine synchronisation, transport-pluggable.

Architecture
------------

    +--------------------+
    | TreeParityMachine  |   pure math: forward pass + weight update
    +--------------------+
            ^
            | owns one
    +--------------------+      uses one
    |   SyncSession      |  -------------->   +-------------------+
    | (per-side protocol |                    |  SyncTransport    |
    |  loop, role, RNG)  |                    |  (abstract)       |
    +--------------------+                    +-------------------+
                                                       ^   ^
                                                       |   |
                                            +----------+   +-----------+
                                            |                          |
                                  +-----------------+        +---------------------+
                                  | LoopbackTrans-  |        | (Phase 2)           |
                                  | port (in-proc   |        | SocketIOTransport   |
                                  | queues)         |        | etc.                |
                                  +-----------------+        +---------------------+

* `TreeParityMachine` is pure math and has no notion of peers or transports.
* `SyncSession` owns ONE TPM and ONE transport, plus a role
  (initiator / responder).  It runs the per-side protocol loop:
  handshake (seed agreement) → mutual-learning rounds → termination.
* `SyncTransport` is a tiny abstract base with primitive send/recv methods.
  The protocol is strictly turn-based, so concrete transports do not need
  message framing or type tags — call order on both sides is enough.

TPM update gate (preserved from Phase 1)
----------------------------------------
Weight updates apply only when the local and remote tau agree, and within
that, only to hidden units whose sigma equals tau.  See
``TreeParityMachine.update_weights``.  Splitting the protocol across a
network must not erode this gate.

Backwards compatibility
-----------------------
The Phase 1 surface ``SyncProtocol(tpm_a, tpm_b, …).synchronize()`` still
works: it builds a paired :class:`LoopbackTransport`, creates two
:class:`SyncSession` instances, runs them on background threads, and
returns the same :class:`SyncResult` dataclass.  Existing tests and
``demo_phase1.py`` are unmodified.
"""

from __future__ import annotations

import logging
import queue
import secrets
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass

import numpy as np

import config
from .tpm import TreeParityMachine


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result + exception types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SyncResult:
    """Outcome of a synchronisation attempt — same shape as Phase 1.

    Attributes
    ----------
    success:
        ``True`` iff the two TPMs reached identical weight fingerprints
        within ``max_rounds``.
    rounds:
        Number of mutual-learning rounds executed.  ``0`` is reserved for
        the "already synchronised" early-exit path of the convenience
        wrapper.
    elapsed_seconds:
        Wall-clock time the loop took, measured with ``time.perf_counter``.
    final_fingerprint:
        SHA-256 hex digest of the weights at termination.  When
        ``success`` is ``True`` both sides hold this same fingerprint.
    """

    success: bool
    rounds: int
    elapsed_seconds: float
    final_fingerprint: str


class TransportTimeout(Exception):
    """Raised by ``SyncTransport.recv_*`` when the peer is silent too long."""


# ---------------------------------------------------------------------------
# Transport: abstract base + in-process loopback implementation
# ---------------------------------------------------------------------------


# Role identifiers used by :class:`SyncSession`.
INITIATOR = "initiator"
RESPONDER = "responder"


class SyncTransport(ABC):
    """Abstract bidirectional message transport for one TPM session.

    A concrete transport carries one peer's worth of traffic.  The
    protocol is strictly turn-based, so transports do not need to frame
    or type-tag messages — call ordering on both sides is enough.

    All ``recv_*`` methods may raise :class:`TransportTimeout` to signal
    that the peer has fallen silent.  :class:`SyncSession` catches this
    and returns a failed :class:`SyncResult` rather than hanging.
    """

    @abstractmethod
    def send_tau(self, tau: int) -> None: ...

    @abstractmethod
    def recv_tau(self) -> int: ...

    @abstractmethod
    def send_fingerprint(self, fp: bytes) -> None: ...

    @abstractmethod
    def recv_fingerprint(self) -> bytes: ...

    @abstractmethod
    def exchange_seed(self, local_seed: int) -> int:
        """Agree on the shared input-generation seed during the handshake.

        Implementations may choose any rule both sides agree on
        (first-writer-wins, XOR, propagate-initiator).  The returned
        ``int`` MUST be identical on both sides.
        """
        ...

    @abstractmethod
    def close(self) -> None: ...


class LoopbackTransport(SyncTransport):
    """In-process transport using a pair of FIFO queues.

    Two paired transports are constructed via :func:`make_loopback_pair`.
    Each transport's *send queue* is the other's *recv queue*, so a
    message written by one side appears for the other side to read.

    Parameters
    ----------
    send_queue:
        Queue that *this* side writes into (the peer reads from it).
    recv_queue:
        Queue that *this* side reads from (the peer writes into it).
    recv_timeout:
        Maximum seconds a ``recv_*`` call will wait before raising
        :class:`TransportTimeout`.  Bounds test runtime if a session
        gets wedged.

    Notes
    -----
    Each enqueued item is a ``(kind, value)`` tuple where ``kind`` is one
    of ``"tau"``, ``"fp"``, or ``"seed"``.  The kind tag is *only* used
    as a sanity check that both sides are in step; if a recv sees an
    unexpected kind it raises ``RuntimeError``, which makes protocol
    bugs surface early.
    """

    def __init__(
        self,
        send_queue: "queue.Queue[tuple[str, object]]",
        recv_queue: "queue.Queue[tuple[str, object]]",
        recv_timeout: float = 5.0,
    ) -> None:
        self._send_queue = send_queue
        self._recv_queue = recv_queue
        self._recv_timeout = float(recv_timeout)
        self._closed = False

    # -- send/recv tau ----------------------------------------------------
    def send_tau(self, tau: int) -> None:
        self._send_queue.put(("tau", int(tau)))

    def recv_tau(self) -> int:
        _, value = self._recv_typed("tau")
        return int(value)  # type: ignore[arg-type]

    # -- send/recv fingerprint -------------------------------------------
    def send_fingerprint(self, fp: bytes) -> None:
        self._send_queue.put(("fp", bytes(fp)))

    def recv_fingerprint(self) -> bytes:
        _, value = self._recv_typed("fp")
        return bytes(value)  # type: ignore[arg-type]

    # -- handshake -------------------------------------------------------
    def exchange_seed(self, local_seed: int) -> int:
        """Symmetric XOR seed agreement.

        Both sides put their local seed; both read the other's; both
        return ``local ^ remote``.  When the responder passes ``0`` the
        agreed seed is exactly the initiator's seed (Phase-1 semantics
        for the existing test fixtures).
        """
        self._send_queue.put(("seed", int(local_seed)))
        _, peer_seed = self._recv_typed("seed")
        return int(local_seed) ^ int(peer_seed)  # type: ignore[arg-type]

    def close(self) -> None:
        self._closed = True

    # -- helpers ---------------------------------------------------------
    def _recv_typed(self, expected: str) -> tuple[str, object]:
        try:
            kind, value = self._recv_queue.get(timeout=self._recv_timeout)
        except queue.Empty as exc:
            raise TransportTimeout(
                f"timed out waiting for {expected!r} after "
                f"{self._recv_timeout:g}s"
            ) from exc
        if kind != expected:
            raise RuntimeError(
                f"transport protocol error: expected {expected!r}, got {kind!r}"
            )
        return kind, value


def make_loopback_pair(
    recv_timeout: float = 5.0,
) -> tuple[LoopbackTransport, LoopbackTransport]:
    """Build two paired :class:`LoopbackTransport` instances.

    The first transport's send queue is the second's recv queue, and
    vice versa.  Hand one to each :class:`SyncSession`.
    """
    q_ab: "queue.Queue[tuple[str, object]]" = queue.Queue()
    q_ba: "queue.Queue[tuple[str, object]]" = queue.Queue()
    t_a = LoopbackTransport(send_queue=q_ab, recv_queue=q_ba,
                            recv_timeout=recv_timeout)
    t_b = LoopbackTransport(send_queue=q_ba, recv_queue=q_ab,
                            recv_timeout=recv_timeout)
    return t_a, t_b


# ---------------------------------------------------------------------------
# Per-side session
# ---------------------------------------------------------------------------


class SyncSession:
    """One side of a TPM mutual-learning protocol.

    Owns a single :class:`TreeParityMachine` and a single
    :class:`SyncTransport`.  Drives the handshake and the per-round loop;
    decides termination by two-party fingerprint agreement.

    Parameters
    ----------
    tpm:
        The local TPM.  This side's secret weights live here.
    transport:
        The :class:`SyncTransport` used to talk to the peer.
    role:
        ``INITIATOR`` or ``RESPONDER``.  Affects only the default value
        of ``local_seed`` (initiator picks a fresh random seed if none
        is given; responder defaults to ``0`` so the initiator's seed
        wins under XOR agreement).  Both roles run identical loops.
    max_rounds:
        Hard upper bound on rounds before declaring failure.
    log_every:
        Emit a debug-level progress line every this many rounds.
        ``0`` disables periodic logging.
    learning_rule:
        Passed through to :py:meth:`TreeParityMachine.update_weights`.
    local_seed:
        This side's contribution to the shared input-generation seed.
        Pass ``None`` to use a fresh OS entropy seed (initiator only;
        responder defaults to ``0``).
    fingerprint_check_every:
        How often to exchange fingerprints (in rounds).  ``1`` means
        every round (Phase 1 behaviour).  Phase 2 networking can
        increase this to reduce wire chatter.
    """

    def __init__(
        self,
        tpm: TreeParityMachine,
        transport: SyncTransport,
        role: str = INITIATOR,
        max_rounds: int = config.TPM_SYNC_MAX_ROUNDS,
        log_every: int = config.TPM_SYNC_LOG_EVERY,
        learning_rule: str = config.TPM_DEFAULT_LEARNING_RULE,
        local_seed: int | None = None,
        fingerprint_check_every: int = 1,
    ) -> None:
        if role not in (INITIATOR, RESPONDER):
            raise ValueError(
                f"role must be {INITIATOR!r} or {RESPONDER!r}, got {role!r}"
            )
        if max_rounds < 1:
            raise ValueError("max_rounds must be >= 1")
        if fingerprint_check_every < 1:
            raise ValueError("fingerprint_check_every must be >= 1")

        self.tpm = tpm
        self.transport = transport
        self.role = role
        self.max_rounds = int(max_rounds)
        self.log_every = int(log_every) if log_every else 0
        self.learning_rule = learning_rule
        self.fingerprint_check_every = int(fingerprint_check_every)

        if local_seed is None:
            # Initiator picks an entropy seed; responder contributes 0 so
            # the agreed seed (XOR) is exactly the initiator's value.
            local_seed = secrets.randbits(64) if role == INITIATOR else 0
        self._local_seed = int(local_seed)

    # ------------------------------------------------------------------
    def synchronize(self) -> SyncResult:
        """Run the full per-side protocol: handshake → rounds → terminate."""
        start = time.perf_counter()

        # --- Handshake -------------------------------------------------
        try:
            agreed_seed = self.transport.exchange_seed(self._local_seed)
        except TransportTimeout:
            elapsed = time.perf_counter() - start
            logger.warning("handshake timed out (role=%s)", self.role)
            return SyncResult(
                success=False, rounds=0,
                elapsed_seconds=elapsed,
                final_fingerprint=self.tpm.weight_fingerprint(),
            )

        rng = np.random.default_rng(agreed_seed)

        # --- Round loop ------------------------------------------------
        for round_idx in range(1, self.max_rounds + 1):
            inputs = self.tpm.generate_random_inputs(rng=rng)
            local_tau, _ = self.tpm.compute_output(inputs)

            try:
                self.transport.send_tau(local_tau)
                remote_tau = self.transport.recv_tau()
            except TransportTimeout:
                return self._timeout_result(
                    start, round_idx, "tau exchange",
                    self.tpm.weight_fingerprint(),
                )

            # TPM update gate, preserved exactly: only when taus agree.
            # `update_weights` itself further restricts updates to hidden
            # units whose sigma == tau.
            if local_tau == remote_tau:
                self.tpm.update_weights(
                    inputs,
                    partner_output=remote_tau,
                    learning_rule=self.learning_rule,
                )

            # Periodic two-party fingerprint agreement.
            if round_idx % self.fingerprint_check_every == 0:
                local_fp = self.tpm.weight_fingerprint()
                local_fp_bytes = local_fp.encode("ascii")
                try:
                    self.transport.send_fingerprint(local_fp_bytes)
                    remote_fp_bytes = self.transport.recv_fingerprint()
                except TransportTimeout:
                    return self._timeout_result(
                        start, round_idx, "fingerprint exchange", local_fp,
                    )
                if local_fp_bytes == remote_fp_bytes:
                    elapsed = time.perf_counter() - start
                    logger.info(
                        "TPMs synchronised after %d rounds (%.4fs, role=%s)",
                        round_idx, elapsed, self.role,
                    )
                    return SyncResult(
                        success=True, rounds=round_idx,
                        elapsed_seconds=elapsed,
                        final_fingerprint=local_fp,
                    )

            if self.log_every and round_idx % self.log_every == 0:
                logger.debug(
                    "round=%d not yet synced (role=%s, fp=%s…)",
                    round_idx, self.role,
                    self.tpm.weight_fingerprint()[:8],
                )

        # --- Round budget exhausted -----------------------------------
        elapsed = time.perf_counter() - start
        logger.warning(
            "TPMs failed to synchronise within %d rounds (role=%s, %.4fs)",
            self.max_rounds, self.role, elapsed,
        )
        return SyncResult(
            success=False, rounds=self.max_rounds,
            elapsed_seconds=elapsed,
            final_fingerprint=self.tpm.weight_fingerprint(),
        )

    # ------------------------------------------------------------------
    def _timeout_result(
        self,
        start: float,
        round_idx: int,
        what: str,
        fingerprint: str,
    ) -> SyncResult:
        elapsed = time.perf_counter() - start
        logger.warning(
            "%s timed out at round %d (role=%s, %.4fs)",
            what, round_idx, self.role, elapsed,
        )
        return SyncResult(
            success=False, rounds=round_idx,
            elapsed_seconds=elapsed,
            final_fingerprint=fingerprint,
        )


# ---------------------------------------------------------------------------
# Phase 1 backwards-compat surface
# ---------------------------------------------------------------------------


# Used as the recv timeout for the in-process wrapper.  Generous because
# the test sync at K=3,N=10,L=3 finishes in tens of milliseconds; this
# value only fires if a session has truly wedged, not under normal load.
_LOOPBACK_RECV_TIMEOUT_S = 30.0


class SyncProtocol:
    """In-process two-party convenience wrapper (Phase 1 surface).

    Builds a paired :class:`LoopbackTransport`, creates one
    :class:`SyncSession` per TPM, and runs them on two background
    threads.  Returns a :class:`SyncResult` reflecting the converged
    state.

    Parameters mirror the Phase 1 signature for backwards compatibility,
    so existing tests and ``demo_phase1.py`` work unchanged.
    """

    def __init__(
        self,
        tpm_a: TreeParityMachine,
        tpm_b: TreeParityMachine,
        max_rounds: int = config.TPM_SYNC_MAX_ROUNDS,
        log_every: int = config.TPM_SYNC_LOG_EVERY,
        learning_rule: str = config.TPM_DEFAULT_LEARNING_RULE,
        seed: int | None = None,
    ) -> None:
        if (tpm_a.K, tpm_a.N, tpm_a.L) != (tpm_b.K, tpm_b.N, tpm_b.L):
            raise ValueError(
                "Both TPMs must share identical (K, N, L) parameters"
            )
        if max_rounds < 1:
            raise ValueError("max_rounds must be >= 1")

        self.tpm_a = tpm_a
        self.tpm_b = tpm_b
        self._max_rounds = int(max_rounds)
        self._log_every = int(log_every) if log_every else 0
        self._learning_rule = learning_rule
        self._seed = seed

    def synchronize(self) -> SyncResult:
        start = time.perf_counter()

        # Phase 1 fast-path: TPMs already agree (e.g. tests that
        # constructed both with the same RNG seed).  Return rounds=0
        # without spinning threads.
        if self.tpm_a.weight_fingerprint() == self.tpm_b.weight_fingerprint():
            elapsed = time.perf_counter() - start
            return SyncResult(
                success=True, rounds=0,
                elapsed_seconds=elapsed,
                final_fingerprint=self.tpm_a.weight_fingerprint(),
            )

        t_a, t_b = make_loopback_pair(recv_timeout=_LOOPBACK_RECV_TIMEOUT_S)

        sess_a = SyncSession(
            tpm=self.tpm_a, transport=t_a, role=INITIATOR,
            max_rounds=self._max_rounds, log_every=self._log_every,
            learning_rule=self._learning_rule,
            local_seed=self._seed,
        )
        sess_b = SyncSession(
            tpm=self.tpm_b, transport=t_b, role=RESPONDER,
            max_rounds=self._max_rounds, log_every=self._log_every,
            learning_rule=self._learning_rule,
            # Responder contributes 0 so the agreed seed (XOR) is
            # exactly the initiator's `seed` argument — preserving
            # Phase-1 reproducibility for existing tests.
            local_seed=0,
        )

        results: list[SyncResult | None] = [None, None]

        def _run(idx: int, sess: SyncSession) -> None:
            try:
                results[idx] = sess.synchronize()
            except Exception:  # noqa: BLE001  (defensive; thread-safety net)
                logger.exception("session %d crashed", idx)
                results[idx] = SyncResult(
                    success=False, rounds=0, elapsed_seconds=0.0,
                    final_fingerprint=sess.tpm.weight_fingerprint(),
                )

        threads = [
            threading.Thread(target=_run, args=(0, sess_a), name="sync-a"),
            threading.Thread(target=_run, args=(1, sess_b), name="sync-b"),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        elapsed = time.perf_counter() - start
        ra, rb = results
        if ra is None or rb is None:
            return SyncResult(
                success=False, rounds=self._max_rounds,
                elapsed_seconds=elapsed,
                final_fingerprint=self.tpm_a.weight_fingerprint(),
            )

        success = ra.success and rb.success
        # On a clean run both sides terminate at the same round.  Take
        # the max as a defensive choice if they differ for any reason.
        rounds = max(ra.rounds, rb.rounds)
        fingerprint = (
            ra.final_fingerprint if success
            else self.tpm_a.weight_fingerprint()
        )
        return SyncResult(
            success=success, rounds=rounds,
            elapsed_seconds=elapsed,
            final_fingerprint=fingerprint,
        )
