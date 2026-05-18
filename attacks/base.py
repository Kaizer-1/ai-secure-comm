"""Attack ABC and per-transport AttackRegistry.

This is the contract every Phase 3 attack simulator implements.  An
`Attack` is plugged into a `TCPTransport` via an `AttackRegistry`;
the transport calls the registry once per outbound and once per
inbound frame, and the registry walks every active attack's hooks
in registration order.

Design notes
------------

* The registry is **per-transport**, not a process-global singleton.
  The training-data generator runs alice and bob in the same process
  on different threads — a global registry would cause an attack
  registered on alice's side to also fire on bob's outbound, which
  would silently break session labelling.  The live `app.py` has one
  `TCPTransport` per process, so this is invisible to it.

* Hooks return ``Optional[Tuple[int, bytes]]``:
    - ``(kind, payload)`` (possibly modified)  — frame is sent / delivered
    - ``None``                                   — frame is dropped

* The transport short-circuits the entire registry call when the
  registry has no active attacks, so the no-attack path is essentially
  zero-cost (one attribute read + one ``if not attacks:`` check).

* Sync-phase frames (TAU/FINGERPRINT/SEED) MUST pass through any
  realistic attack untouched — the simulators model post-handshake
  adversaries, not someone capable of breaking neural-key agreement.
  Each `Attack` subclass enforces this in its own hook bodies; the
  registry itself is policy-free.

* Replay-style attacks need to *inject* additional frames (not just
  modify the current one).  They do that via the transport reference
  passed to `attach()`, by calling `transport._send_frame(...)`
  directly on a background thread.  The hook return value is only
  for "modify or drop the current frame".
"""

from __future__ import annotations

import logging
import threading
from abc import ABC, abstractmethod
from typing import Any, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Frame-shape alias: every hook works on (kind, payload).
Frame = Tuple[int, bytes]
HookResult = Optional[Frame]


class Attack(ABC):
    """One attack scenario (MITM, Replay, ...).

    Subclasses set the ``name`` class attribute and implement the
    two hooks.  A subclass that needs to inject additional frames
    (Replay does) should override `attach`/`detach` to remember the
    transport reference and start/stop a background thread.

    Lifecycle:

        attack = MITMAttack(...)
        registry.register(attack)        # calls attack.attach(transport)
        attack.start()                   # is_active() now True
        ...                              # transport calls hooks
        attack.stop()                    # hooks are still called but
                                         # the subclass should no-op
        registry.unregister(attack)      # calls attack.detach()
    """

    #: Short identifier used in the demo UI and the training-data label.
    name: str = "unknown"

    def __init__(self) -> None:
        self._active = False
        self._stats_lock = threading.Lock()

    # -- lifecycle -------------------------------------------------------
    def start(self) -> None:
        """Mark the attack active.  Subclasses can override to spin up
        background threads, but should always call ``super().start()``."""
        self._active = True

    def stop(self) -> None:
        """Mark the attack inactive.  Background threads (if any) should
        wind down.  Always call ``super().stop()``."""
        self._active = False

    def is_active(self) -> bool:
        return self._active

    def attach(self, transport: Any) -> None:
        """Called by `AttackRegistry.register`.  Default is no-op.

        Override if the attack needs to inject frames (e.g. Replay).
        Pass-through of `Any` for `transport` keeps the dependency
        loose — attacks should only use `_send_frame` and the public
        send_chat etc. helpers, never reach into internals.
        """

    def detach(self) -> None:
        """Called by `AttackRegistry.unregister`.  Default is no-op."""

    # -- hooks (subclasses override) ------------------------------------
    @abstractmethod
    def on_outbound_frame(self, kind: int, payload: bytes) -> HookResult:
        """Called for every frame about to leave the local socket.

        Return the (possibly mutated) ``(kind, payload)`` tuple to
        send, or ``None`` to drop the frame.  Returning the input
        tuple unchanged is the no-op behaviour subclasses use when
        the attack is inactive or the frame doesn't match the
        attack's targeting rules (e.g. a sync-phase frame).
        """

    @abstractmethod
    def on_inbound_frame(self, kind: int, payload: bytes) -> HookResult:
        """Called for every frame just deserialised from the socket.

        Same return contract as `on_outbound_frame`.  Most simulators
        only act on outbound (because they model what an in-process
        attacker can do to its own egress traffic), so the inbound
        hook is typically a pass-through.
        """

    # -- stats (subclasses extend) --------------------------------------
    def get_stats(self) -> dict:
        """Counters and runtime info exposed to the demo UI."""
        return {"name": self.name, "active": self.is_active()}


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class AttackRegistry:
    """Per-transport registry of `Attack` instances.

    The transport calls `apply_outbound` / `apply_inbound` on every
    frame.  When no attacks are registered, both methods short-circuit
    immediately so the non-attacker code path stays cheap.
    """

    def __init__(self, transport: Any = None) -> None:
        self._transport = transport
        self._attacks: List[Attack] = []
        self._lock = threading.RLock()

    # -- registration ---------------------------------------------------
    def register(self, attack: Attack) -> None:
        """Add `attack` to the registry.  Calls ``attack.attach(transport)``
        with the transport this registry is bound to (if any)."""
        with self._lock:
            if attack in self._attacks:
                return
            self._attacks.append(attack)
        try:
            attack.attach(self._transport)
        except Exception:  # noqa: BLE001
            logger.exception("attack.attach raised; continuing anyway")

    def unregister(self, attack: Attack) -> None:
        """Remove `attack` from the registry.  Stops it first, then
        calls `attack.detach()`."""
        with self._lock:
            if attack not in self._attacks:
                return
            self._attacks.remove(attack)
        try:
            if attack.is_active():
                attack.stop()
        except Exception:  # noqa: BLE001
            logger.exception("attack.stop raised; continuing anyway")
        try:
            attack.detach()
        except Exception:  # noqa: BLE001
            logger.exception("attack.detach raised; continuing anyway")

    def attached_transport(self) -> Any:
        return self._transport

    def attach_transport(self, transport: Any) -> None:
        """Late-bind the transport (used when registry is created
        before the transport is connected)."""
        with self._lock:
            self._transport = transport
            for attack in list(self._attacks):
                try:
                    attack.attach(transport)
                except Exception:  # noqa: BLE001
                    logger.exception("attack.attach raised; continuing anyway")

    # -- queries --------------------------------------------------------
    def all_attacks(self) -> List[Attack]:
        with self._lock:
            return list(self._attacks)

    def active_attacks(self) -> List[Attack]:
        with self._lock:
            return [a for a in self._attacks if a.is_active()]

    def __len__(self) -> int:
        with self._lock:
            return len(self._attacks)

    # -- hooks called by the transport ----------------------------------
    def apply_outbound(self, kind: int, payload: bytes) -> HookResult:
        """Walk every active attack's `on_outbound_frame` in order.

        Each hook sees the output of the previous one.  The first
        hook to return ``None`` short-circuits the chain — the frame
        is dropped.  Returning the (possibly modified) tuple from any
        hook continues the chain.
        """
        attacks = self.active_attacks()
        if not attacks:
            return (kind, payload)
        for attack in attacks:
            try:
                result = attack.on_outbound_frame(kind, payload)
            except Exception:  # noqa: BLE001
                logger.exception(
                    "attack %r outbound hook raised; treating as no-op",
                    attack.name,
                )
                continue
            if result is None:
                return None
            kind, payload = result
        return (kind, payload)

    def apply_inbound(self, kind: int, payload: bytes) -> HookResult:
        """Symmetric to `apply_outbound` for received frames."""
        attacks = self.active_attacks()
        if not attacks:
            return (kind, payload)
        for attack in attacks:
            try:
                result = attack.on_inbound_frame(kind, payload)
            except Exception:  # noqa: BLE001
                logger.exception(
                    "attack %r inbound hook raised; treating as no-op",
                    attack.name,
                )
                continue
            if result is None:
                return None
            kind, payload = result
        return (kind, payload)
