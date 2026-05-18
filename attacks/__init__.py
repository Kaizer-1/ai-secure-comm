"""Phase 3 attack simulators.

`Attack` is the ABC every simulator implements; `AttackRegistry` is
the per-transport plug-in point that the TCP transport calls into.

Live simulators:
    - `MITMAttack`   — bit-flips a configurable percentage of CHAT
                       frames after sync completes.
    - `ReplayAttack` — re-injects buffered CHAT frames at a fixed
                       interval, mimicking a network-level replay.
"""

from .base import Attack, AttackRegistry, Frame, HookResult
from .mitm import MITMAttack
from .replay import ReplayAttack

__all__ = [
    "Attack",
    "AttackRegistry",
    "Frame",
    "HookResult",
    "MITMAttack",
    "ReplayAttack",
]
