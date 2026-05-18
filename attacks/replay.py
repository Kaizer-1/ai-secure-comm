"""Replay simulator: re-injects buffered CHAT frames at a fixed cadence.

What it models
--------------
A network-level adversary that captures legitimate ciphertext as it
goes by and re-sends it later.  AES-GCM nonces are random, so the
captured ciphertext is still valid under the session key — the
receiver decrypts it successfully and shows a duplicate chat
message.  The IDS should learn to flag duplicate-payload patterns
and the abnormally-regular inter-arrival timing introduced by the
periodic replay thread.

Mechanism
---------
* On every outbound CHAT frame, push the payload into a bounded
  FIFO buffer (`config.REPLAY_BUFFER_SIZE` slots).
* While active, a daemon thread wakes every `interval_s` seconds
  and re-injects one randomly-chosen buffered frame on the same
  transport via ``transport._send_frame(KIND_CHAT, payload)``.
* Re-injected frames go through the registry's outbound hooks too.
  Each `Attack` is responsible for not getting confused by its own
  output; this attack handles it by checking if the payload is one
  it just injected (tracked via `_recently_injected`).
"""

from __future__ import annotations

import random
import threading
import time
from collections import deque
from typing import Any, Deque, List, Optional

import config
from core.transport_tcp import KIND_CHAT
from .base import Attack, HookResult


_TARGET_KINDS = frozenset({KIND_CHAT})


class ReplayAttack(Attack):
    """Captures CHAT frames into a buffer and re-injects them periodically.

    Parameters
    ----------
    buffer_size:
        How many recent CHAT frames to keep eligible for replay.
        Older entries are evicted FIFO.  Defaults to
        ``config.REPLAY_BUFFER_SIZE``.
    interval_s:
        Seconds between replay injections while active.  Defaults to
        ``config.REPLAY_INTERVAL_S``.
    rng_seed:
        Seed for reproducible buffer selection in tests.  ``None``
        uses OS entropy.
    """

    name = "replay"

    def __init__(
        self,
        buffer_size: int = config.REPLAY_BUFFER_SIZE,
        interval_s: float = config.REPLAY_INTERVAL_S,
        rng_seed: Optional[int] = None,
    ) -> None:
        super().__init__()
        if buffer_size < 1:
            raise ValueError("buffer_size must be >= 1")
        if interval_s <= 0:
            raise ValueError("interval_s must be > 0")
        self.buffer_size = int(buffer_size)
        self.interval_s = float(interval_s)
        self._rng = random.Random(rng_seed)

        # Bounded FIFO of (kind, payload) tuples eligible for replay.
        self._buffer: Deque[bytes] = deque(maxlen=self.buffer_size)
        self._buffer_lock = threading.Lock()

        # Set of payload bytes we just re-injected — so we don't loop
        # by re-buffering our own output.  Trimmed each interval.
        self._recently_injected: set[bytes] = set()
        self._recently_injected_lock = threading.Lock()

        # Background injector thread + control event.
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._transport: Any = None

        # Stats
        self._frames_buffered = 0
        self._frames_replayed = 0
        self._replay_intervals_ms: List[int] = []
        self._last_replay_time: Optional[float] = None

    # -- lifecycle ------------------------------------------------------
    def attach(self, transport: Any) -> None:
        self._transport = transport

    def detach(self) -> None:
        self._transport = None

    def start(self) -> None:
        super().start()
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._injector_loop,
            name="replay-injector",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        super().stop()
        self._stop_event.set()
        thread = self._thread
        self._thread = None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2 * self.interval_s + 1.0)

    # -- hooks ----------------------------------------------------------
    def on_outbound_frame(self, kind: int, payload: bytes) -> HookResult:
        if not self.is_active() or kind not in _TARGET_KINDS:
            return (kind, payload)

        # Don't re-buffer our own re-injections — that would create a
        # feedback loop where one captured frame keeps looping
        # forever.
        with self._recently_injected_lock:
            is_self_injected = payload in self._recently_injected

        if not is_self_injected:
            with self._buffer_lock:
                self._buffer.append(payload)
            with self._stats_lock:
                self._frames_buffered += 1
        return (kind, payload)

    def on_inbound_frame(self, kind: int, payload: bytes) -> HookResult:
        # Replay is asymmetric: lives on the attacker's side and only
        # touches that side's outbound traffic.
        return (kind, payload)

    # -- background injector --------------------------------------------
    def _injector_loop(self) -> None:
        while not self._stop_event.is_set():
            # Sleep first so we never inject before any frame has
            # been captured (avoids a startup race in tests).
            if self._stop_event.wait(timeout=self.interval_s):
                return

            transport = self._transport
            if transport is None:
                continue

            with self._buffer_lock:
                if not self._buffer:
                    continue
                # Pick a random eligible frame; tuple-list snapshot
                # keeps the choice safe against concurrent appends.
                eligible = list(self._buffer)
            payload = self._rng.choice(eligible)

            # Mark as self-injected before sending so the outbound
            # hook (which fires on the inject) doesn't re-buffer it.
            with self._recently_injected_lock:
                self._recently_injected.add(payload)
            try:
                # Send via the transport's framing layer so the bytes
                # land identically to a real outbound frame.
                transport._send_frame(KIND_CHAT, payload)
            except Exception:  # noqa: BLE001
                # Transport may have been closed underneath us; just
                # exit the loop quietly.
                return
            finally:
                with self._recently_injected_lock:
                    self._recently_injected.discard(payload)

            now = time.time()
            with self._stats_lock:
                self._frames_replayed += 1
                if self._last_replay_time is not None:
                    self._replay_intervals_ms.append(
                        int((now - self._last_replay_time) * 1000)
                    )
                self._last_replay_time = now

    # -- stats ----------------------------------------------------------
    def get_stats(self) -> dict:
        with self._stats_lock:
            buffered = self._frames_buffered
            replayed = self._frames_replayed
            intervals = list(self._replay_intervals_ms)
        with self._buffer_lock:
            buf_len = len(self._buffer)
        base = super().get_stats()
        base.update({
            "frames_buffered": buffered,
            "frames_replayed": replayed,
            "buffer_occupancy": buf_len,
            "replay_intervals_ms": intervals,
            "interval_s": self.interval_s,
        })
        return base
