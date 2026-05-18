"""Sliding-window feature extractor for the Phase-4 IDS.

`FeatureExtractor` is the bridge between the live `PeerLink` (and the
Phase-3 training-data generator) and the Phase-4 Random Forest
classifier.  It accumulates per-frame metadata into a bounded ring
buffer and on demand emits a fixed-shape numeric `dict` of features
that captures three kinds of signal:

* **Volume / cadence**:  ``mean_inter_arrival_ms``,
  ``std_inter_arrival_ms``, ``frame_rate_per_second``.
* **Payload shape**:     ``mean_payload_size``, ``std_payload_size``.
* **Anomaly hints**:     ``decrypt_failure_rate``,
  ``duplicate_payload_count`` — the two main signals MITM and Replay
  attacks introduce respectively.
* **Composition**:       ``chat_frame_fraction``,
  ``file_frame_fraction``, ``control_frame_fraction``.

The names + dtype shape here become the column headers of the
training CSV (`data/training_data.csv`) and the feature names of the
Phase-4 model.  Once that file exists, do not rename a feature
without retraining.

Decrypt success / failure
-------------------------
PeerLink records ``decrypt_success=True`` after a successful AES-GCM
decrypt, ``False`` after `InvalidTag`, and ``None`` for outbound
frames (which the local side encrypts and never decrypts).  The
failure-rate metric only counts frames where ``decrypt_success`` is
not None — i.e. inbound app-phase frames the receiver tried to
authenticate.
"""

from __future__ import annotations

import statistics
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional

import config
from core.transport_tcp import (
    KIND_CHAT,
    KIND_CONTROL,
    KIND_FILE_CHUNK,
    KIND_FILE_META,
)


# Frame-kind groupings the extractor reports composition fractions for.
_CHAT_KINDS = frozenset({KIND_CHAT})
_FILE_KINDS = frozenset({KIND_FILE_CHUNK, KIND_FILE_META})
_CONTROL_KINDS = frozenset({KIND_CONTROL})


@dataclass(frozen=True)
class FrameRecord:
    """One observation appended to the extractor's sliding window."""
    timestamp: float          # `time.time()` at observation
    kind: int                 # transport_tcp.KIND_* constant
    size: int                 # bytes on the wire (post-attack payload size)
    direction: str            # "in" or "out"
    decrypt_success: Optional[bool] = None  # only set for inbound CHAT/FILE_*
    payload_hash: Optional[bytes] = None    # short hash for duplicate detection


# Canonical feature schema — exposed so consumers (CSV writer, future
# model) can ask for the ordered key list without instantiating an
# extractor.
FEATURE_NAMES: List[str] = [
    "mean_inter_arrival_ms",
    "std_inter_arrival_ms",
    "mean_payload_size",
    "std_payload_size",
    "decrypt_failure_rate",
    "duplicate_payload_count",
    "frame_rate_per_second",
    "chat_frame_fraction",
    "file_frame_fraction",
    "control_frame_fraction",
]


def _empty_features() -> Dict[str, float]:
    """Zero-valued feature dict — emitted when the window is empty."""
    return {name: 0.0 for name in FEATURE_NAMES}


class FeatureExtractor:
    """Append-and-summarise sliding window.

    Thread-safe — the same extractor is written to from `PeerLink`'s
    reader thread and the chat/file send paths.

    Parameters
    ----------
    window_size:
        Maximum number of frames retained.  Older entries fall off
        the back as new ones arrive.  Defaults to
        ``config.FEATURE_WINDOW_SIZE``.
    """

    def __init__(self, window_size: int = config.FEATURE_WINDOW_SIZE) -> None:
        if window_size < 1:
            raise ValueError("window_size must be >= 1")
        self.window_size = int(window_size)
        self._window: Deque[FrameRecord] = deque(maxlen=self.window_size)
        self._lock = threading.Lock()
        # Cumulative count, never reset — useful for "fire callback
        # every N frames" logic in the calling layer.
        self._total_observed = 0

    # -- ingest ---------------------------------------------------------
    def record(
        self,
        *,
        kind: int,
        size: int,
        direction: str,
        decrypt_success: Optional[bool] = None,
        payload_hash: Optional[bytes] = None,
        timestamp: Optional[float] = None,
    ) -> int:
        """Append one frame observation.  Returns the cumulative count.

        The cumulative count is what the caller checks against
        ``config.FEATURE_UPDATE_EVERY`` to decide when to extract +
        emit features.
        """
        if direction not in ("in", "out"):
            raise ValueError(f"direction must be 'in' or 'out'; got {direction!r}")
        ts = time.time() if timestamp is None else float(timestamp)
        rec = FrameRecord(
            timestamp=ts,
            kind=int(kind),
            size=int(size),
            direction=direction,
            decrypt_success=decrypt_success,
            payload_hash=bytes(payload_hash) if payload_hash else None,
        )
        with self._lock:
            self._window.append(rec)
            self._total_observed += 1
            return self._total_observed

    # -- query ---------------------------------------------------------
    def total_observed(self) -> int:
        with self._lock:
            return self._total_observed

    def window_snapshot(self) -> List[FrameRecord]:
        """Return a copy of the current window contents."""
        with self._lock:
            return list(self._window)

    def extract_features(self) -> Dict[str, float]:
        """Compute the canonical feature dict from the current window.

        Empty window → zeros across the board.  Single-frame window
        → inter-arrival std falls back to 0 (one sample has no
        spread); other features compute from the one observation.
        """
        with self._lock:
            window = list(self._window)

        if not window:
            return _empty_features()

        sizes = [rec.size for rec in window]
        timestamps = [rec.timestamp for rec in window]
        kinds = [rec.kind for rec in window]
        decrypt_observations = [
            rec.decrypt_success for rec in window
            if rec.decrypt_success is not None
        ]

        # Inter-arrival deltas in milliseconds.  Skipped for a
        # single-frame window (no pairs).
        if len(timestamps) >= 2:
            deltas_ms = [
                (timestamps[i] - timestamps[i - 1]) * 1000.0
                for i in range(1, len(timestamps))
            ]
            mean_iat = statistics.mean(deltas_ms)
            std_iat = statistics.pstdev(deltas_ms) if len(deltas_ms) > 1 else 0.0
        else:
            mean_iat = 0.0
            std_iat = 0.0

        mean_size = statistics.mean(sizes)
        std_size = statistics.pstdev(sizes) if len(sizes) > 1 else 0.0

        if decrypt_observations:
            decrypt_failure_rate = (
                sum(1 for ok in decrypt_observations if not ok)
                / len(decrypt_observations)
            )
        else:
            decrypt_failure_rate = 0.0

        # Duplicate-payload count: how many frames in the window share
        # a payload_hash with at least one earlier frame.  Replay
        # attacks light this metric up.  Frames with no hash recorded
        # don't contribute.
        hash_counts = Counter(
            rec.payload_hash for rec in window if rec.payload_hash is not None
        )
        duplicate_payload_count = sum(c - 1 for c in hash_counts.values() if c > 1)

        # Frame rate per second across the window's time span.
        if len(timestamps) >= 2:
            span_s = max(timestamps[-1] - timestamps[0], 1e-6)
            frame_rate = len(window) / span_s
        else:
            frame_rate = 0.0

        n = float(len(window))
        chat_frac = sum(1 for k in kinds if k in _CHAT_KINDS) / n
        file_frac = sum(1 for k in kinds if k in _FILE_KINDS) / n
        ctrl_frac = sum(1 for k in kinds if k in _CONTROL_KINDS) / n

        return {
            "mean_inter_arrival_ms": float(mean_iat),
            "std_inter_arrival_ms": float(std_iat),
            "mean_payload_size": float(mean_size),
            "std_payload_size": float(std_size),
            "decrypt_failure_rate": float(decrypt_failure_rate),
            "duplicate_payload_count": float(duplicate_payload_count),
            "frame_rate_per_second": float(frame_rate),
            "chat_frame_fraction": float(chat_frac),
            "file_frame_fraction": float(file_frac),
            "control_frame_fraction": float(ctrl_frac),
        }

    def reset(self) -> None:
        """Clear the window.  Useful between sessions in tests."""
        with self._lock:
            self._window.clear()
            self._total_observed = 0
