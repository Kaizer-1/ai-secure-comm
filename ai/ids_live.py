"""Live IDS classifier — Phase 4B.

Wraps the trained Random Forest bundle produced by `ai/ids_train.py` and
turns every `on_features_updated` snapshot into a real-time threat
classification with hysteresis so the alert state doesn't flap on every
minor probability wiggle.

State machine
-------------
warming_up  → model has not yet seen `min_observations_required` windows;
              returns probabilities but makes no alert decisions.
monitoring  → enough observations collected; no active alert.
alerting    → an attack class crossed `alert_threshold_fire` (0.70 default);
              the alert stays until that class's probability drops below
              `alert_threshold_clear` (0.50 default).  Switching attack
              type mid-alert is intentionally suppressed — let the current
              alert clear first.

Usage (from PeerLink)
---------------------
    ids = LiveIDS(model_path="ai/trained_model.pkl")
    state = ids.evaluate(features_dict)   # call on every on_features_updated
    ids.reset()                           # call when peer disconnects
"""

from __future__ import annotations

import datetime as _dt
import logging
import math
import statistics as _stats
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import pandas as pd

logger = logging.getLogger(__name__)


class LiveIDS:
    """Real-time threat classifier backed by a saved Random Forest bundle.

    Parameters
    ----------
    model_path:
        Path to the joblib bundle written by `ai/ids_train.py`.  The file
        must exist and contain the keys ``model``, ``feature_names``, and
        ``label_encoder``; otherwise construction raises immediately
        (fail-fast at startup, not on first prediction).
    alert_threshold_fire:
        Probability at or above which a non-normal class triggers a new
        alert.  Must be strictly greater than ``alert_threshold_clear``.
    alert_threshold_clear:
        Probability below which the currently active alert type's score
        must fall before the alert is cleared.
    min_observations_required:
        Number of ``evaluate()`` calls that must complete before the IDS
        begins making alert decisions.  Prevents flaky early alerts when
        the sliding feature window is still warming up.
    """

    def __init__(
        self,
        model_path: str = "ai/trained_model.pkl",
        *,
        alert_threshold_fire: float = 0.70,
        alert_threshold_clear: float = 0.50,
        min_observations_required: int = 3,
    ) -> None:
        if alert_threshold_clear >= alert_threshold_fire:
            raise ValueError(
                f"alert_threshold_clear ({alert_threshold_clear}) must be "
                f"strictly less than alert_threshold_fire ({alert_threshold_fire})"
            )

        bundle = self._load_bundle(model_path)

        self._model = bundle["model"]
        self._feature_names: List[str] = list(bundle["feature_names"])
        self._feature_names_set = set(self._feature_names)

        # label_encoder maps {class_name: int_index} — invert for decode.
        label_enc: Dict[str, int] = bundle["label_encoder"]
        self._idx_to_label: Dict[int, str] = {v: k for k, v in label_enc.items()}

        self._fire_threshold = float(alert_threshold_fire)
        self._clear_threshold = float(alert_threshold_clear)
        self._min_observations = int(min_observations_required)

        # Runtime state — reset() zeroes these.
        self._observation_count: int = 0
        self._active_alert: Optional[Dict[str, Any]] = None
        self._last_state: Optional[Dict[str, Any]] = None

        # Phase 5A: detection-latency tracking.  Intentionally NOT cleared by
        # reset() so measurements accumulate across multiple demo runs within
        # one process lifetime.  Capped at 100 entries (oldest dropped first).
        self._latency_measurements: List[float] = []  # milliseconds

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, features_dict: dict) -> Dict[str, Any]:
        """Classify one feature snapshot and return the current IDS state.

        Parameters
        ----------
        features_dict:
            The ``dict`` emitted by ``FeatureExtractor.extract_features()``.
            Must contain every key in the bundle's ``feature_names`` list.
            Extra keys are silently dropped.  NaN values cause a warning
            and a no-op (previous state is returned unchanged).

        Returns
        -------
        dict with keys:
            ``state``           – "warming_up" | "monitoring" | "alerting"
            ``active_alert``    – None or {"type", "confidence", "since"}
            ``probabilities``   – {"normal": float, "mitm": float, "replay": float}
            ``observation_count`` – int
        """
        self._observation_count += 1

        # NaN guard — return previous state without modifying alert.
        if self._has_nan(features_dict):
            logger.warning(
                "IDS evaluate: features_dict contains NaN; skipping window %d",
                self._observation_count,
            )
            return self._current_or_default()

        # Validate required keys before touching the model.
        self._check_features(features_dict)

        # Still warming up — compute probabilities but make no decisions.
        if self._observation_count < self._min_observations:
            probs = self._compute_probs(features_dict)
            state = self._build_state(probs)
            self._last_state = state
            return state

        probs = self._compute_probs(features_dict)
        self._update_alert(probs)
        state = self._build_state(probs)
        self._last_state = state
        return state

    def current_state(self) -> Dict[str, Any]:
        """Return the most recently computed state without re-evaluating."""
        return self._current_or_default()

    def reset(self) -> None:
        """Clear all accumulated state.

        Call this when the peer disconnects or a new sync starts so stale
        alert state from a previous session does not bleed into the new one.
        Latency measurements are intentionally preserved across resets.
        """
        self._observation_count = 0
        self._active_alert = None
        self._last_state = None
        logger.debug("LiveIDS reset")

    # Phase 5A — detection latency tracking
    def record_alert_latency(
        self, attack_start_time: float, detection_time: float
    ) -> None:
        """Record wall-clock latency from attack launch to first alert.

        Parameters
        ----------
        attack_start_time:
            ``time.time()`` value captured when the attack was started
            (e.g. when the demo-panel button was clicked).
        detection_time:
            ``time.time()`` value captured when the IDS alert fired.
        """
        latency_ms = (detection_time - attack_start_time) * 1000.0
        if len(self._latency_measurements) >= 100:
            self._latency_measurements.pop(0)
        self._latency_measurements.append(latency_ms)
        logger.debug("IDS latency recorded: %.0f ms", latency_ms)

    def get_latency_stats(self) -> Dict[str, Any]:
        """Return summary stats for all recorded detection latencies.

        Returns a dict with keys: count, mean_ms, median_ms, min_ms, max_ms,
        measurements_ms.  All ``*_ms`` values are ``None`` when count is 0.
        """
        m = self._latency_measurements
        if not m:
            return {
                "count": 0,
                "mean_ms": None,
                "median_ms": None,
                "min_ms": None,
                "max_ms": None,
                "measurements_ms": [],
            }
        return {
            "count": len(m),
            "mean_ms": round(_stats.mean(m), 1),
            "median_ms": round(_stats.median(m), 1),
            "min_ms": round(min(m), 1),
            "max_ms": round(max(m), 1),
            "measurements_ms": list(m),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _load_bundle(model_path: str) -> Dict[str, Any]:
        path = Path(model_path)
        if not path.exists():
            raise FileNotFoundError(
                f"IDS model bundle not found at {path!r}.  "
                "Run 'python ai/ids_train.py' to generate it."
            )
        try:
            bundle = joblib.load(path)
        except Exception as exc:
            raise RuntimeError(
                f"Failed to load IDS model bundle from {path!r}: {exc}"
            ) from exc
        for required in ("model", "feature_names", "label_encoder"):
            if required not in bundle:
                raise KeyError(
                    f"IDS bundle at {path!r} is missing required key {required!r}. "
                    "Re-train the model with 'python ai/ids_train.py'."
                )
        return bundle

    def _check_features(self, features_dict: dict) -> None:
        missing = [f for f in self._feature_names if f not in features_dict]
        if missing:
            raise ValueError(
                f"IDS evaluate: features_dict is missing required keys: {missing}. "
                "This indicates a mismatch between the live feature schema and the "
                "trained model — check that ai/feature_extractor.FEATURE_NAMES "
                "matches the bundle's feature_names."
            )
        extra = [k for k in features_dict if k not in self._feature_names_set]
        if extra:
            logger.debug("IDS evaluate: dropping unexpected feature keys: %s", extra)

    @staticmethod
    def _has_nan(features_dict: dict) -> bool:
        for v in features_dict.values():
            try:
                if math.isnan(float(v)):
                    return True
            except (TypeError, ValueError):
                pass
        return False

    def _compute_probs(self, features_dict: dict) -> Dict[str, float]:
        """Run predict_proba and return {label_name: probability} dict."""
        X = pd.DataFrame(
            [[features_dict[f] for f in self._feature_names]],
            columns=self._feature_names,
        )
        proba = self._model.predict_proba(X)[0]
        # model.classes_ are the int indices [0, 1, 2] used at training time.
        return {
            self._idx_to_label[int(cls)]: float(p)
            for cls, p in zip(self._model.classes_, proba)
        }

    def _update_alert(self, probs: Dict[str, float]) -> None:
        """Apply hysteresis logic to transition the active alert."""
        if self._active_alert is None:
            # Not currently alerting — fire if any attack class crosses threshold.
            attack_candidates = [
                (label, p) for label, p in probs.items()
                if label != "normal" and p >= self._fire_threshold
            ]
            if attack_candidates:
                # Pick the highest-probability attack class.
                best_label, best_p = max(attack_candidates, key=lambda kv: kv[1])
                self._active_alert = {
                    "type": best_label,
                    "confidence": best_p,
                    "since": _dt.datetime.now(_dt.timezone.utc).isoformat(),
                }
                logger.info(
                    "IDS alert fired: type=%s confidence=%.3f",
                    best_label, best_p,
                )
        else:
            # Currently alerting — check only the ACTIVE alert type.
            # Deliberately do NOT switch types mid-alert; let the current
            # alert clear first, then a new alert for the other type can fire.
            active_type = self._active_alert["type"]
            active_p = probs.get(active_type, 0.0)
            if active_p < self._clear_threshold:
                logger.info(
                    "IDS alert cleared: was %s (p=%.3f < clear_threshold=%.2f)",
                    active_type, active_p, self._clear_threshold,
                )
                self._active_alert = None
            else:
                self._active_alert["confidence"] = active_p

    def _build_state(self, probs: Dict[str, float]) -> Dict[str, Any]:
        if self._observation_count < self._min_observations:
            state_name = "warming_up"
        elif self._active_alert is not None:
            state_name = "alerting"
        else:
            state_name = "monitoring"

        return {
            "state": state_name,
            "active_alert": (
                dict(self._active_alert) if self._active_alert is not None else None
            ),
            "probabilities": probs,
            "observation_count": self._observation_count,
        }

    def _current_or_default(self) -> Dict[str, Any]:
        if self._last_state is not None:
            return dict(self._last_state)
        # Before any evaluate() call or after NaN on the very first call.
        return {
            "state": "warming_up",
            "active_alert": None,
            "probabilities": {
                label: 0.0 for label in self._idx_to_label.values()
            },
            "observation_count": self._observation_count,
        }
