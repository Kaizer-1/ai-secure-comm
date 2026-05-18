"""Tests for ai.ids_live.LiveIDS — Phase 4B."""

from __future__ import annotations

import os
import socket
import tempfile
import threading
import time
import unittest
from typing import Dict, List

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

import config
from ai.ids_live import LiveIDS
from ai.ids_train import FEATURE_NAMES
from core.peer_link import PeerLink

_LABEL_ENCODER: Dict[str, int] = {"mitm": 0, "normal": 1, "replay": 2}


def _build_synthetic_bundle(path: str) -> None:
    n = len(FEATURE_NAMES)

    def _row(dfr: float = 0.0, dpc: float = 0.0) -> List[float]:
        base = [50.0, 10.0, 100.0, 20.0, dfr, dpc, 5.0, 0.8, 0.1, 0.1]
        assert len(base) == n
        return base

    rows = [
        _row(dfr=0.30),
        _row(dfr=0.25),
        _row(),
        _row(),
        _row(dpc=3.0),
        _row(dpc=2.5),
    ]
    X = pd.DataFrame(rows, columns=FEATURE_NAMES)
    y = np.array([0, 0, 1, 1, 2, 2])

    model = RandomForestClassifier(n_estimators=5, random_state=42)
    model.fit(X, y)

    bundle = {
        "model": model,
        "feature_names": list(FEATURE_NAMES),
        "label_encoder": _LABEL_ENCODER,
        "filter_applied": True,
        "test_accuracy": 1.0,
        "random_state": 42,
        "test_size": 0.33,
        "n_samples": 6,
        "trained_at": "2026-05-12T00:00:00+00:00",
        "trained_on": "synthetic",
        "hyperparams": {},
    }
    joblib.dump(bundle, path)


def _normal_features() -> dict:
    return {
        "mean_inter_arrival_ms": 50.0,
        "std_inter_arrival_ms": 10.0,
        "mean_payload_size": 100.0,
        "std_payload_size": 20.0,
        "decrypt_failure_rate": 0.0,
        "duplicate_payload_count": 0.0,
        "frame_rate_per_second": 5.0,
        "chat_frame_fraction": 0.8,
        "file_frame_fraction": 0.1,
        "control_frame_fraction": 0.1,
    }


def _mitm_features() -> dict:
    f = _normal_features()
    f["decrypt_failure_rate"] = 0.30
    return f


def _replay_features() -> dict:
    f = _normal_features()
    f["duplicate_payload_count"] = 3.0
    return f


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _ControlledLiveIDS(LiveIDS):
    """Subclass that returns a scripted probability sequence."""

    def __init__(self, bundle_path: str, prob_sequence: list, **kwargs):
        super().__init__(bundle_path, **kwargs)
        self._prob_sequence = prob_sequence
        self._call_idx = 0

    def _compute_probs(self, features_dict: dict) -> Dict[str, float]:
        idx = min(self._call_idx, len(self._prob_sequence) - 1)
        self._call_idx += 1
        return dict(self._prob_sequence[idx])


class TestLiveIDS(unittest.TestCase):

    _bundle_path: str = ""

    @classmethod
    def setUpClass(cls) -> None:
        fd, path = tempfile.mkstemp(suffix=".pkl", prefix="test_ids_bundle_")
        os.close(fd)
        _build_synthetic_bundle(path)
        cls._bundle_path = path

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            os.unlink(cls._bundle_path)
        except OSError:
            pass

    # ------------------------------------------------------------------
    # 1. Warming-up guard
    # ------------------------------------------------------------------
    def test_warming_up(self):
        """Fewer than min_observations_required calls -> always warming_up."""
        ids = LiveIDS(self._bundle_path, min_observations_required=3)
        for i in range(2):
            state = ids.evaluate(_mitm_features())
            self.assertEqual(state["state"], "warming_up", msg=f"call {i+1}")
            self.assertIsNone(state["active_alert"])
        self.assertEqual(ids.current_state()["state"], "warming_up")

    # ------------------------------------------------------------------
    # 2. MITM alert fires
    # ------------------------------------------------------------------
    def test_basic_alert_fires(self):
        """Past warm-up with high mitm probability -> alert fires."""
        probs = [
            {"normal": 0.90, "mitm": 0.05, "replay": 0.05},
            {"normal": 0.90, "mitm": 0.05, "replay": 0.05},
            {"normal": 0.05, "mitm": 0.87, "replay": 0.08},
        ]
        ids = _ControlledLiveIDS(
            self._bundle_path, probs, min_observations_required=3
        )
        for _ in range(2):
            ids.evaluate(_mitm_features())
        state = ids.evaluate(_mitm_features())

        self.assertEqual(state["state"], "alerting")
        self.assertIsNotNone(state["active_alert"])
        self.assertEqual(state["active_alert"]["type"], "mitm")
        self.assertAlmostEqual(state["active_alert"]["confidence"], 0.87)
        self.assertIn("since", state["active_alert"])

    # ------------------------------------------------------------------
    # 3. Alert clears on normal traffic
    # ------------------------------------------------------------------
    def test_alert_clears(self):
        """Alert fires then probability drops below clear threshold -> monitoring."""
        probs = [
            {"normal": 0.90, "mitm": 0.05, "replay": 0.05},
            {"normal": 0.90, "mitm": 0.05, "replay": 0.05},
            {"normal": 0.05, "mitm": 0.85, "replay": 0.10},
            {"normal": 0.92, "mitm": 0.04, "replay": 0.04},
        ]
        ids = _ControlledLiveIDS(
            self._bundle_path, probs, min_observations_required=3
        )
        for _ in range(3):
            ids.evaluate(_mitm_features())
        state = ids.evaluate(_normal_features())

        self.assertEqual(state["state"], "monitoring")
        self.assertIsNone(state["active_alert"])

    # ------------------------------------------------------------------
    # 4. Hysteresis prevents flapping
    # ------------------------------------------------------------------
    def test_hysteresis_does_not_flap(self):
        """Oscillating probabilities produce exactly one fire and one clear.

        obs 1-2  warming_up
        obs 3    first decision, mitm=0.30 < 0.70 -> monitoring
        obs 4    mitm=0.75 >= 0.70 -> monitoring->alerting
        obs 5-7  mitm oscillates 0.55-0.75, all >= 0.50 -> stays alerting
        obs 8    mitm=0.04 < 0.50 -> alerting->monitoring
        obs 9-10 stays monitoring
        """
        probs = [
            {"normal": 0.90, "mitm": 0.05, "replay": 0.05},
            {"normal": 0.90, "mitm": 0.05, "replay": 0.05},
            {"normal": 0.65, "mitm": 0.30, "replay": 0.05},
            {"normal": 0.20, "mitm": 0.75, "replay": 0.05},
            {"normal": 0.35, "mitm": 0.60, "replay": 0.05},
            {"normal": 0.20, "mitm": 0.75, "replay": 0.05},
            {"normal": 0.35, "mitm": 0.55, "replay": 0.10},
            {"normal": 0.92, "mitm": 0.04, "replay": 0.04},
            {"normal": 0.92, "mitm": 0.04, "replay": 0.04},
            {"normal": 0.92, "mitm": 0.04, "replay": 0.04},
        ]
        ids = _ControlledLiveIDS(
            self._bundle_path, probs, min_observations_required=3
        )

        transitions: List[str] = []
        prev_state = "warming_up"
        for _ in probs:
            s = ids.evaluate(_mitm_features())
            if s["state"] != prev_state:
                transitions.append(f"{prev_state}->{s['state']}")
                prev_state = s["state"]

        self.assertEqual(
            transitions.count("monitoring->alerting"), 1,
            msg=f"transitions: {transitions}",
        )
        self.assertEqual(
            transitions.count("alerting->monitoring"), 1,
            msg=f"transitions: {transitions}",
        )
        self.assertNotIn("warming_up->alerting", transitions)

    # ------------------------------------------------------------------
    # 5. Multiple attack classes above threshold — highest wins
    # ------------------------------------------------------------------
    def test_multiple_classes_above_threshold(self):
        """When mitm=0.60 and replay=0.75 both exceed the fire threshold,
        replay wins (higher probability)."""
        probs = [
            {"normal": 0.90, "mitm": 0.05, "replay": 0.05},
            {"normal": 0.90, "mitm": 0.05, "replay": 0.05},
            {"normal": 0.05, "mitm": 0.60, "replay": 0.75},
        ]
        ids = _ControlledLiveIDS(
            self._bundle_path, probs,
            min_observations_required=3,
            alert_threshold_fire=0.55,
            alert_threshold_clear=0.40,
        )
        for _ in range(2):
            ids.evaluate(_replay_features())
        state = ids.evaluate(_replay_features())

        self.assertEqual(state["state"], "alerting")
        self.assertEqual(state["active_alert"]["type"], "replay")
        self.assertAlmostEqual(state["active_alert"]["confidence"], 0.75)

    # ------------------------------------------------------------------
    # 6. Normal traffic never triggers an alert
    # ------------------------------------------------------------------
    def test_no_alert_for_normal(self):
        """Clean normal traffic for many windows -> stays monitoring, no alert."""
        probs = [{"normal": 0.95, "mitm": 0.03, "replay": 0.02}] * 20
        ids = _ControlledLiveIDS(
            self._bundle_path, probs, min_observations_required=3
        )
        for _ in range(20):
            state = ids.evaluate(_normal_features())
            if state["state"] != "warming_up":
                self.assertEqual(state["state"], "monitoring")
                self.assertIsNone(state["active_alert"])

    # ------------------------------------------------------------------
    # 7. reset() clears all state
    # ------------------------------------------------------------------
    def test_reset_clears_state(self):
        """After an alert fires, reset() zeros observation_count and alert."""
        probs = [
            {"normal": 0.90, "mitm": 0.05, "replay": 0.05},
            {"normal": 0.90, "mitm": 0.05, "replay": 0.05},
            {"normal": 0.05, "mitm": 0.85, "replay": 0.10},
        ]
        ids = _ControlledLiveIDS(
            self._bundle_path, probs, min_observations_required=3
        )
        for _ in range(3):
            ids.evaluate(_mitm_features())

        self.assertEqual(ids.current_state()["state"], "alerting")

        ids.reset()

        post = ids.current_state()
        self.assertEqual(post["state"], "warming_up")
        self.assertEqual(post["observation_count"], 0)
        self.assertIsNone(post["active_alert"])

    # ------------------------------------------------------------------
    # 8. Missing model raises clearly
    # ------------------------------------------------------------------
    def test_missing_model_raises_clearly(self):
        """Constructing with a nonexistent path raises FileNotFoundError."""
        bad_path = "/tmp/this_does_not_exist_4b_test_12345.pkl"
        with self.assertRaises(FileNotFoundError) as ctx:
            LiveIDS(bad_path)
        self.assertIn(bad_path, str(ctx.exception))

    # ------------------------------------------------------------------
    # 9. PeerLink without IDS attached works normally
    # ------------------------------------------------------------------
    def test_disable_ids_in_peerlink(self):
        """PeerLink with no IDS attached still fires on_features_updated
        correctly and never fires on_threat_alert."""
        features_seen: list = []
        errors: list = []
        alert_fired = threading.Event()

        port = _free_port()
        alice = PeerLink(
            role=config.ROLE_A,
            bind_host="127.0.0.1",
            peer_host="127.0.0.1",
            peer_port=port,
            initiator_role=config.ROLE_A,
            connect_timeout=5.0,
            recv_timeout=5.0,
        )
        bob = PeerLink(
            role=config.ROLE_B,
            bind_host="127.0.0.1",
            peer_host="127.0.0.1",
            peer_port=port,
            initiator_role=config.ROLE_A,
            connect_timeout=5.0,
            recv_timeout=5.0,
        )
        bob.on_features_updated = lambda f: features_seen.append(f)
        bob.on_error = lambda exc: errors.append(exc)
        alice.on_threat_alert = lambda _: alert_fired.set()
        bob.on_threat_alert = lambda _: alert_fired.set()

        synced = threading.Event()
        bob.on_sync_complete = lambda *_: synced.set()

        ta = threading.Thread(target=alice.connect, daemon=True)
        tb = threading.Thread(target=bob.connect, daemon=True)
        ta.start()
        tb.start()
        self.assertTrue(synced.wait(timeout=10), "PeerLink sync timed out")

        for _ in range(6):
            alice.send_chat("ping")

        time.sleep(0.3)

        alice.close()
        bob.close()

        self.assertFalse(
            alert_fired.is_set(),
            "on_threat_alert fired but no IDS was attached",
        )
        self.assertEqual(errors, [], f"unexpected errors: {errors}")
        self.assertGreater(len(features_seen), 0, "on_features_updated never fired")


if __name__ == "__main__":
    unittest.main()
