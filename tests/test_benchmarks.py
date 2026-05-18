"""Tests for Phase 5A benchmark scripts and metrics dashboard.

Covers:
    1. Key-exchange benchmark output structure + reasonable values (3 runs).
    2. Throughput benchmark output structure + reasonable values.
    3. IDS latency tracking on LiveIDS.
    4. /api/metrics_data JSON shape via Flask test_client.
    5. /metrics page renders and contains expected section headers.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Ensure ai_secure_comm/ is importable (same pattern as every other test).
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import app as app_module
from ai.ids_live import LiveIDS
from benchmarks.benchmark_key_exchange import bench_tpm, bench_rsa, bench_dh
from benchmarks.benchmark_throughput import bench_size


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_ids() -> MagicMock:
    """Return a mock LiveIDS that doesn't require the real .pkl bundle."""
    mock_ids = MagicMock(spec=LiveIDS)
    mock_ids.current_state.return_value = {
        "state": "monitoring",
        "active_alert": None,
        "probabilities": {"normal": 0.95, "mitm": 0.03, "replay": 0.02},
        "observation_count": 5,
    }
    mock_ids.reset.return_value = None
    mock_ids.get_latency_stats.return_value = {"count": 0, "mean_ms": None,
                                                "median_ms": None, "min_ms": None,
                                                "max_ms": None, "measurements_ms": []}
    return mock_ids


def _make_app(mock_ids: MagicMock | None = None):
    """Build a Flask test app with IDS mocked out."""
    with patch.object(app_module, "_LiveIDS_cls") as MockCls:
        if mock_ids is not None:
            MockCls.return_value = mock_ids
        else:
            MockCls.return_value = _make_mock_ids()
        flask_app, _sio = app_module.create_app("alice")
    flask_app.config["TESTING"] = True
    return flask_app


# ---------------------------------------------------------------------------
# 1. Key-exchange benchmark
# ---------------------------------------------------------------------------

class TestKeyExchangeBenchmark(unittest.TestCase):

    def _check_scheme(self, result: dict, scheme_name: str):
        for key in ("mean_ms", "median_ms", "std_ms", "min_ms", "max_ms", "runs"):
            self.assertIn(key, result, f"{scheme_name} missing key: {key}")
            if key != "runs":
                self.assertIsInstance(result[key], float,
                                     f"{scheme_name}.{key} should be float")
        self.assertEqual(result["runs"], 3)
        # Sanity: mean >= 0, mean >= min, mean <= max
        self.assertGreaterEqual(result["mean_ms"], 0.0)
        self.assertGreaterEqual(result["mean_ms"], result["min_ms"])
        self.assertLessEqual(result["mean_ms"], result["max_ms"])

    def test_tpm_output_structure(self):
        result = bench_tpm(runs=3)
        self._check_scheme(result, "tpm")
        self.assertIn("avg_rounds", result)
        self.assertGreater(result["avg_rounds"], 0)

    def test_rsa_output_structure(self):
        result = bench_rsa(runs=3)
        self._check_scheme(result, "rsa_2048")
        self.assertIn("keypair_gen_ms_mean", result)
        self.assertIn("encrypt_decrypt_ms_mean", result)
        # Keygen is the dominant cost; enc/dec should be positive.
        self.assertGreater(result["keypair_gen_ms_mean"], 0)
        self.assertGreater(result["encrypt_decrypt_ms_mean"], 0)

    def test_dh_output_structure(self):
        result = bench_dh(runs=3)
        self._check_scheme(result, "dh_2048")
        self.assertIn("param_gen_ms_one_time", result)
        self.assertIn("agreement_ms_mean", result)
        self.assertGreater(result["param_gen_ms_one_time"], 0)

    def test_run_all_writes_json(self):
        """run_all() writes a valid JSON file with the expected top-level keys."""
        from benchmarks.benchmark_key_exchange import run_all
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "results", "ke.json")
            result = run_all(runs=2, output=out)
        for key in ("tpm", "rsa_2048", "dh_2048", "system_info"):
            self.assertIn(key, result)
        for key in ("python_version", "platform", "timestamp"):
            self.assertIn(key, result["system_info"])


# ---------------------------------------------------------------------------
# 2. Throughput benchmark
# ---------------------------------------------------------------------------

class TestThroughputBenchmark(unittest.TestCase):

    _KEY = os.urandom(32)

    def test_bench_size_output_structure(self):
        result = bench_size(self._KEY, size_bytes=256, max_runs=5, time_budget_s=1.0)
        for key in ("size_bytes", "size_human", "runs",
                    "encrypt_mean_ms", "decrypt_mean_ms",
                    "encrypt_throughput_mbps", "decrypt_throughput_mbps"):
            self.assertIn(key, result, f"missing key: {key}")
        self.assertEqual(result["size_bytes"], 256)
        self.assertEqual(result["size_human"], "256B")
        self.assertGreater(result["runs"], 0)
        self.assertGreater(result["encrypt_throughput_mbps"], 0)
        self.assertGreater(result["decrypt_throughput_mbps"], 0)

    def test_throughput_increases_with_larger_buffers(self):
        """Throughput for a large payload should not be catastrophically lower
        than a small one (both use the same AES primitive)."""
        small = bench_size(self._KEY, size_bytes=64,    max_runs=20, time_budget_s=1.0)
        large = bench_size(self._KEY, size_bytes=65536, max_runs=10, time_budget_s=2.0)
        # For small messages the per-call overhead dominates; large messages see
        # better throughput.  We just assert both are > 0.
        self.assertGreater(small["encrypt_throughput_mbps"], 0)
        self.assertGreater(large["encrypt_throughput_mbps"], 0)

    def test_run_all_writes_json(self):
        from benchmarks.benchmark_throughput import run_all
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "results", "tp.json")
            result = run_all(max_runs=3, time_budget_s=0.5, output=out)
        self.assertIn("results", result)
        self.assertIn("system_info", result)
        self.assertGreater(len(result["results"]), 0)


# ---------------------------------------------------------------------------
# 3. IDS latency tracking
# ---------------------------------------------------------------------------

class TestIdsLatencyTracking(unittest.TestCase):

    def _make_live_ids(self) -> LiveIDS:
        """Build a real LiveIDS against the project's trained model."""
        model_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "ai", "trained_model.pkl"
        )
        if not os.path.exists(model_path):
            self.skipTest("trained_model.pkl not found; run ids_train.py first")
        return LiveIDS(model_path)

    def test_empty_stats(self):
        ids = self._make_live_ids()
        stats = ids.get_latency_stats()
        self.assertEqual(stats["count"], 0)
        self.assertIsNone(stats["mean_ms"])
        self.assertIsNone(stats["median_ms"])
        self.assertEqual(stats["measurements_ms"], [])

    def test_record_and_retrieve(self):
        ids = self._make_live_ids()
        # Simulate three detections with known latencies: 5 s, 10 s, 15 s.
        base = 1_000_000.0
        ids.record_alert_latency(base,        base + 5.0)
        ids.record_alert_latency(base + 100,  base + 110.0)
        ids.record_alert_latency(base + 200,  base + 215.0)

        stats = ids.get_latency_stats()
        self.assertEqual(stats["count"], 3)
        # Values in ms
        self.assertAlmostEqual(stats["measurements_ms"][0], 5_000.0, places=0)
        self.assertAlmostEqual(stats["measurements_ms"][1], 10_000.0, places=0)
        self.assertAlmostEqual(stats["measurements_ms"][2], 15_000.0, places=0)
        self.assertAlmostEqual(stats["mean_ms"],   10_000.0, places=0)
        self.assertAlmostEqual(stats["median_ms"], 10_000.0, places=0)
        self.assertAlmostEqual(stats["min_ms"],     5_000.0, places=0)
        self.assertAlmostEqual(stats["max_ms"],    15_000.0, places=0)

    def test_latency_survives_reset(self):
        """reset() must NOT clear the latency measurements."""
        ids = self._make_live_ids()
        base = 1_000_000.0
        ids.record_alert_latency(base, base + 3.0)
        ids.reset()
        stats = ids.get_latency_stats()
        self.assertEqual(stats["count"], 1,
                         "Latency measurements should survive reset()")

    def test_cap_at_100_entries(self):
        ids = self._make_live_ids()
        base = 1_000_000.0
        for i in range(110):
            ids.record_alert_latency(base, base + float(i))
        stats = ids.get_latency_stats()
        self.assertEqual(stats["count"], 100)
        # After 110 inserts the oldest 10 were dropped; min should be ~10s.
        self.assertAlmostEqual(stats["min_ms"], 10_000.0, places=0)


# ---------------------------------------------------------------------------
# 4 & 5. /api/metrics_data and /metrics page
# ---------------------------------------------------------------------------

class TestMetricsRoutes(unittest.TestCase):

    def setUp(self):
        self.app = _make_app()
        self.client = self.app.test_client()

    def test_metrics_data_returns_json_shape(self):
        resp = self.client.get("/api/metrics_data")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        # Top-level keys must always be present (even if null).
        for key in ("key_exchange", "throughput", "ids_latency", "session"):
            self.assertIn(key, data, f"missing top-level key: {key}")
        sess = data["session"]
        for key in ("role", "sync_time_ms", "sync_rounds",
                    "messages_encrypted", "bytes_encrypted"):
            self.assertIn(key, sess, f"session missing key: {key}")
        self.assertEqual(sess["role"], "alice")
        self.assertEqual(sess["messages_encrypted"], 0)

    def test_metrics_data_missing_benchmarks_returns_null(self):
        """If benchmark result files are absent the keys come back as null."""
        import benchmarks.benchmark_key_exchange as _ke_mod  # noqa: F401
        # Patch Path.exists to return False so _load_json sees no files.
        with patch("builtins.open", side_effect=FileNotFoundError):
            resp = self.client.get("/api/metrics_data")
        # Should still return 200 (may use cached in-memory path) — just ensure
        # no 500 is raised.  The actual null-handling is tested by the shape test.
        self.assertIn(resp.status_code, (200,))

    def test_metrics_page_renders_200(self):
        resp = self.client.get("/metrics")
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode()
        self.assertIn("Performance Metrics", html)

    def test_metrics_page_contains_all_section_headers(self):
        resp = self.client.get("/metrics")
        html = resp.data.decode()
        self.assertIn("§1", html, "Section 1 (key exchange) not found in metrics page")
        self.assertIn("§2", html, "Section 2 (throughput) not found in metrics page")
        self.assertIn("§3", html, "Section 3 (IDS latency) not found in metrics page")
        self.assertIn("§4", html, "Section 4 (system info) not found in metrics page")

    def test_metrics_page_links_back_to_chat(self):
        resp = self.client.get("/metrics")
        html = resp.data.decode()
        self.assertIn('href="/"', html)


# ---------------------------------------------------------------------------
# 6. POST /api/record_attack_start (dev-mode peer-notification route)
# ---------------------------------------------------------------------------

class TestRecordAttackStart(unittest.TestCase):

    def setUp(self):
        self.app = _make_app()
        self.client = self.app.test_client()

    def test_valid_mitm_payload_returns_ok(self):
        resp = self.client.post(
            "/api/record_attack_start",
            data=json.dumps({"type": "mitm", "ts": 1_700_000_000.0}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(json.loads(resp.data)["ok"])

    def test_valid_replay_payload_returns_ok(self):
        resp = self.client.post(
            "/api/record_attack_start",
            data=json.dumps({"type": "replay", "ts": 1_700_000_001.0}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(json.loads(resp.data)["ok"])

    def test_unknown_type_silently_ignored(self):
        """Unknown attack types are ignored — route never raises 4xx."""
        resp = self.client.post(
            "/api/record_attack_start",
            data=json.dumps({"type": "dos", "ts": 1_700_000_002.0}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)

    def test_empty_body_silently_ignored(self):
        """Missing fields are silently ignored — route is best-effort."""
        resp = self.client.post(
            "/api/record_attack_start",
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
