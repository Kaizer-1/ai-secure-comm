"""Tests for `ai.ids_train` — offline Random Forest IDS trainer.

All five tests generate synthetic data in-memory or via tempfiles;
no real CSV or real model files are required.  The full suite must
complete in under 5 seconds.
"""

from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from ai.ids_train import (
    FEATURE_NAMES,
    LABEL_COLUMN,
    _assert_columns_present,
    _filter_attack_rows_by_signal,
    train_and_save,
    train_from_csv,
)


# ---------------------------------------------------------------------------
# Helpers shared across tests
# ---------------------------------------------------------------------------

def _make_csv(n: int = 30, seed: int = 0, class_counts: dict | None = None) -> str:
    """Write a valid synthetic CSV to a tempfile and return the path.

    Parameters
    ----------
    n:
        Total rows.  Ignored when `class_counts` is given.
    class_counts:
        Dict mapping label string to count, e.g.
        ``{"normal": 10, "mitm": 50, "replay": 50}``.
    """
    rng = np.random.default_rng(seed)
    if class_counts is None:
        labels = ["normal", "mitm", "replay"]
        rows_per_class = n // len(labels)
        rows = {lbl: rows_per_class for lbl in labels}
        # give the remainder to "normal"
        rows["normal"] += n - rows_per_class * len(labels)
    else:
        rows = class_counts

    records = []
    for lbl, count in rows.items():
        for _ in range(count):
            feat = {name: float(rng.uniform(0, 1)) for name in FEATURE_NAMES}
            feat[LABEL_COLUMN] = lbl
            records.append(feat)

    df = pd.DataFrame(records)
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".csv", delete=False, encoding="utf-8"
    )
    df.to_csv(tmp.name, index=False)
    tmp.close()
    return tmp.name


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------


class TestLoadCsv(unittest.TestCase):
    """test_load_csv — shape, dtypes, and missing-column error."""

    def test_valid_csv_loads_with_correct_shape(self):
        path = _make_csv(n=30)
        df = pd.read_csv(path)
        # Should have all feature columns + label column.
        self.assertGreaterEqual(len(df), 30)
        for col in FEATURE_NAMES:
            self.assertIn(col, df.columns)
        self.assertIn(LABEL_COLUMN, df.columns)
        # Feature columns should be numeric.
        for col in FEATURE_NAMES:
            self.assertTrue(
                pd.api.types.is_numeric_dtype(df[col]),
                f"column {col!r} should be numeric",
            )

    def test_missing_column_raises_value_error(self):
        path = _make_csv(n=30)
        df = pd.read_csv(path)
        df_bad = df.drop(columns=[FEATURE_NAMES[0]])
        with self.assertRaises(ValueError) as ctx:
            _assert_columns_present(df_bad)
        self.assertIn(FEATURE_NAMES[0], str(ctx.exception))


class TestTrainReturnsModel(unittest.TestCase):
    """test_train_returns_fitted_model — returned bundle has a usable model."""

    def test_model_is_fitted_and_can_predict(self):
        path = _make_csv(n=30)
        bundle = train_from_csv(path, test_size=0.2, random_state=0, verbose=False)

        model = bundle["model"]
        # A fitted RandomForestClassifier exposes `classes_`.
        self.assertTrue(
            hasattr(model, "classes_"),
            "model.classes_ should exist after fitting",
        )
        # Should be able to predict on a single row with 10 features.
        row = pd.DataFrame(np.zeros((1, len(FEATURE_NAMES))), columns=FEATURE_NAMES)
        pred = model.predict(row)
        self.assertEqual(len(pred), 1)


class TestSaveLoadRoundtrip(unittest.TestCase):
    """test_save_load_roundtrip — persisted model predicts identically."""

    def test_predictions_match_after_save_load(self):
        csv_path = _make_csv(n=30)
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            pkl_path = f.name

        bundle = train_and_save(
            csv_path, pkl_path, test_size=0.2, random_state=0, verbose=False,
        )
        loaded = joblib.load(pkl_path)

        # Predictions on a fixed synthetic input should be identical.
        rng = np.random.default_rng(99)
        X_probe = pd.DataFrame(
            rng.uniform(0, 1, size=(5, len(FEATURE_NAMES))),
            columns=FEATURE_NAMES,
        )
        preds_original = bundle["model"].predict(X_probe)
        preds_loaded = loaded["model"].predict(X_probe)

        np.testing.assert_array_equal(preds_original, preds_loaded)


class TestMetadataPreserved(unittest.TestCase):
    """test_metadata_preserved — bundle contains all required keys."""

    REQUIRED_KEYS = {
        "model",
        "feature_names",
        "label_encoder",
        "trained_on",
        "trained_at",
        "n_samples",
        "test_accuracy",
        "test_size",
        "random_state",
        "hyperparams",
    }

    def test_all_required_keys_present(self):
        path = _make_csv(n=30)
        bundle = train_from_csv(path, test_size=0.2, random_state=0, verbose=False)
        for key in self.REQUIRED_KEYS:
            self.assertIn(key, bundle, f"bundle missing key: {key!r}")

    def test_feature_names_match_canonical_schema(self):
        path = _make_csv(n=30)
        bundle = train_from_csv(path, test_size=0.2, random_state=0, verbose=False)
        self.assertEqual(bundle["feature_names"], FEATURE_NAMES)

    def test_test_accuracy_is_in_unit_interval(self):
        path = _make_csv(n=30)
        bundle = train_from_csv(path, test_size=0.2, random_state=0, verbose=False)
        self.assertGreaterEqual(bundle["test_accuracy"], 0.0)
        self.assertLessEqual(bundle["test_accuracy"], 1.0)


class TestHandlesImbalancedClasses(unittest.TestCase):
    """test_handles_imbalanced_classes — balanced weights, trains without error."""

    def test_imbalanced_data_trains_with_balanced_weight(self):
        path = _make_csv(class_counts={"normal": 10, "mitm": 50, "replay": 50})
        bundle = train_from_csv(path, test_size=0.2, random_state=0, verbose=False)

        model = bundle["model"]
        # class_weight="balanced" must be set in hyperparams.
        self.assertEqual(
            bundle["hyperparams"].get("class_weight"), "balanced",
            "class_weight should be 'balanced'",
        )
        # Model must have fitted successfully.
        self.assertTrue(hasattr(model, "classes_"))
        # All three classes should appear in the fitted model.
        self.assertEqual(len(model.classes_), 3)


class TestFilterDropsMitmWithNoSignal(unittest.TestCase):
    """Filter must drop mitm rows where decrypt_failure_rate == 0."""

    def _make_mitm_df(self) -> pd.DataFrame:
        """Return a DataFrame with 3 mitm rows: two with no signal, one with."""
        rows = []
        base = {name: 0.0 for name in FEATURE_NAMES}
        # Row 0: mitm, zero failure rate — should be dropped
        rows.append({**base, "decrypt_failure_rate": 0.0, LABEL_COLUMN: "mitm"})
        # Row 1: mitm, zero failure rate — should be dropped
        rows.append({**base, "decrypt_failure_rate": 0.0, LABEL_COLUMN: "mitm"})
        # Row 2: mitm, non-zero failure rate — should be KEPT
        rows.append({**base, "decrypt_failure_rate": 0.15, LABEL_COLUMN: "mitm"})
        return pd.DataFrame(rows)

    def test_drops_mitm_rows_with_zero_decrypt_failure(self):
        df = self._make_mitm_df()
        result = _filter_attack_rows_by_signal(df, verbose=False)
        mitm_rows = result[result[LABEL_COLUMN] == "mitm"]
        self.assertEqual(len(mitm_rows), 1)
        self.assertGreater(mitm_rows.iloc[0]["decrypt_failure_rate"], 0)

    def test_drops_count_is_correct(self):
        df = self._make_mitm_df()
        result = _filter_attack_rows_by_signal(df, verbose=False)
        # Started with 3 mitm rows, 2 should be dropped
        self.assertEqual(len(df) - len(result), 2)


class TestFilterDropsReplayWithNoSignal(unittest.TestCase):
    """Filter must drop replay rows where duplicate_payload_count == 0."""

    def _make_replay_df(self) -> pd.DataFrame:
        rows = []
        base = {name: 0.0 for name in FEATURE_NAMES}
        # Row 0: replay, no duplicates — should be dropped
        rows.append({**base, "duplicate_payload_count": 0.0, LABEL_COLUMN: "replay"})
        # Row 1: replay, has duplicates — should be KEPT
        rows.append({**base, "duplicate_payload_count": 1.0, LABEL_COLUMN: "replay"})
        return pd.DataFrame(rows)

    def test_drops_replay_rows_with_zero_duplicates(self):
        df = self._make_replay_df()
        result = _filter_attack_rows_by_signal(df, verbose=False)
        replay_rows = result[result[LABEL_COLUMN] == "replay"]
        self.assertEqual(len(replay_rows), 1)
        self.assertGreater(replay_rows.iloc[0]["duplicate_payload_count"], 0)


class TestFilterKeepsAllNormal(unittest.TestCase):
    """Filter must keep ALL normal rows regardless of feature values."""

    def test_all_normal_rows_preserved(self):
        base = {name: 0.0 for name in FEATURE_NAMES}
        # Normal rows with all-zero features — filter must not touch them.
        rows = [{**base, LABEL_COLUMN: "normal"} for _ in range(10)]
        df = pd.DataFrame(rows)
        result = _filter_attack_rows_by_signal(df, verbose=False)
        self.assertEqual(len(result), 10)
        self.assertTrue((result[LABEL_COLUMN] == "normal").all())

    def test_mixed_labels_normal_intact(self):
        base = {name: 0.0 for name in FEATURE_NAMES}
        rows = [
            {**base, LABEL_COLUMN: "normal"},
            {**base, "decrypt_failure_rate": 0.0, LABEL_COLUMN: "mitm"},   # dropped
            {**base, "duplicate_payload_count": 0.0, LABEL_COLUMN: "replay"},  # dropped
            {**base, "decrypt_failure_rate": 0.2, LABEL_COLUMN: "mitm"},    # kept
        ]
        df = pd.DataFrame(rows)
        result = _filter_attack_rows_by_signal(df, verbose=False)
        self.assertEqual(len(result[result[LABEL_COLUMN] == "normal"]), 1)
        self.assertEqual(len(result[result[LABEL_COLUMN] == "mitm"]), 1)
        self.assertEqual(len(result[result[LABEL_COLUMN] == "replay"]), 0)


class TestNoFilterBypassesFiltering(unittest.TestCase):
    """Passing filter_rows=False must leave all rows intact."""

    def test_no_filter_keeps_zero_signal_attack_rows(self):
        base = {name: 0.0 for name in FEATURE_NAMES}
        # Rows that would be dropped by the filter when enabled.
        rows = [
            {**base, "decrypt_failure_rate": 0.0, LABEL_COLUMN: "mitm"},
            {**base, "duplicate_payload_count": 0.0, LABEL_COLUMN: "replay"},
            {**base, LABEL_COLUMN: "normal"},
        ]
        csv_path = _make_csv(n=30)  # need a valid CSV on disk for train_from_csv
        # Construct a minimal synthetic CSV that has the no-signal rows
        df_raw = pd.DataFrame(rows)
        # Pad to 30 rows so stratified split works (need ≥1 of each class)
        extra = _make_csv.__wrapped__ if hasattr(_make_csv, "__wrapped__") else None
        # Build a proper CSV via the helper and overwrite with our rows
        import tempfile as _tf
        rng = np.random.default_rng(0)
        all_rows = []
        for lbl in ("normal", "mitm", "replay"):
            for _ in range(10):
                feat = {name: float(rng.uniform(0, 1)) for name in FEATURE_NAMES}
                # Zero out the signal columns for attack rows to trigger the filter
                if lbl == "mitm":
                    feat["decrypt_failure_rate"] = 0.0
                if lbl == "replay":
                    feat["duplicate_payload_count"] = 0.0
                feat[LABEL_COLUMN] = lbl
                all_rows.append(feat)
        df_noisy = pd.DataFrame(all_rows)
        with _tf.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            df_noisy.to_csv(f.name, index=False)
            path = f.name

        # With filter ON: attack rows with zero signal should be dropped
        bundle_filtered = train_from_csv(path, test_size=0.2, random_state=0,
                                         filter_rows=True, verbose=False)
        self.assertTrue(bundle_filtered["filter_applied"])

        # With filter OFF: all 30 rows remain
        bundle_raw = train_from_csv(path, test_size=0.2, random_state=0,
                                    filter_rows=False, verbose=False)
        self.assertFalse(bundle_raw["filter_applied"])
        self.assertEqual(bundle_raw["n_samples"], 30)

    def test_filter_applied_field_in_bundle(self):
        path = _make_csv(n=30)
        bundle_on = train_from_csv(path, test_size=0.2, random_state=0,
                                   filter_rows=True, verbose=False)
        bundle_off = train_from_csv(path, test_size=0.2, random_state=0,
                                    filter_rows=False, verbose=False)
        self.assertIn("filter_applied", bundle_on)
        self.assertTrue(bundle_on["filter_applied"])
        self.assertFalse(bundle_off["filter_applied"])


if __name__ == "__main__":
    unittest.main()
