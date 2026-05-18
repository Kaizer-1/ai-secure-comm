"""Offline Random-Forest IDS trainer.

Phase-4A deliverable.  Loads the labelled feature CSV produced by
`data/generate_training_data.py`, fits a RandomForestClassifier, and
writes the trained model + the metadata Phase-4B needs to use it
correctly (column order, label-encoder mapping, training timestamp,
test accuracy) to disk via joblib.

This module is **standalone** — it imports nothing from the live
runtime (no `core.peer_link`, no Flask).  Phase-4B's live classifier
will be a separate module that loads what this script produced.

Usage:

    python ai/ids_train.py
    python ai/ids_train.py --input data/training_data.csv \\
                           --output ai/trained_model.pkl \\
                           --test-size 0.2 --random-state 42

Programmatic:

    from ai.ids_train import train_from_csv
    bundle = train_from_csv("data/training_data.csv")
    bundle["model"].predict([[…]])    # 10 features, ordering per
                                       # bundle["feature_names"]
"""

from __future__ import annotations

import argparse
import datetime as _dt
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder


# ---------------------------------------------------------------------------
# Defaults — top-level constants so CLI flags and tests can reach them.
# ---------------------------------------------------------------------------
DEFAULT_INPUT = "data/training_data.csv"
DEFAULT_OUTPUT = "ai/trained_model.pkl"
DEFAULT_TEST_SIZE = 0.2
DEFAULT_RANDOM_STATE = 42

#: Hyperparameters.  Phase 4A's spec asks for these defaults; future
#: tuning can override at the CLI but no grid-search loop here.
RF_HYPERPARAMS: Dict[str, Any] = {
    "n_estimators": 100,
    "max_depth": None,
    "min_samples_split": 2,
    "min_samples_leaf": 1,
    "class_weight": "balanced",  # labels are imbalanced (~50/25/25)
    # `random_state` is set per-call from the CLI / function arg.
    "n_jobs": -1,                 # use all cores; trees are independent
}

#: Canonical feature schema.  Authoritative copy lives in
#: `ai.feature_extractor.FEATURE_NAMES`; we duplicate it here to keep
#: this script importable without pulling the rest of the project.
#: A startup check (`_assert_columns_present`) verifies the CSV has
#: every name in this list, so a drift between the two is caught
#: immediately at training time, not silently at predict time.
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
LABEL_COLUMN = "label"

#: When True, rows labelled `mitm` with ``decrypt_failure_rate == 0`` and
#: rows labelled `replay` with ``duplicate_payload_count == 0`` are dropped
#: before the train/test split.  These rows are attacker-perspective
#: observations: the attacker's process never sees the receiver-side anomaly
#: signals, so the features look identical to normal traffic even though the
#: label says otherwise.  Keeping them degrades recall for both attack classes.
#: Set to False (or pass ``--no-filter`` on the CLI) to train on raw data.
FILTER_ATTACK_ROWS_BY_SIGNAL: bool = True


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def _assert_columns_present(df: pd.DataFrame) -> None:
    """Fail fast with a concrete error message if the CSV is missing
    feature or label columns.  Silently mismatched columns are a
    classic source of silent ML bugs; we kill them at the front door."""
    expected = set(FEATURE_NAMES + [LABEL_COLUMN])
    missing = expected - set(df.columns)
    if missing:
        raise ValueError(
            f"training CSV is missing required columns: "
            f"{sorted(missing)}.  Expected at minimum "
            f"{sorted(expected)}; saw {sorted(df.columns)}."
        )


def _drop_nan_rows(df: pd.DataFrame) -> pd.DataFrame:
    """Drop rows containing any NaN; log the count if anything was
    removed.  No silent imputation — if the feature pipeline produced
    a NaN, that's a bug to investigate, not a value to fudge."""
    cols = FEATURE_NAMES + [LABEL_COLUMN]
    before = len(df)
    df = df.dropna(subset=cols).reset_index(drop=True)
    dropped = before - len(df)
    if dropped:
        logger.warning("dropped %d rows containing NaN values", dropped)
    return df


def _filter_attack_rows_by_signal(df: pd.DataFrame, verbose: bool = True) -> pd.DataFrame:
    """Drop attack-labelled rows that carry zero receiver-side attack signal.

    Rows labelled `mitm` with ``decrypt_failure_rate == 0`` and rows labelled
    `replay` with ``duplicate_payload_count == 0`` are attacker-perspective
    observations: the attacking process never sees its own ``InvalidTag`` or
    its own replay duplicates, so the feature vector is indistinguishable from
    normal even though the label says otherwise.  Keeping these rows degrades
    classifier recall for both attack classes.

    ALL rows labelled `normal` are kept unchanged.
    """
    before_counts = df[LABEL_COLUMN].value_counts().to_dict()

    mitm_mask = (df[LABEL_COLUMN] == "mitm") & (df["decrypt_failure_rate"] == 0)
    replay_mask = (df[LABEL_COLUMN] == "replay") & (df["duplicate_payload_count"] == 0)
    drop_mask = mitm_mask | replay_mask

    df_filtered = df[~drop_mask].reset_index(drop=True)
    after_counts = df_filtered[LABEL_COLUMN].value_counts().to_dict()

    if verbose:
        before_str = "  ".join(
            f"{lbl}={before_counts.get(lbl, 0)}"
            for lbl in sorted(before_counts)
        )
        after_str = "  ".join(
            f"{lbl}={after_counts.get(lbl, 0)}"
            for lbl in sorted(before_counts)
        )
        dropped_mitm = before_counts.get("mitm", 0) - after_counts.get("mitm", 0)
        dropped_replay = before_counts.get("replay", 0) - after_counts.get("replay", 0)
        print(
            "Filter: dropping attack-labeled rows with zero attack signal\n"
            f"  Before: {before_str}  (total {len(df)})\n"
            f"  After:  {after_str}  (total {len(df_filtered)})\n"
            f"  Dropped: mitm={dropped_mitm}  replay={dropped_replay}"
        )

    return df_filtered


def _encode_labels(y_str: pd.Series) -> tuple[np.ndarray, Dict[str, int]]:
    """LabelEncoder produces deterministic int labels in the order
    they're encountered in `classes_`.  We preserve that mapping in
    metadata so Phase-4B can decode predictions back to strings
    without re-fitting the encoder."""
    le = LabelEncoder()
    y = le.fit_transform(y_str)
    mapping = {cls: int(idx) for idx, cls in enumerate(le.classes_)}
    return y, mapping


# ---------------------------------------------------------------------------
# Main training entry point (importable + invoked by CLI).
# ---------------------------------------------------------------------------


def train_from_csv(
    input_path: str = DEFAULT_INPUT,
    *,
    test_size: float = DEFAULT_TEST_SIZE,
    random_state: int = DEFAULT_RANDOM_STATE,
    hyperparams: Optional[Dict[str, Any]] = None,
    filter_rows: bool = FILTER_ATTACK_ROWS_BY_SIGNAL,
    verbose: bool = True,
) -> Dict[str, Any]:
    """Train a Random Forest on `input_path` and return a bundle dict.

    The returned dict has the exact shape `train_and_save` writes to
    disk.  Tests use this directly without going through the CLI.

    Parameters
    ----------
    filter_rows:
        When True (default), drops attack-labelled rows that contain no
        receiver-side attack signal before the train/test split.  Pass
        False to train on the raw unfiltered CSV.

    Returns
    -------
    bundle : dict
        ``model``: fitted ``RandomForestClassifier``
        ``feature_names``: list (canonical feature order)
        ``label_encoder``: dict ``{class_name: int_id}``
        ``trained_on``: input CSV path (str)
        ``trained_at``: ISO-8601 timestamp
        ``n_samples``: total rows used (post-filter, post-NaN-drop)
        ``test_accuracy``: float in [0, 1]
        ``test_size``, ``random_state``, ``hyperparams``: reproducibility
        ``filter_applied``: bool — whether signal-based filtering was used
    """
    df = pd.read_csv(input_path)
    _assert_columns_present(df)
    df = _drop_nan_rows(df)
    if filter_rows:
        df = _filter_attack_rows_by_signal(df, verbose=verbose)

    X = df[FEATURE_NAMES].astype(float)   # DataFrame, not numpy — preserves column names for model.feature_names_in_
    y_str = df[LABEL_COLUMN].astype(str)
    y, label_mapping = _encode_labels(y_str)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size,
        stratify=y, random_state=random_state,
    )

    params = dict(RF_HYPERPARAMS)
    if hyperparams:
        params.update(hyperparams)
    params["random_state"] = random_state

    model = RandomForestClassifier(**params)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    test_accuracy = float(accuracy_score(y_test, y_pred))
    # `target_names` decodes the int classes back to label strings so
    # the printed report is human-readable.
    target_names = sorted(label_mapping, key=lambda k: label_mapping[k])
    report_text = classification_report(
        y_test, y_pred, target_names=target_names, zero_division=0,
    )

    if verbose:
        print()
        print("=" * 72)
        print("Random Forest IDS — training report")
        print("=" * 72)
        print(f"  input      : {input_path}")
        print(f"  rows used  : {len(df)} ({len(X_train)} train / "
              f"{len(X_test)} test, test_size={test_size})")
        print(f"  classes    : {target_names}")
        print(f"  hyperparams: {params}")
        print()
        print(f"  test accuracy: {test_accuracy:.4f}")
        print()
        print(report_text)

        importances = sorted(
            zip(FEATURE_NAMES, model.feature_importances_),
            key=lambda kv: kv[1], reverse=True,
        )
        print("  top-10 feature importances:")
        for name, imp in importances[:10]:
            bar = "█" * int(round(imp * 50))
            print(f"    {name:>26s}  {imp:.4f}  {bar}")
        print("=" * 72)

    return {
        "model": model,
        "feature_names": list(FEATURE_NAMES),
        "label_encoder": label_mapping,
        "trained_on": str(input_path),
        "trained_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "n_samples": int(len(df)),
        "test_accuracy": test_accuracy,
        "test_size": float(test_size),
        "random_state": int(random_state),
        "hyperparams": params,
        "filter_applied": bool(filter_rows),
    }


def train_and_save(
    input_path: str = DEFAULT_INPUT,
    output_path: str = DEFAULT_OUTPUT,
    *,
    test_size: float = DEFAULT_TEST_SIZE,
    random_state: int = DEFAULT_RANDOM_STATE,
    filter_rows: bool = FILTER_ATTACK_ROWS_BY_SIGNAL,
    verbose: bool = True,
) -> Dict[str, Any]:
    """Train + persist to disk.  Returns the in-memory bundle as well
    so callers can inspect the model without re-loading."""
    bundle = train_from_csv(
        input_path, test_size=test_size, random_state=random_state,
        filter_rows=filter_rows, verbose=verbose,
    )
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, out)
    if verbose:
        print(f"saved trained model to {out}")
    return bundle


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Train a Random Forest IDS on the Phase-3 labelled feature "
            "CSV and persist it for the Phase-4B live classifier."
        ),
    )
    parser.add_argument(
        "--input", default=DEFAULT_INPUT,
        help="Path to the training CSV "
             f"(default: {DEFAULT_INPUT}).",
    )
    parser.add_argument(
        "--output", default=DEFAULT_OUTPUT,
        help="Where to save the trained model bundle "
             f"(default: {DEFAULT_OUTPUT}).",
    )
    parser.add_argument(
        "--test-size", type=float, default=DEFAULT_TEST_SIZE,
        help="Fraction of rows held out for evaluation "
             f"(default: {DEFAULT_TEST_SIZE}).",
    )
    parser.add_argument(
        "--random-state", type=int, default=DEFAULT_RANDOM_STATE,
        help="Random seed for the train/test split and the forest "
             f"(default: {DEFAULT_RANDOM_STATE}).",
    )
    parser.add_argument(
        "--no-filter", action="store_true", default=False,
        help="Disable the training-time filter that drops attack-labelled "
             "rows with zero receiver-side signal.  Useful for inspecting "
             "raw-data performance or debugging the filter itself.",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    train_and_save(
        input_path=args.input,
        output_path=args.output,
        test_size=args.test_size,
        random_state=args.random_state,
        filter_rows=not args.no_filter,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
