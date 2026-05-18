"""Offline IDS training-report generator.

Phase-4A deliverable.  Loads the trained model bundle produced by
`ai/ids_train.py`, re-runs the same 80/20 split (using the stored
random_state so the test set is identical to the one the trainer
held out), and writes four artefacts to a report directory:

    confusion_matrix.png      — annotated heatmap
    feature_importances.png   — horizontal bar chart (top 10)
    classification_report.txt — per-class precision / recall / F1
    model_summary.txt         — hyperparams, sizes, accuracy, macro F1

Usage:

    python ai/ids_report.py
    python ai/ids_report.py --model ai/trained_model.pkl \\
                            --input data/training_data.csv \\
                            --output ai/report/
"""

from __future__ import annotations

import argparse
import datetime as _dt
import sys
from pathlib import Path
from typing import List, Optional

import joblib
import matplotlib
matplotlib.use("Agg")  # headless — no display needed
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.model_selection import train_test_split



DEFAULT_MODEL = "ai/trained_model.pkl"
DEFAULT_INPUT = "data/training_data.csv"
DEFAULT_OUTPUT = "ai/report/"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sorted_label_names(label_encoder: dict) -> List[str]:
    """Return class names sorted by their encoded integer id."""
    return sorted(label_encoder, key=lambda k: label_encoder[k])


def _rebuild_test_set(bundle: dict, input_path: str):
    """Re-create the held-out test set that matches the trained model.

    Uses the random_state and test_size stored in the bundle so the
    confusion matrix reflects the exact split the trainer held out,
    not a fresh random draw.  When the bundle was trained with
    ``filter_applied=True``, the same signal-based filter is applied
    before splitting so the test rows come from the same distribution
    the model was trained on.
    """
    df = pd.read_csv(input_path)
    feature_names = bundle["feature_names"]
    label_encoder = bundle["label_encoder"]

    # Drop NaN rows first (mirrors the trainer).
    df = df.dropna(subset=feature_names + ["label"]).reset_index(drop=True)

    # Apply the same filter the trainer used, if any.
    # Logic mirrors ai/ids_train._filter_attack_rows_by_signal exactly.
    if bundle.get("filter_applied", False):
        drop = (
            ((df["label"] == "mitm") & (df["decrypt_failure_rate"] == 0))
            | ((df["label"] == "replay") & (df["duplicate_payload_count"] == 0))
        )
        df = df[~drop].reset_index(drop=True)

    X = df[feature_names].astype(float)   # DataFrame — column names match model.feature_names_in_
    y_str = df["label"].astype(str)

    # Encode labels to ints using the stored mapping.
    y = np.array([label_encoder[v] for v in y_str])

    _, X_test, _, y_test = train_test_split(
        X, y,
        test_size=bundle["test_size"],
        stratify=y,
        random_state=bundle["random_state"],
    )
    return X_test, y_test


# ---------------------------------------------------------------------------
# Report generators
# ---------------------------------------------------------------------------


def _write_confusion_matrix(
    y_test: np.ndarray,
    y_pred: np.ndarray,
    label_names: List[str],
    out_path: Path,
) -> None:
    cm = confusion_matrix(y_test, y_pred)

    fig = plt.figure(figsize=(8, 6))
    ax = fig.add_subplot(111)

    im = ax.imshow(cm, interpolation="nearest", cmap="Blues")
    fig.colorbar(im, ax=ax)

    ax.set_xticks(range(len(label_names)))
    ax.set_yticks(range(len(label_names)))
    ax.set_xticklabels(label_names, rotation=45, ha="right")
    ax.set_yticklabels(label_names)
    ax.set_xlabel("Predicted label")
    ax.set_ylabel("True label")
    ax.set_title("IDS Confusion Matrix (held-out test set)")

    # Annotate each cell with its count.
    thresh = cm.max() / 2.0
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(
                j, i, str(cm[i, j]),
                ha="center", va="center",
                color="white" if cm[i, j] > thresh else "black",
            )

    fig.tight_layout()
    plt.savefig(out_path)
    plt.close(fig)


def _write_feature_importances(
    feature_names: List[str],
    importances: np.ndarray,
    out_path: Path,
) -> None:
    pairs = sorted(zip(feature_names, importances), key=lambda kv: kv[1])
    names = [p[0] for p in pairs]
    values = [p[1] for p in pairs]

    fig = plt.figure(figsize=(8, 5))
    ax = fig.add_subplot(111)
    ax.barh(names, values)
    ax.set_xlabel("Mean decrease in impurity (feature importance)")
    ax.set_title("Random Forest — Feature Importances (top 10)")
    fig.tight_layout()
    plt.savefig(out_path)
    plt.close(fig)


def _write_classification_report(
    y_test: np.ndarray,
    y_pred: np.ndarray,
    label_names: List[str],
    out_path: Path,
) -> str:
    report = classification_report(
        y_test, y_pred, target_names=label_names, zero_division=0,
    )
    out_path.write_text(report, encoding="utf-8")
    return report


def _write_model_summary(
    bundle: dict,
    n_train: int,
    n_test: int,
    y_test: np.ndarray,
    y_pred: np.ndarray,
    label_names: List[str],
    out_path: Path,
) -> None:
    macro_f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)
    lines = [
        "IDS Model Summary",
        "=" * 60,
        f"trained_at     : {bundle.get('trained_at', 'n/a')}",
        f"trained_on     : {bundle.get('trained_on', 'n/a')}",
        f"n_samples      : {bundle.get('n_samples', 'n/a')}",
        f"n_train        : {n_train}",
        f"n_test         : {n_test}",
        f"test_size      : {bundle.get('test_size', 'n/a')}",
        f"random_state   : {bundle.get('random_state', 'n/a')}",
        "",
        "Hyperparameters",
        "-" * 60,
    ]
    for k, v in sorted(bundle.get("hyperparams", {}).items()):
        lines.append(f"  {k:<24s}: {v}")
    lines += [
        "",
        "Evaluation (held-out test set)",
        "-" * 60,
        f"  accuracy       : {bundle.get('test_accuracy', 0.0):.4f}",
        f"  macro F1       : {macro_f1:.4f}",
        "",
        "Classes",
        "-" * 60,
    ]
    label_encoder = bundle.get("label_encoder", {})
    for name in label_names:
        lines.append(f"  {label_encoder[name]}  {name}")
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def generate_report(
    model_path: str = DEFAULT_MODEL,
    input_path: str = DEFAULT_INPUT,
    output_dir: str = DEFAULT_OUTPUT,
) -> List[str]:
    """Generate all report artefacts.  Returns list of created file paths."""
    bundle = joblib.load(model_path)
    model = bundle["model"]
    feature_names = bundle["feature_names"]
    label_encoder = bundle["label_encoder"]
    label_names = _sorted_label_names(label_encoder)

    X_test, y_test = _rebuild_test_set(bundle, input_path)
    y_pred = model.predict(X_test)

    n_total = bundle.get("n_samples", len(X_test))
    n_test = len(X_test)
    n_train = n_total - n_test

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    cm_path = out / "confusion_matrix.png"
    fi_path = out / "feature_importances.png"
    cr_path = out / "classification_report.txt"
    ms_path = out / "model_summary.txt"

    _write_confusion_matrix(y_test, y_pred, label_names, cm_path)
    _write_feature_importances(feature_names, model.feature_importances_, fi_path)
    _write_classification_report(y_test, y_pred, label_names, cr_path)
    _write_model_summary(bundle, n_train, n_test, y_test, y_pred, label_names, ms_path)

    created = [str(cm_path), str(fi_path), str(cr_path), str(ms_path)]

    print()
    print("IDS report generated successfully.")
    print(f"  output directory : {out.resolve()}")
    for p in created:
        print(f"  {p}")

    return created


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate evaluation report for the trained IDS model.",
    )
    parser.add_argument(
        "--model", default=DEFAULT_MODEL,
        help=f"Path to the trained model bundle (default: {DEFAULT_MODEL}).",
    )
    parser.add_argument(
        "--input", default=DEFAULT_INPUT,
        help=f"Path to the training CSV (default: {DEFAULT_INPUT}).",
    )
    parser.add_argument(
        "--output", default=DEFAULT_OUTPUT,
        help=f"Output directory for report artefacts (default: {DEFAULT_OUTPUT}).",
    )
    args = parser.parse_args(argv)
    generate_report(
        model_path=args.model,
        input_path=args.input,
        output_dir=args.output,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
