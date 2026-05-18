"""Generate labelled training data for the Phase-4 Random Forest IDS.

Runs many short alice↔bob sessions back-to-back on 127.0.0.1, each
labelled `normal` / `mitm` / `replay`.  Each session captures
periodic feature snapshots (whatever PeerLink's `on_features_updated`
callback emits) and appends one CSV row per snapshot, plus the
session label.

Usage:

    python data/generate_training_data.py --sessions 200 \\
        --output data/training_data.csv

Output columns: every name in `ai.feature_extractor.FEATURE_NAMES`
(in canonical order) followed by `label` and `session_id`.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import random
import socket
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import List, Optional

# Make the project root (the dir containing config.py) importable even
# when this script is run from anywhere.
_HERE = Path(__file__).resolve().parent
_PROJECT_ROOT = _HERE.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import config
from ai.feature_extractor import FEATURE_NAMES
from attacks.mitm import MITMAttack
from attacks.replay import ReplayAttack
from core.peer_link import PeerLink


logger = logging.getLogger(__name__)

CSV_COLUMNS: List[str] = list(FEATURE_NAMES) + ["label", "session_id"]
LABELS = ("normal", "mitm", "replay")
LABEL_WEIGHTS = (0.50, 0.25, 0.25)


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _random_message(rng: random.Random, min_len: int = 4, max_len: int = 80) -> str:
    """Generate a randomised plausible chat-message string.

    Mixed alphanumeric content keeps payload sizes varied without
    introducing trivial patterns the model could overfit to.
    """
    n = rng.randint(min_len, max_len)
    alphabet = "abcdefghijklmnopqrstuvwxyz "
    return "".join(rng.choice(alphabet) for _ in range(n))


def _run_session(
    *,
    session_id: str,
    label: str,
    rng: random.Random,
    log_dir: Optional[Path] = None,
) -> List[dict]:
    """Run one session; return the list of feature snapshots captured.

    Each snapshot is the dict that `FeatureExtractor.extract_features`
    returned, plus the session label and id.
    """
    port = _free_port()

    # Each side gets its own PeerLink object, sharing only the TCP port.
    alice = PeerLink(
        role=config.ROLE_A,
        bind_host="127.0.0.1",
        peer_host="127.0.0.1",
        peer_port=port,
        initiator_role=config.ROLE_A,
        connect_timeout=10.0,
    )
    bob = PeerLink(
        role=config.ROLE_B,
        bind_host="127.0.0.1",
        peer_host="127.0.0.1",
        peer_port=port,
        initiator_role=config.ROLE_A,
        connect_timeout=10.0,
    )

    # We collect snapshots from BOTH sides.  Receiver-side snapshots
    # carry the decrypt-failure-rate signal that MITM lights up;
    # sender-side snapshots carry the buffer/replay signature.
    snapshots: List[dict] = []
    snapshots_lock = threading.Lock()

    def make_capture(role: str):
        def cb(features: dict) -> None:
            row = {**features, "label": label,
                   "session_id": session_id, "_observer": role}
            with snapshots_lock:
                snapshots.append(row)
        return cb

    alice.on_features_updated = make_capture(config.ROLE_A)
    bob.on_features_updated = make_capture(config.ROLE_B)

    # Non-fatal callback bin for sync-completed detection.
    alice_sync = threading.Event()
    bob_sync = threading.Event()
    alice.on_sync_complete = lambda *_: alice_sync.set()
    bob.on_sync_complete = lambda *_: bob_sync.set()

    # Quietly suppress decrypt-failure errors that MITM produces.
    alice.on_error = lambda exc: None
    bob.on_error = lambda exc: None

    ta = threading.Thread(target=alice.connect, daemon=True)
    tb = threading.Thread(target=bob.connect, daemon=True)
    ta.start()
    time.sleep(0.05)  # tiny stagger so listener binds first
    tb.start()

    if not (alice_sync.wait(20.0) and bob_sync.wait(20.0)):
        alice.close(); bob.close()
        raise RuntimeError(f"session {session_id} failed to sync")

    ta.join(timeout=5.0)
    tb.join(timeout=5.0)

    # Now register the labelled attack (if any) on alice's side.
    attack = None
    try:
        if label == "mitm":
            attack = MITMAttack(
                tamper_probability=config.MITM_TAMPER_PROBABILITY,
                rng_seed=rng.randrange(1 << 31),
            )
        elif label == "replay":
            attack = ReplayAttack(
                buffer_size=config.REPLAY_BUFFER_SIZE,
                # Tighten the interval a bit for training so the
                # replay signal fires often enough in the short
                # session window.
                interval_s=max(0.4, config.REPLAY_INTERVAL_S / 5),
                rng_seed=rng.randrange(1 << 31),
            )
        if attack is not None:
            alice.attack_registry.register(attack)
            attack.start()

        # Send a randomised burst of chat from alice → bob.  The
        # replay attack's interval is much shorter than the session
        # window, so it will fire several times.
        n_msgs = rng.randint(15, 35)
        for _ in range(n_msgs):
            try:
                alice.send_chat(_random_message(rng))
            except Exception:  # noqa: BLE001
                break
            time.sleep(rng.uniform(0.05, 0.20))

        # Brief tail so any in-flight replay injections land + their
        # decrypt failures (if MITM) get recorded.
        time.sleep(0.5)
    finally:
        if attack is not None:
            try:
                attack.stop()
            except Exception:  # noqa: BLE001
                pass
        alice.close()
        bob.close()

    # Persist raw snapshot dump if a log dir is given.
    if log_dir is not None:
        log_dir.mkdir(parents=True, exist_ok=True)
        out = {
            "session_id": session_id,
            "label": label,
            "snapshots": snapshots,
        }
        (log_dir / f"session_{session_id}.json").write_text(
            json.dumps(out, separators=(",", ":")) + "\n"
        )

    return snapshots


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run many alice↔bob sessions and write labelled feature "
            "rows to a CSV the Phase-4 IDS will train on."
        ),
    )
    parser.add_argument(
        "--sessions", type=int, default=200,
        help="Number of sessions to run (default: 200).",
    )
    parser.add_argument(
        "--output", type=str, default="data/training_data.csv",
        help="Path to the output CSV (default: data/training_data.csv).",
    )
    parser.add_argument(
        "--seed", type=int, default=None,
        help="RNG seed for reproducible label / message choices.  "
             "Per-session attack RNGs derive from this seed.",
    )
    parser.add_argument(
        "--save-logs", action="store_true",
        help="Also write per-session JSON logs to data/training_logs/.",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    rng = random.Random(args.seed)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    log_dir = (
        output_path.parent / "training_logs"
        if args.save_logs else None
    )

    # Open the CSV in write mode (overwrite any existing file — this
    # script always produces a fresh dataset).
    with output_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS,
                                extrasaction="ignore")
        writer.writeheader()

        total_rows = 0
        per_label = {l: 0 for l in LABELS}
        failures = 0

        for i in range(1, args.sessions + 1):
            session_id = uuid.uuid4().hex[:12]
            label = rng.choices(LABELS, weights=LABEL_WEIGHTS, k=1)[0]
            try:
                rows = _run_session(
                    session_id=session_id,
                    label=label,
                    rng=rng,
                    log_dir=log_dir,
                )
            except Exception as exc:  # noqa: BLE001
                failures += 1
                print(f"  session {i} ({label}) failed: {exc}",
                      file=sys.stderr)
                continue

            for row in rows:
                writer.writerow(row)
                total_rows += 1
                per_label[label] += 1

            if i % 10 == 0 or i == args.sessions:
                print(
                    f"[{i:>4}/{args.sessions}] sessions run; "
                    f"rows={total_rows}  "
                    f"normal={per_label['normal']}  "
                    f"mitm={per_label['mitm']}  "
                    f"replay={per_label['replay']}  "
                    f"fails={failures}"
                )

    print()
    print(f"wrote {total_rows} rows to {output_path}")
    print(f"  normal: {per_label['normal']}")
    print(f"  mitm:   {per_label['mitm']}")
    print(f"  replay: {per_label['replay']}")
    if failures:
        print(f"  failures: {failures} / {args.sessions} sessions")
    return 0 if total_rows > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
