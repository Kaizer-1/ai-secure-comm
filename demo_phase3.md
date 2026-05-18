# Phase 3 Demo Walkthrough

End-to-end demo flow once Phase 3 is built.  Use this as both a
live-demo script and a smoke-test checklist before declaring
Phase 3 complete.

## Prerequisites

```bash
cd ai_secure_comm
source .venv/bin/activate
pip install -r requirements.txt
python -m unittest discover tests          # 122 tests should pass
```

If the test suite is green, the cryptographic core, the network
layer, the attack simulators, and the feature extractor are all
working.  This walkthrough exercises the live UI on top.

---

## Part 1 — Baseline (Phase 2 still works)

```bash
python launcher_dev.py
```

Two browser tabs open at <http://127.0.0.1:5001/> (alice) and
<http://127.0.0.1:5002/> (bob).  Both show the role headers, both
sync within ~1 s, both display matching key fingerprints.  Send a
few messages back and forth; toggle the wire-view panel to confirm
ciphertext flows.  This is the Phase 2 baseline; if anything here
breaks, stop and debug *before* attacking.

---

## Part 2 — MITM attack

1. Click into alice's tab.  Press **Ctrl+Shift+D** (Cmd+Shift+D on
   Mac).  A red/orange overlay appears in the top-right:

   > Demo Controls — Adversarial Simulation
   > [Launch MITM] [Launch Replay] [Stop All Attacks]
   > no attacks active

2. Click **Launch MITM**.  The status row updates to:

   > ● mitm active
   > mitm: tampered 0/0 (target 30%)

3. Send 10 messages from alice → bob.  In bob's tab, **most**
   messages arrive normally, but **roughly 30%** appear as a
   distinct red/orange-bordered bubble:

   > ⚠ Tampered ciphertext rejected
   > AES-GCM authentication failed · 47 bytes
   > [hex preview: 04ccbe0e6a1f…]

   The wire-view panel on the right shows the same ciphertext with
   a red `✗ rejected` marker and a strikethrough — the audience
   sees both *the bytes that arrived on the network* AND *the
   security layer catching them*.  In alice's demo panel:

   > mitm: tampered 3/10 (target 30%)

   This is exactly the IDS signal — Phase 4's model will key on
   the elevated `decrypt_failure_rate` in bob's feature window.

4. Click **Stop All Attacks**.  The next batch of messages flow
   through clean.  Recovery is immediate — no sync re-handshake
   needed; the AES key is unchanged.

---

## Part 3 — Replay attack

1. Still in alice's panel, click **Launch Replay**.  Status row:

   > ● replay active
   > replay: buffered 0, replayed 0, every 3.0s

2. Send 5 messages from alice → bob.  Each message is captured into
   a 5-slot buffer on alice's side.  Within ~3 s, bob starts
   receiving **duplicate chat bubbles** — the same plaintext bob
   already received now arrives a second time.  The duplicate
   bubble is rendered identically to the original except for an
   italic footnote:

   > ↻ duplicate of earlier message at HH:MM:SS

   This is the demo's punchline for replay: AES-GCM lets the
   bytes through (same key, same ciphertext, kind-only AAD —
   *the cryptographic layer cannot tell* this is a replay), but
   the IDS in Phase 4 will flag the duplicate via
   `duplicate_payload_count`.  The wire-view panel shows the
   same hex twice on the inbound side, confirming the wire
   really did carry the same bytes again.

   In alice's demo panel:

   > replay: buffered 5, replayed 4, every 3.0s

3. Click **Stop All Attacks**.  Replay stops immediately.

---

## Part 4 — Both at once

(Optional, for the "examiner pushes back" case.)

Click **Launch MITM** then **Launch Replay**.  Both attacks run
concurrently — bob's chat log fills with a mix of decrypt-failure
bubbles and duplicate ciphertext entries.  This is what the
Phase-4 model will be trained to disambiguate.

Click **Stop All Attacks** to clean up.

---

## Part 5 — Generate the training dataset

In a separate terminal (the launcher can keep running):

```bash
python data/generate_training_data.py --sessions 200 \
    --output data/training_data.csv
```

Progress prints every 10 sessions.  Total runtime ≈ 2–3 min on a
laptop.  Output:

```
[ 200/200] sessions run; rows=1834  normal=920  mitm=470  replay=444  fails=0
wrote 1834 rows to data/training_data.csv
  normal: 920
  mitm:   470
  replay: 444
```

Inspect the CSV:

```bash
head -3 data/training_data.csv
wc -l data/training_data.csv
```

You should see the 12-column header (10 features + label +
session_id) and ≥ 1000 data rows.  Per-label feature stats can be
spot-checked with:

```bash
python -c "
import csv, statistics
from collections import defaultdict
rows = defaultdict(list)
with open('data/training_data.csv') as f:
    for r in csv.DictReader(f):
        rows[r['label']].append(r)
for l in ('normal', 'mitm', 'replay'):
    df = [float(r['decrypt_failure_rate']) for r in rows[l]]
    dup = [float(r['duplicate_payload_count']) for r in rows[l]]
    print(f'{l:8} n={len(rows[l]):4}  '
          f'fail mean={statistics.mean(df):.3f}  '
          f'dup mean={statistics.mean(dup):.2f}')
"
```

Expected separation (numbers will vary slightly under different RNG
seeds, but the ordering should be stable):

| Label  | decrypt_failure_rate | duplicate_payload_count |
| ---    | ---                  | ---                     |
| normal | ~0                   | ~0                      |
| mitm   | ~0.10–0.20           | ~0                      |
| replay | ~0.30–0.45           | ~1.0–1.5                |

Both signals are non-trivial enough that a Random Forest can learn
them but not so on-the-nose that the model is overfit to a single
threshold.  Phase 4 will train on this CSV.

---

## Part 6 — Cleanup

Ctrl+C the launcher.  Both Flask processes shut down; the demo
panel state is in-process only and is dropped with the processes.

---

## Known boundaries (do NOT debug as Phase 3 bugs)

- **No threat alert UI** in chat yet — the `threat_alert` SocketIO
  event is a no-op stub; Phase 4 wires it.
- **No model training** — `data/training_data.csv` exists, but
  there is no classifier yet.
- **Sender-side feature rows look like normal even when attacked**
  (because the sender doesn't see decrypt failures).  This is
  intentional — the IDS in Phase 4 will be the receiver's
  perspective only.  Both perspectives are kept in the CSV so the
  model can learn that some labelled rows look identical to
  normal — a property a real IDS has to handle.
- **Demo controls won't appear** if `config.DEMO_MODE` is `False`
  (which it isn't, by default for the project).
- **Pressing Ctrl/Shift/D outside the chat tab** does nothing —
  the listener only fires on focused chat tabs.

If any step above fails on a fresh checkout, that *is* a Phase 3
bug — fix it before declaring Phase 3 complete.
