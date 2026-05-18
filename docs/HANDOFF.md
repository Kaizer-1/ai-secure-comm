# Handoff Document
Last updated: 2026-05-17 (Phase 5A complete — performance metrics dashboard)

## Project in 30 seconds
A 5-phase college project showing secure two-device communication: Tree
Parity Machines exchange a key through mutual learning, AES-256-GCM
encrypts the traffic, and a Random Forest IDS flags MITM / replay
anomalies.  Phases 1–3 complete: cryptographic foundation, real
network + chat UI + file transfer, and now attack simulators with a
labelled training dataset for the IDS.  Two browser tabs (dev mode)
or two laptops (demo mode) sync TPMs over real TCP, exchange
encrypted chat, drag-and-drop files, and (with Ctrl+Shift+D) launch
in-process MITM / Replay attacks against the live channel.

## Where we are
Phase: **5A of 5 — complete** (Phases 1–4 all done; 5A done; 5B and 5C pending).
Status: **178/178 unit tests pass (1 skipped)**; `demo_phase1.py` runs
unchanged; [`demo_final.md`](../demo_final.md) is the canonical ~12 min
viva demo guide (now includes §11 metrics dashboard).  The full Phase 1–5A
stack is verified: TPM key exchange, AES-256-GCM chat + file transfer,
MITM/Replay attack simulators, live IDS with threat gauge and alert UI,
end-to-end smoke tests, and a performance metrics dashboard comparing
TPM vs RSA-2048 vs DH-2048 with AES-GCM throughput and IDS detection
latency tracking.

## What works right now
- **Cryptographic core (Phase 1, untouched by Phase 2):**
  - `core/tpm.py` — `TreeParityMachine` with three learning rules,
    deterministic seeding, SHA-256 fingerprint.
  - `core/sync_protocol.py` — three-layer architecture: `SyncTransport`
    (abstract) + `LoopbackTransport` + `SyncSession` + Phase-1
    convenience wrapper `SyncProtocol`.
  - `core/crypto_engine.py` — AES-256-GCM with TPM-derived key,
    `nonce(12) || ct || tag(16)` bundle layout, AAD support.
- **Network layer (Phase 2):**
  - `core/transport_tcp.py` — plain-TCP `SyncTransport` with
    length-prefixed framing.  Frame kinds: TAU/FINGERPRINT/SEED for
    sync; CHAT/FILE_META/FILE_CHUNK/CONTROL for app traffic.  Thread-
    safe sends, `TransportTimeout` on stalls, `PeerDisconnectedError`
    on EOF.  `TCPListener`, `bind_and_accept`, `connect` factories.
  - `core/file_transfer.py` — chunking + AAD helpers.
    `make_file_meta` / `iter_chunks` / `aad_for_chunk` /
    `assemble_chunks` / `verify_sha256`.
  - `core/peer_link.py` — `PeerLink` owns one TCP socket for the
    full session: connect → sync (with progress callbacks) →
    derive key → app-mode reader thread that decrypts and dispatches
    CHAT / FILE_META / FILE_CHUNK / CONTROL frames via callbacks.
- **Web UI (Phase 2):**
  - `app.py` — role-aware Flask + SocketIO entry: `python app.py
    --role alice|bob`.  Wires `PeerLink` callbacks to SocketIO
    events.  Routes for chat page, file upload (button + drag-drop),
    completed-file download, hidden `/_demo` (Phase 3 placeholder).
    **Tracks an explicit session-state machine** (status ∈ {idle,
    syncing, synced, error}) and replays the appropriate event(s)
    to any newly-connected SocketIO client so a browser refresh
    recovers in ~10 ms (no fresh sync, UI immediately re-unlocked).
  - `templates/chat.html`, `static/js/chat.js`, `static/css/style.css`
    — single role-aware template with color-coded role headers,
    connection status dot, key fingerprint badge, two-column chat +
    wire-view layout, **role-themed "Choose file" button + drop zone
    sharing one upload path**.  Tailwind via CDN, no build step.
    Status updates funnel through one `setStatus(state)` helper;
    `setStatus("connecting")` on `connect` is *deferred 500 ms* so
    a late-firing connect handler (post-refresh transport upgrade)
    cannot roll the indicator back from "synchronised" to
    "connecting…" — replay `sync_complete` always cancels the
    deferred write before the user sees it.  Reconnects show a
    subtle "(reconnected — earlier messages not shown)" banner
    because chat history is in-memory only.
  - `launcher_dev.py` — single-command dev mode (spawns both roles,
    opens both browser tabs, forwards subprocess logs).
  - `network_check.py` — demo-day pre-flight.  **alice runs first
    and waits up to 60 s for bob; both sides exchange a
    `NETCHECK_OK\\n` handshake and only then declare success.**
    Exit 0 on full round-trip, 1 otherwise.
- **Phase 4C (threat-detection UI — complete):**
  - `app.py` — `_on_features_updated` callback emits `ids_probabilities`
    SocketIO event `{probabilities, state, active_alert_type,
    active_alert_confidence, timestamp}` on every feature window.
    `state["ids_last_probabilities"]` and `state["ids_last_alert"]` stored
    for reconnect replay.  `on_browser_connect` replays both so a refreshed
    tab immediately sees the current gauge and any active banner.
    Existing `_on_threat_alert` now writes `state["ids_last_alert"]`;
    `_on_threat_cleared` clears it to `None`.
  - `templates/chat.html` — four new `flex-none` strips (all hidden by
    default, revealed progressively): `#ids-status-bar` (gauge, always
    visible after sync), `#threat-banner` (MITM=amber, Replay=rose),
    `#threat-cleared-bar` (3-second green flash), `#history-strip`
    (≤ 5 alert chips).
  - `static/js/chat.js` — `updateGauge`, `showThreatBanner`,
    `hideThreatBanner`, `_showClearedBar`, `addHistoryChip`,
    `finalizeActiveChip`; handlers for `ids_probabilities`,
    `threat_alert`, `threat_cleared`; gauge revealed on `sync_complete`.
  - `static/css/style.css` — `.ids-gauge-fill` (width + colour
    transition), `.ids-gauge-pulse`, `.threat-banner-enter / -exit`,
    `.threat-banner-glow`, `.ids-chip`, pure-CSS `data-tip` tooltip.
  - `tests/test_ids_probabilities.py` — 5 new tests using
    Flask-SocketIO test client + patched PeerLink.
  - **153/153 tests pass** (148 prior + 5 new).
- **Phase 4B (live IDS integration — complete):**
  - `ai/ids_live.py` — `LiveIDS` class.  Loads the saved bundle once at
    startup.  `evaluate(features_dict)` classifies each feature snapshot
    and returns `{state, active_alert, probabilities, observation_count}`.
    State machine: `warming_up` (< 3 windows) → `monitoring` → `alerting`
    with hysteresis (fire ≥ 0.70, clear < 0.50 — 0.20-wide band prevents
    flapping).  `reset()` clears stale state on peer disconnect.
  - `config.py` — `IDS_MODEL_PATH`, `IDS_ALERT_THRESHOLD_FIRE` (0.70),
    `IDS_ALERT_THRESHOLD_CLEAR` (0.50), `IDS_MIN_OBSERVATIONS` (3),
    `IDS_ENABLE` (True).  Set `IDS_ENABLE = False` to disable IDS
    entirely (app behaves as Phase 3).
  - `core/peer_link.py` — `set_ids(ids)` attaches a `LiveIDS` after
    construction; `on_threat_alert` and `on_threat_cleared` callbacks
    added.  `_record_frame` calls `ids.evaluate()` every
    `FEATURE_UPDATE_EVERY` frames; `_handle_ids_state_transition` compares
    new state to previous and fires the appropriate callback.  `ids.reset()`
    called on peer disconnect.  PeerLink works normally with no IDS
    attached (graceful degradation).
  - `app.py` — `LiveIDS` constructed at `create_app` time (one instance per
    process, non-fatal if model is absent).  Attached to `PeerLink` in
    `on_start_sync` after `ids.reset()`.  `on_threat_alert` emits
    `threat_alert` SocketIO event `{type, confidence, probabilities,
    timestamp, features_snapshot}`.  `on_threat_cleared` emits
    `threat_cleared` `{previously_alerting_type, duration_seconds,
    timestamp}`.
  - **148/148 tests pass** (139 prior + 9 new in `test_ids_live.py`).
- **Phase 4A (offline IDS training pipeline — complete):**
  - `ai/ids_train.py` — standalone Random Forest trainer.  Loads
    `data/training_data.csv`, fits 100-tree `RandomForestClassifier`
    (`class_weight="balanced"`), saves a metadata bundle (model,
    feature_names, label_encoder, accuracy, hyperparams, timestamps)
    to `ai/trained_model.pkl` via joblib.  CLI and programmatic API.
  - `ai/ids_report.py` — standalone report generator.  Loads the
    trained bundle, re-splits identically via stored random_state,
    writes `ai/report/confusion_matrix.png`,
    `ai/report/feature_importances.png`,
    `ai/report/classification_report.txt`,
    `ai/report/model_summary.txt`.
  - Training results (post-filter): 1418 rows (1134 train / 284 test),
    accuracy **1.0000**, macro F1 **1.0000**.  A training-time filter
    drops attack-labelled rows with zero receiver-side signal (attacker-
    perspective rows) before the split.  Controlled by
    `FILTER_ATTACK_ROWS_BY_SIGNAL = True` in `ids_train.py` and a
    `--no-filter` CLI flag.  `filter_applied` field in bundle lets
    Phase-4B and the report generator apply the same filter.  See
    DECISIONS.md → "Training-time filter for attacker-perspective rows."
  - `tests/test_ids_train.py` — 8 test methods on synthetic data
    (load/validate CSV, fit, save/load roundtrip, metadata keys,
    imbalanced-class handling).
  - `requirements.txt` updated: `pandas`, `scikit-learn`, `joblib`,
    `matplotlib`.
  - **132/132 tests pass** in ~4 s.
- **Phase 3 (attacks + features + training data + demo UX):**
  - `attacks/` package — `Attack` ABC + per-`TCPTransport`
    `AttackRegistry`; `MITMAttack` (~30% bit-flip on CHAT frames,
    sync frames untouched); `ReplayAttack` (5-slot FIFO buffer +
    daemon thread re-injecting on a fixed cadence).
  - Registry hooks wired into `core/transport_tcp.py` send/recv —
    zero-cost when no attacks are registered.
  - `ai/feature_extractor.py` — sliding-window 10-feature schema.
    `core/peer_link.py` records every send/recv into one extractor
    per PeerLink; fires `on_features_updated` every 5 frames.
  - `app.py` + `chat.html` + `chat.js`: hidden Ctrl/Cmd+Shift+D
    panel with red/orange "danger" palette and four SocketIO
    events (gated on `config.DEMO_MODE`) for launching / stopping
    the simulators.
  - **Tampered-message UI**: `_handle_chat`'s `InvalidTag` branch
    fires a dedicated `on_chat_decryption_failed(bundle)` callback;
    `app.py` emits a distinct `chat_decryption_failed` SocketIO
    event; `chat.js` renders a red/orange-bordered "⚠ Tampered
    ciphertext rejected" bubble + a `✗ rejected` marker in the
    wire view.
  - **Replay-duplicate UI**: kind-only AAD lets replays decrypt
    cleanly into duplicate `chat_received` events; `chat.js`
    keeps a bounded `Map<ciphertext_hex → first-seen ts>` and
    annotates duplicates with an italic
    `↻ duplicate of earlier message at HH:MM:SS` footnote.  The
    chat does NOT auto-suppress; Phase 4's IDS is the thing that
    flags.
  - `data/generate_training_data.py` (multi-session runner) +
    `data/training_data.csv` (≥ 1500 labelled rows, regenerated
    against the post-fix AAD: replay rows now show duplicates ≈ 1
    with decrypt_failure_rate ≈ 0; mitm rows show
    decrypt_failure_rate ≈ 0.15 with duplicates ≈ 0).
- **Tests** — **126/126 pass** under
  `python -m unittest discover tests` in ~3.5 s.  Breakdown
  (Phase 1+2 unchanged at 74) + Phase 3 contributed 52: 10
  registry, 9 MITM, 9 Replay, 20 FeatureExtractor, 2 PeerLink-with-
  attacks end-to-end (`test_peer_link_attacks.py`).
- **Demos** — three run cleanly:
  - `demo_phase1.py` — unchanged from Phase 1.
  - `demo_phase2.md` — Phase 2 smoke-test walkthrough.
  - `demo_phase3.md` — Phase 3 walkthrough (sync, baseline chat,
    Ctrl+Shift+D, MITM, Stop, Replay, Stop, generate dataset).
- Documentation set is complete and self-consistent.

## What was just being worked on
Phase 5A — performance metrics dashboard.
Summary of Phase 5A work:

1. **`benchmarks/benchmark_key_exchange.py`** — standalone script.  Times
   TPM neural key exchange (via `SyncProtocol`), RSA-2048 (keygen + OAEP
   encrypt/decrypt), and DH-2048 (parameters once, then agreement loop).
   Writes `benchmarks/results/key_exchange.json`.  Results on this machine
   (50 runs): TPM 41 ms / 221 rounds, RSA 68 ms, DH agreement 10 ms
   (one-time param-gen 39 s).
2. **`benchmarks/benchmark_throughput.py`** — standalone AES-256-GCM
   throughput benchmark across 7 message sizes (64 B → 4 MB).  Writes
   `benchmarks/results/throughput.json`.  Peak ~7.6 GB/s for large messages
   (hardware AES-NI); per-call overhead dominates at 64 B.
3. **`ai/ids_live.py`** — `record_alert_latency()` and
   `get_latency_stats()` added; `_latency_measurements` list survives
   `reset()`.
4. **`app.py`** — `/metrics` and `/api/metrics_data` routes; attack
   launch-time tracking for IDS latency; `messages_encrypted` /
   `bytes_encrypted` session counters.
5. **`templates/metrics.html`** + **`static/js/metrics.js`** — dark-themed
   dashboard: key-exchange bar chart, AES throughput line chart (log x-axis),
   IDS latency histogram, system info.  5 s auto-refresh on live sections.
6. **`templates/chat.html`** — small `metrics` link added to header.
7. **`tests/test_benchmarks.py`** — 16 new tests; all 174/174 pass (1 skipped).
8. **Docs updated** — PHASE_LOG, HANDOFF, PROJECT_STATE, ARCHITECTURE,
   DECISIONS, README, demo_final all reflect Phase 5A complete.

Nothing in flight.  Phase 5B starts here.

## Critical context to know
- **Two-channel architecture, deliberately separated.**
  - Browser ↔ Flask (per role) over SocketIO — UI events only.
  - alice ↔ bob over **a single plain-TCP socket** — TPM sync first,
    then encrypted app traffic on the same connection.  Do NOT open a
    second socket post-sync; that would break the cryptographic
    binding between the sync handshake and the app traffic.
- **`PEER_TCP_PORT` (default 9001) is the alice↔bob channel; it is
  distinct from `FLASK_PORT_*`.**  Don't confuse them — Flask serves
  the browser, TCP carries the protocol.
- **Demo day flips two `config.py` knobs.** Server laptop:
  `BIND_HOST = "0.0.0.0"`.  Client laptop: `PEER_HOST = "<peer
  hotspot IP>"`.  No code changes anywhere else.
- **TPM defaults small (`K=3, N=10, L=3`).** Don't tune them; the
  demo audience needs them inspectable.
- **TPM update gate (do not erode).**  Weight updates apply only when
  local and remote tau agree, and within that, only to hidden units
  whose sigma equals tau.  Lives in
  `TreeParityMachine.update_weights`.  Forgetting this gate breaks
  synchronisation.
- **`recv_*` raises `TransportTimeout` on stalls; `SyncSession`
  catches it.**  The TCP transport additionally raises
  `PeerDisconnectedError` on EOF — `PeerLink.reader_loop` catches
  that and fires `on_peer_disconnected`.
- **AES-GCM raises `cryptography.exceptions.InvalidTag` on tamper.**
  Phase 4's IDS will rely on this exception bubbling — never
  catch-and-silence it inside `CryptoEngine` or `PeerLink`.
- **AAD discipline (Phase 3-onward)** — the cryptographic layer
  deliberately leaves replay detection to the IDS:
  - Chat / control / file-meta: `struct.pack(">B", kind)` —
    kind-only.  No per-direction seq counter, so replays
    DECRYPT SUCCESSFULLY at the receiver and show up as visible
    duplicate `chat_received` events that Phase 4's IDS will
    flag via `duplicate_payload_count`.  See
    `docs/DECISIONS.md` → "Kind-only AAD…" for full rationale.
  - File chunks: `f"{file_id}:{idx}/{total}"` — bound to logical
    file position; chunk-level integrity unchanged.
- **`async_mode="threading"` is pinned in config.**  Do NOT install
  eventlet or gevent; their socket monkey-patching breaks the
  plain-TCP `PeerLink` running in a background thread.
- **`threat_alert` SocketIO event name is reserved.**  No emit yet;
  Phase 4 will wire it up.  The JS already has a no-op listener so
  Phase 4 doesn't have to retrofit.
- **Phase-3 attack registry is per-`TCPTransport`, NOT process-global.**
  The training-data generator runs alice + bob in one process; a
  global registry would mean an attack on alice also fires on bob's
  outbound and silently corrupt the session label.  See
  `attacks/base.py` and `core/peer_link.py`.
- **Phase-3 feature schema (`ai/feature_extractor.FEATURE_NAMES`)**
  is the canonical column order for `data/training_data.csv` AND
  the feature names of the Phase-4 model.  Renaming or reordering
  requires retraining.  Load-bearing features:
  `decrypt_failure_rate` (lit by MITM and Replay) and
  `duplicate_payload_count` (the discriminator that separates
  Replay from MITM).
- **Sender-side feature rows look indistinguishable from normal
  even when an attack is active.**  Intentional — the attacker's
  side doesn't see the cryptographic anomaly.  The CSV keeps both
  perspectives so the Phase-4 model can learn that some labelled
  rows are unrecoverable from features alone (a property a real
  IDS has to handle gracefully).
- **Import convention** unchanged: relative imports inside `core/`,
  `import config` (absolute) from project-root modules.  `app.py`,
  `launcher_dev.py`, `network_check.py` all live at the runtime root
  alongside `config.py`.
- **A virtualenv exists at `ai_secure_comm/.venv/`** for development
  on this machine.  Recreate via
  `python -m venv .venv && pip install -r requirements.txt` on a
  fresh clone.  Note that the dev-only `python-socketio` client used
  for one-off smoke tests is NOT in `requirements.txt` — install it
  manually if you want to repeat the end-to-end smoke from Python.

## How to verify current state works
```bash
cd ai_secure_comm
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 1. Unit tests — all 74 should pass.
python -m unittest discover tests

# 2. Phase 1 demo — should still print "Phase 1 demo finished
#    successfully."
python demo_phase1.py

# 3. Phase 2 dev mode — opens both UIs, both auto-sync, chat works,
#    drag-and-drop files transfer with SHA-verified reassembly.
python launcher_dev.py
# (then follow demo_phase2.md as a checklist)
```

## What works — Phase 5A additions
- **Performance metrics dashboard** — `GET /metrics` renders a four-section
  Chart.js page.  `GET /api/metrics_data` serves JSON combining disk-cached
  benchmark results with live IDS latency stats and session counters.
- **Key-exchange benchmark** — `benchmarks/benchmark_key_exchange.py --runs 50`
  times TPM, RSA-2048, and DH-2048.  Results pre-populated in
  `benchmarks/results/key_exchange.json`.
- **Throughput benchmark** — `benchmarks/benchmark_throughput.py` times
  AES-256-GCM across 64 B → 4 MB.  Results in `benchmarks/results/throughput.json`.
- **IDS detection-latency tracking** — `LiveIDS.record_alert_latency()` stores
  wall-clock latency from demo-panel button-click to alert fire.
  `get_latency_stats()` surfaces in §3 of the dashboard.
- **`chat.html` `metrics` link** — small link in the header opens `/metrics`.

## Next concrete steps — Phase 5B scope

Phase 5A is complete.  Phase 5B covers the two-laptop deployment dry-run.

### Phase 5B scope
- **Two-laptop deployment dry-run** — run the full demo on two machines
  on a mobile hotspot using the existing `demo_final.md` script; document
  any friction points; update `config.py` comments if the hotspot IP
  workflow needs clarification.
- **Demo rehearsal** — timed run through `demo_final.md` §4 with a
  practice audience (including the new §11 metrics step); aim for 10–12 min;
  adjust narration if any section runs long.
- **Final report material** — collect screenshots of each major UI state
  (sync, normal chat, MITM alert, cleared, Replay alert, metrics dashboard)
  and the IDS confusion matrix from `ai/report/`.  Write the "Results"
  section using the benchmark numbers from `benchmarks/results/*.json`.

### Deferred items still on the wishlist
- Pin numpy patch version for round-count reproducibility on CI.
- Glossary for tau / sigma / K / N / L in `ARCHITECTURE.md`.
- Top-level repo README at the parent directory.
- HKDF / streaming-AEAD discussion in `DECISIONS.md`.

## Where to find more detail
- `PROJECT_STATE.md` — current status snapshot.
- `ARCHITECTURE.md` — module roles, public interfaces, two-channel
  diagram, frame format, frame-kind table.
- `DECISIONS.md` — why each non-obvious choice was made.
- `PHASE_LOG.md` — chronological history.
- `demo_phase2.md` — step-by-step manual walkthrough / smoke test.
