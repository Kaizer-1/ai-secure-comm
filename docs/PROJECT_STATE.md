# Project State
Last updated: 2026-05-17 (Phase 5A complete — metrics dashboard)
Current Phase: 5A of 5 (complete — Phase 5B next)
Phase 1 Status: Complete ✅
Pre-Phase-2 refactor (sync split): Complete ✅
Pre-Phase-2 polish (config + docs): Complete ✅
Phase 2 Status: Complete and fully verified ✅
Phase 3 Status: Complete and fully verified ✅
Phase 4A Status: Complete and verified ✅ (refined)
  - Training-time filter drops attacker-perspective rows before split.
    `FILTER_ATTACK_ROWS_BY_SIGNAL = True` in `ai/ids_train.py`;
    `--no-filter` CLI flag disables.  Bundle includes `filter_applied`.
  - Filtered training set: 1418 rows (244 mitm, 944 normal, 231 replay).
  - Model saved to `ai/trained_model.pkl` with full metadata bundle.
  - Test accuracy: 1.0000; macro F1: 1.0000 (on filtered held-out set).
  - Evaluation report artefacts (updated) in `ai/report/`.
  - 15 unit tests in test_ids_train.py; 139/139 total pass.
Phase 4B Status: Complete ✅
  - `ai/ids_live.py` — LiveIDS with warming_up/monitoring/alerting state
    machine, hysteresis (fire=0.70, clear=0.50), NaN guard, reset().
  - `config.py` — IDS_MODEL_PATH, IDS_ALERT_THRESHOLD_FIRE/CLEAR,
    IDS_MIN_OBSERVATIONS, IDS_ENABLE.
  - `core/peer_link.py` — set_ids(), on_threat_alert, on_threat_cleared
    callbacks, _handle_ids_state_transition, IDS reset on disconnect.
  - `app.py` — LiveIDS constructed at startup (non-fatal if absent),
    attached to PeerLink on sync, emits threat_alert / threat_cleared.
  - 9 new tests in test_ids_live.py; **148/148 total pass.**
Phase 4C Status: Complete ✅
  - `app.py` — `ids_probabilities` SocketIO event fires on every feature window;
    `ids_last_probabilities` + `ids_last_alert` stored for reconnect replay.
  - `templates/chat.html` — IDS status bar (gauge), threat banner (MITM=amber,
    Replay=rose), cleared confirmation bar, alert history strip (≤ 5 chips).
  - `static/js/chat.js` — `updateGauge`, `showThreatBanner`, `hideThreatBanner`,
    `addHistoryChip`, `finalizeActiveChip`; handlers for `ids_probabilities`,
    `threat_alert`, `threat_cleared`; gauge revealed on `sync_complete`.
  - `static/css/style.css` — gauge fill transition, threat pulse, banner slide
    animations, chip scale-in, pure-CSS chip tooltip.
  - 5 new tests in `test_ids_probabilities.py`; **153/153 total pass.**
Phase 4D Status: Complete ✅
  - `tests/test_end_to_end.py` — 5-test end-to-end smoke suite using real TCP
    and Flask-SocketIO test client: chat round-trip, MITM detection (rf
    confidence 0.88 observed), replay detection (skipped — 3 s injection
    interval makes it too slow for CI, documented), alert-clear via mock IDS.
  - `demo_final.md` — comprehensive 10-12 min viva demo guide superseding
    demo_phase2.md and demo_phase3.md.
  - UserWarning in test_ids_train.py silenced (DataFrames instead of raw numpy).
  - ResourceWarning diagnosed as Python 3.13 GC timing quirk; documented in
    DECISIONS.md as known-non-blocking; PeerLink.close() improved with
    reader-thread join.
  - All docs updated (README, HANDOFF, PROJECT_STATE, ARCHITECTURE, PHASE_LOG).
  - **158/158 unit tests pass (1 skipped).**

## Completed
- **Phase 1 — cryptographic foundation** (unchanged):
  `core/tpm.py`, `core/sync_protocol.py`, `core/crypto_engine.py`,
  `demo_phase1.py`.
- **Phase 2 — network + UI** (unchanged):
  `core/transport_tcp.py`, `core/file_transfer.py`,
  `core/peer_link.py`, `app.py`, `templates/chat.html`,
  `static/js/chat.js`, `static/css/style.css`, `launcher_dev.py`,
  `network_check.py`, `demo_phase2.md`.
- **Phase 3 — attacks + features + training data**:
  - `attacks/base.py` — `Attack` ABC + per-`TCPTransport`
    `AttackRegistry` (NOT process-global; see `DECISIONS.md`).
  - `attacks/mitm.py` — `MITMAttack` (~30% bit-flip on CHAT
    frames; sync frames untouched).
  - `attacks/replay.py` — `ReplayAttack` (5-slot FIFO + 3 s
    re-injection daemon).
  - `core/transport_tcp.py` — registry hooks in `_send_frame` /
    `recv_frame` (zero-cost when no registry attached).
  - `ai/feature_extractor.py` — sliding-window
    `FeatureExtractor` with canonical 10-feature schema.
  - `core/peer_link.py` — owns one `AttackRegistry` + one
    `FeatureExtractor` per PeerLink; `_record_frame` helper
    feeds the extractor on every send/recv; fires
    `on_features_updated` every 5 frames.
  - `app.py` — four demo SocketIO events
    (`demo_launch_mitm` / `demo_launch_replay` /
    `demo_stop_attacks` / `demo_status`) gated on
    `config.DEMO_MODE`.
  - `templates/chat.html` + `static/js/chat.js` — hidden
    Ctrl/Cmd+Shift+D overlay panel with red/orange palette.
  - `data/generate_training_data.py` — multi-session runner.
  - `data/training_data.csv` — 1834 labelled feature rows
    (942 normal / 448 mitm / 444 replay).
  - `demo_phase3.md` walkthrough.
- **Tests** — **158/158 passing (1 skipped)** in ~7 s.  Phase 3 contributed
  50 new cases: 10 registry, 9 MITM, 9 Replay, 20 FeatureExtractor,
  2 PeerLink-with-attacks end-to-end (`test_peer_link_attacks.py`
  — verifies MITM tampering surfaces as `on_chat_decryption_failed`
  not `on_error`; verifies post-AAD-fix replays decrypt cleanly
  and produce duplicate `chat_received` events).
- **Documentation set** updated and self-consistent:
  - `ARCHITECTURE.md` carries the "Phase 3 — Attack simulation +
    feature extraction" section with the registry diagram,
    simulator descriptions, feature-pipeline diagram, feature
    schema table, and post-fix kind-only-AAD discipline.
  - `DECISIONS.md` records seven Phase-3 decisions (in-process
    attacks, hook design, attacker-side asymmetry, feature
    schema, CSV format, kind-only AAD, dedicated
    `on_chat_decryption_failed` callback).
  - `PHASE_LOG.md` carries dated entries per Phase-3
    sub-deliverable plus the manual-test fix entry.
  - `HANDOFF.md` carries the Phase 4 scope.
  - `README.md` carries a "Generate training data" subsection
    under "How to run".

Phase 5A Status: Complete ✅
  - `benchmarks/benchmark_key_exchange.py` — times TPM, RSA-2048, DH-2048.
    Results (50 runs, this machine): TPM 41 ms / 221 rounds; RSA 68 ms
    (keygen 65 ms); DH agreement 10 ms (param-gen 39 s one-time).
    Written to `benchmarks/results/key_exchange.json`.
  - `benchmarks/benchmark_throughput.py` — AES-256-GCM throughput 64 B →
    4 MB.  Peak ~7.6 GB/s for large messages (hardware AES-NI).
    Written to `benchmarks/results/throughput.json`.
  - `ai/ids_live.py` — `record_alert_latency()` + `get_latency_stats()`
    added; latency list survives `reset()`.
  - `app.py` — `/metrics` + `/api/metrics_data` routes; attack-launch
    timestamps stored for latency recording; `messages_encrypted` counter.
  - `templates/metrics.html` — four-section dashboard: key-exchange bar
    chart, throughput line chart, IDS latency histogram, system info.
  - `static/js/metrics.js` — Chart.js charts; 5 s auto-refresh for live
    sections.
  - `tests/test_benchmarks.py` — 16 new tests.
  - **178/178 tests pass (1 skipped).** (174 + 4 for record_attack_start route)

## In Progress
- Nothing — Phase 5A is fully closed.

## Next Steps — Phase 5B
Two-laptop deployment dry-run via mobile hotspot: run `network_check.py`,
start alice + bob on separate machines, follow `demo_final.md`, document
any friction points.  Detailed scope in `HANDOFF.md`.

## Blockers / Open Questions
- None.  All Phase 1–2 invariants (round counts, fingerprints,
  AES bundle layout, refresh recovery) preserved through the
  Phase-3 additions.

## Deferred (non-blocking)
- Pin numpy patch version for round-count reproducibility on CI.
- Glossary for tau / sigma / K / N / L in `ARCHITECTURE.md`.
- Top-level repo README at the parent directory.
- HKDF / streaming-AEAD discussion in `DECISIONS.md`.
