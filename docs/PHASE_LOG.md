# Phase Log

Chronological record of work.  Append a new dated entry after each
meaningful coding session.

## 2026-04-27 — Phase 1 kickoff
- Created `ai_secure_comm/` skeleton with `core/`, `tests/`, `docs/`.
- Initialised documentation set: `PROJECT_STATE`, `ARCHITECTURE`, `DECISIONS`,
  `PHASE_LOG`, `HANDOFF`.
- About to start implementing `config.py` and `core/tpm.py`.

## 2026-04-27 — Phase 1 implementation
- Wrote `config.py` (TPM defaults K=3, N=10, L=3; AES 256-GCM with 12-byte
  nonce / 16-byte tag; localhost peer placeholders).
- Implemented `core/tpm.py` (Tree Parity Machine with three learning rules,
  weight clipping into [-L, L], int8 storage, SHA-256 fingerprint).
- Implemented `core/sync_protocol.py` (`SyncProtocol`, `SyncResult`,
  shared-seed input feed, timeout-protected mutual-learning loop).
- Implemented `core/crypto_engine.py` (AES-256-GCM wrapper, key derivation
  via SHA-256 of canonical int8 weights, nonce-prefix bundle layout).
- Wrote three unittest modules covering all of the above (33 tests).
- Wrote `demo_phase1.py` and `README.md`.

## 2026-04-27 — Phase 1 verification
- `python -m unittest discover tests` → 33/33 OK in ~0.4 s.
- `python demo_phase1.py` → synchronised in 258 rounds (37 ms),
  encrypt/decrypt round-trip succeeded, tampered ciphertext correctly
  rejected with `InvalidTag`.
- Test sync stats across 10 fresh-seed runs: avg 215 rounds, worst 348,
  far below the 10 000-round timeout.
- Phase 1 declared complete; updated `PROJECT_STATE.md` and
  `HANDOFF.md` with the "Phase 2 starts here" pointer.

## 2026-04-27 — Pre-Phase-2 review of Phase 1 codebase
- Reviewed `core/sync_protocol.py`, `core/crypto_engine.py`, `core/tpm.py`,
  `config.py`, tests, and the doc set with Phase 2's needs in mind.
- Verdict: TPM and CryptoEngine layers are well-shaped for the network
  split.  `SyncProtocol` is shaped as an omniscient orchestrator and
  must be split before Phase 2.  Several config/doc items flagged as
  nice-to-fix; the rest of the stack is fine to defer.
- Severity ranking written into the review reply.

## 2026-04-27 — Pre-Phase-2 refactor: `SyncProtocol` split into `SyncSession` + `SyncTransport`
- Reshaped `core/sync_protocol.py` into three layers: `TreeParityMachine`
  (untouched math) → `SyncSession` (per-side protocol loop) →
  `SyncTransport` (pluggable I/O).
- Added `LoopbackTransport` (in-process queue pair) and
  `make_loopback_pair()` factory.
- Kept `SyncProtocol(tpm_a, tpm_b, …)` as a thin convenience wrapper
  that builds a paired loopback and runs two sessions on background
  threads.  Backwards-compatible: same constructor, same `SyncResult`.
- Added `tests/test_transport.py` with 8 new cases covering loopback
  delivery (tau/fp/seed both directions), recv-timeout behaviour,
  unexpected-kind detection, two `SyncSession`s converging through a
  paired loopback, fast-fail on a wedged peer, and constructor input
  validation.
- All previously-passing tests still pass: **41/41 OK** in ~0.7 s.
- `demo_phase1.py` produces identical output: 258 rounds, same final
  fingerprint `52b58488…`, same derived AES key, same plaintext after
  decrypt, same tamper rejection.
- Behavioural invariants preserved: round counts in
  `test_ten_runs_all_synchronise` are byte-identical (avg=214.8,
  worst=348), confirming the XOR-seed agreement collapses to
  "initiator's seed" exactly as Phase 1 assumed.

## 2026-04-27 — Pre-Phase-2 polish (config split, role rename, doc fixes)
- `config.py`: split the conflated `PEER_HOST` knob into `BIND_HOST`
  (server bind address, defaults to `127.0.0.1`, flip to `0.0.0.0`
  on demo day) and `PEER_HOST` (client dial address, set to the peer
  laptop's hotspot IP on demo day).
- `config.py`: renamed role identifiers from `device_a` / `device_b`
  to `alice` / `bob` to align with the user vocabulary and the
  Phase 2 CLI flag (`--role alice`).  No code changes required outside
  `config.py` — `demo_phase1.py` reads the values via `config.ROLE_A`
  / `config.ROLE_B` so the rename ripples through automatically.
- `docs/ARCHITECTURE.md`: promoted the TPM update-gate note into an
  explicit blockquote ("Forgetting this gate breaks synchronization.")
  and added a new "Import convention" section documenting the
  relative-inside-`core` / absolute-`import config` split.
- `docs/HANDOFF.md`: rewrote "Next concrete steps" with the concrete
  Phase 2 scope (Flask + SocketIO, `app.py` with `--role` CLI flag,
  SyncTransport implementation, role-aware chat UI, wire-view panel,
  drag-and-drop file transfer with chunked AEAD).  Updated the
  "Critical context" wording about the host split.
- `docs/DECISIONS.md`: two new entries — host-split rationale and
  role-rename rationale.
- All 41 tests still pass; `demo_phase1.py` still runs cleanly.
- Pre-Phase-2 work is now complete.  Phase 2 starts here.

## 2026-04-28 — Phase 2 kickoff: web stack + config additions
- Added Phase 2 settings to `config.py`: `FLASK_HOST`, `FLASK_PORT_ALICE`,
  `FLASK_PORT_BOB`, `FLASK_SECRET_KEY`, `SOCKETIO_ASYNC_MODE`,
  `SOCKETIO_PING_INTERVAL`, `SOCKETIO_PING_TIMEOUT`, `PEER_TCP_PORT`,
  `INITIATOR_ROLE`, `PEER_RECV_TIMEOUT`, `FILE_CHUNK_BYTES`,
  `FILE_MAX_BYTES`, `WIRE_VIEW_BUFFER`, `SYNC_PROGRESS_EVERY`.
  Removed the leftover `PEER_PORT` placeholder (replaced by
  `PEER_TCP_PORT` for the alice↔bob channel and `FLASK_PORT_*` for the
  web servers).
- `requirements.txt`: added `flask>=3.0,<4.0` and
  `flask-socketio>=5.3,<6.0`.  Pinned `SOCKETIO_ASYNC_MODE="threading"`
  in config so we deliberately do NOT depend on eventlet or gevent.

## 2026-04-28 — Phase 2: TCP transport + framing
- Built `core/transport_tcp.py`: `TCPTransport(SyncTransport)` with the
  same six-method interface as `LoopbackTransport`, plus app-layer
  helpers for chat / file_meta / file_chunk / control sends.
  Length-prefixed framing (`[kind:1][length:4 BE][payload]`).  Frame
  kinds defined as constants (TAU/FINGERPRINT/SEED for sync,
  CHAT/FILE_CHUNK/FILE_META/CONTROL for app).  Thread-safe sends via
  `Lock`; `recv_*` raises `TransportTimeout` on stalls,
  `PeerDisconnectedError` on EOF.  TCP_NODELAY enabled by default.
- `TCPListener` (one-shot bind + accept), `bind_and_accept` and
  `connect` factory functions; `connect()` retries on `ConnectionRefused`
  to handle the dialer-races-listener case.
- Tests: `tests/test_transport_tcp.py` — 14 cases covering all five
  frame kinds in both directions, partial-read handling
  (split-across-recvs), large-payload concurrent send/recv,
  `TransportTimeout` on silent peer, `PeerDisconnectedError` on close,
  send-after-close rejection, listener accept timeout, thread-safe
  concurrent sends, `bind_and_accept` smoke.

## 2026-04-28 — Phase 2: file transfer helpers
- Built `core/file_transfer.py`: `make_file_meta` (UUID4 file_id,
  SHA-256, size, total_chunks; rejects > `FILE_MAX_BYTES`),
  `iter_chunks` (in-order, yields `(0, b"")` for empty files),
  `aad_for_chunk` (deterministic `f"{file_id}:{idx}/{total}"` AAD),
  `assemble_chunks` (orders by index, complains on missing),
  `verify_sha256`.
- Tests: `tests/test_file_transfer.py` — 14 cases including a full
  encrypt-each-chunk → reassemble → SHA-verify round trip on small
  (~1 KB) and medium (~2 MiB) files, plus negative tests (AAD tamper
  → `InvalidTag`, post-decrypt corruption → SHA mismatch).

## 2026-04-28 — Phase 2: PeerLink (TCP + sync + app dispatch)
- Built `core/peer_link.py`: owns one TCP transport for the session's
  full lifetime — `connect()` either binds (initiator) or dials
  (responder), runs `SyncSession` over a `_ProgressTransport`
  decorator that emits `on_sync_progress` callbacks every
  `SYNC_PROGRESS_EVERY` rounds, derives the AES key via
  `CryptoEngine.derive_key_from_tpm`, then enters app mode.  In app
  mode a daemon reader thread loops on `recv_frame` and dispatches
  CHAT / FILE_META / FILE_CHUNK / CONTROL frames to callback hooks
  (`on_chat_received`, `on_file_meta_received`,
  `on_file_chunk_received`, `on_file_complete`,
  `on_peer_disconnected`, `on_error`).
- AAD discipline: chat / control / file-meta use a per-direction
  monotonic 64-bit sequence (`struct.pack(">BQ", kind, seq)`); file
  chunks use `aad_for_chunk(file_id, idx, total)`.
- File-transfer outbound: `send_file(path)` builds the meta, sends a
  FILE_META frame (encrypted JSON), then iterates chunks and sends
  each as `[file_id:16][idx:4][total:4][AES bundle]` in a FILE_CHUNK
  frame.  Receiver assembles in a per-file dict and emits
  `on_file_complete(meta, sha_ok, plaintext)` once all chunks arrive.
- Tests: `tests/test_peer_link.py` — 5 cases: full sync to matching
  key fingerprints (with progress events captured), single chat
  round-trip, multiple-chats-in-sequence, send-before-sync rejection,
  small-file round-trip with SHA verification.  All run two PeerLinks
  in two threads on 127.0.0.1.

## 2026-04-28 — Phase 2: Flask app + role-aware UI
- Built `app.py`: `create_app(role)` returns Flask + Flask-SocketIO
  for one role.  Routes: `GET /` (renders `chat.html`), `POST /upload`
  (drag-and-drop intake, async send), `GET /download/<file_id>`
  (completed-file blob), `GET /_demo` (404 placeholder for Phase 3).
  SocketIO events: `start_sync` and `send_chat` from the browser;
  `hello`, `sync_progress`, `sync_complete`, `chat_received`,
  `chat_sent`, `file_meta_received`, `file_chunk_received`,
  `file_sent`, `file_complete`, `peer_disconnected`, `error` to the
  browser.  `threat_alert` reserved (no emit yet — Phase 4).
- CLI: `python app.py --role alice|bob`, optional `--host` and
  `--port` overrides.
- Built `templates/chat.html`: Tailwind via CDN, Socket.IO via CDN,
  no build step.  Role header (color-coded), connection status dot,
  AES key fingerprint badge, two-column main (chat + wire view),
  drop zone, sync progress bar.
- Built `static/js/chat.js`: SocketIO event handlers, chat bubble
  rendering, wire-view feed (capped at `WIRE_VIEW_BUFFER`),
  drag-and-drop uploads via `fetch /upload`, reconnection banner.
- Built `static/css/style.css`: sync-bar pulse animation + wire-view
  scrollbar styling (everything else is Tailwind utilities inline).

## 2026-04-28 — Phase 2: dev launcher + demo-day pre-flight
- Built `launcher_dev.py`: spawns both `app.py --role` subprocesses,
  forwards their logs prefixed `[alice]` / `[bob]`, opens both UIs in
  the default browser, Ctrl+C tears down with SIGTERM then SIGKILL.
- Built `network_check.py`: per-role pre-flight.  Initiator binds
  `BIND_HOST:PEER_TCP_PORT`, responder pings + TCP-connects.  Clear
  ✓/✗ output and exit code.

## 2026-04-28 — Phase 2: end-to-end smoke test
- Manually verified the full stack: `launcher_dev.py` → both Flask
  servers bind → both browser tabs render with role colors → both
  TPMs sync over real TCP → matching key fingerprints
  (`267f4d63859b6d86…`) → chat round-trips with 57-byte ciphertext
  bundles visible in the wire view → drag-and-drop file transfers
  reassemble with `sha_ok=True`.
- TPM sync over TCP converged in 194 rounds for the smoke run —
  identical envelope to Phase 1's in-process sync (~250 rounds).
- All 74 tests pass: 41 prior + 14 transport_tcp + 14 file_transfer
  + 5 peer_link.  `demo_phase1.py` still runs unchanged.

## 2026-04-28 — Phase 2: docs refresh + walkthrough
- `docs/ARCHITECTURE.md`: new "Phase 2 — network layer + web UI"
  section with the two-channel diagram, frame-format spec, frame-kind
  table, and per-module summaries.
- `docs/DECISIONS.md`: five new entries — plain TCP for the peer
  channel, length-prefixed framing scheme, single connection reused
  post-sync, `INITIATOR_ROLE` for binding asymmetry, `async_mode="threading"`
  pinning.
- `README.md`: updated phases table (Phase 2 now ✅ complete), expanded
  layout, added "How to run" with dev-mode and demo-mode invocations.
- New `demo_phase2.md`: step-by-step walkthrough that doubles as the
  manual smoke test for declaring Phase 2 complete.

## 2026-04-28 — Phase 2 manual-test fixes
**File-picker button, network_check made truly peer-aware, browser
refresh recovery via backend session state.**

Manual smoke testing of the Phase 2 build surfaced three issues; all
fixed before Phase 3 starts.

- *Issue 3 (most architectural) — browser refresh recovery.*
  - `app.py` now carries an explicit session-state machine
    (`status` ∈ {idle, syncing, synced, error}) plus cached
    `sync_rounds`, `sync_time_ms`, `key_fingerprint`, `last_progress`,
    and `last_error`.
  - `on_browser_connect` replays the appropriate event(s) to the new
    client: `sync_complete` (with `replay: True`) when synced,
    cached `sync_progress` (with `replay: True`) when syncing-with-
    progress, `sync_in_progress` when syncing-without-progress yet,
    `error` when errored, nothing when idle.
  - `chat.js` no longer emits `start_sync` immediately on connect; it
    waits 2 s for a backend state event and only then assumes idle
    and triggers a fresh sync.  Any state event cancels the timer.
  - On `sync_complete` with `replay: true`, JS shows a subtle
    `(reconnected — earlier messages not shown)` system bubble
    instead of the usual "key derived after N rounds" message.
  - Manual scenarios verified: fresh-load sync, reconnect after sync
    completes (8 ms to UI unlock), reconnect during sync, peer tab
    unaffected by the other tab's refresh.

- *Issue 2 — `network_check.py`.*
  - Old behaviour: alice bound, printed success, exited; the released
    port left bob's connect attempt to fail.
  - New behaviour: alice's check stays alive, calls `accept()` with a
    60 s timeout, and exchanges a `NETCHECK_OK\\n` handshake with bob
    before declaring success.  Bob pings, dials, exchanges the
    handshake, declares success.  Both sides exit 0 only when the
    full round-trip succeeds.  Help text and error messages updated
    to reflect "alice runs first and waits, bob runs second within
    60 seconds."

- *Issue 1 — file-picker button.*
  - Added a teal/amber "Choose file" button (role-themed via Tailwind
    utilities) plus a hidden `<input type="file">`.  Both the button
    path and the existing drag-and-drop path call the same
    `sendFile(file)` JS function — single upload code path.
  - Upload now uses `XMLHttpRequest` so we can show "Transferring…
    X%" progress; on completion the JS narrates "Sending over the
    secure channel…" until the `file_sent` SocketIO event fires the
    final "✓ Sent" system bubble.  Receiver mirrors with "Receiving…
    X%" tied to `file_chunk_received` events and a "✓ Received"
    bubble on `file_complete`.
  - Pre-existing bug surfaced by the new UX: the upload route was
    leaking the `tempfile.mkstemp` prefix into the displayed
    filename (e.g. `upload-us2ptbk1-demo.txt`).  Fixed in `app.py`
    by saving into a fresh tempdir under `secure_filename(f.filename)`.

All 74 unit tests still pass.  Manual smoke tests added (kept under
`/tmp/` — they're throwaway harnesses, not project deliverables):
fresh-load + reconnect scenarios, file-picker HTML/upload checks,
end-to-end SocketIO round-trip.

## 2026-04-29 — Status indicator fix (refresh recovery, take 2)
**Root cause and the fix that actually stuck.**

The previous session refactored to `setStatus(state)` and added an
explicit `setStatus("synced")` at the top of the `sync_complete`
handler.  Manual testing confirmed messages flow correctly after
refresh — but the *header status indicator* still stayed stuck on
"connecting…" while the input enable + key fingerprint badge
correctly transitioned.  Same code path different outcome ⇒ a real
event-ordering issue, not a missing call.

**Root cause (diagnosed by tracing the event order):**
`socket = io({ reconnection: true, ... })` — with reconnection
enabled, the SocketIO `connect` handler can fire *more than once*
per page lifetime (initial connect, then again after any
transport blip / Engine.IO polling→websocket upgrade).  After a
browser refresh:

```
   connect          → setStatus("connecting")    ← wins initially
   replay sync_complete (~8ms)
                    → setStatus("synced")        ← correct
   …later: transient transport upgrade or blip…
   connect (second)  → setStatus("connecting")   ← OVERWRITES "synced"
```

The asymmetry between "input enable works" and "status doesn't"
is exactly because the input-enable path lives in `enableInput`
which only runs from `sync_complete`; the late-firing connect
handler doesn't touch it.  The status text/dot is the only thing
both handlers write to.

**Fix: deferred-connecting grace period.**
`socket.on("connect")` no longer writes `setStatus("connecting")`
synchronously.  It schedules a `setTimeout` 500 ms in the future
that *would* write it.  Every state-bearing event handler
(`sync_progress`, `sync_in_progress`, `sync_complete`, `error`,
`peer_disconnected`) cancels the deferred timer before doing its
own `setStatus`.  Replay `sync_complete` arrives in ~10 ms over
loopback (and even over Wi-Fi, well under 500 ms), so the deferred
"connecting" write is cancelled before the user ever sees it.
First-load (idle backend) still shows "connecting…" because no
event arrives within 500 ms.  `disconnect` keeps writing
`setStatus("connecting")` synchronously — a real disconnect
deserves immediate feedback.

**Pattern:**
```js
function scheduleConnectingStatus() {
  cancelConnectingDelay();
  connectingDelayTimer = setTimeout(
    () => { connectingDelayTimer = null; setStatus("connecting"); },
    CONNECTING_DELAY_MS,  // 500
  );
}
socket.on("connect", () => { …; scheduleConnectingStatus(); … });
socket.on("sync_complete", (d) => {
  cancelConnectingDelay();   // first thing the handler does
  setStatus("synced");
  enableInput(d.key_fingerprint);
});
```

**Status indicator fix: factored status updates into setStatus()
helper, ensures reconnect-replay sync correctly displays
synchronised state.**  All 74 unit tests still pass; manual scenario
harnesses confirm SocketIO event order unchanged (replay
sync_complete in 12 ms in this run).  The fix is purely additive on
the JS timeline — same events fire in the same order; only the
*timing* of the `setStatus("connecting")` DOM write changes.

## 2026-04-29 — Status indicator fix, take 3 (latch + reconcile)
**The deferred-only grace period from take 2 wasn't sufficient — the
status indicator continued to be stuck on "connecting…" after a
refresh in real-browser manual testing.**

Honest root-cause notes for future debugging:

- The previous (deferred 500 ms) fix was **necessary but not
  sufficient**.  My automated `python-socketio` scenario test was
  passing throughout because the python-socketio client doesn't run
  JS at all; it only validates that the Flask backend emits the
  right SocketIO event payloads in the right order, which the
  backend does correctly.  The bug lives entirely in client-side
  event ordering inside the browser's socket.io client + DOM event
  loop, and I had no automated way to observe it.  The user's
  manual reports were the authoritative signal; I should have
  trusted them harder instead of cycling through partial fixes.
- The most plausible mechanism the deferred fix doesn't catch:
  `socket.on("connect")` can fire *more than once* per page lifetime
  — Engine.IO transport upgrades, brief disconnect/reconnects under
  `reconnection: true`, or any other case where the SocketIO Manager
  resurfaces the connect event.  After the first `sync_complete`
  has correctly painted "synchronised", a subsequent `connect`
  scheduled a new 500 ms deferred "connecting…" write; if no
  state-bearing event arrived inside that 500 ms window (which is
  the common case once the initial replay sync_complete is done),
  the deferred write fired and the indicator silently rolled back.

**Take 3 fix — two independent safeguards in `static/js/chat.js`:**

1. **`hasEverSynced` latch.**  Set `true` inside the `sync_complete`
   handler.  The `connect` handler now checks this latch and skips
   `scheduleConnectingStatus()` once it's `true`.  No subsequent
   connect handler can ever schedule another "connecting" write.
   The current "synchronised" indicator is the truth of the
   session; we don't second-guess it on later transport events.
2. **`reconcileSyncedStatus()` on every app-phase event.**  Chat
   events (`chat_received`, `chat_sent`) and file events
   (`file_meta_received`, `file_chunk_received`, `file_sent`,
   `file_complete`) all start by calling
   `reconcileSyncedStatus()`, which re-asserts `setStatus("synced")`
   when `hasEverSynced` is true.  An app-phase event existing at
   all proves the session is synced — so even if some future
   ordering glitch leaves the header on "connecting…", the very
   next message will fix it.  The user can no longer end up in a
   state where the header is wrong but everything else works.

Plus a small dev-experience improvement: `templates/chat.html` now
loads `chat.js` with a `?v=2026-04-29-fix4` cache-buster query
string, so a browser cannot serve a stale chat.js across fix
iterations even if its revalidation behaviour differs from
expectation.

**Conceptual model of the resulting state machine:**
`hasEverSynced` is a one-way latch; once set, the only event that
can move the header status away from "synchronised" is an explicit
`error` or `peer_disconnected`, both of which write
`setStatus("error")` directly.  Reconnects, transport upgrades,
ghost connect events — all become inert.  This is correct because
the AES key, once derived, is the actual session state; no
network-level event invalidates it.

74 unit tests still pass.  All three scenario harnesses
(refresh-recovery, file-picker, e2e smoke) green.  Manual
verification on the user's actual browser is the authoritative
test for this fix and is the next step.

## 2026-04-30 — Phase 3 kickoff: config + attack base + registry
- `config.py`: added `DEMO_MODE`, `MITM_TAMPER_PROBABILITY` (0.30),
  `REPLAY_BUFFER_SIZE` (5), `REPLAY_INTERVAL_S` (3.0),
  `FEATURE_WINDOW_SIZE` (20), `FEATURE_UPDATE_EVERY` (5).
- New `attacks/` package: `base.py` defines the `Attack` ABC plus a
  per-`TCPTransport` `AttackRegistry` (deliberately NOT a process
  global — the training-data generator runs alice + bob in one
  process, and a global registry would silently corrupt session
  labelling).  Hooks return `Optional[(kind, payload)]` so each
  attack can mutate or drop frames; chain semantics are
  "first-None short-circuits, mutated tuple feeds the next attack."

## 2026-04-30 — Phase 3: MITM + Replay simulators
- `attacks/mitm.py` — `MITMAttack` flips a configurable fraction of
  outbound CHAT frames' bits.  Sync-phase frames
  (TAU/FINGERPRINT/SEED) are explicitly excluded — Tree Parity
  Machine sync's security model assumes a passive observer; a
  tampering simulator that broke it would just measure "AES-GCM
  detects garbage", not the IDS signal.  Stats: `frames_seen`,
  `frames_tampered`.
- `attacks/replay.py` — `ReplayAttack` maintains a bounded FIFO
  (5 slots) of recent CHAT frames and a daemon thread re-injects
  one every interval via `transport._send_frame(KIND_CHAT, payload)`.
  Self-injection guard prevents the captured-then-re-injected
  frame from looping into the buffer.  Stats: `frames_buffered`,
  `frames_replayed`, `replay_intervals_ms`, `buffer_occupancy`.

## 2026-04-30 — Phase 3: TCP transport hooks (zero-cost when no attacks)
- `core/transport_tcp.py`: `_send_frame` and `recv_frame` now
  consult an optional per-transport `attack_registry` before /
  after the framing layer.  When no registry is attached the path
  stays exactly as it was in Phase 2 (one attribute read + one
  None check).  Recv-side drops loop to fetch the next frame
  silently.  `attach_attack_registry` lets `PeerLink` late-bind.

## 2026-04-30 — Phase 3: Feature extractor + PeerLink integration
- New `ai/` package with `FeatureExtractor` — sliding-window
  collector with the canonical 10-feature schema in
  `FEATURE_NAMES` (volume/cadence: 4, payload shape: 2, anomaly
  hints: 2, composition: 3).  Thread-safe; uses Python's
  `statistics` module so no extra deps.  `record(...)` returns
  the cumulative observation count so callers can throttle
  feature-extraction calls.
- `core/peer_link.py`: each PeerLink now owns one `AttackRegistry`
  + one `FeatureExtractor` + a private `_record_frame` helper that
  appends to the extractor and fires `on_features_updated` every
  `FEATURE_UPDATE_EVERY` (5) frames.  Recording is wired into
  every send_chat / send_control / send_file outbound path and
  every _handle_chat / _handle_control / _handle_file_meta /
  _handle_file_chunk inbound path, with `decrypt_success`
  tracked from the `InvalidTag` catch points.  Phase-2 invariants
  preserved — 74 prior tests remain green.

## 2026-04-30 — Phase 3: Tests (48 new cases)
- `tests/test_attack_registry.py` (10 cases): registration
  idempotency, unregister stops + detaches, hooks fire in order,
  drop short-circuits, exception in one hook continues the chain,
  active filter, late-binding transport.
- `tests/test_attacks_mitm.py` (9 cases): inactive passes through;
  sync frames untouched even at 100% probability; tampering rate
  sits in expected band over 1000 frames; empty payload counts as
  seen but not tampered; inbound is passthrough; default
  flip-bits-per-frame produces Hamming-distance 1; constructor
  validation.
- `tests/test_attacks_replay.py` (9 cases): inactive doesn't
  buffer; sync frames not buffered; FIFO eviction at capacity;
  injector thread fires at expected interval and only with CHAT
  kind; self-injected frames don't loop; stop is clean +
  idempotent; constructor validation.
- `tests/test_feature_extractor.py` (20 cases): empty/single-frame
  edge cases; uniform inter-arrival mean/std; payload-size stats;
  decrypt-failure rate ignores outbound; partial failures; unique
  vs repeated payload-hash counting; kind composition fractions;
  window cap; cumulative count; reset.

Total: **122/122 tests pass** (74 prior + 48 new) in ~2.5 s.

## 2026-04-30 — Phase 3: Demo controls (backend + UI)
- `app.py`: four SocketIO events gated on `config.DEMO_MODE` —
  `demo_launch_mitm`, `demo_launch_replay`, `demo_stop_attacks`,
  `demo_status`.  Each event creates / starts / unregisters an
  `Attack` against the live `PeerLink.attack_registry` and emits
  `demo_attack_state` (full snapshot) plus
  `demo_attack_active` / `demo_attacks_stopped` for transition
  signalling.
- `templates/chat.html`: hidden fixed-position overlay panel with
  red/orange palette so the audience can tell at a glance these
  are adversarial controls.  Three buttons + status row.
- `static/js/chat.js`: `Ctrl+Shift+D` / `Cmd+Shift+D` chord toggles
  the panel; buttons emit the corresponding events; the panel
  re-syncs via `demo_status` on connect / open so a refreshed
  tab catches up to whatever attacks are already running.  No
  visible change to the main chat UI when the panel is hidden —
  Phase 4 will add the threat-alert banner.
- Cache-bust query string on the script tag bumped to
  `?v=2026-04-30-phase3` so browsers fetch the new JS without a
  hard refresh.

## 2026-04-30 — Phase 3: Training data generation
- New `data/generate_training_data.py` — standalone runner that
  spawns alice + bob `PeerLink`s on 127.0.0.1:<random-free-port>,
  syncs them, picks a label (50/25/25 normal/mitm/replay),
  registers the labelled attack on alice's side, sends 15–35
  randomised chats, captures every `on_features_updated` snapshot
  from BOTH sides, writes one row per snapshot.  CLI flags:
  `--sessions`, `--output`, `--seed`, `--save-logs`.
- Generated `data/training_data.csv`: **1834 labelled rows** from
  200 sessions (942 normal / 448 mitm / 444 replay), 218 KB.
  Per-label feature stats:
  - `normal`: decrypt_failure_rate=0, duplicate_payload_count=0
  - `mitm`:   decrypt_failure_rate ≈ 0.14 (max 0.60), duplicates=0
  - `replay`: decrypt_failure_rate ≈ 0.35 (max 1.00), duplicates ≈ 1.13 (max 4)
  Distinguishable but not trivially separable — exactly the
  examiner-proof property the spec asked for.  Replay produces
  decrypt failures *as well as* duplicates because Phase 2's AAD-
  as-sequence-number design rejects the stale AAD; the duplicate
  count is the discriminator that separates replay from MITM.

## 2026-04-30 — Phase 3: Walkthrough + docs
- `demo_phase3.md` — step-by-step demo script that doubles as the
  manual smoke-test checklist (run launcher, open both tabs, sync,
  Ctrl+Shift+D, MITM, Stop, Replay, Stop, generate dataset,
  inspect CSV).  Lists known boundaries (no threat UI yet, sender-
  side rows look like normal under attack — both intentional).
- `docs/ARCHITECTURE.md`: new "Phase 3 — Attack simulation +
  feature extraction" section with the registry diagram, the
  MITM / Replay descriptions, the feature-pipeline ASCII diagram,
  and the canonical feature schema table.
- `docs/DECISIONS.md`: five new entries — in-process attack
  simulation vs third-laptop adversary; per-frame hook design with
  drop semantics; attack-side asymmetry (only attacker's process
  runs the simulator); 10-feature schema choice; CSV format for
  training data.

## 2026-05-01 — Phase 4A polish: DataFrame-based fit/predict (feature names)

**Problem:** `ai/ids_train.py` called `df[FEATURE_NAMES].to_numpy(dtype=float)`
before `model.fit()`, stripping column names.  sklearn silently omits
`model.feature_names_in_` in this case and emits a `UserWarning` whenever a
named DataFrame is later passed to `predict()` or `predict_proba()`.  This is a
foot-gun for Phase 4B: if the live feature vector is assembled in a different
column order than training, predictions are silently wrong.

**Fix (two lines):**
- `ai/ids_train.py` line 229: `df[FEATURE_NAMES].to_numpy(dtype=float)` →
  `df[FEATURE_NAMES].astype(float)` — passes a DataFrame to `model.fit()`.
- `ai/ids_report.py` line 86: same change to `_rebuild_test_set`'s `X`
  extraction so predict-time columns also carry names.

**Verification:**
- Both scripts retrained / rerun under `-W error::UserWarning` — no warnings.
- `model.feature_names_in_` now exists and matches `bundle["feature_names"]`
  exactly.
- `model.predict(pd.DataFrame([...], columns=feature_names))` runs cleanly.
- 139/139 tests pass; accuracy and macro F1 unchanged (1.00).

## 2026-05-01 — Phase 4A refinement: training-time filter for attacker-perspective rows

### Problem
Phase 4A trained with macro F1 = 0.7792 (MITM recall 0.62, Replay recall
0.61).  Investigation confirmed the cause: the training CSV contains rows
from the *attacker's* local perspective — the attacking process never sees
its own `InvalidTag` or its own duplicate payloads, so those rows carry
attack labels but have zero receiver-side signal.  Keeping them in training
causes the forest to see "sometimes attack-labelled rows look exactly like
normal" — which degrades recall.

### Fix
Training-time signal filter added to `ai/ids_train.py`.  Applied after
CSV load and NaN drop, before the train/test split:
- Keep a `mitm` row only if `decrypt_failure_rate > 0`
- Keep a `replay` row only if `duplicate_payload_count > 0`
- Keep ALL `normal` rows unconditionally

Rows that fail their filter rule are **dropped** (not relabeled).
`data/training_data.csv` and `data/generate_training_data.py` are NOT
modified — the filter runs at training time, preserving raw data for
debugging.

### Implementation details
- `FILTER_ATTACK_ROWS_BY_SIGNAL = True` constant (default on).
- `_filter_attack_rows_by_signal(df)` pure helper function.
- `train_from_csv(..., filter_rows=True)` parameter threads the flag
  through to the function.
- `train_and_save(...)` gains the same `filter_rows` parameter.
- CLI `--no-filter` flag disables it for raw-data inspection.
- Bundle now includes `filter_applied: bool` field so downstream tools
  (report generator, Phase-4B loader) know the training-data provenance.
- `ai/ids_report.py` updated: `_rebuild_test_set` applies the identical
  filter when `bundle["filter_applied"]` is True, ensuring the report's
  test set comes from the same distribution as training.

### Before / after row counts
  | Label  | Before filter | After filter | Dropped |
  |--------|---------------|--------------|---------|
  | normal | 944           | 944          | 0       |
  | mitm   | 500           | 243          | 257     |
  | replay | 478           | 231          | 247     |
  | total  | 1922          | 1418         | 504     |

### Training results — refined (seed 42, 80/20 stratified, filtered data)
- Rows: 1418 (1134 train / 284 test)
- Test accuracy: **1.0000**; macro F1: **1.0000**

  | class  | precision | recall | F1   | support |
  |--------|-----------|--------|------|---------|
  | mitm   | 1.00      | 1.00   | 1.00 | 49      |
  | normal | 1.00      | 1.00   | 1.00 | 189     |
  | replay | 1.00      | 1.00   | 1.00 | 46      |

  Perfect accuracy is expected: after filtering, the three classes are
  cleanly separable by `decrypt_failure_rate` (MITM) and
  `duplicate_payload_count` (Replay).  The Random Forest trivially learns
  these two threshold rules.

### Feature importance shift
  | Before filter | After filter | Importance |
  |---------------|--------------|------------|
  | decrypt_failure_rate 0.1617 | decrypt_failure_rate 0.4665 | |
  | mean_inter_arrival_ms 0.1603 | duplicate_payload_count 0.3237 | |
  | std_inter_arrival_ms 0.1593 | mean_inter_arrival_ms 0.0814 | |

  The two anomaly-hint features now dominate at 79% combined importance,
  which reflects the clean signal in the filtered training set.

### New tests (7 methods across 4 classes in `tests/test_ids_train.py`)
- `TestFilterDropsMitmWithNoSignal` (2): drops mitm rows with zero
  decrypt_failure_rate; correct drop count.
- `TestFilterDropsReplayWithNoSignal` (1): drops replay rows with zero
  duplicate_payload_count.
- `TestFilterKeepsAllNormal` (2): all-zero-feature normal rows preserved;
  mixed-label scenario normal intact.
- `TestNoFilterBypassesFiltering` (2): filter_rows=False keeps all rows;
  `filter_applied` field correct in both cases.

**139/139 tests pass** (132 prior + 7 new) in ~4.4 s.

## 2026-05-01 — Phase 4A: Offline IDS training pipeline

### Confirmed from previous session
- `ai/ids_train.py` — standalone Random Forest trainer.  Loads
  `data/training_data.csv`, fits `RandomForestClassifier` (100 trees,
  `n_estimators=100`, `class_weight="balanced"`, `n_jobs=-1`), saves
  a metadata bundle to `ai/trained_model.pkl` via joblib.  Programmatic
  entry point `train_from_csv()` used by the test suite; `train_and_save()`
  for on-disk use; CLI `python ai/ids_train.py [--input] [--output]
  [--test-size] [--random-state]`.
- `requirements.txt` — added `pandas>=2.1`, `scikit-learn>=1.4`,
  `joblib>=1.3`, `matplotlib>=3.8`.

### Built this session
- `ai/ids_report.py` — standalone report generator.  Loads the trained
  bundle, re-runs the held-out test split (same `random_state` + `test_size`
  from metadata so the set is identical), and writes four artefacts to
  `--output` (default `ai/report/`):
  - `confusion_matrix.png` — annotated 8×6 heatmap, plain matplotlib.
  - `feature_importances.png` — horizontal bar chart (10 features), 8×5.
  - `classification_report.txt` — per-class precision / recall / F1.
  - `model_summary.txt` — hyperparams, split sizes, accuracy, macro F1.
  CLI: `python ai/ids_report.py [--model] [--input] [--output]`.
- `tests/test_ids_train.py` — 8 test methods across 5 test cases
  (all on synthetic data, no real CSV required, completes in <5 s):
  - `TestLoadCsv` (2): valid CSV shape/dtypes + missing-column `ValueError`.
  - `TestTrainReturnsModel` (1): fitted model has `classes_`, can `predict`.
  - `TestSaveLoadRoundtrip` (1): serialise + reload → predictions identical.
  - `TestMetadataPreserved` (3): all required bundle keys present; feature
    names match canonical schema; test accuracy in [0, 1].
  - `TestHandlesImbalancedClasses` (1): imbalanced 10/50/50 data trains
    without error, `class_weight="balanced"` confirmed in bundle.

### Training run results (executed: `python ai/ids_train.py`)
- Dataset: 1922 rows (1537 train / 385 test, 80/20 stratified, seed 42)
- Classes: mitm, normal, replay
- Test accuracy: **0.8000**; macro F1: **0.7792**
- Per-class (held-out test set):

  | class  | precision | recall | F1   | support |
  |--------|-----------|--------|------|---------|
  | mitm   | 0.98      | 0.62   | 0.76 | 100     |
  | normal | 0.72      | 0.99   | 0.83 | 189     |
  | replay | 0.94      | 0.61   | 0.74 | 96      |

  Reduced recall for mitm/replay is expected and intentional: sender-side
  rows in the CSV are labelled mitm/replay but have normal-looking features
  (the attacker's process never sees `InvalidTag` or duplicate-payload
  events).  See DECISIONS.md → "Attack-side asymmetry."
- Top feature importances (out of 10):
  1. `decrypt_failure_rate`    0.1617
  2. `mean_inter_arrival_ms`   0.1603
  3. `std_inter_arrival_ms`    0.1593
  4. `frame_rate_per_second`   0.1359
  5. `std_payload_size`        0.1318
  Chat/file/control fractions all ≈ 0 — training traffic was all-chat.

### Report artefacts generated (`python ai/ids_report.py`)
- `ai/report/confusion_matrix.png`
- `ai/report/feature_importances.png`
- `ai/report/classification_report.txt`
- `ai/report/model_summary.txt`

### Tests
**132/132 pass** (124 prior + 8 new) in ~4.0 s.

Phase 4A declared complete.  Phase 4B starts here: load the saved model
in PeerLink, hook to `on_features_updated`, fire `threat_alert` SocketIO
events when probability > threshold.

## 2026-04-30 — Phase 3 manual-test fixes (Issues 1 + 2 + doc audit)
Manual smoke testing of the Phase 3 build surfaced two real
issues; both fixed and documented.

- **Issue 2 (real bug) — Replay produces decrypt errors instead
  of duplicates.**  Root cause: the chat / control / file-meta
  AAD was `struct.pack(">BQ", kind, seq)` where `seq` was the
  per-direction monotonic counter.  This bound replay protection
  into the AEAD layer, so every replay deterministically failed
  `InvalidTag` — silently suppressing the visible duplicate the
  demo (and the IDS) needs to see.
  **Fix:** AAD reduced to kind-only (`struct.pack(">B", kind)`)
  in `core/peer_link.py`.  All 6 call sites updated; the seq
  counters are now pure instrumentation.  Replays now decrypt
  successfully and arrive at the receiver as byte-for-byte
  duplicate `chat_received` events.  See `docs/DECISIONS.md` →
  "Kind-only AAD" for the full rationale (this is a deliberate
  pedagogical choice to push replay detection up to the
  Phase-4 IDS layer, not a security regression).

- **Issue 1 (UX) — MITM rejection appeared as "error: unknown".**
  Root cause: `_handle_chat`'s `InvalidTag` branch fired the
  generic `on_error` callback, which `app.py` emitted as the
  generic `error` SocketIO event, which `chat.js` rendered as a
  bland system bubble.  The audience saw "looks broken" instead
  of "the security layer is catching MITM-tampered traffic."
  **Fix (backend):** PeerLink now exposes
  `on_chat_decryption_failed(bundle)`.  `_handle_chat` fires this
  for InvalidTag (only).  `_handle_control` and
  `_handle_file_meta` keep using `on_error` (rarer + no UI
  affordance for those).
  **Fix (frontend):** `app.py` emits a new `chat_decryption_failed`
  SocketIO event with payload `{reason, timestamp,
  ciphertext_size, ciphertext_hex, ciphertext_preview_hex}`.
  `chat.js` renders a distinct red/orange-bordered bubble:
  > ⚠ Tampered ciphertext rejected
  > AES-GCM authentication failed · 47 bytes
  > [hex preview…]
  Wire-view panel marks the rejected ciphertext with `✗ rejected`
  + red border + strikethrough hex.

- **Issue 1 (related) — Replay duplicates need a visible marker.**
  Now that replays decrypt successfully (Issue 2 fix), bob sees
  duplicate `chat_received` events.  `chat.js` maintains a
  bounded `Map<ciphertext_hex → first-seen timestamp>` and on
  every inbound chat checks if the ciphertext was already seen.
  Duplicates render as a normal inbound bubble PLUS an italic
  footnote `↻ duplicate of earlier message at HH:MM:SS`.  Not
  auto-suppressed — the IDS in Phase 4 is the thing that flags;
  the chat just shows them with the marker.

- **New tests** (`tests/test_peer_link_attacks.py`, 2 cases):
  end-to-end PeerLink runs that verify (a) MITM tampering fires
  `on_chat_decryption_failed` and zero `on_error`; (b) replays
  decrypt successfully and zero `on_chat_decryption_failed`,
  with at least one duplicate ciphertext bundle in the inbound
  stream.  All previously-passing tests still pass: **124/124
  OK** in ~3.5 s.

- **Training data regenerated.**  `data/training_data.csv` was
  stale post-fix (pre-fix replay rows had decrypt_failure_rate
  ≈ 0.35 because the AEAD was rejecting replays; post-fix that
  signal moves to ≈ 0 with `duplicate_payload_count` carrying
  the load).  Regenerated to 200 sessions with seed 20260430.

- **Cache-bust** on `chat.js` bumped to
  `?v=2026-04-30-phase3-fix` so browsers fetch the new JS without
  a hard refresh.

- **Doc audit (Issue 3):** `docs/DECISIONS.md` got two new entries
  ("Kind-only AAD…" and "`on_chat_decryption_failed` is its own
  callback…"); `docs/PHASE_LOG.md` (this entry); `README.md`
  gained a "Generate training data" subsection under "How to
  run"; `docs/HANDOFF.md` and `docs/PROJECT_STATE.md` updated
  with Phase 4 next steps.  No changes needed to
  `docs/ARCHITECTURE.md` — the Phase-3 sections describe behaviour
  as it now stands; the AAD comment block in `core/peer_link.py`
  was rewritten to match the kind-only design.

## 2026-05-12 — Phase 4B: Live IDS integration

Phase 4B integrates the trained Random Forest into the running application
so attack windows produce real-time `threat_alert` SocketIO events.  No UI
work (that is Phase 4C); all changes are backend only.

### `ai/ids_live.py` — LiveIDS classifier wrapper (new file)

`LiveIDS` loads the saved model bundle once at construction and exposes a
single `evaluate(features_dict) → state_dict` method called on every
`on_features_updated` event.

**State machine:**
```
warming_up → monitoring → alerting → monitoring
```
- `warming_up`: fewer than `min_observations_required` (default 3) windows
  seen; probabilities computed but no alert decisions made.  Prevents flaky
  early alerts when the sliding feature window is partially filled.
- `monitoring`: past warm-up, no active alert.
- `alerting`: active alert — an attack class crossed `alert_threshold_fire`
  (0.70) and its probability has not yet fallen below `alert_threshold_clear`
  (0.50).

**Hysteresis design:**
- Fire: if NOT alerting and any non-normal class P ≥ 0.70, fire.
  When multiple classes qualify, the highest-probability one wins.
- Stay: while alerting, check only the *active* alert's own probability —
  never switch attack type mid-alert; let it clear first.
- Clear: if alerting and the active alert's class P < 0.50, clear.

The fire/clear asymmetry (0.70 vs 0.50) prevents single-window probability
noise from toggling alerts on every other tick.

**NaN handling:** NaN values in a feature window log a warning and return
the previous state unchanged (no-op).

**Error on missing model:** `FileNotFoundError` at construction if the pkl
does not exist — fail-fast at startup, not on first prediction.

**`reset()`:** clears `observation_count` and `active_alert`; called when
a peer disconnects so stale alert state does not bleed into a new session.

### `config.py` — new Phase 4B constants

```python
IDS_MODEL_PATH = "ai/trained_model.pkl"
IDS_ALERT_THRESHOLD_FIRE = 0.70
IDS_ALERT_THRESHOLD_CLEAR = 0.50
IDS_MIN_OBSERVATIONS = 3
IDS_ENABLE = True
```

`IDS_ENABLE = False` skips IDS construction entirely; app runs as Phase 3.

### `core/peer_link.py` — IDS wiring

- `set_ids(ids)` method attaches a `LiveIDS` instance after construction.
  PeerLink functions normally (no alerts) if no IDS is attached.
- `_ids_last_state` tracks the previous IDS state for transition detection.
- Two new callbacks: `on_threat_alert(alert_event)` and
  `on_threat_cleared(cleared_event)`.
- `_record_frame` now calls `ids.evaluate(features)` after firing
  `on_features_updated`, then calls `_handle_ids_state_transition`.
- `_handle_ids_state_transition` fires:
  - `on_threat_alert` on monitoring→alerting (first alert) OR
    alerting→alerting with confidence delta ≥ 0.10.
  - `on_threat_cleared` on alerting→monitoring.
- `ids.reset()` called in `_reader_loop` PeerDisconnectedError handler.

### `app.py` — startup wiring + SocketIO emission

- At `create_app` time (once per process): constructs `LiveIDS` if
  `config.IDS_ENABLE` is True.  Failure is non-fatal — logs clearly and
  continues without IDS (Phase 3 behaviour preserved, demo still works).
- In `on_start_sync`: calls `ids.reset()` then `link.set_ids(ids)` before
  kicking off `link.connect()`.
- `on_threat_alert` callback emits `threat_alert` SocketIO event:
  `{type, confidence, probabilities, timestamp, features_snapshot}`.
  `features_snapshot` contains only `decrypt_failure_rate` and
  `duplicate_payload_count` — keeps the payload small.
- `on_threat_cleared` callback emits `threat_cleared` SocketIO event:
  `{previously_alerting_type, duration_seconds, timestamp}`.

### Tests: `tests/test_ids_live.py` (9 new methods)

| Method | What it verifies |
| --- | --- |
| `test_warming_up` | state = warming_up for obs < min_obs |
| `test_basic_alert_fires` | high mitm prob → alerting, type=mitm |
| `test_alert_clears` | prob drop below clear threshold → monitoring |
| `test_hysteresis_does_not_flap` | exactly one fire + one clear |
| `test_multiple_classes_above_threshold` | highest prob wins |
| `test_no_alert_for_normal` | clean traffic never alerts |
| `test_reset_clears_state` | reset() zeros count + alert |
| `test_missing_model_raises_clearly` | FileNotFoundError with path |
| `test_disable_ids_in_peerlink` | no IDS → no alert, features still fire |

State-machine tests use `_ControlledLiveIDS` (scripted probability sequences).
Loading tests use a synthetic 5-tree RF bundle built in `setUpClass`.

**148/148 tests pass** (139 prior + 9 new) in ~5 s.

## 2026-05-13 — Phase 4C: Threat-detection UI

Phase 4C turns the invisible Phase-4B SocketIO events into a
demo-ready visual "the IDS just caught an attack" moment.
All work is frontend-only except for one small backend addition
(the continuous `ids_probabilities` event).

### Backend addition: `ids_probabilities` event (`app.py`)

A new `_on_features_updated` callback is wired in `on_start_sync`.
It fires on every feature window (same cadence as the IDS evaluation,
every `FEATURE_UPDATE_EVERY = 5` frames), calls
`_ids_instance.current_state()` to retrieve the previous window's
classification, and emits a `ids_probabilities` SocketIO event:

```python
{
  "probabilities": {"normal": 0.95, "mitm": 0.03, "replay": 0.02},
  "state": "monitoring",           # "warming_up" | "monitoring" | "alerting"
  "active_alert_type": null,       # "mitm" | "replay" | null
  "active_alert_confidence": null, # float | null
  "timestamp": "2026-05-13T14:23:00+00:00"
}
```

The event is high-frequency and fire-and-forget (no ack needed);
its purpose is to animate the gauge smoothly rather than just
flipping between on/off states on `threat_alert` / `threat_cleared`.

**Reconnect replay:** `on_start_sync` also stores the latest payload
in `state["ids_last_probabilities"]` and the active alert in
`state["ids_last_alert"]` (cleared to `None` when `threat_cleared`
fires).  `on_browser_connect` replays both so a refreshed browser tab
immediately sees the current gauge level and any active alert banner.

The existing `_on_threat_alert` callback was extended to write
`state["ids_last_alert"] = payload` before emitting; `_on_threat_cleared`
writes `None` to clear it.

### Frontend: `templates/chat.html`

Four new `flex-none` strip elements inserted between `#reconnect-banner`
and `<main>` (all hidden by default, revealed progressively):

1. **`#ids-status-bar`** — always-visible IDS gauge strip (shown on
   `sync_complete`).  Contains: "IDS — Anomaly Detection" label, a
   200 px horizontal bar track with two CSS zone-boundary markers at
   50% and 70%, a fill div, a percentage readout, and a level label.
2. **`#threat-banner`** — slides in on `threat_alert`, fades on
   `threat_cleared`.  Contains: ⚠ glyph, attack type, confidence %,
   started time + live "Xs ago" counter, evidence features.  Colour
   palette set dynamically (amber for MITM, rose for Replay).
3. **`#threat-cleared-bar`** — brief green "✓ Threat cleared" flash,
   auto-hides after 3 s.
4. **`#history-strip`** — horizontal row of coloured alert chips
   (max 5), newest on the left.  Hidden until the first chip is added.

### Frontend: `static/js/chat.js`

All new logic lives under a clearly delimited `Phase 4C` comment block.

**Gauge:**
- `updateGauge(probabilities, idsState, alertType)` — computes
  `max(P(mitm), P(replay))`, sets `fill.style.width` (smooth CSS
  transition), sets `fill.style.backgroundColor` (green→amber→red
  by zone + alert state), and updates the level label text/colour.
- Pulse animation (`ids-gauge-pulse` CSS class) added on alertType set,
  removed on clear.

**Banner:**
- `showThreatBanner(data)` — applies palette, populates content, removes
  `hidden`, adds `threat-banner-enter` CSS animation, starts the 1 s
  "Xs ago" interval timer (`_startAgoTimer`), and arms a 10 s auto-fade
  (`_scheduleAutoFade`).  Each new `threat_alert` re-arms the auto-fade
  timer so sustained alerts don't disappear while still active.
- `hideThreatBanner(showCleared, data)` — adds `threat-banner-exit`,
  sets `hidden` after 300 ms, optionally calls `_showClearedBar(data)`.
- `_showClearedBar` — shows `#threat-cleared-bar` with duration and
  auto-hides after 3 s.

**History chips:**
- `addHistoryChip(type, startTs)` — creates a styled `<span>` with
  CSS `ids-chip` class (scale-in animation), prepends to
  `#history-chips`, enforces the 5-chip limit, shows the strip.
  A CSS `data-tip` attribute drives the pure-CSS hover tooltip.
- `finalizeActiveChip(durationSeconds)` — finds the in-progress entry
  (endTs === null) and replaces `"active"` with the final duration.
  History is in-memory only; a page refresh resets it.

**History chip deduplication:** a new `threat_alert` event creates a
chip only if there is no currently-active chip of the same type.
Confidence-jump re-emissions (alerting→alerting with Δconf ≥ 0.10)
re-arm the banner but do not create a second chip.

**SocketIO event handlers (replacing the Phase-4B no-op stub):**
- `ids_probabilities` → unhides `#ids-status-bar`, calls `updateGauge`.
- `threat_alert` → `updateGauge`, `showThreatBanner`, maybe `addHistoryChip`.
- `threat_cleared` → reset gauge to monitoring/0, `finalizeActiveChip`,
  `hideThreatBanner(true, data)`.

**`sync_complete` hook:** one added line reveals `#ids-status-bar` so
the gauge shows "WARMING UP · 0%" immediately after sync, before the
first `ids_probabilities` event fires.

### Frontend: `static/css/style.css`

New rules appended (no existing rules touched):
- `.ids-gauge-fill` — `transition: width 0.8s cubic-bezier, background-color 0.6s`.
- `.ids-gauge-pulse` / `@keyframes ids-gauge-pulse` — opacity 1→0.75,
  1.5 s cycle.
- `.threat-banner-enter` / `@keyframes threat-banner-in` — translateY(-100%)→0
  + opacity 0→1, 300 ms.
- `.threat-banner-exit` / `@keyframes threat-banner-out` — reverse.
- `.threat-banner-glow` / `@keyframes threat-glow-pulse` — box-shadow +
  opacity pulse, 1.5 s.
- `.ids-chip` / `@keyframes ids-chip-in` — scale 0.75→1 + opacity 0→1, 200 ms.
- `.ids-chip[data-tip]:hover::after` — pure-CSS tooltip.

### Tests: `tests/test_ids_probabilities.py` (5 new methods)

| Method | What it verifies |
| --- | --- |
| `test_payload_has_required_keys` | all 5 keys present in emitted payload |
| `test_payload_values_monitoring` | monitoring state → active_alert_type = null |
| `test_payload_values_alerting` | alerting state → type + confidence populated |
| `test_ids_disabled_no_emit` | no IDS → no crash |
| `test_reconnect_replays_last_probabilities` | second client gets replayed ids_probabilities |

Uses Flask-SocketIO test client + patched `PeerLink.connect` to
avoid real TCP, and patched `PeerLink.set_ids` to capture the link
instance for direct callback invocation.

**153/153 tests pass** (148 prior + 5 new) in ~5 s.

## 2026-05-14 — Phase 4C polish: two UI bug fixes

### Issue 1 — IDS alert stuck active after demo panel "Stop Attacks"

**Symptom:** Clicking "Stop All Attacks" in the demo panel stopped the attack
simulators, but the IDS gauge stayed red and the history chip stayed "active"
for up to `FEATURE_WINDOW_SIZE` (20) normal frames while the sliding feature
window aged out the malicious observations.

**Root cause:** Technically correct IDS behaviour — the feature window has no
way to know the attack stopped.  Bad demo UX — the audience sees a red gauge
for ~30 s after the "Stop" button is clicked.

**Fix (`app.py`):** In `on_demo_stop`, after unregistering attacks, added an
explicit IDS cleanup block gated on `_ids_instance is not None`:

1. Snapshot the current IDS state (including `active_alert["since"]`) **before**
   calling `reset()` — needed to compute duration for `threat_cleared`.
2. Call `_ids_instance.reset()` — zeroes `observation_count`, `active_alert`,
   and `_last_state`.
3. Set `link._ids_last_state = None` — prevents `_handle_ids_state_transition`
   from firing a spurious `on_threat_cleared` on the very next `evaluate()` call
   (without this, `prev="alerting"` + `new="warming_up"` would trigger the
   callback a second time).
4. Emit `ids_probabilities` with `{normal: 1.0, mitm: 0.0, replay: 0.0,
   state: "monitoring"}` — gauge immediately snaps green.
5. If an alert was active, emit `threat_cleared` with the computed duration —
   banner fades and history chip gets its final duration.
6. Update `state["ids_last_probabilities"]` and `state["ids_last_alert"]` so a
   simultaneous reconnect sees the clean state.

This is explicitly demo-only convenience: in a real adversarial scenario the
victim would not know the attacker stopped.  The IDS warms up fresh on the
next incoming frames after the reset.

### Issue 2 — Chat input scrolls off screen with many messages

**Symptom:** After ~15+ messages, the user had to scroll the browser window
down to reach the input box.  Expected: input anchored at the bottom, chat
messages scroll up inside the chat area (standard chat-app pattern).

**Root cause:** Two compounding layout issues:
- `body` had `min-h-screen` (`min-height: 100vh`), allowing the body to grow
  taller than the viewport as chat content accumulated.
- `<main>` used `display: grid` with `grid-auto-rows: auto`, which sizes rows
  to their content.  Grid rows are not constrained by the grid container's
  height — the `flex-1 min-h-0` on main correctly limits its OWN height, but
  auto-sized grid rows are measured from content, not from the container.
  Result: the section stretched to its chat content, pushing the form below
  the fold.

**Fix (`templates/chat.html`):** Three-line change:

1. `body`: `min-h-screen flex flex-col` → `h-screen overflow-hidden flex flex-col`.
   `h-screen` pins the body to exactly 100 vh; `overflow-hidden` prevents
   any child from accidentally extending the page.
2. `<main>`: `flex-1 grid grid-cols-1 lg:grid-cols-2 min-h-0` →
   `flex-1 flex flex-col lg:flex-row min-h-0`.  Switching from grid to flex
   means each section uses `flex-1 min-h-0` to fill the allocated space
   rather than sizing to content.
3. Both `<section>` tags: added `flex-1 min-w-0` so they share the available
   height (small screens: stacked, each half height) / width (large screens:
   side by side, each half width).

The chain is now fully constrained at every level:
`body (100vh) → main (flex-1) → section (flex-1 min-h-0) → chat-log (flex-1 overflow-y-auto)`.

**153/153 tests pass** (no new tests — pure layout fix).

## 2026-05-16 — Phase 4D: end-to-end tests, demo guide, final docs

### Warning cleanup
- **UserWarning silenced** in `tests/test_ids_train.py`: two `model.predict()`
  calls now wrap numpy arrays in `pd.DataFrame(..., columns=FEATURE_NAMES)` so
  the feature names match `model.feature_names_in_`.  Tests pass under
  `-W error::UserWarning`.
- **ResourceWarning diagnosed and deferred**: `unclosed socket` warnings in
  `tests/test_peer_link.py` are Python 3.13 GC timing artefacts — the sockets
  are properly closed (fd=-1 confirmed via `alice._transport._sock`), but the
  cyclic GC runs the socket finaliser during a subsequent test's thread startup.
  No actual file-descriptor leak.  `PeerLink.close()` improved to join the
  reader thread (timeout 1.0 s) as a belt-and-suspenders improvement even
  though it doesn't fully suppress the cosmetic warning.  Decision documented in
  `docs/DECISIONS.md` § "Known non-blocking — ResourceWarning under Python 3.13 GC."

### End-to-end test suite (`tests/test_end_to_end.py`)
5 tests using real TCP + Flask-SocketIO test client:
- `TestEndToEndNormalSession.test_chat_round_trip_and_no_false_alert` — real
  TPM sync over loopback TCP, alice sends, bob receives `chat_received` with
  correct plaintext, no `threat_alert` fires.
- `TestEndToEndMITMDetection.test_mitm_detected_within_15_messages` — MITM
  registered via `demo_launch_mitm`, 15 messages sent, bob's IDS fires
  `threat_alert` type=mitm confidence≥0.70 (0.88 observed in practice).
- `TestEndToEndReplayDetection` — `@unittest.skip`: ReplayAttack injects once
  every 3 s; reaching 3 feature-window observations takes > 30 s.  Covered in
  `demo_final.md` §8.
- `TestEndToEndAlertClears.test_threat_cleared_fires_after_stop` — mock IDS in
  alerting state, `demo_stop_attacks` emits `threat_cleared`.
- `TestEndToEndAlertClears.test_threat_cleared_clears_stored_alert_state` —
  after clear, reconnecting client does not receive stale `threat_alert` banner.

**158/158 tests pass (1 skipped)** in ~7 s.

### `demo_final.md`
Comprehensive 10-12 minute viva demo guide covering: pre-demo setup,
dev-mode quick start, two-laptop demo-mode config, full narrated demo script
(§1 cold start + sync, §2 normal chat, §3 file transfer, §4 demo panel reveal,
§5 MITM launch, §6 MITM detection moment, §7 stop + clear, §8 Replay,
§9 refresh recovery, §10 cleanup), Q&A pointers table (8 common examiner
questions with one-line answer hints), and troubleshooting table.
Supersedes `demo_phase2.md` and `demo_phase3.md`.

### Documentation updates
- `README.md` — phase table updated (4B, 4C, 4D all ✅; Phase 5 scope updated);
  test count 74 → 158; layout section expanded to include `ai/`, `attacks/`,
  `data/`; `demo_final.md` listed.
- `docs/HANDOFF.md` — Phase 4D work summarised in "What was just being worked
  on"; "Next concrete steps" rewritten as Phase 5 scope.
- `docs/PROJECT_STATE.md` — Phase 4D Status → Complete ✅; test count 158/158;
  "In Progress" → nothing; "Next Steps" → Phase 5.
- `docs/ARCHITECTURE.md` — fixed two stale `SocketIOTransport` references to
  `TCPTransport`; added Phase 4A section documenting `ids_train.py`,
  `ids_report.py`, and the metadata bundle pattern.
- `docs/PHASE_LOG.md` — this entry.

## 2026-05-17 — Phase 5A: Performance Metrics Dashboard

### Benchmark scripts (`benchmarks/`)
- `benchmarks/__init__.py` — package marker.
- `benchmarks/benchmark_key_exchange.py` — standalone script.  CLI:
  `python benchmarks/benchmark_key_exchange.py [--runs 50] [--output ...]`.
  Times three key-exchange schemes with `--runs` repetitions each:
  - **TPM neural** — `SyncProtocol` over `LoopbackTransport`; records
    `mean/median/std/min/max ms` and `avg_rounds`.
  - **RSA-2048** — keypair generation + OAEP encrypt/decrypt of 256-bit
    key; records total `mean_ms` plus `keypair_gen_ms_mean` and
    `encrypt_decrypt_ms_mean` as sub-costs.
  - **DH-2048** — parameters generated once (recorded as
    `param_gen_ms_one_time`), then `--runs` agreement rounds (both sides
    generate private keys, exchange public keys, derive shared secret,
    SHA-256 to 256 bits).  Agreement mean recorded separately.
  - Outputs a structured JSON to `benchmarks/results/key_exchange.json`.
  - Actual results on this machine (50 runs): TPM 41 ms / 221 rounds,
    RSA 68 ms (keygen 65 ms), DH agreement 10 ms (param-gen 39 s one-time).
- `benchmarks/benchmark_throughput.py` — standalone script.  Times
  AES-256-GCM encrypt + decrypt for sizes 64 B → 4 MB, up to 100 runs
  per size within a 5 s time budget.  Records per-direction
  `encrypt_throughput_mbps` and `decrypt_throughput_mbps`.
  Outputs to `benchmarks/results/throughput.json`.
  - Actual results: peaks at ~7.6 GB/s for large messages (hardware AES
    acceleration); per-call overhead dominates at 64 B (28 MB/s enc).
- `benchmarks/results/` — pre-populated with `key_exchange.json` and
  `throughput.json` from the initial benchmark run.

### IDS latency tracking (`ai/ids_live.py`)
- Added `_latency_measurements: list[float]` (ms, capped at 100) to
  `LiveIDS.__init__`.  NOT cleared by `reset()` — measurements accumulate
  across sessions within one process lifetime.
- `record_alert_latency(attack_start_time, detection_time)` — called by
  `app.py` when an alert fires after a demo-panel attack launch.  Stores
  `(detection_time - attack_start_time) * 1000` ms.
- `get_latency_stats()` — returns `{count, mean_ms, median_ms, min_ms,
  max_ms, measurements_ms}`.  All scalar values are `None` when count is 0.

### `app.py` additions
- `import json`, `from pathlib import Path` added.
- Session state gains `messages_encrypted` and `bytes_encrypted` counters,
  incremented in `on_send_chat`.
- `_attack_start_times` dict and `_attack_start_lock` added at `create_app`
  scope; `on_demo_mitm` / `on_demo_replay` store `time.time()` on launch.
- `_on_threat_alert` reads and consumes the stored start time; calls
  `ids.record_alert_latency()` if both are set.
- Route `GET /metrics` — renders `templates/metrics.html`.
- Route `GET /api/metrics_data` — reads `benchmarks/results/*.json` from
  disk (returns `null` if absent), queries `ids.get_latency_stats()`, and
  returns a JSON blob with keys `key_exchange`, `throughput`, `ids_latency`,
  `session`.

### Dashboard UI (`templates/metrics.html`, `static/js/metrics.js`)
- `templates/metrics.html` — standalone page matching the dark terminal
  theme.  Four sections: §1 key-exchange bar chart + summary table,
  §2 AES-GCM throughput line chart (log x-axis) + table, §3 IDS
  latency histogram + stat tiles, §4 system info + session stats.
  Linked from `chat.html` header via a small `metrics` link.
- `static/js/metrics.js` — fetches `/api/metrics_data` on load,
  renders all Chart.js charts using the existing teal/amber/rose palette.
  Auto-refreshes IDS latency and session stats every 5 s; other sections
  are static (benchmark data doesn't change during a session).

### Tests (`tests/test_benchmarks.py`)
Sixteen new tests across five test classes:
- `TestKeyExchangeBenchmark` (4): structure of TPM/RSA/DH results; `run_all`
  writes valid JSON.
- `TestThroughputBenchmark` (3): `bench_size` structure; throughput > 0;
  `run_all` writes valid JSON.
- `TestIdsLatencyTracking` (4): empty stats; record + retrieve; latency
  survives `reset()`; cap at 100 entries.
- `TestMetricsRoutes` (5): `/api/metrics_data` shape; missing-benchmark
  null handling; `/metrics` returns 200; all four section headers present;
  back-link exists.

**174/174 tests pass (1 skipped)** in ~23 s.

### Documentation
- `docs/HANDOFF.md` updated: Phase 5A in "What works"; next steps → Phase 5B.
- `docs/PROJECT_STATE.md` updated: Phase 5A ✅; 5B and 5C pending.
- `docs/ARCHITECTURE.md` updated: new "Phase 5A — Benchmarks & Metrics
  Dashboard" section.
- `docs/DECISIONS.md` updated: two new entries — standalone benchmark
  scripts; IDS latency approximation from button-click.
- `README.md` updated: benchmarks section; metrics dashboard section;
  test count 158 → 174.
- `demo_final.md` updated: new §11 "Metrics Dashboard" step (~1 min).

## 2026-05-17 — Phase 5A polish: IDS latency tracking fix

**Bug:** IDS §3 detection-latency section of `/metrics` stayed empty after
attacks even though the JS rendering and `/api/metrics_data` route were correct.

**Root cause:** In dev mode `launcher_dev.py` spawns alice and bob as two
separate OS processes with completely independent Python memory spaces.  When
the user clicks "Launch MITM" the `demo_launch_mitm` SocketIO event fires in
*alice's* process and stores the timestamp in *alice's* `_attack_start_times`.
The MITM attack corrupts alice's outbound frames; *bob* is the one that receives
them, so bob's LiveIDS fires the `threat_alert`.  Bob's `_on_threat_alert`
looked up `_attack_start_times["mitm"]` in *bob's* process — always `None`.
`record_alert_latency` was never called.  The same applied to Replay attacks.

**Fix:** Added a fire-and-forget server-to-server HTTP POST from the attacking
process (alice) to the receiver's Flask server (bob) immediately after the demo
button stores the local timestamp.

Changes in `app.py`:
- Added `import http.client` to top-level imports.
- Added `_notify_peer_attack_start(attack_type, ts)` helper inside the
  `if config.DEMO_MODE:` block.  Connects to `127.0.0.1:{peer_flask_port}`,
  POSTs `{"type": attack_type, "ts": ts}` with a 1 s timeout, swallows all
  exceptions (silent in two-laptop demo mode where localhost doesn't reach
  the peer machine).
- Added `POST /api/record_attack_start` route inside the DEMO_MODE block.
  Stores the received timestamp in the local `_attack_start_times` so that
  when the receiver's `_on_threat_alert` fires it finds the timestamp and
  can call `record_alert_latency` correctly.
- Modified `on_demo_mitm` and `on_demo_replay`: store launch time in a local
  variable `t_launch`, pass it to `_attack_start_lock`, and spawn a daemon
  thread calling `_notify_peer_attack_start`.

**Tests:** 4 new tests in `TestRecordAttackStart` (test_benchmarks.py):
valid mitm payload → 200 + ok=True; valid replay payload → 200 + ok=True;
unknown type silently ignored; empty body silently ignored.

**178/178 tests pass (1 skipped).**
