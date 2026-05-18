# Architecture

This is a living document. Update it whenever a module is added or its public
interface changes.

## High-level vision (all 5 phases)

```
+-------------+        Public channel        +-------------+
|  Device A   |  <------------------------>  |  Device B   |
|             |   (TPM sync, then ciphertext)|             |
+-------------+                              +-------------+
       |                                            |
       v                                            v
   Tree Parity Machine  --- mutual learning -->  Tree Parity Machine
       |                                            |
       v  shared synchronized weights               v
   SHA-256 -> 256-bit AES key                   SHA-256 -> 256-bit AES key
       |                                            |
       v                                            v
   AES-256-GCM encrypt  ----- ciphertext ----->  AES-256-GCM decrypt
                                                    |
                                                    v
                                            Random Forest IDS
                                       (flags MITM / replay anomalies)
```

Phase 1 implements the left/right *vertical* paths only — neural key agreement
and authenticated encryption, fully in-process.  The horizontal "wire" between
devices and the IDS appear in later phases.

## Phase 1 modules

### `config.py`
Single source of truth for tunable parameters.  No other file may hard-code
values that belong here (TPM dimensions, AES nonce/tag sizes, peer host/port
placeholders, role identifiers).

### `core/tpm.py` — `TreeParityMachine`
A Tree Parity Machine is a feed-forward network with `K` hidden perceptrons,
each receiving its own slice of `N` ternary inputs, and a single output equal
to the product of the hidden-unit signs.  Weights are integers in `[-L, L]`.

Public interface:
- `__init__(K, N, L, rng=None)` — construct a TPM with random weights in `[-L, L]`.
- `generate_random_inputs()` — produce a `(K, N)` array of `±1` inputs.
- `compute_output(inputs)` — return `(tau, sigmas)` where `tau ∈ {-1, +1}` is
  the network output and `sigmas` are the per-hidden-unit outputs.
- `update_weights(inputs, partner_output, learning_rule="hebbian")` — apply
  the chosen learning rule iff the local output equals the partner output.
  Supported rules: `"hebbian"`, `"anti_hebbian"`, `"random_walk"`.
- `export_weights()` — return a flat `numpy.int8` array suitable for hashing.
- `weight_fingerprint()` — SHA-256 of the exported weights, used to verify sync.

### `core/sync_protocol.py` — three-layer split

The synchronisation code is split into three layers so the same protocol
runs in-process (Phase 1, for tests and the demo) and across the network
(Phase 2 onwards) without changes to the protocol logic itself.

```
   TreeParityMachine            (pure math: forward pass + weight update,
        ^                        no notion of peers or transports)
        | owns one
   SyncSession                  (per-side protocol loop: handshake →
        |                        rounds → two-party termination)
        | uses one
   SyncTransport                (abstract send/recv primitives)
   /          \
  /            \
 LoopbackTransport      (Phase 2) TCPTransport
 (in-process queues)
```

**TPM update gate** (preserved from Phase 1, do not erode in any new
transport):

> Weight updates apply only when local and remote tau agree, and within
> that, only to hidden units whose sigma equals tau.  **Forgetting this
> gate breaks synchronization.**

The gate lives inside `TreeParityMachine.update_weights`; any
transport-level work must continue to call it with `partner_output`
set to the actual remote tau (not a placeholder, not "always equal"),
so the gate can do its job.

#### `SyncTransport` (abstract base)
Tiny interface that any transport must implement.  The protocol is
strictly turn-based, so transports do not need framing or type tags —
call ordering on both sides is enough.
- `send_tau(tau: int)`, `recv_tau() -> int`
- `send_fingerprint(fp: bytes)`, `recv_fingerprint() -> bytes`
- `exchange_seed(local_seed: int) -> int` — both sides exchange seeds
  during the handshake; the returned value MUST be identical on both.
  Implementations may use first-writer-wins, XOR, or initiator-wins —
  the contract is only "both sides agree."
- `close() -> None`

`recv_*` calls raise `TransportTimeout` if the peer falls silent;
`SyncSession` catches this and returns a failed `SyncResult` rather
than hanging.

#### `LoopbackTransport`
In-process implementation backed by two FIFO queues.  Built in pairs
via `make_loopback_pair(recv_timeout=...)` — each transport's send
queue is the other's recv queue.  Used by the Phase 1 convenience
wrapper and by tests.  Items are enqueued as `(kind, value)` tuples;
unexpected kinds raise `RuntimeError` so protocol bugs surface early.

#### `SyncSession`
Owns one TPM, one transport, and a role (`INITIATOR` / `RESPONDER`).

Public interface:
- `SyncSession(tpm, transport, role=INITIATOR, max_rounds=…,
  log_every=…, learning_rule=…, local_seed=None,
  fingerprint_check_every=1)`
- `synchronize() -> SyncResult` — runs handshake → round loop →
  termination.  Returns the same `SyncResult` shape as Phase 1.

Per-round loop (both sides identical):
1. Generate input vector from the agreed seed (deterministic; both
   sides produce the same vector each round).
2. Compute local tau via `tpm.compute_output(inputs)`.
3. Exchange taus via the transport.
4. Update local weights only when `local_tau == remote_tau` (the
   update gate).
5. Every `fingerprint_check_every` rounds, exchange fingerprints; if
   they match, both sides terminate with success.
6. After `max_rounds` without agreement, return failure.

#### `SyncProtocol` (Phase 1 backwards-compat surface)
Convenience wrapper that takes both TPMs in one process, builds a
paired `LoopbackTransport`, creates two `SyncSession`s, and runs them
on background threads.  Same constructor signature as Phase 1; same
`SyncResult` shape on return.  Existing tests and `demo_phase1.py`
keep using this wrapper unchanged.

#### `SyncResult`
Frozen dataclass: `success`, `rounds`, `elapsed_seconds`,
`final_fingerprint`.  Same shape on every code path (single-side
session, two-party wrapper, success, failure).

### `core/crypto_engine.py` — `CryptoEngine`
Thin wrapper around `cryptography.hazmat.primitives.ciphers.aead.AESGCM`.

Public interface:
- `CryptoEngine(key: bytes)` — 32-byte key required.
- `CryptoEngine.derive_key_from_tpm(weights) -> bytes` (classmethod) — SHA-256
  digest of the canonicalised weight bytes; returns 32 bytes.
- `encrypt(plaintext: bytes, associated_data: bytes | None = None) -> bytes` —
  returns `nonce(12) || ciphertext || tag(16)`.
- `decrypt(bundle: bytes, associated_data: bytes | None = None) -> bytes` —
  raises `cryptography.exceptions.InvalidTag` on tampering.

## Module interactions (Phase 1)

```
demo_phase1.py
   |
   |-- builds two TreeParityMachine(K, N, L, seed=…)
   |-- hands them to SyncProtocol(...).synchronize()
   |        |
   |        |-- creates a paired LoopbackTransport
   |        |-- spawns two SyncSession threads (initiator + responder)
   |        |-- each session: handshake → mutual-learning rounds → terminate
   |
   |-- both TPMs now share identical weights
   |-- CryptoEngine.derive_key_from_tpm(tpm.export_weights()) on each side
   |-- CryptoEngine(key).encrypt(...) / decrypt(...)
```

No networking, no UI, no IDS in this phase.  Phase 2 introduces a
`TCPTransport` that plugs into the same `SyncSession`; the loop
body and TPM logic stay unchanged.

## Import convention

Inside the `core/` package, modules use **relative imports** for sibling
modules (e.g. `from .tpm import TreeParityMachine` in
`core/sync_protocol.py`).  For project-root modules — currently just
`config.py` — the convention is the **absolute** form `import config`,
because `ai_secure_comm/` is the runtime root on `sys.path`, not a
package (it has no top-level `__init__.py`).  The standard test and
demo invocations both run from inside `ai_secure_comm/`, which puts the
working directory on `sys.path` and makes `import config` resolve.

Phase 2 modules under a new top-level (e.g. `app/`) should follow the
same convention: relative imports inside the package, `import config`
from project-root modules.

## Phase 2 — network layer + web UI

Phase 2 turns the in-process Phase 1 stack into a runnable two-laptop
demo.  Two **independent channels**, deliberately separated:

```
                                     ┌─────────────────────┐
                                     │  Browser (alice)    │
                                     │  127.0.0.1:5001     │
                                     └──────────┬──────────┘
                                                │  SocketIO  (UI events)
                                                ▼
              ┌───────────────────────────────────────────────────┐
              │  app.py --role alice  (Flask + Flask-SocketIO)    │
              │                                                   │
              │   PeerLink(alice)  ─────────────┐                 │
              └────────────────┬────────────────┘                 │
                               │  plain TCP                       │
                               │  framed: kind(1) | len(4) |      │
                               │           payload                │
                               ▼                                  │
              ┌───────────────────────────────────────────────────┐│
              │  app.py --role bob   (Flask + Flask-SocketIO)    ││
              │                                                   ││
              │   PeerLink(bob)                                   ││
              └──────────┬────────────────────────────────────────┘
                         │  SocketIO  (UI events)
                         ▼
              ┌─────────────────────┐
              │  Browser (bob)      │
              │  127.0.0.1:5002     │
              └─────────────────────┘
```

**Channel 1 — Browser ↔ Flask (per role):** SocketIO over the role's
Flask port (`FLASK_PORT_ALICE` / `FLASK_PORT_BOB` in dev; both 5001 on
demo day).  Carries UI events: `start_sync`, `send_chat`,
`sync_progress`, `chat_received`, `file_*`, etc.

**Channel 2 — alice ↔ bob TCP:** A single plain-TCP connection between
the two Python processes.  Carries the TPM sync handshake and, after
sync completes, the encrypted application traffic (chat messages and
file chunks).  We deliberately use **one socket for the entire
session** — the cryptographic key derived from sync stays bound to
this connection.

### Backend session state and the reconnect-replay pattern

The Flask app in `app.py` carries an explicit session-state machine
for its `PeerLink` so a browser tab can refresh without losing the
synced indicator:

```
   idle ─[start_sync]─→ syncing ─[on_sync_complete]─→ synced
                            │
                            └─[on_error]─→ error
```

Cached fields: `key_fingerprint`, `sync_rounds`, `sync_time_ms`,
`last_progress` (the most recent `on_sync_progress` payload),
`last_error`.  The state never resets — one process, one session.

When a SocketIO client connects (whether the first tab or a refresh),
the connect handler reads `status` and emits the matching event back
to *just that client*:

| Status      | Replay event                                                          |
| ---         | ---                                                                   |
| `synced`    | `sync_complete` with `replay: true` and the cached key fingerprint    |
| `syncing` + cached progress | `sync_progress` with `replay: true` and the cached round count |
| `syncing` + no progress yet | `sync_in_progress` with `replay: true`                |
| `error`     | `error` with the cached message and `replay: true`                    |
| `idle`      | nothing — JS waits 2 s and then triggers a fresh `start_sync`         |

The frontend (`static/js/chat.js`) installs a 2-second timer on
`socket.connect`; *any* state event cancels it.  On `sync_complete`
with `replay: true`, the JS shows a subtle `(reconnected — earlier
messages not shown)` system bubble because chat history is in-memory
only.  Net result: a refresh during a synced session restores the UI
in ~10 ms with no fresh TPM sync.

### Frame format on the alice ↔ bob channel

Every message is a length-prefixed frame:

```
+----------+--------------------+-------------------+
| kind     | length (4 bytes,   | payload           |
| (1 byte) |  big-endian uint)  | (length bytes)    |
+----------+--------------------+-------------------+
```

5-byte fixed header; payload size bounded only by RAM.  TCP can
deliver bytes in any chunking, so the reader loops `recv()` until
each region has fully arrived.  See `core/transport_tcp.py`.

### Frame kinds

| Constant         | Value | Direction | Plaintext payload | Used by |
| --- | --- | --- | --- | --- |
| `KIND_TAU`         | `0x01` | both | 1 signed byte (±1) | sync |
| `KIND_FINGERPRINT` | `0x02` | both | 64-char hex digest | sync |
| `KIND_SEED`        | `0x03` | both | 8-byte BE uint     | sync handshake |
| `KIND_CHAT`        | `0x10` | both | AES-GCM bundle of UTF-8 text | app |
| `KIND_FILE_META`   | `0x12` | sender→receiver | AES-GCM bundle of JSON | app |
| `KIND_FILE_CHUNK`  | `0x11` | sender→receiver | header (24 B) + AES-GCM bundle | app |
| `KIND_CONTROL`     | `0x20` | both | AES-GCM bundle of JSON | reserved |

Sync-phase frames (TAU/FINGERPRINT/SEED) carry plaintext on the wire —
they leak nothing useful because TPM mutual learning's security
assumes a passive observer sees the public inputs and outputs.  All
app-phase frames carry **only ciphertext**.

### `core/transport_tcp.py` — `TCPTransport`, `TCPListener`
Plain-TCP `SyncTransport`.  Same six-method interface as
`LoopbackTransport`; the protocol code is unaware of which one carries
its bytes.

- `TCPListener(host, port)` — bind once; expose `port` for tests that
  use `port=0`; one-shot `accept()`.
- `bind_and_accept(host, port, timeout)` — convenience wrapper around
  `TCPListener` for the simple case.
- `connect(host, port, timeout)` — dials the peer; retries on
  `ConnectionRefused` until `timeout` (handles the dialer-races-listener
  case automatically).
- `TCPTransport.set_recv_timeout(None)` switches to blocking-recv;
  `PeerLink` flips this after sync to make app-mode reads block
  indefinitely.
- `_send_frame` is guarded by a `Lock` so chat/file uploads from
  multiple threads can share one transport safely.
- Exceptions: `TransportTimeout` on stalls (same type
  `LoopbackTransport` raises), `PeerDisconnectedError` on EOF /
  socket close, `FrameKindMismatch` if a typed recv sees the wrong
  kind during sync.

### `core/peer_link.py` — `PeerLink`
The session-lifetime owner of one peer's TCP transport.  Combines:

1. **Connect** — dial or bind based on `INITIATOR_ROLE`.
2. **Sync** — wraps the `TCPTransport` in a `_ProgressTransport`
   decorator, runs `SyncSession`, fires `on_sync_progress` callbacks
   every `SYNC_PROGRESS_EVERY` rounds.
3. **Derive key** — `CryptoEngine.derive_key_from_tpm(weights)`.
4. **App mode** — switches transport to blocking recv, starts a
   reader thread that decrypts and dispatches `CHAT` / `FILE_META` /
   `FILE_CHUNK` / `CONTROL` frames via callbacks.

**The same TCP socket is reused post-sync** — see `_establish_tcp` and
the reader loop.  Opening a second connection would mean the app
traffic is unauthenticated relative to the sync (a fresh socket could
be from anyone).

AAD discipline (Phase 3-onward, post-bugfix):
- Chat / file-meta / control: kind-only — `struct.pack(">B", kind)`.
  We deliberately do NOT include a per-direction sequence number,
  even though the textbook answer for replay protection is to
  bind one in.  Reason: this is a pedagogical project whose point
  is showing an *AI-based* IDS catching attacks that aren't
  already eliminated by the cryptographic layer.  Binding seq
  into AAD makes replay an AEAD-layer concern that the IDS never
  sees.  Kind-only AAD lets replays decrypt cleanly and surface
  as visible duplicates the IDS can flag via
  `duplicate_payload_count`.  See `docs/DECISIONS.md` →
  "Kind-only AAD…" for the full rationale.  The kind byte still
  authenticates so an attacker can't reframe between CHAT /
  CONTROL / FILE_META on the wire.
- File chunks: `f"{file_id}:{idx}/{total}".encode()` — bound to
  the logical file position, so chunk reorders and drops surface
  as `InvalidTag`.  This is unrelated to replay defence and is
  the right design here.

Phase 4's IDS sees `InvalidTag` (from MITM tampering) AND
`duplicate_payload_count` (from replay) as its two main signals
— `decrypt_failure_rate` and `duplicate_payload_count` are the
load-bearing features in the schema.

### `core/file_transfer.py` — chunking helpers
- `make_file_meta(path, chunk_bytes)` — UUID4 file_id, SHA-256 digest,
  size, total_chunks.  Rejects files larger than `FILE_MAX_BYTES`.
- `iter_chunks(path, chunk_bytes)` — yields `(idx, bytes)` in order.
  Empty files yield exactly one zero-length chunk so the receiver's
  "all chunks present" check is uniform.
- `aad_for_chunk(file_id, idx, total)` — deterministic AAD string.
- `assemble_chunks(file_id, total, dict)` — orders by index, complains
  if any are missing.
- `verify_sha256(plaintext, hex)` — trailing integrity check.

### `app.py` — role-aware Flask + SocketIO
- `python app.py --role alice` / `--role bob`.
- One Flask app per process; SocketIO with `async_mode="threading"`.
- Routes: `GET /` (renders `chat.html`), `POST /upload`
  (drag-and-drop file ingest), `GET /download/<file_id>`
  (completed-file blob), `GET /_demo` (hidden 404 — Phase 3 reserves
  this path).
- SocketIO events from browser: `start_sync`, `send_chat`.
- SocketIO events to browser: `hello`, `sync_progress`,
  `sync_complete`, `chat_received`, `chat_sent`, `file_meta_received`,
  `file_chunk_received`, `file_sent`, `file_complete`,
  `peer_disconnected`, `error`, `threat_alert` (reserved for Phase 4).
- The `PeerLink` runs on a background thread spawned from
  `start_sync`; its callbacks emit SocketIO events back to the browser.

### `templates/chat.html`, `static/js/chat.js`, `static/css/style.css`
Single role-aware template.  Tailwind via CDN, Socket.IO via CDN.
Two-column layout: chat bubbles + drop zone on the left, wire-view
panel on the right.  No build step.  The CSS file holds only what
Tailwind utilities can't express cleanly (the sync-bar pulse animation
and the wire-view scrollbar styling).

### `launcher_dev.py`, `network_check.py`
- `launcher_dev.py` — single-command dev mode: spawns both roles,
  opens both browser tabs, forwards subprocess logs prefixed by
  `[alice]` / `[bob]`, Ctrl+C tears everything down.
- `network_check.py` — demo-day pre-flight: initiator binds, responder
  pings + TCP-connects.  Clear ✓/✗ output and exit code.

## Phase 3 — Attack simulation + feature extraction

Phase 3 adds two adversarial simulators (MITM and Replay), a hidden
keyboard-shortcut UI to launch them during a demo, and an offline
training-data generator that produces labelled feature rows the
Phase-4 IDS will train on.  No machine learning yet — this phase is
about producing both the attack signal and the feature pipeline that
captures it.

### `attacks/` — registry + simulators

```
                   per-PeerLink
   TCPTransport ───────────────► AttackRegistry
       │                              │  iterates active attacks
       │  every send / recv:          │  in registration order
       │  apply_outbound / apply_inbound
       │                              │
       v                              v
   socket bytes                  ┌─────────────────────┐
                                 │  Attack instances   │
                                 │  - MITMAttack       │
                                 │  - ReplayAttack     │
                                 │  - (future…)        │
                                 └─────────────────────┘
```

The registry is **per-`TCPTransport`** rather than a process-global
singleton.  Reason: the training-data generator runs alice and bob
in the same process on different threads — a global registry would
mean an attack registered on alice also fires on bob's outbound,
silently corrupting session labelling.  The live `app.py` has one
TCPTransport per process, so it sees no difference.

The two transport hooks (`_send_frame` and `recv_frame`) call
`apply_outbound` / `apply_inbound` only when a registry is attached;
the no-attack path is essentially zero-cost.  Hooks return
``Optional[Tuple[int, bytes]]`` — modified tuple, unchanged tuple,
or ``None`` to drop the frame entirely.  Recv-side drops cause the
reader loop to silently fetch the next frame.

#### `MITMAttack`
On every outbound CHAT frame, with probability
``config.MITM_TAMPER_PROBABILITY`` (default 0.30), flips a random
bit in the ciphertext payload.  Sync-phase frames
(TAU/FINGERPRINT/SEED) are explicitly excluded — Tree Parity
Machine sync's security model assumes a passive observer; a
tampering simulator that broke it would just measure "AES-GCM
detects garbage", not the IDS signal.

What the receiver sees: `cryptography.exceptions.InvalidTag` on
each tampered chat, surfaced as a *dedicated*
`PeerLink.on_chat_decryption_failed(bundle)` callback (NOT the
generic `on_error`).  `app.py` re-emits as a `chat_decryption_failed`
SocketIO event; `chat.js` renders a red/orange-bordered
"⚠ Tampered ciphertext rejected" bubble + a `✗ rejected` wire-view
marker.  The Phase-4 IDS keys on `decrypt_failure_rate` rising in
the feature window.

#### `ReplayAttack`
Maintains a bounded FIFO of recently-seen CHAT frames
(``config.REPLAY_BUFFER_SIZE``, default 5).  A daemon thread wakes
every ``config.REPLAY_INTERVAL_S`` seconds (default 3 s) and
re-injects a randomly-chosen buffered frame via
``transport._send_frame(KIND_CHAT, payload)`` — same wire shape as
a legitimate send.  Because the post-Phase-3 AAD is kind-only
(no per-direction seq), the replayed ciphertext **decrypts
successfully** at the receiver — the AEAD doesn't see anything
wrong with it.  The IDS detects the replay via the elevated
`duplicate_payload_count`.  The duplicate signal is the
discriminator that separates replay from MITM.

Self-injection guard: the replay attack tracks payloads it just
re-injected and skips re-buffering them when they come back through
its own outbound hook.  Otherwise one captured frame would loop
indefinitely.

### `ai/feature_extractor.py` — sliding window

```
   PeerLink._record_frame(kind, payload, direction, decrypt_success)
                       │
                       │  records FrameRecord into:
                       v
   FeatureExtractor (deque, maxlen=config.FEATURE_WINDOW_SIZE = 20)
                       │
                       │  every config.FEATURE_UPDATE_EVERY (= 5) frames:
                       v
   PeerLink.on_features_updated(extract_features() dict)
                       │
                       │  consumed by:
                       ▼
   - Phase 3:  data/generate_training_data.py → CSV row
   - Phase 4:  live IDS classifier → threat_alert SocketIO event
```

Canonical feature schema (the column order in
`data/training_data.csv` and the feature names of the Phase-4
model — do not rename without retraining):

| Feature                       | Signal it captures                                    |
| ---                           | ---                                                   |
| `mean_inter_arrival_ms`       | typing cadence; replay's regular timer is anomalous   |
| `std_inter_arrival_ms`        | spread; periodic replay flattens it                   |
| `mean_payload_size`           | normal AES bundle size baseline                       |
| `std_payload_size`            | spread; injected duplicates are always same-sized     |
| `decrypt_failure_rate`        | **MITM** primary signal; also lit by Replay          |
| `duplicate_payload_count`     | **Replay** primary signal; ~0 under MITM             |
| `frame_rate_per_second`       | bursts of injected frames                             |
| `chat_frame_fraction`         | composition; lets the model condition on traffic mix  |
| `file_frame_fraction`         | "                                                     |
| `control_frame_fraction`      | "                                                     |

### `data/generate_training_data.py`

Standalone runner — no Flask, no UI, just `PeerLink` × N.  Per
session: bind a free port, spin alice + bob in two threads, sync,
choose a label (50/25/25 normal/mitm/replay), register the attack
on alice's side if any, send 15–35 randomised chats, capture every
`on_features_updated` snapshot from BOTH sides, write each row to
the CSV with the session label.  See `data/training_data.csv` for
the produced dataset; ≥ 1500 rows from 200 sessions.

### Demo controls (hidden, Ctrl/Cmd+Shift+D)

`app.py` gates four SocketIO event handlers behind
``config.DEMO_MODE``:
- `demo_launch_mitm` — instantiates `MITMAttack`, registers, starts.
- `demo_launch_replay` — same for `ReplayAttack`.
- `demo_stop_attacks` — unregisters everything currently registered.
- `demo_status` — replays the active-attack list to a (re)connecting
  client.

Server emits `demo_attack_state` (full snapshot for the panel),
`demo_attack_active`, `demo_attacks_stopped`.  The browser-side
panel is a fixed-position overlay with red/orange "danger" palette
so the audience can tell at a glance these are adversarial
controls.  Pressing the chord toggles it; pressing again hides.

The Phase-4 `threat_alert` SocketIO event already has a stub
listener in `chat.js` (no UI); the IDS will start firing it next
phase without any frontend retrofitting.

## Module interactions (Phase 2)

```
launcher_dev.py
   ├─ subprocess: app.py --role alice
   │     └─ create_app("alice")  →  Flask + SocketIO on :5001
   │           └─ on "start_sync":  PeerLink("alice").connect()  (background thread)
   │                 ├─ TCPListener(BIND_HOST, PEER_TCP_PORT).accept()  ─────┐
   │                 ├─ SyncSession(tpm, ProgressTransport(transport), ...)  │ same
   │                 │     synchronize()  →  fingerprint match              │ TCP
   │                 ├─ CryptoEngine.derive_key_from_tpm(weights)            │ socket
   │                 └─ reader thread: recv_frame → decrypt → callback       │
   │                                                                         │
   └─ subprocess: app.py --role bob                                          │
         └─ create_app("bob")    →  Flask + SocketIO on :5002                │
               └─ on "start_sync":  PeerLink("bob").connect()                │
                     ├─ tcp_connect(PEER_HOST, PEER_TCP_PORT)  ──────────────┘
                     ├─ SyncSession(tpm, ProgressTransport(transport), RESPONDER)
                     ├─ CryptoEngine.derive_key_from_tpm(weights)
                     └─ reader thread: recv_frame → decrypt → callback
```

## Phase 4A — Offline IDS training pipeline

Phase 4A produces the Random Forest model that Phase 4B loads at runtime.
All training happens offline; no model-fitting code runs in the live app.

### `ai/ids_train.py` — offline trainer

**Entry point:** `python ai/ids_train.py` (or `from ai.ids_train import train_and_save`).

Reads `data/training_data.csv`, applies an optional attacker-perspective row
filter (rows where the attack label has zero receiver-side signal are dropped
— see `docs/DECISIONS.md` → "Training-time filter for attacker-perspective
rows"), fits a 100-tree `RandomForestClassifier(class_weight="balanced")`,
and serialises a **metadata bundle** via `joblib.dump`:

```python
{
    "model":          RandomForestClassifier,  # fitted
    "feature_names":  list[str],               # canonical FEATURE_NAMES order
    "label_encoder":  LabelEncoder,            # int ↔ class-name mapping
    "trained_on":     str,                     # CSV path
    "trained_at":     str,                     # ISO timestamp
    "n_samples":      int,                     # rows used for training + test
    "test_accuracy":  float,
    "test_size":      float,
    "random_state":   int,
    "hyperparams":    dict,                    # class_weight, n_estimators, …
    "filter_applied": bool,                    # whether the filter ran
}
```

The bundle pattern means Phase 4B can load one file and get everything it
needs — no schema drift between training and inference.

### `ai/ids_report.py` — evaluation report generator

Loads the trained bundle, re-splits identically (via `bundle["random_state"]`),
and writes four artefacts to `ai/report/`:

| File | Contents |
| --- | --- |
| `confusion_matrix.png` | Annotated heatmap on held-out test set |
| `feature_importances.png` | Horizontal bar chart (top features) |
| `classification_report.txt` | Per-class precision / recall / F1 |
| `model_summary.txt` | Hyperparams, split sizes, accuracy, macro F1 |

Phase-4A training results (1418 filtered rows, 80/20 split, seed 42):
accuracy **1.0000**, macro F1 **1.0000**.

## Phase 4B — Live IDS layer

Phase 4B adds a real-time threat classifier that sits between the
`FeatureExtractor` and the browser.  No new TCP connections are opened;
all new code wires into existing callback chains.

### Data flow

```
PeerLink._record_frame(kind, payload, direction, decrypt_success)
    │
    ▼
FeatureExtractor.record(...)               ← unchanged Phase 3 path
    │  every FEATURE_UPDATE_EVERY frames
    ▼
FeatureExtractor.extract_features()  →  features_dict (10 floats)
    │
    ├──→ on_features_updated(features_dict)  ← Flask callback unchanged
    │
    └──→ LiveIDS.evaluate(features_dict)
              │
              ▼
         state_dict = {state, active_alert, probabilities, observation_count}
              │
              ▼
    PeerLink._handle_ids_state_transition(state_dict, features_dict)
              │
              ├── monitoring→alerting or confidence delta ≥ 0.10:
              │       on_threat_alert(alert_event)
              │           └──→ socketio.emit("threat_alert", {...})
              │
              └── alerting→monitoring:
                      on_threat_cleared(cleared_event)
                          └──→ socketio.emit("threat_cleared", {...})
```

### `ai/ids_live.LiveIDS`

Thin wrapper around the saved Random Forest bundle.

**Construction:** `LiveIDS(model_path, alert_threshold_fire=0.70,
alert_threshold_clear=0.50, min_observations_required=3)`.  Loads the
bundle via `joblib.load` and builds an inverted label map
`{int_index → class_name}` from the bundle's `label_encoder`.  Raises
`FileNotFoundError` immediately if the model is absent — fail-fast at
startup.

**`evaluate(features_dict) → dict`:** Called on every `on_features_updated`
event.  Builds a named `pd.DataFrame` in canonical column order, calls
`model.predict_proba()`, applies the state machine, returns:
```python
{
    "state": "warming_up" | "monitoring" | "alerting",
    "active_alert": None | {"type": str, "confidence": float, "since": iso_str},
    "probabilities": {"normal": float, "mitm": float, "replay": float},
    "observation_count": int,
}
```

**State machine (hysteresis):**
```
warming_up ──[obs_count >= min_obs]──► monitoring
monitoring ──[P(attack) >= fire_thr]──► alerting   (highest-P class wins)
alerting   ──[P(active) <  clear_thr]──► monitoring  (type never switches)
```
Fire threshold (0.70) and clear threshold (0.50) form a 0.20-wide
hysteresis band that prevents UI flapping on single noisy windows.

**`reset()`:** zeroes `observation_count` and `active_alert`; called on
peer disconnect to prevent stale Phase N state bleeding into Phase N+1.

### SocketIO events added in Phase 4B

| Event | Direction | Payload |
| --- | --- | --- |
| `threat_alert` | server → browser | `{type, confidence, probabilities, timestamp, features_snapshot}` |
| `threat_cleared` | server → browser | `{previously_alerting_type, duration_seconds, timestamp}` |

`features_snapshot` contains only `decrypt_failure_rate` and
`duplicate_payload_count` — the two anomaly-hint features — to keep the
payload small.

### SocketIO events added in Phase 4C

| Event | Direction | Payload |
| --- | --- | --- |
| `ids_probabilities` | server → browser | `{probabilities, state, active_alert_type, active_alert_confidence, timestamp}` |

`ids_probabilities` fires on EVERY feature window (every
`FEATURE_UPDATE_EVERY = 5` frames), regardless of whether the IDS state
changes.  Its purpose is to animate the threat-level gauge smoothly.  The
payload is high-frequency and fire-and-forget — no application-level ack
or reliability guarantee is needed.  `probabilities` is the full
`{normal, mitm, replay}` triple.  `state` is
`"warming_up" | "monitoring" | "alerting"`.

**Reconnect replay:** `on_browser_connect` replays the most recent
`ids_probabilities` payload (stored in `state["ids_last_probabilities"]`)
and any active `threat_alert` (stored in `state["ids_last_alert"]`, cleared
to `None` on `threat_cleared`) to a freshly connecting tab, so the gauge
and banner are immediately correct after a browser refresh.

### Phase 4C — Threat-detection UI (`chat.html`, `chat.js`, `style.css`)

The browser-side IDS layer renders three visual components:

1. **IDS status bar** (`#ids-status-bar`) — always-visible horizontal
   gauge strip below the main header.  A colour-filled bar shows
   `max(P(mitm), P(replay))` on a 0–100% scale with zone markers at
   50% (green→amber) and 70% (amber→red).  Revealed on `sync_complete`;
   updated on every `ids_probabilities` event.

2. **Threat alert banner** (`#threat-banner`) — full-width colour-coded
   banner that slides in on `threat_alert` and fades on `threat_cleared`.
   Amber palette for MITM, rose palette for Replay.  Carries: attack type,
   confidence %, started time, live "Xs ago" counter, evidence features.
   Auto-fades after 10 s with no new `threat_alert`; re-armed by each
   new event.

3. **Alert history strip** (`#history-strip`) — horizontal row of ≤ 5
   coloured chips, newest first.  Each chip shows attack type, start time,
   and duration (or "active").  Hovering shows a tooltip.  In-memory only;
   does not survive a page refresh.

All transitions use CSS `transition` / `@keyframes` — no JS animation
loops, no `requestAnimationFrame`.  The gauge fill uses
`transition: width 0.8s cubic-bezier, background-color 0.6s`.

### Configuration (`config.py`)

```python
IDS_MODEL_PATH = "ai/trained_model.pkl"
IDS_ALERT_THRESHOLD_FIRE = 0.70
IDS_ALERT_THRESHOLD_CLEAR = 0.50
IDS_MIN_OBSERVATIONS = 3
IDS_ENABLE = True   # False → no IDS, app runs as Phase 3
```

### Graceful degradation

If `IDS_ENABLE = False` or if construction raises (model file missing,
corrupt bundle), `app.py` logs at ERROR and continues without IDS.  All
Phase 1–3 functionality (sync, chat, file transfer, attack simulators)
operates normally; `threat_alert` events simply never fire.  `PeerLink`
always operates correctly with `_ids = None`.

---

## Phase 5A — Benchmarks & Metrics Dashboard

### `benchmarks/` package

Two standalone benchmark scripts.  Neither is imported by any runtime
module — they are off-path tools used to populate `benchmarks/results/`
before a demo.

```
benchmarks/
├── __init__.py
├── benchmark_key_exchange.py   # TPM / RSA-2048 / DH-2048 timing
├── benchmark_throughput.py     # AES-256-GCM throughput vs. message size
└── results/
    ├── key_exchange.json       # written by benchmark_key_exchange.py
    └── throughput.json         # written by benchmark_throughput.py
```

**`benchmark_key_exchange.py`** — times three key-exchange schemes:

| Scheme | What is timed |
|---|---|
| TPM (neural) | `SyncProtocol.synchronize()` end-to-end over `LoopbackTransport` |
| RSA-2048 | key-pair generation + OAEP encrypt/decrypt of 256-bit session key |
| DH-2048 | both sides generate private keys, exchange public keys, derive + SHA-256 shared secret; parameter generation timed separately |

Output: `{tpm, rsa_2048, dh_2048, system_info}` — each scheme carries
`mean_ms, median_ms, std_ms, min_ms, max_ms` plus scheme-specific extras
(`avg_rounds`, `keypair_gen_ms_mean`, `param_gen_ms_one_time`, etc.).

**`benchmark_throughput.py`** — times AES-256-GCM encrypt + decrypt for
message sizes 64 B → 4 MB, up to 100 runs per size within a 5 s budget.
Records `encrypt_throughput_mbps` and `decrypt_throughput_mbps` per size.

### IDS latency tracking (`ai/ids_live.py` addition)

Three new methods on `LiveIDS`:
- `record_alert_latency(start: float, detected: float)` — appends
  `(detected - start) * 1000` ms to an internal list (capped at 100).
  Called by `app.py`'s `_on_threat_alert` when a button-click timestamp
  was stored by `on_demo_mitm` / `on_demo_replay`.
- `get_latency_stats()` — returns `{count, mean_ms, median_ms, min_ms,
  max_ms, measurements_ms}`.  Used by `/api/metrics_data`.
- The list survives `reset()` so measurements accumulate across multiple
  demo attacks within one process lifetime.

### Metrics dashboard routes (`app.py`)

Two additive routes inside `create_app`:
- `GET /metrics` — renders `templates/metrics.html`.
- `GET /api/metrics_data` — reads `benchmarks/results/key_exchange.json`
  and `benchmarks/results/throughput.json` from disk (returns `null` if
  absent), queries `ids.get_latency_stats()`, and returns session stats
  (`sync_time_ms`, `sync_rounds`, `messages_encrypted`, `bytes_encrypted`).
  Refreshed by `metrics.js` every 5 s for the live sections.

### Dashboard UI (`templates/metrics.html`, `static/js/metrics.js`)

`metrics.html` is a standalone page (separate from `chat.html`) with a
"← back to chat" link and four sections rendered by Chart.js:

| Section | Chart type | Data source |
|---|---|---|
| §1 Key-Exchange Setup Time | Horizontal bar | `key_exchange.json` |
| §2 AES-GCM Throughput | Line, log x-axis | `throughput.json` |
| §3 IDS Detection Latency | Histogram (bar) | Live — `/api/metrics_data` |
| §4 System Info & Session Stats | DL lists | Mix of disk + live |

All charts use the existing teal/amber/rose palette on a `bg-slate-900`
background.  No build step — Chart.js loaded via CDN alongside Tailwind.

`chat.html` header carries a small `metrics` link that opens `/metrics`.
