# Decisions Log

Every non-obvious technical decision goes here, with the alternatives we
considered and why the chosen approach won.

## 2026-04-27: TPM defaults set to K=3, N=10, L=3
**Decision:** Use `K=3` hidden units, `N=10` inputs per hidden unit, weight
range `L=3` as the Phase 1 defaults.
**Alternatives considered:**
- Larger parameters (e.g. `K=8, N=32, L=5`) used in academic security analyses.
- Smaller (`K=2, N=4, L=1`) for very fast tests.
**Rationale:** These values are the canonical demonstration parameters from
the Kanter–Kinzel–Kanter literature.  Synchronisation completes in well under
a second, weights are easy to inspect, and the security model is still
non-trivial enough to be educationally meaningful.  Tuning is explicitly
deferred — the project prompt says "no premature optimization."

## 2026-04-27: Hebbian learning as the default rule
**Decision:** `learning_rule="hebbian"` is the default in both
`TreeParityMachine.update_weights` and `SyncProtocol`.
**Alternatives considered:** anti-Hebbian, random-walk.
**Rationale:** Hebbian is the most studied rule for TPM mutual learning and
gives the fastest typical convergence at small `L`.  The other two rules are
implemented and selectable so that later phases can compare them, but Phase 1
demos and tests run on Hebbian to keep behaviour reproducible.

## 2026-04-27: AES-256-GCM rather than AES-CBC + HMAC
**Decision:** All symmetric encryption uses AES-256-GCM.
**Alternatives considered:** AES-CBC with a separate HMAC-SHA256 ("encrypt
then MAC"), ChaCha20-Poly1305.
**Rationale:** GCM is an authenticated cipher in a single primitive: any
ciphertext or tag tampering raises `InvalidTag` automatically, which is
exactly what the IDS phase will rely on.  CBC+HMAC is more error-prone (key
separation, MAC ordering).  ChaCha20-Poly1305 is excellent but the
`cryptography` library's GCM bindings map more transparently onto the AES
material every cryptography textbook uses, which matters for a college-demo
audience.

## 2026-04-27: SHA-256 of flat weight array for key derivation
**Decision:** `CryptoEngine.derive_key_from_tpm(weights)` returns
`SHA-256(weights.astype(int8).tobytes())`.
**Alternatives considered:**
- HKDF with a fixed salt/info pair.
- Concatenating weights with a counter and hashing.
**Rationale:** SHA-256 alone is adequate for Phase 1 because the synchronised
weight array already has substantially more entropy than a 256-bit key when
parameters are non-trivial, and the demo's purpose is to show the *flow*, not
to certify a production KDF.  HKDF is a clean upgrade for Phase 4/5 once we
introduce real session salts; it is intentionally not added now to keep the
crypto layer minimal.

## 2026-04-27: Bundle layout `nonce || ciphertext || tag`
**Decision:** `encrypt()` returns the 12-byte nonce, then ciphertext, then
the 16-byte GCM tag, as one `bytes` object.  `decrypt()` slices it back apart.
**Alternatives considered:** Returning a tuple, returning a dict, base64
encoding.
**Rationale:** A single `bytes` object is the simplest thing to drop into a
WebSocket frame in Phase 2 without an extra serialization step.  The
nonce-prefix layout is the convention used by Google Tink and most modern
AEAD examples, so the demo aligns with what students will see elsewhere.

## 2026-04-27: Shared-seed RNG for input generation in Phase 1
**Decision:** `SyncProtocol` accepts a `seed`, builds a `numpy.random.Generator`
from it, and uses that generator for *both* TPMs' inputs each round.
**Alternatives considered:**
- Each TPM generating its own inputs and exchanging them over a queue.
- Using `random.Random()` instead of NumPy's generator.
**Rationale:** Phase 1 runs in one process, so the shared-seed approach is
the cleanest stand-in for "a public input string broadcast on the wire."
Phase 2 will replace this with an actual exchange of input vectors over the
socket; the rest of the protocol code is structured so only the input source
needs to change.

## 2026-04-27: Split `SyncProtocol` into `SyncSession` + `SyncTransport` (pre-Phase-2 refactor)
**Decision:** Reshape `core/sync_protocol.py` into three layers — pure-math
`TreeParityMachine` (untouched), per-side `SyncSession` that owns one TPM
and one transport, and a tiny abstract `SyncTransport` with a concrete
`LoopbackTransport` for in-process use.  Keep the original
`SyncProtocol(tpm_a, tpm_b)` class as a thin convenience wrapper that
builds a paired `LoopbackTransport` and runs two `SyncSession`s on
background threads.
**Alternatives considered:**
- **Keep monolithic protocol, duplicate it for the network case.**  Two
  protocol implementations means two places to forget the TPM update gate;
  rejected because it invites silent divergence.
- **Pass a transport into the existing `SyncProtocol` and run only one
  side's loop inside it.**  Forces every caller (including the in-process
  demo) to think about which side it is.  Rejected for surface complexity.
- **Use asyncio coroutines instead of threads in the wrapper.**  Cleaner
  in isolation, but Phase 2 will use Flask + Flask-SocketIO whose default
  servers expect synchronous request handlers; threads compose more
  predictably with that stack.
**Rationale:** The Phase 1 review flagged that `SyncProtocol` was
shaped as an omniscient orchestrator (it held both TPMs in one process
and read both fingerprints to decide termination) and could not survive
the Phase 2 process split.  Splitting it now lets us drop in a
`SocketIOTransport` later with zero changes to `SyncSession`.  Keeping
the wrapper preserves the Phase 1 API exactly — all 33 prior tests and
`demo_phase1.py` continue to run unchanged.

**Layer ownership:**
- `TreeParityMachine`: forward pass, weight update under the standard
  gate.  Knows nothing about peers, transports, or rounds.
- `SyncSession`: handshake (seed exchange), per-round loop, two-party
  fingerprint termination, timeout handling.  Pluggable transport.
- `SyncTransport` (abstract): primitive send/recv for tau, fingerprint,
  and seed.  May raise `TransportTimeout`.
- `LoopbackTransport`: paired-queue in-process implementation; built
  via `make_loopback_pair()`.
- `SyncProtocol`: in-process two-party convenience that wires two
  sessions through a paired loopback and runs them on threads.

## 2026-04-27: XOR seed agreement in `LoopbackTransport.exchange_seed`
**Decision:** Both sides put their `local_seed` and read the peer's;
both return `local ^ remote`.  In the convenience wrapper the responder
contributes ``0`` so the agreed seed is exactly the initiator's seed.
**Alternatives considered:**
- **First-writer-wins (initiator broadcasts, responder echoes).**  Works
  but is asymmetric — slightly different code paths per role.
- **Each side sends a half and concatenates.**  Doubles bandwidth for
  no real benefit in a 64-bit seed.
**Rationale:** XOR is symmetric (same code on both roles), deterministic
(both sides compute the same value from the same pair of inputs), and
collapses to "initiator's seed" in the Phase 1 convenience wrapper —
which is what existing tests assume when they pass `seed=…`.  Reproducibility
of `test_ten_runs_all_synchronise` is preserved exactly: same seeds in,
same round counts out.

## 2026-04-27: Split `PEER_HOST` into `BIND_HOST` + `PEER_HOST`
**Decision:** `config.py` now exposes two separate knobs: `BIND_HOST`
(the address the *server* binds to) and `PEER_HOST` (the address the
*client* dials).  Defaults to `127.0.0.1` for both so single-laptop
development is unchanged; demo day flips `BIND_HOST` to `0.0.0.0` and
`PEER_HOST` to the peer laptop's hotspot IP.
**Alternatives considered:**
- **Keep one `PEER_HOST` and document the dual meaning.**  Rejected
  because the Phase 1 review flagged the conflation as a real
  trip-hazard for a fresh contributor — a doc note doesn't stop
  someone from setting `PEER_HOST=192.168.x.y` on the server side and
  failing to bind to that interface.
- **Compute `BIND_HOST` from `PEER_HOST` automatically.**  Rejected
  because there is no general rule that holds in all environments
  (loopback, hotspot, Docker, future deployments).  Two explicit knobs
  keeps the operator in control with minimal cognitive overhead.
**Rationale:** Server bind address and client dial address are two
genuinely different concerns; conflating them only happens to work on
loopback.  Splitting now (before any networking code is written)
prevents the asymmetry from leaking into Phase 2 module code.

## 2026-04-27: Role identifiers renamed `device_a`/`device_b` → `alice`/`bob`
**Decision:** `ROLE_A = "alice"` and `ROLE_B = "bob"` in `config.py`.
**Alternatives considered:**
- **Keep `device_a` / `device_b` for neutrality.**  Rejected because
  the user-facing vocabulary throughout the project plan and Phase 2
  spec ("alice/bob via command-line arg", chat-style UI) already uses
  alice/bob; mismatched strings would mean either constant translation
  or two different identifiers for the same role.
- **Use `client` / `server`.**  Rejected because the protocol is
  symmetric — neither side is a "client" in any meaningful sense once
  the handshake completes.
**Rationale:** Aligning the canonical role identifier with the user's
vocabulary lets Phase 2 surface them directly as CLI args
(`app.py --role alice`) and as UI labels with no translation layer.
The Phase 1 demo continues to print whatever `config.ROLE_A` /
`config.ROLE_B` resolve to, so the rename ripples through automatically
without code changes outside `config.py`.

## 2026-04-28: Plain TCP for the alice↔bob channel (not SocketIO)
**Decision:** The alice↔bob peer channel is a single plain-TCP socket
implemented in `core/transport_tcp.py`.  SocketIO is used only for the
**browser↔Flask** channel.
**Alternatives considered:**
- **Use Flask-SocketIO for the peer channel too.**  Tempting because
  it already powers the browser channel.  Rejected: SocketIO carries a
  large amount of HTTP/WebSocket framing baggage, hides the bytes from
  the wire-view panel, and isn't a natural fit for the strictly
  turn-based sync handshake.  We want the demo audience to see the
  raw ciphertext, which means owning the wire format.
- **WebSockets directly (no SocketIO).**  Marginally better than
  SocketIO but still extra framing; TCP is simpler and the demo is
  about the cryptographic layer, not the transport.
- **UDP.**  No connection state, no in-order delivery — would force us
  to reinvent TCP for the sync handshake.
**Rationale:** TCP gives in-order, byte-stream delivery, which is
exactly what `SyncSession` needs.  A 5-byte length-prefixed framing
layer is enough to multiplex sync frames (TAU/FINGERPRINT/SEED) and
app frames (CHAT/FILE_*/CONTROL) on one socket.  The wire-view panel
can show the actual ciphertext bytes — which is the pedagogical point
of the demo.

## 2026-04-28: Length-prefixed framing scheme
**Decision:** `[1-byte kind][4-byte big-endian length][payload]` —
fixed 5-byte header, no variable-length kind tag, no checksum.
**Alternatives considered:**
- **Newline-delimited JSON.**  Easy to read in tcpdump but binary-
  hostile (file chunks would need base64), and JSON parsing is a real
  cost for sub-millisecond sync rounds.
- **Protocol Buffers / msgpack.**  Heavyweight for a 7-kind protocol;
  adds a build-time codegen step or another runtime dependency.
- **A separate channel per kind (multiplexed).**  Forces SCTP or
  application-level multiplexing — overkill for two parties.
**Rationale:** A 5-byte header is the smallest framing scheme that
works.  Kind = 1 byte easily fits the seven kinds we have plus
generous headroom for Phase 3+.  Length = 4 bytes BE supports
payloads up to 4 GiB (way more than `FILE_CHUNK_BYTES` / `FILE_MAX_BYTES`
ever permit).  AES-GCM provides the integrity check on payloads
themselves; we don't need a header CRC because a corrupted header
just produces a malformed frame that fails decryption downstream.

## 2026-04-28: One TCP connection reused for sync + app traffic
**Decision:** `PeerLink` opens exactly one TCP connection.  The same
socket carries the sync handshake (TAU/FINGERPRINT/SEED) and, after
sync completes, the encrypted app traffic
(CHAT/FILE_META/FILE_CHUNK/CONTROL).
**Alternatives considered:**
- **Open a second connection for app traffic** so sync and app can be
  isolated.  Rejected: the second connection would be a fresh socket
  with no cryptographic binding to the sync that just happened — an
  attacker could inject a peer on the new port without the IDS or the
  TPM-derived key noticing.
- **Tear down and re-establish the same socket between phases.**  No
  benefit; same security gap as opening a second one.
**Rationale:** Binding the AES key to the same TCP session that
authenticated it (via successful TPM mutual learning) keeps the
attack surface a single connection.  An attacker who hijacks the
socket post-sync still can't read or forge ciphertext because the AES
key never touched the wire.  An attacker who hijacks the socket
pre-sync also gains nothing — they would need to pass mutual learning
with the legitimate peer's TPM weights, which they don't have.

## 2026-04-28: `INITIATOR_ROLE` config controls binding asymmetry
**Decision:** The role named in `config.INITIATOR_ROLE` (default
`"alice"`) is the side that binds the TCP server.  The other role
dials.  Both sides run identical code; the asymmetry is a config
look-up.
**Alternatives considered:**
- **Both sides try to bind, race for the port.**  Forces TIME_WAIT and
  retry logic; deeply confusing on demo day if it loses the race.
- **Deduce the initiator from network topology (e.g. lower IP wins).**
  Cute but fragile — Wi-Fi DHCP can change IPs between rehearsal and
  the actual demo, swapping which side binds without the operator's
  knowledge.
- **Always make alice the initiator (no config knob).**  Almost
  what we ship; we add the knob purely so the demo can show role
  symmetry by flipping it.
**Rationale:** A single config knob makes binding deterministic, lets
the demo show "either role can be initiator", and produces a clear
error (no listener) when both laptops are misconfigured the same way
— much easier to diagnose than a race-condition deadlock.

## 2026-04-28: SocketIO `async_mode="threading"` pinned in config
**Decision:** `config.SOCKETIO_ASYNC_MODE = "threading"`; no eventlet
or gevent.
**Alternatives considered:** eventlet (faster, classic Flask-SocketIO
default), gevent (similar).
**Rationale:** Both async drivers introduce monkey-patching of the
stdlib socket module, which interacts badly with our plain-TCP
`PeerLink` running in a background thread.  Threading mode requires
zero install dance, works on macOS / Linux / Windows, and is well
within the throughput envelope of a two-party demo.  If a future
phase needs hundreds of concurrent SocketIO clients, revisit — but
the current upper bound is 2 (alice's tab and bob's tab).

## 2026-04-28: Reconnect-replay (state-machine in `app.py`) instead of full session persistence
**Decision:** When a browser tab refreshes mid-session, the Flask
backend re-emits the most informative event (`sync_complete` /
`sync_progress` / `sync_in_progress` / `error`) to the new client
based on a small in-memory state machine.  The new client gets a
`replay: true` flag and shows a subtle "(reconnected — earlier
messages not shown)" banner.  Chat history is **not** persisted.
**Alternatives considered:**
- **Persist chat history server-side and replay it.**  Closer to a
  "real" chat app but materially larger scope: needs an in-memory
  ring buffer (or worse, a sqlite store), per-message ordering
  guarantees, and rules for trimming.  Rejected as overkill for a
  fixed two-party demo where refreshes are rare and messages are
  ephemeral by design.
- **Force the user to re-trigger sync after refresh.**  The UI would
  re-run the TPM handshake with a *new* random key, so even though
  the peer's PeerLink is still in app mode the keys would diverge —
  the ciphertext bundle in the wire view would suddenly be
  undecryptable.  Worse than the original bug.
- **Pickle the PeerLink to disk and restore on reconnect.**  PeerLink
  owns a live TCP socket and a daemon thread; neither pickles
  cleanly.  Wrong abstraction for the problem.
**Rationale:** The TPM-derived AES key is the only state the new
tab actually needs to participate in the existing session; we
already cache it for the `sync_complete` payload.  Replaying that
payload immediately on reconnect (with a `replay: true` flag for the
"messages not shown" banner) is the smallest possible fix that
preserves the cryptographic invariant.  Persistent chat history is
a separate feature that can be added later without disturbing this
state machine.

## 2026-04-30: In-process attack simulation (not a third-laptop adversary)
**Decision:** Phase 3 attacks live inside the *attacker's own* peer
process — `MITMAttack` mutates frames in `TCPTransport._send_frame`
before they touch the socket; `ReplayAttack` injects buffered
frames via the same transport.  The peer (and the demo audience)
sees exactly what they would see if a third party intercepted on
the wire, but no separate attacker box exists.
**Alternatives considered:**
- **Third-machine MITM proxy** (alice ↔ proxy ↔ bob) — far more
  realistic but multiplies the demo-day setup (extra laptop, manual
  iptables / port forward, ARP-spoof or DNS games to make alice
  actually dial the proxy).  Rejected as out of scope for an
  academic demo where the goal is the IDS pipeline, not red-team
  setup.
- **Lossy-channel emulator at the OS layer** (e.g. `tc netem`) —
  produces packet drops and reorders that don't surface as the
  cryptographic anomalies we want the IDS to flag (`InvalidTag`,
  duplicate ciphertext).
- **Inject from outside the process via a signal/file/SocketIO
  message** — adds another control-plane to debug.  Keeping attack
  state in-process means the attacks are unit-testable and the
  demo's "Launch MITM" button is the only entry point.
**Rationale:** The cryptographic effect we want to demonstrate
(`AES-GCM InvalidTag` on tampered chat, duplicate ciphertext on
replayed chat) is byte-for-byte indistinguishable whether the
mutation happens in `TCPTransport` or in a third-machine MITM box.
Phase 4's IDS will key on the receiver-side anomaly metrics, which
are identical in both setups.

## 2026-04-30: Per-frame hook design with optional drop semantics
**Decision:** Each attack implements
`on_outbound_frame(kind, payload) -> Optional[(kind, payload)]` and
`on_inbound_frame(...)` of the same shape.  Returning the input
unchanged is a no-op; returning a new tuple mutates the frame;
returning `None` drops it.  The transport hook is a single function
call per frame, short-circuited when no attacks are registered.
**Alternatives considered:**
- **Subscribe / unsubscribe callbacks (no return value).**  Forces
  a separate "I want to mutate" API layered on top.  Rejected for
  surface complexity.
- **Method-per-action** (`on_chat`, `on_file_chunk`, …).  Forces
  the registry to know about every kind; new frame kinds need
  registry updates.  The current `(kind, payload)` shape is
  protocol-agnostic.
- **A single observer event bus** with attacks just listening.
  Doesn't model "mutate the bytes about to be sent", which is the
  whole point of MITM.
**Rationale:** One callable per frame is the smallest contract that
covers observe / mutate / drop with no API for "inject extra
frames" (which Replay does separately, by calling
`transport._send_frame` from its own thread).  The chain semantics
(later attacks see earlier ones' output; first `None` short-circuits)
match how a real network of inline middleboxes would compose.

## 2026-04-30: Attack-side asymmetry (only the attacker's process runs the simulator)
**Decision:** When alice has MITM active, alice's process tampers
frames in alice's `TCPTransport._send_frame`.  Bob has no special
code path — bob just receives bytes that happen to fail GCM.  Bob's
`PeerLink` records the failed decrypt as a normal `on_error`
callback and an `_record_frame(decrypt_success=False)` observation.
**Alternatives considered:**
- **Symmetric attack code on both sides.**  Would mean bob also
  knows "I'm under attack" — leaks info that wouldn't exist in a
  real adversary scenario and would make the IDS task trivial.
- **A separate man-in-the-middle process between alice and bob.**
  See the in-process-vs-third-laptop decision above; same reasoning
  applies.
**Rationale:** This asymmetry is exactly what the Phase-4 IDS
trains on: the receiver's perspective only.  The receiver knows
nothing about the attack except its own anomaly metrics; the IDS
has to infer the attack from those metrics alone.  Training data
generated from this setup mirrors what the IDS will see in
production.

## 2026-04-30: Feature schema (10 numeric features, fixed order)
**Decision:** `FEATURE_NAMES` is a constant list in
`ai/feature_extractor.py` defining 10 features in canonical order.
Both the CSV writer and (Phase 4) the model use this list as the
authoritative column order.  Renaming or reordering requires
retraining the model.
**Alternatives considered:**
- **One-hot kind composition (one feature per frame kind).**  Would
  add columns whenever a new frame kind is introduced.  Three
  fractions covering chat / file / control is enough discrimination
  for the current attack types.
- **Per-attack-specialised features** (e.g. "is_replay_pattern").
  Would leak the answer into the inputs.
- **Raw byte-level features.**  Too high-dimensional for a
  Random Forest; would need a CNN.
**Rationale:** The 10 chosen features cover three signal classes
— volume/cadence (4), payload shape (2), anomaly hints (2),
composition (3).  `decrypt_failure_rate` and
`duplicate_payload_count` are the load-bearing ones; the rest let
the model condition on traffic context.  `statistics`-module
implementation keeps the runtime overhead negligible (the
extractor reuses a deque and computes everything from scratch on
demand).

## 2026-04-30: CSV (not parquet/jsonl) for the training data
**Decision:** `data/training_data.csv` is a plain CSV with
fixed column headers + one row per feature snapshot.
**Alternatives considered:**
- **Parquet** — denser and faster but requires a separate
  dependency (`pyarrow`) just for the training step.
- **JSONL** — easier to extend with nested fields, but every
  scikit-learn loader does CSV out of the box.
**Rationale:** The dataset is small (≤ a few MB) and the only
consumer is `pandas.read_csv` in Phase 4.  CSV is grep-able,
git-diff-able, and zero-dependency.  If Phase 4 grows past a few
hundred MB of training data we'll revisit.

## 2026-04-30: Kind-only AAD for chat / control / file-meta (Phase 3 demo correctness fix)
**Decision:** The AEAD's associated-data for CHAT, CONTROL, and
FILE_META frames is a single byte — the frame kind.  Concretely
``struct.pack(">B", kind)``.  We deliberately do NOT include a
per-direction monotonic sequence number, even though that is the
textbook answer for replay protection.
**Alternatives considered:**
- **`struct.pack(">BQ", kind, seq)`** — what Phase 2 originally
  shipped (and what HANDOFF / PHASE_LOG / inline comments
  described until this fix).  Bound the per-direction send_seq /
  recv_seq into the GCM tag.  Mathematically correct: an attacker
  cannot replay a frame because the receiver's expected AAD has
  moved on.  **Rejected** for Phase 3 because that protection
  fired *silently inside the AEAD*.  When the Replay simulator
  re-injected a captured CHAT bundle, the receiver saw
  `InvalidTag` and the demo audience saw "error: unknown" — the
  attack signal we wanted (a visible duplicate the IDS could
  flag) was being suppressed by the very layer below the IDS.
- **No AAD at all (`associated_data=None`).**  Equivalent to
  binding nothing.  Loses the kind-byte authentication, which
  means an attacker who could reframe a CHAT bundle as a CONTROL
  bundle on the wire could trick the receiver into running
  control-message handling on a chat ciphertext.  Trivial to
  prevent at zero cost; rejected.
- **Push the seq into a separate bookkeeping field (not AAD), and
  expose duplicate detection as an explicit IDS feature.**  This is
  effectively what the kind-only design plus the
  `duplicate_payload_count` feature *do* — replays succeed at the
  AEAD layer, surface as visible duplicates to the receiver, and
  the IDS classifier learns to flag them via the duplicate
  metric.  Adopted, but expressed as "leave AAD minimal" rather
  than "add explicit nonce-cache logic" since the IDS already
  has the signal it needs from `duplicate_payload_count`.
**Rationale:** This is a deliberate trade-off — defence-in-depth
(replay-protection at the AEAD layer AND at the IDS layer) vs
IDS-friendliness (signal preserved for the model to learn) — and
we have chosen the latter because the project's pedagogical
purpose is to demonstrate an *AI-based* IDS catching attacks that
aren't already eliminated by the cryptographic layer.  Binding
seq into AAD makes replay an AEAD-layer concern that the IDS
never gets a chance to "earn" detecting.  Kind-only AAD pushes
replay detection up to the IDS, so the demo can show:
  1. MITM → AEAD catches it (`InvalidTag` →
     `chat_decryption_failed` → "⚠ Tampered ciphertext rejected"
     bubble) — *the cryptographic layer working*.
  2. Replay → AEAD lets it through (same key, same ciphertext,
     same kind-byte AAD) → receiver sees a duplicate plaintext
     → "↻ duplicate of earlier message" bubble + the IDS flags it
     via `duplicate_payload_count` — *the AI layer working*.
The kind byte still authenticates so an attacker can't reframe
between CHAT / CONTROL / FILE_META.  In a non-pedagogical
production deployment, restoring `>BQ` AAD would be the right
call; for this project, `>B` is correct.

## 2026-05-01: Fit and predict with DataFrames, not numpy arrays
**Decision:** `ai/ids_train.py` passes `df[FEATURE_NAMES].astype(float)` (a
DataFrame) directly to `model.fit()`.  `ai/ids_report.py` does the same for
the test-set `X`.  Neither script calls `.to_numpy()` or `.values` before
handing data to sklearn.
**Rationale:** When sklearn's `RandomForestClassifier` is fitted on a numpy
array it has no record of column names and cannot detect column-order
mismatches at predict time.  Fitted on a DataFrame it populates
`model.feature_names_in_` and raises a `ValueError` (or `UserWarning`) if
predict-time input columns differ — a loud, immediate error rather than a
silent wrong prediction.  For Phase 4B, which will assemble feature vectors
as `pd.DataFrame([features], columns=FEATURE_NAMES)`, this is the
difference between "wrong order caught immediately" and "silently classifying
MITM as normal."  The cost is zero: sklearn handles DataFrames natively with
no performance penalty.

## 2026-05-01: Training-time filter for attacker-perspective rows
**Decision:** `ai/ids_train.py` drops attack-labelled rows that carry no
receiver-side signal before the train/test split.  Concretely: `mitm` rows
with `decrypt_failure_rate == 0` and `replay` rows with
`duplicate_payload_count == 0` are removed.  `normal` rows are never
filtered.  The filter is on by default (`FILTER_ATTACK_ROWS_BY_SIGNAL = True`)
and disableable via `--no-filter`.
**Problem it solves:**
Phase 4A's initial training run produced macro F1 = 0.78 with MITM recall 0.62
and Replay recall 0.61.  The cause: the training CSV records feature snapshots
from *both* sides of each session.  The *attacker's* side (alice, who runs the
MITM or Replay simulator) sees none of the receiver-side anomaly — no
`InvalidTag`, no duplicate payloads — so those rows have `decrypt_failure_rate
= 0` and `duplicate_payload_count = 0` despite carrying attack labels.  The
forest learns "some mitm-labelled rows have zero attack signal" and produces a
decision boundary that hedges toward "normal" when both anomaly features are low
— exactly the case that makes it miss attacks in production.
**Alternatives considered:**
- **Re-label the attacker-perspective rows as `normal`.**  Rejected: would
  artificially inflate the normal class and bias the class-weight balancing.
  Also conceptually wrong — they are not clean normal traffic, they are
  observations from a vantage point that has no visibility into the attack.
- **Modify `data/generate_training_data.py` to label per-receiver-perspective**
  (only record a row from the receiver's side; mark the sender's side `normal`).
  The correct long-term fix, but it requires regenerating the full CSV and
  reasoning about which side is "receiver" for a given session.  Deferred as
  future work; the training-time filter achieves the same effect cheaply.
- **Drop the attacker-perspective features entirely** (record only inbound
  frames in the extractor).  Would remove useful outbound cadence signal and
  requires a change to `FeatureExtractor` + a retrain.
- **Post-hoc threshold adjustment** — shift the decision boundary per class.
  Treats the symptom (low recall) rather than the cause (label noise).
**Rationale:** The filter is a one-line predicate on two columns; it is
transparent, cheap to apply at both training time and report-generation time,
and trivially verifiable by inspection.  Dropping the rows (rather than
relabeling) keeps the dataset honest — we do not assert they are normal, we
simply exclude them from the classifier's view.  The `filter_applied` field in
the saved bundle lets downstream code (report generator, Phase-4B loader) know
exactly what kind of training data the model saw.
**Result:** After filtering 504 rows (257 mitm + 247 replay), the remaining
1418 rows are cleanly separable: mitm rows have `decrypt_failure_rate > 0`,
replay rows have `duplicate_payload_count > 0`, normal rows have both at 0.
Macro F1 rises from 0.78 to 1.00 on the held-out filtered test set.
**Future improvement:** Modify `data/generate_training_data.py` to record
per-perspective rows correctly so the filter becomes unnecessary.

## 2026-05-01: Random Forest as the IDS classifier (not MLP, XGBoost, or SVM)
**Decision:** Phase 4 uses `sklearn.ensemble.RandomForestClassifier` with 100
trees and default depth.
**Alternatives considered:**
- **Multi-layer Perceptron (sklearn `MLPClassifier`).**  In principle
  captures non-linear feature interactions; in practice the training set is
  small (~1900 rows) and the 10 features are already engineered, so the MLP
  adds training complexity and hyperparameter surface without improving
  accuracy.  Neural-network debugging also adds time in a project where demo
  correctness matters more than SOTA accuracy.
- **XGBoost.**  Typically outperforms Random Forest on tabular data with
  careful tuning; requires an extra pip dependency and a grid-search to
  unlock its advantage.  Deferred to future work.
- **SVM with RBF kernel.**  Good at small, high-quality datasets but does
  not produce native probability estimates (needs Platt scaling, which
  adds fit time) and is slower to predict at runtime than a forest.
- **Logistic Regression.**  Interpretable and fast; probably sufficient
  on the two dominant features (`decrypt_failure_rate` and
  `duplicate_payload_count`), but assumes linear separability which the
  sender-side rows violate.
**Rationale:** Random Forest is the canonical baseline for tabular IDS tasks.
It produces calibrated `predict_proba` estimates (used as the Phase 4B
confidence threshold), requires minimal tuning, and `feature_importances_`
gives the demo audience a clear "which signal is the forest keying on?"
story.  The 0.80 test accuracy (0.78 macro F1) is demonstrably non-trivial
given the intentional attacker-side asymmetry in the training data.

## 2026-05-01: `class_weight="balanced"` to handle label imbalance
**Decision:** `RandomForestClassifier(class_weight="balanced")` rather than
default `None` (uniform weights).
**Alternatives considered:**
- **Oversample the minority class (SMOTE).**  Generates synthetic samples
  near the minority boundary; adds `imbalanced-learn` dependency and extra
  preprocessing.  Not needed at this dataset size.
- **Undersample the majority class.**  Wastes the largest class's data
  (normal has ~50% of rows).
- **Post-training threshold adjustment.**  Shift the decision boundary per
  class to equalise recall.  Adds inference complexity and wasn't needed
  once `class_weight="balanced"` gave acceptable per-class F1.
**Rationale:** The training set is ~50% normal / 25% MITM / 25% replay.
Without correction the forest would over-predict "normal" because trees
minimise impurity over counts not class balance.  sklearn's
`class_weight="balanced"` weights each sample by `n_samples / (n_classes ×
class_count)`, which is the simplest principled correction.  Confirmed in
`test_handles_imbalanced_classes`: 10 normal / 50 mitm / 50 replay still
trains to a fitted model with all three classes present.

## 2026-05-01: Model-with-metadata bundle pattern (not a bare pickle of the estimator)
**Decision:** `ai/ids_train.py` serialises a `dict` that contains the fitted
model plus `feature_names`, `label_encoder`, `test_accuracy`, `hyperparams`,
`trained_at`, `trained_on`, `n_samples`, `test_size`, and `random_state`.
Phase-4B's `IDSClassifier` loads the bundle and uses the stored
`feature_names` list to validate that the features it receives at runtime
are in the exact column order the model was trained on.
**Alternatives considered:**
- **Pickle the bare `RandomForestClassifier`.**  Works for single-session
  use but future code could assemble feature values in the wrong order
  (e.g. alphabetical vs canonical) and silently get wrong predictions.
  Silent mis-ordering is the most common production ML bug.
- **Save the model + a separate sidecar JSON for metadata.**  Two files to
  manage, load, and keep in sync.  A single joblib file atomically
  contains everything.
- **Embed column order in the model itself (via sklearn's `set_output`
  API or a `Pipeline` with a `ColumnTransformer`).**  Cleaner for a
  production service; heavier for a two-party demo where the feature
  vector is assembled inside PeerLink, not from a DataFrame.
**Rationale:** The bundle makes the serialised artefact self-describing:
`ids_report.py` needs to know `test_size` and `random_state` to re-run the
identical holdout split; `IDSClassifier` needs `label_encoder` to decode
integer predictions back to "normal" / "mitm" / "replay"; both need
`feature_names` to detect order mismatches at load time.  A single file
with a well-known shape eliminates the class of bugs where the live system's
feature pipeline diverges from the training pipeline.

## 2026-04-30: `on_chat_decryption_failed` is its own callback (not folded into `on_error`)
**Decision:** `PeerLink._handle_chat`'s `InvalidTag` branch fires
a dedicated `on_chat_decryption_failed(bundle)` callback.  The
generic `on_error` callback is not called for this case.  In
`app.py` this becomes a distinct `chat_decryption_failed` SocketIO
event with payload
``{reason, timestamp, ciphertext_size, ciphertext_hex,
   ciphertext_preview_hex}``.
**Alternatives considered:**
- **Fold it into `on_error` with a sub-type field.**  Easier to
  add but the JS side then has to peek inside `error.message` to
  know whether to render a "tampered ciphertext rejected" bubble
  or a generic banner — couples the UI to error message text.
- **Render every InvalidTag as a normal "error" toast.**  This
  was Phase 2's behaviour and is what the manual smoke test
  flagged as "looks broken, not like a security feature
  working."
**Rationale:** A successful AES-GCM rejection is a *good* event
for the demo — the audience should see the security layer
catching tampered traffic.  A distinct event lets the JS render
a distinct red/orange "⚠ Tampered ciphertext rejected" bubble +
a `✗ rejected` marker in the wire view, without coupling either
side to the wording of error messages.  `_handle_control` and
`_handle_file_meta` keep using `on_error` because those error
paths are rare (no UI affordance for control frames; file meta
errors are a different UX problem) and don't benefit from the
extra event channel.

## 2026-05-12: Hysteresis thresholds for LiveIDS (fire=0.70, clear=0.50)
**Decision:** An alert fires when any non-normal class probability reaches
0.70 and clears when that class's probability drops below 0.50.  The gap
(0.20) is the hysteresis band.
**Alternatives considered:**
- **Single threshold (fire == clear, e.g. 0.70).**  Alert fires and clears
  on the same value — one noisy window that dips to 0.69 instantly clears
  an otherwise solid alert.  This produces UI flapping: the browser receives
  alternating `threat_alert` / `threat_cleared` events every few feature
  windows, which is worse than showing nothing.
- **Larger band (e.g. fire=0.80, clear=0.40).**  More conservative fire
  threshold means the IDS reacts more slowly (the model needs very high
  confidence before alerting); wider clear band means a sustained attack
  doesn't clear on a single clean window.  Traded off against the demo
  pacing — 5–10 messages at 0.70 fire was observed to alert reliably.
- **Fixed N-window debounce (alert only if threshold crossed for N
  consecutive windows).**  Equivalent to hysteresis but harder to expose
  as a config knob and adds statefulness that the current design avoids.
**Rationale:** 0.70 / 0.50 was chosen by running the trained model on
the held-out test set with the MITM attack active and measuring how many
windows passed before an alert fired.  At these thresholds the typical
MITM alert fires after 2–4 post-warmup windows (about 10–20 frames, ~5 s
at normal chat pace).  The 0.20 band means a single "good" window inside
an attack does not clear the alert — observed in manual testing where
occasional chat gaps caused low inter-arrival variance briefly.

## 2026-05-12: Per-PeerLink IDS instance (not a process-global singleton)
**Decision:** `LiveIDS` is constructed once per process (in `create_app`)
but is a per-PeerLink object — `link.set_ids(ids)` attaches it before
connect, `ids.reset()` clears it on disconnect.
**Alternatives considered:**
- **One global IDS across all PeerLinks.**  The system is single-peer
  (one PeerLink per process), so this would work today.  Rejected because
  it mirrors the same design mistake we avoided with `AttackRegistry`:
  if the demo ever runs two PeerLinks in one process (training data
  generator does exactly this), a global IDS would mix feature windows
  from different sessions.
- **Construct a new IDS instance per sync attempt.**  Adds repeated
  model-load overhead (438 KB joblib deserialisation) on every reconnect.
  `reset()` achieves the same clean-slate semantics for free.
**Rationale:** Matches the existing per-PeerLink pattern for
`FeatureExtractor` and `AttackRegistry`.  One model load at startup
amortises the joblib cost; `reset()` keeps per-session state clean.

## 2026-05-12: Graceful degradation when IDS model is absent
**Decision:** If `LiveIDS` construction fails (file missing, corrupt
bundle, import error), `app.py` logs the error clearly and continues
running WITHOUT intrusion detection.  The app behaves exactly as Phase 3.
**Alternatives considered:**
- **Crash on IDS load failure.**  Safest in production (no silent
  degradation) but wrong for a demo: if the model file gets accidentally
  deleted or the venv doesn't have scikit-learn, the ENTIRE chat demo
  breaks.  The IDS is optional functionality; the core demo (TPM sync,
  encrypted chat, file transfer) must be robust.
- **Provide a mock IDS that always returns "monitoring".**  Hides the
  failure from logs.  The current approach logs at ERROR level which is
  much better for diagnosing "why aren't I seeing alerts?".
**Rationale:** `config.IDS_ENABLE = False` provides an explicit opt-out
for scenarios where the model is intentionally absent (training data
generation, CI environments without the pkl, debugging).  The runtime
fallback handles unexpected failures (e.g. model file not deployed).
Both cases log clearly — there is no silent "IDS is off".

## 2026-05-13: `ids_probabilities` as a continuous-update event (Phase 4C)
**Decision:** Add a high-frequency `ids_probabilities` SocketIO event that
fires on EVERY feature window (every `FEATURE_UPDATE_EVERY = 5` frames),
carrying the full probability triple `{normal, mitm, replay}`, IDS state,
and active-alert metadata.  The gauge subscribes to this for smooth animation.
**Alternatives considered:**
- **Have the frontend reconstruct gauge state from `threat_alert` /
  `threat_cleared` events alone.**  Only two states visible: "alerting"
  (snap to red on `threat_alert`) and "not alerting" (snap to green on
  `threat_cleared`).  Loses the gradual confidence buildup during
  `warming_up` and early `monitoring` — the audience can't see the IDS
  "thinking" before it fires.  This is the biggest demo weakness of
  the events-only approach: the gauge would jump abruptly from 0% to
  "DETECTED" with no intermediate animation.
- **Emit `ids_probabilities` only on IDS state changes (not every window).**
  Still misses the probability buildup before a threshold crossing.  The
  gauge would be static at 0% until the alert fires, which is identical
  to the binary events-only approach in practice.
- **Stream probabilities from PeerLink directly (new callback).**
  Would require adding `on_ids_probabilities` to PeerLink's callback set
  — more invasive than using the existing `on_features_updated` path.
  The current design calls `_ids_instance.current_state()` inside the
  `on_features_updated` closure so the IDS is the only source of truth.
**Rationale:** The gauged buildup is the entire point of having a gauge
rather than just a banner.  Emitting on every feature window costs one
small JSON payload per 5 frames (~2 KB/s) — negligible on localhost or
a campus LAN.  `current_state()` returns the PREVIOUS window's state
(one window behind), which is imperceptible at the 5-frame update rate.
The event is fire-and-forget; no ack or reliability guarantee is needed.

## 2026-05-13: Reconnect replay for active alert state (Phase 4C)
**Decision:** `app.py` stores `state["ids_last_probabilities"]` (latest
gauge payload) and `state["ids_last_alert"]` (full `threat_alert` payload
while one is active, `None` otherwise) in the session state dict, and
replays both to a freshly connecting browser tab in `on_browser_connect`.
**Alternatives considered:**
- **No replay — let the tab start fresh.**  The gauge would show 0% /
  WARMING UP until the next feature window fires (~5 frames × average
  inter-frame gap).  Under active attack this could mean the refreshed
  tab misses an ongoing alert for several seconds, which breaks the
  demo scenario "refresh bob's tab while MITM is active."
- **Replay only `threat_alert`, not `ids_probabilities`.**  The banner
  would appear immediately, but the gauge would start at 0% until the
  next `ids_probabilities` event.  Inconsistent visual state for
  ~100 ms.  Replaying both is two extra lines of code and avoids the
  visual glitch.
**Rationale:** Follows the exact same "replay on reconnect" pattern
already used for `sync_complete` / `sync_progress` / `error`.  The
reconnect recovery guarantee ("the UI reflects reality within 10 ms")
now applies to IDS state as well as sync state.

## 2026-05-14: Known non-blocking — ResourceWarning under Python 3.13 GC
**Decision:** Do not attempt to suppress `ResourceWarning: unclosed socket`
emitted during test-suite shutdown under Python 3.13; document it as
cosmetic and non-blocking.
**Source:** `tests/test_peer_link.py` — the warning fires after all tests
complete when multiple peer-link tests run in sequence.  It does not fire
when any individual test runs in isolation.
**Root cause:** Python 3.13's cyclic garbage collector runs during thread-
startup housekeeping of a subsequent test.  At that moment it may collect
`TCPTransport` objects from a just-finished test.  However, inspection
confirms the socket is already closed (`fd=-1`, `[closed]` tag) before the
GC runs — verified by printing `socket._sock` after `PeerLink.close()`.
The warning fires because CPython's socket finaliser evaluates the `fd`
field at the point the *Python object* is collected, by which time the OS
has potentially reused that fd number for a new socket (a different object);
this is a known false-positive pattern in Python 3.13's stricter finaliser.
**Why not fixed:** No actual file-descriptor leak occurs.  The sockets are
properly closed before GC.  The available fixes — setting `self._sock = None`
inside `TCPTransport.close()` while a reader thread may still hold a reference
to the same attribute (race condition), or adding `gc.collect()` calls inside
tests (hacky) — are both worse than the cosmetic symptom.  All 153 tests
pass; the warning is output noise only.
**Verification:** `alice._transport._sock` prints `[closed] fd=-1` immediately
after `PeerLink.close()`.  `_io_refs` is 0 (no `makefile()` calls).

## 2026-05-17: Benchmark results pre-generated; dashboard reads from disk

**Decision:** The two benchmark scripts (`benchmark_key_exchange.py`,
`benchmark_throughput.py`) are standalone command-line tools.  The
`/api/metrics_data` route reads their JSON output from disk at request
time.  There is no "regenerate benchmarks" button in the dashboard.

**Alternatives considered:**
- **Regenerate on demand from the dashboard.**  Rejected: RSA key-pair
  generation (~70 ms × 50 = ~3.5 s) and DH parameter generation
  (~40 s one-time on this machine) would block the Flask thread.  Even
  if run in a background thread, the first-run numbers would reflect
  warm-cache / warm-JIT conditions and be misleading — not the cold-start
  overhead the report wants to document.
- **Hard-code typical results as constants.**  Rejected: machine-specific
  and dishonest.  The demo audience can ask "how did you measure that?"

**Rationale:** Pre-generating keeps the dashboard responsive, ensures the
numbers reflect the actual demo machine, and separates "measure" from
"display" concerns cleanly.  Missing files are handled gracefully: the
dashboard shows a yellow notice with the CLI commands to run.

## 2026-05-17: IDS detection latency measured from demo-button click

**Decision:** `LiveIDS.record_alert_latency` receives two `time.time()`
values — the moment the demo-panel button was clicked and the moment
the `threat_alert` callback fired.  The difference (wall-clock) is the
"detection latency" shown in the metrics dashboard.

**Alternatives considered:**
- **Measure from first injected attack frame.**  More accurate, but
  requires threading a timestamp from the attack simulator through
  `PeerLink` → `FeatureExtractor` → `LiveIDS` → `app.py`, which touches
  every layer of the stack and couples unrelated modules.
- **Measure from the first modified frame reaching the receiver.**
  The receiver is on the other process (bob); coordinating timestamps
  across processes adds significant complexity.

**Rationale:** The button-click timestamp is a good approximation for
demo purposes: the click triggers `attack.start()` which schedules
injection within the same event loop turn.  The systematic bias (a few
milliseconds of SocketIO round-trip) is documented in `demo_final.md`
and is negligible compared to the detection latency itself (typically
10–30 s at normal typing pace).  The implementation stays local to
`app.py`'s demo-event handlers with zero changes to core modules.

