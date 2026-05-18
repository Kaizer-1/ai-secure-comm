"""Centralised configuration for the AI-Enhanced Secure Communication System.

Every tunable value lives here.  No other module in the codebase is allowed
to hard-code an IP address, port, TPM dimension, or AES parameter — they
must import from this file.

When the demo is moved from a single laptop (localhost simulation) to two
real laptops on a mobile hotspot, **only this file should change**.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Tree Parity Machine (neural cryptography) parameters
# ---------------------------------------------------------------------------
# K = number of hidden perceptrons.  Each one sees its own slice of inputs.
# N = number of inputs feeding each hidden perceptron.
# L = weights are integers in the closed interval [-L, L].
#
# The defaults below (K=3, N=10, L=3) are the canonical demonstration
# parameters from the Kanter–Kinzel–Kanter neural-cryptography papers.
# They are deliberately small: synchronisation finishes in well under a
# second on a laptop, weights are easy to inspect for teaching, and the
# protocol is still non-trivial.  Do *not* "tune" these in Phase 1.
TPM_K: int = 3
TPM_N: int = 10
TPM_L: int = 3

# Default learning rule used by `SyncProtocol` and any consumer that does
# not override it.  Supported values: "hebbian", "anti_hebbian", "random_walk".
TPM_DEFAULT_LEARNING_RULE: str = "hebbian"

# Hard upper bound on the number of mutual-learning rounds we will attempt
# before declaring synchronisation a failure.  Real Hebbian sync at the
# default parameters typically needs ~100–500 rounds, so 10 000 leaves a
# very generous safety margin.
TPM_SYNC_MAX_ROUNDS: int = 10_000

# Print a progress line every N rounds during synchronisation.  Set to a
# large number (or None) to silence routine progress logging.
TPM_SYNC_LOG_EVERY: int = 500

# ---------------------------------------------------------------------------
# AES-256-GCM parameters
# ---------------------------------------------------------------------------
# Key length in bytes.  GCM is defined for 128/192/256-bit keys; we always
# use 256 because the SHA-256 of the TPM weights is a natural 32-byte value.
AES_KEY_BYTES: int = 32

# GCM nonce length in bytes.  12 is the NIST-recommended size — any other
# value forces an internal GHASH derivation and reduces interoperability.
AES_NONCE_BYTES: int = 12

# GCM authentication tag length in bytes.  16 is the maximum and the
# default for the `cryptography` library; do not shorten it for a demo.
AES_TAG_BYTES: int = 16

# ---------------------------------------------------------------------------
# Peer / role identifiers (Phase 1 placeholders)
# ---------------------------------------------------------------------------
# Phase 1 runs entirely in one Python process, so these values are not yet
# used to open any sockets.  They are here so that Phase 2 can switch from
# in-process simulation to real networking by editing this file only.
#
# Canonical role identifiers used for CLI args (`--role alice`) and UI
# display in Phase 2.  The "alice / bob" vocabulary aligns with the
# project's chat-style demo; do not localise these strings.
ROLE_A: str = "alice"
ROLE_B: str = "bob"

# ---------------------------------------------------------------------------
# Network endpoints (Phase 2 will start using these)
# ---------------------------------------------------------------------------
# `BIND_HOST` and `PEER_HOST` are intentionally *separate* knobs because
# the server's bind address and the client's dial address are two
# different things in any real two-laptop deployment:
#
#   Dev (single laptop, two processes):
#       BIND_HOST = "127.0.0.1"      # server binds to loopback only
#       PEER_HOST = "127.0.0.1"      # client dials loopback
#
#   Demo (two laptops on a mobile hotspot):
#       BIND_HOST = "0.0.0.0"        # server accepts on every interface
#       PEER_HOST = "192.168.x.y"    # client dials the peer laptop's IP
#
# `PEER_PORT` is the same on both sides (the server's listening port,
# which is also what the client connects to).

# Address the *server* binds to.  Use 0.0.0.0 on demo day so the server
# accepts connections from the peer laptop's hotspot IP, not just from
# loopback.  Defaults to loopback for safe single-laptop development.
BIND_HOST: str = "127.0.0.1"

# Address the *client* dials to reach its peer.  On a single laptop both
# processes use 127.0.0.1.  On demo day, set this to the peer laptop's
# IP on the hotspot subnet (e.g. "192.168.43.10").
PEER_HOST: str = "127.0.0.1"

# How long (seconds) a client should wait for the server before giving up.
# Used by the network code in Phase 2.
PEER_CONNECT_TIMEOUT: float = 10.0

# Plain TCP port for the alice↔bob peer channel (TPM sync + encrypted
# chat + encrypted file chunks all share this socket).  The initiator
# binds to (BIND_HOST, PEER_TCP_PORT); the other side dials
# (PEER_HOST, PEER_TCP_PORT).  Distinct from the Flask web ports below.
PEER_TCP_PORT: int = 9001

# Which role binds the TCP server in any given run.  The other role
# dials.  Keep this consistent on both laptops (whichever one is
# "initiator" must run with the role named here).
INITIATOR_ROLE: str = "alice"

# How long (seconds) the SyncSession waits for a single peer message
# before raising `TransportTimeout`.  Generous because a slow Wi-Fi
# round-trip is normal; tightening this only helps if you actually
# want fast failures.
PEER_RECV_TIMEOUT: float = 30.0

# ---------------------------------------------------------------------------
# Flask web servers (one per role)
# ---------------------------------------------------------------------------
# In dev mode (single laptop), alice and bob run as two Python
# processes on the same machine, so each must use a distinct Flask
# port.  In demo mode (two laptops), each laptop runs only its own
# role, so they can both use 5001 — just be aware of the dev/demo
# split below.

# Flask binds here.  127.0.0.1 in dev; flip to 0.0.0.0 on demo day so
# the page is reachable from the peer laptop's browser if you ever
# want to view both UIs from one machine.  Note: this is independent
# of `BIND_HOST` (which controls the alice↔bob TCP channel).
FLASK_HOST: str = "127.0.0.1"

# Dev-mode ports (single laptop, two processes).  Both alice and bob
# load their own UI from these ports.  In demo mode each laptop runs
# only its own role and traditionally uses port 5001 — but reusing
# distinct ports here causes no harm if you keep them.
FLASK_PORT_ALICE: int = 5001
FLASK_PORT_BOB: int = 5002

# Acceptable for a local-network academic demo; **regenerate** for any
# real deployment.  Used by Flask sessions and Flask-SocketIO signing.
FLASK_SECRET_KEY: str = "dev-only-change-for-demo"

# ---------------------------------------------------------------------------
# Flask-SocketIO
# ---------------------------------------------------------------------------
# Pinned to "threading" deliberately: it avoids the eventlet/gevent
# install dance and works fine for two-tab dev and two-laptop demo.
# If you ever switch, install the chosen driver before changing this.
SOCKETIO_ASYNC_MODE: str = "threading"

# Friendlier defaults than SocketIO's stock 5-second values — a slow
# Wi-Fi packet drop should not be misinterpreted as a disconnect.
SOCKETIO_PING_INTERVAL: int = 25  # seconds
SOCKETIO_PING_TIMEOUT: int = 60   # seconds

# ---------------------------------------------------------------------------
# File transfer
# ---------------------------------------------------------------------------
# Each chunk is encrypted as its own AES-GCM bundle with a fresh
# random nonce; AAD binds (file_id, chunk_index, total_chunks) so the
# receiver detects drops, reorders, and replays before decrypting.
FILE_CHUNK_BYTES: int = 65_536          # 64 KiB
FILE_MAX_BYTES: int = 50 * 1024 * 1024  # 50 MiB safety cap

# ---------------------------------------------------------------------------
# Wire view (UI)
# ---------------------------------------------------------------------------
# Number of recent ciphertext bundles retained in the browser-side
# wire-view panel.  Older entries scroll off.
WIRE_VIEW_BUFFER: int = 50

# How often (in TPM sync rounds) to push a `sync_progress` event to
# the browser.  Smaller values give a smoother progress bar; larger
# values reduce SocketIO chatter.
SYNC_PROGRESS_EVERY: int = 10

# ---------------------------------------------------------------------------
# Phase 3 — Attack simulators + demo controls
# ---------------------------------------------------------------------------
# `DEMO_MODE` gates the attack-launch SocketIO events in `app.py` and
# the visibility of the hidden demo panel in `chat.js`.  In a non-demo
# deployment this would be `False`; for the project demo, leave it on.
DEMO_MODE: bool = True

# MITM simulator: probability with which an active MITM tampers any
# given outbound CHAT frame.  Sync-phase frames (TAU/FINGERPRINT/SEED)
# are NEVER tampered — the simulator models a post-handshake
# adversary, not someone capable of breaking neural-key agreement.
MITM_TAMPER_PROBABILITY: float = 0.30

# Replay simulator: how many recent CHAT frames to keep in the buffer
# for re-injection, and how often (seconds) to replay one of them on
# the wire.  Tuned so attack signal is detectable but not trivial.
REPLAY_BUFFER_SIZE: int = 5
REPLAY_INTERVAL_S: float = 3.0

# ---------------------------------------------------------------------------
# Phase 3 — Feature extraction (consumed by Phase 4 IDS)
# ---------------------------------------------------------------------------
# Sliding-window length over which `FeatureExtractor` computes
# numeric features.  Larger windows smooth the signal at the cost of
# slower reaction to changes.  20 frames matches the demo's chat
# pace (~5 s of chat at typing speed).
FEATURE_WINDOW_SIZE: int = 20

# Fire `on_features_updated(features_dict)` every N frames a PeerLink
# observes (sent + received).  The training-data generator samples
# these snapshots; Phase 4's live IDS will classify each snapshot.
FEATURE_UPDATE_EVERY: int = 5

# ---------------------------------------------------------------------------
# Phase 4B — Live IDS (intrusion detection)
# ---------------------------------------------------------------------------
# Path to the Random Forest bundle written by `ai/ids_train.py`.  Relative
# to the runtime root (the directory containing app.py).
IDS_MODEL_PATH: str = "ai/trained_model.pkl"

# Probability at or above which a non-normal class fires an alert.
# Must be strictly greater than IDS_ALERT_THRESHOLD_CLEAR.
IDS_ALERT_THRESHOLD_FIRE: float = 0.70

# Probability below which an active alert's class must fall before it clears.
# Lower than FIRE so a single noisy window doesn't immediately un-alert.
IDS_ALERT_THRESHOLD_CLEAR: float = 0.50

# Number of feature-update windows that must be observed before the IDS
# begins making alert decisions.  Prevents flaky alerts on the first few
# partially-filled sliding windows.
IDS_MIN_OBSERVATIONS: int = 3

# Master switch.  When False, app.py skips IDS construction entirely;
# no threat_alert events fire and the app behaves exactly as Phase 3.
# Useful for debugging and for running the training-data generator without
# IDS interference.
IDS_ENABLE: bool = True

# ---------------------------------------------------------------------------
# Reproducibility
# ---------------------------------------------------------------------------
# A seed used by tests and the Phase 1 demo when they want deterministic
# behaviour.  Production runs should always pass `seed=None` so a fresh
# OS-level entropy source is used.
DEMO_SEED: int = 20260427
