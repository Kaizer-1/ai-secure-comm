"""High-level peer link: TCP connection + TPM sync + encrypted app channel.

`PeerLink` owns one peer's view of a session for its full lifetime:

1. **Connect** — bind & accept (initiator) or dial (responder) a TCP
   connection to the other role.
2. **Sync** — run `SyncSession` over the TCP transport with a
   progress-reporting decorator so the UI can show a live counter.
3. **Derive key** — feed the synchronised TPM weights through
   `CryptoEngine.derive_key_from_tpm` to get a 256-bit AES key.
4. **App mode** — start a background reader thread that consumes
   `CHAT` / `FILE_META` / `FILE_CHUNK` / `CONTROL` frames, decrypts
   them, and dispatches to the callbacks the Flask layer installs.

The Flask layer (or any future CLI client) only sees this class; it
does not import `core.transport_tcp` or `core.sync_protocol` directly.

AAD discipline (Phase 3-onward — see `_AAD_FMT` and `docs/DECISIONS.md`):
- Chat / control / file-meta frames use a kind-only AAD
  (``struct.pack(">B", kind)``).  We deliberately do NOT bind a
  sequence number into the AAD, because that would silently turn
  every replay into an `InvalidTag` at the AEAD layer; Phase 3
  pushes replay-detection up to the IDS so replays surface as
  visible duplicates the IDS can flag.
- File chunks use ``aad_for_chunk(file_id, idx, total)`` — the
  scheme defined in `core.file_transfer`.  Chunk-position binding
  is what guarantees in-file integrity, independent of replay
  considerations.
"""

from __future__ import annotations

import json
import logging
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional

from cryptography.exceptions import InvalidTag

import config
from ai.feature_extractor import FeatureExtractor
from attacks.base import AttackRegistry

# LiveIDS is an optional dependency — PeerLink must work without the model
# file present (Phase 1–3 tests, training-data generator, etc.).
try:
    from ai.ids_live import LiveIDS as _LiveIDS
except Exception:  # noqa: BLE001
    _LiveIDS = None  # type: ignore[assignment,misc]
from .crypto_engine import CryptoEngine
from .file_transfer import (
    aad_for_chunk,
    assemble_chunks,
    iter_chunks,
    make_file_meta,
    verify_sha256,
)
from .sync_protocol import (
    INITIATOR,
    RESPONDER,
    SyncResult,
    SyncSession,
    SyncTransport,
    TransportTimeout,
)
from .tpm import TreeParityMachine
from .transport_tcp import (
    KIND_CHAT,
    KIND_CONTROL,
    KIND_FILE_CHUNK,
    KIND_FILE_META,
    PeerDisconnectedError,
    TCPListener,
    TCPTransport,
    connect as tcp_connect,
)


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Frame payload helpers
# ---------------------------------------------------------------------------

# Chat / file-meta / control AAD: 1-byte kind only.
#
# Why kind-only and NOT (kind, seq) like Phase 2 originally shipped:
# the seq in the AAD silently turned every replay into an `InvalidTag`
# at the AEAD layer.  Phase 3 wants replays to *succeed* and surface
# as visible duplicates so the IDS can flag them as duplicate-payload
# anomalies.  Removing seq from the AAD pushes replay defence up to
# the IDS layer (Phase 4); the AEAD continues to authenticate the
# kind byte, so an attacker still can't reframe a CHAT bundle as a
# CONTROL bundle.  See `docs/DECISIONS.md` for the full rationale.
_AAD_FMT = ">B"

# Chunk header that prefixes each FILE_CHUNK frame's payload (in plaintext on
# the wire — the secret is the chunk content, not its identity).
#   16 bytes  file_id (uuid4 hex, ASCII)
#   4 bytes   chunk_index (BE unsigned)
#   4 bytes   total_chunks (BE unsigned)
#   N bytes   AES-GCM bundle (nonce || ct || tag)
_CHUNK_HEADER_FMT = ">16sII"
_CHUNK_HEADER_LEN = struct.calcsize(_CHUNK_HEADER_FMT)


def _aad(kind: int) -> bytes:
    """AAD for chat / control / file-meta frames.  Kind-only — see the
    `_AAD_FMT` comment above for why we deliberately do NOT include a
    sequence number."""
    return struct.pack(_AAD_FMT, kind & 0xFF)


def _file_id_to_wire(file_id_hex: str) -> bytes:
    """Pack a 32-hex-char file_id into 16 bytes for the chunk header."""
    if len(file_id_hex) != 32:
        raise ValueError(f"file_id must be 32 hex chars; got len={len(file_id_hex)}")
    return bytes.fromhex(file_id_hex)


def _wire_to_file_id(raw: bytes) -> str:
    return raw.hex()


# ---------------------------------------------------------------------------
# Progress-reporting transport wrapper
# ---------------------------------------------------------------------------


class _ProgressTransport(SyncTransport):
    """Decorator that emits sync-progress callbacks every N rounds.

    Wraps an inner :class:`SyncTransport`.  Each ``recv_tau`` call ends
    one round; we use ``send_tau`` to remember our local tau so the
    wrapper can report whether the round's taus matched (handy for the
    UI's "matched / round" ratio).

    Pass the wrapped transport to `SyncSession`; the underlying
    `TCPTransport` is reused unchanged for app-phase traffic.
    """

    def __init__(
        self,
        inner: SyncTransport,
        on_progress: Optional[Callable[[int, int, int], None]] = None,
        progress_every: int = config.SYNC_PROGRESS_EVERY,
        max_rounds: int = config.TPM_SYNC_MAX_ROUNDS,
    ) -> None:
        self._inner = inner
        self._on_progress = on_progress
        self._progress_every = max(1, int(progress_every))
        self._max_rounds = int(max_rounds)
        self._round = 0
        self._matched = 0
        self._last_sent_tau: Optional[int] = None

    def send_tau(self, tau: int) -> None:
        self._last_sent_tau = int(tau)
        self._inner.send_tau(tau)

    def recv_tau(self) -> int:
        remote = self._inner.recv_tau()
        self._round += 1
        if self._last_sent_tau is not None and remote == self._last_sent_tau:
            self._matched += 1
        if self._on_progress is not None and (
            self._round == 1 or self._round % self._progress_every == 0
        ):
            try:
                self._on_progress(self._round, self._matched, self._max_rounds)
            except Exception:  # noqa: BLE001
                logger.exception("on_progress callback raised; continuing sync")
        return remote

    def send_fingerprint(self, fp: bytes) -> None:
        self._inner.send_fingerprint(fp)

    def recv_fingerprint(self) -> bytes:
        return self._inner.recv_fingerprint()

    def exchange_seed(self, local_seed: int) -> int:
        return self._inner.exchange_seed(local_seed)

    def close(self) -> None:
        self._inner.close()


# ---------------------------------------------------------------------------
# State + main class
# ---------------------------------------------------------------------------


@dataclass
class _IncomingFile:
    meta: dict
    chunks: Dict[int, bytes] = field(default_factory=dict)
    started_at: float = field(default_factory=time.time)


class PeerLink:
    """One side of the encrypted alice↔bob channel.

    Parameters
    ----------
    role:
        ``"alice"`` or ``"bob"``.  Decides handshake direction by
        comparing against ``initiator_role`` (default ``config.INITIATOR_ROLE``).
    bind_host, peer_host, peer_port, initiator_role:
        Test hooks; production code uses the config defaults.

    Callbacks (set as attributes after construction):
        on_sync_progress(round, matched, total)
        on_sync_complete(SyncResult, key_fingerprint_hex)
        on_chat_received(plaintext, ciphertext_bundle)
        on_chat_decryption_failed(ciphertext_bundle)  # Phase 3 — fires
                                            # when an inbound CHAT frame
                                            # fails AES-GCM (the MITM
                                            # signal); distinct from
                                            # `on_error`.
        on_file_meta_received(meta_dict)
        on_file_chunk_received(file_id, chunk_index, total_chunks)
        on_file_complete(meta_dict, sha_ok: bool, plaintext: bytes)
        on_peer_disconnected()
        on_error(exc)
        on_features_updated(features_dict)  # Phase 3 — fires every
                                            # config.FEATURE_UPDATE_EVERY
                                            # frames observed.
    """

    def __init__(
        self,
        role: str,
        *,
        bind_host: Optional[str] = None,
        peer_host: Optional[str] = None,
        peer_port: Optional[int] = None,
        initiator_role: Optional[str] = None,
        connect_timeout: Optional[float] = None,
        recv_timeout: Optional[float] = None,
        feature_window_size: Optional[int] = None,
        feature_update_every: Optional[int] = None,
    ) -> None:
        if role not in (config.ROLE_A, config.ROLE_B):
            raise ValueError(
                f"role must be {config.ROLE_A!r} or {config.ROLE_B!r}; got {role!r}"
            )

        self.role = role
        self.bind_host = bind_host or config.BIND_HOST
        self.peer_host = peer_host or config.PEER_HOST
        self.peer_port = peer_port if peer_port is not None else config.PEER_TCP_PORT
        self.initiator_role = initiator_role or config.INITIATOR_ROLE
        self.is_initiator = (self.role == self.initiator_role)
        self.connect_timeout = (
            connect_timeout if connect_timeout is not None
            else config.PEER_CONNECT_TIMEOUT
        )
        self.recv_timeout = (
            recv_timeout if recv_timeout is not None
            else config.PEER_RECV_TIMEOUT
        )
        self.peer_role = (
            config.ROLE_B if self.role == config.ROLE_A else config.ROLE_A
        )

        # Runtime state.
        self._transport: Optional[TCPTransport] = None
        self._tpm: Optional[TreeParityMachine] = None
        self._crypto: Optional[CryptoEngine] = None
        self._reader_thread: Optional[threading.Thread] = None
        self._closed = False
        self._sync_done = threading.Event()

        # AAD sequence counters (per direction; advance on chat / meta /
        # control sends and recvs; file chunks use their own AAD scheme).
        self._send_seq = 0
        self._recv_seq = 0

        # Pending incoming files keyed by file_id.
        self._incoming: Dict[str, _IncomingFile] = {}

        # Phase-3: per-PeerLink attack registry (the TCPTransport
        # consults this for every send/recv).  Built up-front so demo
        # code can register attacks before / during sync if desired,
        # though both bundled simulators only act post-sync.
        self.attack_registry = AttackRegistry()

        # Phase-3: per-PeerLink feature extractor for the IDS pipeline.
        self.feature_extractor = FeatureExtractor(
            window_size=(
                feature_window_size
                if feature_window_size is not None
                else config.FEATURE_WINDOW_SIZE
            ),
        )
        self._feature_update_every = int(
            feature_update_every
            if feature_update_every is not None
            else config.FEATURE_UPDATE_EVERY
        )

        # Phase 4B: optional live IDS instance + last-known IDS state for
        # transition detection.  Set via set_ids() after construction.
        self._ids: Optional[object] = None
        self._ids_last_state: Optional[dict] = None

        # Callbacks — assigned by the Flask app.  Default to no-op.
        self.on_sync_progress: Optional[Callable[[int, int, int], None]] = None
        self.on_sync_complete: Optional[Callable[[SyncResult, str], None]] = None
        self.on_chat_received: Optional[Callable[[str, bytes], None]] = None
        self.on_file_meta_received: Optional[Callable[[dict], None]] = None
        self.on_file_chunk_received: Optional[
            Callable[[str, int, int], None]
        ] = None
        self.on_file_complete: Optional[
            Callable[[dict, bool, bytes], None]
        ] = None
        self.on_peer_disconnected: Optional[Callable[[], None]] = None
        self.on_error: Optional[Callable[[BaseException], None]] = None
        # Phase 3 — fires every `feature_update_every` frames.
        self.on_features_updated: Optional[Callable[[dict], None]] = None
        # Phase 3 — fires when a CHAT frame fails AES-GCM
        # authentication (InvalidTag), most often because a MITM
        # attack tampered with the ciphertext on the wire.  Distinct
        # from `on_error` so the UI can render a meaningful
        # "tampered ciphertext rejected" bubble rather than a
        # generic error.  Receives the raw bundle that failed.
        self.on_chat_decryption_failed: Optional[Callable[[bytes], None]] = None
        # Phase 4B — IDS alert callbacks.
        # on_threat_alert(alert_event: dict) fires when:
        #   • monitoring → alerting (first alert), or
        #   • alerting → alerting with confidence delta ≥ 0.10.
        # on_threat_cleared(cleared_event: dict) fires when alerting → monitoring.
        self.on_threat_alert: Optional[Callable[[dict], None]] = None
        self.on_threat_cleared: Optional[Callable[[dict], None]] = None

    # ------------------------------------------------------------------
    # Phase 4B: IDS attachment
    # ------------------------------------------------------------------
    def set_ids(self, ids: object) -> None:
        """Attach a LiveIDS instance.  Call before connect() for best results.

        PeerLink functions normally (no alerts fire) when no IDS is attached,
        preserving Phase 1–3 behaviour for tests that don't need IDS.
        """
        self._ids = ids
        self._ids_last_state = None

    # ------------------------------------------------------------------
    # Connection + sync
    # ------------------------------------------------------------------
    def connect(self) -> SyncResult:
        """Establish the TCP link and run the TPM sync.

        Blocks the calling thread until sync finishes (or fails).  Use
        a background thread if you need this to be non-blocking — the
        Flask app does exactly that.
        """
        if self._transport is not None:
            raise RuntimeError("connect() already called")

        try:
            self._transport = self._establish_tcp()
            # Bind the per-PeerLink attack registry to the freshly
            # established transport.  No attacks are registered yet —
            # demo-mode SocketIO handlers attach them at runtime.
            self.attack_registry.attach_transport(self._transport)
            self._transport.attach_attack_registry(self.attack_registry)

            sync_role = INITIATOR if self.is_initiator else RESPONDER
            self._tpm = TreeParityMachine(
                config.TPM_K, config.TPM_N, config.TPM_L,
            )

            wrapped = _ProgressTransport(
                self._transport,
                on_progress=self.on_sync_progress,
                progress_every=config.SYNC_PROGRESS_EVERY,
                max_rounds=config.TPM_SYNC_MAX_ROUNDS,
            )
            session = SyncSession(
                tpm=self._tpm,
                transport=wrapped,
                role=sync_role,
                max_rounds=config.TPM_SYNC_MAX_ROUNDS,
                learning_rule=config.TPM_DEFAULT_LEARNING_RULE,
            )
            result = session.synchronize()

            if not result.success:
                self._fire(self.on_error,
                           RuntimeError(f"TPM sync failed: {result!r}"))
                self.close()
                return result

            # Derive the AES key from the synchronised weights.
            key = CryptoEngine.derive_key_from_tpm(self._tpm.export_weights())
            self._crypto = CryptoEngine(key)
            key_fp = key.hex()

            # Switch the underlying transport to blocking mode for the
            # app phase — chat/file traffic is bursty, no per-call timeout.
            self._transport.set_recv_timeout(None)

            # Start the reader thread that dispatches app frames.
            self._reader_thread = threading.Thread(
                target=self._reader_loop,
                name=f"peer-link-{self.role}-reader",
                daemon=True,
            )
            self._reader_thread.start()

            self._sync_done.set()
            self._fire(self.on_sync_complete, result, key_fp)
            return result

        except TransportTimeout as exc:
            self._fire(self.on_error, exc)
            self.close()
            raise
        except Exception as exc:  # noqa: BLE001
            self._fire(self.on_error, exc)
            self.close()
            raise

    def _establish_tcp(self) -> TCPTransport:
        if self.is_initiator:
            listener = TCPListener(self.bind_host, self.peer_port)
            try:
                return listener.accept(
                    timeout=self.connect_timeout,
                    recv_timeout=self.recv_timeout,
                )
            finally:
                listener.close()
        return tcp_connect(
            self.peer_host, self.peer_port,
            timeout=self.connect_timeout,
            recv_timeout=self.recv_timeout,
        )

    # ------------------------------------------------------------------
    # Outbound app-mode methods
    # ------------------------------------------------------------------
    def send_chat(self, plaintext: str) -> bytes:
        """Encrypt and send a chat message; return the bundle for wire-view."""
        self._require_app_mode()
        self._send_seq += 1  # kept as instrumentation; not in AAD
        bundle = self._crypto.encrypt(  # type: ignore[union-attr]
            plaintext.encode("utf-8"),
            associated_data=_aad(KIND_CHAT),
        )
        self._transport.send_chat(bundle)  # type: ignore[union-attr]
        self._record_frame(kind=KIND_CHAT, payload=bundle, direction="out")
        return bundle

    def send_control(self, payload: dict) -> bytes:
        """Encrypt and send a control message (JSON); return the bundle."""
        self._require_app_mode()
        self._send_seq += 1
        bundle = self._crypto.encrypt(  # type: ignore[union-attr]
            json.dumps(payload).encode("utf-8"),
            associated_data=_aad(KIND_CONTROL),
        )
        self._transport.send_control(bundle)  # type: ignore[union-attr]
        self._record_frame(kind=KIND_CONTROL, payload=bundle, direction="out")
        return bundle

    def send_file(self, path: str) -> dict:
        """Send a complete file: meta + every chunk.

        Blocks the caller until the last chunk is on the wire.  Returns
        the meta dict so the caller can record it (for UI display, etc).
        """
        self._require_app_mode()
        meta = make_file_meta(path)

        # 1. FILE_META frame: encrypted JSON with chat-style AAD.
        self._send_seq += 1
        meta_bundle = self._crypto.encrypt(  # type: ignore[union-attr]
            json.dumps(meta).encode("utf-8"),
            associated_data=_aad(KIND_FILE_META),
        )
        self._transport.send_file_meta(meta_bundle)  # type: ignore[union-attr]
        self._record_frame(kind=KIND_FILE_META, payload=meta_bundle,
                           direction="out")

        # 2. FILE_CHUNK frames: header (file_id|idx|total) + AES bundle.
        for idx, chunk in iter_chunks(path, chunk_bytes=meta["chunk_bytes"]):
            aad = aad_for_chunk(meta["file_id"], idx, meta["total_chunks"])
            chunk_bundle = self._crypto.encrypt(  # type: ignore[union-attr]
                chunk, associated_data=aad,
            )
            header = struct.pack(
                _CHUNK_HEADER_FMT,
                _file_id_to_wire(meta["file_id"]),
                idx,
                meta["total_chunks"],
            )
            wire_payload = header + chunk_bundle
            self._transport.send_file_chunk(wire_payload)  # type: ignore[union-attr]
            self._record_frame(kind=KIND_FILE_CHUNK, payload=wire_payload,
                               direction="out")
        return meta

    # ------------------------------------------------------------------
    # Reader thread (app phase)
    # ------------------------------------------------------------------
    def _reader_loop(self) -> None:
        try:
            while not self._closed:
                kind, payload = self._transport.recv_frame()  # type: ignore[union-attr]
                if kind == KIND_CHAT:
                    self._handle_chat(payload)
                elif kind == KIND_FILE_META:
                    self._handle_file_meta(payload)
                elif kind == KIND_FILE_CHUNK:
                    self._handle_file_chunk(payload)
                elif kind == KIND_CONTROL:
                    self._handle_control(payload)
                else:
                    logger.warning("ignoring unknown frame kind %#x", kind)
        except PeerDisconnectedError:
            if self._ids is not None:
                try:
                    self._ids.reset()
                except Exception:  # noqa: BLE001
                    logger.exception("IDS reset on disconnect raised; ignoring")
            self._fire(self.on_peer_disconnected)
        except Exception as exc:  # noqa: BLE001
            if not self._closed:
                self._fire(self.on_error, exc)

    def _handle_chat(self, bundle: bytes) -> None:
        self._recv_seq += 1  # kept as instrumentation; not in AAD
        try:
            plaintext_bytes = self._crypto.decrypt(  # type: ignore[union-attr]
                bundle, associated_data=_aad(KIND_CHAT),
            )
        except InvalidTag:
            # Record the failed decrypt — this is the signal MITM
            # attacks generate, and Phase 4's IDS keys on the
            # resulting decrypt_failure_rate.
            self._record_frame(kind=KIND_CHAT, payload=bundle,
                               direction="in", decrypt_success=False)
            # Distinct callback (not the generic on_error) so the UI
            # can render a "tampered ciphertext rejected" bubble
            # instead of an undifferentiated error.
            self._fire(self.on_chat_decryption_failed, bundle)
            return
        self._record_frame(kind=KIND_CHAT, payload=bundle,
                           direction="in", decrypt_success=True)
        plaintext = plaintext_bytes.decode("utf-8", errors="replace")
        self._fire(self.on_chat_received, plaintext, bundle)

    def _handle_control(self, bundle: bytes) -> None:
        self._recv_seq += 1
        try:
            self._crypto.decrypt(  # type: ignore[union-attr]
                bundle, associated_data=_aad(KIND_CONTROL),
            )
        except InvalidTag as exc:
            self._record_frame(kind=KIND_CONTROL, payload=bundle,
                               direction="in", decrypt_success=False)
            self._fire(self.on_error, exc)
            return
        self._record_frame(kind=KIND_CONTROL, payload=bundle,
                           direction="in", decrypt_success=True)
        # Phase 2 has no control-message consumers; reserved for future use.

    def _handle_file_meta(self, bundle: bytes) -> None:
        self._recv_seq += 1
        try:
            meta_bytes = self._crypto.decrypt(  # type: ignore[union-attr]
                bundle, associated_data=_aad(KIND_FILE_META),
            )
        except InvalidTag as exc:
            self._record_frame(kind=KIND_FILE_META, payload=bundle,
                               direction="in", decrypt_success=False)
            self._fire(self.on_error, exc)
            return
        self._record_frame(kind=KIND_FILE_META, payload=bundle,
                           direction="in", decrypt_success=True)
        try:
            meta = json.loads(meta_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._fire(self.on_error, exc)
            return
        self._incoming[meta["file_id"]] = _IncomingFile(meta=meta)
        self._fire(self.on_file_meta_received, meta)

    def _handle_file_chunk(self, payload: bytes) -> None:
        if len(payload) < _CHUNK_HEADER_LEN:
            self._fire(self.on_error,
                       ValueError("FILE_CHUNK payload shorter than header"))
            return
        header = payload[:_CHUNK_HEADER_LEN]
        bundle = payload[_CHUNK_HEADER_LEN:]
        file_id_raw, idx, total = struct.unpack(_CHUNK_HEADER_FMT, header)
        file_id = _wire_to_file_id(file_id_raw)

        incoming = self._incoming.get(file_id)
        if incoming is None:
            self._fire(self.on_error,
                       ValueError(f"chunk for unknown file_id {file_id}"))
            return

        try:
            aad = aad_for_chunk(file_id, int(idx), int(total))
            chunk = self._crypto.decrypt(  # type: ignore[union-attr]
                bundle, associated_data=aad,
            )
        except (InvalidTag, ValueError) as exc:
            self._record_frame(kind=KIND_FILE_CHUNK, payload=payload,
                               direction="in", decrypt_success=False)
            self._fire(self.on_error, exc)
            return

        self._record_frame(kind=KIND_FILE_CHUNK, payload=payload,
                           direction="in", decrypt_success=True)
        incoming.chunks[int(idx)] = chunk
        self._fire(self.on_file_chunk_received, file_id, int(idx), int(total))

        if len(incoming.chunks) == int(total):
            try:
                plaintext = assemble_chunks(file_id, int(total), incoming.chunks)
            except ValueError as exc:
                self._fire(self.on_error, exc)
                return
            sha_ok = verify_sha256(plaintext, incoming.meta["sha256"])
            self._fire(self.on_file_complete, incoming.meta, sha_ok, plaintext)
            del self._incoming[file_id]

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._transport is not None:
            self._transport.close()
        if (self._reader_thread is not None
                and self._reader_thread.is_alive()
                and self._reader_thread is not threading.current_thread()):
            self._reader_thread.join(timeout=1.0)

    def wait_for_sync(self, timeout: Optional[float] = None) -> bool:
        """Block until sync completes; return True iff it succeeded."""
        return self._sync_done.wait(timeout=timeout)

    @property
    def is_synced(self) -> bool:
        return self._sync_done.is_set() and self._crypto is not None

    @property
    def key_fingerprint(self) -> Optional[str]:
        if self._crypto is None:
            return None
        return self._crypto._key.hex()  # type: ignore[attr-defined]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _require_app_mode(self) -> None:
        if self._crypto is None or self._transport is None:
            raise RuntimeError(
                "PeerLink not in app mode; sync has not completed"
            )

    @staticmethod
    def _fire(callback: Optional[Callable], *args) -> None:
        if callback is None:
            return
        try:
            callback(*args)
        except Exception:  # noqa: BLE001
            logger.exception("PeerLink callback raised; continuing")

    # ------------------------------------------------------------------
    # Phase-3: feature extraction
    # ------------------------------------------------------------------
    @staticmethod
    def _payload_hash(payload: bytes) -> bytes:
        """Short hash used by the FeatureExtractor for duplicate detection.

        Truncated SHA-256 — 8 bytes is plenty (collision probability
        negligible inside a 20-frame window) and keeps the window
        memory tiny.
        """
        import hashlib
        return hashlib.sha256(payload).digest()[:8]

    def _record_frame(
        self,
        *,
        kind: int,
        payload: bytes,
        direction: str,
        decrypt_success: Optional[bool] = None,
    ) -> None:
        """Push one frame observation through the FeatureExtractor and
        fire `on_features_updated` every `FEATURE_UPDATE_EVERY` frames.

        Catches and logs any callback errors — feature extraction
        must never break the chat path.
        """
        try:
            total = self.feature_extractor.record(
                kind=kind,
                size=len(payload),
                direction=direction,
                decrypt_success=decrypt_success,
                payload_hash=self._payload_hash(payload),
            )
        except Exception:  # noqa: BLE001
            logger.exception("FeatureExtractor.record raised; continuing")
            return
        if total % self._feature_update_every == 0:
            try:
                features = self.feature_extractor.extract_features()
            except Exception:  # noqa: BLE001
                logger.exception("extract_features raised; continuing")
                return
            self._fire(self.on_features_updated, features)
            # Phase 4B: feed features into the live IDS (if one is attached).
            if self._ids is not None:
                try:
                    ids_state = self._ids.evaluate(features)
                    self._handle_ids_state_transition(ids_state, features)
                except Exception:  # noqa: BLE001
                    logger.exception("LiveIDS.evaluate raised; continuing")

    def _handle_ids_state_transition(
        self, new_state: dict, features: dict
    ) -> None:
        """Compare new IDS state to previous and fire alert/clear callbacks.

        Fires on_threat_alert when:
          • monitoring → alerting (first alert in this window), or
          • alerting → alerting with confidence delta ≥ 0.10 (significant
            change worth re-notifying the UI without spamming on every tick).

        Fires on_threat_cleared when alerting → monitoring.

        The features dict is forwarded so app.py can include an anomaly
        snapshot in the SocketIO event without re-computing features.
        """
        prev = self._ids_last_state
        self._ids_last_state = new_state

        new_alerting = new_state.get("state") == "alerting"
        prev_alerting = (prev is not None and prev.get("state") == "alerting")

        if new_alerting and not prev_alerting:
            # Transition: monitoring (or warming_up) → alerting.
            alert = new_state["active_alert"]
            self._fire(self.on_threat_alert, {
                "type": alert["type"],
                "confidence": alert["confidence"],
                "probabilities": new_state["probabilities"],
                "since": alert["since"],
                "features_snapshot": {
                    "decrypt_failure_rate": features.get("decrypt_failure_rate"),
                    "duplicate_payload_count": features.get("duplicate_payload_count"),
                },
            })

        elif new_alerting and prev_alerting:
            # Sustained alert — fire again only on a meaningful confidence jump.
            new_conf = new_state["active_alert"]["confidence"]
            prev_conf = prev["active_alert"]["confidence"]  # type: ignore[index]
            if abs(new_conf - prev_conf) >= 0.10:
                alert = new_state["active_alert"]
                self._fire(self.on_threat_alert, {
                    "type": alert["type"],
                    "confidence": new_conf,
                    "probabilities": new_state["probabilities"],
                    "since": alert["since"],
                    "features_snapshot": {
                        "decrypt_failure_rate": features.get("decrypt_failure_rate"),
                        "duplicate_payload_count": features.get("duplicate_payload_count"),
                    },
                })

        elif not new_alerting and prev_alerting:
            # Transition: alerting → monitoring.
            prev_alert = prev["active_alert"]  # type: ignore[index]
            self._fire(self.on_threat_cleared, {
                "previously_alerting_type": prev_alert["type"],
                "since": prev_alert.get("since"),
            })
