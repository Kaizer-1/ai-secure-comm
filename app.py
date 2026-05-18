"""Role-aware Flask + SocketIO entry point.

Run as:
    python app.py --role alice
    python app.py --role bob

Both invocations run the SAME script.  The CLI flag selects which
config role this process plays, which Flask port to bind, and which
side of the alice↔bob TCP link is the initiator (the one that binds).

The browser ↔ Flask channel and the alice ↔ bob TCP channel are
deliberately separate.  This file owns the browser channel; the TCP
channel lives behind `core.peer_link.PeerLink`.

Architecture:
    Browser  <—SocketIO—>  Flask app  <—callbacks—>  PeerLink  <—TCP—>  Peer
"""

from __future__ import annotations

import argparse
import datetime
import http.client
import io
import json
import logging
import os
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Optional

from flask import (
    Flask,
    abort,
    jsonify,
    render_template,
    request,
    send_file,
)
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename

import config
from attacks.mitm import MITMAttack
from attacks.replay import ReplayAttack
from core.peer_link import PeerLink

# LiveIDS is imported lazily inside create_app so import errors surface there
# with context rather than crashing the whole module load.
_LiveIDS_cls = None
if config.IDS_ENABLE:
    try:
        from ai.ids_live import LiveIDS as _LiveIDS_cls  # type: ignore[assignment]
    except Exception:  # noqa: BLE001
        logging.getLogger(__name__).error(
            "Failed to import LiveIDS; IDS will be disabled", exc_info=True
        )


logger = logging.getLogger(__name__)


def _peer_role(role: str) -> str:
    return config.ROLE_B if role == config.ROLE_A else config.ROLE_A


def _flask_port_for(role: str) -> int:
    if role == config.ROLE_A:
        return config.FLASK_PORT_ALICE
    if role == config.ROLE_B:
        return config.FLASK_PORT_BOB
    raise ValueError(f"unknown role: {role!r}")


def create_app(role: str) -> tuple[Flask, SocketIO]:
    """Build the Flask app and SocketIO server for one role.

    All per-process state — the PeerLink, completed-file buffers,
    in-flight uploads — lives in closures here.  The Flask app is one
    process per role, so there's no cross-role state to synchronise.
    """
    if role not in (config.ROLE_A, config.ROLE_B):
        raise ValueError(f"role must be 'alice' or 'bob'; got {role!r}")

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.config["SECRET_KEY"] = config.FLASK_SECRET_KEY

    socketio = SocketIO(
        app,
        async_mode=config.SOCKETIO_ASYNC_MODE,
        ping_interval=config.SOCKETIO_PING_INTERVAL,
        ping_timeout=config.SOCKETIO_PING_TIMEOUT,
        # Same-origin in dev (alice and bob each load from their own
        # Flask port) — but '*' is harmless for a local-network demo
        # and survives the demo-mode case where both laptops use 5001.
        cors_allowed_origins="*",
    )

    # ---- Phase 4B: construct the live IDS once at startup ----
    # Failures here are non-fatal: the app logs clearly and continues
    # running without intrusion detection (Phase 3 behaviour preserved).
    _ids_instance: Optional[object] = None
    if _LiveIDS_cls is not None:
        try:
            _ids_instance = _LiveIDS_cls(
                model_path=config.IDS_MODEL_PATH,
                alert_threshold_fire=config.IDS_ALERT_THRESHOLD_FIRE,
                alert_threshold_clear=config.IDS_ALERT_THRESHOLD_CLEAR,
                min_observations_required=config.IDS_MIN_OBSERVATIONS,
            )
            logger.info("[%s] IDS loaded from %s", role, config.IDS_MODEL_PATH)
        except Exception:  # noqa: BLE001
            logger.error(
                "[%s] IDS failed to load — running without intrusion detection",
                role, exc_info=True,
            )

    # ---- per-process session state (single peer, single session) ----
    #
    # `status` drives the reconnect-replay logic in `on_browser_connect`.
    # Transitions:
    #   idle    → syncing  (on first start_sync)
    #   syncing → synced   (sync_complete callback)
    #   syncing → error    (PeerLink on_error fires before sync_complete)
    #   synced  → synced   (peer_disconnected leaves status alone — the
    #                       key is still valid; we just notify the UI)
    #
    # When a browser tab refreshes, the new SocketIO `connect` handler
    # reads `status` and replays the appropriate event(s) to the new
    # client, so the UI immediately reflects reality without waiting
    # for a fresh sync to finish.
    state: dict = {
        "peer_link": None,         # PeerLink once start_sync fires
        "status": "idle",          # "idle" | "syncing" | "synced" | "error"
        "sync_started": False,
        "started_at": None,
        # populated when sync_complete fires; replayed on reconnect
        "key_fingerprint": None,
        "sync_rounds": None,
        "sync_time_ms": None,
        # most recent on_sync_progress payload, replayed on reconnect
        "last_progress": None,     # {"round": int, "matched": int, "total": int}
        # populated on error; replayed on reconnect
        "last_error": None,
        # Phase 4C: most recent ids_probabilities payload; replayed on reconnect
        # so a refreshed browser tab immediately sees the current gauge state.
        "ids_last_probabilities": None,
        # Phase 4C: full threat_alert payload while an alert is active; cleared
        # when threat_cleared fires so a refreshed tab sees the active banner.
        "ids_last_alert": None,
        # Phase 5A: per-session message counters for the metrics dashboard.
        "messages_encrypted": 0,
        "bytes_encrypted": 0,
    }
    received_files: dict[str, dict] = {}  # file_id -> {meta, plaintext}
    state_lock = threading.Lock()

    # Phase 5A: track when each demo attack was launched so the detection
    # latency (button-click → alert-fire) can be recorded on LiveIDS.
    _attack_start_times: dict = {"mitm": None, "replay": None}
    _attack_start_lock = threading.Lock()

    # ====================================================================
    # HTTP routes
    # ====================================================================

    @app.route("/")
    def index():
        return render_template(
            "chat.html",
            role=role,
            peer_role=_peer_role(role),
            wire_view_buffer=config.WIRE_VIEW_BUFFER,
        )

    @app.route("/upload", methods=["POST"])
    def upload():
        """Browser drops a file → save to a temp path → kick off transfer."""
        if state["status"] != "synced":
            return jsonify({"error": "not synced yet"}), 409
        if "file" not in request.files:
            return jsonify({"error": "no file in request"}), 400
        f = request.files["file"]
        if not f.filename:
            return jsonify({"error": "empty filename"}), 400

        # Save into a fresh tempdir under the *original* (sanitised)
        # filename so `make_file_meta` derives a clean basename — the
        # peer (and the audience watching the demo) sees the name the
        # user picked, not a `tempfile.mkstemp` prefix.
        safe_name = secure_filename(f.filename) or "uploaded.bin"
        tmp_dir = tempfile.mkdtemp(prefix="upload-")
        tmp_path = os.path.join(tmp_dir, safe_name)
        f.save(tmp_path)

        size = os.path.getsize(tmp_path)
        if size > config.FILE_MAX_BYTES:
            try:
                os.remove(tmp_path)
                os.rmdir(tmp_dir)
            except OSError:
                pass
            return jsonify({"error": f"file too large ({size} bytes)"}), 413

        # Send asynchronously so the HTTP response doesn't block on
        # large transfers.  The peer's progress events stream in via
        # SocketIO independently.
        def _send_then_clean() -> None:
            try:
                meta = state["peer_link"].send_file(tmp_path)
                socketio.emit("file_sent", {
                    "file_id": meta["file_id"],
                    "filename": meta["filename"],
                    "size": meta["size"],
                    "total_chunks": meta["total_chunks"],
                })
            except Exception as exc:  # noqa: BLE001
                logger.exception("file send failed")
                socketio.emit("error", {"message": f"send failed: {exc}"})
            finally:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
                try:
                    os.rmdir(tmp_dir)
                except OSError:
                    pass

        threading.Thread(target=_send_then_clean,
                         name="file-sender", daemon=True).start()
        return jsonify({"status": "uploading", "filename": safe_name,
                        "size": size}), 202

    @app.route("/download/<file_id>")
    def download(file_id):
        entry = received_files.get(file_id)
        if entry is None:
            abort(404)
        return send_file(
            io.BytesIO(entry["plaintext"]),
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name=entry["meta"]["filename"],
        )

    @app.route("/_demo")
    def demo_panel():
        # Phase 3 placeholder: the attack-controls panel will live here.
        # For now it is hidden so the demo cannot accidentally find it.
        abort(404)

    @app.route("/metrics")
    def metrics_page():
        return render_template("metrics.html", role=role)

    @app.route("/api/metrics_data")
    def metrics_data():
        """Return benchmark results + live IDS latency + session stats as JSON.

        Benchmark JSON files are read from disk at request time; missing files
        are returned as ``null`` so the dashboard can show a friendly message.
        """
        app_dir = Path(__file__).resolve().parent
        results_dir = app_dir / "benchmarks" / "results"

        def _load_json(filename: str):
            p = results_dir / filename
            if p.exists():
                try:
                    return json.loads(p.read_text())
                except Exception:
                    return None
            return None

        key_exchange = _load_json("key_exchange.json")
        throughput = _load_json("throughput.json")

        ids_latency = None
        if _ids_instance is not None and hasattr(_ids_instance, "get_latency_stats"):
            try:
                ids_latency = _ids_instance.get_latency_stats()
            except Exception:
                pass

        with state_lock:
            sync_time_ms = state["sync_time_ms"]
            sync_rounds = state["sync_rounds"]
            messages_encrypted = state["messages_encrypted"]
            bytes_encrypted = state["bytes_encrypted"]

        return jsonify({
            "key_exchange": key_exchange,
            "throughput": throughput,
            "ids_latency": ids_latency,
            "session": {
                "role": role,
                "sync_time_ms": sync_time_ms,
                "sync_rounds": sync_rounds,
                "messages_encrypted": messages_encrypted,
                "bytes_encrypted": bytes_encrypted,
            },
        })

    # ====================================================================
    # SocketIO events (browser → Flask)
    # ====================================================================

    @socketio.on("connect")
    def on_browser_connect():
        """Replay current session state to a freshly connected tab.

        See the `state` block above for the status state machine.  We
        always emit `hello` (so the UI knows its role labels), then
        replay the most informative event for the current status:

          synced  → emit `sync_complete` with `replay: True` so the
                    JS unlocks the input and shows the existing key
                    fingerprint; the JS will surface a small
                    "(reconnected — earlier messages not shown)"
                    banner because chat history is in-memory only.
          syncing → emit the cached `sync_progress` if we have one
                    (with `replay: True`), otherwise emit a generic
                    `sync_in_progress` event so the JS shows an
                    indeterminate progress bar.
          error   → emit `error` with the cached message so the UI
                    can show what happened and offer a retry.
          idle    → emit nothing; the JS will trigger `start_sync`
                    after a 2-second grace window.
        """
        with state_lock:
            status = state["status"]
            replay_synced = (
                {
                    "rounds": state["sync_rounds"],
                    "time_ms": state["sync_time_ms"],
                    "key_fingerprint": state["key_fingerprint"],
                    "replay": True,
                }
                if status == "synced" else None
            )
            replay_progress = (
                {**state["last_progress"], "replay": True}
                if status == "syncing" and state["last_progress"] else None
            )
            generic_in_progress = (
                status == "syncing" and state["last_progress"] is None
            )
            replay_error = (
                {"message": state["last_error"] or "previous sync failed",
                 "replay": True}
                if status == "error" else None
            )

        # `emit` (without the socketio prefix) sends to *just* the
        # requesting client — the right thing for state replay.
        emit("hello", {
            "role": role,
            "peer_role": _peer_role(role),
            "status": status,
        })
        if replay_synced is not None:
            emit("sync_complete", replay_synced)
        elif replay_progress is not None:
            emit("sync_progress", replay_progress)
        elif generic_in_progress:
            emit("sync_in_progress", {"replay": True})
        elif replay_error is not None:
            emit("error", replay_error)

        # Phase 4C: replay IDS gauge state and any active alert so a
        # refreshed browser tab immediately shows the current threat level
        # rather than starting blank.
        with state_lock:
            ids_probs = state["ids_last_probabilities"]
            ids_alert = state["ids_last_alert"]
        if ids_probs is not None:
            emit("ids_probabilities", ids_probs)
        if ids_alert is not None:
            emit("threat_alert", ids_alert)

    @socketio.on("start_sync")
    def on_start_sync():
        with state_lock:
            if state["sync_started"]:
                return
            state["sync_started"] = True
            state["status"] = "syncing"
            state["started_at"] = time.time()
            link = PeerLink(role=role)
            state["peer_link"] = link

        # Phase 4B: attach IDS to this session's PeerLink.
        # reset() clears any stale alert state from a previous session so a
        # reconnect starts fresh without inheriting the previous window's signal.
        if _ids_instance is not None:
            _ids_instance.reset()
            link.set_ids(_ids_instance)

        # Wire the callbacks BEFORE we kick off connect().
        def _on_sync_progress(r, m, t):
            with state_lock:
                state["last_progress"] = {
                    "round": r, "matched": m, "total": t,
                }
            socketio.emit(
                "sync_progress", {"round": r, "matched": m, "total": t},
            )
        link.on_sync_progress = _on_sync_progress

        def _on_sync_complete(result, fp_hex):
            elapsed_ms = (
                int((time.time() - state["started_at"]) * 1000)
                if state["started_at"] else None
            )
            with state_lock:
                state["status"] = "synced"
                state["key_fingerprint"] = fp_hex
                state["sync_rounds"] = result.rounds
                state["sync_time_ms"] = elapsed_ms
            socketio.emit("sync_complete", {
                "rounds": result.rounds,
                "time_ms": elapsed_ms,
                "key_fingerprint": fp_hex,
            })
        link.on_sync_complete = _on_sync_complete

        link.on_chat_received = lambda pt, bundle: socketio.emit(
            "chat_received",
            {
                "plaintext": pt,
                "ciphertext_hex": bundle.hex(),
                "timestamp": time.time(),
            },
        )

        # Phase 3 — distinct event for AES-GCM auth failures on inbound
        # CHAT.  PeerLink fires this *instead of* `on_error` for the
        # InvalidTag case, so the UI can render a meaningful "tampered
        # ciphertext rejected" bubble (the MITM signal) rather than the
        # opaque "error: unknown" message Phase 2 produced.
        def _on_chat_decryption_failed(bundle: bytes) -> None:
            preview_len = min(len(bundle), 24)
            socketio.emit("chat_decryption_failed", {
                "reason": "auth_tag_invalid",
                "timestamp": time.time(),
                "ciphertext_size": len(bundle),
                "ciphertext_hex": bundle.hex(),  # full bundle for wire view
                "ciphertext_preview_hex": bundle[:preview_len].hex(),
            })
        link.on_chat_decryption_failed = _on_chat_decryption_failed

        link.on_file_meta_received = lambda meta: socketio.emit(
            "file_meta_received",
            {
                "file_id": meta["file_id"],
                "filename": meta["filename"],
                "size": meta["size"],
                "total_chunks": meta["total_chunks"],
            },
        )

        link.on_file_chunk_received = lambda fid, idx, total: socketio.emit(
            "file_chunk_received",
            {"file_id": fid, "chunk_index": idx, "total_chunks": total},
        )

        def _on_file_complete(meta, sha_ok, plaintext):
            received_files[meta["file_id"]] = {
                "meta": meta, "plaintext": plaintext,
            }
            socketio.emit("file_complete", {
                "file_id": meta["file_id"],
                "filename": meta["filename"],
                "size": meta["size"],
                "sha_ok": bool(sha_ok),
                "download_url": f"/download/{meta['file_id']}",
            })
        link.on_file_complete = _on_file_complete

        link.on_peer_disconnected = lambda: socketio.emit(
            "peer_disconnected", {}
        )

        def _on_error(exc):
            msg = str(exc)
            with state_lock:
                # Only mark the session "error" if sync hasn't completed
                # — once we're in app mode, transient send/decrypt
                # errors don't invalidate the key.
                if state["status"] != "synced":
                    state["status"] = "error"
                    state["last_error"] = msg
            socketio.emit("error", {"message": msg})
        link.on_error = _on_error

        # Phase 4B — IDS alert callbacks.
        def _on_threat_alert(alert_event: dict) -> None:
            now = datetime.datetime.now(datetime.timezone.utc).isoformat()
            payload = {
                "type": alert_event["type"],
                "confidence": alert_event["confidence"],
                "probabilities": alert_event["probabilities"],
                "timestamp": now,
                # Only the two anomaly-hint features — keeps the payload small.
                "features_snapshot": alert_event.get("features_snapshot", {}),
            }
            # Store so a reconnecting browser tab immediately gets the banner.
            with state_lock:
                state["ids_last_alert"] = payload
            socketio.emit("threat_alert", payload)
            logger.warning(
                "[%s] IDS threat_alert: type=%s confidence=%.2f",
                role, alert_event["type"], alert_event["confidence"],
            )

            # Phase 5A: record detection latency if the matching attack was
            # launched via the demo panel (button-click timestamp available).
            alert_type = alert_event.get("type", "")
            with _attack_start_lock:
                start_t = _attack_start_times.get(alert_type)
                if start_t is not None:
                    _attack_start_times[alert_type] = None  # consume — one shot per launch
            if (
                start_t is not None
                and _ids_instance is not None
                and hasattr(_ids_instance, "record_alert_latency")
            ):
                try:
                    _ids_instance.record_alert_latency(start_t, time.time())
                except Exception:  # noqa: BLE001
                    pass

        link.on_threat_alert = _on_threat_alert

        def _on_threat_cleared(cleared_event: dict) -> None:
            since_str = cleared_event.get("since") or ""
            duration_seconds: Optional[float] = None
            if since_str:
                try:
                    since_dt = datetime.datetime.fromisoformat(since_str)
                    duration_seconds = (
                        datetime.datetime.now(datetime.timezone.utc) - since_dt
                    ).total_seconds()
                except Exception:  # noqa: BLE001
                    pass
            payload = {
                "previously_alerting_type": cleared_event["previously_alerting_type"],
                "duration_seconds": duration_seconds,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }
            # Clear the stored alert so refreshed tabs don't replay a stale banner.
            with state_lock:
                state["ids_last_alert"] = None
            socketio.emit("threat_cleared", payload)
            logger.info(
                "[%s] IDS threat_cleared: was %s for %.1fs",
                role,
                cleared_event["previously_alerting_type"],
                duration_seconds or 0.0,
            )
        link.on_threat_cleared = _on_threat_cleared

        # Phase 4C — continuous probability updates for the gauge.
        # Fires on every feature window (same cadence as IDS evaluation).
        # Uses current_state() which returns the PREVIOUS window's evaluation —
        # one window behind is imperceptible at the UI update rate (~5 frames).
        def _on_features_updated(features: dict) -> None:
            if _ids_instance is None:
                return
            try:
                ids_state = _ids_instance.current_state()
            except Exception:  # noqa: BLE001
                return
            active = ids_state.get("active_alert")
            now = datetime.datetime.now(datetime.timezone.utc).isoformat()
            payload = {
                "probabilities": ids_state.get("probabilities", {}),
                "state": ids_state.get("state", "warming_up"),
                "active_alert_type": active["type"] if active else None,
                "active_alert_confidence": active["confidence"] if active else None,
                "timestamp": now,
            }
            with state_lock:
                state["ids_last_probabilities"] = payload
            socketio.emit("ids_probabilities", payload)
        link.on_features_updated = _on_features_updated

        threading.Thread(
            target=link.connect, name="peer-link-connect", daemon=True,
        ).start()

    @socketio.on("send_chat")
    def on_send_chat(data):
        text = (data or {}).get("text", "")
        if not text:
            return
        with state_lock:
            link: Optional[PeerLink] = state["peer_link"]
            if state["status"] != "synced" or link is None:
                socketio.emit("error", {"message": "not synced yet"})
                return
        try:
            bundle = link.send_chat(text)
        except Exception as exc:  # noqa: BLE001
            socketio.emit("error", {"message": f"send failed: {exc}"})
            return
        # Update per-session encryption counters for the metrics dashboard.
        with state_lock:
            state["messages_encrypted"] += 1
            state["bytes_encrypted"] += len(text.encode())
        # Echo to this side's wire view as outbound.
        socketio.emit("chat_sent", {
            "plaintext": text,
            "ciphertext_hex": bundle.hex(),
            "timestamp": time.time(),
        })

    # ====================================================================
    # Phase-3 demo controls (gated on config.DEMO_MODE)
    # ====================================================================
    # The events here are surfaced by the hidden Ctrl/Cmd+Shift+D panel
    # in chat.js.  When `DEMO_MODE` is False (any non-demo deployment)
    # we DON'T register the handlers at all, so the events are simply
    # ignored by the server — there's no privileged endpoint a hostile
    # client could probe.
    if config.DEMO_MODE:

        # Track the live attack instances per type so "stop" can stop
        # exactly the one(s) the user launched.
        demo_attacks: dict = {"mitm": None, "replay": None}
        demo_lock = threading.Lock()

        def _serialize_active_attacks() -> list:
            """Snapshot the registered attacks' stats for the UI."""
            with state_lock:
                link = state["peer_link"]
            if link is None:
                return []
            return [a.get_stats() for a in link.attack_registry.all_attacks()]

        def _broadcast_attack_state() -> None:
            socketio.emit("demo_attack_state", {
                "active": [
                    a["name"] for a in _serialize_active_attacks()
                    if a.get("active")
                ],
                "stats": _serialize_active_attacks(),
            })

        def _ensure_synced_link() -> Optional[PeerLink]:
            with state_lock:
                link = state["peer_link"]
                if state["status"] != "synced" or link is None:
                    socketio.emit("error", {
                        "message": "attack controls require an active sync"
                    })
                    return None
                return link

        def _notify_peer_attack_start(attack_type: str, ts: float) -> None:
            # In dev mode (single laptop) the peer Flask server is always on
            # localhost; POST it the attack-start timestamp so it can record
            # detection latency when its own IDS fires the alert.
            # In two-laptop demo mode this call fails silently — acceptable
            # because latency tracking is a dashboard nicety, not correctness.
            peer_port = (
                config.FLASK_PORT_BOB if role == config.ROLE_A
                else config.FLASK_PORT_ALICE
            )
            try:
                body = json.dumps({"type": attack_type, "ts": ts}).encode()
                conn = http.client.HTTPConnection("127.0.0.1", peer_port, timeout=1.0)
                conn.request(
                    "POST", "/api/record_attack_start", body=body,
                    headers={"Content-Type": "application/json"},
                )
                conn.getresponse()
                conn.close()
            except Exception:  # noqa: BLE001
                pass

        @app.route("/api/record_attack_start", methods=["POST"])
        def record_attack_start():
            """Receive attack-start timestamp from the peer process (dev mode).

            Alice stores the demo-launch timestamp in her own process, but the
            IDS alert fires in bob's separate process.  Alice POSTs the timestamp
            here so bob's _on_threat_alert can compute latency correctly.
            """
            try:
                data = request.json or {}
                attack_type = data.get("type", "")
                ts = data.get("ts")
                if attack_type in ("mitm", "replay") and ts is not None:
                    with _attack_start_lock:
                        _attack_start_times[attack_type] = float(ts)
                return jsonify({"ok": True})
            except Exception:  # noqa: BLE001
                return jsonify({"ok": False}), 400

        @socketio.on("demo_launch_mitm")
        def on_demo_mitm():
            link = _ensure_synced_link()
            if link is None:
                return
            with demo_lock:
                if demo_attacks["mitm"] is not None and demo_attacks["mitm"].is_active():
                    return
                attack = MITMAttack()
                link.attack_registry.register(attack)
                attack.start()
                demo_attacks["mitm"] = attack
            # Phase 5A: record launch time for IDS detection-latency tracking.
            # Notify peer too — the IDS alert fires on the receiver's side.
            t_launch = time.time()
            with _attack_start_lock:
                _attack_start_times["mitm"] = t_launch
            threading.Thread(
                target=_notify_peer_attack_start, args=("mitm", t_launch), daemon=True,
            ).start()
            socketio.emit("demo_attack_active", {"type": "mitm"})
            _broadcast_attack_state()
            logger.warning("[demo] MITM attack launched on %s", role)

        @socketio.on("demo_launch_replay")
        def on_demo_replay():
            link = _ensure_synced_link()
            if link is None:
                return
            with demo_lock:
                if demo_attacks["replay"] is not None and demo_attacks["replay"].is_active():
                    return
                attack = ReplayAttack()
                link.attack_registry.register(attack)
                attack.start()
                demo_attacks["replay"] = attack
            # Phase 5A: record launch time for IDS detection-latency tracking.
            # Notify peer too — the IDS alert fires on the receiver's side.
            t_launch = time.time()
            with _attack_start_lock:
                _attack_start_times["replay"] = t_launch
            threading.Thread(
                target=_notify_peer_attack_start, args=("replay", t_launch), daemon=True,
            ).start()
            socketio.emit("demo_attack_active", {"type": "replay"})
            _broadcast_attack_state()
            logger.warning("[demo] Replay attack launched on %s", role)

        @socketio.on("demo_stop_attacks")
        def on_demo_stop():
            with state_lock:
                link = state["peer_link"]
            if link is None:
                return
            with demo_lock:
                for kind, attack in list(demo_attacks.items()):
                    if attack is None:
                        continue
                    try:
                        link.attack_registry.unregister(attack)
                    except Exception:  # noqa: BLE001
                        logger.exception("unregister %s raised", kind)
                    demo_attacks[kind] = None
            socketio.emit("demo_attacks_stopped", {})
            _broadcast_attack_state()
            logger.warning("[demo] all attacks stopped on %s", role)

            # Phase 4C: immediately clear the IDS gauge when the demo panel
            # explicitly stops attacks.  Without this, the sliding feature
            # window retains malicious frames until they age out via normal
            # traffic (up to FEATURE_WINDOW_SIZE = 20 frames), keeping the
            # gauge red well after the attack stops — bad demo UX.
            # In a real adversarial scenario we wouldn't know the attacker
            # stopped; in the viva demo we do, so we cheat deliberately.
            if _ids_instance is not None:
                # Snapshot current alert state BEFORE reset so we can build
                # the threat_cleared payload with accurate duration.
                try:
                    ids_before = _ids_instance.current_state()
                except Exception:  # noqa: BLE001
                    ids_before = {}
                was_alerting = ids_before.get("state") == "alerting"
                alert_before = ids_before.get("active_alert")

                # Zero out the IDS (observation_count, active_alert, _last_state).
                try:
                    _ids_instance.reset()
                except Exception:  # noqa: BLE001
                    logger.exception("[demo] IDS reset raised on stop; continuing")

                # Reset PeerLink's cached IDS state so _handle_ids_state_transition
                # does NOT fire an extra on_threat_cleared on the NEXT evaluate()
                # call (prev=None → no alerting→monitoring transition detected).
                link._ids_last_state = None

                # Push a clean probability snapshot to the gauge immediately.
                now = datetime.datetime.now(datetime.timezone.utc).isoformat()
                clean_payload = {
                    "probabilities": {"normal": 1.0, "mitm": 0.0, "replay": 0.0},
                    "state": "monitoring",
                    "active_alert_type": None,
                    "active_alert_confidence": None,
                    "timestamp": now,
                }
                with state_lock:
                    state["ids_last_probabilities"] = clean_payload
                    state["ids_last_alert"] = None
                socketio.emit("ids_probabilities", clean_payload)

                # If an alert was active, emit threat_cleared so the banner
                # fades and the history chip gets its final duration.
                if was_alerting and alert_before:
                    since_str = alert_before.get("since") or ""
                    duration_seconds: Optional[float] = None
                    if since_str:
                        try:
                            since_dt = datetime.datetime.fromisoformat(since_str)
                            duration_seconds = (
                                datetime.datetime.now(datetime.timezone.utc) - since_dt
                            ).total_seconds()
                        except Exception:  # noqa: BLE001
                            pass
                    socketio.emit("threat_cleared", {
                        "previously_alerting_type": alert_before["type"],
                        "duration_seconds": duration_seconds,
                        "timestamp": now,
                    })
                    logger.info(
                        "[demo] IDS alert cleared by demo stop (was %s for %.1fs)",
                        alert_before["type"], duration_seconds or 0.0,
                    )

        @socketio.on("demo_status")
        def on_demo_status():
            socketio.emit("demo_attack_state", {
                "active": [
                    a["name"] for a in _serialize_active_attacks()
                    if a.get("active")
                ],
                "stats": _serialize_active_attacks(),
            })

    return app, socketio


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="AI-Enhanced Secure Communication — role-aware web UI",
    )
    parser.add_argument(
        "--role",
        required=True,
        choices=[config.ROLE_A, config.ROLE_B],
        help="Which role this process plays (alice or bob).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Override the Flask port.  Defaults to FLASK_PORT_ALICE / "
             "FLASK_PORT_BOB based on --role.",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="Override the Flask bind host.  Defaults to config.FLASK_HOST.",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    role = args.role
    host = args.host or config.FLASK_HOST
    port = args.port or _flask_port_for(role)

    app, socketio = create_app(role)
    print(
        f"[{role}] starting Flask on http://{host}:{port}/   "
        f"(peer TCP {config.PEER_TCP_PORT}; "
        f"initiator={config.INITIATOR_ROLE})",
        flush=True,
    )
    # `allow_unsafe_werkzeug=True` so the threading-mode dev server
    # actually binds; for a local-network academic demo this is fine,
    # and config.FLASK_SECRET_KEY's comment already calls out that any
    # real deployment needs a proper WSGI server.
    socketio.run(
        app,
        host=host,
        port=port,
        debug=False,
        allow_unsafe_werkzeug=True,
        use_reloader=False,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
