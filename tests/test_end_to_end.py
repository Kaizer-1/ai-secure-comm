"""End-to-end smoke tests for the Phase 1-4 stack.

Each test spins up one or two Flask-SocketIO apps via ``create_app()`` and
exercises the complete browser ↔ Flask ↔ PeerLink pipeline using
Flask-SocketIO's synchronous test client.

Skipped tests
-------------
TestEndToEndReplayDetection.test_replay_detected_by_ids
    ReplayAttack injects one buffered frame every REPLAY_INTERVAL_S = 3.0 s.
    Accumulating 3 feature-window observations (IDS_MIN_OBSERVATIONS = 3) via
    re-injected frames requires waiting > 30 s in wall time — too slow for an
    automated regression suite.  Covered manually in demo_final.md §7.

Design notes
------------
*  Real TCP is used for tests that exercise PeerLink sync and chat.  Each test
   grabs a random free port and temporarily writes it to config.PEER_TCP_PORT
   so that the PeerLink instances created inside on_start_sync use it.
*  Alice is always the TCP initiator (binds and waits); her start_sync is
   emitted first, followed by a short sleep, then bob's start_sync.
*  Events are collected by polling ``client.get_received()`` — the SocketIO
   test client is synchronous and has no blocking wait API.
*  The ``ResourceWarning: unclosed socket`` that Python 3.13's GC may emit
   after these tests is a known non-blocking cosmetic issue; see
   docs/DECISIONS.md § "Known non-blocking — ResourceWarning under Python
   3.13 GC".
"""

from __future__ import annotations

import socket
import threading
import time
import unittest
from typing import Optional
from unittest.mock import MagicMock, patch

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import app as app_module
import config as config_module
from core.sync_protocol import SyncResult


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _free_port() -> int:
    """Return a random, currently-unused TCP port on 127.0.0.1."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _drain_until(
    client, stop_event: str, timeout: float = 20.0
) -> list[dict]:
    """Poll ``client.get_received()`` until *stop_event* appears or timeout.

    Returns ALL events collected during the poll (including the stop event).
    If timeout expires without seeing the event, returns whatever accumulated.
    """
    collected: list[dict] = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        batch = client.get_received()
        collected.extend(batch)
        if any(e["name"] == stop_event for e in batch):
            return collected
        time.sleep(0.05)
    return collected


def _find(events: list[dict], name: str) -> Optional[dict]:
    """Return the first event matching *name*, or ``None``."""
    return next((e for e in events if e["name"] == name), None)


def _event_names(events: list[dict]) -> set[str]:
    return {e["name"] for e in events}


def _connect_and_sync(
    alice_sio,
    alice_app,
    bob_sio,
    bob_app,
    sync_timeout: float = 25.0,
):
    """Connect test clients and synchronise both PeerLinks over real TCP.

    Returns ``(alice_client, bob_client, alice_events, bob_events)`` where
    *alice_events* / *bob_events* are the events collected up to and including
    ``sync_complete``.

    Callers must set ``config_module.PEER_TCP_PORT`` to a free port *before*
    calling this function.
    """
    alice_client = alice_sio.test_client(alice_app)
    bob_client = bob_sio.test_client(bob_app)
    alice_client.connect()
    bob_client.connect()

    # Alice is the initiator (binds).  Emit her start_sync first so the
    # listener is up before bob's background thread tries to dial in.
    alice_client.emit("start_sync")
    time.sleep(0.15)
    bob_client.emit("start_sync")

    alice_events = _drain_until(alice_client, "sync_complete", timeout=sync_timeout)
    bob_events = _drain_until(bob_client, "sync_complete", timeout=sync_timeout)
    return alice_client, bob_client, alice_events, bob_events


# ---------------------------------------------------------------------------
# Test: normal session — chat round-trip, no false alert
# ---------------------------------------------------------------------------

class TestEndToEndNormalSession(unittest.TestCase):
    """Full chat round-trip over real TCP + TPM sync with IDS disabled.

    Verifies: alice sends → bob receives ``chat_received`` with correct
    plaintext; alice receives ``chat_sent`` echo; no ``threat_alert`` fires.
    """

    def test_chat_round_trip_and_no_false_alert(self):
        port = _free_port()
        orig_port = config_module.PEER_TCP_PORT
        try:
            config_module.PEER_TCP_PORT = port

            # IDS disabled — this test is about the chat pipeline only.
            with patch.object(app_module, "_LiveIDS_cls", None):
                alice_app, alice_sio = app_module.create_app("alice")
                bob_app, bob_sio = app_module.create_app("bob")
            alice_app.config["TESTING"] = True
            bob_app.config["TESTING"] = True

            alice_client, bob_client, alice_sync_events, bob_sync_events = (
                _connect_and_sync(alice_sio, alice_app, bob_sio, bob_app)
            )

            self.assertIsNotNone(
                _find(alice_sync_events, "sync_complete"),
                "Alice TPM sync timed out (>25 s)",
            )
            self.assertIsNotNone(
                _find(bob_sync_events, "sync_complete"),
                "Bob TPM sync timed out (>25 s)",
            )
            alice_sync_payload = _find(alice_sync_events, "sync_complete")["args"][0]
            self.assertIn(
                "key_fingerprint", alice_sync_payload,
                "sync_complete must carry key_fingerprint",
            )

            # Alice sends one message.
            alice_client.emit("send_chat", {"text": "hello end-to-end"})

            # Bob must receive chat_received with the original plaintext.
            bob_after = _drain_until(bob_client, "chat_received", timeout=5.0)
            chat_ev = _find(bob_after, "chat_received")
            self.assertIsNotNone(chat_ev, "Bob did not receive chat_received within 5 s")
            self.assertEqual(chat_ev["args"][0]["plaintext"], "hello end-to-end")

            # Alice must have received chat_sent (wire-view echo on alice's side).
            alice_after = alice_client.get_received()
            self.assertIn("chat_sent", _event_names(alice_after))

            # No threat_alert should have fired on either side.
            all_events = (
                alice_sync_events + alice_after + bob_sync_events + bob_after
            )
            self.assertNotIn(
                "threat_alert",
                _event_names(all_events),
                "IDS false alert fired during normal session",
            )

        finally:
            config_module.PEER_TCP_PORT = orig_port


# ---------------------------------------------------------------------------
# Test: MITM detection
# ---------------------------------------------------------------------------

class TestEndToEndMITMDetection(unittest.TestCase):
    """MITM attack launched via demo API → bob's IDS fires threat_alert.

    MITMAttack bit-flips ~30 % of alice's outbound CHAT frames.  Bob
    receives corrupted bundles, AES-GCM auth fails, and
    ``decrypt_failure_rate`` in bob's feature window rises.  After
    FEATURE_UPDATE_EVERY × IDS_MIN_OBSERVATIONS = 5 × 3 = 15 frames bob's
    IDS transitions from warming_up → monitoring → alerting and emits
    ``threat_alert`` with ``type="mitm"`` and ``confidence ≥ 0.70``.

    Probabilistic note: with tamper_probability=0.30 and 15 trials the
    expected number of tampered frames is 4–5.  The chance of fewer than 3
    tampered frames (which might keep mitm confidence < 0.70) is ~12 %.
    If this test proves flaky in CI, increase the message count to 25 or
    mark it ``@unittest.skip`` with this explanation.
    """

    def test_mitm_detected_within_15_messages(self):
        port = _free_port()
        orig_port = config_module.PEER_TCP_PORT
        try:
            config_module.PEER_TCP_PORT = port

            # Both apps use the real trained IDS model.
            alice_app, alice_sio = app_module.create_app("alice")
            bob_app, bob_sio = app_module.create_app("bob")
            alice_app.config["TESTING"] = True
            bob_app.config["TESTING"] = True

            alice_client, bob_client, alice_sync_events, bob_sync_events = (
                _connect_and_sync(alice_sio, alice_app, bob_sio, bob_app)
            )
            self.assertIsNotNone(
                _find(alice_sync_events, "sync_complete"),
                "Alice TPM sync timed out",
            )
            self.assertIsNotNone(
                _find(bob_sync_events, "sync_complete"),
                "Bob TPM sync timed out",
            )

            # Register MITMAttack on alice's transport via the demo API.
            alice_client.emit("demo_launch_mitm")
            time.sleep(0.05)  # let the handler complete

            # 15 messages → 3 feature-window evaluations on bob's side
            # (FEATURE_UPDATE_EVERY = 5, IDS_MIN_OBSERVATIONS = 3).
            for i in range(15):
                alice_client.emit("send_chat", {"text": f"probe-{i:02d}"})
                time.sleep(0.02)  # avoid overwhelming the reader thread

            # Wait for bob's IDS to fire threat_alert.
            # 30 s headroom covers variable TPM round counts and slow CI.
            bob_alert_events = _drain_until(
                bob_client, "threat_alert", timeout=30.0
            )
            alert_ev = _find(bob_alert_events, "threat_alert")
            self.assertIsNotNone(
                alert_ev,
                "Bob IDS did not fire threat_alert after 15 MITM-tampered "
                "messages (30 s timeout).  See class docstring for the "
                "probabilistic failure mode.",
            )
            payload = alert_ev["args"][0]
            self.assertEqual(payload["type"], "mitm")
            self.assertGreaterEqual(payload["confidence"], 0.70)

        finally:
            config_module.PEER_TCP_PORT = orig_port


# ---------------------------------------------------------------------------
# Test: Replay detection (skipped — too slow for automated regression)
# ---------------------------------------------------------------------------

@unittest.skip(
    "ReplayAttack injects one buffered frame every REPLAY_INTERVAL_S = 3.0 s.  "
    "Accumulating the IDS_MIN_OBSERVATIONS = 3 feature-window evaluations via "
    "re-injected frames requires > 30 s of wall time — unsuitable for CI.  "
    "Covered manually in demo_final.md §7 (Replay attack walkthrough)."
)
class TestEndToEndReplayDetection(unittest.TestCase):
    """Replay attack detected by bob's IDS (skipped — see class docstring)."""

    def test_replay_detected_by_ids(self):
        pass  # not reached


# ---------------------------------------------------------------------------
# Test: alert clears after demo_stop_attacks
# ---------------------------------------------------------------------------

class TestEndToEndAlertClears(unittest.TestCase):
    """demo_stop_attacks with an active IDS alert → threat_cleared fires.

    Uses a mock IDS (no real TCP needed) so the test is fast and
    deterministic.  The mock returns ``state="alerting"`` on the first
    ``current_state()`` call (which demo_stop_attacks reads before reset)
    and ``state="monitoring"`` on subsequent calls (after reset).
    """

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_alerting_ids() -> MagicMock:
        """Mock IDS that starts in alerting state and clears after reset."""
        mock = MagicMock()
        call_count: list[int] = [0]

        def _current_state() -> dict:
            call_count[0] += 1
            if call_count[0] <= 1:
                return {
                    "state": "alerting",
                    "active_alert": {
                        "type": "mitm",
                        "confidence": 0.85,
                        "since": "2026-01-01T00:00:00+00:00",
                    },
                    "probabilities": {
                        "normal": 0.10, "mitm": 0.85, "replay": 0.05,
                    },
                    "observation_count": 10,
                }
            return {
                "state": "monitoring",
                "active_alert": None,
                "probabilities": {
                    "normal": 1.0, "mitm": 0.0, "replay": 0.0,
                },
                "observation_count": 0,
            }

        mock.current_state.side_effect = _current_state
        mock.reset.return_value = None
        return mock

    def _capture_link(self, client) -> Optional[object]:
        """Emit start_sync (connect patched to no-op) and return the PeerLink.

        Captures the instance via a wrapper around PeerLink.set_ids so we
        can fire on_sync_complete directly to force state → "synced".
        """
        captured: dict = {}
        ready = threading.Event()
        orig_set_ids = app_module.PeerLink.set_ids

        def _fake_set_ids(self_link, ids):
            orig_set_ids(self_link, ids)
            captured["link"] = self_link
            ready.set()

        with (
            patch.object(app_module.PeerLink, "connect", return_value=None),
            patch.object(app_module.PeerLink, "set_ids", _fake_set_ids),
        ):
            client.emit("start_sync")
            ready.wait(timeout=3.0)

        return captured.get("link")

    # ------------------------------------------------------------------
    # Test
    # ------------------------------------------------------------------

    def test_threat_cleared_fires_after_stop(self):
        mock_ids = self._make_alerting_ids()

        with patch.object(app_module, "_LiveIDS_cls") as MockCls:
            MockCls.return_value = mock_ids
            flask_app, sio = app_module.create_app("alice")
        flask_app.config["TESTING"] = True

        client = sio.test_client(flask_app)
        client.connect()

        link = self._capture_link(client)
        self.assertIsNotNone(link, "PeerLink capture via set_ids failed")

        # Force state → "synced" by invoking on_sync_complete directly.
        # This makes _ensure_synced_link() inside demo_stop_attacks succeed.
        fake_result = SyncResult(
            success=True, rounds=42, elapsed_seconds=0.1,
            final_fingerprint="aabbcc",
        )
        link.on_sync_complete(fake_result, "aa:bb:cc:dd")
        time.sleep(0.05)  # let the background socketio.emit settle

        client.get_received()  # flush hello / sync_complete replays

        # IDS is in "alerting" state (mock's first current_state() call).
        # demo_stop_attacks reads state before reset → sees alerting → emits
        # threat_cleared.
        client.emit("demo_stop_attacks")

        cleared_events = _drain_until(client, "threat_cleared", timeout=3.0)
        cleared_ev = _find(cleared_events, "threat_cleared")
        self.assertIsNotNone(
            cleared_ev, "threat_cleared was not emitted after demo_stop_attacks"
        )
        payload = cleared_ev["args"][0]
        self.assertEqual(payload["previously_alerting_type"], "mitm")
        self.assertIsNotNone(payload["timestamp"])

    def test_threat_cleared_clears_stored_alert_state(self):
        """After threat_cleared, a reconnecting client must not see the banner."""
        mock_ids = self._make_alerting_ids()

        with patch.object(app_module, "_LiveIDS_cls") as MockCls:
            MockCls.return_value = mock_ids
            flask_app, sio = app_module.create_app("alice")
        flask_app.config["TESTING"] = True

        client = sio.test_client(flask_app)
        client.connect()
        link = self._capture_link(client)

        fake_result = SyncResult(
            success=True, rounds=1, elapsed_seconds=0.0,
            final_fingerprint="aabbcc",
        )
        link.on_sync_complete(fake_result, "aa:bb:cc:dd")
        time.sleep(0.05)
        client.get_received()

        # Fire demo_stop_attacks → threat_cleared → ids_last_alert cleared.
        client.emit("demo_stop_attacks")
        _drain_until(client, "threat_cleared", timeout=3.0)

        # A second client connecting NOW should NOT receive threat_alert
        # in its connect-time state replay (ids_last_alert was cleared).
        client2 = sio.test_client(flask_app)
        client2.connect()
        reconnect_events = client2.get_received()
        self.assertNotIn(
            "threat_alert",
            _event_names(reconnect_events),
            "Reconnecting client should not receive a stale threat_alert banner",
        )


if __name__ == "__main__":
    unittest.main()
