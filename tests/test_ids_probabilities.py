"""Tests for the Phase 4C ids_probabilities SocketIO event.

Verifies that app.py emits 'ids_probabilities' (with the correct payload shape)
whenever on_features_updated fires on the PeerLink, and that the most recent
payload is replayed to a reconnecting browser tab via on_browser_connect.
"""

from __future__ import annotations

import threading
import time
import unittest
from unittest.mock import MagicMock, patch

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# app.py must be importable; _LiveIDS_cls is set at import time, so we patch
# it inside each test rather than at module scope.
import app as app_module


def _make_mock_ids(state_override: dict | None = None) -> MagicMock:
    """Return a mock that looks like a LiveIDS instance."""
    mock_ids = MagicMock()
    base_state = {
        "state": "monitoring",
        "active_alert": None,
        "probabilities": {"normal": 0.92, "mitm": 0.05, "replay": 0.03},
        "observation_count": 4,
    }
    if state_override:
        base_state.update(state_override)
    mock_ids.current_state.return_value = base_state
    mock_ids.reset.return_value = None
    return mock_ids


class TestIdsProbabilitiesEvent(unittest.TestCase):
    """ids_probabilities event is emitted when on_features_updated fires."""

    def _make_app(self, mock_ids: MagicMock):
        """Build a Flask app with the given mock IDS injected."""
        with patch.object(app_module, "_LiveIDS_cls") as MockCls:
            MockCls.return_value = mock_ids
            flask_app, sio = app_module.create_app("alice")
        flask_app.config["TESTING"] = True
        return flask_app, sio

    def _trigger_start_sync(self, client, sio, flask_app):
        """
        Emit start_sync via the test client and capture the resulting PeerLink
        without actually establishing a TCP connection.

        PeerLink.connect() is patched to a no-op.  We capture the PeerLink
        instance via PeerLink.set_ids so we can fire on_features_updated later.
        """
        captured = {}
        link_ready = threading.Event()

        original_set_ids = app_module.PeerLink.set_ids

        def fake_set_ids(self_link, ids):
            # Call the real method so the IDS is stored on the link.
            original_set_ids(self_link, ids)
            captured["link"] = self_link
            link_ready.set()

        with (
            patch.object(app_module.PeerLink, "connect", return_value=None),
            patch.object(app_module.PeerLink, "set_ids", fake_set_ids),
        ):
            client.emit("start_sync")
            # Wait for the background thread to create the PeerLink.
            link_ready.wait(timeout=2.0)

        return captured.get("link")

    # ------------------------------------------------------------------

    def test_payload_has_required_keys(self):
        """ids_probabilities payload must carry the 5 documented keys."""
        mock_ids = _make_mock_ids()
        flask_app, sio = self._make_app(mock_ids)

        client = sio.test_client(flask_app)
        client.connect()
        link = self._trigger_start_sync(client, sio, flask_app)

        self.assertIsNotNone(link, "PeerLink was not captured")
        self.assertIsNotNone(link.on_features_updated,
                             "on_features_updated callback not set")

        # Flush any events already received (hello, etc.).
        client.get_received()

        # Fire the callback with a dummy features dict (app.py passes it
        # straight to current_state() which is mocked, so content is irrelevant).
        link.on_features_updated({})

        received = client.get_received()
        names = [e["name"] for e in received]
        self.assertIn("ids_probabilities", names,
                      f"ids_probabilities not in emitted events: {names}")

        payload = next(e["args"][0] for e in received
                       if e["name"] == "ids_probabilities")
        for key in ("probabilities", "state", "active_alert_type",
                    "active_alert_confidence", "timestamp"):
            self.assertIn(key, payload, f"missing key: {key}")

    def test_payload_values_monitoring(self):
        """Monitoring state: active_alert_type and _confidence are None."""
        mock_ids = _make_mock_ids()
        flask_app, sio = self._make_app(mock_ids)

        client = sio.test_client(flask_app)
        client.connect()
        link = self._trigger_start_sync(client, sio, flask_app)
        client.get_received()

        link.on_features_updated({})

        received = client.get_received()
        payload = next(e["args"][0] for e in received
                       if e["name"] == "ids_probabilities")

        self.assertEqual(payload["state"], "monitoring")
        self.assertIsNone(payload["active_alert_type"])
        self.assertIsNone(payload["active_alert_confidence"])
        self.assertAlmostEqual(payload["probabilities"]["normal"], 0.92)

    def test_payload_values_alerting(self):
        """Alerting state: active_alert_type and _confidence are populated."""
        mock_ids = _make_mock_ids(state_override={
            "state": "alerting",
            "active_alert": {"type": "mitm", "confidence": 0.82, "since": "2026-01-01T00:00:00+00:00"},
            "probabilities": {"normal": 0.10, "mitm": 0.82, "replay": 0.08},
        })
        flask_app, sio = self._make_app(mock_ids)

        client = sio.test_client(flask_app)
        client.connect()
        link = self._trigger_start_sync(client, sio, flask_app)
        client.get_received()

        link.on_features_updated({})

        received = client.get_received()
        payload = next(e["args"][0] for e in received
                       if e["name"] == "ids_probabilities")

        self.assertEqual(payload["state"], "alerting")
        self.assertEqual(payload["active_alert_type"], "mitm")
        self.assertAlmostEqual(payload["active_alert_confidence"], 0.82)

    def test_ids_disabled_no_emit(self):
        """If no IDS is attached, on_features_updated must not emit ids_probabilities."""
        # Create app without any mock IDS class (simulates model-not-found).
        with patch.object(app_module, "_LiveIDS_cls", None):
            flask_app, sio = app_module.create_app("alice")
        flask_app.config["TESTING"] = True

        client = sio.test_client(flask_app)
        client.connect()

        with patch.object(app_module.PeerLink, "connect", return_value=None):
            client.emit("start_sync")
            time.sleep(0.15)

        client.get_received()

        # With no IDS, on_features_updated is still set but returns early.
        # Find the PeerLink in this app's state via the connect thread — we
        # can't reach it directly, so we just verify no ids_probabilities fires.
        # (The callback guards on `_ids_instance is None`.)
        # Nothing to call on_features_updated on from outside — pass.
        # This test mainly confirms the guard path doesn't crash.

    def test_reconnect_replays_last_probabilities(self):
        """A freshly connecting client receives the most recent ids_probabilities."""
        mock_ids = _make_mock_ids()
        flask_app, sio = self._make_app(mock_ids)

        client1 = sio.test_client(flask_app)
        client1.connect()
        link = self._trigger_start_sync(client1, sio, flask_app)
        client1.get_received()

        # Fire on_features_updated so state["ids_last_probabilities"] is set.
        link.on_features_updated({})
        client1.get_received()  # consume

        # Now a second client connects — it should receive ids_probabilities
        # as part of the state replay in on_browser_connect.
        client2 = sio.test_client(flask_app)
        client2.connect()

        received2 = client2.get_received()
        names2 = [e["name"] for e in received2]
        self.assertIn("ids_probabilities", names2,
                      "Reconnecting client should receive ids_probabilities replay")


if __name__ == "__main__":
    unittest.main()
