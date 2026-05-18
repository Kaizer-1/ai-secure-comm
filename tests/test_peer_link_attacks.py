"""End-to-end PeerLink tests with attack registry hooks active.

These tests run two real PeerLinks on 127.0.0.1 and validate the
post-Phase-3 contract:

* MITM tampering surfaces as `on_chat_decryption_failed` callbacks
  (and a corresponding rise in `feature_extractor.decrypt_failure_rate`),
  NOT as generic `on_error` events.

* Replay attacks decrypt successfully on the receiver — the spec
  says replays must produce visible duplicate chat messages so the
  IDS layer can flag them as `duplicate_payload_count` anomalies.
  The AEAD layer no longer rejects them, because the AAD is
  kind-only (no per-direction sequence number).
"""

from __future__ import annotations

import socket
import threading
import time
import unittest

import config
from attacks.mitm import MITMAttack
from attacks.replay import ReplayAttack
from core.peer_link import PeerLink


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _run_pair(port: int) -> tuple[PeerLink, PeerLink]:
    alice = PeerLink(
        role=config.ROLE_A,
        bind_host="127.0.0.1", peer_host="127.0.0.1",
        peer_port=port, initiator_role=config.ROLE_A,
        connect_timeout=5.0,
    )
    bob = PeerLink(
        role=config.ROLE_B,
        bind_host="127.0.0.1", peer_host="127.0.0.1",
        peer_port=port, initiator_role=config.ROLE_A,
        connect_timeout=5.0,
    )
    ta = threading.Thread(target=alice.connect, daemon=True)
    tb = threading.Thread(target=bob.connect, daemon=True)
    ta.start(); time.sleep(0.05); tb.start()
    if not alice.wait_for_sync(timeout=15.0):
        alice.close(); bob.close()
        raise RuntimeError("alice failed to sync")
    if not bob.wait_for_sync(timeout=15.0):
        alice.close(); bob.close()
        raise RuntimeError("bob failed to sync")
    ta.join(timeout=5.0); tb.join(timeout=5.0)
    return alice, bob


class TestMITMSurfacesAsDecryptionFailedCallback(unittest.TestCase):
    def test_tampered_chat_fires_on_chat_decryption_failed_not_on_error(self):
        port = _free_port()
        alice = bob = None
        try:
            alice, bob = _run_pair(port)

            received_ok: list = []
            decrypt_failed: list = []
            generic_errors: list = []

            bob.on_chat_received = lambda pt, bundle: received_ok.append(pt)
            bob.on_chat_decryption_failed = (
                lambda bundle: decrypt_failed.append(bundle)
            )
            bob.on_error = lambda exc: generic_errors.append(repr(exc))

            # 100% tamper rate so we know every CHAT must fail.
            mitm = MITMAttack(tamper_probability=1.0,
                              flip_bits_per_frame=1, rng_seed=1)
            alice.attack_registry.register(mitm)
            mitm.start()

            n_msgs = 8
            for i in range(n_msgs):
                alice.send_chat(f"msg-{i}")
                time.sleep(0.02)
            time.sleep(0.4)

            # All CHAT decrypts must have failed AS DECRYPTION FAILURES
            # (specifically — not as generic on_error events).
            self.assertEqual(len(received_ok), 0)
            self.assertEqual(len(decrypt_failed), n_msgs)
            self.assertEqual(len(generic_errors), 0,
                             f"unexpected on_error invocations: {generic_errors!r}")

            # FeatureExtractor reflects the failures as well.
            feats = bob.feature_extractor.extract_features()
            self.assertGreater(feats["decrypt_failure_rate"], 0.0)
        finally:
            if alice is not None: alice.close()
            if bob is not None: bob.close()


class TestReplayDecryptsSuccessfully(unittest.TestCase):
    def test_replays_decrypt_and_become_visible_duplicates(self):
        """The Phase-3 contract: replayed chat ciphertext SUCCEEDS at
        decrypt and is delivered to `on_chat_received` as a duplicate."""
        port = _free_port()
        alice = bob = None
        try:
            alice, bob = _run_pair(port)

            received: list = []
            received_event = threading.Event()
            decrypt_failed: list = []

            def on_chat(pt, bundle):
                received.append((pt, bundle))
                # We expect at least n_msgs originals + at least one
                # replay.  Set the event once we've seen at least one
                # extra delivery.
                if len(received) >= 4:
                    received_event.set()

            bob.on_chat_received = on_chat
            bob.on_chat_decryption_failed = (
                lambda bundle: decrypt_failed.append(bundle)
            )

            # Tight injection cadence so the test is fast.
            replay = ReplayAttack(buffer_size=5, interval_s=0.1, rng_seed=2)
            alice.attack_registry.register(replay)
            replay.start()

            n_msgs = 3
            for i in range(n_msgs):
                alice.send_chat(f"original-{i}")
                time.sleep(0.05)
            # Wait for at least one replay to land.
            self.assertTrue(received_event.wait(timeout=5.0),
                            "expected the replay attack to produce at least "
                            "one duplicate delivery")

            # NO decrypt failures on the receiver — replays must NOT
            # be rejected by the AEAD layer post-Phase-3.
            self.assertEqual(
                decrypt_failed, [],
                "replays must decrypt successfully; AAD must not bind a "
                "per-direction seq",
            )

            # And we must see at least one duplicate ciphertext bundle.
            bundles_seen = [bundle for (_, bundle) in received]
            unique_bundles = set(bundles_seen)
            self.assertLess(len(unique_bundles), len(bundles_seen),
                            f"no duplicate bundle found in {len(bundles_seen)} "
                            f"deliveries — replay didn't actually replay")
        finally:
            if alice is not None: alice.close()
            if bob is not None: bob.close()


if __name__ == "__main__":
    unittest.main()
