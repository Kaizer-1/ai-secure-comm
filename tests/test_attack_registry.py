"""Tests for `attacks.base.AttackRegistry`."""

from __future__ import annotations

import unittest
from typing import List, Optional, Tuple

from attacks.base import Attack, AttackRegistry


class _RecordingAttack(Attack):
    """Test stub: records every hook call; can mutate or drop."""

    def __init__(
        self,
        name: str = "rec",
        outbound_xform=None,
        inbound_xform=None,
    ) -> None:
        super().__init__()
        self.name = name
        self.outbound_calls: List[Tuple[int, bytes]] = []
        self.inbound_calls: List[Tuple[int, bytes]] = []
        self.attached_to: Optional[object] = None
        self.detached = False
        self._outbound_xform = outbound_xform
        self._inbound_xform = inbound_xform

    def attach(self, transport):
        self.attached_to = transport

    def detach(self):
        self.detached = True

    def on_outbound_frame(self, kind, payload):
        self.outbound_calls.append((kind, payload))
        return self._outbound_xform(kind, payload) if self._outbound_xform else (kind, payload)

    def on_inbound_frame(self, kind, payload):
        self.inbound_calls.append((kind, payload))
        return self._inbound_xform(kind, payload) if self._inbound_xform else (kind, payload)


class TestRegistryRegistration(unittest.TestCase):
    def test_register_calls_attach_with_transport(self):
        sentinel = object()
        reg = AttackRegistry(transport=sentinel)
        a = _RecordingAttack()
        reg.register(a)
        self.assertEqual(a.attached_to, sentinel)
        self.assertIn(a, reg.all_attacks())

    def test_register_is_idempotent(self):
        reg = AttackRegistry()
        a = _RecordingAttack()
        reg.register(a)
        reg.register(a)
        self.assertEqual(len(reg), 1)

    def test_unregister_stops_active_and_calls_detach(self):
        reg = AttackRegistry()
        a = _RecordingAttack()
        reg.register(a)
        a.start()
        self.assertTrue(a.is_active())
        reg.unregister(a)
        self.assertFalse(a.is_active())
        self.assertTrue(a.detached)
        self.assertNotIn(a, reg.all_attacks())

    def test_unregister_unknown_is_noop(self):
        reg = AttackRegistry()
        a = _RecordingAttack()
        # Not registered.  Should not raise.
        reg.unregister(a)

    def test_attach_transport_late_binding(self):
        reg = AttackRegistry()
        a = _RecordingAttack()
        reg.register(a)
        self.assertIsNone(a.attached_to)
        sentinel = object()
        reg.attach_transport(sentinel)
        self.assertEqual(reg.attached_transport(), sentinel)
        self.assertEqual(a.attached_to, sentinel)


class TestRegistryHookFiring(unittest.TestCase):
    def test_no_attacks_passes_through(self):
        reg = AttackRegistry()
        self.assertEqual(reg.apply_outbound(0x10, b"x"), (0x10, b"x"))
        self.assertEqual(reg.apply_inbound(0x10, b"x"), (0x10, b"x"))

    def test_inactive_attacks_dont_fire(self):
        reg = AttackRegistry()
        a = _RecordingAttack()
        reg.register(a)
        # Not started — should be inert.
        self.assertEqual(reg.apply_outbound(0x10, b"hello"), (0x10, b"hello"))
        self.assertEqual(a.outbound_calls, [])

    def test_active_attack_sees_frames(self):
        reg = AttackRegistry()
        a = _RecordingAttack()
        reg.register(a)
        a.start()
        reg.apply_outbound(0x10, b"hello")
        reg.apply_inbound(0x10, b"world")
        self.assertEqual(a.outbound_calls, [(0x10, b"hello")])
        self.assertEqual(a.inbound_calls, [(0x10, b"world")])

    def test_multiple_attacks_fire_in_registration_order(self):
        order: List[str] = []

        def out_a(kind, payload):
            order.append("a")
            return (kind, payload + b"-a")

        def out_b(kind, payload):
            order.append("b")
            return (kind, payload + b"-b")

        reg = AttackRegistry()
        a = _RecordingAttack(name="a", outbound_xform=out_a)
        b = _RecordingAttack(name="b", outbound_xform=out_b)
        reg.register(a); reg.register(b)
        a.start(); b.start()
        kind, payload = reg.apply_outbound(0x10, b"x")
        self.assertEqual(order, ["a", "b"])
        # b sees a's output:
        self.assertEqual(payload, b"x-a-b")

    def test_drop_short_circuits_chain(self):
        order: List[str] = []

        def out_a(kind, payload):
            order.append("a")
            return None  # drop

        def out_b(kind, payload):
            order.append("b")
            return (kind, payload)

        reg = AttackRegistry()
        a = _RecordingAttack(name="a", outbound_xform=out_a)
        b = _RecordingAttack(name="b", outbound_xform=out_b)
        reg.register(a); reg.register(b)
        a.start(); b.start()
        result = reg.apply_outbound(0x10, b"x")
        self.assertIsNone(result)
        # b's hook should NOT have run:
        self.assertEqual(order, ["a"])

    def test_hook_exception_treated_as_noop_and_chain_continues(self):
        def raises(kind, payload):
            raise RuntimeError("boom")

        order: List[str] = []

        def out_b(kind, payload):
            order.append("b")
            return (kind, payload + b"-b")

        reg = AttackRegistry()
        a = _RecordingAttack(name="a", outbound_xform=raises)
        b = _RecordingAttack(name="b", outbound_xform=out_b)
        reg.register(a); reg.register(b)
        a.start(); b.start()
        kind, payload = reg.apply_outbound(0x10, b"x")
        self.assertEqual(order, ["b"])
        self.assertEqual(payload, b"x-b")

    def test_active_attacks_filter(self):
        reg = AttackRegistry()
        a = _RecordingAttack(name="a")
        b = _RecordingAttack(name="b")
        reg.register(a); reg.register(b)
        a.start()
        active = reg.active_attacks()
        self.assertEqual([x.name for x in active], ["a"])


if __name__ == "__main__":
    unittest.main()
