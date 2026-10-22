"""Requester, consumer, and agent role surfaces."""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SDK_DIR = os.path.dirname(HERE)
sys.path.insert(0, SDK_DIR)

from ccp import CCPError, Grant, SigningKey  # noqa: E402
from ccp.agent import Agent, attenuates  # noqa: E402
from ccp.consumer import (  # noqa: E402
    permission_card,
    verify_manifest,
    verify_signal,
)
from ccp.requester import Requester, build_manifest, build_signal  # noqa: E402

INTENTS = {
    "example.lookup": {
        "description": "Look up one item requested by the consumer",
        "params_schema": "schema:example.lookup.params.v1",
        "result_schema": "schema:example.lookup.result.v1",
        "required_capabilities": ["store.read"],
        "placement": "local",
        "data_egress": {"network": False, "fields": []},
        "suggested_limits": {"calls_per_hour": 10},
        "confirmation": "grant-policy",
    }
}


def make_grant(**overrides):
    values = {
        "id": "g",
        "requester_key": "key:ed25519:x",
        "contact_id": "c",
        "manifest_digest": "sha256:abc",
        "manifest_version": 1,
        "intents": ["example.lookup", "files.search"],
        "limits": {"calls_per_hour": 10},
        "created_at": "2026-10-22T10:00:00Z",
        "expires_at": "2026-10-22T23:00:00Z",
        "confirmation": {
            "example.lookup": "per_action",
            "files.search": "none",
        },
        "capabilities": ["store.read", "files.read"],
        "placement": ["local"],
        "egress": {"network": False, "fields": []},
    }
    values.update(overrides)
    return Grant(**values)


class RoleTestCase(unittest.TestCase):
    def setUp(self):
        self.provider = SigningKey.from_seed(bytes(range(32)))
        self.requester_key = SigningKey.from_seed(bytes(range(32, 64)))
        self.provider_requester = Requester(self.provider)
        self.requester = Requester(self.requester_key)
        self.manifest_wire = self.provider_requester.manifest(
            {"id": self.provider.key_id, "name": "Example Service"}, 1, INTENTS
        )
        self.manifest = verify_manifest(self.manifest_wire)

    def signal_wire(self, **overrides):
        values = {
            "request_id": "req-1",
            "grant_digest": self.manifest.digest,
            "intent": "example.lookup",
            "params": {"item_id": "item-123"},
            "issued_at": "2026-10-22T12:00:00Z",
            "expires_at": "2026-10-22T12:01:00Z",
        }
        values.update(overrides)
        return self.requester.signal(**values)


class RequesterTests(RoleTestCase):
    def test_manifest_round_trip(self):
        manifest = verify_manifest(self.manifest_wire)
        self.assertEqual(manifest.provider_name, "Example Service")
        self.assertEqual(manifest.version, 1)
        self.assertIn("example.lookup", manifest.intents)

    def test_manifest_requires_provider_id(self):
        with self.assertRaises(CCPError) as caught:
            build_manifest({}, 1, INTENTS)
        self.assertEqual(caught.exception.code, "invalid_request")

    def test_signal_round_trip(self):
        signal = verify_signal(self.signal_wire(),
                               self.requester_key.verifying_key())
        self.assertEqual(signal.request_id, "req-1")
        self.assertEqual(signal.intent, "example.lookup")
        self.assertEqual(signal.params, {"item_id": "item-123"})
        self.assertEqual(signal.data["grant_digest"], self.manifest.digest)

    def test_build_signal_defaults(self):
        built = build_signal("r1", "sha256:x", "example.lookup",
                             {"item_id": "x"}, "a", "b")
        self.assertEqual(built["ccp"], "0.5-draft")
        self.assertNotIn("signature", built)


class ConsumerTests(RoleTestCase):
    def test_verify_manifest_rejects_wrong_provider(self):
        with self.assertRaises(CCPError) as caught:
            verify_manifest(self.manifest_wire, "key:ed25519:AAAA")
        self.assertEqual(caught.exception.code, "unauthenticated")

    def test_verify_signal_rejects_tampered_params(self):
        tampered = self.signal_wire().replace('"item-123"', '"item-999"')
        with self.assertRaises(CCPError) as caught:
            verify_signal(tampered, self.requester_key.verifying_key())
        self.assertEqual(caught.exception.code, "unauthenticated")

    def test_card_for_local_intent(self):
        card = permission_card(self.manifest, "example.lookup")
        self.assertEqual(card.who, "Example Service")
        self.assertEqual(card.what,
                         "Look up one item requested by the consumer")
        self.assertEqual(card.data_read, ["store.read"])
        self.assertEqual(card.where, "on this device")
        self.assertEqual(card.egress,
                         "does not send data off the device")
        self.assertEqual(card.recurrence, "applies once")
        self.assertEqual(card.to_dict()["who"], "Example Service")

    def test_card_for_remote_intent(self):
        intents = {
            "remote.read": {
                "description": "Read a remote record",
                "params_schema": "s",
                "result_schema": "r",
                "required_capabilities": [],
                "placement": "remote",
                "data_egress": {"network": True, "fields": ["item_id"]},
            }
        }
        wire = self.provider_requester.manifest(
            {"id": self.provider.key_id}, 1, intents)
        card = permission_card(verify_manifest(wire), "remote.read")
        self.assertEqual(card.where, "via remote")
        self.assertEqual(card.egress,
                         "sends item_id to a remote endpoint")

    def test_card_rejects_unknown_intent(self):
        with self.assertRaises(CCPError) as caught:
            permission_card(self.manifest, "nope")
        self.assertEqual(caught.exception.code, "intent_not_allowed")


class AgentTests(RoleTestCase):
    def test_agent_signal_binds_the_grant(self):
        agent = Agent(self.requester_key)
        grant = make_grant(requester_key=agent.key_id,
                           manifest_digest=self.manifest.digest)
        wire = agent.signal_for(
            intent="example.lookup",
            params={"item_id": "item-123"},
            grant=grant,
            request_id="req-a",
            issued_at="2026-10-22T12:00:00Z",
            expires_at="2026-10-22T12:01:00Z",
        )
        signal = verify_signal(wire, agent.verifying_key)
        self.assertEqual(signal.data["grant_digest"], self.manifest.digest)
        self.assertEqual(signal.intent, "example.lookup")

    def test_agent_exposes_its_identity(self):
        agent = Agent(self.requester_key)
        self.assertEqual(agent.key_id, self.requester_key.key_id)
        self.assertEqual(agent.verifying_key.key_id, agent.key_id)


class AttenuationTests(unittest.TestCase):
    def test_accepts_a_narrower_child(self):
        child = make_grant(
            intents=["example.lookup"],
            limits={"calls_per_hour": 5},
            expires_at="2026-10-22T20:00:00Z",
            capabilities=["store.read"],
        )
        self.assertTrue(attenuates(make_grant(), child))

    def test_rejects_wider_intents(self):
        parent = make_grant(intents=["example.lookup"])
        child = make_grant(intents=["example.lookup", "files.search"])
        self.assertFalse(attenuates(parent, child))

    def test_rejects_wider_limits(self):
        self.assertFalse(
            attenuates(make_grant(),
                       make_grant(limits={"calls_per_hour": 20})))

    def test_rejects_a_longer_expiry(self):
        self.assertFalse(
            attenuates(make_grant(),
                       make_grant(expires_at="2026-10-24T00:00:00Z")))

    def test_rejects_weaker_confirmation(self):
        parent = make_grant(confirmation={"example.lookup": "per_action"})
        child = make_grant(confirmation={"example.lookup": "none"})
        self.assertFalse(attenuates(parent, child))

    def test_rejects_broader_egress(self):
        self.assertFalse(
            attenuates(make_grant(),
                       make_grant(egress={"network": True, "fields": []})))


if __name__ == "__main__":
    unittest.main()
