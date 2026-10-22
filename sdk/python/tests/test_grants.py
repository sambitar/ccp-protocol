"""Least-authority grant construction (§9.1, §9.2, §26.1)."""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SDK_DIR = os.path.dirname(HERE)
sys.path.insert(0, SDK_DIR)

from ccp import CCPError, create_grant  # noqa: E402
from world import build_world  # noqa: E402


class CreateGrantTests(unittest.TestCase):
    def setUp(self):
        self.world = build_world()
        self.kwargs = {
            "contact_id": "c-1",
            "requester_key": self.world["requester"].key_id,
            "manifest": self.world["manifest"],
            "intents": ["example.lookup"],
            "created_at": "2026-10-22T12:00:00Z",
            "expires_at": "2026-10-22T23:00:00Z",
        }

    def test_derives_least_authority_from_the_manifest(self):
        grant = create_grant(**self.kwargs)
        self.assertEqual(grant.limits, {"calls_per_hour": 10})
        self.assertEqual(grant.capabilities, ["store.read"])
        self.assertEqual(grant.placement, ["local"])
        self.assertEqual(grant.egress, {"network": False, "fields": []})
        self.assertEqual(grant.confirmation,
                         {"example.lookup": "per_action"})
        self.assertEqual(grant.state, "active")
        self.assertTrue(grant.id)

    def test_rejects_a_limit_above_the_suggestion(self):
        with self.assertRaises(CCPError) as caught:
            create_grant(**self.kwargs, limits={"calls_per_hour": 11})
        self.assertEqual(caught.exception.code, "invalid_request")

    def test_rejects_an_unknown_intent(self):
        with self.assertRaises(CCPError) as caught:
            create_grant(**dict(self.kwargs, intents=["other.intent"]))
        self.assertEqual(caught.exception.code, "intent_not_allowed")

    def test_rejects_unnecessary_capabilities(self):
        with self.assertRaises(CCPError) as caught:
            create_grant(**self.kwargs,
                         capabilities=["store.read", "net.request"])
        self.assertEqual(caught.exception.code, "invalid_request")

    def test_rejects_undeclared_egress(self):
        with self.assertRaises(CCPError) as caught:
            create_grant(**self.kwargs, egress={"network": True})
        self.assertEqual(caught.exception.code, "invalid_request")

    def test_confirmation_cannot_relax_without_a_policy(self):
        with self.assertRaises(CCPError) as caught:
            create_grant(**self.kwargs,
                         confirmation={"example.lookup": "none"})
        self.assertEqual(caught.exception.code, "invalid_request")

    def test_an_admitted_grant_may_suppress_confirmation(self):
        grant = create_grant(
            **self.kwargs,
            confirmation={"example.lookup": "none"},
            admitted_by="r-read")
        self.assertEqual(grant.confirmation, {"example.lookup": "none"})

    def test_rejects_expiry_before_creation(self):
        with self.assertRaises(CCPError) as caught:
            create_grant(**dict(self.kwargs,
                                expires_at="2026-10-22T11:00:00Z"))
        self.assertEqual(caught.exception.code, "invalid_request")

    def test_rejects_a_non_active_state_without_a_reason(self):
        with self.assertRaises(CCPError) as caught:
            create_grant(**self.kwargs, state="paused")
        self.assertEqual(caught.exception.code, "invalid_request")


if __name__ == "__main__":
    unittest.main()
