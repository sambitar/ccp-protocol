"""End-to-end runtime scenarios."""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SDK_DIR = os.path.dirname(HERE)
sys.path.insert(0, SDK_DIR)

from ccp import SigningKey  # noqa: E402
from world import STORE, build_world, signal_for  # noqa: E402


class RuntimeTests(unittest.TestCase):
    def submit(self, world, document):
        return world["runtime"].submit(document,
                                       world["requester"].verifying_key())

    def test_authorized(self):
        world = build_world()
        decision = self.submit(world, signal_for(world))
        self.assertTrue(decision.authorized)
        self.assertEqual(decision.result, STORE["item-123"])
        self.assertEqual(world["runtime"].limits.counters("g-1"),
                         {"calls_per_hour": 1})
        events = [event["event"] for event in world["runtime"].audit.events()]
        self.assertIn("executing", events)
        self.assertIn("completed", events)

    def test_confirmation_approved(self):
        world = build_world(confirmation="per_action")
        first = self.submit(world, signal_for(world, request_id="req-a"))
        self.assertTrue(first.needs_confirmation)
        self.assertIsNotNone(first.pending_id)
        done = world["runtime"].confirm(first.pending_id, True)
        self.assertTrue(done.authorized)
        self.assertEqual(done.result, STORE["item-123"])

    def test_confirmation_denied(self):
        world = build_world(confirmation="per_action")
        first = self.submit(world, signal_for(world, request_id="req-a"))
        self.assertTrue(first.needs_confirmation)
        denied = world["runtime"].confirm(first.pending_id, False)
        self.assertEqual(denied.outcome, "cancelled")
        self.assertEqual(world["runtime"].limits.counters("g-1"),
                         {"calls_per_hour": 0})

    def test_replay(self):
        world = build_world()
        document = signal_for(world)
        self.assertTrue(self.submit(world, document).authorized)
        self.assertEqual(self.submit(world, document).error,
                         "replay_detected")

    def test_limit(self):
        world = build_world(limits={"calls_per_hour": 1})
        self.assertTrue(self.submit(world, signal_for(world, request_id="r1")).authorized)
        blocked = self.submit(world, signal_for(world, request_id="r2"))
        self.assertEqual(blocked.error, "limit_exceeded")

    def test_bad_signature(self):
        world = build_world()
        stranger = SigningKey.generate()
        document = signal_for(world, signer=stranger)
        self.assertEqual(self.submit(world, document).error, "unauthenticated")

    def test_no_grant(self):
        world = build_world()
        stranger = SigningKey.generate()
        document = signal_for(world, signer=stranger)
        decision = world["runtime"].submit(document, stranger.verifying_key())
        self.assertEqual(decision.error, "no_matching_grant")

    def test_revoked(self):
        world = build_world()
        world["grant"].revoke()
        self.assertEqual(self.submit(world, signal_for(world)).error,
                         "grant_revoked")

    def test_expired(self):
        world = build_world(expires_at="2026-10-22T11:00:00Z")
        self.assertEqual(self.submit(world, signal_for(world)).error,
                         "grant_expired")

    def test_invalid_params(self):
        world = build_world()
        self.assertEqual(self.submit(world, signal_for(world, params={})).error,
                         "invalid_request")

    def test_capability_unavailable(self):
        world = build_world(capabilities=[])
        self.assertEqual(self.submit(world, signal_for(world)).error,
                         "capability_unavailable")

    def test_protocol_mismatch(self):
        world = build_world()
        document = signal_for(world, ccp="0.2-draft")
        self.assertEqual(self.submit(world, document).error, "invalid_request")

    def test_malformed(self):
        world = build_world()
        self.assertEqual(self.submit(world, "not json").error,
                         "invalid_request")

    def test_pause_and_resume(self):
        world = build_world()
        world["grant"].pause()
        self.assertEqual(self.submit(world, signal_for(world, request_id="p1")).error,
                         "grant_paused")
        world["grant"].resume()
        self.assertTrue(self.submit(world, signal_for(world, request_id="p2")).authorized)

    def test_confirm_rechecks_grant_state(self):
        world = build_world(confirmation="per_action")
        first = self.submit(world, signal_for(world, request_id="req-a"))
        self.assertTrue(first.needs_confirmation)
        world["grant"].revoke()
        decision = world["runtime"].confirm(first.pending_id, True)
        self.assertEqual(decision.error, "grant_revoked")


if __name__ == "__main__":
    unittest.main()
