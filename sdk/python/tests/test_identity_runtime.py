"""Identity verification wired to grant suspension (§7.4)."""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SDK_DIR = os.path.dirname(HERE)
sys.path.insert(0, SDK_DIR)

from ccp import (  # noqa: E402
    IDENTITY_CHANGED_REASON,
    IdentityError,
    SigningKey,
    build_identity_document,
)
from world import NOW, build_world, signal_for  # noqa: E402

OTHER = SigningKey.from_seed(bytes(range(96, 128)))
ISSUED = "2026-10-22T00:00:00Z"
UNTIL = "2027-10-22T00:00:00Z"


def document(key):
    return build_identity_document(
        {"name": "Peer", "issued_at": ISSUED, "expires_at": UNTIL}, key)


class ContactIdentityTests(unittest.TestCase):
    def test_matching_document_leaves_grants_alone(self):
        world = build_world()
        verified = world["runtime"].verify_contact_identity(
            document(world["requester"]),
            contact_id="c-1",
            expected_identity=world["requester"].key_id,
            now=NOW,
        )
        self.assertEqual(verified.identity, world["requester"].key_id)
        self.assertEqual(world["runtime"].grants.get("g-1").state, "active")

    def test_key_change_suspends_the_contact_grants(self):
        world = build_world()
        runtime = world["runtime"]

        with self.assertRaises(IdentityError) as caught:
            runtime.verify_contact_identity(
                document(OTHER),
                contact_id="c-1",
                expected_identity=world["requester"].key_id,
                now=NOW,
            )
        self.assertEqual(caught.exception.code, "identity_changed")

        grant = runtime.grants.get("g-1")
        self.assertEqual(grant.state, "suspended")
        self.assertEqual(grant.state_reason, IDENTITY_CHANGED_REASON)

        events = [event["event"] for event in runtime.audit.events()]
        self.assertIn("identity_changed", events)

        decision = runtime.submit(signal_for(world),
                                  world["requester"].verifying_key())
        self.assertEqual(decision.error, "grant_suspended")

    def test_a_key_change_cannot_be_resumed_in_one_click(self):
        world = build_world()
        runtime = world["runtime"]
        with self.assertRaises(IdentityError):
            runtime.verify_contact_identity(
                document(OTHER),
                contact_id="c-1",
                expected_identity=world["requester"].key_id,
                now=NOW,
            )
        with self.assertRaises(Exception) as caught:
            runtime.resume_grant("g-1")
        self.assertEqual(getattr(caught.exception, "code", None),
                         "grant_suspended")

    def test_a_forged_document_never_suspends(self):
        world = build_world()
        runtime = world["runtime"]
        forged = document(world["requester"]).replace("Peer", "Evil")

        with self.assertRaises(IdentityError) as caught:
            runtime.verify_contact_identity(
                forged,
                contact_id="c-1",
                expected_identity=world["requester"].key_id,
                now=NOW,
            )
        self.assertEqual(caught.exception.code, "unauthenticated")
        self.assertEqual(runtime.grants.get("g-1").state, "active")

    def test_a_manual_suspend_can_resume(self):
        world = build_world()
        runtime = world["runtime"]
        runtime.suspend_grant("g-1", "manual review")
        self.assertEqual(runtime.resume_grant("g-1").state, "active")


if __name__ == "__main__":
    unittest.main()
