"""Runtime admission under a reviewed policy (§25.8.3)."""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SDK_DIR = os.path.dirname(HERE)
sys.path.insert(0, SDK_DIR)

from ccp import (  # noqa: E402
    AdmissionRequest,
    Grant,
    SigningKey,
    build_admission_policy,
    verify_admission_policy,
)
from world import NOW, build_world, signal_for  # noqa: E402

HOST = SigningKey.from_seed(bytes(range(96, 128)))
ISSUED = "2026-10-22T00:00:00Z"
UNTIL = "2027-01-01T00:00:00Z"

RULE = {
    "id": "r-read",
    "contacts": ["c-1"],
    "intents": ["example.lookup"],
    "risk": "read",
    "limits": {"calls_per_hour": 5},
    "confirmation": "none",
    "expires_at": UNTIL,
}


def policy():
    document = build_admission_policy({
        "version": 1,
        "default": "confirm",
        "rules": [dict(RULE)],
        "issued_at": ISSUED,
        "expires_at": UNTIL,
    }, HOST)
    return verify_admission_policy(document, now=NOW)


def request(world, **overrides):
    values = {
        "requester_key": world["requester"].key_id,
        "contact_id": "c-1",
        "intent": "example.lookup",
        "risk": "read",
        "now": NOW,
    }
    values.update(overrides)
    return AdmissionRequest(**values)


class AdmitRequestTests(unittest.TestCase):
    def test_creates_a_least_authority_grant_and_records_the_rule(self):
        world = build_world()
        runtime = world["runtime"]
        outcome = runtime.admit_request(policy(), request(world),
                                        world["manifest"])
        grant = outcome.grant

        self.assertEqual(outcome.result.decision, "allow")
        self.assertEqual(outcome.result.rule_id, "r-read")
        self.assertRegex(grant.id, r"^pg-[0-9a-f]{32}$")
        self.assertEqual(grant.requester_key, world["requester"].key_id)
        self.assertEqual(grant.contact_id, "c-1")
        self.assertEqual(grant.intents, ["example.lookup"])
        self.assertEqual(grant.limits, {"calls_per_hour": 5})
        self.assertEqual(grant.confirmation, {"example.lookup": "none"})

        admitted = [event for event in runtime.audit.events()
                    if event["event"] == "admitted"]
        self.assertEqual(admitted[0]["rule_id"], "r-read")
        self.assertEqual(admitted[0]["grant_id"], grant.id)

    def test_reuses_the_deterministic_grant(self):
        world = build_world()
        runtime = world["runtime"]
        first = runtime.admit_request(policy(), request(world),
                                      world["manifest"])
        second = runtime.admit_request(policy(), request(world),
                                       world["manifest"])
        self.assertEqual(second.grant.id, first.grant.id)
        self.assertEqual(second.grant.created_at, first.grant.created_at)
        self.assertEqual(
            len([g for g in runtime.grants.all() if g.id == first.grant.id]),
            1)

    def test_refuses_to_recreate_a_revoked_grant(self):
        world = build_world()
        runtime = world["runtime"]
        first = runtime.admit_request(policy(), request(world),
                                      world["manifest"])
        runtime.revoke_grant(first.grant.id, "user asked")

        again = runtime.admit_request(policy(), request(world),
                                      world["manifest"])
        self.assertEqual(again.result.decision, "deny")
        self.assertEqual(again.result.reason, "grant_revoked")
        self.assertIsNone(again.grant)

    def test_does_not_create_a_grant_when_the_user_must_decide(self):
        world = build_world()
        outcome = world["runtime"].admit_request(
            policy(), request(world, contact_id="c-other"), world["manifest"])
        self.assertEqual(outcome.result.decision, "confirm")
        self.assertIsNone(outcome.grant)

    def test_the_admitted_grant_authorizes_the_request(self):
        world = build_world()
        runtime = world["runtime"]
        runtime.grants.remove("g-1")
        outcome = runtime.admit_request(policy(), request(world),
                                        world["manifest"])

        decision = runtime.submit(signal_for(world),
                                  world["requester"].verifying_key())
        self.assertTrue(decision.authorized)
        self.assertEqual(runtime.limits.counters(outcome.grant.id),
                         {"calls_per_hour": 1})

    def test_resolves_the_grant_that_enables_the_intent(self):
        world = build_world()
        runtime = world["runtime"]
        runtime.grants.remove("g-1")
        base = dict(world["grant"].to_dict())
        # Insertion order puts the unusable grant first.
        runtime.grants.add(Grant(**dict(base, id="g-other",
                                        intents=["other.intent"])))
        runtime.grants.add(Grant(**dict(base, id="g-good")))

        decision = runtime.submit(signal_for(world),
                                  world["requester"].verifying_key())
        self.assertTrue(decision.authorized)
        self.assertEqual(runtime.limits.counters("g-good"),
                         {"calls_per_hour": 1})


if __name__ == "__main__":
    unittest.main()
