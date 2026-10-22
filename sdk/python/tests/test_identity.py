"""Identity documents and admission policies (§25.8)."""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SDK_DIR = os.path.dirname(HERE)
sys.path.insert(0, SDK_DIR)

from ccp import (  # noqa: E402
    AdmissionRequest,
    IdentityError,
    SigningKey,
    admit,
    admitted_grant,
    admitted_grant_id,
    build_admission_policy,
    build_identity_document,
    identity_digest,
    policy_digest,
    verify_admission_policy,
    verify_identity_document,
)

KEY = SigningKey.from_seed(bytes(range(32)))
OTHER = SigningKey.from_seed(bytes(range(32, 64)))
IDENTITY = KEY.key_id
OTHER_IDENTITY = OTHER.key_id
NOW = "2026-10-22T12:00:00Z"
ISSUED = "2026-10-22T00:00:00Z"
UNTIL = "2027-10-22T00:00:00Z"
DIGEST = "sha256:" + "ab" * 32
OTHER_DIGEST = "sha256:" + "cd" * 32


def document(**overrides):
    claims = {
        "name": "Example Service",
        "roles": ["provider"],
        "endpoints": [{
            "transport": "https",
            "manifest": "https://example.com/manifest",
            "signal": "https://example.com/ccp",
        }],
        "manifest_digest": DIGEST,
        "policy_digest": DIGEST,
        "issued_at": ISSUED,
        "expires_at": UNTIL,
    }
    claims.update(overrides)
    return build_identity_document(claims, KEY)


READ_RULE = {
    "id": "r-read",
    "contacts": ["c-agent-1"],
    "intents": ["files.search", "calendar.read"],
    "risk": "read",
    "limits": {"calls_per_hour": 60},
    "confirmation": "none",
    "expires_at": UNTIL,
}

PAY_RULE = {
    "id": "r-pay",
    "requesters": [OTHER_IDENTITY],
    "intents": ["payment.address.resolve"],
    "risk": "disclose",
    "destinations": ["wallet:acct-9"],
    "confirmation": "none",
    "expires_at": UNTIL,
}


def policy(rules=None, **overrides):
    body = {
        "version": 1,
        "default": "confirm",
        "rules": rules if rules is not None else [dict(READ_RULE), dict(PAY_RULE)],
        "issued_at": ISSUED,
        "expires_at": UNTIL,
    }
    body.update(overrides)
    return build_admission_policy(body, KEY)


def request(**overrides):
    values = {
        "requester_key": OTHER_IDENTITY,
        "contact_id": "c-agent-1",
        "intent": "files.search",
        "risk": "read",
        "now": NOW,
    }
    values.update(overrides)
    return AdmissionRequest(**values)


class IdentityDocumentTests(unittest.TestCase):
    def test_round_trip(self):
        verified = verify_identity_document(document(), now=NOW)
        self.assertEqual(verified.identity, IDENTITY)
        self.assertEqual(verified.name, "Example Service")
        self.assertEqual(verified.roles, ["provider"])
        self.assertEqual(verified.manifest_digest, DIGEST)
        self.assertEqual(len(verified.endpoints), 1)

    def test_deterministic_and_digestible(self):
        self.assertEqual(document(), document())
        self.assertRegex(identity_digest(document()), r"^sha256:[0-9a-f]{64}$")

    def test_tampered_document(self):
        tampered = document().replace("Example Service", "Evil Service")
        with self.assertRaises(IdentityError) as caught:
            verify_identity_document(tampered, now=NOW)
        self.assertEqual(caught.exception.code, "unauthenticated")

    def test_changed_key(self):
        with self.assertRaises(IdentityError) as caught:
            verify_identity_document(
                document(), now=NOW, expected_identity=OTHER_IDENTITY)
        self.assertEqual(caught.exception.code, "identity_changed")

    def test_validity_window(self):
        for issued, expires in (
            ("2025-01-01T00:00:00Z", "2025-06-01T00:00:00Z"),
            ("2027-06-01T00:00:00Z", "2028-01-01T00:00:00Z"),
        ):
            with self.assertRaises(IdentityError) as caught:
                verify_identity_document(
                    document(issued_at=issued, expires_at=expires), now=NOW)
            self.assertEqual(caught.exception.code, "identity_expired")

    def test_clock_skew(self):
        verified = verify_identity_document(
            document(issued_at="2026-10-22T12:01:00Z"), now=NOW)
        self.assertEqual(verified.issued_at, "2026-10-22T12:01:00Z")

    def test_digest_bindings(self):
        with self.assertRaises(IdentityError) as caught:
            verify_identity_document(document(), now=NOW,
                                     manifest_digest=OTHER_DIGEST)
        self.assertEqual(caught.exception.code, "manifest_mismatch")
        with self.assertRaises(IdentityError) as caught:
            verify_identity_document(document(), now=NOW,
                                     policy_digest=OTHER_DIGEST)
        self.assertEqual(caught.exception.code, "policy_mismatch")

    def test_unknown_role(self):
        with self.assertRaises(IdentityError) as caught:
            verify_identity_document(document(roles=["provider", "admin"]),
                                     now=NOW)
        self.assertEqual(caught.exception.code, "invalid_request")


class PolicyTests(unittest.TestCase):
    def test_verifies(self):
        verified = verify_admission_policy(policy(), now=NOW,
                                           expected_host=IDENTITY)
        self.assertEqual(verified.host, IDENTITY)
        self.assertEqual(verified.version, 1)
        self.assertEqual(verified.default, "confirm")
        self.assertEqual([rule.id for rule in verified.rules], ["r-read", "r-pay"])
        self.assertEqual(policy_digest(policy()), verified.digest)

    def test_default_must_not_admit(self):
        wire = policy(**{"default": "allow"})
        with self.assertRaises(IdentityError) as caught:
            verify_admission_policy(wire, now=NOW)
        self.assertEqual(caught.exception.code, "invalid_request")

    def test_rule_must_name_a_subject(self):
        rule = dict(READ_RULE)
        del rule["contacts"]
        with self.assertRaises(IdentityError) as caught:
            verify_admission_policy(policy(rules=[rule]), now=NOW)
        self.assertEqual(caught.exception.code, "invalid_request")

    def test_write_is_not_admittable(self):
        with self.assertRaises(IdentityError) as caught:
            verify_admission_policy(policy(rules=[dict(READ_RULE, risk="write")]),
                                    now=NOW)
        self.assertEqual(caught.exception.code, "invalid_request")

    def test_disclose_needs_destinations(self):
        rule = dict(PAY_RULE)
        del rule["destinations"]
        with self.assertRaises(IdentityError) as caught:
            verify_admission_policy(policy(rules=[rule]), now=NOW)
        self.assertEqual(caught.exception.code, "invalid_request")

    def test_expired(self):
        with self.assertRaises(IdentityError) as caught:
            verify_admission_policy(policy(), now="2028-01-01T00:00:00Z")
        self.assertEqual(caught.exception.code, "policy_expired")


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.policy = verify_admission_policy(policy(), now=NOW)

    def test_matching_contact_rule(self):
        result = admit(self.policy, request())
        self.assertEqual(result.decision, "allow")
        self.assertEqual(result.reason, "rule_matched")
        self.assertEqual(result.rule_id, "r-read")
        granted = admitted_grant(self.policy, request(), result)
        self.assertEqual(granted.intent, "files.search")
        self.assertEqual(granted.limits, {"calls_per_hour": 60})
        self.assertEqual(granted.expires_at, UNTIL)
        self.assertRegex(granted.id, r"^pg-[0-9a-f]{32}$")

    def test_unknown_contact_falls_back(self):
        self.assertEqual(admit(self.policy,
                               request(contact_id="c-stranger")).decision,
                         "confirm")

    def test_write_is_denied(self):
        self.assertEqual(admit(self.policy, request(risk="write")).decision,
                         "deny")

    def test_disclose_destination(self):
        good = request(contact_id="c", intent="payment.address.resolve",
                       risk="disclose", destination="wallet:acct-9")
        bad = request(contact_id="c", intent="payment.address.resolve",
                      risk="disclose", destination="wallet:acct-1")
        self.assertEqual(admit(self.policy, good).decision, "allow")
        self.assertEqual(admit(self.policy, bad).decision, "confirm")

    def test_requester_rule_matches_by_key(self):
        result = admit(self.policy, request(
            requester_key=IDENTITY, contact_id="c",
            intent="payment.address.resolve", risk="disclose",
            destination="wallet:acct-9"))
        self.assertEqual(result.decision, "confirm")

    def test_no_grant_without_allow(self):
        result = admit(self.policy, request(contact_id="c-stranger"))
        self.assertIsNone(admitted_grant(self.policy, request(), result))

    def test_grant_id_is_deterministic(self):
        first = admitted_grant(self.policy, request(), admit(self.policy, request()))
        second = admitted_grant(self.policy, request(), admit(self.policy, request()))
        self.assertEqual(first.id, second.id)
        self.assertEqual(first.id, admitted_grant_id(self.policy, "r-read", request()))

    def test_revoked_grant_is_not_recreated(self):
        grant_id = admitted_grant_id(self.policy, "r-read", request())
        result = admit(self.policy, request(), revoked={grant_id})
        self.assertEqual(result.decision, "deny")
        self.assertEqual(result.reason, "grant_revoked")
        self.assertIsNone(admitted_grant(self.policy, request(), result))

    def test_revocation_is_scoped_to_one_rule(self):
        grant_id = admitted_grant_id(self.policy, "r-read", request())
        result = admit(self.policy, request(
            contact_id="c", intent="payment.address.resolve",
            risk="disclose", destination="wallet:acct-9"), revoked={grant_id})
        self.assertEqual(result.decision, "allow")
        self.assertEqual(result.rule_id, "r-pay")

    def test_policy_change_yields_a_new_id(self):
        amended = verify_admission_policy(
            policy(rules=[dict(READ_RULE, limits={"calls_per_hour": 30})]), now=NOW)
        self.assertNotEqual(
            admitted_grant_id(amended, "r-read", request()),
            admitted_grant_id(self.policy, "r-read", request()))


if __name__ == "__main__":
    unittest.main()
