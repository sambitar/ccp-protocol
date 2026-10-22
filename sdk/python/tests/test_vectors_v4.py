"""Run the SDK against the v4 conformance vectors (§25.8)."""

import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SDK_DIR = os.path.dirname(HERE)
ROOT_DIR = os.path.dirname(os.path.dirname(SDK_DIR))
sys.path.insert(0, SDK_DIR)

from ccp.identity import (  # noqa: E402
    AdmissionRequest,
    IdentityError,
    admit,
    verify_admission_policy,
    verify_identity_document,
)

VECTOR_DIR = os.path.join(ROOT_DIR, "test-vectors", "v4")


def load(name):
    with open(os.path.join(VECTOR_DIR, name), encoding="utf-8") as handle:
        return json.load(handle)


DATA = load("identity.json")


def code(run):
    try:
        run()
        return "valid"
    except IdentityError as exc:
        return exc.code


class IdentityVectors(unittest.TestCase):
    def test_identities(self):
        for vector in DATA["identities"]:
            with self.subTest(vector=vector["id"]):
                got = code(lambda: verify_identity_document(
                    vector["document"],
                    now=vector["now"],
                    expected_identity=vector.get("expected_identity"),
                    manifest_digest=vector.get("manifest_digest"),
                    policy_digest=vector.get("policy_digest"),
                ))
                self.assertEqual(got, vector["expected"])


class PolicyVectors(unittest.TestCase):
    def test_policies(self):
        for vector in DATA["policies"]:
            with self.subTest(vector=vector["id"]):
                got = code(lambda: verify_admission_policy(
                    vector["document"],
                    now=vector["now"],
                    expected_host=vector.get("expected_host"),
                ))
                self.assertEqual(got, vector["expected"])


class AdmissionVectors(unittest.TestCase):
    def test_admissions(self):
        for vector in DATA["admissions"]:
            with self.subTest(vector=vector["id"]):
                policy = verify_admission_policy(vector["policy"],
                                                 now=vector["verify_now"])
                request = vector["request"]
                result = admit(policy, AdmissionRequest(
                    requester_key=request["requester_key"],
                    contact_id=request["contact_id"],
                    intent=request["intent"],
                    risk=request["risk"],
                    now=request["now"],
                    destination=request.get("destination"),
                ), revoked=set(vector.get("revoked", [])))
                self.assertEqual(result.decision, vector["expected"])
                if "expected_rule" in vector:
                    self.assertEqual(result.rule_id, vector["expected_rule"])
                if "expected_reason" in vector:
                    self.assertEqual(result.reason, vector["expected_reason"])


if __name__ == "__main__":
    unittest.main()
