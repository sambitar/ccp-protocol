"""Run the SDK against the frozen v2 conformance vectors."""

import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SDK_DIR = os.path.dirname(HERE)
ROOT_DIR = os.path.dirname(os.path.dirname(SDK_DIR))
sys.path.insert(0, SDK_DIR)

from ccp import canonical  # noqa: E402
from ccp.canonical import CanonicalError  # noqa: E402
from ccp.decision import decide  # noqa: E402
from ccp.model import Grant  # noqa: E402

VECTOR_DIR = os.path.join(ROOT_DIR, "test-vectors", "v2")

INTENT_SPEC = {
    "required_capabilities": ["store.read"],
    "confirmation": "grant-policy",
}
PARAMS_SCHEMA = {
    "type": "object",
    "properties": {"item_id": {"type": "string"}},
    "required": ["item_id"],
    "additionalProperties": False,
}


def load(name):
    with open(os.path.join(VECTOR_DIR, name), encoding="utf-8") as handle:
        return json.load(handle)


class CanonicalV2Vectors(unittest.TestCase):
    def test_vectors(self):
        for vector in load("canonical-json.json")["vectors"]:
            with self.subTest(vector["id"]):
                if "expect_error" in vector:
                    with self.assertRaises(CanonicalError) as caught:
                        canonical.canonicalize(vector["document"])
                    self.assertEqual(caught.exception.code,
                                     vector["expect_error"])
                else:
                    self.assertEqual(canonical.canonicalize(vector["document"]),
                                     vector["expected_canonical"])


class ValidationV2Vectors(unittest.TestCase):
    def test_vectors(self):
        for vector in load("validation.json")["vectors"]:
            with self.subTest(vector["id"]):
                grant = (Grant.from_dict(vector["grant"])
                         if vector["grant"] else None)
                decision = decide(
                    grant, vector["signal"], vector["signer"],
                    vector["context"]["now"],
                    set(vector["context"]["seen"]),
                    vector["context"]["counters"],
                    intent_spec=INTENT_SPEC,
                    params_schema=PARAMS_SCHEMA,
                )
                self.assertEqual(decision, vector["expected"])


if __name__ == "__main__":
    unittest.main()
