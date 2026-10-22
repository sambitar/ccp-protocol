"""Run the SDK against the frozen conformance vectors."""

import hashlib
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SDK_DIR = os.path.dirname(HERE)
ROOT_DIR = os.path.dirname(os.path.dirname(SDK_DIR))
sys.path.insert(0, SDK_DIR)

from ccp import canonical, crypto, state_machine  # noqa: E402
from ccp.canonical import CanonicalError  # noqa: E402
from ccp.decision import decide  # noqa: E402
from ccp.model import Grant  # noqa: E402

VECTOR_DIR = os.path.join(ROOT_DIR, "test-vectors")

# The single core intent used by the validation vectors.
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


class CanonicalVectors(unittest.TestCase):
    def test_vectors(self):
        for vector in load("canonical-json.json")["vectors"]:
            with self.subTest(vector["id"]):
                if "expect_error" in vector:
                    with self.assertRaises(CanonicalError) as caught:
                        canonical.canonicalize(vector["document"])
                    self.assertEqual(caught.exception.code, vector["expect_error"])
                else:
                    self.assertEqual(canonical.canonicalize(vector["document"]),
                                     vector["expected_canonical"])


class Ed25519Vectors(unittest.TestCase):
    def test_known_answer(self):
        for vector in load("ed25519.json")["kat_vectors"]:
            with self.subTest(vector["id"]):
                key = crypto.SigningKey.from_seed(
                    bytes.fromhex(vector["secret_key_hex"]))
                message = bytes.fromhex(vector["message_hex"])
                self.assertEqual(key.public_bytes.hex(), vector["public_key_hex"])
                self.assertEqual(key.key_id, vector["key_id"])
                self.assertEqual(key.sign(message), vector["signature_field"])
                self.assertTrue(key.verifying_key().verify(
                    message, vector["signature_field"]))

    def test_signing_vectors(self):
        for vector in load("ed25519.json")["signing_vectors"]:
            with self.subTest(vector["id"]):
                signing_input = canonical.signing_bytes(vector["document"])
                self.assertEqual(signing_input.decode("utf-8"),
                                 vector["signing_input"])
                self.assertEqual(hashlib.sha256(signing_input).hexdigest(),
                                 vector["signing_input_sha256"])
                key = crypto.SigningKey.from_seed(
                    bytes.fromhex(vector["seed_hex"]))
                self.assertEqual(key.public_bytes.hex(), vector["public_key_hex"])
                self.assertEqual(key.sign(signing_input),
                                 vector["signature_field"])
                signature_b64 = vector["signature_field"][len("ed25519:"):]
                self.assertEqual(
                    canonical.signed_wire(vector["document"], signature_b64),
                    vector["wire"])


class StateMachineVectors(unittest.TestCase):
    def test_vectors(self):
        for vector in load("state-machine.json")["vectors"]:
            with self.subTest(vector["id"]):
                self.assertEqual(
                    state_machine.next_state(vector["from"], vector["event"]),
                    vector["to"])


class ValidationVectors(unittest.TestCase):
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
