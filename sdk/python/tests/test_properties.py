"""Deterministic property tests for canonicalization and decisions."""

import os
import random
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SDK_DIR = os.path.dirname(HERE)
sys.path.insert(0, SDK_DIR)

from ccp import canonical, schema  # noqa: E402
from ccp.canonical import CanonicalError  # noqa: E402
from ccp.decision import decide  # noqa: E402
from ccp.model import Grant  # noqa: E402

STRINGS = [
    "a", "Z", "0", " ", "\u00e9", "e\u0301", "\U0001f600", "\x00", "\x1f",
    '"', "\\", "/", "~", "\u4f8b",
]

ERROR_CODES = {"malformed", "duplicate", "negative", "float", "constant"}

BASE_GRANT = {
    "id": "g-1",
    "requester_key": "key:ed25519:requester",
    "contact_id": "c-1",
    "manifest_digest": "sha256:digest",
    "manifest_version": 1,
    "intents": ["example.lookup"],
    "limits": {"calls_per_hour": 10},
    "created_at": "2026-10-22T10:00:00Z",
    "expires_at": "2026-10-22T13:00:00Z",
    "confirmation": {"example.lookup": "none"},
    "capabilities": ["store.read"],
    "placement": ["local"],
    "egress": {"network": False},
    "state": "active",
    "state_reason": None,
}
BASE_SIGNAL = {
    "ccp": "0.5-draft",
    "request_id": "req-1",
    "grant_digest": "sha256:digest",
    "intent": "example.lookup",
    "params": {"item_id": "item-123"},
    "issued_at": "2026-10-22T12:00:00Z",
    "expires_at": "2026-10-22T12:01:00Z",
}
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
OUTCOMES = {
    "authorized", "confirmation_required", "invalid_request",
    "unauthenticated", "no_matching_grant", "intent_not_allowed",
    "grant_expired", "grant_revoked", "grant_paused", "grant_suspended",
    "request_expired", "replay_detected", "limit_exceeded",
    "capability_unavailable",
}


def random_string(rng, maximum=8):
    length = rng.randrange(maximum + 1)
    return "".join(rng.choice(STRINGS) for _ in range(length))


def random_value(rng, depth=0):
    pick = rng.randrange(4 if depth >= 3 else 6)
    if pick == 0:
        return None
    if pick == 1:
        return rng.random() < 0.5
    if pick == 2:
        return (18446744073709551616 if rng.random() < 0.1
                else rng.randrange(1000000))
    if pick == 3:
        return random_string(rng)
    if pick == 4:
        return [random_value(rng, depth + 1) for _ in range(rng.randrange(4))]
    result = {}
    for index in range(rng.randrange(4)):
        result["%s%d" % (random_string(rng, 4), index)] = random_value(
            rng, depth + 1)
    return result


class CanonicalProperties(unittest.TestCase):
    def test_round_trip_and_idempotence(self):
        rng = random.Random(20261022)
        for _ in range(300):
            value = random_value(rng)
            canonical_text = canonical.serialize(value)
            self.assertEqual(canonical.canonicalize(canonical_text),
                             canonical_text)

    def test_random_text_never_escapes_the_error_vocabulary(self):
        rng = random.Random(7)
        pool = list('{}[]"\\:,01-.eENItfnu a\n\t') + [
            "\u00e9", "\U0001f600", "\x00", "\ud800",
        ]
        for _ in range(300):
            text = "".join(rng.choice(pool) for _ in range(rng.randrange(20)))
            try:
                canonical_text = canonical.canonicalize(text)
            except CanonicalError as error:
                self.assertIn(error.code, ERROR_CODES)
                continue
            self.assertEqual(canonical.canonicalize(canonical_text),
                             canonical_text)

    def test_lone_surrogate_is_rejected(self):
        with self.assertRaises(CanonicalError):
            canonical.canonicalize('{"a":"\\ud800"}')

    def test_large_integer_round_trips(self):
        self.assertEqual(
            canonical.canonicalize('{"n":18446744073709551616}'),
            '{"n":18446744073709551616}',
        )


class DecisionProperties(unittest.TestCase):
    def test_deterministic_and_known_outcomes(self):
        rng = random.Random(99)
        states = ["active", "paused", "suspended", "revoked", "expired"]
        times = [
            "2026-10-22T11:00:00Z",
            "2026-10-22T12:00:30Z",
            "2026-10-22T13:00:00Z",
        ]
        for _ in range(300):
            grant = dict(BASE_GRANT)
            grant["state"] = rng.choice(states)
            grant["expires_at"] = rng.choice(times)
            grant["limits"] = {"calls_per_hour": rng.randrange(15)}

            signal = dict(BASE_SIGNAL)
            signal["expires_at"] = rng.choice(times)
            if rng.random() < 0.2:
                signal["params"] = {}
            if rng.random() < 0.1:
                signal["intent"] = "files.search"

            seen = {"req-1"} if rng.random() < 0.2 else set()
            counters = {"calls_per_hour": rng.randrange(15)}
            signer = ("key:ed25519:other" if rng.random() < 0.1
                      else BASE_GRANT["requester_key"])
            now = rng.choice(times)

            first = decide(
                Grant.from_dict(grant), signal, signer, now, seen, counters,
                intent_spec=INTENT_SPEC, params_schema=PARAMS_SCHEMA,
            )
            second = decide(
                Grant.from_dict(grant), signal, signer, now, set(seen),
                counters, intent_spec=INTENT_SPEC,
                params_schema=PARAMS_SCHEMA,
            )
            self.assertEqual(first, second)
            self.assertIn(first, OUTCOMES)


class PortabilityFixes(unittest.TestCase):
    def test_astral_string_length_is_one_code_point(self):
        self.assertTrue(schema.is_valid(
            "\U0001f600",
            {"type": "string", "minLength": 1, "maxLength": 1},
        ))

    def test_huge_multiple_of_uses_integer_modulo(self):
        huge = 18446744073709551616
        self.assertTrue(schema.is_valid(
            huge, {"type": "integer", "multipleOf": 2}))
        self.assertFalse(schema.is_valid(
            huge, {"type": "integer", "multipleOf": 3}))


if __name__ == "__main__":
    unittest.main()
