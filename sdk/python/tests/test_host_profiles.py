"""Host contracts (§26.4)."""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SDK_DIR = os.path.dirname(HERE)
sys.path.insert(0, SDK_DIR)

from ccp import (  # noqa: E402
    CORE_HOSTS,
    HostProfileError,
    HostRegistry,
    validate_host_profile,
)


class HostProfileTests(unittest.TestCase):
    def test_extension_hosts_need_a_class(self):
        registry = HostRegistry()
        with self.assertRaises(HostProfileError) as caught:
            registry.register_host("net.request", lambda: 1)
        self.assertIn("requires a class", caught.exception.message)

    def test_core_hosts_need_no_profile(self):
        registry = HostRegistry()
        registry.register_host("store.read", lambda: 1)
        self.assertEqual(registry.host_meta("store.read")["profile"], {
            "class": "read",
            "risk": "read",
            "minConfirmation": "none",
            "idempotency": "pure",
            "network": False,
            "placement": ["local"],
            "fields": [],
        })

    def test_write_control_and_compute_default_to_per_action(self):
        self.assertEqual(
            validate_host_profile("store.write", {"class": "write"}),
            {"class": "write", "risk": "write",
             "minConfirmation": "per_action", "idempotency": "caller_key",
             "network": False, "placement": ["local"], "fields": []})
        self.assertEqual(
            validate_host_profile("device.operation",
                                  {"class": "control",
                                   "risk": "irreversible"})["minConfirmation"],
            "per_action")
        self.assertEqual(
            validate_host_profile("model.infer",
                                  {"class": "compute"})["minConfirmation"],
            "per_action")

    def test_a_write_host_cannot_suppress_confirmation(self):
        with self.assertRaises(HostProfileError):
            validate_host_profile("store.write",
                                  {"class": "write",
                                   "minConfirmation": "none"})

    def test_an_irreversible_host_cannot_suppress_confirmation(self):
        with self.assertRaises(HostProfileError):
            validate_host_profile("payment.submit",
                                  {"class": "write",
                                   "risk": "irreversible",
                                   "minConfirmation": "none"})

    def test_a_network_disclose_host_must_declare_fields(self):
        with self.assertRaises(HostProfileError):
            validate_host_profile("net.request",
                                  {"class": "disclose", "network": True})

    def test_unknown_placement_and_duplicate_fields_are_rejected(self):
        with self.assertRaises(HostProfileError):
            validate_host_profile("net.request",
                                  {"class": "disclose", "network": True,
                                   "placement": ["edge"], "fields": ["q"]})
        with self.assertRaises(HostProfileError):
            validate_host_profile("net.request",
                                  {"class": "disclose", "network": True,
                                   "fields": ["q", "q"]})

    def test_core_catalogue(self):
        self.assertEqual(CORE_HOSTS, frozenset({
            "store.read", "files.read", "files.search",
            "notify", "confirm", "audit.append",
        }))


if __name__ == "__main__":
    unittest.main()
