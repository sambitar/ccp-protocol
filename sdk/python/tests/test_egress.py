"""Egress and placement enforcement (§12)."""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SDK_DIR = os.path.dirname(HERE)
sys.path.insert(0, SDK_DIR)

from ccp import (  # noqa: E402
    AdmissionRequest,
    AuditLog,
    GrantStore,
    HostRegistry,
    ManifestStore,
    Runtime,
    SchemaRegistry,
    SigningKey,
    build_admission_policy,
    create_grant,
    sign_manifest,
    sign_signal,
    verify_admission_policy,
    verify_manifest,
)

NOW = "2026-10-22T12:00:30Z"
PROVIDER = SigningKey.from_seed(bytes(range(32)))
REQUESTER = SigningKey.from_seed(bytes(range(32, 64)))

PARAMS = {
    "type": "object",
    "properties": {"q": {"type": "string"}},
    "required": ["q"],
    "additionalProperties": False,
}
RESULT = {
    "type": "object",
    "properties": {"ok": {"type": "boolean"}},
    "required": ["ok"],
    "additionalProperties": False,
}

LOCAL_INTENT = {
    "description": "Fetch something",
    "params_schema": "schema:example.fetch.params.v1",
    "result_schema": "schema:example.fetch.result.v1",
    "required_capabilities": ["net.request"],
    "placement": "local",
    "data_egress": {"network": False, "fields": []},
    "suggested_limits": {"calls_per_hour": 5},
    "confirmation": "none",
}


def world(intent=None, **host_options):
    document = sign_manifest(
        {"id": PROVIDER.key_id, "name": "Example Service"},
        1,
        {"example.fetch": intent or dict(LOCAL_INTENT)},
        PROVIDER,
    )
    manifest = verify_manifest(document)
    grant = create_grant(
        contact_id="c-1",
        requester_key=REQUESTER.key_id,
        manifest=manifest,
        intents=["example.fetch"],
        created_at="2026-10-22T10:00:00Z",
        expires_at="2026-10-22T23:00:00Z",
    )
    hosts = HostRegistry()
    hosts.register_host("net.request", lambda q: {"ok": True}, **host_options)
    hosts.register_intent(
        "example.fetch",
        lambda params, access: access.call("net.request", params["q"]),
    )
    runtime = Runtime(
        grants=GrantStore([grant]),
        manifests=ManifestStore([manifest]),
        schemas=SchemaRegistry({
            "schema:example.fetch.params.v1": PARAMS,
            "schema:example.fetch.result.v1": RESULT,
        }),
        hosts=hosts,
        audit=AuditLog(),
        clock=lambda: NOW,
    )
    signal = sign_signal(
        "r1", manifest.digest, "example.fetch", {"q": "hello"},
        "2026-10-22T12:00:00Z", "2026-10-22T12:01:00Z", REQUESTER,
    )
    return {"runtime": runtime, "grant": grant, "signal": signal,
            "hosts": hosts, "manifest": manifest}


def submit(world):
    return world["runtime"].submit(world["signal"],
                                   REQUESTER.verifying_key())


class EgressTests(unittest.TestCase):
    def test_refuses_a_network_host_under_a_local_grant(self):
        decision = submit(world(network=True, host_class="disclose",
                                fields=["q"]))
        self.assertEqual(decision.error, "capability_unavailable")
        self.assertIn("network egress", decision.detail)

    def test_allows_a_declared_network_host(self):
        intent = dict(LOCAL_INTENT,
                      data_egress={"network": True, "fields": ["q"]})
        world_ = world(intent, host_class="disclose", network=True,
                       fields=["q"])
        first = submit(world_)
        self.assertTrue(first.needs_confirmation)
        done = world_["runtime"].confirm(first.pending_id, True)
        self.assertTrue(done.authorized)
        self.assertEqual(done.result, {"ok": True})

    def test_refuses_an_undeclared_field(self):
        intent = dict(LOCAL_INTENT,
                      data_egress={"network": True, "fields": ["q"]})
        decision = submit(world(intent, host_class="disclose", network=True,
                                fields=["q", "token"]))
        self.assertEqual(decision.error, "capability_unavailable")
        self.assertIn("undeclared field token", decision.detail)

    def test_refuses_remote_placement_on_a_local_host(self):
        intent = dict(LOCAL_INTENT, placement="remote",
                      data_egress={"network": True, "fields": ["q"]})
        decision = submit(world(intent, host_class="disclose", network=True,
                                fields=["q"]))
        self.assertEqual(decision.error, "capability_unavailable")
        self.assertIn("placement", decision.detail)

    def test_allows_remote_placement_when_the_host_declares_it(self):
        intent = dict(LOCAL_INTENT, placement="remote",
                      data_egress={"network": True, "fields": ["q"]})
        world_ = world(intent, host_class="disclose", network=True,
                       placement=["local", "remote"], fields=["q"])
        first = submit(world_)
        self.assertTrue(first.needs_confirmation)
        done = world_["runtime"].confirm(first.pending_id, True)
        self.assertTrue(done.authorized)

    def test_the_proxy_checks_the_ceiling_again(self):
        hosts = HostRegistry()
        hosts.register_host("net.request", lambda: "ok", host_class="disclose",
                            network=True, fields=["q"])
        access = hosts.access(["net.request"],
                              {"network": False, "fields": frozenset()})
        with self.assertRaises(PermissionError):
            access.call("net.request")

    def test_an_unannotated_core_host_is_local_and_offline(self):
        hosts = HostRegistry()
        hosts.register_host("store.read", lambda: "ok")
        self.assertEqual(hosts.host_meta("store.read")["profile"], {
            "class": "read",
            "risk": "read",
            "minConfirmation": "none",
            "idempotency": "pure",
            "network": False,
            "placement": ["local"],
            "fields": [],
        })
        access = hosts.access(["store.read"],
                              {"network": False, "fields": frozenset()})
        self.assertEqual(access.call("store.read"), "ok")

    def test_a_policy_cannot_admit_a_host_that_needs_a_human(self):
        intent = dict(LOCAL_INTENT,
                      data_egress={"network": True, "fields": ["q"]})
        world_ = world(intent, host_class="disclose", network=True,
                       fields=["q"])
        host_key = SigningKey.from_seed(bytes(range(96, 128)))
        policy = verify_admission_policy(
            build_admission_policy({
                "version": 1,
                "default": "confirm",
                "rules": [{
                    "id": "r-fetch",
                    "contacts": ["c-1"],
                    "intents": ["example.fetch"],
                    "risk": "read",
                    "limits": {"calls_per_hour": 5},
                    "confirmation": "none",
                    "expires_at": "2027-01-01T00:00:00Z",
                }],
                "issued_at": "2026-10-22T00:00:00Z",
                "expires_at": "2027-01-01T00:00:00Z",
            }, host_key),
            now=NOW,
        )

        outcome = world_["runtime"].admit_request(
            policy,
            AdmissionRequest(
                requester_key=world_["grant"].requester_key,
                contact_id="c-1",
                intent="example.fetch",
                risk="read",
                now=NOW,
            ),
            world_["manifest"],
        )
        self.assertEqual(outcome.result.decision, "deny")
        self.assertEqual(outcome.result.reason, "risk_not_admittable")
        self.assertIsNone(outcome.grant)


if __name__ == "__main__":
    unittest.main()
