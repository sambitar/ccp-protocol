"""Durable SQLite store tests."""

import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SDK_DIR = os.path.dirname(HERE)
sys.path.insert(0, SDK_DIR)

from ccp import (  # noqa: E402
    HostRegistry,
    Pending,
    Runtime,
    SchemaRegistry,
    Signal,
    SqliteStores,
)
from world import (  # noqa: E402
    INTENTS,
    NOW,
    PARAMS_SCHEMA,
    RESULT_SCHEMA,
    STORE,
    build_world,
    signal_for,
)


def make_runtime(stores):
    hosts = HostRegistry()
    hosts.register_host("store.read", lambda item_id: STORE.get(item_id))
    hosts.register_intent(
        "example.lookup",
        lambda params, access: access.call("store.read", params["item_id"]),
    )
    schemas = SchemaRegistry({
        "schema:example.lookup.params.v1": PARAMS_SCHEMA,
        "schema:example.lookup.result.v1": RESULT_SCHEMA,
    })
    return Runtime(
        grants=stores.grants,
        manifests=stores.manifests,
        replay=stores.replay,
        limits=stores.limits,
        pending=stores.pending,
        schemas=schemas,
        hosts=hosts,
        audit=stores.audit,
        clock=lambda: NOW,
    )


class GrantStoreTests(unittest.TestCase):
    def setUp(self):
        self.stores = SqliteStores()
        self.addCleanup(self.stores.close)

    def test_round_trip_and_find(self):
        world = build_world()
        self.stores.grants.add(world["grant"])
        got = self.stores.grants.get("g-1")
        self.assertEqual(got.requester_key, world["grant"].requester_key)
        self.assertEqual(got.limits, {"calls_per_hour": 10})
        found = self.stores.grants.find(got.requester_key,
                                        got.manifest_digest)
        self.assertEqual(found.id, "g-1")

    def test_revocation_is_visible(self):
        world = build_world()
        grant = world["grant"]
        self.stores.grants.add(grant)
        grant.revoke("test")
        self.stores.grants.add(grant)
        found = self.stores.grants.find(grant.requester_key,
                                        grant.manifest_digest)
        self.assertEqual(found.state, "revoked")

    def test_remove(self):
        world = build_world()
        self.stores.grants.add(world["grant"])
        self.assertIsNotNone(self.stores.grants.remove("g-1"))
        self.assertIsNone(self.stores.grants.get("g-1"))
        self.assertIsNone(self.stores.grants.remove("g-1"))


class ManifestStoreTests(unittest.TestCase):
    def setUp(self):
        self.stores = SqliteStores()
        self.addCleanup(self.stores.close)

    def test_round_trip(self):
        world = build_world()
        digest = world["manifest"].digest
        self.stores.manifests.add(world["manifest"])
        loaded = self.stores.manifests.get(digest)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.digest, digest)
        self.assertIsNotNone(loaded.intent_spec("example.lookup"))
        self.assertIsNone(self.stores.manifests.get("sha256:missing"))


class ReplayStoreTests(unittest.TestCase):
    def setUp(self):
        self.stores = SqliteStores()
        self.addCleanup(self.stores.close)

    def test_mark_if_new(self):
        self.assertFalse(self.stores.replay.seen("r1"))
        self.assertTrue(self.stores.replay.mark_if_new("r1"))
        self.assertFalse(self.stores.replay.mark_if_new("r1"))
        self.assertTrue(self.stores.replay.seen("r1"))
        self.assertEqual(self.stores.replay.snapshot(), {"r1"})

    def test_expire(self):
        self.stores.replay.mark_if_new("r1")
        self.assertEqual(
            self.stores.replay.expire("2999-01-01T00:00:00Z"), 1)
        self.assertFalse(self.stores.replay.seen("r1"))


class LimitTrackerTests(unittest.TestCase):
    def setUp(self):
        self.stores = SqliteStores()
        self.addCleanup(self.stores.close)

    def test_reserve_all_or_none(self):
        self.assertTrue(self.stores.limits.try_reserve("g", {"a": 2, "b": 1}))
        self.assertEqual(self.stores.limits.counters("g"), {"a": 1, "b": 1})

        # b is exhausted; the failed attempt must not increment a.
        self.assertFalse(
            self.stores.limits.try_reserve("g", {"a": 2, "b": 1}))
        self.assertEqual(self.stores.limits.counters("g"), {"a": 1, "b": 1})

        # a still has room up to its ceiling of 2, then is exhausted.
        self.assertTrue(self.stores.limits.try_reserve("g", {"a": 2}))
        self.assertEqual(self.stores.limits.counters("g"), {"a": 2, "b": 1})
        self.assertFalse(self.stores.limits.try_reserve("g", {"a": 2}))
        self.assertEqual(self.stores.limits.counters("g"), {"a": 2, "b": 1})

    def test_release_never_goes_negative(self):
        self.stores.limits.try_reserve("g", {"a": 1})
        self.stores.limits.release("g", {"a": 1})
        self.assertEqual(self.stores.limits.counters("g"), {"a": 0})
        self.stores.limits.release("g", {"a": 1})
        self.assertEqual(self.stores.limits.counters("g"), {"a": 0})


class PendingStoreTests(unittest.TestCase):
    def setUp(self):
        self.stores = SqliteStores()
        self.addCleanup(self.stores.close)

    def test_take_at_most_once(self):
        world = build_world()
        signal = Signal.parse(signal_for(world))
        pending = Pending("p1", signal, world["grant"],
                          INTENTS["example.lookup"])
        self.stores.pending.put(pending)

        got = self.stores.pending.get("p1")
        self.assertIsNotNone(got)
        self.assertEqual(got.signal.request_id, "req-1")

        taken = self.stores.pending.take("p1")
        self.assertIsNotNone(taken)
        self.assertEqual(taken.grant.id, "g-1")
        self.assertIsNone(self.stores.pending.take("p1"))


class AuditStoreTests(unittest.TestCase):
    def setUp(self):
        self.stores = SqliteStores()
        self.addCleanup(self.stores.close)

    def test_append_only(self):
        self.stores.audit.append({"event": "a"})
        self.stores.audit.append(
            {"event": "b", "at": "2026-10-22T00:00:00Z"})
        events = self.stores.audit.events()
        self.assertEqual([event["event"] for event in events], ["a", "b"])
        self.assertEqual(len(self.stores.audit), 2)
        self.assertEqual(events[1]["at"], "2026-10-22T00:00:00Z")


class RuntimeIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.path = os.path.join(self.tempdir.name, "ccp.db")

    def test_authorized_and_replay(self):
        world = build_world()
        stores = SqliteStores(self.path)
        self.addCleanup(stores.close)
        stores.grants.add(world["grant"])
        stores.manifests.add(world["manifest"])
        runtime = make_runtime(stores)

        first = runtime.submit(signal_for(world),
                               world["requester"].verifying_key())
        self.assertTrue(first.authorized)
        self.assertEqual(first.result, STORE["item-123"])

        replay = runtime.submit(signal_for(world),
                                world["requester"].verifying_key())
        self.assertEqual(replay.error, "replay_detected")

    def test_state_survives_reopen(self):
        world = build_world()
        document = signal_for(world)

        stores = SqliteStores(self.path)
        stores.grants.add(world["grant"])
        stores.manifests.add(world["manifest"])
        runtime = make_runtime(stores)
        self.assertTrue(
            runtime.submit(document, world["requester"].verifying_key())
            .authorized)
        stores.close()

        reopened = SqliteStores(self.path)
        self.addCleanup(reopened.close)
        self.assertIsNotNone(reopened.grants.get("g-1"))
        self.assertTrue(reopened.replay.seen("req-1"))

        runtime2 = make_runtime(reopened)
        replay = runtime2.submit(document,
                                 world["requester"].verifying_key())
        self.assertEqual(replay.error, "replay_detected")

    def test_pending_survives_reopen(self):
        world = build_world(confirmation="per_action")

        stores = SqliteStores(self.path)
        stores.grants.add(world["grant"])
        stores.manifests.add(world["manifest"])
        runtime = make_runtime(stores)
        first = runtime.submit(signal_for(world),
                               world["requester"].verifying_key())
        self.assertTrue(first.needs_confirmation)
        pending_id = first.pending_id
        stores.close()

        reopened = SqliteStores(self.path)
        self.addCleanup(reopened.close)
        runtime2 = make_runtime(reopened)
        done = runtime2.confirm(pending_id, True)
        self.assertTrue(done.authorized)
        self.assertEqual(done.result, STORE["item-123"])


if __name__ == "__main__":
    unittest.main()
