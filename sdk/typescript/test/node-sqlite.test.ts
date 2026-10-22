import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { SqliteStores } from "../src/node/sqlite.js";
import { HostRegistry, Runtime, SchemaRegistry } from "../src/runtime.js";
import {
  NOW,
  PARAMS_SCHEMA,
  RESULT_SCHEMA,
  REQUESTER_PUBLIC,
  STORE,
  buildWorld,
  signalFor,
} from "./world.js";

function runtimeFor(stores: SqliteStores): Runtime {
  const hosts = new HostRegistry();
  hosts.registerHost("store.read", (id: string) => STORE[id]);
  hosts.registerIntent("example.lookup", (params: any, access: any) =>
    access.call("store.read", params.item_id)
  );
  const schemas = new SchemaRegistry({
    "schema:example.lookup.params.v1": PARAMS_SCHEMA,
    "schema:example.lookup.result.v1": RESULT_SCHEMA,
  });
  return new Runtime({
    grants: stores.grants,
    manifests: stores.manifests,
    replay: stores.replay,
    limits: stores.limits,
    pending: stores.pending,
    schemas,
    hosts,
    audit: stores.audit,
    clock: () => NOW,
  });
}

describe("SqliteGrantStore", () => {
  it("round-trips and finds by requester and digest", () => {
    const world = buildWorld();
    const stores = new SqliteStores();
    try {
      stores.grants.add(world.grant);
      expect(stores.grants.get("g-1")?.requester_key).toBe(
        world.grant.requester_key
      );
      expect(stores.grants.get("g-1")?.limits).toEqual({ calls_per_hour: 10 });
      expect(
        stores.grants.find(
          world.grant.requester_key,
          world.grant.manifest_digest
        )?.id
      ).toBe("g-1");
    } finally {
      stores.close();
    }
  });

  it("makes revocation visible to the next lookup", () => {
    const world = buildWorld();
    const stores = new SqliteStores();
    try {
      stores.grants.add(world.grant);
      stores.grants.add({ ...world.grant, state: "revoked" });
      expect(
        stores.grants.find(
          world.grant.requester_key,
          world.grant.manifest_digest
        )?.state
      ).toBe("revoked");
    } finally {
      stores.close();
    }
  });
});

describe("SqliteReplayStore", () => {
  it("marks an id at most once", () => {
    const stores = new SqliteStores();
    try {
      expect(stores.replay.has("r1")).toBe(false);
      expect(stores.replay.markIfNew("r1")).toBe(true);
      expect(stores.replay.markIfNew("r1")).toBe(false);
      expect(stores.replay.has("r1")).toBe(true);
    } finally {
      stores.close();
    }
  });
});

describe("SqliteLimitStore", () => {
  it("reserves all-or-none and never goes negative", () => {
    const stores = new SqliteStores();
    try {
      expect(stores.limits.tryReserve("g", { a: 2, b: 1 })).toBe(true);
      expect(stores.limits.counters("g")).toEqual({ a: 1, b: 1 });

      // b is exhausted; a must not be incremented by the failed attempt.
      expect(stores.limits.tryReserve("g", { a: 2, b: 1 })).toBe(false);
      expect(stores.limits.counters("g")).toEqual({ a: 1, b: 1 });

      expect(stores.limits.tryReserve("g", { a: 2 })).toBe(true);
      expect(stores.limits.counters("g")).toEqual({ a: 2, b: 1 });

      stores.limits.release("g", { a: 2, b: 1 });
      expect(stores.limits.counters("g")).toEqual({ a: 1, b: 0 });
      stores.limits.release("g", { a: 2, b: 1 });
      expect(stores.limits.counters("g")).toEqual({ a: 0, b: 0 });
      stores.limits.release("g", { a: 2, b: 1 });
      expect(stores.limits.counters("g")).toEqual({ a: 0, b: 0 });
    } finally {
      stores.close();
    }
  });
});

describe("SqlitePendingStore", () => {
  it("takes a pending confirmation at most once", () => {
    const world = buildWorld();
    const stores = new SqliteStores();
    try {
      stores.pending.put({
        id: "p1",
        signal: { request_id: "req-1" },
        grant: world.grant,
        intentSpec: { name: "example.lookup" },
        state: "awaiting_confirmation",
      });
      expect(stores.pending.get("p1")?.grant.id).toBe("g-1");
      expect(stores.pending.take("p1")?.id).toBe("p1");
      expect(stores.pending.take("p1")).toBeUndefined();
    } finally {
      stores.close();
    }
  });
});

describe("SqliteAuditLog", () => {
  it("appends events", () => {
    const stores = new SqliteStores();
    try {
      stores.audit.append({ event: "a" });
      stores.audit.append({ event: "b" });
      expect(stores.audit.events().map((event: any) => event.event)).toEqual([
        "a",
        "b",
      ]);
      expect(stores.audit.length).toBe(2);
    } finally {
      stores.close();
    }
  });
});

describe("Runtime over SQLite", () => {
  it("authorizes a valid signal and rejects a replay", async () => {
    const world = buildWorld();
    const stores = new SqliteStores();
    try {
      stores.grants.add(world.grant);
      stores.manifests.add(world.manifest);
      const runtime = runtimeFor(stores);
      const document = signalFor(world);

      const first = await runtime.submit(document, REQUESTER_PUBLIC);
      expect(first.outcome).toBe("authorized");
      expect(first.result).toEqual(STORE["item-123"]);

      const replay = await runtime.submit(document, REQUESTER_PUBLIC);
      expect(replay.outcome).toBe("replay_detected");
    } finally {
      stores.close();
    }
  });

  it("persists grants and replay state across reopen", async () => {
    const directory = mkdtempSync(join(tmpdir(), "ccp-ts-sqlite-"));
    const path = join(directory, "ccp.db");
    const world = buildWorld();
    const document = signalFor(world);
    try {
      const first = new SqliteStores(path);
      first.grants.add(world.grant);
      first.manifests.add(world.manifest);
      const runtime = runtimeFor(first);
      expect((await runtime.submit(document, REQUESTER_PUBLIC)).outcome).toBe(
        "authorized"
      );
      first.close();

      const reopened = new SqliteStores(path);
      try {
        expect(reopened.grants.get("g-1")?.id).toBe("g-1");
        expect(reopened.replay.has("req-1")).toBe(true);
        const runtime2 = runtimeFor(reopened);
        expect(
          (await runtime2.submit(document, REQUESTER_PUBLIC)).outcome
        ).toBe("replay_detected");
      } finally {
        reopened.close();
      }
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("persists a revocation across reopen", async () => {
    const directory = mkdtempSync(join(tmpdir(), "ccp-ts-sqlite-"));
    const path = join(directory, "ccp.db");
    const world = buildWorld();
    try {
      const first = new SqliteStores(path);
      first.grants.add(world.grant);
      first.manifests.add(world.manifest);
      const runtime = runtimeFor(first);
      const revoked = await runtime.revokeGrant("g-1", "user asked");
      expect(revoked.state).toBe("revoked");
      first.close();

      const reopened = new SqliteStores(path);
      try {
        expect(reopened.grants.get("g-1")?.state).toBe("revoked");
        const runtime2 = runtimeFor(reopened);
        expect(
          (await runtime2.submit(signalFor(world), REQUESTER_PUBLIC)).error
        ).toBe("grant_revoked");
      } finally {
        reopened.close();
      }
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("persists a pending confirmation across reopen", async () => {
    const directory = mkdtempSync(join(tmpdir(), "ccp-ts-sqlite-"));
    const path = join(directory, "ccp.db");
    const world = buildWorld({ confirmation: "per_action" });
    try {
      const first = new SqliteStores(path);
      first.grants.add(world.grant);
      first.manifests.add(world.manifest);
      const runtime = runtimeFor(first);
      const submitted = await runtime.submit(
        signalFor(world),
        REQUESTER_PUBLIC
      );
      expect(submitted.outcome).toBe("confirmation_required");
      const pendingId = submitted.pending_id!;
      first.close();

      const reopened = new SqliteStores(path);
      try {
        const runtime2 = runtimeFor(reopened);
        const done = await runtime2.confirm(pendingId, true);
        expect(done.outcome).toBe("authorized");
        expect(done.result).toEqual(STORE["item-123"]);
      } finally {
        reopened.close();
      }
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
