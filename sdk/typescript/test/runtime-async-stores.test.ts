import { describe, expect, it } from "vitest";
import { Runtime } from "../src/runtime.js";
import type {
  AuditStore,
  Grant,
  GrantStore,
  LimitStore,
  PendingRequest,
  PendingStore,
  ReplayStore,
} from "../src/stores.js";
import {
  MemoryGrantStore,
  MemoryLimitStore,
  MemoryManifestStore,
  MemoryPendingStore,
  MemoryReplayStore,
} from "../src/stores.js";
import { NOW, REQUESTER_PUBLIC, buildWorld, signalFor } from "./world.js";

const tick = <T>(value: T): Promise<T> =>
  new Promise((resolve) => setTimeout(() => resolve(value), 0));

function asyncStores(initial: Grant) {
  const grants = new MemoryGrantStore([initial]);
  const replay = new MemoryReplayStore();
  const limits = new MemoryLimitStore();
  const pending = new MemoryPendingStore();
  const events: unknown[] = [];

  const grantStore: GrantStore = {
    add: (grant) => tick(grants.add(grant)),
    get: (id) => tick(grants.get(id)),
    find: (key, digest) => tick(grants.find(key, digest)),
    remove: (id) => tick(grants.remove(id)),
    all: () => tick(grants.all()),
  };
  const replayStore: ReplayStore = {
    has: (id) => tick(replay.has(id)),
    markIfNew: (id) => tick(replay.markIfNew(id)),
  };
  const limitStore: LimitStore = {
    tryReserve: (id, ceilings) => tick(limits.tryReserve(id, ceilings)),
    release: (id, ceilings) => tick(limits.release(id, ceilings)),
    counters: (id) => tick(limits.counters(id)),
  };
  const pendingStore: PendingStore = {
    put: (request: PendingRequest) => tick(pending.put(request)),
    get: (id) => tick(pending.get(id)),
    take: (id) => tick(pending.take(id)),
  };
  const audit: AuditStore = {
    append: (event) => tick(events.push(event)),
  };

  return { grantStore, replayStore, limitStore, pendingStore, audit, events };
}

function runtimeFor(world: ReturnType<typeof buildWorld>) {
  const stores = asyncStores(world.grant);
  const runtime = new Runtime({
    grants: stores.grantStore,
    manifests: new MemoryManifestStore([world.manifest]),
    schemas: world.runtime.schemas,
    hosts: world.runtime.hosts,
    replay: stores.replayStore,
    limits: stores.limitStore,
    pending: stores.pendingStore,
    audit: stores.audit,
    clock: () => NOW,
  });
  return { runtime, events: stores.events };
}

describe("Runtime with asynchronous stores", () => {
  it("authorizes and records the audit trail through awaited calls", async () => {
    const world = buildWorld();
    const { runtime, events } = runtimeFor(world);

    const decision = await runtime.submit(signalFor(world), REQUESTER_PUBLIC);
    expect(decision.outcome).toBe("authorized");
    expect(events.map((event: any) => event.event)).toEqual([
      "executing",
      "completed",
    ]);
  });

  it("resolves a confirmation at most once", async () => {
    const world = buildWorld({ confirmation: "per_action" });
    const { runtime } = runtimeFor(world);

    const first = await runtime.submit(
      signalFor(world, { requestId: "req-a" }),
      REQUESTER_PUBLIC
    );
    expect(first.outcome).toBe("confirmation_required");

    const [a, b] = await Promise.all([
      runtime.confirm(first.pending_id!, true),
      runtime.confirm(first.pending_id!, true),
    ]);
    const outcomes = [a.outcome, b.outcome].sort();
    expect(outcomes).toEqual(["authorized", "invalid_request"]);
  });

  it("reserves limits atomically across concurrent submits", async () => {
    const world = buildWorld({ limits: { calls_per_hour: 1 } });
    const { runtime } = runtimeFor(world);

    const decisions = await Promise.all([
      runtime.submit(signalFor(world, { requestId: "r1" }), REQUESTER_PUBLIC),
      runtime.submit(signalFor(world, { requestId: "r2" }), REQUESTER_PUBLIC),
    ]);
    const outcomes = decisions.map((decision) => decision.outcome).sort();
    expect(outcomes).toEqual(["authorized", "limit_exceeded"]);
  });
});
