import { describe, expect, it } from "vitest";
import { HostRegistry } from "../src/runtime.js";
import {
  MemoryLimitStore,
  MemoryPendingStore,
  MemoryReplayStore,
} from "../src/stores.js";

describe("MemoryLimitStore", () => {
  it("reserves all-or-nothing and trips at equality", () => {
    const limits = new MemoryLimitStore();
    expect(limits.tryReserve("g", { calls: 1 })).toBe(true);
    expect(limits.tryReserve("g", { calls: 1 })).toBe(false);
    expect(limits.counters("g")).toEqual({ calls: 1 });
    limits.release("g", { calls: 1 });
    expect(limits.counters("g")).toEqual({ calls: 0 });
  });
});

describe("MemoryReplayStore", () => {
  it("marks only once", () => {
    const replay = new MemoryReplayStore();
    expect(replay.markIfNew("r1")).toBe(true);
    expect(replay.markIfNew("r1")).toBe(false);
    expect(replay.has("r1")).toBe(true);
    expect(replay.snapshot().has("r1")).toBe(true);
  });
});

describe("MemoryPendingStore", () => {
  it("takes a pending request at most once", () => {
    const pending = new MemoryPendingStore();
    pending.put({
      id: "p1",
      signal: {},
      grant: {} as never,
      intentSpec: {},
      state: "awaiting_confirmation",
    });
    expect(pending.get("p1")?.id).toBe("p1");
    expect(pending.take("p1")?.id).toBe("p1");
    expect(pending.take("p1")).toBeUndefined();
  });
});

describe("HostRegistry", () => {
  it("mediates access to granted hosts only", () => {
    const hosts = new HostRegistry();
    hosts.registerHost("store.read", (id: string) => ({ id }));
    const access = hosts.access(["store.read"]);
    expect(access.call("store.read", "x")).toEqual({ id: "x" });
    expect(() => access.call("files.read", "y")).toThrow(/not granted/);
  });
});
