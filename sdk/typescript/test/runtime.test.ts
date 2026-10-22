import { describe, expect, it } from "vitest";
import { publicFromSeed } from "../src/crypto.js";
import {
  REQUESTER_PUBLIC,
  STORE,
  STRANGER_SEED,
  buildWorld,
  signalFor,
} from "./world.js";

describe("Runtime", () => {
  it("authorizes a valid signal", async () => {
    const world = buildWorld();
    const decision = await world.runtime.submit(signalFor(world), REQUESTER_PUBLIC);
    expect(decision.outcome).toBe("authorized");
    expect(decision.result).toEqual(STORE["item-123"]);
    expect(await world.runtime.limits.counters("g-1")).toEqual({
      calls_per_hour: 1,
    });
  });

  it("requires and executes confirmation", async () => {
    const world = buildWorld({ confirmation: "per_action" });
    const first = await world.runtime.submit(
      signalFor(world, { requestId: "req-a" }),
      REQUESTER_PUBLIC
    );
    expect(first.outcome).toBe("confirmation_required");
    expect(first.pending_id).toBeTruthy();
    const done = await world.runtime.confirm(first.pending_id!, true);
    expect(done.outcome).toBe("authorized");
  });

  it("cancels a denied confirmation and releases the limit", async () => {
    const world = buildWorld({ confirmation: "per_action" });
    const first = await world.runtime.submit(
      signalFor(world, { requestId: "req-a" }),
      REQUESTER_PUBLIC
    );
    const denied = await world.runtime.confirm(first.pending_id!, false);
    expect(denied.outcome).toBe("cancelled");
    expect(await world.runtime.limits.counters("g-1")).toEqual({
      calls_per_hour: 0,
    });
  });

  it("rejects a replay", async () => {
    const world = buildWorld();
    const document = signalFor(world);
    expect((await world.runtime.submit(document, REQUESTER_PUBLIC)).outcome).toBe(
      "authorized"
    );
    expect((await world.runtime.submit(document, REQUESTER_PUBLIC)).error).toBe(
      "replay_detected"
    );
  });

  it("enforces limits", async () => {
    const world = buildWorld({ limits: { calls_per_hour: 1 } });
    expect(
      (
        await world.runtime.submit(
          signalFor(world, { requestId: "r1" }),
          REQUESTER_PUBLIC
        )
      ).outcome
    ).toBe("authorized");
    expect(
      (
        await world.runtime.submit(
          signalFor(world, { requestId: "r2" }),
          REQUESTER_PUBLIC
        )
      ).error
    ).toBe("limit_exceeded");
  });

  it("rejects a bad signature", async () => {
    const world = buildWorld();
    const document = signalFor(world, { signer: STRANGER_SEED });
    expect((await world.runtime.submit(document, REQUESTER_PUBLIC)).error).toBe(
      "unauthenticated"
    );
  });

  it("rejects a request with no grant", async () => {
    const world = buildWorld();
    const document = signalFor(world, { signer: STRANGER_SEED });
    expect(
      (await world.runtime.submit(document, publicFromSeed(STRANGER_SEED))).error
    ).toBe("no_matching_grant");
  });

  it("rejects revoked and paused grants", async () => {
    const world = buildWorld();
    world.grant.state = "revoked";
    expect((await world.runtime.submit(signalFor(world), REQUESTER_PUBLIC)).error).toBe(
      "grant_revoked"
    );

    world.grant.state = "paused";
    expect(
      (
        await world.runtime.submit(
          signalFor(world, { requestId: "p1" }),
          REQUESTER_PUBLIC
        )
      ).error
    ).toBe("grant_paused");

    world.grant.state = "active";
    expect(
      (
        await world.runtime.submit(
          signalFor(world, { requestId: "p2" }),
          REQUESTER_PUBLIC
        )
      ).outcome
    ).toBe("authorized");
  });

  it("rejects an expired grant", async () => {
    const world = buildWorld({ expiresAt: "2026-10-22T11:00:00Z" });
    expect((await world.runtime.submit(signalFor(world), REQUESTER_PUBLIC)).error).toBe(
      "grant_expired"
    );
  });

  it("rejects invalid params", async () => {
    const world = buildWorld();
    expect(
      (
        await world.runtime.submit(
          signalFor(world, { params: {} }),
          REQUESTER_PUBLIC
        )
      ).error
    ).toBe("invalid_request");
  });

  it("rejects when a capability is unavailable", async () => {
    const world = buildWorld({ capabilities: [] });
    expect((await world.runtime.submit(signalFor(world), REQUESTER_PUBLIC)).error).toBe(
      "capability_unavailable"
    );
  });

  it("rejects a protocol mismatch", async () => {
    const world = buildWorld();
    expect(
      (
        await world.runtime.submit(
          signalFor(world, { ccp: "0.2-draft" }),
          REQUESTER_PUBLIC
        )
      ).error
    ).toBe("invalid_request");
  });

  it("rejects malformed input", async () => {
    const world = buildWorld();
    expect((await world.runtime.submit("not json", REQUESTER_PUBLIC)).error).toBe(
      "invalid_request"
    );
  });

  it("re-checks grant state when confirming", async () => {
    const world = buildWorld({ confirmation: "per_action" });
    const first = await world.runtime.submit(
      signalFor(world, { requestId: "req-a" }),
      REQUESTER_PUBLIC
    );
    world.grant.state = "revoked";
    expect((await world.runtime.confirm(first.pending_id!, true)).error).toBe(
      "grant_revoked"
    );
  });
});
