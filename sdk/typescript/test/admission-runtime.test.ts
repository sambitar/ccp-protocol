import { describe, expect, it } from "vitest";
import {
  buildAdmissionPolicy,
  verifyAdmissionPolicy,
  type PolicyRule,
} from "../src/identity.js";
import { NOW, REQUESTER_PUBLIC, buildWorld, signalFor } from "./world.js";

const HOST_SEED = Uint8Array.from({ length: 32 }, (_, index) => index + 96);
const ISSUED = "2026-10-22T00:00:00Z";
const UNTIL = "2027-01-01T00:00:00Z";

const RULE: PolicyRule = {
  id: "r-read",
  contacts: ["c-1"],
  intents: ["example.lookup"],
  risk: "read",
  limits: { calls_per_hour: 5 },
  confirmation: "none",
  expires_at: UNTIL,
};

function policy() {
  return verifyAdmissionPolicy(
    buildAdmissionPolicy(
      {
        version: 1,
        default: "confirm",
        rules: [RULE],
        issuedAt: ISSUED,
        expiresAt: UNTIL,
      },
      HOST_SEED
    ),
    { now: NOW }
  );
}

function request(
  world: ReturnType<typeof buildWorld>,
  overrides: Record<string, unknown> = {}
) {
  return {
    requesterKey: world.grant.requester_key,
    contactId: "c-1",
    intent: "example.lookup",
    risk: "read" as const,
    now: NOW,
    ...overrides,
  };
}

function auditEvents(world: ReturnType<typeof buildWorld>): any[] {
  return (world.runtime.audit as unknown as { events(): any[] }).events();
}

describe("Runtime.admitRequest", () => {
  it("creates a least-authority grant and records the rule", async () => {
    const world = buildWorld();
    const { result, grant } = await world.runtime.admitRequest({
      policy: policy(),
      request: request(world),
      manifest: world.manifest,
    });

    expect(result.decision).toBe("allow");
    expect(result.ruleId).toBe("r-read");
    expect(grant?.id).toMatch(/^pg-[0-9a-f]{32}$/);
    expect(grant?.requester_key).toBe(world.grant.requester_key);
    expect(grant?.contact_id).toBe("c-1");
    expect(grant?.intents).toEqual(["example.lookup"]);
    expect(grant?.limits).toEqual({ calls_per_hour: 5 });
    // The policy is the consumer's explicit automation decision (§9.5).
    expect(grant?.confirmation["example.lookup"]).toBe("none");

    const admitted = auditEvents(world).find(
      (event: any) => event.event === "admitted"
    );
    expect(admitted.rule_id).toBe("r-read");
    expect(admitted.grant_id).toBe(grant?.id);
  });

  it("reuses the deterministic grant instead of widening it", async () => {
    const world = buildWorld();
    const first = await world.runtime.admitRequest({
      policy: policy(),
      request: request(world),
      manifest: world.manifest,
    });
    const second = await world.runtime.admitRequest({
      policy: policy(),
      request: request(world),
      manifest: world.manifest,
    });

    expect(second.grant?.id).toBe(first.grant?.id);
    expect(second.grant?.created_at).toBe(first.grant?.created_at);
    const matches = (await world.runtime.grants.all()).filter(
      (grant) => grant.id === first.grant?.id
    );
    expect(matches).toHaveLength(1);
  });

  it("refuses to re-create a revoked grant", async () => {
    const world = buildWorld();
    const first = await world.runtime.admitRequest({
      policy: policy(),
      request: request(world),
      manifest: world.manifest,
    });
    await world.runtime.revokeGrant(first.grant!.id);

    const again = await world.runtime.admitRequest({
      policy: policy(),
      request: request(world),
      manifest: world.manifest,
    });
    expect(again.result.decision).toBe("deny");
    expect(again.result.reason).toBe("grant_revoked");
    expect(again.grant).toBeUndefined();
  });

  it("does not create a grant when the policy defers to the user", async () => {
    const world = buildWorld();
    const { result, grant } = await world.runtime.admitRequest({
      policy: policy(),
      request: request(world, { contactId: "c-other" }),
      manifest: world.manifest,
    });
    expect(result.decision).toBe("confirm");
    expect(grant).toBeUndefined();
  });

  it("produces a grant the runtime can then authorize", async () => {
    const world = buildWorld();
    await world.runtime.grants.remove("g-1");

    const { grant } = await world.runtime.admitRequest({
      policy: policy(),
      request: request(world),
      manifest: world.manifest,
    });
    expect(grant).toBeDefined();

    const decision = await world.runtime.submit(
      signalFor(world),
      REQUESTER_PUBLIC
    );
    expect(decision.outcome).toBe("authorized");
    expect(
      (await world.runtime.limits.counters(grant!.id)).calls_per_hour
    ).toBe(1);
  });

  it("skips a grant that does not enable the intent", async () => {
    const world = buildWorld();
    await world.runtime.grants.remove("g-1");
    // Insertion order puts the unusable grant first.
    await world.runtime.grants.add({
      ...world.grant,
      id: "g-other",
      intents: ["other.intent"],
    });
    await world.runtime.grants.add({ ...world.grant, id: "g-good" });

    const decision = await world.runtime.submit(
      signalFor(world),
      REQUESTER_PUBLIC
    );
    expect(decision.outcome).toBe("authorized");
    expect(await world.runtime.limits.counters("g-good")).toEqual({
      calls_per_hour: 1,
    });
  });
});
