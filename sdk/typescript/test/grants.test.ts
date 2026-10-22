import { describe, expect, it } from "vitest";
import { keyIdFromPublic, publicFromSeed } from "../src/crypto.js";
import { CcpError } from "../src/errors.js";
import { createGrant } from "../src/grants.js";
import { signManifest } from "../src/requester.js";
import { buildWorld, INTENTS, PROVIDER_SEED } from "./world.js";

function options(world: ReturnType<typeof buildWorld>) {
  return {
    id: "g-test",
    requesterKey: world.requesterId,
    contactId: "c-1",
    manifest: world.manifest,
    intents: ["example.lookup"],
    createdAt: "2026-10-22T10:00:00Z",
    expiresAt: "2026-10-22T23:00:00Z",
  };
}

function codeOf(fn: () => unknown): string | undefined {
  try {
    fn();
  } catch (error) {
    if (error instanceof CcpError) return error.code;
    throw error;
  }
  return undefined;
}

describe("createGrant", () => {
  it("derives a least-authority grant from the manifest", () => {
    const world = buildWorld();
    const grant = createGrant(options(world));

    expect(grant.limits).toEqual({ calls_per_hour: 10 });
    expect(grant.confirmation).toEqual({ "example.lookup": "per_action" });
    expect(grant.capabilities).toEqual(["store.read"]);
    expect(grant.placement).toEqual(["local"]);
    expect(grant.egress).toEqual({ network: false, fields: [] });
    expect(grant.state).toBe("active");
    expect(grant.state_reason).toBeNull();
  });

  it("allows narrowing limits but not widening them", () => {
    const world = buildWorld();
    expect(createGrant({ ...options(world), limits: { calls_per_hour: 5 } }).limits).toEqual({
      calls_per_hour: 5,
    });
    expect(
      codeOf(() =>
        createGrant({ ...options(world), limits: { calls_per_hour: 11 } })
      )
    ).toBe("invalid_request");
  });

  it("allows tightening confirmation but not relaxing it", () => {
    const world = buildWorld();
    const strict = createGrant({
      ...options(world),
      confirmation: { "example.lookup": "per_action" },
    });
    expect(strict.confirmation["example.lookup"]).toBe("per_action");

    // The manifest already requires per-action confirmation.
    expect(
      codeOf(() =>
        createGrant({
          ...options(world),
          confirmation: { "example.lookup": "none" },
        })
      )
    ).toBe("invalid_request");

    // A manifest that permits automation can still be tightened.
    const permissive = signManifest(
      {
        provider: {
          id: keyIdFromPublic(publicFromSeed(PROVIDER_SEED)),
          name: "Example Service",
        },
        version: 1,
        intents: {
          "example.lookup": {
            ...INTENTS["example.lookup"],
            confirmation: "none",
          },
        },
      },
      PROVIDER_SEED
    );
    const tightened = createGrant({
      ...options(world),
      manifest: permissive,
      confirmation: { "example.lookup": "per_action" },
    });
    expect(tightened.confirmation["example.lookup"]).toBe("per_action");
  });

  it("requires every capability and rejects unused ones", () => {
    const world = buildWorld();
    expect(
      codeOf(() => createGrant({ ...options(world), capabilities: [] }))
    ).toBe("capability_unavailable");
    expect(
      codeOf(() =>
        createGrant({
          ...options(world),
          capabilities: ["store.read", "files.read"],
        })
      )
    ).toBe("invalid_request");
  });

  it("rejects intents the manifest does not declare", () => {
    const world = buildWorld();
    expect(
      codeOf(() =>
        createGrant({ ...options(world), intents: ["files.search"] })
      )
    ).toBe("intent_not_allowed");
    expect(
      codeOf(() => createGrant({ ...options(world), intents: [] }))
    ).toBe("invalid_request");
  });

  it("rejects placement and egress broader than the manifest", () => {
    const world = buildWorld();
    expect(
      codeOf(() =>
        createGrant({ ...options(world), placement: ["remote"] })
      )
    ).toBe("invalid_request");
    expect(
      codeOf(() =>
        createGrant({
          ...options(world),
          egress: { network: true, fields: [] },
        })
      )
    ).toBe("invalid_request");
    expect(
      codeOf(() =>
        createGrant({
          ...options(world),
          egress: { network: false, fields: ["message"] },
        })
      )
    ).toBe("invalid_request");
  });

  it("validates timestamps, keys, and non-active states", () => {
    const world = buildWorld();
    expect(
      codeOf(() =>
        createGrant({
          ...options(world),
          expiresAt: "2026-10-22T10:00:00Z",
        })
      )
    ).toBe("invalid_request");
    expect(
      codeOf(() =>
        createGrant({ ...options(world), createdAt: "2026-10-22 10:00:00" })
      )
    ).toBe("invalid_request");
    expect(
      codeOf(() =>
        createGrant({ ...options(world), requesterKey: "key:ed25519:nope" })
      )
    ).toBe("invalid_request");
    expect(
      codeOf(() => createGrant({ ...options(world), state: "paused" }))
    ).toBe("invalid_request");
    expect(
      createGrant({
        ...options(world),
        state: "paused",
        stateReason: "user paused",
      }).state_reason
    ).toBe("user paused");
  });

  it("accepts signed manifest wire as well as a verified manifest", () => {
    const world = buildWorld();
    const grant = createGrant({ ...options(world), manifest: world.manifestWire });
    expect(grant.manifest_digest).toBe(world.manifest.digest);
  });
});
