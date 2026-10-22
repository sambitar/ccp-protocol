import { describe, expect, it } from "vitest";
import { Agent, attenuates } from "../src/agent.js";
import { keyIdFromPublic, publicFromSeed } from "../src/crypto.js";
import type { Grant } from "../src/stores.js";

function grant(overrides: Partial<Grant> = {}): Grant {
  return {
    id: "g",
    requester_key: "key:ed25519:x",
    contact_id: "c",
    manifest_digest: "sha256:abc",
    manifest_version: 1,
    intents: ["example.lookup", "files.search"],
    limits: { calls_per_hour: 10 },
    created_at: "2026-10-22T10:00:00Z",
    expires_at: "2026-10-22T23:00:00Z",
    confirmation: { "example.lookup": "per_action", "files.search": "none" },
    capabilities: ["store.read", "files.read"],
    placement: ["local"],
    egress: { network: false, fields: [] },
    state: "active",
    state_reason: null,
    ...overrides,
  };
}

describe("attenuates", () => {
  it("accepts a narrower child", () => {
    const child = grant({
      intents: ["example.lookup"],
      limits: { calls_per_hour: 5 },
      expires_at: "2026-10-22T20:00:00Z",
      capabilities: ["store.read"],
    });
    expect(attenuates(grant(), child)).toBe(true);
  });

  it("rejects wider intents", () => {
    const parent = grant({ intents: ["example.lookup"] });
    const child = grant({ intents: ["example.lookup", "files.search"] });
    expect(attenuates(parent, child)).toBe(false);
  });

  it("rejects wider limits", () => {
    expect(attenuates(grant(), grant({ limits: { calls_per_hour: 20 } }))).toBe(
      false
    );
  });

  it("rejects a longer expiry", () => {
    expect(
      attenuates(grant(), grant({ expires_at: "2026-10-24T00:00:00Z" }))
    ).toBe(false);
  });

  it("rejects weaker confirmation", () => {
    const parent = grant({ confirmation: { "example.lookup": "per_action" } });
    const child = grant({ confirmation: { "example.lookup": "none" } });
    expect(attenuates(parent, child)).toBe(false);
  });

  it("rejects broader egress", () => {
    const child = grant({ egress: { network: true, fields: [] } });
    expect(attenuates(grant(), child)).toBe(false);
  });
});

describe("Agent", () => {
  it("exposes its public key and key id", () => {
    const seed = Uint8Array.from({ length: 32 }, (_, i) => i);
    const agent = new Agent(seed);
    expect(agent.publicKey).toEqual(publicFromSeed(seed));
    expect(agent.keyId).toBe(keyIdFromPublic(agent.publicKey));
  });

  it("builds a signed signal bound to a grant", () => {
    const agent = new Agent(Uint8Array.from({ length: 32 }, (_, i) => i));
    const wire = agent.signalFor(
      { intent: "example.lookup", params: { item_id: "x" } },
      grant(),
      {
        requestId: "r1",
        issuedAt: "2026-10-22T12:00:00Z",
        expiresAt: "2026-10-22T12:01:00Z",
      }
    );
    const data = JSON.parse(wire);
    expect(data.request_id).toBe("r1");
    expect(data.grant_digest).toBe("sha256:abc");
    expect(data.intent).toBe("example.lookup");
  });
});
